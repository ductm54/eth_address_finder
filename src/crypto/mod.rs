use rand::rngs::OsRng;
use secp256k1::{PublicKey, Scalar, Secp256k1, SecretKey, SignOnly};
use tiny_keccak::{Hasher, Keccak};

thread_local! {
    // Secp256k1::signing_only() builds per-context state; caching per-thread
    // avoids paying that cost on every key check. We only sign, never verify.
    static SECP: Secp256k1<SignOnly> = Secp256k1::signing_only();
}

/// Generate a random Ethereum private key
pub fn generate_private_key() -> SecretKey {
    SecretKey::new(&mut OsRng)
}

/// Hash a (pre-derived) secp256k1 public key into a 20-byte Ethereum address.
fn pubkey_to_address_bytes(public_key: &PublicKey) -> [u8; 20] {
    // Uncompressed serialization is 0x04 || X || Y (65 bytes); skip the tag.
    let public_key_bytes = &public_key.serialize_uncompressed()[1..];

    let mut keccak = Keccak::v256();
    let mut hash = [0u8; 32];
    keccak.update(public_key_bytes);
    keccak.finalize(&mut hash);

    let mut address = [0u8; 20];
    address.copy_from_slice(&hash[12..]);
    address
}

/// Derive the raw 20-byte Ethereum address from a private key.
///
/// Each call performs a full secp256k1 scalar multiplication (~28 µs). If
/// you're checking many candidates in a row, prefer [`IncrementalKeygen`],
/// which pays that cost once and then advances via cheap point addition.
pub fn private_key_to_address_bytes(private_key: &SecretKey) -> [u8; 20] {
    let public_key = SECP.with(|secp| PublicKey::from_secret_key(secp, private_key));
    pubkey_to_address_bytes(&public_key)
}

/// Iterator-like state that amortizes secp256k1 scalar multiplication across
/// a run of candidate keys.
///
/// Starts from a uniformly-random secret `k₀` and its public point `P₀ = k₀·G`
/// (one scalar multiplication at construction), then each call to
/// [`IncrementalKeygen::advance`] steps to `k_{i+1} = k_i + 1` and
/// `P_{i+1} = P_i + G` using a single point addition — roughly an order of
/// magnitude cheaper than a fresh scalar multiplication.
///
/// Keys produced this way are still unpredictable to an adversary: the
/// starting point is fresh entropy, and knowing the final key reveals the
/// starting one, which is a group element sampled from a full 256-bit
/// space. This is the standard technique used by vanity-address tools.
pub struct IncrementalKeygen {
    secret: SecretKey,
    public: PublicKey,
    g_public: PublicKey,
    one_tweak: Scalar,
}

impl IncrementalKeygen {
    /// Seed from a fresh random `k₀`, performing one scalar multiplication.
    pub fn new() -> Self {
        let secret = SecretKey::new(&mut OsRng);
        let public = SECP.with(|secp| PublicKey::from_secret_key(secp, &secret));

        // G, stored as a PublicKey so we can use pure point-addition to step.
        let mut one_bytes = [0u8; 32];
        one_bytes[31] = 1;
        let one_secret = SecretKey::from_slice(&one_bytes).expect("1 is a valid secp256k1 scalar");
        let g_public = SECP.with(|secp| PublicKey::from_secret_key(secp, &one_secret));
        let one_tweak = Scalar::from(one_secret);

        Self {
            secret,
            public,
            g_public,
            one_tweak,
        }
    }

    /// Current private key (corresponds to [`Self::address_bytes`]).
    pub fn secret(&self) -> SecretKey {
        self.secret
    }

    /// Keccak-256 of the current uncompressed public key, truncated to 20 bytes.
    pub fn address_bytes(&self) -> [u8; 20] {
        pubkey_to_address_bytes(&self.public)
    }

    /// Step to `k+1` / `P+G`. Cost: one point addition + one scalar add mod n.
    pub fn advance(&mut self) {
        // Overflow past the group order n ≈ 2²⁵⁶ is not reachable in practice.
        self.secret = self
            .secret
            .add_tweak(&self.one_tweak)
            .expect("scalar order overflow is unreachable");
        self.public = self
            .public
            .combine(&self.g_public)
            .expect("P + G is never the identity for P ≠ -G");
    }
}

impl Default for IncrementalKeygen {
    fn default() -> Self {
        Self::new()
    }
}

/// Format a 20-byte address as `0x<40 hex chars>`.
pub fn address_to_hex(address: &[u8; 20]) -> String {
    format!("0x{}", hex::encode(address))
}

/// Derive Ethereum address from private key, returning the hex form.
///
/// Convenience wrapper around [`private_key_to_address_bytes`] + [`address_to_hex`].
/// Prefer the byte-level primitives in hot loops.
pub fn private_key_to_address(private_key: &SecretKey) -> String {
    address_to_hex(&private_key_to_address_bytes(private_key))
}

/// Pre-decoded prefix/suffix alternatives, so the hot loop never re-lowercases
/// or re-decodes anything per candidate. Each side holds zero-or-more
/// alternatives; an address matches if it satisfies *any* prefix alternative
/// AND *any* suffix alternative (with an empty list meaning "no constraint").
#[derive(Debug, Clone)]
pub struct MatchRule {
    prefix_alts: Vec<Vec<u8>>,
    suffix_alts: Vec<Vec<u8>>,
}

impl MatchRule {
    /// Build a rule from lists of alternative prefix/suffix hex strings.
    /// An empty slice means "no constraint on this side". Non-hex characters
    /// or overly long inputs return an error.
    pub fn new<S: AsRef<str>>(prefixes: &[S], suffixes: &[S]) -> Result<Self, String> {
        let prefix_alts = decode_alts(prefixes)?;
        let suffix_alts = decode_alts(suffixes)?;
        let max_prefix = prefix_alts.iter().map(Vec::len).max().unwrap_or(0);
        let max_suffix = suffix_alts.iter().map(Vec::len).max().unwrap_or(0);
        if max_prefix + max_suffix > 40 {
            return Err(format!(
                "prefix + suffix length exceeds 40 hex chars (got {max_prefix} + {max_suffix})"
            ));
        }
        Ok(Self {
            prefix_alts,
            suffix_alts,
        })
    }

    /// Returns true if `address` matches one of the prefix alternatives (or
    /// no prefix is required) AND one of the suffix alternatives (or none is
    /// required).
    #[inline]
    pub fn matches(&self, address: &[u8; 20]) -> bool {
        let prefix_ok = self.prefix_alts.is_empty()
            || self
                .prefix_alts
                .iter()
                .any(|alt| matches_prefix(address, alt));
        if !prefix_ok {
            return false;
        }
        self.suffix_alts.is_empty()
            || self
                .suffix_alts
                .iter()
                .any(|alt| matches_suffix(address, alt))
    }
}

#[inline]
fn matches_prefix(address: &[u8; 20], alt: &[u8]) -> bool {
    for (i, &want) in alt.iter().enumerate() {
        if nibble_at(address, i) != want {
            return false;
        }
    }
    true
}

#[inline]
fn matches_suffix(address: &[u8; 20], alt: &[u8]) -> bool {
    let len = alt.len();
    for (i, &want) in alt.iter().enumerate() {
        if nibble_at(address, 40 - len + i) != want {
            return false;
        }
    }
    true
}

fn decode_alts<S: AsRef<str>>(alts: &[S]) -> Result<Vec<Vec<u8>>, String> {
    alts.iter().map(|s| decode_nibbles(s.as_ref())).collect()
}

#[inline]
fn nibble_at(address: &[u8; 20], i: usize) -> u8 {
    let byte = address[i / 2];
    if i % 2 == 0 {
        byte >> 4
    } else {
        byte & 0x0f
    }
}

fn decode_nibbles(s: &str) -> Result<Vec<u8>, String> {
    let trimmed = s.strip_prefix("0x").unwrap_or(s);
    let mut out = Vec::with_capacity(trimmed.len());
    for (idx, c) in trimmed.chars().enumerate() {
        match c.to_digit(16) {
            Some(d) => out.push(d as u8),
            None => {
                return Err(format!(
                    "non-hex character {c:?} at position {idx} in {s:?}"
                ))
            }
        }
    }
    Ok(out)
}

/// Back-compat: check if an address (hex string form) matches the prefix/suffix.
///
/// Allocates; prefer [`MatchRule::matches`] in hot code.
pub fn address_matches(address: &str, prefix: &Option<String>, suffix: &Option<String>) -> bool {
    let prefixes: Vec<&str> = prefix.as_deref().into_iter().collect();
    let suffixes: Vec<&str> = suffix.as_deref().into_iter().collect();
    let rule = match MatchRule::new(&prefixes, &suffixes) {
        Ok(r) => r,
        Err(_) => return false,
    };
    let hex = address.strip_prefix("0x").unwrap_or(address);
    let bytes = match hex::decode(hex) {
        Ok(b) if b.len() == 20 => b,
        _ => return false,
    };
    let mut arr = [0u8; 20];
    arr.copy_from_slice(&bytes);
    rule.matches(&arr)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hex_round_trips_through_byte_primitives() {
        let key = generate_private_key();
        let hex_direct = private_key_to_address(&key);
        let via_bytes = address_to_hex(&private_key_to_address_bytes(&key));
        assert_eq!(hex_direct, via_bytes);
    }

    fn one(s: &str) -> Vec<&str> {
        vec![s]
    }
    const NONE: &[&str] = &[];

    #[test]
    fn match_rule_prefix_and_suffix() {
        let mut addr = [0u8; 20];
        addr[0] = 0xab;
        addr[19] = 0xcd;
        let rule = MatchRule::new(&one("ab"), &one("cd")).unwrap();
        assert!(rule.matches(&addr));

        let rule = MatchRule::new(&one("ab"), &one("ce")).unwrap();
        assert!(!rule.matches(&addr));

        let rule = MatchRule::new(&one("abc"), NONE).unwrap();
        assert!(!rule.matches(&addr)); // third nibble is 0, not c
    }

    #[test]
    fn match_rule_odd_length_suffix() {
        // Suffix of 3 nibbles should check the last 3 nibbles of the hex form.
        // Last 3 nibbles of 0x...xy where last byte is 0xcd is "xcd". Byte
        // addr[18] = 0xab, addr[19] = 0xcd → last 4 nibbles: a,b,c,d →
        // last 3: b,c,d.
        let mut addr = [0u8; 20];
        addr[18] = 0xab;
        addr[19] = 0xcd;
        assert!(MatchRule::new(NONE, &one("bcd")).unwrap().matches(&addr));
        assert!(!MatchRule::new(NONE, &one("acd")).unwrap().matches(&addr));
    }

    #[test]
    fn match_rule_rejects_non_hex() {
        assert!(MatchRule::new(&one("xyz"), NONE).is_err());
    }

    #[test]
    fn match_rule_multi_suffix_matches_any_alt() {
        // Only the last 3 nibbles matter. Build addresses ending in each
        // alternative and verify they all match the same rule.
        let rule = MatchRule::new(NONE, &["001", "002", "003"]).unwrap();

        for (last_byte_high, last_byte_low, expected) in [
            (0x00u8, 0x01u8, true), // ends in ...001
            (0x00, 0x02, true),     // ...002
            (0x00, 0x03, true),     // ...003
            (0x00, 0x04, false),    // ...004 should not match
        ] {
            let mut addr = [0u8; 20];
            addr[18] = last_byte_high;
            addr[19] = last_byte_low;
            assert_eq!(rule.matches(&addr), expected, "addr={addr:?}");
        }
    }

    #[test]
    fn match_rule_multi_prefix_matches_any_alt() {
        let rule = MatchRule::new(&["ab", "cd"], NONE).unwrap();
        let mut a = [0u8; 20];
        a[0] = 0xab;
        assert!(rule.matches(&a));
        let mut b = [0u8; 20];
        b[0] = 0xcd;
        assert!(rule.matches(&b));
        let mut c = [0u8; 20];
        c[0] = 0xef;
        assert!(!rule.matches(&c));
    }

    #[test]
    fn match_rule_multi_requires_prefix_and_suffix_alt() {
        // Both sides must hit *one* alternative each.
        let rule = MatchRule::new(&["ab", "cd"], &["01", "02"]).unwrap();
        let mut ok = [0u8; 20];
        ok[0] = 0xcd;
        ok[19] = 0x02;
        assert!(rule.matches(&ok));

        let mut wrong_suffix = [0u8; 20];
        wrong_suffix[0] = 0xab;
        wrong_suffix[19] = 0x03;
        assert!(!rule.matches(&wrong_suffix));

        let mut wrong_prefix = [0u8; 20];
        wrong_prefix[0] = 0xef;
        wrong_prefix[19] = 0x01;
        assert!(!rule.matches(&wrong_prefix));
    }

    #[test]
    fn match_rule_length_limit_uses_longest_alt() {
        // 40-nibble prefix alt plus any non-empty suffix must exceed the budget.
        let long_prefix = "a".repeat(40);
        assert!(MatchRule::new(&[long_prefix.as_str()], &["0"]).is_err());
        // Within budget: 30 + 10 is fine.
        let p = "a".repeat(30);
        let s = "b".repeat(10);
        assert!(MatchRule::new(&[p.as_str()], &[s.as_str()]).is_ok());
    }

    #[test]
    fn incremental_keygen_matches_fresh_derivation() {
        // Take a snapshot of (secret_i, address_i) from the incremental
        // iterator and verify that deriving address fresh from secret_i
        // gives the same bytes. This guards against the point-addition
        // path silently drifting away from the canonical scalar-mult path.
        let mut kg = IncrementalKeygen::new();
        for _ in 0..16 {
            let secret = kg.secret();
            let incremental = kg.address_bytes();
            let fresh = private_key_to_address_bytes(&secret);
            assert_eq!(
                incremental, fresh,
                "incremental address drifted from scalar-mult derivation"
            );
            kg.advance();
        }
    }

    #[test]
    fn match_rule_accepts_0x_prefix() {
        let rule = MatchRule::new(&one("0xab"), NONE).unwrap();
        let mut addr = [0u8; 20];
        addr[0] = 0xab;
        assert!(rule.matches(&addr));
    }
}
