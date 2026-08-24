//! # Pellitory-39
//!
//! Secure backup and recovery for cryptocurrency wallets using SLIP-0039
//! secret sharing.
//!
//! Supports **Bitcoin** (BIP-39 mnemonics), **Monero** (25-word mnemonics
//! and hex spend keys), and any other hex-encoded secret up to 64 bytes.
//!
//! ## Security
//!
//! - All secret material is wrapped in `Zeroizing<T>` or `SecretBox<T>` and
//!   wiped from memory on drop.
//! - Cryptographic RNG (`OsRng`) for all key generation.
//! - Intermediate buffers are explicitly zeroised after use.

// SECURITY: forbid `unsafe` at the crate level so future contributions
// cannot silently introduce hand-rolled pointer arithmetic or unchecked
// operations in this security-critical codebase. Cryptographic primitives
// live in audited dependencies and are exempt from this check.
#![forbid(unsafe_code)]

pub mod monero;
pub mod sharing;
pub mod gui_support;
pub mod encrypt;
pub mod export;

use anyhow::anyhow;
use zeroize::Zeroizing;

/// The coin / secret family a command operates on.
///
/// Used by the CLI (`--coin`/`-c` flag) to select how input is
/// interpreted and how output is formatted. Mirrors the GUI's coin tabs
/// (Bitcoin / Monero), with an additional `Hex` variant for raw secrets
/// that don't map to a specific wallet ecosystem.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Coin {
    /// Bitcoin / Ethereum — BIP-39 mnemonics and entropy.
    Bitcoin,
    /// Monero — 25-word mnemonics and hex spend keys.
    Monero,
    /// Raw hex secret — no coin-specific key derivation.
    Hex,
}

impl Coin {
    /// Parse a coin from a case-insensitive string.
    ///
    /// Accepts:
    ///   • `bitcoin` / `btc` → [`Coin::Bitcoin`]
    ///   • `monero` / `xmr` → [`Coin::Monero`]
    ///   • `hex`            → [`Coin::Hex`]
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        match s.to_ascii_lowercase().as_str() {
            "bitcoin" | "btc" => Ok(Coin::Bitcoin),
            "monero" | "xmr" => Ok(Coin::Monero),
            "hex" => Ok(Coin::Hex),
            other => Err(anyhow!(
                "unknown coin '{other}' — expected bitcoin/btc, monero/xmr, or hex"
            )),
        }
    }
}

/// The supported input formats for secrets.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum InputKind {
    /// Raw hexadecimal bytes.
    Hex,
    /// 25-word Monero mnemonic.
    MoneroMnemonic,
    /// 12/15/18/21/24-word BIP-39 mnemonic (Bitcoin, Ethereum, etc.).
    Bip39Mnemonic,
}

/// Auto-detect the input kind and convert to raw hex bytes.
///
/// Accepts:
/// - A hex string (even number of hex digits, typically 32 or 64 chars)
/// - A 25-word Monero mnemonic
/// - A 12/15/18/21/24-word BIP-39 mnemonic
///
/// Returns the detected kind and the secret as hex.
pub fn detect_and_normalise(input: &str) -> anyhow::Result<(InputKind, Zeroizing<String>)> {
    let trimmed = input.trim();
    let words: Vec<&str> = trimmed.split_whitespace().collect();

    match words.len() {
        // Single token — treat as hex.
        1 => {
            let candidate = words[0];
            if !candidate.len().is_multiple_of(2) || !candidate.chars().all(|c| c.is_ascii_hexdigit()) {
                anyhow::bail!(
                    "single-token input looks like hex but is invalid \
                     (must be an even number of hex digits)"
                );
            }
            Ok((InputKind::Hex, Zeroizing::new(candidate.to_lowercase())))
        }

        // 25 words — Monero mnemonic.
        25 => {
            let seed = monero::mnemonic::decode(trimmed)?;
            let hex_str = hex::encode(seed);
            Ok((InputKind::MoneroMnemonic, Zeroizing::new(hex_str)))
        }

        // 12, 15, 18, 21, 24 words — BIP-39 mnemonic.
        n @ (12 | 15 | 18 | 21 | 24) => {
            let mnemonic = bip39::Mnemonic::from_phrase(trimmed, bip39::Language::English)
                .map_err(|e| anyhow::anyhow!("invalid BIP-39 mnemonic ({n} words): {e}"))?;
            let hex_str = hex::encode(mnemonic.entropy());
            Ok((InputKind::Bip39Mnemonic, Zeroizing::new(hex_str)))
        }

        other => {
            anyhow::bail!(
                "cannot auto-detect input with {other} words. \
                 Expected: hex, 25-word Monero mnemonic, or \
                 12/15/18/21/24-word BIP-39 mnemonic."
            );
        }
    }
}

/// The BIP-39 entropy byte lengths supported by `tiny-bip39` (and the
/// spec): 128 / 160 / 192 / 224 / 256 bits → 12 / 15 / 18 / 21 / 24 words.
pub const BIP39_ENTROPY_LENGTHS: [usize; 5] = [16, 20, 24, 28, 32];

/// Derive a BIP-39 mnemonic **phrase** from raw entropy bytes.
///
/// This is the "derive" path for Bitcoin / Ethereum and any other BIP-39
/// wallet: take raw hex entropy (16 / 20 / 24 / 28 / 32 bytes) and turn it
/// into a recoverable 12 / 15 / 18 / 21 / 24-word seed phrase. The
/// checksum word is computed by `tiny-bip39`.
///
/// The returned phrase is wrapped in [`Zeroizing`] so it is wiped from
/// memory on drop — the phrase is secret-equivalent to the entropy.
///
/// # Errors
///
/// Returns an error if the entropy length is not one of the BIP-39-valid
/// sizes. Hex decoding is the caller's responsibility; pass raw bytes.
pub fn derive_bip39_mnemonic(entropy: &[u8]) -> anyhow::Result<Zeroizing<String>> {
    if !BIP39_ENTROPY_LENGTHS.contains(&entropy.len()) {
        return Err(anyhow!(
            "BIP-39 entropy must be one of 16 / 20 / 24 / 28 / 32 bytes \
             (128/160/192/224/256 bits → 12/15/18/21/24 words), got {} bytes",
            entropy.len()
        ));
    }
    let mnemonic = bip39::Mnemonic::from_entropy(entropy, bip39::Language::English)
        .map_err(|e| anyhow!("BIP-39 encoding failed: {e}"))?;
    // `into_phrase` returns an owned `String` holding the secret phrase.
    // Wrap it in `Zeroizing` so it is scrubbed on drop; the bare `String`
    // is moved in and never copied.
    Ok(Zeroizing::new(mnemonic.into_phrase()))
}

#[cfg(test)]
mod bip39_derive_tests {
    use super::*;

    #[test]
    fn derives_24_words_from_32_bytes() {
        let entropy = [0u8; 32];
        let phrase = derive_bip39_mnemonic(&entropy).expect("32 bytes is valid");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 24);
    }

    #[test]
    fn derives_12_words_from_16_bytes() {
        let entropy = [0u8; 16];
        let phrase = derive_bip39_mnemonic(&entropy).expect("16 bytes is valid");
        let words: Vec<&str> = phrase.split_whitespace().collect();
        assert_eq!(words.len(), 12);
    }

    /// All-zero entropy has a known BIP-39 mnemonic — the canonical
    /// "abandon abandon ... about" vector. Pinning it guards against a
    /// silently broken checksum or wordlist.
    #[test]
    fn matches_canonical_all_zero_vector() {
        let entropy = [0u8; 16];
        let phrase = derive_bip39_mnemonic(&entropy).unwrap();
        assert_eq!(
            phrase.as_str(),
            "abandon abandon abandon abandon abandon abandon \
             abandon abandon abandon abandon abandon about"
        );
    }

    #[test]
    fn rejects_invalid_entropy_lengths() {
        for bad in [0usize, 12, 17, 33, 64] {
            assert!(
                derive_bip39_mnemonic(&vec![0u8; bad]).is_err(),
                "len {bad} should be rejected"
            );
        }
    }

    /// The phrase round-trips back to the same entropy via `tiny-bip39`,
    /// proving we are not mutating the input or miscounting words.
    #[test]
    fn phrase_roundtrips_to_entropy() {
        let entropy: Vec<u8> = (0..32u8).collect();
        let phrase = derive_bip39_mnemonic(&entropy).unwrap();
        let m = bip39::Mnemonic::from_phrase(phrase.as_str(), bip39::Language::English)
            .expect("phrase must round-trip");
        assert_eq!(m.entropy(), entropy.as_slice());
    }
}

#[cfg(test)]
mod coin_tests {
    use super::*;

    #[test]
    fn parse_full_names() {
        assert_eq!(Coin::parse("bitcoin").unwrap(), Coin::Bitcoin);
        assert_eq!(Coin::parse("monero").unwrap(), Coin::Monero);
        assert_eq!(Coin::parse("hex").unwrap(), Coin::Hex);
    }

    #[test]
    fn parse_tickers() {
        assert_eq!(Coin::parse("btc").unwrap(), Coin::Bitcoin);
        assert_eq!(Coin::parse("xmr").unwrap(), Coin::Monero);
    }

    #[test]
    fn parse_case_insensitive() {
        assert_eq!(Coin::parse("Bitcoin").unwrap(), Coin::Bitcoin);
        assert_eq!(Coin::parse("MONERO").unwrap(), Coin::Monero);
        assert_eq!(Coin::parse("Hex").unwrap(), Coin::Hex);
        assert_eq!(Coin::parse("BTC").unwrap(), Coin::Bitcoin);
        assert_eq!(Coin::parse("Xmr").unwrap(), Coin::Monero);
    }

    #[test]
    fn parse_rejects_unknown() {
        assert!(Coin::parse("ethereum").is_err());
        assert!(Coin::parse("doge").is_err());
        assert!(Coin::parse("").is_err());
        assert!(Coin::parse("bitcoin ").is_err());
    }
}
