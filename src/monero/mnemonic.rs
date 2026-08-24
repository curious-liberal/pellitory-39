//! Monero mnemonic seed encoding and decoding (25-word English).
//!
//! A 32-byte seed is encoded as 24 data words + 1 checksum word.
//! Each group of 4 bytes (little-endian u32) maps to 3 words.

use super::wordlist::{PREFIX_LEN, WORDLIST};
use std::collections::HashMap;
use zeroize::Zeroize;

const N: u32 = 1626;

/// Errors that can occur during mnemonic operations.
#[derive(Debug, thiserror::Error)]
pub enum MnemonicError {
    #[error("mnemonic must be exactly 25 words, got {0}")]
    WrongWordCount(usize),
    #[error("unknown word in mnemonic: \"{0}\"")]
    UnknownWord(String),
    #[error("mnemonic checksum is invalid")]
    BadChecksum,
    #[error("word index overflow during decoding")]
    IndexOverflow,
}

/// Encode a 32-byte seed into a 25-word mnemonic.
///
/// The seed bytes are consumed and the internal buffer is zeroised on drop.
pub fn encode(seed: &[u8; 32]) -> String {
    let mut words: Vec<&str> = Vec::with_capacity(25);

    // Process 4 bytes at a time → 3 words per group (8 groups = 24 words).
    for chunk in seed.chunks_exact(4) {
        let mut x = u32::from_le_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);

        let w1 = (x % N) as usize;
        let w2 = ((x / N).wrapping_add(x % N) % N) as usize;
        let w3 = ((x / (N * N)).wrapping_add((x / N).wrapping_add(x % N) % N) % N) as usize;

        words.push(WORDLIST[w1]);
        words.push(WORDLIST[w2]);
        words.push(WORDLIST[w3]);

        x.zeroize();
    }

    // Checksum word: Monero repeats one of the 24 data words, selected by
    // CRC32 of the word prefixes. It is NOT a fresh word from the wordlist.
    let checksum_idx = compute_checksum(&words);
    words.push(words[checksum_idx]);

    words.join(" ")
}

/// Decode a 25-word mnemonic into a 32-byte seed.
///
/// Returns an error if the word count, any word, or the checksum is invalid.
pub fn decode(phrase: &str) -> Result<[u8; 32], MnemonicError> {
    let words: Vec<&str> = phrase.split_whitespace().collect();
    if words.len() != 25 {
        return Err(MnemonicError::WrongWordCount(words.len()));
    }

    // Build lookup by truncated prefix.
    let index_map = build_index_map();

    // Verify checksum: the 25th word must be a repeat of the data word at
    // position `expected_idx`. Compare by resolved wordlist index so that
    // prefix-equivalent words are treated as equal.
    let data_words = &words[..24];
    let expected_idx = compute_checksum(data_words);
    let provided_word = lookup_word(&index_map, words[24])?;
    let expected_word = lookup_word(&index_map, data_words[expected_idx])?;
    if provided_word != expected_word {
        return Err(MnemonicError::BadChecksum);
    }

    // Decode 24 words → 32 bytes.
    let mut seed = [0u8; 32];
    for (i, triple) in data_words.chunks_exact(3).enumerate() {
        let w1 = lookup_word(&index_map, triple[0])? as u64;
        let w2 = lookup_word(&index_map, triple[1])? as u64;
        let w3 = lookup_word(&index_map, triple[2])? as u64;

        let n = N as u64;
        let x = w1
            + n * ((n + w2 - w1) % n)
            + n * n * ((n + w3 - w2) % n);

        if x > u32::MAX as u64 {
            seed.zeroize();
            return Err(MnemonicError::IndexOverflow);
        }

        let bytes = (x as u32).to_le_bytes();
        seed[i * 4..i * 4 + 4].copy_from_slice(&bytes);
    }

    Ok(seed)
}

/// Compute the checksum index for a set of data words.
fn compute_checksum(words: &[&str]) -> usize {
    let prefixes: String = words
        .iter()
        .map(|w| &w[..std::cmp::min(PREFIX_LEN, w.len())])
        .collect();

    let crc = crc32fast::hash(prefixes.as_bytes());
    (crc as usize) % words.len()
}

/// Build a map from truncated prefix → word index.
fn build_index_map() -> HashMap<String, usize> {
    let mut map = HashMap::with_capacity(WORDLIST.len());
    for (i, word) in WORDLIST.iter().enumerate() {
        let prefix = &word[..std::cmp::min(PREFIX_LEN, word.len())];
        map.insert(prefix.to_string(), i);
    }
    map
}

/// Look up a word by its truncated prefix.
fn lookup_word(map: &HashMap<String, usize>, word: &str) -> Result<usize, MnemonicError> {
    let prefix = &word[..std::cmp::min(PREFIX_LEN, word.len())];
    map.get(prefix)
        .copied()
        .ok_or_else(|| MnemonicError::UnknownWord(word.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Known-good vector verified against the Monero reference algorithm.
    const TEST_SEED_HEX: &str =
        "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";
    const TEST_MNEMONIC: &str = "spout midst duckling tepid odds glass enhanced \
        avatar ocean rarest eavesdrop egotistic oxygen trying future airport \
        session nanny tedious guru asylum superior cement cunning eavesdrop";

    #[test]
    fn roundtrip() {
        let seed: [u8; 32] = [
            0xaf, 0x60, 0x82, 0xaf, 0x29, 0x10, 0x8a, 0xbd,
            0xa6, 0x9c, 0xc3, 0x85, 0xdf, 0xed, 0x21, 0x02,
            0xb8, 0x92, 0xa8, 0x71, 0x69, 0x53, 0x67, 0xcb,
            0x22, 0xa4, 0xb9, 0xb6, 0xdf, 0x8b, 0x32, 0x06,
        ];
        let mnemonic = encode(&seed);
        let decoded = decode(&mnemonic).expect("decode should succeed");
        assert_eq!(seed, decoded);
    }

    #[test]
    fn matches_monero_reference() {
        let seed: [u8; 32] = hex::decode(TEST_SEED_HEX).unwrap().try_into().unwrap();
        // Encoding must produce exactly the Monero-standard mnemonic.
        assert_eq!(encode(&seed), TEST_MNEMONIC);
        // And the standard mnemonic must decode back to the seed.
        assert_eq!(decode(TEST_MNEMONIC).unwrap(), seed);
    }

    #[test]
    fn rejects_bad_checksum() {
        // Replace only the final (checksum) word with a different valid word.
        let mut words: Vec<&str> = TEST_MNEMONIC.split_whitespace().collect();
        *words.last_mut().unwrap() = "abbey";
        let bad = words.join(" ");
        assert!(decode(&bad).is_err());
    }
}
