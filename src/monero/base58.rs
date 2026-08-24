//! Monero-flavour Base58 encoding.
//!
//! Unlike Bitcoin's base58, Monero encodes fixed-size blocks:
//! 8 bytes → 11 chars, with a shorter final block.

const ALPHABET: &[u8; 58] = b"123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

/// Number of base58 characters needed for a block of `byte_count` bytes.
const ENCODED_BLOCK_SIZES: [usize; 9] = [0, 2, 3, 5, 6, 7, 9, 10, 11];

const FULL_BLOCK_SIZE: usize = 8;
const FULL_ENCODED_BLOCK_SIZE: usize = 11;

/// Encode a byte slice into Monero base58.
pub fn encode(data: &[u8]) -> String {
    if data.is_empty() {
        return String::new();
    }

    let full_blocks = data.len() / FULL_BLOCK_SIZE;
    let remainder = data.len() % FULL_BLOCK_SIZE;
    let result_len = full_blocks * FULL_ENCODED_BLOCK_SIZE
        + if remainder > 0 {
            ENCODED_BLOCK_SIZES[remainder]
        } else {
            0
        };

    let mut result = vec![b'1'; result_len]; // '1' is base58 zero
    let mut pos = 0;

    for i in 0..full_blocks {
        let start = i * FULL_BLOCK_SIZE;
        encode_block(&data[start..start + FULL_BLOCK_SIZE], &mut result[pos..pos + FULL_ENCODED_BLOCK_SIZE]);
        pos += FULL_ENCODED_BLOCK_SIZE;
    }

    if remainder > 0 {
        let start = full_blocks * FULL_BLOCK_SIZE;
        let encoded_size = ENCODED_BLOCK_SIZES[remainder];
        encode_block(&data[start..], &mut result[pos..pos + encoded_size]);
    }

    // SAFETY: ALPHABET only contains valid ASCII characters.
    String::from_utf8(result).expect("base58 alphabet is ASCII")
}

fn encode_block(data: &[u8], out: &mut [u8]) {
    // Treat `data` as a big-endian unsigned integer.
    let mut num: u128 = 0;
    for &b in data {
        num = (num << 8) | u128::from(b);
    }

    // Convert to base58, filling output right-to-left.
    for o in out.iter_mut().rev() {
        let rem = (num % 58) as usize;
        num /= 58;
        *o = ALPHABET[rem];
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_known_vector() {
        // A short sanity check: encoding 8 zero bytes should give 11 '1's.
        let zeros = [0u8; 8];
        let encoded = encode(&zeros);
        assert_eq!(encoded.len(), 11);
        assert!(encoded.chars().all(|c| c == '1'));
    }
}
