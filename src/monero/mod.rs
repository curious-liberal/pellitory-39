//! Monero key derivation and address generation.
//!
//! Given a private spend key (32-byte scalar), derive:
//! - Private view key: `sc_reduce32(Keccak256(private_spend_key))`
//! - Public spend key: `private_spend_key * G`
//! - Public view key:  `private_view_key * G`
//! - Address:          Base58(network_byte ‖ pub_spend ‖ pub_view ‖ checksum)

mod base58;
pub mod mnemonic;
mod wordlist;

use curve25519_dalek::{constants::ED25519_BASEPOINT_TABLE, Scalar};
use secrecy::SecretBox;
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, Zeroizing};

/// Network byte for Monero mainnet standard addresses.
const MAINNET_NETWORK_BYTE: u8 = 0x12;

/// All derived keys and the wallet address.
pub struct DerivedKeys {
    /// 25-word Monero mnemonic
    pub mnemonic: Zeroizing<String>,
    /// 64-char hex seed
    pub hex_seed: Zeroizing<String>,
    /// Private spend key (hex) — SECRET
    pub private_spend_key: SecretBox<String>,
    /// Public spend key (hex)
    pub public_spend_key: String,
    /// Private view key (hex) — SECRET
    pub private_view_key: SecretBox<String>,
    /// Public view key (hex)
    pub public_view_key: String,
    /// Monero mainnet address (95 chars)
    pub address: String,
}

impl Drop for DerivedKeys {
    fn drop(&mut self) {
        self.public_spend_key.zeroize();
        self.public_view_key.zeroize();
        self.address.zeroize();
    }
}

/// Errors during key derivation.
#[derive(Debug)]
pub enum DeriveError {
    InvalidHexLength(usize),
    InvalidHex(hex::FromHexError),
    Mnemonic(mnemonic::MnemonicError),
}

impl std::fmt::Display for DeriveError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DeriveError::InvalidHexLength(n) => {
                write!(f, "hex spend key must be 64 characters, got {n}")
            }
            DeriveError::InvalidHex(_) => write!(f, "invalid hex in spend key"),
            DeriveError::Mnemonic(e) => write!(f, "mnemonic error: {e}"),
        }
    }
}

impl std::error::Error for DeriveError {}

impl From<mnemonic::MnemonicError> for DeriveError {
    fn from(e: mnemonic::MnemonicError) -> Self {
        DeriveError::Mnemonic(e)
    }
}

/// Derive all Monero keys from a hex spend key or 25-word Monero mnemonic.
pub fn derive_keys(input: &str) -> Result<DerivedKeys, DeriveError> {
    let trimmed = input.trim();

    let mut seed = if trimmed.len() == 64 && trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        parse_hex_seed(trimmed)?
    } else {
        mnemonic::decode(trimmed)?
    };

    // Private spend key: reduce seed modulo the curve order l.
    let mut private_spend_scalar = Scalar::from_bytes_mod_order(seed);
    seed = *private_spend_scalar.as_bytes();

    let hex_seed = Zeroizing::new(hex::encode(seed));

    // Private view key: Keccak256(private_spend_key), then sc_reduce32.
    let mut hash = Zeroizing::new([0u8; 32]);
    keccak256(&seed, &mut hash);
    let mut private_view_scalar = Scalar::from_bytes_mod_order(*hash);
    hash.zeroize();

    // Public keys: scalar × basepoint.
    let public_spend_point = (&private_spend_scalar * ED25519_BASEPOINT_TABLE).compress();
    let public_view_point = (&private_view_scalar * ED25519_BASEPOINT_TABLE).compress();

    // Monero address.
    let address = encode_address(
        MAINNET_NETWORK_BYTE,
        public_spend_point.as_bytes(),
        public_view_point.as_bytes(),
    );

    // Mnemonic.
    let mnemonic_str = Zeroizing::new(mnemonic::encode(&seed));

    let private_spend_hex = hex::encode(private_spend_scalar.as_bytes());
    let private_view_hex = hex::encode(private_view_scalar.as_bytes());

    // Zeroize the raw scalars now that we've extracted what we need.
    private_spend_scalar.zeroize();
    private_view_scalar.zeroize();

    let result = DerivedKeys {
        mnemonic: mnemonic_str,
        hex_seed,
        private_spend_key: SecretBox::new(Box::new(private_spend_hex)),
        public_spend_key: hex::encode(public_spend_point.as_bytes()),
        private_view_key: SecretBox::new(Box::new(private_view_hex)),
        public_view_key: hex::encode(public_view_point.as_bytes()),
        address,
    };

    seed.zeroize();
    Ok(result)
}

fn parse_hex_seed(hex_str: &str) -> Result<[u8; 32], DeriveError> {
    if hex_str.len() != 64 {
        return Err(DeriveError::InvalidHexLength(hex_str.len()));
    }
    // Wrap the decoded bytes in `Zeroizing` so the heap buffer holding the
    // raw spend key is overwritten with zeroes before it is freed — ordinary
    // `Vec::Drop` only frees without scrubbing. Mirrors `MasterSecret::from_hex`.
    let mut bytes = Zeroizing::new(hex::decode(hex_str).map_err(DeriveError::InvalidHex)?);
    let mut arr = [0u8; 32];
    arr.copy_from_slice(&bytes);
    bytes.zeroize();
    Ok(arr)
}

/// Keccak-256 (NOT SHA-3-256 — Monero uses the original Keccak).
fn keccak256(input: &[u8], output: &mut [u8; 32]) {
    let mut hasher = Keccak::v256();
    hasher.update(input);
    hasher.finalize(output);
}

/// Build a Monero address: base58(network ‖ pub_spend ‖ pub_view ‖ checksum).
fn encode_address(network_byte: u8, pub_spend: &[u8; 32], pub_view: &[u8; 32]) -> String {
    let mut data = Vec::with_capacity(69);
    data.push(network_byte);
    data.extend_from_slice(pub_spend);
    data.extend_from_slice(pub_view);

    let mut hash = [0u8; 32];
    keccak256(&data, &mut hash);
    data.extend_from_slice(&hash[..4]);
    hash.zeroize();

    debug_assert_eq!(data.len(), 69);
    base58::encode(&data)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secrecy::ExposeSecret;

    const TEST_SPEND_KEY: &str =
        "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";

    // All values verified against an independent Monero reference implementation.
    const EXPECTED_VIEW_KEY: &str =
        "157874dc4e2961c872f87aaf4346146d0f596e2f116a51fbac01b693a8e3020a";
    const EXPECTED_PUB_SPEND: &str =
        "7aff30fbdc005ecb03f57a11e250e0d665621ffde1d44c6aa84a8212cc0d1236";
    const EXPECTED_PUB_VIEW: &str =
        "25c1b6920540fbcfcb0e36bd2c88f5c1e62e5ef1d621279e7230b47648e64a63";
    const EXPECTED_ADDRESS: &str =
        "46HSxE7KoiDaxWFWR1wmJfcrunNj4TLiPJqiCJkQn345A4JJzgBNhUvbkrYWJX4EVJZS4kJGfGj7CTW8GEUHsbEZCEupMt6";

    #[test]
    fn derive_from_hex() {
        let keys = derive_keys(TEST_SPEND_KEY).expect("derivation should succeed");
        assert_eq!(keys.address.len(), 95);
        assert!(keys.address.starts_with('4'));
    }

    #[test]
    fn matches_reference_vector() {
        let keys = derive_keys(TEST_SPEND_KEY).expect("derivation should succeed");
        assert_eq!(keys.private_view_key.expose_secret(), EXPECTED_VIEW_KEY);
        assert_eq!(keys.public_spend_key, EXPECTED_PUB_SPEND);
        assert_eq!(keys.public_view_key, EXPECTED_PUB_VIEW);
        assert_eq!(keys.address, EXPECTED_ADDRESS);
    }

    #[test]
    fn hex_roundtrip() {
        let keys = derive_keys(TEST_SPEND_KEY).expect("derivation should succeed");
        let keys2 = derive_keys(&keys.mnemonic).expect("mnemonic derivation should succeed");
        assert_eq!(keys.address, keys2.address);
        assert_eq!(
            keys.private_spend_key.expose_secret(),
            keys2.private_spend_key.expose_secret()
        );
    }
}
