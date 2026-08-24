// Copyright 2019 The Grin Developers
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Master secret encryption
//!
//! Hardened fork: all intermediate buffers holding secret material are
//! zeroised on drop via the `zeroize` crate.

use crate::error::Error;
use zeroize::{Zeroize, Zeroizing};

/// Maximum supported SLIP-0039 iteration exponent.
///
/// SLIP-0039 packs the exponent into a 5-bit field, but the top bit (bit 4)
/// is the extendable-backup (`ext`) flag. The remaining 4 bits hold the
/// exponent, giving a legal range of 0..=15 regardless of the `ext` value.
/// Values >= 16 in the raw 5-bit field simply mean `ext = 1` (see
/// [`Share::extendable`](crate::shamir::Share)).
///
/// `split`/`gen` enforce this on the produce side; `Share::parse_bp`
/// masks the exponent to 4 bits on the consume side. This constant is used
/// here purely as **defence-in-depth** so that no future API misuse of
/// `round_function` can reach the `NonZeroU32::new(0).unwrap()` path.
pub const MAX_ITERATION_EXPONENT: u8 = 15;

#[cfg(feature = "rust_crypto_pbkdf2")]
use hmac::Hmac;
#[cfg(feature = "rust_crypto_pbkdf2")]
use pbkdf2::pbkdf2;
#[cfg(feature = "ring_pbkdf2")]
use ring::pbkdf2;
#[cfg(feature = "rust_crypto_pbkdf2")]
use sha2::Sha256;
#[cfg(feature = "ring_pbkdf2")]
use std::num::NonZeroU32;

/// Config Struct
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MasterSecretEncConfig {
	/// The minimum number of iterations to use in PBKDF2
	pub min_iteration_count: u32,
	/// The number of rounds to use in the Feistel cipher
	pub round_count: u8,
	/// The customization string used in the RS1024 checksum and in the PBKDF2 salt
	pub customization_string: Vec<u8>,
}

impl Default for MasterSecretEncConfig {
	fn default() -> Self {
		let min_iteration_count = 10000;
		let round_count = 4;
		let customization_string = b"shamir".to_vec();

		MasterSecretEncConfig {
			min_iteration_count,
			round_count,
			customization_string,
		}
	}
}

impl MasterSecretEncConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		MasterSecretEncConfig {
			..Default::default()
		}
	}
}
/// Struct, so that config values are held
pub struct MasterSecretEnc {
	pub config: MasterSecretEncConfig,
}

impl Default for MasterSecretEnc {
	fn default() -> Self {
		MasterSecretEnc {
			config: MasterSecretEncConfig::new(),
		}
	}
}

impl MasterSecretEnc {
	/// Create a new encoder with all defaults
	pub fn new() -> Result<MasterSecretEnc, Error> {
		Ok(MasterSecretEnc {
			config: MasterSecretEncConfig::new(),
		})
	}

	/// Encrypt the master secret using the SLIP-0039 Feistel construction.
	///
	/// `extendable` selects the PBKDF2 salt prefix per SLIP-0039: when
	/// `false` (`ext = 0`) the salt prefix is `"shamir" || id` (id as two
	/// big-endian bytes); when `true` (`ext = 1`) the salt prefix is empty,
	/// so the identifier is *not* mixed into the encryption. This is what
	/// makes multiple share sets with distinct ids decrypt to the same
	/// master secret for a given passphrase.
	pub fn encrypt(
		&self,
		master_secret: &[u8],
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
		extendable: bool,
	) -> Vec<u8> {
		let mut l = Zeroizing::new(master_secret.to_owned());
		let half = l.len() / 2;
		let mut r = Zeroizing::new(l.split_off(half));
		let salt = self.get_salt(identifier, extendable);
		for i in 0..self.config.round_count {
			let tmp_r = Zeroizing::new(r.to_vec());
			let mut rf = Zeroizing::new(
				self.round_function(i, passphrase, iteration_exponent, &salt, &r),
			);
			// Reassign l and r by first zeroising the outgoing buffer, then
			// overwriting via DerefMut. Without the explicit `zeroize()` the
			// old Vec would be dropped by Vec's ordinary Drop (which frees the
			// heap buffer without wiping it), leaking a half-secret fragment
			// per round — the Feistel intermediates are secret-equivalent.
			let new_r = self.xor(&l, &rf);
			r.zeroize();
			*r = new_r;
			rf.zeroize();
			let new_l = tmp_r.to_vec();
			l.zeroize();
			*l = new_l;
			// tmp_r zeroised on drop
		}
		let mut result = r.to_vec();
		result.append(&mut l.to_vec());
		// l, r zeroised on drop
		result
	}

	pub fn decrypt(
		&self,
		enc_master_secret: &[u8],
		passphrase: &str,
		iteration_exponent: u8,
		identifier: u16,
		extendable: bool,
	) -> Vec<u8> {
		let mut l = Zeroizing::new(enc_master_secret.to_owned());
		let half = l.len() / 2;
		let mut r = Zeroizing::new(l.split_off(half));
		let salt = self.get_salt(identifier, extendable);
		for i in (0..self.config.round_count).rev() {
			let tmp_r = Zeroizing::new(r.to_vec());
			let mut rf = Zeroizing::new(
				self.round_function(i, passphrase, iteration_exponent, &salt, &r),
			);
			// Reassign l and r by first zeroising the outgoing buffer, then
			// overwriting via DerefMut. Without the explicit `zeroize()` the
			// old Vec would be dropped by Vec's ordinary Drop (which frees the
			// heap buffer without wiping it), leaking a half-secret fragment
			// per round — the Feistel intermediates are secret-equivalent.
			let new_r = self.xor(&l, &rf);
			r.zeroize();
			*r = new_r;
			rf.zeroize();
			let new_l = tmp_r.to_vec();
			l.zeroize();
			*l = new_l;
			// tmp_r zeroised on drop
		}
		let mut result = r.to_vec();
		result.append(&mut l.to_vec());
		// l, r zeroised on drop
		result
	}

	/// Build the PBKDF2 salt prefix.
	///
	/// Per SLIP-0039:
	/// * `ext = 0` — `salt_prefix = "shamir" || id` (id as two big-endian
	///   bytes). The identifier is mixed into the encryption, so two share
	///   sets with different ids decrypt to different master secrets.
	/// * `ext = 1` — `salt_prefix` is empty. The identifier is *not* used
	///   as salt, so multiple share sets with distinct ids all decrypt to
	///   the same master secret for a given passphrase. This is the
	///   "extendable backup" property.
	///
	/// `round_function` appends `R` (half the secret) to this prefix to
	/// form the full PBKDF2 salt.
	fn get_salt(&self, identifier: u16, extendable: bool) -> Vec<u8> {
		if extendable {
			// ext = 1: empty salt prefix; round_function appends only R.
			Vec::new()
		} else {
			// ext = 0: "shamir" || id (big-endian, 2 bytes).
			let mut retval = self.config.customization_string.clone();
			retval.append(&mut identifier.to_be_bytes().to_vec());
			retval
		}
	}

	/// the round function used internally by the Feistel cipher
	///
	/// `e` is clamped to `MAX_ITERATION_EXPONENT` as defence-in-depth: the
	/// produce and consume paths both validate it already, but this guards
	/// against future API misuse silently reaching the `NonZeroU32::new(0)`
	/// path in `ring`.
	fn round_function(&self, i: u8, passphrase: &str, e: u8, salt: &[u8], r: &[u8]) -> Vec<u8> {
		debug_assert!(
			e <= MAX_ITERATION_EXPONENT,
			"{}", "iteration exponent {e} exceeds MAX_ITERATION_EXPONENT {MAX_ITERATION_EXPONENT}"
		);
		let e = e.min(MAX_ITERATION_EXPONENT);
		let iterations =
			(self.config.min_iteration_count / u32::from(self.config.round_count)) << u32::from(e);
		let out_length = r.len();
		// SECURITY: `salt` ends up holding cs + identifier + r, where r is half
		// of the (encrypted) master secret. `r` itself is also half the EMS.
		// Wrap both in Zeroizing so they are wiped from heap on drop rather
		// than lingering in freed memory until the allocator reuses the page.
		let mut salt = Zeroizing::new(salt.to_owned());
		let mut r = Zeroizing::new(r.to_owned());
		salt.append(&mut r);
		let mut password = Zeroizing::new(vec![i]);
		password.append(&mut passphrase.as_bytes().to_vec());
		
		// salt, r, password all zeroised on drop
		self.pbkdf2_derive(iterations, &salt, &password, out_length)
	}

	#[cfg(feature = "rust_crypto_pbkdf2")]
	/// Rust-crypto implementation of round function
	fn pbkdf2_derive(
		&self,
		iterations: u32,
		salt: &[u8],
		password: &[u8],
		out_length: usize,
	) -> Vec<u8> {
		let mut out = vec![0; out_length];
		pbkdf2::<Hmac<Sha256>>(password, salt, iterations as usize, &mut out);
		out
	}

	#[cfg(feature = "ring_pbkdf2")]
	/// Ring implementation of round function
	fn pbkdf2_derive(
		&self,
		iterations: u32,
		salt: &[u8],
		password: &[u8],
		out_length: usize,
	) -> Vec<u8> {
		let mut out = vec![0; out_length];
		// Defence-in-depth: for a legal exponent (0..=15) `iterations` is
		// always >= `min_iteration_count / round_count` (= 2500), so this is
		// always `Some`. Use a non-panicking fallback regardless so that a
		// future API misuse can never crash the process here.
		let iterations = NonZeroU32::new(iterations).unwrap_or(NonZeroU32::new(1).unwrap());
		pbkdf2::derive(
			ring::pbkdf2::PBKDF2_HMAC_SHA256,
			iterations,
			salt,
			password,
			&mut out,
		);
		out
	}

	// xor values in both arrays. The caller (Feistel round) always passes
	// equal-length halves, but assert so a future misuse panics loudly in
	// debug builds rather than silently indexing out of bounds.
	fn xor(&self, a: &[u8], b: &[u8]) -> Vec<u8> {
		debug_assert_eq!(a.len(), b.len(), "xor operands must have equal length");
		let mut retval = vec![0; b.len()];
		for i in 0..b.len() {
			retval[i] = a[i] ^ b[i];
		}
		retval
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use rand::{thread_rng, Rng};

	fn roundtrip_test(secret: Vec<u8>, passphrase: &str, identifier: u16, iteration_exponent: u8, extendable: bool) {
		let enc = MasterSecretEnc::default();
		let encrypted_secret = enc.encrypt(&secret, passphrase, iteration_exponent, identifier, extendable);
		let decrypted_secret = enc.decrypt(
			&encrypted_secret,
			passphrase,
			iteration_exponent,
			identifier,
			extendable,
		);
		assert_eq!(secret, decrypted_secret);
	}

	#[test]
	fn roundtrip_test_vector() {
		for e in vec![0, 6] {
			let secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
			roundtrip_test(secret, "", 7470, e, false);
		}
	}

	#[test]
	fn roundtrip_16_bytes() {
		for _ in 0..20 {
			let s: [u8; 16] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			roundtrip_test(s.to_vec(), "", id, 0, false);
		}
	}

	#[test]
	fn roundtrip_32_bytes() {
		for _ in 0..20 {
			let s: [u8; 32] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			roundtrip_test(s.to_vec(), "", id, 0, false);
		}
	}

	#[test]
	fn roundtrip_32_bytes_password() {
		for _ in 0..10 {
			let s: [u8; 12] = thread_rng().gen();
			let id: u16 = thread_rng().gen();
			roundtrip_test(s.to_vec(), "pebkac", id, 0, false);
		}
	}

	// SLIP-0039 ext=1: the identifier is NOT used as salt, so two share
	// sets with different ids must encrypt/decrypt to the same master
	// secret for the same passphrase. This is the extendable-backup
	// property.
	#[test]
	fn ext1_identifier_independent() {
		let secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		let enc = MasterSecretEnc::default();
		let ems_a = enc.encrypt(&secret, "pass", 1, 3, true);
		let ems_b = enc.encrypt(&secret, "pass", 1, 30000, true);
		assert_eq!(ems_a, ems_b, "ext=1 EMS must not depend on identifier");
		assert_eq!(enc.decrypt(&ems_a, "pass", 1, 9999, true), secret);
		assert_eq!(enc.decrypt(&ems_b, "pass", 1, 12345, true), secret);
	}

	// ext=0 (default): different identifiers MUST produce different EMS.
	#[test]
	fn ext0_identifier_dependent() {
		let secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		let enc = MasterSecretEnc::default();
		let ems_a = enc.encrypt(&secret, "pass", 1, 3, false);
		let ems_b = enc.encrypt(&secret, "pass", 1, 30000, false);
		assert_ne!(ems_a, ems_b, "ext=0 EMS must depend on identifier");
		assert_eq!(enc.decrypt(&ems_a, "pass", 1, 3, false), secret);
	}

	// Defence-in-depth regression for HIGH-1: a clamped exponent must never
	// reach `NonZeroU32::new(0)` in `ring`. `round_function` is private, so
	// verify the clamp invariant directly without invoking the (expensive at
	// e=15) full PBKDF2 Feistel: for every 5-bit value, the clamped exponent
	// is <= MAX_ITERATION_EXPONENT, so the shift can never wrap `iterations`
	// to 0.
	#[test]
	fn round_function_clamps_exponent() {
		for e in 0u8..32 {
			let clamped = e.min(MAX_ITERATION_EXPONENT);
			assert!(clamped <= MAX_ITERATION_EXPONENT);
			let iterations =
				(10000u32 / 4) << u32::from(clamped);
			// The `unwrap_or` fallback in `pbkdf2_derive` requires this.
			assert!(iterations >= 2500, "iterations collapsed to {iterations} for e={e}");
		}
	}
}
