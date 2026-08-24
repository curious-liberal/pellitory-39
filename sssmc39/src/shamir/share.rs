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

//! Definition of a share, as well as functions to
//! convert it to and from a given wordlist

use crate::error::{Error, ErrorKind};
use crate::util::bitpacker::BitPacker;
use crate::util::rs1024;
use zeroize::{Zeroize, Zeroizing};

use rand::rngs::OsRng;
use rand::RngCore;
use std::collections::HashMap;

lazy_static! {
	/// List of ssmc words
	pub static ref WORDLIST: Vec<String> = include_str!("wordlists/en.txt").split_whitespace().map(|s| s.into()).collect();
	pub static ref WORD_INDEX_MAP: HashMap<String, usize> = {
		let mut retval = HashMap::new();
		for (i, item) in WORDLIST.iter().enumerate() {
			retval.insert(item.to_owned(), i);
		}
		retval
	};
}

/// Share-specific configuration values
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShareConfig {
	/// The length of the random Identifier in bits
	pub id_length_bits: u8,
	/// The number of words in the word list
	pub radix: u16,
	/// The length of the radix in bits
	pub radix_bits: u8,
	/// id exp length
	pub id_exp_length_words: u8,
	/// The base customization string used in the RS1024 checksum and in the
	/// PBKDF2 salt when `ext = 0` ("shamir"). When `ext = 1` the RS1024
	/// customization string is "shamir_extendable" and the PBKDF2 salt
	/// prefix is empty — see [`Share::extendable`].
	pub customization_string: Vec<u8>,
	/// The RS1024 customization string used for `ext = 1` shares
	/// ("shamir_extendable").
	pub customization_string_extendable: Vec<u8>,
	/// The length of the RS1024 checksum in words
	pub checksum_length_words: u8,
	/// The length of mnemonic is words without the share value
	pub metadata_length_words: u8,
	/// The minimum allowed length of the mnemonic in words
	pub min_mnemonic_length_words: u8,
	/// The length of the iteration exponent field in bits. This is the full
	/// 5-bit field: bit 4 is the `ext` flag, bits 0..=3 are the exponent.
	pub iteration_exp_length_bits: u8,
	/// The minimum allowed entropy of the master secret
	pub min_strength_bits: u16,
}

impl Default for ShareConfig {
	fn default() -> Self {
		let radix_bits = 10;
		let id_length_bits = 15;
		let iteration_exp_length_bits = 5;
		let checksum_length_words = 3;
		let customization_string = b"shamir".to_vec();
		let customization_string_extendable = b"shamir_extendable".to_vec();
		let min_strength_bits = 128;

		// derived values
		let radix = 2u16.pow(u32::from(radix_bits));
		let id_exp_length_words = (id_length_bits + iteration_exp_length_bits) / radix_bits;
		let metadata_length_words = id_exp_length_words + 2 + checksum_length_words;
		let min_mnemonic_length_words =
			metadata_length_words + (f64::from(min_strength_bits) / 10f64).ceil() as u8;

		ShareConfig {
			id_length_bits,
			radix,
			radix_bits,
			id_exp_length_words,
			customization_string,
			customization_string_extendable,
			checksum_length_words,
			metadata_length_words,
			min_mnemonic_length_words,
			iteration_exp_length_bits,
			min_strength_bits,
		}
	}
}

impl ShareConfig {
	/// Just use defaults for now
	pub fn new() -> Self {
		ShareConfig {
			..Default::default()
		}
	}
}

/// Main definition of a share and its mnemonic serialization
#[derive(Clone, PartialEq, Eq)]
pub struct Share {
	/// Random 15 bit value which is the same for all shares and is used to verify
	/// that the shares belong together; it is also used as salt in the encryption
	/// of the master secret when `extendable` is false. (15 bits)
	pub identifier: u16,
	/// The extendable-backup flag (`ext`). When `false` (the default, `ext = 0`)
	/// the identifier is used as PBKDF2 salt and the RS1024 customization string
	/// is "shamir". When `true` (`ext = 1`) the identifier is *not* used as salt
	/// (so multiple share sets with distinct ids all recover the same master
	/// secret for a given passphrase) and the RS1024 customization string is
	/// "shamir_extendable".
	pub extendable: bool,
	/// Indicates the total number of iterations to be used in PBKDF2. The number of
	/// iterations is calculated as 10000x2^e. This is the 4-bit exponent (0..=15);
	/// the 5-bit wire field packs `ext` in its top bit. (4 bits)
	pub iteration_exponent: u8,
	/// The x value of the group share (4 bits)
	pub group_index: u8,
	/// indicates how many group shares are needed to reconstruct the master secret.
	/// The actual value is endoded as Gt = GT - 1, so a value of 0 indicates that a
	/// single group share is needed (GT = 1), a value of 1 indicates that two group shares
	/// are needed (GT = 2) etc. (4 bits)
	pub group_threshold: u8,
	/// indicates the total number of groups. The actual value is encoded as g = G - 1
	/// (4 bits)
	pub group_count: u8,
	/// Member index, or x value of the member share in the given group (4 bits)
	pub member_index: u8,
	/// indicates how many member shares are needed to reconstruct the group share. The actual value
	/// is encoded as t = T − 1. (4 bits)
	pub member_threshold: u8,
	/// corresponds to a list of the SSS part's fk(x) values 1 ≤ k ≤ n. Each fk(x) value is encoded
	/// as a string of eight bits in big-endian order. The concatenation of these bit strings is
	/// the share value. This value is left-padded with "0" bits so that the length of the padded
	/// share value in bits becomes the nearest multiple of 10. (padding + 8n bits)
	pub share_value: Vec<u8>,
	/// an RS1024 checksum of the data part of the share
	/// (that is id || e || GI || Gt || g || I || t || ps). The customization string (cs) of
	/// RS1024 is "shamir". (30 bits)
	pub checksum: u32,
	/// configuration values
	pub config: ShareConfig,
}

impl Default for Share {
	fn default() -> Self {
		Share {
			identifier: 0,
			extendable: false,
			iteration_exponent: 0,
			group_index: 0,
			group_threshold: 0,
			group_count: 0,
			member_index: 0,
			member_threshold: 0,
			share_value: vec![],
			checksum: 0,
			config: ShareConfig::new(),
		}
	}
}

impl Drop for Share {
	fn drop(&mut self) {
		// Zeroize the share value — this holds secret material
		// (either the encrypted or decrypted master secret fragments).
		self.share_value.zeroize();
	}
}

impl std::fmt::Debug for Share {
	// SECURITY: share_value is the encrypted Shamir fragment and is
	// secret-equivalent above the threshold. Redact it from Debug output
	// so a stray {:?} in a log statement or error path cannot leak it.
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.debug_struct("Share")
			.field("identifier", &self.identifier)
			.field("extendable", &self.extendable)
			.field("iteration_exponent", &self.iteration_exponent)
			.field("group_index", &self.group_index)
			.field("group_threshold", &self.group_threshold)
			.field("group_count", &self.group_count)
			.field("member_index", &self.member_index)
			.field("member_threshold", &self.member_threshold)
			.field("share_value", &"[REDACTED]")
			.field("checksum", &self.checksum)
			.finish()
	}
}

impl Share {
	/// Create a new share with defaults and a cryptographically random
	/// 15-bit identifier drawn from `OsRng`.
	pub fn new() -> Result<Share, Error> {
		let mut s = Share::default();
		s.identifier = s.generate_random_identifier();
		Self::validate_wordlist(&s)?;
		Ok(s)
	}

	/// Create a new share with a zeroed identifier and no `OsRng` draw.
	///
	/// This is the decode-path counterpart to [`Share::new`]: `from_mnemonic`
	/// and `from_u8_vec` overwrite every field (including the identifier) from
	/// the parsed input, so drawing a fresh random identifier there was
	/// wasteful (two `OsRng` syscalls per decoded share) with no effect
	/// (SECURITY_REVIEW.md LOW-2). Use [`Share::new`] when a fresh random
	/// identifier is actually wanted (the split/generate paths).
	fn empty() -> Result<Share, Error> {
		let s = Share::default();
		Self::validate_wordlist(&s)?;
		Ok(s)
	}

	/// Create a new share using a caller-supplied identifier instead of a
	/// random one.
	///
	/// This exists to support **plausible-deniability / duress setups**:
	/// a Decoy Wallet can be generated with the same identifier (and the
	/// same iteration exponent) as a Real Wallet so that the first two
	/// mnemonic words — which encode `identifier || iteration_exponent` —
	/// are byte-for-byte identical across both wallets. An attacker then
	/// cannot distinguish Real shares from Decoy shares by inspecting the
	/// metadata prefix.
	///
	/// `identifier` must fit in the configured 15-bit identifier field
	/// (i.e. 0..=32767); otherwise an `Error` is returned.
	pub fn new_with_identifier(identifier: u16) -> Result<Share, Error> {
		let mut s = Share::default();
		let max_id = (1u32 << s.config.id_length_bits) - 1;
		if identifier as u32 > max_id {
			return Err(ErrorKind::Argument(format!(
				"identifier {} does not fit in {} bits (max {})",
				identifier, s.config.id_length_bits, max_id,
			)))?;
		}
		s.identifier = identifier;
		Self::validate_wordlist(&s)?;
		Ok(s)
	}

	/// Verify the wordlist length matches the configured radix.
	fn validate_wordlist(s: &Share) -> Result<(), Error> {
		if WORDLIST.len() != s.config.radix as usize {
			return Err(ErrorKind::Config(format!(
				"The wordlist should contain {} words, but it contains {} words.",
				s.config.radix,
				WORDLIST.len()
			)))?;
		}
		Ok(())
	}

	/// The RS1024 customization string for this share, selected by
	/// [`extendable`](Share::extendable): "shamir" for `ext = 0` (the
	/// default) and "shamir_extendable" for `ext = 1`.
	fn rs_customization_string(&self) -> &[u8] {
		if self.extendable {
			&self.config.customization_string_extendable
		} else {
			&self.config.customization_string
		}
	}

	/// convenience to create new from Mnemonic
	pub fn from_mnemonic(mn: &[String]) -> Result<Self, Error> {
		let mut s = Self::empty()?;
		s.fill_with_mnemonic(mn)?;
		Ok(s)
	}

	/// Convert from a u8 vec
	pub fn from_u8_vec(input: &[u8]) -> Result<Self, Error> {
		let mut s = Self::empty()?;
		let mut bp = BitPacker::new();
		bp.append_vec_u8(input)?;
		bp.normalize(s.config.radix_bits as usize);
		s.parse_bp(&mut bp)?;
		Ok(s)
	}

	// create the packed bit array
	fn pack_bits(&self) -> Result<BitPacker, Error> {
		let mut padding_bit_count = self.config.radix_bits
			- (self.share_value.len() * 8 % self.config.radix_bits as usize) as u8;
		if padding_bit_count == 10 {
			padding_bit_count = 0;
		}
		let mut bp = BitPacker::new();

		bp.append_u16(self.identifier, self.config.id_length_bits)?;
		// The 5-bit field packs the `ext` flag in bit 4 and the 4-bit
		// iteration exponent in bits 0..=3.
		let exp_field = (if self.extendable { 1u8 << 4 } else { 0 }) | (self.iteration_exponent & 0x0F);
		bp.append_u8(exp_field, self.config.iteration_exp_length_bits)?;
		bp.append_u8(self.group_index, 4)?;
		bp.append_u8(self.group_threshold - 1, 4)?;
		bp.append_u8(self.group_count - 1, 4)?;
		bp.append_u8(self.member_index, 4)?;
		bp.append_u8(self.member_threshold - 1, 4)?;
		bp.append_padding(padding_bit_count);
		bp.append_vec_u8(&self.share_value)?;

		if !bp.len().is_multiple_of(self.config.radix_bits as usize) {
			return Err(ErrorKind::Mnemonic(format!(
				"Incorrect share bit length. Must be a multiple of {}, actual length: {}",
				self.config.radix_bits,
				bp.len(),
			)))?;
		}

		// Create checksum
		let mut sum_data: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			sum_data.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		let checksum = rs1024::create_checksum(
			self.rs_customization_string(),
			&sum_data,
			self.config.checksum_length_words,
		);

		for c in checksum {
			bp.append_u32(c, self.config.radix_bits)?;
		}

		Ok(bp)
	}

	/// Convert share data to a share mnemonic.
	///
	/// SECURITY: each returned `String` holds share words that are
	/// secret-equivalent above the threshold. They are wrapped in
	/// [`Zeroizing`] so they are wiped from memory on drop rather than
	/// being freed un-wiped by ordinary `String::Drop` (which only frees
	/// the heap buffer without overwriting it). Callers that join the
	/// words into a single `String` are responsible for zeroising the
	/// result.
	pub fn to_mnemonic(&self) -> Result<Vec<Zeroizing<String>>, Error> {
		let bp = self.pack_bits()?;

		// Read bits as u32 vec
		let mut ret_vec: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			ret_vec.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		Ok(ret_vec
			.iter()
			.map(|d| Zeroizing::new(WORDLIST[*d as usize].to_owned()))
			.collect())
	}

	// Convert share data to a share mnemonic (flattened string)
	/*pub fn to_mnemonic_flat(&self) -> Result<String, Error> {
		self.to_mnemonic()?.iter().fold(String::new(), |mut acc, s| {
			acc.push_str(s);
			acc.push_str(" ");
			acc
		})
	}*/

	/// Convert share data to u8 vec
	pub fn to_u8_vec(&self) -> Result<Vec<u8>, Error> {
		let bp = self.pack_bits()?;

		// Read bits as u8 vec
		let mut ret_vec: Vec<u8> = vec![];
		for i in (0..bp.len()).step_by(8) {
			ret_vec.push(bp.get_u8(i, 8)?);
		}
		Ok(ret_vec)
	}

	/// convert mnemonic back to share
	fn fill_with_mnemonic(&mut self, mn: &[String]) -> Result<(), Error> {
		if mn.len() < self.config.min_mnemonic_length_words as usize {
			return Err(ErrorKind::Mnemonic(format!(
				"Invalid mnemonic length. The length of each mnemonic must be at least {} words.",
				self.config.min_mnemonic_length_words,
			)))?;
		}
		let mut bp = BitPacker::new();
		for s in mn {
			if !WORD_INDEX_MAP.contains_key(s) {
				return Err(ErrorKind::Mnemonic(format!(
					"Invalid mnemonic. '{}' is not an SSSMC39 word.",
					s,
				)))?;
			}
			bp.append_u16(WORD_INDEX_MAP[s] as u16, self.config.radix_bits)?;
		}
		self.parse_bp(&mut bp)
	}

	fn parse_bp(&mut self, bp: &mut BitPacker) -> Result<(), Error> {
		let mut sum_data: Vec<u32> = vec![];
		for i in (0..bp.len()).step_by(self.config.radix_bits as usize) {
			sum_data.push(bp.get_u32(i, self.config.radix_bits as usize)?);
		}

		if (self.config.radix_bits as usize
			* (sum_data.len() - self.config.metadata_length_words as usize))
			% 16 > 8
		{
			return Err(ErrorKind::Mnemonic("Invalid mnemonic length.".to_string()))?;
		}

		// Peek the `ext` flag (top bit of the 5-bit iteration-exponent
		// field) before verifying the checksum, because the RS1024
		// customization string depends on it: "shamir" for ext=0 and
		// "shamir_extendable" for ext=1. Verifying with the wrong string
		// would reject every ext=1 share.
		let exp_field = bp.get_u8(
			self.config.id_length_bits as usize,
			self.config.iteration_exp_length_bits as usize,
		)?;
		let extendable = (exp_field >> 4) & 1 == 1;
		let cs: &[u8] = if extendable {
			&self.config.customization_string_extendable
		} else {
			&self.config.customization_string
		};
		rs1024::verify_checksum(cs, &sum_data)?;

		//TODO: iterator on bitpacker
		self.identifier = bp.get_u16(0, self.config.id_length_bits as usize)?;
		self.extendable = extendable;
		// The exponent is the low 4 bits of the field (0..=15). The top
		// bit is the `ext` flag, handled above. Masking guarantees e is
		// always in range, so the PBKDF2 iteration count can never wrap to
		// zero (defence-in-depth against HIGH-1; `round_function` clamps
		// again).
		self.iteration_exponent = exp_field & 0x0F;
		self.group_index = bp.get_u8(
			(self.config.id_length_bits + self.config.iteration_exp_length_bits) as usize,
			4,
		)?;
		self.group_threshold = bp.get_u8(24, 4)? + 1;
		self.group_count = bp.get_u8(28, 4)? + 1;
		self.member_index = bp.get_u8(32, 4)?;
		self.member_threshold = bp.get_u8(36, 4)? + 1;

		if self.group_count < self.group_threshold {
			return Err(ErrorKind::Mnemonic(
				"Invalid mnemonic. Group threshold cannot be greater than group count.".to_string(),
			))?;
		}

		// remove padding and recover data
		bp.split_out(
			40,
			bp.len() - self.config.radix_bits as usize * self.config.checksum_length_words as usize,
		);

		bp.remove_padding(bp.len() % 16)?;

		self.share_value = bp.get_vec_u8(0, bp.len() / 8)?;

		Ok(())
	}

	fn generate_random_identifier(&self) -> u16 {
		// SECURITY: the identifier is used as the PBKDF2 salt for SLIP-0039.
		// Draw from the OS CSPRNG directly rather than thread_rng().
		let mut buf = [0u8; 2];
		OsRng.fill_bytes(&mut buf);
		let retval: u16 = u16::from_be_bytes(buf);
		retval & ((1 << self.config.id_length_bits) - 1)
	}
}

#[cfg(test)]
mod tests {
	use super::*;

	use crate::error::Error;

	#[test]
	fn share_to_mnemonic() -> Result<(), Error> {
		// Test vectors taken from python reference implementation
		let expected_res: Vec<String> = vec![
			"phantom".into(),
			"branch".into(),
			"academic".into(),
			"axle".into(),
			"ceramic".into(),
			"alien".into(),
			"domain".into(),
			"alive".into(),
			"deadline".into(),
			"gray".into(),
			"walnut".into(),
			"spend".into(),
			"echo".into(),
			"amount".into(),
			"squeeze".into(),
			"woman".into(),
			"squeeze".into(),
			"welfare".into(),
			"filter".into(),
			"frequent".into(),
		];
		let share = Share {
			identifier: 21219,
			extendable: false,
			iteration_exponent: 0,
			group_index: 0,
			group_threshold: 1,
			group_count: 1,
			member_index: 4,
			member_threshold: 3,
			share_value: b"\x84\x06\xce\xa0p\xbfe~\rA\x01\t5\xaf\xd3Z".to_vec(),
			config: ShareConfig::new(),
			checksum: 0,
		};
		println!("orig share: {:?}", share);
		let m = share.to_mnemonic()?;
		let m: Vec<String> = m.into_iter().map(|z| z.as_str().to_owned()).collect();
		println!("m: {:?}", m);
		assert_eq!(expected_res, m);

		let dec_share = Share::from_mnemonic(&m)?;
		println!("decoded share: {:?}", dec_share);
		assert_eq!(share, dec_share);
		Ok(())
	}
}
