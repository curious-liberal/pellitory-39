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

//! Functions and structs that specifically define the SLIPS-0039 scheme

use super::{Share, Splitter};
use crate::error::{Error, ErrorKind};
use zeroize::{Zeroize, Zeroizing};

use std::collections::BTreeMap;
use std::fmt;

use crate::util;

/// Struct for returned shares
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct GroupShare {
	/// Group id
	pub group_id: u16,
	/// iteration exponent
	pub iteration_exponent: u8,
	/// extendable-backup flag (`ext`)
	pub extendable: bool,
	/// group index
	pub group_index: u8,
	/// group threshold
	pub group_threshold: u8,
	/// number of group shares
	pub group_count: u8,
	/// member threshold:
	pub member_threshold: u8,
	/// Member shares for the group
	pub member_shares: Vec<Share>,
}

impl fmt::Display for GroupShare {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		writeln!(
			f,
			"Group {} of {} - {} of {} shares required: ",
			self.group_index + 1,
			self.group_count,
			self.member_threshold,
			self.member_shares.len()
		)?;
		for s in &self.member_shares {
			// SECURITY (SECURITY_REVIEW.md LOW-1): `to_mnemonic()` can fail on a
			// malformed share. This impl is not used by the CLI (which serialises
			// via ShareFormatter/JSON), so propagate the error as a Display error
			// rather than `.unwrap()`-ing and panicking on untrusted input.
			let words = s.to_mnemonic().map_err(|_| fmt::Error)?;
			for w in &words {
				write!(f, "{} ", w.as_str())?;
			}
			writeln!(f)?;
		}
		Ok(())
	}
}

impl GroupShare {
	/// return list of mnemonics
	pub fn mnemonic_list(&self) -> Result<Vec<Vec<Zeroizing<String>>>, Error> {
		let mut ret_vec = vec![];
		for s in &self.member_shares {
			ret_vec.push(s.to_mnemonic()?);
		}
		Ok(ret_vec)
	}

	/// return list of mnemonics as space separated strings
	pub fn mnemonic_list_flat(&self) -> Result<Vec<Zeroizing<String>>, Error> {
		let mut ret_vec = vec![];
		for s in &self.member_shares {
			let joined = s.to_mnemonic()?.iter().fold(String::new(), |mut acc, s| {
				acc.push_str(s.as_str());
				acc.push(' ');
				acc
			});
			ret_vec.push(Zeroizing::new(joined));
		}
		Ok(ret_vec)
	}

	/// decode member shares to single share
	pub fn decode_shares(&mut self) -> Result<Share, Error> {
		let sp = Splitter::new(None);
		sp.recover_secret(&self.member_shares, self.member_threshold)
	}
}

/// Split a master secret into mnemonic shares
/// group_threshold: The number of groups required to reconstruct the master secret
/// groups: A list of (member_threshold, member_count) pairs for each group, where member_count
/// is the number of shares to generate for the group and member_threshold is the number of
/// members required to reconstruct the group secret.
/// master_secret: The master secret to split.
/// passphrase: The passphrase used to encrypt the master secret.
/// iteration_exponent: The iteration exponent.
/// extendable: The extendable-backup flag (`ext`). When `false` (the default,
///   `ext = 0`) the identifier is mixed into the PBKDF2 salt. When `true`
///   (`ext = 1`) the identifier is not used as salt, so multiple share sets
///   with distinct ids all recover the same master secret for a given
///   passphrase — the SLIP-0039 "extendable backup" property.
/// identifier: Optional fixed 15-bit identifier. When `Some`, the
///   supplied value is used instead of a fresh random one. This is
///   intended for plausible-deniability / duress setups, where a Decoy
///   Wallet must share the same metadata prefix (first two mnemonic
///   words) as a Real Wallet. When `None`, a random identifier is drawn
///   from `OsRng` as normal.
/// return: List of mnemonics.
pub fn generate_mnemonics(
	group_threshold: u8,
	groups: &[(u8, u8)],
	master_secret: &[u8],
	passphrase: &str,
	iteration_exponent: u8,
	extendable: bool,
	identifier: Option<u16>,
) -> Result<Vec<GroupShare>, Error> {
	// Generate a 'proto share' so to speak, with identifer generated and group data filled
	let mut proto_share = match identifier {
		Some(id) => Share::new_with_identifier(id)?,
		None => Share::new()?,
	};
	proto_share.group_threshold = group_threshold;
	proto_share.group_count = groups.len() as u8;
	proto_share.iteration_exponent = iteration_exponent;
	proto_share.extendable = extendable;

	if master_secret.len() * 8 < proto_share.config.min_strength_bits as usize {
		Err(ErrorKind::Value(format!(
			"The length of the master secret ({} bytes) must be at least {} bytes.",
			master_secret.len(),
			(f64::from(proto_share.config.min_strength_bits) / 8f64).ceil(),
		)))?;
	}

	if !master_secret.len().is_multiple_of(2) {
		Err(ErrorKind::Value(
			"The length of the master secret in bytes must be an even number".to_string(),
		))?;
	}

	if group_threshold as usize > groups.len() {
		Err(ErrorKind::Value(format!(
			"The requested group threshold ({}) must not exceed the number of groups ({}).",
			group_threshold,
			groups.len()
		)))?;
	}

	let encoder = util::encrypt::MasterSecretEnc::new()?;

	let mut encrypted_master_secret = Zeroizing::new(encoder.encrypt(
		master_secret,
		passphrase,
		iteration_exponent,
		proto_share.identifier,
		extendable,
	));

	let sp = Splitter::new(None);

	let group_shares = sp.split_secret(
		&proto_share,
		group_threshold,
		groups.len() as u8,
		&encrypted_master_secret,
	)?;

	// Wipe the encrypted master secret now that it's been split.
	encrypted_master_secret.zeroize();

	let mut retval: Vec<GroupShare> = vec![];

	let gs_len = group_shares.len();
	for (i, elem) in group_shares.into_iter().enumerate() {
		proto_share.group_index = i as u8;
		proto_share.group_threshold = group_threshold;
		proto_share.group_count = gs_len as u8;
		let (member_threshold, member_count) = groups[i];
		let member_shares = sp.split_secret(
			&proto_share,
			member_threshold,
			member_count,
			&elem.share_value,
		)?;
		retval.push(GroupShare {
			group_id: proto_share.identifier,
			iteration_exponent,
			extendable,
			group_index: i as u8,
			group_threshold,
			group_count: gs_len as u8,
			member_threshold,
			member_shares,
		});
	}

	Ok(retval)
}

pub fn generate_mnemonics_random(
	group_threshold: u8,
	groups: &[(u8, u8)],
	strength_bits: u16,
	passphrase: &str,
	iteration_exponent: u8,
	extendable: bool,
	identifier: Option<u16>,
) -> Result<Vec<GroupShare>, Error> {
	let proto_share = match identifier {
		Some(id) => Share::new_with_identifier(id)?,
		None => Share::new()?,
	};
	if strength_bits < proto_share.config.min_strength_bits {
		Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be at least {} bits.",
			strength_bits, proto_share.config.min_strength_bits,
		)))?;
	}
	if !strength_bits.is_multiple_of(16) {
		Err(ErrorKind::Value(format!(
			"The requested strength of the master secret({} bits) must be a multiple of 16 bits.",
			strength_bits,
		)))?;
	}
	let mut random_secret = Zeroizing::new(util::fill_vec_rand(strength_bits as usize / 8));
	let result = generate_mnemonics(
		group_threshold,
		groups,
		&random_secret,
		passphrase,
		iteration_exponent,
		extendable,
		identifier,
	);
	random_secret.zeroize();
	result
}

/// Combines mnemonic shares to obtain the master secret which was previously split using
/// Shamir's secret sharing scheme.
/// mnemonics: List of mnemonics.
/// passphrase: The passphrase used to encrypt the master secret.
/// return: The master secret.
pub fn combine_mnemonics(mnemonics: &[Vec<String>], passphrase: &str) -> Result<Vec<u8>, Error> {
	let group_shares = decode_mnemonics(mnemonics)?;
	let mut shares = vec![];
	for mut gs in group_shares {
		shares.push(gs.decode_shares()?);
	}
	let sp = Splitter::new(None);
	// restore proper member index for groups
	let shares = shares
		.into_iter()
		.map(|mut s| {
			s.member_index = s.group_index;
			s
		})
		.collect::<Vec<_>>();
	let ems = sp.recover_secret(&shares, shares[0].group_threshold)?;
	let encoder = util::encrypt::MasterSecretEnc::new()?;
	let dms = encoder.decrypt(
		&ems.share_value,
		passphrase,
		ems.iteration_exponent,
		ems.identifier,
		ems.extendable,
	);
	Ok(dms)
}

/// Decodes all Mnemonics to a list of shares and performs error checking
fn decode_mnemonics(mnemonics: &[Vec<String>]) -> Result<Vec<GroupShare>, Error> {
	let mut shares = vec![];
	if mnemonics.is_empty() {
		Err(ErrorKind::Mnemonic(
			"List of mnemonics is empty.".to_string(),
		))?;
	}
	let check_len = mnemonics[0].len();
	for m in mnemonics {
		if m.len() != check_len {
			Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same length.".to_string(),
			))?;
		}
		shares.push(Share::from_mnemonic(m)?);
	}

	let check_share = shares[0].clone();
	for s in shares.iter() {
		if s.identifier != check_share.identifier
			|| s.iteration_exponent != check_share.iteration_exponent
			|| s.extendable != check_share.extendable
		{
			Err(ErrorKind::Mnemonic(format!(
				"Invalid set of mnemonics. All mnemonics must begin with the same {} words. \
				 (Identifier and iteration exponent must be the same).",
				s.config.id_exp_length_words,
			)))?;
		}
		if s.group_threshold != check_share.group_threshold {
			Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same group threshold"
					.to_string(),
			))?;
		}
		if s.group_count != check_share.group_count {
			Err(ErrorKind::Mnemonic(
				"Invalid set of mnemonics. All mnemonics must have the same group count"
					.to_string(),
			))?;
		}
	}

	let mut group_index_map = BTreeMap::new();

	for s in shares {
		if !group_index_map.contains_key(&s.group_index) {
			let group_share = GroupShare {
				group_id: s.identifier,
				group_index: s.group_index,
				group_threshold: s.group_threshold,
				iteration_exponent: s.iteration_exponent,
				extendable: s.extendable,
				group_count: s.group_count,
				member_shares: vec![s.clone()],
				member_threshold: s.member_threshold,
			};
			group_index_map.insert(group_share.group_index, group_share);
		} else {
			let e = group_index_map.get_mut(&s.group_index).unwrap();
			e.member_shares.push(s);
		}
	}

	if group_index_map.len() < check_share.group_threshold as usize {
		Err(ErrorKind::Mnemonic(format!(
			"Insufficient number of mnemonic groups ({}). The required number \
			 of groups is {}.",
			group_index_map.len(),
			check_share.group_threshold,
		)))?;
	}

	let groups: Vec<GroupShare> = group_index_map
		.into_iter()
		.map(|g| g.1)
		// remove groups where number of shares is below the member threshold
		.filter(|g| g.member_shares.len() >= g.member_threshold as usize)
		.collect();

	if groups.len() < check_share.group_threshold as usize {
		Err(ErrorKind::Mnemonic(
			"Insufficient number of groups with member counts that meet member threshold."
				.to_string(),
		))?;
	}

	// TODO: Should probably return info making problem mnemonics easier to identify
	for g in groups.iter() {
		if g.member_shares.len() < g.member_threshold as usize {
			Err(ErrorKind::Mnemonic(format!(
				"Insufficient number of mnemonics (Group {}). At least {} mnemonics \
				 are required.",
				g.group_index, g.member_threshold,
			)))?;
		}
		let test_share = g.member_shares[0].clone();
		for ms in g.member_shares.iter() {
			if test_share.member_threshold != ms.member_threshold {
				Err(ErrorKind::Mnemonic(
					"Mismatching member thresholds".to_string(),
				))?;
			}
		}
	}

	// SECURITY/robustness: reject duplicate member indices within a group.
	// For threshold > 1 the digest check in recover_secret catches the
	// resulting wrong secret, but for threshold == 1 the digest check is
	// skipped, and a duplicated share would otherwise yield a silently
	// wrong (but plausible-looking) recovered secret with no error.
	for g in groups.iter() {
		let mut seen = std::collections::HashSet::new();
		for ms in &g.member_shares {
			if !seen.insert(ms.member_index) {
				Err(ErrorKind::Mnemonic(format!(
					"Duplicate share with member index {} in group {}. \
					Each share must be unique.",
					ms.member_index, g.group_index,
				)))?;
			}
		}
	}

	Ok(groups)
}

#[cfg(test)]
mod tests {
	use super::*;

	fn flatten_mnemonics(nms: &[GroupShare]) -> Result<Vec<Vec<String>>, Error> {
		let mut ret = vec![];
		for m in nms {
			for s in m.member_shares.iter() {
				// to_mnemonic returns Vec<Zeroizing<String>>; unwrap to plain
				// Strings for the combine_mnemonics API (test fixtures).
				ret.push(
					s.to_mnemonic()?
						.into_iter()
						.map(|z| z.as_str().to_owned())
						.collect(),
				);
			}
		}
		Ok(ret)
	}

	#[test]
	fn generate_mnemonics_test() -> Result<(), Error> {
		let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();

		// single 3 of 5 test, splat out all mnemonics
		println!("Single 3 of 5 Encoded: {:?}", master_secret);
		let mns = generate_mnemonics(1, &[(3, 5)], &master_secret, "", 0, false, None)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		// Test a few distinct groups
		let mns = generate_mnemonics(
			2,
			&[(3, 5), (2, 5), (3, 3), (13, 16)],
			&master_secret,
			"",
			0,
			false,
			None,
		)?;
		for s in &mns {
			println!("{}", s);
		}
		let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
		println!("Single 3 of 5 Decoded: {:?}", result);
		assert_eq!(result, master_secret);

		// work through some varying sized secrets
		let mut master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		for _ in 0..32 {
			master_secret.push(0);
			master_secret.push(1);

			println!("Single 3 of 5 Encoded: {:?}", master_secret);
			println!("master secret length: {}", master_secret.len());
			let mns = generate_mnemonics(1, &[(3, 5)], &master_secret, "", 0, false, None)?;
			for s in &mns {
				println!("{}", s);
			}
			let result = combine_mnemonics(&flatten_mnemonics(&mns)?, "")?;
			println!("Single 3 of 5 Decoded: {:?}", result);
			assert_eq!(result, master_secret);
		}

		// Test case for particular case which failed with different threshold lenghts
		// TODO: Fold this in to other tests
		let one = "slavery flea acrobat eclipse cultural emission yield invasion seafood says insect square bucket orbit leaves closet heat ugly database decorate";
		let two = "slavery flea acrobat emerald aviation escape year axle method forget rebound burden museum game suitable brave texture deploy together flash";
		let three = "slavery flea acrobat envelope best ceiling dragon threaten isolate headset decrease organize crunch fiction sniff carbon museum username glasses plunge";
		let four = "slavery flea beard echo cradle rebound penalty minister literary object have hazard elephant meaning enemy empty result capture peanut believe";
		let five = "slavery flea beard email blind lips evaluate repair decent rich mortgage swimming branch decision unkind ultimate military sugar prepare airport";
		let mut input = vec![];
		input.push(one.split(' ').map(|s| s.to_owned()).collect());
		input.push(two.split(' ').map(|s| s.to_owned()).collect());
		input.push(three.split(' ').map(|s| s.to_owned()).collect());
		input.push(four.split(' ').map(|s| s.to_owned()).collect());
		input.push(five.split(' ').map(|s| s.to_owned()).collect());
		let _result = combine_mnemonics(&input, "TREZOR")?;

		Ok(())
	}

	// For temporary use as we have no command-line at present
	#[test]
	fn split_master_secret() -> Result<(), Error> {
		let master_secret = b"fdd99010e03f3141662adb33644d5fd2bea0238fa805a2d21e396a22b926558c";
		let mns = generate_mnemonics(1, &[(3, 5)], &master_secret.to_vec(), "", 0, false, None)?;
		for s in &mns {
			println!("{}", s);
		}
		let one = "ending senior academic acne acne lizard armed wrist fancy center blimp broken branch ceiling type bishop senior window mother dominant humidity kidney flip leader cover pupal swimming quarter findings picture much impulse answer threaten bishop express brother sharp unwrap bulge leaves guest ladybug imply thumb dress brave orbit orbit garbage vexed brave deploy tofu regular unusual hunting carbon year";
		let two = "ending senior academic agree acid grill magazine trip impact diagnose headset year puny adorn swimming knife aquatic airline prayer hairy unfold forbid diminish sweater brave column holy spit superior replace script oasis firefly scared goat divorce oral laundry violence merit golden founder unusual taste preach ruin lying bumpy single glasses fitness argue daisy secret loud squeeze theater husky already";
		let three = "ending senior academic amazing academic carbon sheriff march ordinary advocate climate quarter explain view glasses distance scandal modify maiden welcome include webcam snapshot lilac finance faint facility quantity daughter trash formal failure execute grasp necklace trust bishop privacy library infant slim envy parcel boring mixture deploy dough deny patrol evening brave idea blessing slush lizard woman teaspoon news exclude";
		let four = "ending senior academic arcade acquire work exceed network revenue blanket force fiber ting standard fatigue extend acid holiday raspy pink vegan survive river step golden scandal tendency spray parcel vintage amuse remove best else unknown overall mild breathe nuclear wrist criminal jury deal rescue symbolic slow predator railroad verify involve require graduate ambition unknown repair scandal hobo voice railroad";
		let five = "ending senior academic axle acquire golden velvet depart swing endorse champion estate slush alien burning painting obesity surprise punish gasoline elephant educate declare rebuild plains making unkind carve exotic unfold counter cowboy extra fantasy cleanup pickup increase type deliver together fumes nylon acrobat fatigue listen elder toxic losing paper image aide satisfy award axis evoke capital academic violence canyon";
		let mut input = vec![];
		input.push(one.split(' ').map(|s| s.to_owned()).collect());
		input.push(two.split(' ').map(|s| s.to_owned()).collect());
		input.push(three.split(' ').map(|s| s.to_owned()).collect());
		input.push(four.split(' ').map(|s| s.to_owned()).collect());
		input.push(five.split(' ').map(|s| s.to_owned()).collect());
		let result = combine_mnemonics(&input, "")?;
		println!("Result: {}", String::from_utf8(result).unwrap());
		Ok(())
	}

	#[test]
	fn diagnose_iteration_exponent_bug() -> Result<(), Error> {
		let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();
		let passphrase = "test";

		// Step 1: verify encrypt/decrypt round-trip at e=1
		let encoder = crate::util::encrypt::MasterSecretEnc::new()?;
		let proto = Share::new()?;
		let encrypted = encoder.encrypt(&master_secret, passphrase, 1, proto.identifier, false);
		let decrypted = encoder.decrypt(&encrypted, passphrase, 1, proto.identifier, false);
		assert_eq!(decrypted, master_secret, "STEP 1 FAILED: encrypt/decrypt broken at e=1");
		println!("Step 1 PASSED: encrypt/decrypt roundtrip OK at e=1");

		// Step 2: generate shares with e=1
		let mns = generate_mnemonics(1, &[(2, 3)], &master_secret, passphrase, 1, false, None)?;
		let flat = flatten_mnemonics(&mns)?;
		println!("Step 2: generated {} shares with e=1", flat.len());

		// Step 2b: check fields on the ORIGINAL share object (before mnemonic encoding)
		let original_share = &mns[0].member_shares[0];
		println!(
			"Step 2b: ORIGINAL share: e={}, id={}, group_idx={}, group_thr={}, group_cnt={}, mem_idx={}, mem_thr={}",
			original_share.iteration_exponent,
			original_share.identifier,
			original_share.group_index,
			original_share.group_threshold,
			original_share.group_count,
			original_share.member_index,
			original_share.member_threshold,
		);

		// Step 3: decode the share from its mnemonic and compare ALL fields
		let decoded_share = Share::from_mnemonic(&flat[0])?;
		println!(
			"Step 3:  DECODED share: e={}, id={}, group_idx={}, group_thr={}, group_cnt={}, mem_idx={}, mem_thr={}",
			decoded_share.iteration_exponent,
			decoded_share.identifier,
			decoded_share.group_index,
			decoded_share.group_threshold,
			decoded_share.group_count,
			decoded_share.member_index,
			decoded_share.member_threshold,
		);

		// Check each field individually for clear diagnostics
		assert_eq!(decoded_share.identifier, original_share.identifier,
			"identifier mismatch: original={}, decoded={}",
			original_share.identifier, decoded_share.identifier);
		assert_eq!(decoded_share.iteration_exponent, original_share.iteration_exponent,
			"iteration_exponent mismatch: original={}, decoded={}",
			original_share.iteration_exponent, decoded_share.iteration_exponent);
		assert_eq!(decoded_share.group_index, original_share.group_index,
			"group_index mismatch");
		assert_eq!(decoded_share.group_threshold, original_share.group_threshold,
			"group_threshold mismatch");
		assert_eq!(decoded_share.group_count, original_share.group_count,
			"group_count mismatch");
		assert_eq!(decoded_share.member_index, original_share.member_index,
			"member_index mismatch");
		assert_eq!(decoded_share.member_threshold, original_share.member_threshold,
			"member_threshold mismatch");

		// Step 4: if all fields match, test full pipeline
		let result = combine_mnemonics(&flat[..2].to_vec(), passphrase)?;
		assert_eq!(result, master_secret, "STEP 4 FAILED: full pipeline combine wrong");
		println!("Step 4 PASSED: full pipeline combine OK at e=1");

		Ok(())
	}

	#[test]
	fn duplicate_share_in_group_is_rejected() -> Result<(), Error> {
		// Regression test for the duplicate-member-index robustness fix.
		// Previously, for threshold == 1, supplying the same share twice
		// could silently produce a wrong secret (the digest check is
		// skipped when threshold == 1). We now reject duplicates eagerly.
		let master_secret = b"\x0c\x94\x90\xbcn\xd6\xbc\xbf\xac>\xbe}\xeeV\xf2P".to_vec();

		// 1-of-2 group: each share alone reconstructs the secret.
		let mns = generate_mnemonics(1, &[(1, 2)], &master_secret, "dup", 0, false, None)?;
		let flat = flatten_mnemonics(&mns)?;
		assert_eq!(flat.len(), 2);

		// A single share on its own should succeed.
		let ok = combine_mnemonics(&flat[..1].to_vec(), "dup")?;
		assert_eq!(ok, master_secret);

		// The same share supplied twice must now error rather than
		// silently returning a (possibly wrong) secret.
		let dup = vec![flat[0].clone(), flat[0].clone()];
		let result = combine_mnemonics(&dup, "dup");
		assert!(
			result.is_err(),
			"duplicate share must be rejected, but combine succeeded: {:?}",
			result.map(|v| crate::to_hex(v))
		);

		// Sanity: two distinct shares from a 1-of-2 split should also be
		// rejected (duplicate member indices: both are index 0 in their
		// own group? no — distinct member_index 0 and 1). Actually verify
		// the distinct case still works for a higher threshold.
		let mns3 = generate_mnemonics(1, &[(2, 3)], &master_secret, "dup2", 0, false, None)?;
		let flat3 = flatten_mnemonics(&mns3)?;
		let two_distinct = flat3[..2].to_vec();
		let ok2 = combine_mnemonics(&two_distinct, "dup2")?;
		assert_eq!(ok2, master_secret, "two distinct shares must still combine");

		// And duplicating one of those two must fail.
		let dup2 = vec![flat3[0].clone(), flat3[0].clone()];
		assert!(
			combine_mnemonics(&dup2, "dup2").is_err(),
			"duplicate share in a threshold>1 group must also be rejected"
		);

		Ok(())
	}
}
