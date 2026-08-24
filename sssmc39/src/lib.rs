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

//! Main API definition
//! Should ultimately allow some flexibility around how shares can be
//! provided and returned (e.g. provide hex string instead of mnemonics)

#![deny(non_upper_case_globals)]
#![deny(non_camel_case_types)]
#![deny(non_snake_case)]
#![deny(unused_mut)]
#![warn(missing_docs)]
// SECURITY: forbid `unsafe` at the crate level so future contributions
// cannot silently introduce hand-rolled pointer arithmetic or unchecked
// operations in this SLIP-39 implementation. The Shamir/Feistel core
// must remain pure safe Rust; cryptographic primitives are delegated to
// audited dependencies (ring, sha2, hmac).
#![forbid(unsafe_code)]

#[macro_use]
extern crate lazy_static;

mod error;
mod field;
mod shamir;
mod util;

pub use error::{Error, ErrorKind};
pub use shamir::{GroupShare, Share};
// TODO: only exposed for tests
pub use util::hex::{from_hex, to_hex};

//TODO: Proper docs
/// Generates shares from the provided master secret (e.g. BIP39 entropy)
///
/// `extendable`: the SLIP-0039 extendable-backup flag (`ext`). Pass `false`
/// (the default, `ext = 0`) for the original format where the identifier is
/// mixed into the PBKDF2 salt. Pass `true` (`ext = 1`) for the extendable
/// format, where the identifier is not used as salt so multiple share sets
/// with distinct ids all recover the same master secret for a given
/// passphrase.
///
/// `identifier`: when `Some`, forces the SLIP-0039 15-bit identifier to
/// this value instead of drawing a fresh random one. Used for
/// plausible-deniability / duress setups so a Decoy Wallet can share the
/// same metadata prefix (first two mnemonic words) as a Real Wallet.
pub fn generate_mnemonics(
	group_threshold: u8,
	groups: &[(u8, u8)],
	master_secret: &[u8],
	passphrase: &str,
	iteration_exponent: u8,
	extendable: bool,
	identifier: Option<u16>,
) -> Result<Vec<GroupShare>, Error> {
	shamir::generate_mnemonics(
		group_threshold,
		groups,
		master_secret,
		passphrase,
		iteration_exponent,
		extendable,
		identifier,
	)
}

// TODO: Proper docs
// should allow for different input formats
/// Combines shares into a master secret (e.g. BIP39 entropy)
pub fn combine_mnemonics(mnemonics: &[Vec<String>], passphrase: &str) -> Result<Vec<u8>, Error> {
	shamir::combine_mnemonics(mnemonics, passphrase)
}

// TODO: Proper docs
/// Generate a random master secret (e.g. BIP39 entropy) and returns the shares from it
///
/// `identifier`: see [`generate_mnemonics`].
pub fn generate_mnemonics_random(
	group_threshold: u8,
	groups: &[(u8, u8)],
	strength_bits: u16,
	passphrase: &str,
	iteration_exponent: u8,
	extendable: bool,
	identifier: Option<u16>,
) -> Result<Vec<GroupShare>, Error> {
	shamir::generate_mnemonics_random(
		group_threshold,
		groups,
		strength_bits,
		passphrase,
		iteration_exponent,
		extendable,
		identifier,
	)
}
