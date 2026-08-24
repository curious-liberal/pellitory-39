// Copyright 2018 The Grin Developers
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

/// Implements hex-encoding from bytes to string and decoding of strings
/// to bytes. Given that rustc-serialize is deprecated and serde doesn't
/// provide easy hex encoding, hex is a bit in limbo right now in Rust-
/// land. It's simple enough that we can just have our own.
use std::fmt::Write;

use crate::error::{Error, ErrorKind};

/// Encode the provided bytes into a hex string
pub fn to_hex(bytes: Vec<u8>) -> String {
	let mut s = String::new();
	for byte in bytes {
		write!(&mut s, "{:02x}", byte).expect("Unable to write");
	}
	s
}

/// Decode a hex string into bytes.
///
/// Accepts an optional `0x` prefix. Returns an `Error` on invalid input —
/// odd length, empty, or non-hex characters. (SECURITY_REVIEW.md LOW-3:
/// previously manufactured a `ParseIntError` by parsing `"QQQ"` to preserve
/// a legacy return type; this is a breaking signature change for the
/// hardened fork, switching to the crate's own `Error`.)
pub fn from_hex(hex_str: String) -> Result<Vec<u8>, Error> {
	let hex_str_no_prefix = hex_str.strip_prefix("0x").unwrap_or(&hex_str);
	let hex_trim = hex_str_no_prefix.trim();

	if hex_trim.is_empty() {
		return Err(ErrorKind::Value("empty hex string".to_string()).into());
	}
	if hex_trim.len() % 2 == 1 {
		return Err(ErrorKind::Value(format!(
			"odd-length hex string ({} chars)",
			hex_trim.len()
		))
		.into());
	}

	split_n(hex_trim, 2)
		.iter()
		.map(|b| {
			u8::from_str_radix(b, 16)
				.map_err(|_| ErrorKind::Value(format!("invalid hex digit in '{b}'")))
		})
		.collect::<Result<Vec<u8>, _>>()
		.map_err(Error::from)
}

fn split_n(s: &str, n: usize) -> Vec<&str> {
	// `s.len()` is guaranteed >= n here because from_hex rejects empty and
	// odd-length input before reaching this point.
	debug_assert!(s.len() >= n);
	(0..=(s.len() - n) / 2)
		.map(|i| &s[2 * i..2 * i + n])
		.collect()
}

#[cfg(test)]
mod test {
	use super::*;

	#[test]
	fn test_to_hex() {
		assert_eq!(to_hex(vec![0, 0, 0, 0]), "00000000");
		assert_eq!(to_hex(vec![10, 11, 12, 13]), "0a0b0c0d");
		assert_eq!(to_hex(vec![0, 0, 0, 255]), "000000ff");
	}

	#[test]
	fn test_from_hex() {
		assert_eq!(from_hex("00000000".to_string()).unwrap(), vec![0, 0, 0, 0]);
		assert_eq!(
			from_hex("0a0b0c0d".to_string()).unwrap(),
			vec![10, 11, 12, 13]
		);
		assert_eq!(
			from_hex("000000ff".to_string()).unwrap(),
			vec![0, 0, 0, 255]
		);
		assert!(from_hex("0x0a0b0c0d".to_string()).unwrap() == vec![10, 11, 12, 13]);
		assert!(from_hex(" 0a0b0c0d ".to_string()).unwrap() == vec![10, 11, 12, 13]);
	}

	#[test]
	fn test_from_hex_rejects_invalid() {
		// empty
		assert!(from_hex("".to_string()).is_err());
		assert!(from_hex("   ".to_string()).is_err());
		// odd length
		assert!(from_hex("abc".to_string()).is_err());
		// non-hex
		assert!(from_hex("zzzz".to_string()).is_err());
		assert!(from_hex("0xQQ".to_string()).is_err());
	}
}
