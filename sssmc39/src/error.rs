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

//! Error types for the sssmc39 crate.
//!
//! Hardened fork: migrated from the unmaintained `failure` crate to
//! `thiserror`, removing a deprecated dependency and the associated
//! `non_local_definitions` compiler warnings.

use thiserror::Error;

/// The specific kind of error that occurred.
#[derive(Clone, Eq, PartialEq, Debug, Error)]
pub enum ErrorKind {
	/// Configuration error, with details
	#[error("Configuration Error: {0}")]
	Config(String),

	/// Inconsistency between different arguments
	#[error("Argument Error: {0}")]
	Argument(String),

	/// Problems with a mnemonic or inconsistent mnemonics
	#[error("Mnemonic Error: {0}")]
	Mnemonic(String),

	/// Assembling the full master secret resulted in an incorrect checksum
	#[error("Digest Error: {0}")]
	Digest(String),

	/// Invalid usage of BitPacker.add_uX (num_bits longer than the size of uX)
	#[error("BitVec Error: {0}")]
	BitVec(String),

	/// (unused currently)
	#[error("Checksum Validation Error: {0}")]
	Checksum(String),

	/// Invalid value of one of the arguments
	#[error("Value Error: {0}")]
	Value(String),

	/// Invalid usage of BitPacker.remove_padding (num_bits contained set bits)
	#[error("Padding Error: All padding bits must be 0")]
	Padding,

	/// (unused currently)
	#[error("Generic error: {0}")]
	GenericError(String),
}

/// The main error type returned by this crate.
#[derive(Clone, Eq, PartialEq, Debug, Error)]
#[error("{inner}")]
pub struct Error {
	inner: ErrorKind,
}

impl Error {
	/// Return the kind of this error.
	pub fn kind(&self) -> ErrorKind {
		self.inner.clone()
	}

	/// Return the cause of this error as a string.
	pub fn cause_string(&self) -> String {
		format!("{}", self.inner)
	}
}

impl From<ErrorKind> for Error {
	fn from(kind: ErrorKind) -> Error {
		Error { inner: kind }
	}
}
