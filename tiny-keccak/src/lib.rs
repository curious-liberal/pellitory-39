//! Keccak derived functions specified in [`FIPS-202`], [`SP800-185`] and [`KangarooTwelve`].
//!
//! # Example
//!
//! ```
//! # use tiny_keccak::Hasher;
//! #
//! # fn foo<H: Hasher>(mut hasher: H) {
//! let input_a = b"hello world";
//! let input_b = b"!";
//! let mut output = [0u8; 32];
//! hasher.update(input_a);
//! hasher.update(input_b);
//! hasher.finalize(&mut output);
//! # }
//! ```
//!
//! # Credits
//!
//! - [`coruus/keccak-tiny`] for C implementation of keccak function
//! - [`@quininer`] for `no-std` support and rust implementation [`SP800-185`]
//! - [`mimoo/GoKangarooTwelve`] for GO implementation of `KangarooTwelve`
//! - [`@Vurich`] for optimizations
//! - [`@oleganza`] for adding support for half-duplex use
//!
//! # License
//!
//! [`CC0`]. Attribution kindly requested. Blame taken too,
//! but not liability.
//!
//! [`FIPS-202`]: https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.202.pdf
//! [`SP800-185`]: https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-185.pdf
//! [`KangarooTwelve`]: https://eprint.iacr.org/2016/770.pdf
//! [`coruus/keccak-tiny`]: https://github.com/coruus/keccak-tiny
//! [`mimoo/GoKangarooTwelve`]: https://github.com/mimoo/GoKangarooTwelve
//! [`@quininer`]: https://github.com/quininer
//! [`@Vurich`]: https://github.com/Vurich
//! [`@oleganza`]: https://github.com/oleganza
//! [`CC0`]: https://github.com/debris/tiny-keccak/blob/master/LICENSE

#![no_std]
#![deny(missing_docs)]
// SECURITY (pellitory-39 fork): forbid `unsafe` at the crate level. The
// upstream sponge I/O (the `core::mem::transmute` in `Buffer::execute`
// and the raw-pointer loop in `xorin`) has been rewritten in safe Rust
// (see `Buffer::execute` / `xorin`), so no `unsafe` remains anywhere in
// this fork — under every feature gate, not just the `keccak` feature the
// parent project uses.
#![forbid(unsafe_code)]

// SECURITY (pellitory-39 fork): import for the zeroize impls below.
use zeroize::Zeroize;

const RHO: [u32; 24] = [
    1, 3, 6, 10, 15, 21, 28, 36, 45, 55, 2, 14, 27, 41, 56, 8, 25, 43, 62, 18, 39, 61, 20, 44,
];

const PI: [usize; 24] = [
    10, 7, 11, 17, 18, 3, 5, 16, 8, 21, 24, 4, 15, 23, 19, 13, 12, 2, 20, 14, 22, 9, 6, 1,
];

const WORDS: usize = 25;

macro_rules! keccak_function {
    ($doc: expr, $name: ident, $rounds: expr, $rc: expr) => {
        #[doc = $doc]
        #[allow(unused_assignments)]
        #[allow(non_upper_case_globals)]
        pub fn $name(a: &mut [u64; $crate::WORDS]) {
            use crunchy::unroll;

            for i in 0..$rounds {
                let mut array: [u64; 5] = [0; 5];

                // Theta
                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                let y = y_count * 5;
                                array[x] ^= a[x + y];
                            }
                        }
                    }
                }

                unroll! {
                    for x in 0..5 {
                        unroll! {
                            for y_count in 0..5 {
                                let y = y_count * 5;
                                a[y + x] ^= array[(x + 4) % 5] ^ array[(x + 1) % 5].rotate_left(1);
                            }
                        }
                    }
                }

                // Rho and pi
                let mut last = a[1];
                unroll! {
                    for x in 0..24 {
                        array[0] = a[$crate::PI[x]];
                        a[$crate::PI[x]] = last.rotate_left($crate::RHO[x]);
                        last = array[0];
                    }
                }

                // Chi
                unroll! {
                    for y_step in 0..5 {
                        let y = y_step * 5;

                        unroll! {
                            for x in 0..5 {
                                array[x] = a[y + x];
                            }
                        }

                        unroll! {
                            for x in 0..5 {
                                a[y + x] = array[x] ^ ((!array[(x + 1) % 5]) & (array[(x + 2) % 5]));
                            }
                        }
                    }
                };

                // Iota
                a[0] ^= $rc[i];
            }
        }
    }
}

#[cfg(feature = "k12")]
mod keccakp;

#[cfg(feature = "k12")]
pub use keccakp::keccakp;

#[cfg(any(
    feature = "keccak",
    feature = "shake",
    feature = "sha3",
    feature = "cshake",
    feature = "kmac",
    feature = "tuple_hash",
    feature = "parallel_hash"
))]
mod keccakf;

#[cfg(any(
    feature = "keccak",
    feature = "shake",
    feature = "sha3",
    feature = "cshake",
    feature = "kmac",
    feature = "tuple_hash",
    feature = "parallel_hash"
))]
pub use keccakf::keccakf;

#[cfg(feature = "k12")]
mod k12;

#[cfg(feature = "k12")]
pub use k12::{KangarooTwelve, KangarooTwelveXof};

#[cfg(feature = "keccak")]
mod keccak;

#[cfg(feature = "keccak")]
pub use keccak::Keccak;

#[cfg(feature = "shake")]
mod shake;

#[cfg(feature = "shake")]
pub use shake::Shake;

#[cfg(feature = "sha3")]
mod sha3;

#[cfg(feature = "sha3")]
pub use sha3::Sha3;

#[cfg(feature = "cshake")]
mod cshake;

#[cfg(feature = "cshake")]
pub use cshake::CShake;

#[cfg(feature = "kmac")]
mod kmac;

#[cfg(feature = "kmac")]
pub use kmac::{Kmac, KmacXof};

#[cfg(feature = "tuple_hash")]
mod tuple_hash;

#[cfg(feature = "tuple_hash")]
pub use tuple_hash::{TupleHash, TupleHashXof};

#[cfg(feature = "parallel_hash")]
mod parallel_hash;

#[cfg(feature = "parallel_hash")]
pub use parallel_hash::{ParallelHash, ParallelHashXof};

/// A trait for hashing an arbitrary stream of bytes.
///
/// # Example
///
/// ```
/// # use tiny_keccak::Hasher;
/// #
/// # fn foo<H: Hasher>(mut hasher: H) {
/// let input_a = b"hello world";
/// let input_b = b"!";
/// let mut output = [0u8; 32];
/// hasher.update(input_a);
/// hasher.update(input_b);
/// hasher.finalize(&mut output);
/// # }
/// ```
pub trait Hasher {
    /// Absorb additional input. Can be called multiple times.
    fn update(&mut self, input: &[u8]);

    /// Pad and squeeze the state to the output.
    fn finalize(self, output: &mut [u8]);
}

/// A trait used to convert [`Hasher`] into it's [`Xof`] counterpart.
///
/// # Example
///
/// ```
/// # use tiny_keccak::IntoXof;
/// #
/// # fn foo<H: IntoXof>(hasher: H) {
/// let xof = hasher.into_xof();
/// # }
/// ```
///
/// [`Hasher`]: trait.Hasher.html
/// [`Xof`]: trait.Xof.html
pub trait IntoXof {
    /// A type implementing [`Xof`], eXtendable-output function interface.
    ///
    /// [`Xof`]: trait.Xof.html
    type Xof: Xof;

    /// A method used to convert type into [`Xof`].
    ///
    /// [`Xof`]: trait.Xof.html
    fn into_xof(self) -> Self::Xof;
}

/// Extendable-output function (`XOF`) is a function on bit strings in which the output can be
/// extended to any desired length.
///
/// # Example
///
/// ```
/// # use tiny_keccak::Xof;
/// #
/// # fn foo<X: Xof>(mut xof: X) {
/// let mut output = [0u8; 64];
/// xof.squeeze(&mut output[0..32]);
/// xof.squeeze(&mut output[32..]);
/// # }
/// ```
pub trait Xof {
    /// A method used to retrieve another part of hash function output.
    fn squeeze(&mut self, output: &mut [u8]);
}

// SP800-185 length-encoding helpers (`EncodedLen`/`value`/`left_encode`/
// `right_encode`) and the KangarooTwelve sponge `reset` are used only by
// the `cshake`/`kmac`/`tuple_hash`/`parallel_hash`/`k12` feature modules,
// which the parent project does not enable (it uses only `keccak`). Silence
// the unused warnings so the fork's `keccak`-only build is clean without
// feature-gating each item (which would increase fork divergence). A
// `cargo build --all-features` build uses all of these and is warning-free.
#[allow(dead_code)]
struct EncodedLen {
    offset: usize,
    buffer: [u8; 9],
}

impl EncodedLen {
    #[allow(dead_code)]
    fn value(&self) -> &[u8] {
        &self.buffer[self.offset..]
    }
}

#[allow(dead_code)]
fn left_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[1..].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(8);
    buffer[offset - 1] = 9 - offset as u8;

    EncodedLen {
        offset: offset - 1,
        buffer,
    }
}

#[allow(dead_code)]
fn right_encode(len: usize) -> EncodedLen {
    let mut buffer = [0u8; 9];
    buffer[..8].copy_from_slice(&(len as u64).to_be_bytes());
    let offset = buffer.iter().position(|i| *i != 0).unwrap_or(7);
    buffer[8] = 8 - offset as u8;
    EncodedLen { offset, buffer }
}

#[derive(Default, Clone)]
struct Buffer([u64; WORDS]);

// SECURITY (pellitory-39 fork): zeroize the sponge state. `Buffer`
// holds the absorbed input (including the Monero private spend key
// during view-key derivation); upstream drops it un-wiped. `[u64; 25]:
// Zeroize` is provided by `zeroize`'s array impl, which writes zeroes
// over the in-range words. The hashing algorithm is unchanged — this
// only affects what happens to the buffer's memory when it is dropped.
impl Zeroize for Buffer {
    fn zeroize(&mut self) {
        self.0.zeroize();
    }
}

impl Buffer {
    fn words(&mut self) -> &mut [u64; WORDS] {
        &mut self.0
    }

    #[inline]
    fn execute<F: FnOnce(&mut [u8])>(&mut self, offset: usize, len: usize, f: F) {
        // Keccak lanes are absorbed and squeezed in little-endian byte
        // order (FIPS-202). Build a 200-byte little-endian view of the 25
        // lanes, let the caller mutate the requested sub-slice, then write
        // the bytes back into the lanes.
        //
        // SECURITY (pellitory-39 fork): this replaces upstream's
        // `unsafe { core::mem::transmute(&mut self.0) }` (and the big-endian
        // `swap_bytes` dance) with a fully safe copy-out / mutate / copy-in.
        // The crate is `#![forbid(unsafe_code)]`, so no hand-rolled pointer
        // aliasing remains in the sponge I/O. The 200-byte copy is
        // negligible next to a Keccak-f permutation, and the hashing
        // algorithm is unchanged (verified by the parent project's
        // `matches_reference_vector` test pinning the exact Keccak-derived
        // Monero keys/address).
        let mut bytes = [0u8; WORDS * 8];
        for (i, w) in self.0.iter().enumerate() {
            bytes[i * 8..][..8].copy_from_slice(&w.to_le_bytes());
        }
        f(&mut bytes[offset..][..len]);
        for (i, w) in self.0.iter_mut().enumerate() {
            let mut lane = [0u8; 8];
            lane.copy_from_slice(&bytes[i * 8..][..8]);
            *w = u64::from_le_bytes(lane);
        }
    }

    fn setout(&mut self, dst: &mut [u8], offset: usize, len: usize) {
        self.execute(offset, len, |buffer| dst[..len].copy_from_slice(buffer));
    }

    fn xorin(&mut self, src: &[u8], offset: usize, len: usize) {
        self.execute(offset, len, |dst| {
            assert!(dst.len() <= src.len());
            // SECURITY (pellitory-39 fork): replace upstream's raw-pointer
            // XOR loop with a safe indexed loop. Bounds are guaranteed by
            // the `assert!` above (`dst.len() <= src.len()`), so indexing
            // `src[i]` for `i < dst.len()` is always in range.
            for i in 0..dst.len() {
                dst[i] ^= src[i];
            }
        });
    }

    fn pad(&mut self, offset: usize, delim: u8, rate: usize) {
        self.execute(offset, 1, |buff| buff[0] ^= delim);
        self.execute(rate - 1, 1, |buff| buff[0] ^= 0x80);
    }
}

trait Permutation {
    fn execute(a: &mut Buffer);
}

#[derive(Clone, Copy)]
enum Mode {
    Absorbing,
    Squeezing,
}

struct KeccakState<P> {
    buffer: Buffer,
    offset: usize,
    rate: usize,
    delim: u8,
    mode: Mode,
    permutation: core::marker::PhantomData<P>,
}

// SECURITY (pellitory-39 fork): wipe the sponge state on drop so the
// absorbed secret (notably the Monero private spend key) does not
// linger in freed heap memory. `Keccak` owns a `KeccakState`, and every
// `Hasher::finalize(self, …)` consumes the `Keccak` by value, so this
// `Drop` fires on the normal finalize path as well as on early drop.
// `offset`/`rate`/`delim`/`mode` are not secret and are left as-is.
impl<P> Drop for KeccakState<P> {
    fn drop(&mut self) {
        self.buffer.zeroize();
    }
}

impl<P> Clone for KeccakState<P> {
    fn clone(&self) -> Self {
        KeccakState {
            buffer: self.buffer.clone(),
            offset: self.offset,
            rate: self.rate,
            delim: self.delim,
            mode: self.mode,
            permutation: core::marker::PhantomData,
        }
    }
}

impl<P: Permutation> KeccakState<P> {
    fn new(rate: usize, delim: u8) -> Self {
        assert!(rate != 0, "rate cannot be equal 0");
        KeccakState {
            buffer: Buffer::default(),
            offset: 0,
            rate,
            delim,
            mode: Mode::Absorbing,
            permutation: core::marker::PhantomData,
        }
    }

    fn keccak(&mut self) {
        P::execute(&mut self.buffer);
    }

    fn update(&mut self, input: &[u8]) {
        if let Mode::Squeezing = self.mode {
            self.mode = Mode::Absorbing;
            self.fill_block();
        }

        //first foldp
        let mut ip = 0;
        let mut l = input.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.xorin(&input[ip..], offset, rate);
            self.keccak();
            ip += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.xorin(&input[ip..], offset, l);
        self.offset = offset + l;
    }

    fn pad(&mut self) {
        self.buffer.pad(self.offset, self.delim, self.rate);
    }

    fn squeeze(&mut self, output: &mut [u8]) {
        if let Mode::Absorbing = self.mode {
            self.mode = Mode::Squeezing;
            self.pad();
            self.fill_block();
        }

        // second foldp
        let mut op = 0;
        let mut l = output.len();
        let mut rate = self.rate - self.offset;
        let mut offset = self.offset;
        while l >= rate {
            self.buffer.setout(&mut output[op..], offset, rate);
            self.keccak();
            op += rate;
            l -= rate;
            rate = self.rate;
            offset = 0;
        }

        self.buffer.setout(&mut output[op..], offset, l);
        self.offset = offset + l;
    }

    fn finalize(mut self, output: &mut [u8]) {
        self.squeeze(output);
    }

    fn fill_block(&mut self) {
        self.keccak();
        self.offset = 0;
    }

    #[allow(dead_code)]
    fn reset(&mut self) {
        self.buffer = Buffer::default();
        self.offset = 0;
        self.mode = Mode::Absorbing;
    }
}

fn bits_to_rate(bits: usize) -> usize {
    200 - bits / 4
}

#[cfg(test)]
mod tests {
    use crate::{left_encode, right_encode};

    #[test]
    fn test_left_encode() {
        assert_eq!(left_encode(0).value(), &[1, 0]);
        assert_eq!(left_encode(128).value(), &[1, 128]);
        assert_eq!(left_encode(65536).value(), &[3, 1, 0, 0]);
        assert_eq!(left_encode(4096).value(), &[2, 16, 0]);
        assert_eq!(left_encode(54321).value(), &[2, 212, 49]);
    }

    #[test]
    fn test_right_encode() {
        assert_eq!(right_encode(0).value(), &[0, 1]);
        assert_eq!(right_encode(128).value(), &[128, 1]);
        assert_eq!(right_encode(65536).value(), &[1, 0, 0, 3]);
        assert_eq!(right_encode(4096).value(), &[16, 0, 2]);
        assert_eq!(right_encode(54321).value(), &[212, 49, 2]);
    }
}
