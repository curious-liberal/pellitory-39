//! SLIP-0039 secret sharing: split secrets into shares and combine them.
//!
//! This module wraps the `sssmc39` crate with secure memory handling —
//! all intermediate secret material is zeroised on drop.

use anyhow::{anyhow, Error, Result};
use serde::Serialize;
use sssmc39::*;
use zeroize::{Zeroize, Zeroizing};

/// Master secret with automatic zeroisation on drop.
///
/// Not `Clone` — prevents untracked copies of secret material floating
/// about in memory.
pub struct MasterSecret(Zeroizing<Vec<u8>>);

impl MasterSecret {
    /// Generate a new random master secret with the given bit strength.
    /// Uses `OsRng` (operating system entropy), never a userspace PRNG.
    pub fn generate(strength_bits: u16) -> Result<Self> {
        use rand::rngs::OsRng;
        use rand::Rng;

        let proto_share = Share::new().map_err(Error::msg)?;
        if strength_bits < proto_share.config.min_strength_bits {
            return Err(anyhow!(
                "master secret must be at least {} bits, got {}",
                proto_share.config.min_strength_bits,
                strength_bits,
            ));
        }
        if !strength_bits.is_multiple_of(16) {
            return Err(anyhow!(
                "master secret must be a multiple of 16 bits, got {}",
                strength_bits,
            ));
        }

        let len = strength_bits as usize / 8;
        let mut v = Zeroizing::new(vec![0u8; len]);
        let mut rng = OsRng;
        for byte in v.iter_mut() {
            *byte = rng.gen();
        }
        Ok(Self(v))
    }

    /// Create a MasterSecret from existing bytes.
    pub fn from_bytes(bytes: &[u8]) -> Self {
        Self(Zeroizing::new(bytes.to_vec()))
    }

    /// Create a MasterSecret from a hex string.
    pub fn from_hex(hex_str: &str) -> Result<Self> {
        let mut bytes = Zeroizing::new(hex::decode(hex_str.trim())?);
        let ms = Self(Zeroizing::new(bytes.to_vec()));
        bytes.zeroize();
        Ok(ms)
    }
}

impl AsRef<Vec<u8>> for MasterSecret {
    fn as_ref(&self) -> &Vec<u8> {
        &self.0
    }
}

impl std::fmt::Debug for MasterSecret {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("MasterSecret([REDACTED])")
    }
}

/// SLIP-0039 share group output with serialisation.
pub struct Slip39Output(Vec<GroupShare>);

impl Slip39Output {
    /// Split a master secret into SLIP-0039 shares.
    ///
    /// `identifier` is drawn from `OsRng`. See [`Slip39Output::split_with_identifier`]
    /// for the variant that accepts a fixed identifier (used for
    /// plausible-deniability / duress setups).
    pub fn split(
        group_threshold: u8,
        groups: &[(u8, u8)],
        master_secret: &MasterSecret,
        passphrase: &str,
        iteration_exponent: u8,
        extendable: bool,
    ) -> Result<Self> {
        Self::split_with_identifier(
            group_threshold,
            groups,
            master_secret,
            passphrase,
            iteration_exponent,
            extendable,
            None,
        )
    }

    /// Split a master secret into SLIP-0039 shares with a fixed
    /// 15-bit identifier.
    ///
    /// `extendable` selects the SLIP-0039 extendable-backup format: `false`
    /// (the default, `ext = 0`) mixes the identifier into the PBKDF2 salt;
    /// `true` (`ext = 1`) omits the identifier from the salt so multiple
    /// share sets with distinct ids recover the same master secret for a
    /// given passphrase.
    ///
    /// Pass `Some(identifier)` to force the SLIP-0039 identifier to a
    /// specific value (0..=32767) instead of generating a random one.
    /// This makes the first two mnemonic words — which encode
    /// `identifier || ext || iteration_exponent` — identical to those of
    /// another wallet split with the same identifier, ext flag, and exponent.
    ///
    /// **Duress / plausible deniability.** Generate a Real Wallet, note
    /// its identifier (visible via `pellitory-39 inspect`), then generate
    /// a Decoy Wallet with `--identifier <REAL_ID>` and the same
    /// `--iterations`, `--extendable`, and group structure. Shares from
    /// both wallets will then be indistinguishable by their metadata
    /// prefix, so an attacker cannot tell Real shares from Decoy shares
    /// just by looking at them.
    ///
    /// Pass `None` to keep the default random-identifier behaviour.
    pub fn split_with_identifier(
        group_threshold: u8,
        groups: &[(u8, u8)],
        master_secret: &MasterSecret,
        passphrase: &str,
        iteration_exponent: u8,
        extendable: bool,
        identifier: Option<u16>,
    ) -> Result<Self> {
        let group_shares = generate_mnemonics(
            group_threshold,
            groups,
            master_secret.as_ref(),
            passphrase,
            iteration_exponent,
            extendable,
            identifier,
        )
        .map_err(Error::msg)?;
        Ok(Self(group_shares))
    }

    /// Serialise to pretty JSON.
    ///
    /// The returned string is wrapped in [`Zeroizing`] so it is wiped from
    /// memory on drop — it contains every share mnemonic, each of which is
    /// secret-equivalent above the threshold. The intermediate `ShareFormatter`
    /// / `GroupFormatter` strings built during serialisation are likewise
    /// zeroised after the JSON is produced (ordinary `String::Drop` only frees
    /// the heap buffer without overwriting it).
    pub fn to_json(&self) -> Result<Zeroizing<String>> {
        let mut formatter = OutputFormatter::from(&self.0);
        let json = Zeroizing::new(serde_json::to_string_pretty(&formatter)?);
        // Wipe the owned mnemonic strings held by the formatter tree. They
        // are secret-equivalent above the threshold and would otherwise be
        // dropped un-wiped at the `;` below.
        for group in formatter.groups.iter_mut() {
            for share in group.shares.iter_mut() {
                share.mnemonic.zeroize();
            }
        }
        Ok(json)
    }

    /// The 15-bit SLIP-0039 identifier shared by every share in this set.
    ///
    /// Used by the duress / plausible-deniability flow: the GUI captures
    /// the Real wallet's identifier and forces the Decoy wallet to reuse
    /// it so the first two mnemonic words match across both wallets.
    pub fn identifier(&self) -> u16 {
        // Every group shares the same identifier; take it from the first.
        self.0[0].group_id
    }

    /// Flatten every share mnemonic in this output into a single `Vec<String>`,
    /// one entry per share (each a space-separated word list).
    ///
    /// For single-group wallets this is just the member shares in order.
    /// The caller owns the strings and is responsible for zeroising them.
    pub fn all_mnemonics(&self) -> Vec<Zeroizing<String>> {
        let mut out = Vec::new();
        for group in &self.0 {
            for share in &group.member_shares {
                if let Ok(words) = share.to_mnemonic() {
                    let joined = words
                        .iter()
                        .map(|w| w.as_str())
                        .collect::<Vec<_>>()
                        .join(" ");
                    out.push(Zeroizing::new(joined));
                }
            }
        }
        out
    }
}

/// Combine SLIP-0039 mnemonics to recover the master secret.
pub fn combine(mnemonics: &[Vec<String>], passphrase: &str) -> Result<Zeroizing<Vec<u8>>> {
    let secret = combine_mnemonics(mnemonics, passphrase).map_err(Error::msg)?;
    Ok(Zeroizing::new(secret))
}

/// Inspect a single SLIP-0039 share to see its metadata.
pub fn inspect(words: &[String]) -> Result<ShareMetadata> {
    let share = Share::from_mnemonic(words).map_err(Error::msg)?;
    Ok(ShareMetadata::from(&share))
}

/// Parse a group specification string like "2of3", "3/5", or "2:3".
pub fn parse_group_spec(src: &str) -> Result<(u8, u8)> {
    let pattern =
        regex::Regex::new(r"^(?P<threshold>\d+)(-?of-?|:|/)(?P<total>\d+)$")?;
    let captures = pattern.captures(src).ok_or_else(|| {
        anyhow!(
            "invalid group spec '{}' — use formats like '2of3', '2/3', or '2:3'",
            src
        )
    })?;
    let threshold: u8 = captures["threshold"].parse()?;
    let total: u8 = captures["total"].parse()?;
    if threshold > total {
        return Err(anyhow!(
            "threshold ({}) cannot exceed total members ({})",
            threshold,
            total
        ));
    }
    if threshold == 0 {
        return Err(anyhow!("threshold must be at least 1"));
    }
    Ok((threshold, total))
}

// ─── Serialisation ──────────────────────────────────────────────────────────

#[derive(Serialize)]
struct ShareFormatter {
    group_index: u8,
    member_index: u8,
    mnemonic: String,
}

impl From<&Share> for ShareFormatter {
    fn from(share: &Share) -> Self {
        let words = share
            .to_mnemonic()
            .expect("formatting a valid mnemonic should not fail");
        let mnemonic = words
            .iter()
            .map(|w| w.as_str())
            .collect::<Vec<_>>()
            .join(" ");
        Self {
            member_index: share.member_index + 1,
            group_index: share.group_index + 1,
            mnemonic,
        }
    }
}

#[derive(Serialize)]
struct GroupFormatter {
    member_threshold: u8,
    member_count: u8,
    shares: Vec<ShareFormatter>,
}

impl From<&GroupShare> for GroupFormatter {
    fn from(group: &GroupShare) -> Self {
        Self {
            member_threshold: group.member_threshold,
            member_count: group.member_shares.len() as u8,
            shares: group.member_shares.iter().map(ShareFormatter::from).collect(),
        }
    }
}

#[derive(Serialize)]
struct OutputFormatter {
    group_count: u8,
    group_threshold: u8,
    groups: Vec<GroupFormatter>,
}

impl<T: AsRef<[GroupShare]>> From<T> for OutputFormatter {
    fn from(value: T) -> Self {
        let group_shares = value.as_ref();
        let share_1_1 = &group_shares[0].member_shares[0];
        Self {
            group_count: share_1_1.group_count,
            group_threshold: share_1_1.group_threshold,
            groups: group_shares.iter().map(GroupFormatter::from).collect(),
        }
    }
}

// NOTE: there is intentionally no `impl Serialize for Slip39Output`.
// `ShareFormatter`/`OutputFormatter` hold plain `String` mnemonic fields
// (secret-equivalent above the threshold) that would be dropped un-wiped
// by ordinary `String::Drop` after a `serde_json::to_string(&output)` call.
// The only zeroising serialisation path is [`Slip39Output::to_json`], which
// builds its own formatter tree and explicitly `.zeroize()`s those strings
// after producing the JSON. All in-tree callers use `to_json()`; removing
// the `Serialize` impl prevents a future caller from accidentally routing
// share mnemonics through the un-zeroising path.

/// Metadata about a single SLIP-0039 share.
#[derive(Serialize, Clone)]
pub struct ShareMetadata {
    pub identifier: u16,
    /// Extendable-backup flag (`ext`): `false` for the original `ext = 0`
    /// format, `true` for `ext = 1`.
    pub extendable: bool,
    pub iterations: u8,
    pub group_threshold: u8,
    pub group_count: u8,
    pub group_index: u8,
    pub member_threshold: u8,
    pub member_index: u8,
}

impl From<&Share> for ShareMetadata {
    fn from(share: &Share) -> Self {
        Self {
            identifier: share.identifier,
            extendable: share.extendable,
            iterations: share.iteration_exponent,
            group_threshold: share.group_threshold,
            group_count: share.group_count,
            group_index: share.group_index + 1,
            member_threshold: share.member_threshold,
            member_index: share.member_index + 1,
        }
    }
}
