//! Cryptographic helpers for the GUI.
//!
//! These functions wrap the existing `pellitory_39` core (gen / split /
//! combine / derive) so the GUI never reimplements cryptography. All
//! secret material is wrapped in `Zeroizing` and wiped on drop.
//!
//! This module has **no** dependency on `eframe` so it can be unit-tested
//! in isolation and reused by non-GUI callers.

use anyhow::{anyhow, Result};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use zeroize::{Zeroize, Zeroizing};

use crate::encrypt::{self, DecryptTarget, EncryptTarget};
use crate::export::{self, BulkPackage};
use crate::monero;
use crate::sharing;
use crate::{detect_and_normalise, derive_bip39_mnemonic, InputKind};

// ─── age encrypt / decrypt wrappers (phase 006) ─────────────────────────────
//
// The GUI never imports the `age` crate or `EncryptTarget` / `DecryptTarget`
// directly. These enums + wrapper functions are the sole boundary, so the
// GUI popups deal only in plain strings and file contents, and all the
// crypto stays here where it is unit-testable without `eframe`.

/// Encryption method chosen in a save popup.
///
/// The GUI builds one of these from user input (passphrase entry, pasted /
/// loaded recipient). It is converted to [`encrypt::EncryptTarget`]
/// internally by the wrappers below.
#[derive(Clone, Debug)]
pub enum EncryptMethod {
    /// age scrypt passphrase recipient.
    Passphrase(Zeroizing<String>),
    /// age X25519 recipient (`age1...`).
    AgeRecipient(String),
    /// SSH recipient (`ssh-ed25519 ...` / `ssh-rsa ...`).
    SshRecipient(String),
}

/// Decryption credential chosen in a decrypt popup.
pub enum DecryptMethod {
    /// age scrypt passphrase identity.
    Passphrase(Zeroizing<String>),
    /// age identity file *contents* (`AGE-SECRET-KEY-1...`).
    AgeIdentity(Zeroizing<Vec<u8>>),
    /// SSH private key file *contents* (OpenSSH format).
    SshIdentity(Zeroizing<Vec<u8>>),
    /// Auto-detect key type (age identity or SSH private key). The GUI
    /// decrypt popup offers a single "age / SSH key" option instead of
    /// forcing the user to pick a format.
    AutoKey(Zeroizing<Vec<u8>>),
}

/// Parse a pasted / loaded recipient string into an [`EncryptMethod`],
/// validating it with the `age` parser so malformed input fails here.
pub fn parse_recipient(s: &str) -> Result<EncryptMethod> {
    let target = encrypt::parse_recipient(s)?;
    Ok(method_from_target(target))
}

/// A short, plain-word fingerprint for display in a popup
/// (e.g. `"X25519 1ab2c3d4"`, `"ssh-ed25519 1ab2c3d4"`).
/// Returns `None` for passphrases (no recipient to fingerprint).
pub fn recipient_fingerprint(method: &EncryptMethod) -> Option<String> {
    let target = target_from_method(method);
    encrypt::recipient_fingerprint(&target).map(|fp| plain_word_fingerprint(method, &fp))
}

/// Encrypt a single share mnemonic to age ASCII armour.
///
/// Wraps [`export::build_single_share_export`]. Returns the armoured
/// bytes (ready to write to a `*.txt.age` file).
pub fn encrypt_single_share(share: &str, method: &EncryptMethod) -> Result<Zeroizing<Vec<u8>>> {
    let target = target_from_method(method);
    export::build_single_share_export(share.as_bytes(), &target)
}

/// Build a bulk export (ZIP or one-file armoured blob).
///
/// Wraps [`export::build_export`]. For [`BulkPackage::Zip`],
/// `methods.len()` must equal `shares.len()`; for [`BulkPackage::OneFile`],
/// `methods.len()` must be 1.
pub fn build_bulk_export(
    shares: &[Zeroizing<String>],
    methods: &[EncryptMethod],
    package: BulkPackage,
    threshold: u8,
) -> Result<Zeroizing<Vec<u8>>> {
    let targets: Vec<EncryptTarget> = methods.iter().map(target_from_method).collect();
    export::build_export(shares, &targets, package, threshold)
}

/// Decrypt age armour (auto-detects binary age too) back to plaintext.
///
/// Wraps [`encrypt::decrypt_share`]. A wrong passphrase / mismatched
/// identity returns age's authenticated error — a genuine error, not
/// silent garbage.
pub fn decrypt_share(armoured: &[u8], method: &DecryptMethod) -> Result<Zeroizing<Vec<u8>>> {
    let target = match method {
        DecryptMethod::Passphrase(p) => {
            DecryptTarget::Passphrase(Zeroizing::new(p.as_str().to_owned()))
        }
        DecryptMethod::AgeIdentity(id) => DecryptTarget::AgeIdentity(id.clone()),
        DecryptMethod::SshIdentity(key) => DecryptTarget::SshIdentity(key.clone()),
        DecryptMethod::AutoKey(key) => DecryptTarget::AutoKey(key.clone()),
    };
    encrypt::decrypt_share(armoured, &target)
}

/// Detect whether bytes are age ASCII armour.
///
/// Wraps [`encrypt::is_age_armored`]. Used by the Recover tab to
/// auto-detect armoured shares on paste / load.
pub fn is_share_armoured(bytes: &[u8]) -> bool {
    encrypt::is_age_armored(bytes)
}

/// Passphrase round-trip self-test.
///
/// Encrypts a known test vector with `pass`, decrypts it, and verifies the
/// plaintext matches. This is a pipeline sanity check run before any
/// passphrase-encrypted file is written. It does NOT catch a passphrase
/// that is typed identically wrong in both fields — that is the job of the
/// confirm field; this just confirms age encrypt/decrypt works end-to-end.
pub fn passphrase_roundtrip_check(pass: &str) -> Result<()> {
    let test_vector = b"pellitory-39 passphrase round-trip check";
    let method = EncryptMethod::Passphrase(Zeroizing::new(pass.to_owned()));
    let armoured = encrypt_single_share_from_bytes(test_vector, &method)?;
    let plain = decrypt_share(
        &armoured,
        &DecryptMethod::Passphrase(Zeroizing::new(pass.to_owned())),
    )?;
    if plain.as_slice() != test_vector {
        return Err(anyhow!(
            "passphrase round-trip self-test failed: plaintext mismatch"
        ));
    }
    Ok(())
}

// ── internal helpers ──────────────────────────────────────────────────────

/// Convert an [`EncryptMethod`] to the crypto-layer [`EncryptTarget`].
fn target_from_method(method: &EncryptMethod) -> EncryptTarget {
    match method {
        EncryptMethod::Passphrase(p) => {
            EncryptTarget::Passphrase(Zeroizing::new(p.as_str().to_owned()))
        }
        EncryptMethod::AgeRecipient(s) => EncryptTarget::AgeRecipient(s.clone()),
        EncryptMethod::SshRecipient(s) => EncryptTarget::SshRecipient(s.clone()),
    }
}

/// Convert a crypto-layer [`EncryptTarget`] back to an [`EncryptMethod`].
fn method_from_target(target: EncryptTarget) -> EncryptMethod {
    match target {
        EncryptTarget::Passphrase(p) => EncryptMethod::Passphrase(p),
        EncryptTarget::AgeRecipient(s) => EncryptMethod::AgeRecipient(s),
        EncryptTarget::SshRecipient(s) => EncryptMethod::SshRecipient(s),
    }
}

/// Encrypt raw bytes (not a share string) — used by the round-trip check.
fn encrypt_single_share_from_bytes(
    bytes: &[u8],
    method: &EncryptMethod,
) -> Result<Zeroizing<Vec<u8>>> {
    let target = target_from_method(method);
    encrypt::encrypt_share(bytes, &target)
}

/// Render a fingerprint in plain words, prefixed by recipient type.
/// The underlying `encrypt::recipient_fingerprint` already returns a
/// prefixed string like `"X25519 abcd"` / `"ssh-ed25519 abcd"`, so we
/// pass it through unchanged.
fn plain_word_fingerprint(_method: &EncryptMethod, fp: &str) -> String {
    fp.to_owned()
}

/// KDF iteration-exponent options exposed to the GUI.
///
/// The spec only exposes "Default (1)" and "High (2)".
pub const ITERATION_OPTIONS: &[u8] = &[1, 2];

/// Result of a duress wallet generation.
pub struct DuressResult {
    /// Real wallet shares, one mnemonic per line.
    pub real_shares: Zeroizing<String>,
    /// Decoy wallet shares, one mnemonic per line (`""` if no decoy).
    pub decoy_shares: Zeroizing<String>,
    /// Real wallet Monero keys (only set for the Monero tab).
    pub real_monero: Option<MoneroRecovery>,
    /// Decoy wallet Monero keys (only set for the Monero tab).
    pub decoy_monero: Option<MoneroRecovery>,
}

/// A recovered Monero wallet (keys + address), for display.
pub struct MoneroRecovery {
    pub mnemonic: Zeroizing<String>,
    pub spend_key: Zeroizing<String>,
    pub view_key: Zeroizing<String>,
    pub address: String,
}

impl Drop for MoneroRecovery {
    fn drop(&mut self) {
        self.address.zeroize();
    }
}

/// Result of splitting an existing secret into SLIP-0039 shares.
pub struct SplitResult {
    /// Formatted shares, one mnemonic per line with comment headers.
    pub shares: Zeroizing<String>,
    /// The auto-detected input kind, for display.
    pub detected_kind: InputKind,
    /// Monero keys for verification (only if the input was a Monero
    /// spend key / mnemonic, or hex input with the Monero coin tab).
    pub monero: Option<MoneroRecovery>,
    /// Decoy wallet shares (empty when no decoy was requested).
    pub decoy_shares: Zeroizing<String>,
    /// Decoy Monero keys for verification (None when no decoy or Bitcoin).
    pub decoy_monero: Option<MoneroRecovery>,
}

/// Recovered wallet output for the Recover tab.
pub enum RecoveryResult {
    /// Bitcoin: a 24-word BIP-39 mnemonic.
    Bip39(Zeroizing<String>),
    /// Monero: full key set.
    Monero(MoneroRecovery),
}

/// Generate 32 bytes of cryptographically secure random entropy (BIP-39
/// 256-bit / Monero spend key). Wrapped in `Zeroizing`.
fn random_secret() -> Zeroizing<Vec<u8>> {
    let mut buf = Zeroizing::new(vec![0u8; 32]);
    OsRng.fill_bytes(&mut buf);
    buf
}

/// Wipe a `Vec<String>` of share mnemonics after they have been copied
/// into a `Zeroizing` buffer by [`format_shares`]. Each share is
/// secret-equivalent above the threshold, so its owned `String` must be
/// explicitly zeroized — ordinary `Drop` for `String` only frees the
/// heap buffer without overwriting it.
#[allow(dead_code)]
fn zeroize_mnemonics(mut mnemonics: Vec<String>) {
    for m in mnemonics.iter_mut() {
        m.zeroize();
    }
}

/// Format a list of share mnemonics as a single string, one per line,
/// with a leading header recording the threshold so the user knows how
/// many shares they need to recover.
fn format_shares(mnemonics: &[Zeroizing<String>], threshold: u8) -> Zeroizing<String> {
    let mut out = String::new();
    out.push_str(&format!(
        "# Pellitory-39 SLIP-0039 shares — {threshold}-of-{} needed to recover.\n",
        mnemonics.len()
    ));
    out.push_str("# One share per line. Keep each share in a separate location.\n");
    for (i, m) in mnemonics.iter().enumerate() {
        out.push_str(&format!("# Share {} of {}\n", i + 1, mnemonics.len()));
        out.push_str(m.as_str());
        out.push('\n');
    }
    Zeroizing::new(out)
}

/// Convert Monero `DerivedKeys` into the GUI's `MoneroRecovery`.
fn monero_keys(keys: &monero::DerivedKeys) -> MoneroRecovery {
    MoneroRecovery {
        mnemonic: Zeroizing::new(keys.mnemonic.as_str().to_owned()),
        spend_key: Zeroizing::new(keys.private_spend_key.expose_secret().clone()),
        view_key: Zeroizing::new(keys.private_view_key.expose_secret().clone()),
        address: keys.address.clone(),
    }
}

/// Generate a duress-compatible pair of wallets (Real + Decoy) for the
/// given coin type.
///
/// The Real wallet is split first with a random identifier; the Decoy
/// wallet is then split with the **same** identifier so the first two
/// mnemonic words match across both wallets.
#[allow(clippy::too_many_arguments)]
pub fn generate_duress(
    coin: Coin,
    threshold: u8,
    total_shares: u8,
    iterations: u8,
    real_pass: &str,
    generate_decoy: bool,
    decoy_pass: &str,
) -> Result<DuressResult> {
    if threshold == 0 || total_shares == 0 {
        return Err(anyhow!("threshold and total shares must be at least 1"));
    }
    if threshold > total_shares {
        return Err(anyhow!(
            "threshold ({threshold}) cannot exceed total shares ({total_shares})"
        ));
    }
    // Empty passwords are allowed — the GUI warns the user first.

    let groups = [(threshold, total_shares)];

    // --- Real wallet ---
    let real_secret = random_secret();
    let real_master = sharing::MasterSecret::from_bytes(&real_secret);
    let real_output = sharing::Slip39Output::split_with_identifier(
        1,
        &groups,
        &real_master,
        real_pass,
        iterations,
        false, // ext = 0 (default, matches CLI default)
        None,  // random identifier
    )?;
    let identifier = real_output.identifier();
    let real_mnemonics = real_output.all_mnemonics();
    let real_shares = format_shares(&real_mnemonics, threshold);
    // real_mnemonics is Vec<Zeroizing<String>>: each share is wiped on drop
    // at the end of this scope, so the explicit zeroize_mnemonics helper is
    // no longer needed here.
    drop(real_mnemonics);

    let real_monero = match coin {
        Coin::Bitcoin => None,
        Coin::Monero => {
            let hex_secret = Zeroizing::new(hex::encode(&*real_secret));
            let keys = monero::derive_keys(&hex_secret)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            Some(monero_keys(&keys))
        }
    };

    // --- Decoy wallet (optional) ---
    let (decoy_shares, decoy_monero) = if generate_decoy {
        let decoy_secret = random_secret();
        let decoy_master = sharing::MasterSecret::from_bytes(&decoy_secret);
        let decoy_output = sharing::Slip39Output::split_with_identifier(
            1,
            &groups,
            &decoy_master,
            decoy_pass,
            iterations,
            false,
            Some(identifier), // force the Real wallet's identifier
        )?;
        let decoy_mnemonics = decoy_output.all_mnemonics();
        let decoy_shares = format_shares(&decoy_mnemonics, threshold);
        drop(decoy_mnemonics);

        let decoy_monero = match coin {
            Coin::Bitcoin => None,
            Coin::Monero => {
                let hex_secret = Zeroizing::new(hex::encode(&*decoy_secret));
                let keys = monero::derive_keys(&hex_secret)
                    .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
                Some(monero_keys(&keys))
            }
        };
        (decoy_shares, decoy_monero)
    } else {
        (Zeroizing::new(String::new()), None)
    };

    Ok(DuressResult {
        real_shares,
        decoy_shares,
        real_monero,
        decoy_monero,
    })
}

/// Recover a wallet from pasted share text (one share per line) and a
/// password.
///
/// Lines beginning with `#` and blank lines are ignored, so the output of
/// [`format_shares`] can be pasted back directly.
pub fn recover(coin: Coin, shares_text: &str, password: &str) -> Result<RecoveryResult> {
    let word_lists = parse_shares_text(shares_text)?;
    if word_lists.is_empty() {
        return Err(anyhow!("no shares provided"));
    }

    let recovered = sharing::combine(&word_lists, password)?;

    match coin {
        Coin::Bitcoin => {
            let mnemonic = bip39::Mnemonic::from_entropy(&recovered, bip39::Language::English)
                .map_err(|e| anyhow!("BIP-39 encoding failed: {e}"))?;
            let phrase = mnemonic.into_phrase();
            Ok(RecoveryResult::Bip39(Zeroizing::new(phrase)))
        }
        Coin::Monero => {
            let hex_str = Zeroizing::new(hex::encode(&*recovered));
            let keys = monero::derive_keys(&hex_str)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            Ok(RecoveryResult::Monero(monero_keys(&keys)))
        }
    }
}

/// Information about pasted share text, for live display in the
/// Recover tab ("3 of 5 shares pasted").
#[derive(Clone, Default)]
pub struct ShareCountInfo {
    /// Number of non-empty, non-comment lines parsed.
    pub count: usize,
    /// Member threshold from the first share, if it could be inspected.
    pub member_threshold: Option<u8>,
    /// Group threshold from the first share, if it could be inspected.
    pub group_threshold: Option<u8>,
    /// Total number of groups, if it could be inspected.
    pub group_count: Option<u8>,
}

/// Parse pasted share text into the `Vec<Vec<String>>` the combine API
/// expects. Strips comments (`#`) and blank lines.
fn parse_shares_text(text: &str) -> Result<Vec<Vec<String>>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let words: Vec<String> = line.split_whitespace().map(str::to_owned).collect();
        if words.is_empty() {
            continue;
        }
        out.push(words);
    }
    Ok(out)
}

/// Analyse pasted share text for live display in the Recover tab.
///
/// Returns the number of shares parsed and, if the first share can be
/// inspected, the threshold information so the GUI can show
/// "3 of 5 shares pasted".
pub fn analyse_shares(text: &str) -> ShareCountInfo {
    let word_lists = parse_shares_text(text).unwrap_or_default();
    let count = word_lists.len();
    if count == 0 {
        return ShareCountInfo {
            count: 0,
            member_threshold: None,
            group_threshold: None,
            group_count: None,
        };
    }
    match sharing::inspect(&word_lists[0]) {
        Ok(meta) => ShareCountInfo {
            count,
            member_threshold: Some(meta.member_threshold),
            group_threshold: Some(meta.group_threshold),
            group_count: Some(meta.group_count),
        },
        Err(_) => ShareCountInfo {
            count,
            member_threshold: None,
            group_threshold: None,
            group_count: None,
        },
    }
}

/// Split an existing secret (Monero spend key, Monero mnemonic, or
/// BIP-39 mnemonic) into SLIP-0039 shares.
///
/// The input format is auto-detected via [`detect_and_normalise`].
/// When `coin` is [`Coin::Monero`] and the input is hex (or a Monero
/// mnemonic), the full Monero key set is derived and returned for
/// verification.
///
/// When `generate_decoy` is true, a second set of shares is produced from
/// a *different* (random) secret split with `decoy_pass` but forced to reuse
/// the Real wallet's SLIP-0039 identifier, so the two share sets are
/// indistinguishable by their metadata prefix (duress / plausible
/// deniability). The decoy recovers to a throwaway wallet, not the real
/// one.
#[allow(clippy::too_many_arguments)]
pub fn split_existing(
    coin: Coin,
    secret_input: &str,
    threshold: u8,
    total_shares: u8,
    iterations: u8,
    password: &str,
    generate_decoy: bool,
    decoy_pass: &str,
) -> Result<SplitResult> {
    if threshold == 0 || total_shares == 0 {
        return Err(anyhow!("threshold and total shares must be at least 1"));
    }
    if threshold > total_shares {
        return Err(anyhow!(
            "threshold ({threshold}) cannot exceed total shares ({total_shares})"
        ));
    }

    let (kind, hex_secret) = detect_and_normalise(secret_input)?;

    // Derive Monero keys for verification when the input is Monero-related
    // or when the Monero coin tab is selected with hex input.
    let monero = match kind {
        InputKind::MoneroMnemonic => {
            let keys = monero::derive_keys(&hex_secret)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            Some(monero_keys(&keys))
        }
        InputKind::Hex if coin == Coin::Monero => {
            let keys = monero::derive_keys(&hex_secret)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            Some(monero_keys(&keys))
        }
        _ => None,
    };

    let master = sharing::MasterSecret::from_hex(&hex_secret)?;
    let groups = [(threshold, total_shares)];
    let output = sharing::Slip39Output::split_with_identifier(
        1,
        &groups,
        &master,
        password,
        iterations,
        false,
        None,
    )?;
    let identifier = output.identifier();
    let mnemonics = output.all_mnemonics();
    let shares = format_shares(&mnemonics, threshold);
    drop(mnemonics);

    // --- Decoy wallet (optional) ---
    let (decoy_shares, decoy_monero) = if generate_decoy {
        let decoy_secret = random_secret();
        let decoy_hex = Zeroizing::new(hex::encode(&*decoy_secret));
        let decoy_master = sharing::MasterSecret::from_bytes(&decoy_secret);
        let decoy_output = sharing::Slip39Output::split_with_identifier(
            1,
            &groups,
            &decoy_master,
            decoy_pass,
            iterations,
            false,
            Some(identifier), // force the Real wallet's identifier
        )?;
        let decoy_mnemonics = decoy_output.all_mnemonics();
        let decoy_shares = format_shares(&decoy_mnemonics, threshold);
        drop(decoy_mnemonics);

        let decoy_monero = match coin {
            Coin::Bitcoin => None,
            Coin::Monero => {
                let keys = monero::derive_keys(&decoy_hex)
                    .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
                Some(monero_keys(&keys))
            }
        };
        (decoy_shares, decoy_monero)
    } else {
        (Zeroizing::new(String::new()), None)
    };

    Ok(SplitResult {
        shares,
        detected_kind: kind,
        monero,
        decoy_shares,
        decoy_monero,
    })
}

/// Which coin the GUI is operating on.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Coin {
    Bitcoin,
    Monero,
}

/// Result of the Derive tab: a BIP-39 phrase (Bitcoin) or a full Monero
/// key set (Monero).
pub enum DeriveResult {
    /// Bitcoin / Ethereum: a 12/15/18/21/24-word BIP-39 mnemonic derived
    /// from raw hex entropy.
    Bip39(Zeroizing<String>),
    /// Monero: the full key set + address, derived from a spend key or
    /// 25-word mnemonic.
    Monero(MoneroRecovery),
}

/// Derive a phrase / key set from raw material for the given coin.
///
/// * **Bitcoin** — `input` is raw hex entropy (16/20/24/28/32 bytes); a
///   BIP-39 mnemonic phrase is returned via [`derive_bip39_mnemonic`].
/// * **Monero** — `input` is a 64-char hex spend key or a 25-word Monero
///   mnemonic; the full key set is returned via [`monero::derive_keys`].
///
/// All secret material is wrapped in `Zeroizing` and wiped on drop. This
/// function performs **no** SLIP-0039 splitting — it is the standalone
/// "derive" path that mirrors the CLI `derive` command.
pub fn derive(coin: Coin, input: &str) -> Result<DeriveResult> {
    match coin {
        Coin::Bitcoin => {
            let trimmed = input.trim();
            if trimmed.is_empty() {
                return Err(anyhow!("no entropy provided"));
            }
            if !trimmed.len().is_multiple_of(2)
                || !trimmed.chars().all(|c| c.is_ascii_hexdigit())
            {
                return Err(anyhow!(
                    "BIP-39 entropy must be an even number of hex digits (got {} chars)",
                    trimmed.len()
                ));
            }
            let mut bytes = Zeroizing::new(hex::decode(trimmed)?);
            let phrase = derive_bip39_mnemonic(&bytes)?;
            bytes.zeroize();
            Ok(DeriveResult::Bip39(phrase))
        }
        Coin::Monero => {
            let keys = monero::derive_keys(input)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            Ok(DeriveResult::Monero(monero_keys(&keys)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The first two words of every SLIP-0039 share encode
    /// `identifier || ext || iteration_exponent`. For the duress protocol to
    /// work, Real and Decoy shares must share these first two words.
    fn first_two_words(mnemonic: &str) -> Vec<String> {
        mnemonic
            .split_whitespace()
            .take(2)
            .map(str::to_owned)
            .collect()
    }

    #[test]
    fn duress_shares_match_prefix() {
        let result = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "real-password",
            true,
            "decoy-password",
        )
        .expect("generation should succeed");

        let real_lines: Vec<&str> = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();
        let decoy_lines: Vec<&str> = result
            .decoy_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .collect();

        assert_eq!(real_lines.len(), 3, "should produce 3 real shares");
        assert_eq!(decoy_lines.len(), 3, "should produce 3 decoy shares");

        // Every real share's first two words must match every decoy share's
        // first two words — that's the entire point of the duress protocol.
        let real_prefix = first_two_words(real_lines[0]);
        for line in &real_lines {
            assert_eq!(first_two_words(line), real_prefix, "real shares must share a prefix");
        }
        for line in &decoy_lines {
            assert_eq!(first_two_words(line), real_prefix, "decoy shares must match real prefix");
        }
    }

    #[test]
    fn recover_bip39_roundtrip() {
        let result = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "real-password",
            false, // no decoy needed for roundtrip
            "",
        )
        .expect("generation should succeed");

        // Extract just the share lines (strip comments).
        let shares_text: String = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(|l| format!("{l}\n"))
            .collect();

        // Take exactly the threshold (2) shares.
        let two_shares: String = shares_text
            .lines()
            .take(2)
            .map(|l| format!("{l}\n"))
            .collect();

        let recovery = recover(Coin::Bitcoin, &two_shares, "real-password")
            .expect("recovery should succeed");

        match recovery {
            RecoveryResult::Bip39(phrase) => {
                let words: Vec<&str> = phrase.split_whitespace().collect();
                assert_eq!(words.len(), 24, "should recover a 24-word BIP-39 mnemonic");
            }
            RecoveryResult::Monero(_) => panic!("expected BIP-39 recovery"),
        }
    }

    #[test]
    fn recover_monero_roundtrip() {
        let result = generate_duress(
            Coin::Monero,
            2,
            3,
            1,
            "real-password",
            false,
            "",
        )
        .expect("generation should succeed");

        let two_shares: String = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .take(2)
            .map(|l| format!("{l}\n"))
            .collect();

        let recovery = recover(Coin::Monero, &two_shares, "real-password")
            .expect("recovery should succeed");

        match recovery {
            RecoveryResult::Monero(m) => {
                assert_eq!(m.address.len(), 95, "Monero address should be 95 chars");
                assert!(m.address.starts_with('4'), "mainnet address starts with 4");
            }
            RecoveryResult::Bip39(_) => panic!("expected Monero recovery"),
        }
    }

    #[test]
    fn wrong_password_produces_different_result() {
        // SLIP-0039 has no password-verification mechanism: the digest
        // validates the *encrypted* master secret, not the password. A wrong
        // password therefore produces a *successful* but garbage recovery,
        // not an error. We verify that the garbage differs from the real
        // mnemonic so the GUI's error-classification code is never misled.
        let result = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "real-password",
            false,
            "",
        )
        .expect("generation should succeed");

        let two_shares: String = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .take(2)
            .map(|l| format!("{l}\n"))
            .collect();

        let correct = recover(Coin::Bitcoin, &two_shares, "real-password")
            .expect("recovery with correct password should succeed");
        let wrong = recover(Coin::Bitcoin, &two_shares, "wrong-password")
            .expect("recovery with wrong password also succeeds (garbage)");

        let correct_phrase = match correct {
            RecoveryResult::Bip39(p) => p,
            _ => panic!("expected BIP-39"),
        };
        let wrong_phrase = match wrong {
            RecoveryResult::Bip39(p) => p,
            _ => panic!("expected BIP-39"),
        };

        assert_ne!(
            correct_phrase.as_str(),
            wrong_phrase.as_str(),
            "wrong password must produce a different mnemonic"
        );
    }

    #[test]
    fn mixed_shares_fail() {
        let real = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "real-password",
            false,
            "",
        )
        .expect("generation should succeed");
        let decoy = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "decoy-password",
            false,
            "",
        )
        .expect("generation should succeed");

        // Mix one real and one decoy share — they have different identifiers
        // (different random secrets), so this must fail.
        let real_share = real
            .real_shares
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .unwrap();
        let decoy_share = decoy
            .real_shares
            .lines()
            .find(|l| !l.starts_with('#') && !l.is_empty())
            .unwrap();

        let mixed = format!("{real_share}\n{decoy_share}\n");

        let err = recover(Coin::Bitcoin, &mixed, "real-password")
            .err()
            .expect("mixed shares should fail");

        // Should be a mnemonic error (identifier mismatch).
        let msg = err.to_string().to_lowercase();
        assert!(
            msg.contains("mnemonic") || msg.contains("identifier") || msg.contains("begin"),
            "mixed shares should produce a mnemonic error, got: {msg}"
        );
    }

    #[test]
    fn empty_password_roundtrip() {
        let result = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "", // empty real password
            false,
            "",
        )
        .expect("generation with empty password should succeed");

        let two_shares: String = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .take(2)
            .map(|l| format!("{l}\n"))
            .collect();

        let recovery = recover(Coin::Bitcoin, &two_shares, "")
            .expect("recovery with empty password should succeed");

        match recovery {
            RecoveryResult::Bip39(phrase) => {
                let words: Vec<&str> = phrase.split_whitespace().collect();
                assert_eq!(words.len(), 24);
            }
            RecoveryResult::Monero(_) => panic!("expected BIP-39"),
        }
    }

    // ─── derive() helper (Derive tab) ─────────────────────────────────────

    #[test]
    fn derive_bip39_canonical_all_zero() {
        let r = derive(Coin::Bitcoin, "00000000000000000000000000000000")
            .expect("16-byte all-zero entropy is valid");
        match r {
            DeriveResult::Bip39(p) => assert_eq!(
                p.as_str(),
                "abandon abandon abandon abandon abandon abandon \
                 abandon abandon abandon abandon abandon about"
            ),
            DeriveResult::Monero(_) => panic!("expected BIP-39"),
        }
    }

    #[test]
    fn derive_bip39_32_bytes_is_24_words() {
        let r = derive(Coin::Bitcoin, "abababababababababababababababababababababababababababababababab")
            .expect("32-byte entropy is valid");
        match r {
            DeriveResult::Bip39(p) => {
                assert_eq!(p.split_whitespace().count(), 24);
            }
            DeriveResult::Monero(_) => panic!("expected BIP-39"),
        }
    }

    #[test]
    fn derive_bip39_rejects_bad_hex_and_lengths() {
        assert!(derive(Coin::Bitcoin, "abc").is_err(), "odd hex");
        assert!(derive(Coin::Bitcoin, "00").is_err(), "1 byte too short");
        assert!(
            derive(Coin::Bitcoin, &"0".repeat(66)).is_err(),
            "33 bytes too long"
        );
        assert!(derive(Coin::Bitcoin, "zzzzzzzzzzzzzzzz").is_err(), "non-hex");
        assert!(derive(Coin::Bitcoin, "   ").is_err(), "blank");
    }

    #[test]
    fn derive_monero_known_vector() {
        // Same reference spend key the rest of the suite uses.
        let r = derive(
            Coin::Monero,
            "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206",
        )
        .expect("known spend key derives");
        match r {
            DeriveResult::Monero(m) => {
                assert_eq!(m.address.len(), 95);
                assert!(m.address.starts_with('4'));
                assert_eq!(
                    m.view_key.as_str(),
                    "157874dc4e2961c872f87aaf4346146d0f596e2f116a51fbac01b693a8e3020a"
                );
            }
            DeriveResult::Bip39(_) => panic!("expected Monero"),
        }
    }

    #[test]
    fn derive_monero_from_mnemonic_matches_hex() {
        let mnemonic = "spout midst duckling tepid odds glass enhanced \
            avatar ocean rarest eavesdrop egotistic oxygen trying future airport \
            session nanny tedious guru asylum superior cement cunning eavesdrop";
        let from_hex = derive(
            Coin::Monero,
            "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206",
        )
        .expect("hex derives");
        let from_mnemonic = derive(Coin::Monero, mnemonic).expect("mnemonic derives");
        match (from_hex, from_mnemonic) {
            (DeriveResult::Monero(a), DeriveResult::Monero(b)) => {
                assert_eq!(a.address, b.address);
                assert_eq!(a.spend_key.as_str(), b.spend_key.as_str());
            }
            _ => panic!("expected two Monero results"),
        }
    }

    // ── age encrypt / decrypt wrapper tests (phase 006) ───────────────────

    /// Build a pair of age X25519 recipient / identity for tests by writing
    /// an identity to a temp file via the `age-keygen` binary is not needed —
    /// instead we use a fixed test identity embedded in the encrypt test
    /// fixtures. For the GUI wrappers we only need a recipient string, so we
    /// generate one deterministically from age's test vectors is overkill;
    /// instead, parse a known-good recipient from the fixtures.
    fn test_age_recipient() -> String {
        // A real age1 X25519 recipient generated for the test suite.
        // (Not a secret — public recipient only.)
        std::fs::read_to_string("tests/fixtures/test_age_recipient.txt")
            .expect("test_age_recipient.txt fixture should exist")
            .trim()
            .to_string()
    }

    fn test_ssh_recipient() -> String {
        std::fs::read_to_string("tests/fixtures/test_ed25519.pub")
            .expect("test_ed25519.pub fixture should exist")
            .trim()
            .to_string()
    }

    fn test_age_identity() -> Vec<u8> {
        std::fs::read("tests/fixtures/test_age_identity.txt")
            .expect("test_age_identity.txt fixture should exist")
    }

    fn test_ssh_private_key() -> Vec<u8> {
        std::fs::read("tests/fixtures/test_ed25519")
            .expect("test_ed25519 fixture should exist")
    }

    /// A sample SLIP-0039 share mnemonic (not a real secret).
    fn sample_share() -> &'static str {
        "slider acrobat invite cluster spike moist dean quiz pour cabin trend anatomy"
    }

    #[test]
    fn encrypt_decrypt_passphrase_roundtrip() {
        let method = EncryptMethod::Passphrase(Zeroizing::new("test-pass-42".to_owned()));
        let armoured = encrypt_single_share(sample_share(), &method)
            .expect("passphrase encrypt should succeed");
        assert!(
            is_share_armoured(&armoured),
            "armoured output should be detected as armour"
        );
        let plain = decrypt_share(
            &armoured,
            &DecryptMethod::Passphrase(Zeroizing::new("test-pass-42".to_owned())),
        )
        .expect("passphrase decrypt should succeed");
        assert_eq!(plain.as_slice(), sample_share().as_bytes());
    }

    #[test]
    fn encrypt_decrypt_passphrase_wrong_pass_errors() {
        let method = EncryptMethod::Passphrase(Zeroizing::new("correct-pass".to_owned()));
        let armoured = encrypt_single_share(sample_share(), &method)
            .expect("encrypt should succeed");
        let err = decrypt_share(
            &armoured,
            &DecryptMethod::Passphrase(Zeroizing::new("wrong-pass".to_owned())),
        )
        .expect_err("wrong passphrase should error, not silent garbage");
        assert!(format!("{err}").to_lowercase().contains("decrypt"));
    }

    #[test]
    fn encrypt_decrypt_age_recipient_roundtrip() {
        let recipient = test_age_recipient();
        let method =
            EncryptMethod::AgeRecipient(recipient.clone());
        let armoured = encrypt_single_share(sample_share(), &method)
            .expect("age recipient encrypt should succeed");
        let plain = decrypt_share(
            &armoured,
            &DecryptMethod::AgeIdentity(Zeroizing::new(test_age_identity())),
        )
        .expect("age identity decrypt should succeed");
        assert_eq!(plain.as_slice(), sample_share().as_bytes());
    }

    #[test]
    fn encrypt_decrypt_ssh_roundtrip() {
        let recipient = test_ssh_recipient();
        let method =
            EncryptMethod::SshRecipient(recipient.clone());
        let armoured = encrypt_single_share(sample_share(), &method)
            .expect("ssh recipient encrypt should succeed");
        let plain = decrypt_share(
            &armoured,
            &DecryptMethod::SshIdentity(Zeroizing::new(test_ssh_private_key())),
        )
        .expect("ssh identity decrypt should succeed");
        assert_eq!(plain.as_slice(), sample_share().as_bytes());
    }

    #[test]
    fn parse_recipient_valid_age() {
        let m = parse_recipient(&test_age_recipient()).expect("valid age recipient parses");
        assert!(matches!(m, EncryptMethod::AgeRecipient(_)));
    }

    #[test]
    fn parse_recipient_valid_ssh() {
        let m = parse_recipient(&test_ssh_recipient()).expect("valid ssh recipient parses");
        assert!(matches!(m, EncryptMethod::SshRecipient(_)));
    }

    #[test]
    fn parse_recipient_invalid_errors() {
        parse_recipient("not-a-recipient").expect_err("garbage should not parse");
    }

    #[test]
    fn recipient_fingerprint_passphrase_is_none() {
        let m = EncryptMethod::Passphrase(Zeroizing::new("p".to_owned()));
        assert_eq!(recipient_fingerprint(&m), None);
    }

    #[test]
    fn recipient_fingerprint_age_is_some() {
        let m = EncryptMethod::AgeRecipient(test_age_recipient());
        assert!(recipient_fingerprint(&m).is_some());
    }

    #[test]
    fn recipient_fingerprint_ssh_is_some() {
        let m = EncryptMethod::SshRecipient(test_ssh_recipient());
        assert!(recipient_fingerprint(&m).is_some());
    }

    #[test]
    fn build_bulk_zip_returns_valid_zip() {
        // 2 shares, bulk passphrase -> ZIP with per-share .age entries.
        let shares = vec![
            Zeroizing::new(sample_share().to_owned()),
            Zeroizing::new(sample_share().to_owned()),
        ];
        let methods = vec![
            EncryptMethod::Passphrase(Zeroizing::new("zip-pass".to_owned())),
            EncryptMethod::Passphrase(Zeroizing::new("zip-pass".to_owned())),
        ];
        let zip = build_bulk_export(&shares, &methods, BulkPackage::Zip, 2)
            .expect("zip export should succeed");
        // ZIP magic.
        assert_eq!(&zip[..2], b"PK");
        // Contains the share1 entry name.
        let zip_str = String::from_utf8_lossy(&zip);
        assert!(zip_str.contains("share1.txt.age"));
        assert!(zip_str.contains("README.txt"));
    }

    #[test]
    fn build_bulk_one_file_returns_armour() {
        let shares = vec![
            Zeroizing::new(sample_share().to_owned()),
            Zeroizing::new(sample_share().to_owned()),
        ];
        let methods = vec![EncryptMethod::Passphrase(Zeroizing::new("of-pass".to_owned()))];
        let blob = build_bulk_export(&shares, &methods, BulkPackage::OneFile, 2)
            .expect("one-file export should succeed");
        assert!(is_share_armoured(&blob), "one-file blob should be armoured");
    }

    #[test]
    fn decrypt_then_recover_roundtrip() {
        // Full pipeline: split -> encrypt each share as armour -> decrypt ->
        // combine via `recover`.
        let result = generate_duress(
            Coin::Bitcoin,
            2,
            3,
            1,
            "split-pass",
            false,
            "",
        )
        .expect("generation should succeed");
        let shares: Vec<String> = result
            .real_shares
            .lines()
            .filter(|l| !l.starts_with('#') && !l.is_empty())
            .map(str::to_owned)
            .collect();
        assert_eq!(shares.len(), 3);

        // Encrypt each share with a passphrase.
        let method = EncryptMethod::Passphrase(Zeroizing::new("age-pass".to_owned()));
        let armoured: Vec<Vec<u8>> = shares
            .iter()
            .map(|s| encrypt_single_share(s, &method).expect("encrypt"))
            .map(|z| z.to_vec())
            .collect();

        // Decrypt two shares and combine.
        let decrypt_method =
            DecryptMethod::Passphrase(Zeroizing::new("age-pass".to_owned()));
        let mut plain_shares = String::new();
        for arm in &armoured[..2] {
            let plain = decrypt_share(arm, &decrypt_method).expect("decrypt");
            plain_shares.push_str(std::str::from_utf8(&plain).unwrap());
            plain_shares.push('\n');
        }

        let recovery = recover(Coin::Bitcoin, &plain_shares, "split-pass")
            .expect("recovery should succeed");
        match recovery {
            RecoveryResult::Bip39(phrase) => {
                let words: Vec<&str> = phrase.split_whitespace().collect();
                assert_eq!(words.len(), 24, "should recover a 24-word mnemonic");
            }
            RecoveryResult::Monero(_) => panic!("expected BIP-39"),
        }
    }

    #[test]
    fn passphrase_roundtrip_check_ok() {
        passphrase_roundtrip_check("any-passphrase").expect("round-trip check should pass");
    }

    #[test]
    fn is_share_armoured_detects_armour() {
        let method = EncryptMethod::Passphrase(Zeroizing::new("p".to_owned()));
        let armoured = encrypt_single_share(sample_share(), &method).unwrap();
        assert!(is_share_armoured(&armoured));
        assert!(!is_share_armoured(sample_share().as_bytes()));
    }
}
