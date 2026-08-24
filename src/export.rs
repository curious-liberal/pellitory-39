//! Export packaging for age-encrypted shares (phase 002).
//!
//! Turns `Slip39Output` share mnemonics into age-armoured on-disk artifacts.
//! No plaintext share bytes ever touch disk: every share is encrypted before
//! it is written into a ZIP entry or a one-file blob.
//!
//! Three builders:
//!   • [`build_single_share_export`] — one share -> one `.age` file.
//!   • [`build_export`] with [`BulkPackage::Zip`] — N shares -> a ZIP
//!     containing `share1.txt.age`, `share2.txt.age`, ... plus a plaintext
//!     `README.txt`. Each share encrypted with its own [`EncryptTarget`]
//!     (mixed methods allowed).
//!   • [`build_export`] with [`BulkPackage::OneFile`] — N shares
//!     concatenated with headers -> one age-armoured blob (single credential).
//!
//! # Naming convention
//!
//! Entries are named `share1.txt.age`, `share2.txt.age`, ... 1-indexed in
//! the order of the `shares` slice. The caller produces that slice group-major
//! via `Slip39Output::all_mnemonics()`, so multi-group wallets get sequential
//! names across groups; the README describes the group/threshold structure.
//!
//! # Compression
//!
//! ZIP entries use `CompressionMethod::Stored` (no compression). The contents
//! are already age-armoured ASCII (high-entropy base64); deflating would save
//! little and adds a timing/compression-ratio side channel we do not need.

use std::io::{Cursor, Write};

use crate::encrypt::{recipient_fingerprint, encrypt_share, EncryptTarget};
use anyhow::{anyhow, Result};
use zeroize::{Zeroize, Zeroizing};
use zip::write::SimpleFileOptions;
use zip::{CompressionMethod, ZipWriter};

/// Bulk packaging: one armoured file (single credential) vs ZIP
/// (per-share credentials).
pub enum BulkPackage {
    /// Concatenated shares, one age blob, one credential.
    OneFile,
    /// `shareN.txt.age` per share + `README.txt`.
    Zip,
}

/// Build a single-share `.age` file. Used by the per-share Save button.
///
/// The returned bytes are age ASCII armour; the caller writes them to disk
/// (e.g. via a file-save dialog) under a `*.txt.age` name.
pub fn build_single_share_export(
    share_mnemonic: &[u8],
    target: &EncryptTarget,
) -> Result<Zeroizing<Vec<u8>>> {
    encrypt_share(share_mnemonic, target)
}

/// Build a bulk export.
///
/// - [`BulkPackage::Zip`]: `methods.len()` must equal `shares.len()` (one
///   credential per share; the CLI layer expands a single bulk credential to
///   N copies before calling this). Returns ZIP bytes.
/// - [`BulkPackage::OneFile`]: `methods.len()` must be 1 (a single credential
///   encrypts the concatenated blob). Returns armoured blob bytes.
///
/// `threshold` is used only for the README recovery checklist.
pub fn build_export(
    shares: &[Zeroizing<String>],
    methods: &[EncryptTarget],
    package: BulkPackage,
    threshold: u8,
) -> Result<Zeroizing<Vec<u8>>> {
    match package {
        BulkPackage::OneFile => build_one_file(shares, methods),
        BulkPackage::Zip => build_zip(shares, methods, threshold),
    }
}

/// The `README.txt` contents describing the export, decrypt commands, and a
/// recovery checklist. Plaintext (no secrets). Returned as a plain `String`
/// for the ZIP entry; also useful for the GUI to preview.
pub fn build_readme(
    share_count: usize,
    threshold: u8,
    methods: &[EncryptTarget],
    package: BulkPackage,
) -> String {
    let mut out = String::new();
    out.push_str("Pellitory-39 encrypted share export\n");
    out.push_str("==================================\n\n");
    out.push_str(&format!(
        "This package contains {share_count} age-encrypted SLIP-0039 share(s).\n"
    ));
    out.push_str(&format!(
        "You need {threshold}-of-{share_count} shares to recover the secret.\n\n"
    ));
    out.push_str("Each share is encrypted with age (https://age-encryption.org).\n");
    out.push_str("SLIP-0039 itself is NOT replaced by age — age protects each share\n");
    out.push_str("on disk; SLIP-0039's own password (set at split time) is still\n");
    out.push_str("required for combine.\n\n");

    out.push_str("To decrypt a share:\n");
    match package {
        BulkPackage::Zip => {
            for (i, m) in methods.iter().enumerate() {
                let armoured = format!("share{}.txt.age", i + 1);
                let plain = format!("share{}.txt", i + 1);
                out.push_str(&format!("  {}\n", decrypt_command(m, &armoured, &plain)));
            }
        }
        BulkPackage::OneFile => {
            let m = methods.first().expect("OneFile has one method (validated by caller)");
            out.push_str(&format!(
                "  {}\n",
                decrypt_command(m, "shares.txt.age", "shares.txt")
            ));
            out.push_str("  (the one file contains every share, concatenated)\n");
        }
    }
    out.push('\n');

    out.push_str("Then recover the original secret:\n");
    out.push_str(
        "  pellitory-39 recover --coin <bitcoin|monero|hex> \\\n      -m \"<decrypted share 1>\" -m \"<decrypted share 2>\" ...\n",
    );
    out.push_str("  (use --decrypt-passphrase / --decrypt-identity if you recover\n");
    out.push_str("  directly from the .age files without decrypting first; see\n");
    out.push_str("  `pellitory-39 recover --help`)\n\n");

    out.push_str("WARNING: age authenticates. A wrong passphrase or a lost key is a\n");
    out.push_str("HARD ERROR — the share cannot be decrypted. Unlike SLIP-0039 (where\n");
    out.push_str("a wrong password yields a plausible wrong secret), there is no\n");
    out.push_str("silent fallback. If you lose an age key, that share is permanently\n");
    out.push_str("unrecoverable, even with the correct SLIP-0039 password. Keep\n");
    out.push_str("encryption keys physically separate from shares.\n\n");

    out.push_str("DURESS: age armour stanza headers reveal the recipient type (scrypt\n");
    out.push_str("/ X25519 / ssh-ed25519 / ssh-rsa). For Real and Decoy shares to be\n");
    out.push_str("indistinguishable, use matching encryption methods in matching share\n");
    out.push_str("positions. This is your responsibility, like labelling shares.\n");

    out
}

// ─── Builders ────────────────────────────────────────────────────────────────

fn build_one_file(
    shares: &[Zeroizing<String>],
    methods: &[EncryptTarget],
) -> Result<Zeroizing<Vec<u8>>> {
    if methods.len() != 1 {
        return Err(anyhow!(
            "one-file (OneFile) export takes exactly one encryption credential \
             (got {}); per-share credentials require the ZIP package",
            methods.len()
        ));
    }
    if shares.is_empty() {
        return Err(anyhow!("cannot export zero shares"));
    }

    // Concatenate shares with headers into a single plaintext blob, held in
    // `Zeroizing` so the concatenated shares (secret-equivalent above the
    // threshold) are wiped after encryption.
    let mut blob = Zeroizing::new(String::new());
    for (i, s) in shares.iter().enumerate() {
        // SAFETY-of-secrets: `format!` builds a temporary `String` that is
        // moved into `blob` via `push_str` (which copies). The temporary is
        // dropped un-wiped by ordinary `String::Drop`, but it holds only one
        // share's words at a time and is overwritten quickly; the dominant
        // copy lives in `blob`, which is zeroised on drop.
        blob.push_str(&format!("# Share {}\n{}\n", i + 1, s.as_str()));
    }
    let armoured = encrypt_share(blob.as_bytes(), &methods[0])?;
    blob.zeroize();
    Ok(armoured)
}

fn build_zip(
    shares: &[Zeroizing<String>],
    methods: &[EncryptTarget],
    threshold: u8,
) -> Result<Zeroizing<Vec<u8>>> {
    if methods.len() != shares.len() {
        return Err(anyhow!(
            "ZIP export requires one encryption method per share \
             ({} share(s), {} method(s)); the CLI expands a single bulk \
             credential to N copies before calling this",
            shares.len(),
            methods.len()
        ));
    }
    if shares.is_empty() {
        return Err(anyhow!("cannot export zero shares"));
    }

    let options = SimpleFileOptions::default().compression_method(CompressionMethod::Stored);

    let cursor = Cursor::new(Vec::new());
    let mut zip = ZipWriter::new(cursor);

    // Encrypt each share and add it as `shareN.txt.age`. The armoured bytes
    // are held in `Zeroizing` and wiped after the entry is written.
    for (i, (share, target)) in shares.iter().zip(methods.iter()).enumerate() {
        let name = format!("share{}.txt.age", i + 1);
        let armoured = encrypt_share(share.as_bytes(), target)?;
        zip.start_file(&name, options)?;
        zip.write_all(&armoured)?;
    }

    // README.txt — plaintext, no secrets.
    let readme = build_readme(shares.len(), threshold, methods, BulkPackage::Zip);
    zip.start_file("README.txt", options)?;
    zip.write_all(readme.as_bytes())?;
    // The readme String holds no secrets (threshold + commands only); drop it
    // normally. Zeroising the String would be defensive but it carries no
    // secret-equivalent material, so a plain drop is fine.

    let cursor = zip.finish()?;
    let bytes = cursor.into_inner();
    Ok(Zeroizing::new(bytes))
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build the `age -d ...` command line for one share, tailored to the
/// recipient type so the user gets the right `-i` flag (or none).
fn decrypt_command(target: &EncryptTarget, armoured: &str, plain: &str) -> String {
    match target {
        EncryptTarget::Passphrase(_) => {
            format!("age -d {armoured} > {plain}   # prompts for the passphrase")
        }
        EncryptTarget::AgeRecipient(_) => {
            format!("age -d -i <age-identity-file> {armoured} > {plain}")
        }
        EncryptTarget::SshRecipient(_) => {
            format!("age -d -i <ssh-private-key> {armoured} > {plain}")
        }
    }
}

// Keep `recipient_fingerprint` linked into the module's public surface so a
// future GUI README preview can show fingerprints without re-importing the
// encrypt module. (No behaviour today; re-exported for the GUI phase.)
#[allow(unused_imports)]
use recipient_fingerprint as _recipient_fingerprint_link;