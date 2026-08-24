//! age encryption for share export (phase 001).
//!
//! This module is the **only** place that imports the `age` crate, so
//! `#![forbid(unsafe_code)]` in `src/lib.rs` stays clean and the audited
//! crypto boundary is confined to one file.
//!
//! Three recipient types are supported, matching the age spec:
//!   • Passphrase (scrypt) — `EncryptTarget::Passphrase`
//!   • X25519 (`age1...`)  — `EncryptTarget::AgeRecipient`
//!   • SSH (Ed25519/RSA)   — `EncryptTarget::SshRecipient`
//!
//! All output is **ASCII-armoured** (`-----BEGIN AGE ENCRYPTED FILE-----`),
//! so every exported share is text-safe and self-describing on disk.
//!
//! All credentials (passphrases, identity-file bytes) are held in
//! `Zeroizing` and wiped on drop at Pellitory's boundary. `age` 0.12
//! itself zeroises most of its internal state via the `secrecy` crate
//! (`SecretBox`/`SecretString` with `Drop`) and manual `Drop` impls://!   • Passphrase → `SecretString` (zeroised on drop)
//!   • `FileKey` → `SecretBox<[u8; 16]>` (zeroised on drop)
//!   • `HmacKey` → `SecretBox<[u8; 32]>` (zeroised on drop)
//!   • `PayloadKey` (ChaCha20Poly1305 stream key) → manual `Drop` + `zeroize`
//!   • SSH Ed25519 key material → `SecretBox<[u8; 64]>` (zeroised on drop)
//!   • RSA private key → `rsa::RsaPrivateKey` has a `Drop` impl
//!
//! The one genuine gap: `age` depends on `x25519-dalek` with
//! `features = ["static_secrets"]` but does **not** enable the `zeroize`
//! cargo feature, so `x25519_dalek::StaticSecret` (the 32-byte private
//! scalar) and `SharedSecret` (the DH output) are **not** zeroised on
//! drop — their `#[cfg_attr(feature = "zeroize", zeroize(drop))]` attrs
//! are inactive. This affects the X25519 and SSH-Ed25519 recipient paths
//! (both do an X25519 DH). age manually `.zeroize()`s the bech32 decode
//! buffer and the decrypted file-key plaintext, but not the scalar or
//! the shared secret. This is documented as residual risk 7 in
//! SECURITY.md. We do not fork upstream.

use std::io::Read;
use std::str::FromStr;

use anyhow::{anyhow, Result};
use zeroize::Zeroizing;

/// The ASCII-armour begin marker. Every share that leaves pellitory via a
/// file starts with this line, so [`is_age_armored`] uses it as the
/// cheap prefix check. (The plan text mentioned `age-encryption.org/v1`,
/// but that is the *binary* age header; in armoured output it is
/// base64-encoded inside the body and not visible as plaintext. The
/// visible plaintext marker of an armoured file is the BEGIN line below.)
const ARMOR_BEGIN: &[u8] = b"-----BEGIN AGE ENCRYPTED FILE-----";

/// One share's encryption target. Lives in `Zeroizing` when held.
///
/// `Clone` is derived so the CLI's bulk-mode path can replicate a single
/// target across N shares before calling `build_export` (the ZIP builder
/// requires one method per share). Cloning a `Passphrase` clones the
/// `Zeroizing<String>` — both copies are zeroised on drop.
#[derive(Clone)]
pub enum EncryptTarget {
    /// Encrypt with a passphrase (age scrypt recipient).
    Passphrase(Zeroizing<String>),
    /// Encrypt to an X25519 recipient (`age1...`).
    AgeRecipient(String),
    /// Encrypt to an SSH recipient (`ssh-ed25519 ...` / `ssh-rsa ...`).
    SshRecipient(String),
}

/// One share's decryption credential.
pub enum DecryptTarget {
    /// Decrypt with a passphrase (age scrypt identity).
    Passphrase(Zeroizing<String>),
    /// Decrypt with an age identity file's contents (`AGE-SECRET-KEY-1...`).
    AgeIdentity(Zeroizing<Vec<u8>>),
    /// Decrypt with an SSH private key file's contents (OpenSSH format).
    SshIdentity(Zeroizing<Vec<u8>>),
    /// Auto-detect: try age identity first, then SSH private key. Used
    /// by the GUI decrypt popup when the user picks "age / SSH key" —
    /// the key format is sniffed rather than forcing the user to choose.
    AutoKey(Zeroizing<Vec<u8>>),
}

/// Autodetect a recipient string: `age1...` -> `AgeRecipient`,
/// `ssh-...` -> `SshRecipient`, else error.
///
/// The recipient is validated by attempting to parse it with the matching
/// `age` parser, so a malformed string fails here rather than at encrypt
/// time.
pub fn parse_recipient(s: &str) -> Result<EncryptTarget> {
    let s = s.trim();
    if s.is_empty() {
        anyhow::bail!("empty recipient string");
    }
    if s.starts_with("age1") {
        let _ = age::x25519::Recipient::from_str(s)
            .map_err(|e| anyhow!("invalid age (X25519) recipient: {e}"))?;
        Ok(EncryptTarget::AgeRecipient(s.to_string()))
    } else if s.starts_with("ssh-") {
        let _ = age::ssh::Recipient::from_str(s)
            .map_err(|e| anyhow!("invalid SSH recipient: {e:?}"))?;
        Ok(EncryptTarget::SshRecipient(s.to_string()))
    } else {
        anyhow::bail!(
            "unrecognised recipient: expected an 'age1...' X25519 recipient \
             or an 'ssh-ed25519 ...' / 'ssh-rsa ...' SSH public key"
        )
    }
}

/// Encrypt `plaintext` to age ASCII armour for the given target.
///
/// Returns the armoured bytes wrapped in [`Zeroizing`] — the armour itself
/// is not secret, but keeping it in `Zeroizing` is defensive and uniform
/// with the rest of the export pipeline.
pub fn encrypt_share(plaintext: &[u8], target: &EncryptTarget) -> Result<Zeroizing<Vec<u8>>> {
    let armoured = match target {
        EncryptTarget::Passphrase(pass) => {
            let secret = age_secret_string(pass);
            let recipient = age::scrypt::Recipient::new(secret);
            age::encrypt_and_armor(&recipient, plaintext)
        }
        EncryptTarget::AgeRecipient(s) => {
            let recipient = age::x25519::Recipient::from_str(s)
                .map_err(|e| anyhow!("invalid age recipient: {e}"))?;
            age::encrypt_and_armor(&recipient, plaintext)
        }
        EncryptTarget::SshRecipient(s) => {
            let recipient = age::ssh::Recipient::from_str(s)
                .map_err(|e| anyhow!("invalid SSH recipient: {e:?}"))?;
            age::encrypt_and_armor(&recipient, plaintext)
        }
    }
    .map_err(|e| anyhow!("age encryption failed: {e}"))?;
    Ok(Zeroizing::new(armoured.into_bytes()))
}

/// Decrypt age ASCII armour (or binary age — auto-detected) for the given
/// credential.
///
/// A wrong passphrase / mismatched identity produces age's authenticated
/// [`age::DecryptError`] — a **genuine error**, not silent garbage. This
/// contrasts with SLIP-0039, where a wrong password yields a plausible
/// but wrong secret (documented in phase 007).
pub fn decrypt_share(ciphertext: &[u8], target: &DecryptTarget) -> Result<Zeroizing<Vec<u8>>> {
    // `ArmoredReader::new` auto-detects ASCII-armoured vs binary age input,
    // so this accepts both our armoured exports and (hypothetically) binary
    // age files. `new_buffered` is the performant path for `&[u8]` slices.
    let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(ciphertext))
        .map_err(|e| anyhow!("age: not a valid age file: {e}"))?;

    let identities = build_identities(target)?;
    let id_refs: Vec<&dyn age::Identity> = identities.iter().map(|i| &**i).collect();

    let mut reader = decryptor
        .decrypt(id_refs.into_iter())
        .map_err(|e| anyhow!("age decryption failed (wrong key?): {e}"))?;

    let mut out = Vec::with_capacity(ciphertext.len());
    reader
        .read_to_end(&mut out)
        .map_err(|e| anyhow!("age: read of plaintext failed: {e}"))?;
    Ok(Zeroizing::new(out))
}

/// Cheap prefix check for age ASCII armour.
///
/// Returns `true` iff `bytes` (after skipping leading whitespace) begins
/// with the age armour BEGIN marker. Used by the recover path to decide
/// whether a share needs decryption before SLIP-0039 combine.
pub fn is_age_armored(bytes: &[u8]) -> bool {
    // Tolerate leading whitespace (e.g. a share pasted with a leading newline).
    let start = bytes
        .iter()
        .position(|&b| !b.is_ascii_whitespace())
        .unwrap_or(0);
    bytes[start..].starts_with(ARMOR_BEGIN)
}

/// Human-readable fingerprint for recipient confirmation display.
///
/// - `Passphrase` -> `None` (no recipient to confirm).
/// - `AgeRecipient` -> the recipient string itself (`age1...`). age
///   identities expose their recipient line as the value the user
///   cross-checks against `age-keygen` output.
/// - `SshRecipient` -> the recipient line (`ssh-ed25519 ...` / `ssh-rsa ...`).
///   age does not expose a separate SSH fingerprint; the full recipient
///   line is the value the user pasted and should confirm.
pub fn recipient_fingerprint(target: &EncryptTarget) -> Option<String> {
    match target {
        EncryptTarget::Passphrase(_) => None,
        EncryptTarget::AgeRecipient(s) => Some(s.clone()),
        EncryptTarget::SshRecipient(s) => Some(s.clone()),
    }
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Build the list of age identities to try for decryption. For an age
/// identity file, every identity in the file is offered (a file may hold
/// multiple); for passphrase and SSH there is exactly one.
fn build_identities(target: &DecryptTarget) -> Result<Vec<Box<dyn age::Identity>>> {
    match target {
        DecryptTarget::Passphrase(pass) => {
            let secret = age_secret_string(pass);
            Ok(vec![Box::new(age::scrypt::Identity::new(secret))])
        }
        DecryptTarget::AgeIdentity(bytes) => {
            let file = age::IdentityFile::from_buffer(&bytes[..])
                .map_err(|e| anyhow!("age: could not read identity file: {e}"))?;
            let ids = file
                .into_identities()
                .map_err(|e| anyhow!("age: could not parse identity file: {e}"))?;
            // `into_identities` returns `Vec<Box<dyn Identity + Send + Sync>>`;
            // coerce to `Box<dyn Identity>` (drops the auto traits, which the
            // decrypt API does not require).
            Ok(ids.into_iter().map(|b| b as Box<dyn age::Identity>).collect())
        }
        DecryptTarget::SshIdentity(bytes) => {
            let id = age::ssh::Identity::from_buffer(&bytes[..], None)
                .map_err(|e| anyhow!("age: could not read SSH private key: {e}"))?;
            Ok(vec![Box::new(id)])
        }
        DecryptTarget::AutoKey(bytes) => {
            // Try age identity first; fall back to SSH.
            match age::IdentityFile::from_buffer(&bytes[..]) {
                Ok(file) => {
                    let ids = file.into_identities().map_err(|e| {
                        anyhow!("age: could not parse identity file: {e}")
                    })?;
                    Ok(ids
                        .into_iter()
                        .map(|b| b as Box<dyn age::Identity>)
                        .collect())
                }
                Err(_) => {
                    let id = age::ssh::Identity::from_buffer(&bytes[..], None)
                        .map_err(|e| anyhow!("age: could not read key (tried age identity and SSH): {e}"))?;
                    Ok(vec![Box::new(id)])
                }
            }
        }
    }
}

/// Convert a `Zeroizing<String>` passphrase into an `age::secrecy::SecretString`
/// without leaving an un-wiped copy.
///
/// `SecretString::from(String)` *moves* the `String`'s heap buffer into the
/// `SecretBox` (which zeroises on drop), so the only copy that exists outside
/// our `Zeroizing` is the one age owns and cleans. We allocate a fresh
/// `String` from the passphrase's bytes, move it into the `SecretString`, and
/// let age zeroise it.
fn age_secret_string(pass: &Zeroizing<String>) -> age::secrecy::SecretString {
    // `to_string()` on `&Zeroizing<String>` (via Deref + Display) yields a
    // fresh owned `String`. `SecretString::from` moves it (no leftover).
    age::secrecy::SecretString::from(pass.to_string())
}