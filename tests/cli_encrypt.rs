//! Integration tests for the CLI encrypt flags (phase 003).
//!
//! Drives the compiled binary through the encrypt/export workflow:
//! `--out`, `--encrypt-passphrase` / `--encrypt-to` /
//! `--encrypt-passphrase-file`, `--confirm-recipient`, `--package`,
//! decoy parity (`--decoy-out`, `--decoy-encrypt-*`), fail-fast
//! validation, and the 7a duress notice.

use std::fs;
use std::io::{Cursor, Read};
use std::path::PathBuf;
use std::process::Command;

use age::secrecy::ExposeSecret;
use pellitory_39::encrypt::{decrypt_share, DecryptTarget};
use zeroize::Zeroizing;

/// Locate the compiled binary (set by cargo for integration tests).
fn bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_pellitory-39"))
}

/// A temp dir that cleans up on drop. Uses a process-wide atomic counter so
/// parallel tests never collide on the same directory name.
struct TempDir(PathBuf);
impl TempDir {
    fn new() -> Self {
        use std::sync::atomic::{AtomicU64, Ordering};
        static COUNTER: AtomicU64 = AtomicU64::new(0);
        let n = COUNTER.fetch_add(1, Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!(
            "pellitory-test-{}-{}",
            std::process::id(),
            n
        ));
        fs::create_dir_all(&dir).unwrap();
        Self(dir)
    }
    fn join(&self, name: &str) -> PathBuf {
        self.0.join(name)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}

const SPEND_KEY: &str = "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";
const SLIP_PASS: &str = "testpass";

fn read_zip_entry(zip_bytes: &[u8], name: &str) -> Vec<u8> {
    let cursor = Cursor::new(zip_bytes.to_vec());
    let mut archive = zip::ZipArchive::new(cursor).expect("open zip");
    let all_names: Vec<String> = archive.file_names().map(str::to_string).collect();
    let idx = all_names
        .iter()
        .position(|n| n == name)
        .unwrap_or_else(|| panic!("entry {name} not found in {all_names:?}"));
    let mut entry = archive.by_index(idx).expect("read entry");
    let mut buf = Vec::new();
    entry.read_to_end(&mut buf).expect("read entry bytes");
    buf
}

fn zip_names(zip_bytes: &[u8]) -> Vec<String> {
    let cursor = Cursor::new(zip_bytes.to_vec());
    let archive = zip::ZipArchive::new(cursor).expect("open zip");
    archive.file_names().map(str::to_string).collect()
}

/// Decrypt an armoured share with a passphrase and return the plaintext String.
fn decrypt_passphrase(armoured: &[u8], pass: &str) -> String {
    let cred = DecryptTarget::Passphrase(Zeroizing::new(pass.to_string()));
    let plain = decrypt_share(armoured, &cred).expect("decrypt");
    String::from_utf8(plain.to_vec()).expect("utf8")
}

/// Run the binary with the given args; returns (exit_code, stdout, stderr).
fn run(args: &[&str], envs: &[(&str, &str)]) -> (i32, String, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("run binary");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

/// Like [`run`] but returns raw stdout bytes (binary-safe, no UTF-8 loss).
/// Use for `--out -` which writes a binary ZIP to stdout.
fn run_bytes(args: &[&str], envs: &[(&str, &str)]) -> (i32, Vec<u8>, String) {
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    let output = cmd.output().expect("run binary");
    (
        output.status.code().unwrap_or(-1),
        output.stdout,
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// ─── Passphrase ZIP round-trip ──────────────────────────────────────────────

#[test]
fn split_encrypt_passphrase_zip_roundtrips() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("out.zip");

    let (code, stdout, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            zipfile.to_str().unwrap(),
        ],
        &[("PELLITORY_ENCRYPT_PASSPHRASE", "age-secret")],
    );
    assert_eq!(code, 0, "split failed: {stderr}");
    // JSON to stdout must be suppressed when --out is set.
    assert!(
        !stdout.contains("\"mnemonic\""),
        "no plaintext shares on stdout when --out is set; got: {stdout}"
    );

    let zip_bytes = fs::read(&zipfile).expect("read zip");
    let names = zip_names(&zip_bytes);
    assert!(names.contains(&"share1.txt.age".to_string()));
    assert!(names.contains(&"share2.txt.age".to_string()));
    assert!(names.contains(&"share3.txt.age".to_string()));

    // Decrypt shares 1 and 2, then recover.
    let s1 = decrypt_passphrase(&read_zip_entry(&zip_bytes, "share1.txt.age"), "age-secret");
    let s2 = decrypt_passphrase(&read_zip_entry(&zip_bytes, "share2.txt.age"), "age-secret");

    let (code, stdout, _stderr) = run(
        &[
            "recover",
            "--coin",
            "hex",
            "-m",
            &s1,
            "-m",
            &s2,
            "-p",
            SLIP_PASS,
        ],
        &[],
    );
    assert_eq!(code, 0, "recover failed");
    let hex_line = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex output");
    assert_eq!(hex_line, SPEND_KEY, "round-trip mismatch");
}

// ─── age X25519 recipient ───────────────────────────────────────────────────

#[test]
fn split_encrypt_to_age_recipient() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("age.zip");
    let identity_file = tmp.join("identity.txt");

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let identity_str = identity.to_string().expose_secret().to_string();
    fs::write(&identity_file, &identity_str).unwrap();

    let (code, stdout, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            &recipient,
            "--confirm-recipient",
        ],
        &[],
    );
    assert_eq!(code, 0, "split failed: {stderr}");
    assert!(!stdout.contains("\"mnemonic\""));

    let zip_bytes = fs::read(&zipfile).unwrap();
    let cred = DecryptTarget::AgeIdentity(Zeroizing::new(identity_str.into_bytes()));
    let s1 = decrypt_share(&read_zip_entry(&zip_bytes, "share1.txt.age"), &cred).expect("dec1");
    let s2 = decrypt_share(&read_zip_entry(&zip_bytes, "share2.txt.age"), &cred).expect("dec2");
    let s1 = String::from_utf8(s1.to_vec()).unwrap();
    let s2 = String::from_utf8(s2.to_vec()).unwrap();

    let (code, stdout, _) = run(
        &["recover", "--coin", "hex", "-m", &s1, "-m", &s2, "-p", SLIP_PASS],
        &[],
    );
    assert_eq!(code, 0);
    let hex_line = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");
    assert_eq!(hex_line, SPEND_KEY);
}

// ─── SSH recipient ──────────────────────────────────────────────────────────

#[test]
fn split_encrypt_to_ssh_recipient() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("ssh.zip");

    let ssh_pub = fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let ssh_priv = fs::read("tests/fixtures/test_ed25519").unwrap();

    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            ssh_pub.trim(),
            "--confirm-recipient",
        ],
        &[],
    );
    assert_eq!(code, 0, "split failed: {stderr}");

    let zip_bytes = fs::read(&zipfile).unwrap();
    let cred = DecryptTarget::SshIdentity(Zeroizing::new(ssh_priv));
    let s1 = decrypt_share(&read_zip_entry(&zip_bytes, "share1.txt.age"), &cred).expect("dec1");
    let s2 = decrypt_share(&read_zip_entry(&zip_bytes, "share2.txt.age"), &cred).expect("dec2");
    let s1 = String::from_utf8(s1.to_vec()).unwrap();
    let s2 = String::from_utf8(s2.to_vec()).unwrap();

    let (code, stdout, _) = run(
        &["recover", "--coin", "hex", "-m", &s1, "-m", &s2, "-p", SLIP_PASS],
        &[],
    );
    assert_eq!(code, 0);
    let hex_line = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");
    assert_eq!(hex_line, SPEND_KEY);
}

// ─── Per-share mixed methods ────────────────────────────────────────────────

#[test]
fn split_per_share_mixed_methods() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("mixed.zip");
    let identity_file = tmp.join("id.txt");
    let pass_file = tmp.join("share3-pass.txt");

    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();
    let identity_str = identity.to_string().expose_secret().to_string();
    fs::write(&identity_file, &identity_str).unwrap();
    fs::write(&pass_file, "mixed-pw-3").unwrap();

    let ssh_pub = fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let ssh_priv = fs::read("tests/fixtures/test_ed25519").unwrap();

    // Order: --encrypt-to values first, then --encrypt-passphrase-file.
    // Share 1 = age recipient, Share 2 = ssh recipient, Share 3 = passphrase.
    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "3of3",
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            &recipient,
            "--encrypt-to",
            ssh_pub.trim(),
            "--encrypt-passphrase-file",
            pass_file.to_str().unwrap(),
            "--confirm-recipient",
        ],
        &[],
    );
    assert_eq!(code, 0, "split failed: {stderr}");

    let zip_bytes = fs::read(&zipfile).unwrap();
    // Share 1 — age
    let s1 = decrypt_share(
        &read_zip_entry(&zip_bytes, "share1.txt.age"),
        &DecryptTarget::AgeIdentity(Zeroizing::new(identity_str.into_bytes())),
    )
    .expect("dec1");
    // Share 2 — ssh
    let s2 = decrypt_share(
        &read_zip_entry(&zip_bytes, "share2.txt.age"),
        &DecryptTarget::SshIdentity(Zeroizing::new(ssh_priv)),
    )
    .expect("dec2");
    // Share 3 — passphrase
    let s3 = decrypt_passphrase(&read_zip_entry(&zip_bytes, "share3.txt.age"), "mixed-pw-3");

    let s1 = String::from_utf8(s1.to_vec()).unwrap();
    let s2 = String::from_utf8(s2.to_vec()).unwrap();
    // 3-of-3: all three needed.
    let (code, stdout, _) = run(
        &[
            "recover", "--coin", "hex", "-m", &s1, "-m", &s2, "-m", &s3, "-p", SLIP_PASS,
        ],
        &[],
    );
    assert_eq!(code, 0, "recover failed");
    let hex_line = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");
    assert_eq!(hex_line, SPEND_KEY);
}

// ─── One-file package ───────────────────────────────────────────────────────

#[test]
fn split_one_file_package() {
    let tmp = TempDir::new();
    let outfile = tmp.join("shares.txt.age");

    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            outfile.to_str().unwrap(),
            "--package",
            "one-file",
        ],
        &[("PELLITORY_ENCRYPT_PASSPHRASE", "of-pass")],
    );
    assert_eq!(code, 0, "split failed: {stderr}");

    let blob = fs::read(&outfile).unwrap();
    assert!(blob.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));
    let plain = decrypt_passphrase(&blob, "of-pass");
    assert!(plain.contains("# Share 1"));
    assert!(plain.contains("# Share 2"));
    assert!(plain.contains("# Share 3"));
}

// ─── --out - writes binary to stdout ────────────────────────────────────────

#[test]
fn split_out_stdout_writes_binary() {
    let (code, stdout_bytes, stderr) = run_bytes(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            "-",
        ],
        &[("PELLITORY_ENCRYPT_PASSPHRASE", "stdout-pass")],
    );
    // stdout is binary (a ZIP), so we check it starts with the ZIP magic PK.
    assert_eq!(code, 0, "split failed: {stderr}");
    assert!(
        stdout_bytes.starts_with(b"PK"),
        "stdout should be a binary ZIP (PK magic), got: {:?}",
        &stdout_bytes.get(..10).unwrap_or(&stdout_bytes)
    );
    // Open the stdout bytes as a ZIP.
    let cursor = Cursor::new(stdout_bytes);
    let archive = zip::ZipArchive::new(cursor).expect("stdout is a valid ZIP");
    let names: Vec<String> = archive.file_names().map(str::to_string).collect();
    assert!(names.contains(&"share1.txt.age".to_string()));
}

// ─── Validation: --encrypt without --out errors ─────────────────────────────

#[test]
fn split_encrypt_without_out_errors() {
    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
        ],
        &[("PELLITORY_ENCRYPT_PASSPHRASE", "x")],
    );
    assert_ne!(code, 0, "should have failed");
    assert!(
        stderr.contains("--out") || stderr.to_lowercase().contains("encryption requires"),
        "should mention --out, got: {stderr}"
    );
}

// ─── Validation: per-share wrong count errors before secret gen ─────────────

#[test]
fn split_per_share_wrong_count_errors() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("bad.zip");
    // Generate 4 valid age recipients for 3 shares (count mismatch).
    let recipients: Vec<String> = (0..4)
        .map(|_| age::x25519::Identity::generate().to_public().to_string())
        .collect();
    let (code, stdout, stderr) = run(
        &[
            "split",
            "--coin",
            "monero",
            "-p",
            SLIP_PASS,
            "--group",
            "2of3", // 3 shares
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            &recipients[0],
            "--encrypt-to",
            &recipients[1],
            "--encrypt-to",
            &recipients[2],
            "--encrypt-to",
            &recipients[3], // 4 methods for 3 shares
            "--confirm-recipient",
        ],
        &[],
    );
    assert_ne!(code, 0, "should have failed");
    // Must NOT leak any Monero key material.
    assert!(
        !stdout.contains("Private spend key") && !stderr.contains("Private spend key"),
        "must not leak keys before config error"
    );
    assert!(
        stderr.to_lowercase().contains("method") || stderr.to_lowercase().contains("share"),
        "should mention method/share count, got: {stderr}"
    );
}

// ─── Validation: one-file + per-share methods errors ────────────────────────

#[test]
fn split_one_file_with_per_share_errors() {
    let tmp = TempDir::new();
    let outfile = tmp.join("bad.txt.age");
    let r1 = age::x25519::Identity::generate().to_public().to_string();
    let r2 = age::x25519::Identity::generate().to_public().to_string();
    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            outfile.to_str().unwrap(),
            "--package",
            "one-file",
            "--encrypt-to",
            &r1,
            "--encrypt-to",
            &r2,
            "--confirm-recipient",
        ],
        &[],
    );
    assert_ne!(code, 0, "should have failed");
    assert!(
        stderr.to_lowercase().contains("one") && stderr.to_lowercase().contains("credential"),
        "should mention one-file/credential, got: {stderr}"
    );
}

// ─── --confirm-recipient required ───────────────────────────────────────────

#[test]
fn confirm_recipient_required() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("nr.zip");
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public().to_string();

    let (code, _, stderr) = run(
        &[
            "split",
            "--coin",
            "hex",
            "-e",
            SPEND_KEY,
            "-p",
            SLIP_PASS,
            "--group",
            "2of3",
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            &recipient,
            // no --confirm-recipient
        ],
        &[],
    );
    assert_ne!(code, 0, "should have failed without --confirm-recipient");
    assert!(
        stderr.contains("--confirm-recipient") || stderr.contains("fingerprint"),
        "should mention --confirm-recipient, got: {stderr}"
    );
}

// ─── generate --decoy: two separate files ───────────────────────────────────

#[test]
fn generate_decoy_two_separate_files() {
    let tmp = TempDir::new();
    let real_zip = tmp.join("real.zip");
    let decoy_zip = tmp.join("decoy.zip");

    let (code, stdout, stderr) = run(
        &[
            "generate",
            "--coin",
            "hex",
            "--group",
            "2of3",
            "--out",
            real_zip.to_str().unwrap(),
            "--decoy",
            "--decoy-out",
            decoy_zip.to_str().unwrap(),
        ],
        &[
            ("PELLITORY_PASSWORD", "real-slip"),
            ("PELLITORY_DECOY_PASSWORD", "decoy-slip"),
            ("PELLITORY_ENCRYPT_PASSPHRASE", "real-age"),
            ("PELLITORY_DECOY_ENCRYPT_PASSPHRASE", "decoy-age"),
        ],
    );
    assert_eq!(code, 0, "generate --decoy failed: {stderr}");
    assert!(!stdout.contains("\"mnemonic\""), "no plaintext on stdout");

    assert!(real_zip.exists(), "real zip exists");
    assert!(decoy_zip.exists(), "decoy zip exists");

    let real_bytes = fs::read(&real_zip).unwrap();
    let decoy_bytes = fs::read(&decoy_zip).unwrap();
    assert!(real_bytes.starts_with(b"PK"), "real is a ZIP");
    assert!(decoy_bytes.starts_with(b"PK"), "decoy is a ZIP");

    // Real shares decrypt with real-age, decoy with decoy-age (different).
    let real_s1 = decrypt_passphrase(&read_zip_entry(&real_bytes, "share1.txt.age"), "real-age");
    let real_s2 = decrypt_passphrase(&read_zip_entry(&real_bytes, "share2.txt.age"), "real-age");
    // Decoy shares must NOT decrypt with real-age.
    assert!(
        decrypt_share(
            &read_zip_entry(&decoy_bytes, "share1.txt.age"),
            &DecryptTarget::Passphrase(Zeroizing::new("real-age".to_string())),
        )
        .is_err(),
        "decoy share must not decrypt with real passphrase"
    );
    let decoy_s1 = decrypt_passphrase(&read_zip_entry(&decoy_bytes, "share1.txt.age"), "decoy-age");
    let decoy_s2 = decrypt_passphrase(&read_zip_entry(&decoy_bytes, "share2.txt.age"), "decoy-age");

    // Real recovers with real-slip.
    let (code, stdout, _) = run(
        &[
            "recover", "--coin", "hex", "-m", &real_s1, "-m", &real_s2, "-p", "real-slip",
        ],
        &[],
    );
    assert_eq!(code, 0);
    let real_hex = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");

    // Decoy recovers with decoy-slip — different secret.
    let (code, stdout, _) = run(
        &[
            "recover", "--coin", "hex", "-m", &decoy_s1, "-m", &decoy_s2, "-p", "decoy-slip",
        ],
        &[],
    );
    assert_eq!(code, 0);
    let decoy_hex = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");
    assert_ne!(real_hex, decoy_hex, "real and decoy secrets differ");
}

// ─── generate --decoy: 7a duress notice ─────────────────────────────────────

#[test]
fn generate_decoy_emits_duress_notice() {
    let tmp = TempDir::new();
    let real_zip = tmp.join("r.zip");
    let decoy_zip = tmp.join("d.zip");

    let (code, _, stderr) = run(
        &[
            "generate",
            "--coin",
            "hex",
            "--group",
            "2of3",
            "--out",
            real_zip.to_str().unwrap(),
            "--decoy",
            "--decoy-out",
            decoy_zip.to_str().unwrap(),
        ],
        &[
            ("PELLITORY_PASSWORD", "rp"),
            ("PELLITORY_DECOY_PASSWORD", "dp"),
            ("PELLITORY_ENCRYPT_PASSPHRASE", "ra"),
            ("PELLITORY_DECOY_ENCRYPT_PASSPHRASE", "da"),
        ],
    );
    assert_eq!(code, 0, "generate failed: {stderr}");
    assert!(
        stderr.to_lowercase().contains("duress")
            && stderr.contains("age")
            && stderr.contains("matching"),
        "7a duress notice must appear on stderr, got: {stderr}"
    );
}

// ─── Fail-fast: no Monero key material leaked on config error ───────────────

#[test]
fn fail_fast_before_secret() {
    let tmp = TempDir::new();
    let zipfile = tmp.join("ff.zip");
    // generate --coin monero with a per-share count mismatch.
    let r1 = age::x25519::Identity::generate().to_public().to_string();
    let r2 = age::x25519::Identity::generate().to_public().to_string();
    let (code, stdout, stderr) = run(
        &[
            "generate",
            "--coin",
            "monero",
            "--group",
            "2of3", // 3 shares
            "--out",
            zipfile.to_str().unwrap(),
            "--encrypt-to",
            &r1,
            "--encrypt-to",
            &r2, // 2 methods for 3 shares
            "--confirm-recipient",
        ],
        &[("PELLITORY_PASSWORD", "p")],
    );
    assert_ne!(code, 0, "should fail");
    assert!(
        !stdout.contains("Private spend key") && !stderr.contains("Private spend key"),
        "must not leak Monero keys before config error; stderr: {stderr}"
    );
    assert!(
        !stdout.contains("Monero address") && !stderr.contains("Monero address"),
        "must not leak Monero address; stderr: {stderr}"
    );
}

// keep Read import alive
#[allow(dead_code)]
fn _read_used<R: Read>(_r: R) {}

// ─── generate --decoy: --encrypt-to parity (age recipients) ─────────────────

#[test]
fn generate_decoy_encrypt_to_recipients() {
    let tmp = TempDir::new();
    let real_zip = tmp.join("real.zip");
    let decoy_zip = tmp.join("decoy.zip");

    let real_id = age::x25519::Identity::generate();
    let real_recipient = real_id.to_public().to_string();
    let decoy_id = age::x25519::Identity::generate();
    let decoy_recipient = decoy_id.to_public().to_string();

    let (code, stdout, stderr) = run(
        &[
            "generate",
            "--coin",
            "hex",
            "--group",
            "2of3",
            "--out",
            real_zip.to_str().unwrap(),
            "--encrypt-to",
            &real_recipient,
            "--confirm-recipient",
            "--decoy",
            "--decoy-out",
            decoy_zip.to_str().unwrap(),
            "--decoy-encrypt-to",
            &decoy_recipient,
            "--decoy-confirm-recipient",
        ],
        &[
            ("PELLITORY_PASSWORD", "real-slip"),
            ("PELLITORY_DECOY_PASSWORD", "decoy-slip"),
        ],
    );
    assert_eq!(code, 0, "generate --decoy --encrypt-to failed: {stderr}");
    assert!(!stdout.contains("\"mnemonic\""), "no plaintext on stdout");

    assert!(real_zip.exists(), "real zip exists");
    assert!(decoy_zip.exists(), "decoy zip exists");

    let real_bytes = fs::read(&real_zip).unwrap();
    let decoy_bytes = fs::read(&decoy_zip).unwrap();
    assert!(real_bytes.starts_with(b"PK"), "real is a ZIP");
    assert!(decoy_bytes.starts_with(b"PK"), "decoy is a ZIP");

    // Real shares decrypt with the real identity, NOT the decoy identity.
    let real_s1 = decrypt_identity(&read_zip_entry(&real_bytes, "share1.txt.age"), &real_id);
    let real_s2 = decrypt_identity(&read_zip_entry(&real_bytes, "share2.txt.age"), &real_id);
    assert!(
        decrypt_identity_err(&read_zip_entry(&decoy_bytes, "share1.txt.age"), &real_id),
        "decoy share must not decrypt with real identity"
    );

    // Decoy shares decrypt with the decoy identity.
    let decoy_s1 = decrypt_identity(&read_zip_entry(&decoy_bytes, "share1.txt.age"), &decoy_id);
    let decoy_s2 = decrypt_identity(&read_zip_entry(&decoy_bytes, "share2.txt.age"), &decoy_id);

    // Real recovers with real-slip.
    let (code, stdout, _) = run(
        &[
            "recover", "--coin", "hex", "-m", &real_s1, "-m", &real_s2, "-p", "real-slip",
        ],
        &[],
    );
    assert_eq!(code, 0);
    let real_hex = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");

    // Decoy recovers with decoy-slip — different secret.
    let (code, stdout, _) = run(
        &[
            "recover", "--coin", "hex", "-m", &decoy_s1, "-m", &decoy_s2, "-p", "decoy-slip",
        ],
        &[],
    );
    assert_eq!(code, 0);
    let decoy_hex = stdout
        .lines()
        .find(|l| l.chars().all(|c| c.is_ascii_hexdigit()) && !l.is_empty())
        .expect("hex");
    assert_ne!(real_hex, decoy_hex, "real and decoy secrets differ");
}

/// Decrypt an armoured share with an age X25519 identity, returning the
/// plaintext mnemonic string.
fn decrypt_identity(armoured: &[u8], id: &age::x25519::Identity) -> String {
    let decryptor = age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armoured))
        .expect("valid age armour");
    let id_ref: &dyn age::Identity = id;
    let mut reader = decryptor
        .decrypt(std::iter::once(id_ref))
        .expect("decrypt with identity");
    let mut out = Vec::new();
    reader.read_to_end(&mut out).expect("read plaintext");
    String::from_utf8(out).expect("utf8").trim().to_string()
}

/// Like [`decrypt_identity`] but returns `true` if decryption fails (used
/// to verify a key does NOT decrypt a share).
fn decrypt_identity_err(armoured: &[u8], id: &age::x25519::Identity) -> bool {
    let decryptor = match age::Decryptor::new_buffered(age::armor::ArmoredReader::new(armoured)) {
        Ok(d) => d,
        Err(_) => return true,
    };
    let id_ref: &dyn age::Identity = id;
    match decryptor.decrypt(std::iter::once(id_ref)) {
        Ok(mut reader) => {
            let mut out = Vec::new();
            reader.read_to_end(&mut out).is_err()
        }
        Err(_) => true,
    }
}