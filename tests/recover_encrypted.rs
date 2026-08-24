//! Integration tests for CLI recover with age-encrypted shares (phase 004).
//!
//! Drives the compiled binary through the recover workflow:
//! `-m @path` file loading, age-armor autodetection, `--decrypt-passphrase`
//! / `--decrypt-identity` single-method fast path, mixed armoured + plain
//! shares, per-share interactive loop (piped stdin), and wrong-passphrase
//! failure (no silent garbage).

use std::fs;
use std::path::PathBuf;
use std::process::Command;

use age::secrecy::ExposeSecret;
use pellitory_39::encrypt::EncryptTarget;
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

const SLIP_PASS: &str = "testpass";
const SPEND_KEY: &str = "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";

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

/// Run the binary with stdin piped from `input`; returns
/// (exit_code, stdout, stderr).
fn run_stdin(args: &[&str], envs: &[(&str, &str)], input: &[u8]) -> (i32, String, String) {
    use std::process::Stdio;
    let mut cmd = Command::new(bin());
    cmd.args(args);
    for (k, v) in envs {
        cmd.env(k, v);
    }
    cmd.stdin(Stdio::piped()).stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = cmd.spawn().expect("spawn binary");
    use std::io::Write;
    child.stdin.take().unwrap().write_all(input).expect("write stdin");
    let output = child.wait_with_output().expect("wait");
    (
        output.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&output.stdout).to_string(),
        String::from_utf8_lossy(&output.stderr).to_string(),
    )
}

// ─── Test helpers: produce encrypted share files ───────────────────────────

/// Encrypt a plaintext mnemonic to an armoured `.age` file at `path`.
fn write_armoured_share(path: &PathBuf, mnemonic: &str, target: &EncryptTarget) {
    let armoured = pellitory_39::export::build_single_share_export(mnemonic.as_bytes(), target)
        .expect("encrypt share");
    fs::write(path, armoured.as_slice()).expect("write .age file");
}

/// Generate a 2-of-3 SLIP-0039 split of a hex secret, returning the share
/// mnemonics. Uses the library `sharing` module directly (not the CLI).
fn split_hex_to_mnemonics(secret_hex: &str, pass: &str, threshold: usize, total: usize) -> Vec<String> {
    use pellitory_39::sharing;
    let master = sharing::MasterSecret::from_hex(secret_hex).unwrap();
    let groups = vec![(threshold as u8, total as u8)];
    let output = sharing::Slip39Output::split(
        1, &groups, &master, pass, 1, true,
    ).unwrap();
    output.all_mnemonics().into_iter().map(|z| z.to_string()).collect()
}

// ─── Tests ─────────────────────────────────────────────────────────────────

#[test]
fn recover_armoured_passphrase_roundtrips() {
    let tmp = TempDir::new();
    // Split into 2-of-3 shares, then encrypt 2 shares with a passphrase.
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let age_pass = "recover-pass";
    let target = EncryptTarget::Passphrase(Zeroizing::new(age_pass.to_string()));
    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &target);
    write_armoured_share(&s2, &shares[1], &target);

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
        ],
        &[
            ("PELLITORY_PASSWORD", SLIP_PASS),
            ("PELLITORY_DECRYPT_PASSPHRASE", age_pass),
        ],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    // Hex output is on stdout.
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_armoured_age_identity() {
    let tmp = TempDir::new();
    // Generate a throwaway age identity, write it to a file, encrypt shares
    // to its recipient.
    let identity = age::x25519::Identity::generate();
    let recipient_str = identity.to_public().to_string();
    let identity_str = identity.to_string().expose_secret().to_string();
    let id_file = tmp.join("identity.txt");
    fs::write(&id_file, identity_str).expect("write identity file");

    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let target = EncryptTarget::AgeRecipient(recipient_str);
    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &target);
    write_armoured_share(&s2, &shares[1], &target);

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
            "--decrypt-identity", &id_file.display().to_string(),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_armoured_ssh_identity() {
    let tmp = TempDir::new();
    let pubkey = fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let privkey = fs::read("tests/fixtures/test_ed25519").unwrap();
    let target = EncryptTarget::SshRecipient(pubkey.trim().to_string());

    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &target);
    write_armoured_share(&s2, &shares[1], &target);

    // Write SSH key to a temp file (the fixture path is relative to cwd,
    // which cargo test sets to the crate root — but pass an absolute path
    // to be robust).
    let key_file = tmp.join("test_ed25519");
    fs::write(&key_file, privkey).unwrap();

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
            "--decrypt-identity", &key_file.display().to_string(),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_mixed_armoured_and_plain() {
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let age_pass = "mix-pass";
    let target = EncryptTarget::Passphrase(Zeroizing::new(age_pass.to_string()));
    // Share 1 armoured, share 2 plain text on -m.
    let s1 = tmp.join("share1.txt.age");
    write_armoured_share(&s1, &shares[0], &target);

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &shares[1], // plain mnemonic
        ],
        &[
            ("PELLITORY_PASSWORD", SLIP_PASS),
            ("PELLITORY_DECRYPT_PASSPHRASE", age_pass),
        ],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_per_share_mixed_credentials() {
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 3, 3);

    // Encrypt share 1 with passphrase, share 2 with age identity, share 3
    // with SSH key.
    let age_pass = "share1-pass";
    let t1 = EncryptTarget::Passphrase(Zeroizing::new(age_pass.to_string()));

    let identity = age::x25519::Identity::generate();
    let recipient_str = identity.to_public().to_string();
    let identity_str = identity.to_string().expose_secret().to_string();
    let id_file = tmp.join("age_identity.txt");
    fs::write(&id_file, identity_str).unwrap();
    let t2 = EncryptTarget::AgeRecipient(recipient_str);

    let pubkey = fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let privkey = fs::read("tests/fixtures/test_ed25519").unwrap();
    let key_file = tmp.join("test_ed25519");
    fs::write(&key_file, privkey).unwrap();
    let t3 = EncryptTarget::SshRecipient(pubkey.trim().to_string());

    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    let s3 = tmp.join("share3.txt.age");
    write_armoured_share(&s1, &shares[0], &t1);
    write_armoured_share(&s2, &shares[1], &t2);
    write_armoured_share(&s3, &shares[2], &t3);

    // Interactive loop via piped stdin. The prompts are per-share method
    // selection: (p)assphrase / (a)ge identity file / (s)sh private key.
    // For each, after choosing the method, we supply the credential.
    // Share 1: passphrase -> "p\n" + passphrase + "\n"
    // Share 2: age identity -> "a\n" + identity file path + "\n"
    // Share 3: ssh key -> "s\n" + ssh key path + "\n"
    let stdin_input = format!(
        "p\n{age_pass}\na\n{id_path}\ns\n{ssh_path}\n",
        age_pass = age_pass,
        id_path = id_file.display(),
        ssh_path = key_file.display(),
    );

    let (code, stdout, stderr) = run_stdin(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
            "-m", &format!("@{}", s3.display()),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
        stdin_input.as_bytes(),
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_wrong_passphrase_fails() {
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let target = EncryptTarget::Passphrase(Zeroizing::new("correct-pass".to_string()));
    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &target);
    write_armoured_share(&s2, &shares[1], &target);

    let (code, _stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
        ],
        &[
            ("PELLITORY_PASSWORD", SLIP_PASS),
            ("PELLITORY_DECRYPT_PASSPHRASE", "wrong-pass"),
        ],
    );
    // Must exit non-zero with a clear error naming a share — NOT a silent
    // garbage recovery.
    assert_ne!(code, 0, "expected failure, got success. stderr: {stderr}");
    assert!(
        stderr.to_lowercase().contains("decrypt") || stderr.to_lowercase().contains("share"),
        "error should mention decrypt/share, got: {stderr}"
    );
}

#[test]
fn recover_at_file_loads_and_autodetects() {
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let age_pass = "at-pass";
    let target = EncryptTarget::Passphrase(Zeroizing::new(age_pass.to_string()));

    // Armoured file.
    let s1 = tmp.join("share1.txt.age");
    write_armoured_share(&s1, &shares[0], &target);

    // Plain mnemonic file (no armour).
    let s2 = tmp.join("share2.txt");
    fs::write(&s2, &shares[1]).unwrap();

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
        ],
        &[
            ("PELLITORY_PASSWORD", SLIP_PASS),
            ("PELLITORY_DECRYPT_PASSPHRASE", age_pass),
        ],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_no_decryption_credential_for_armoured_errors() {
    // Armoured shares but no --decrypt-* flag and no interactive input.
    // Should fail fast with a clear error (not hang waiting for stdin in a
    // non-interactive context).
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);
    let target = EncryptTarget::Passphrase(Zeroizing::new("some-pass".to_string()));
    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &target);
    write_armoured_share(&s2, &shares[1], &target);

    // Pipe empty stdin so the interactive prompt gets EOF instead of hanging.
    let (code, _stdout, stderr) = run_stdin(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
        &[],
    );
    assert_ne!(code, 0, "expected failure for missing credential, got success");
    assert!(
        stderr.to_lowercase().contains("decrypt") || stderr.to_lowercase().contains("share") || stderr.to_lowercase().contains("armoured"),
        "error should mention decrypt/armoured/share, got: {stderr}"
    );
}

#[test]
fn recover_heterogeneous_credential_pool() {
    // Three shares, each encrypted with a different method:
    //   share1 -> passphrase "passA"
    //   share2 -> passphrase "passB"
    //   share3 -> age recipient
    // Supply all three credentials as a pool; the fast path tries each
    // on every armoured share until one works.
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);

    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    let s3 = tmp.join("share3.txt.age");
    write_armoured_share(&s1, &shares[0], &EncryptTarget::Passphrase(Zeroizing::new("passA".to_string())));
    write_armoured_share(&s2, &shares[1], &EncryptTarget::Passphrase(Zeroizing::new("passB".to_string())));

    // For share3, use an age identity recipient.
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let recipient_str = recipient.to_string();
    let id_file = tmp.join("age_identity.txt");
    fs::write(&id_file, identity.to_string().expose_secret().as_bytes()).unwrap();
    write_armoured_share(&s3, &shares[2], &EncryptTarget::AgeRecipient(recipient_str));

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
            "-m", &format!("@{}", s3.display()),
            "--decrypt-passphrase", "passA",
            "--decrypt-passphrase", "passB",
            "--decrypt-identity", &id_file.display().to_string(),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}

#[test]
fn recover_repeatable_identity_pool_tries_all() {
    // Two shares encrypted to two different age recipients. Supply both
    // identity files via repeated --decrypt-identity; each is tried on
    // every armoured share.
    let tmp = TempDir::new();
    let shares = split_hex_to_mnemonics(SPEND_KEY, SLIP_PASS, 2, 3);

    let id1 = age::x25519::Identity::generate();
    let id2 = age::x25519::Identity::generate();
    let id1_file = tmp.join("id1.txt");
    let id2_file = tmp.join("id2.txt");
    fs::write(&id1_file, id1.to_string().expose_secret().as_bytes()).unwrap();
    fs::write(&id2_file, id2.to_string().expose_secret().as_bytes()).unwrap();

    let s1 = tmp.join("share1.txt.age");
    let s2 = tmp.join("share2.txt.age");
    write_armoured_share(&s1, &shares[0], &EncryptTarget::AgeRecipient(id1.to_public().to_string()));
    write_armoured_share(&s2, &shares[1], &EncryptTarget::AgeRecipient(id2.to_public().to_string()));

    let (code, stdout, stderr) = run(
        &[
            "recover",
            "--coin", "hex",
            "-m", &format!("@{}", s1.display()),
            "-m", &format!("@{}", s2.display()),
            "--decrypt-identity", &id1_file.display().to_string(),
            "--decrypt-identity", &id2_file.display().to_string(),
        ],
        &[("PELLITORY_PASSWORD", SLIP_PASS)],
    );
    assert_eq!(code, 0, "recover failed: {stderr}");
    let hex_out = stdout.trim();
    assert_eq!(hex_out, SPEND_KEY, "recovered secret mismatch");
}
