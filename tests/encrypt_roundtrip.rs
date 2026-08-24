//! Integration tests for `src/encrypt.rs` (phase 001 of the age-encrypted
//! share export feature).
//!
//! These tests exercise the full encrypt -> decrypt round-trip for every
//! supported `age` recipient type (passphrase / X25519 / SSH Ed25519), the
//! armour auto-detection helper, the recipient-string parser, and the
//! wrong-passphrase failure path (age authenticates — a wrong key is a
//! genuine error, not silent garbage).

use age::secrecy::ExposeSecret;

use pellitory_39::encrypt::{
    decrypt_share, encrypt_share, is_age_armored, parse_recipient, recipient_fingerprint,
    DecryptTarget, EncryptTarget,
};

const PLAINTEXT: &[u8] = b"transfer flea ceramic round ajar abandon ...";

// ---- Passphrase ----

#[test]
fn passphrase_roundtrip() {
    let target = EncryptTarget::Passphrase(zero_string("correct horse battery staple"));
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt");
    assert!(is_age_armored(&armoured), "output must be armoured");
    assert!(armoured.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

    let cred = DecryptTarget::Passphrase(zero_string("correct horse battery staple"));
    let plain = decrypt_share(&armoured, &cred).expect("decrypt");
    assert_eq!(plain.as_slice(), PLAINTEXT);
}

#[test]
fn wrong_passphrase_fails() {
    let target = EncryptTarget::Passphrase(zero_string("the real passphrase"));
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt");

    let wrong = DecryptTarget::Passphrase(zero_string("a different passphrase"));
    let err = decrypt_share(&armoured, &wrong).expect_err("wrong passphrase must fail");
    // age authenticates: a wrong passphrase is a hard error, NOT silent
    // garbage. Contrast with SLIP-0039 (wrong password -> plausible wrong
    // secret). Call this out in phase 007 docs.
    let msg = format!("{err}");
    assert!(
        msg.contains("decrypt") || msg.contains("key") || msg.contains("scrypt")
            || msg.contains("No matching"),
        "error should mention decryption failure, got: {msg}"
    );
}

// ---- X25519 age recipient ----

#[test]
fn age_recipient_roundtrip() {
    // Generate a throwaway age identity in-test (no keygen tool needed).
    let identity = age::x25519::Identity::generate();
    let recipient = identity.to_public();
    let recipient_str = recipient.to_string();

    let target = EncryptTarget::AgeRecipient(recipient_str.clone());
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt");
    assert!(is_age_armored(&armoured));

    // An age identity file is `# created: ...\n# public key: age1...\nAGE-SECRET-KEY-1...`.
    let identity_str = identity.to_string().expose_secret().to_string();
    let cred = DecryptTarget::AgeIdentity(zero_vec(identity_str.into_bytes()));
    let plain = decrypt_share(&armoured, &cred).expect("decrypt");
    assert_eq!(plain.as_slice(), PLAINTEXT);
}

// ---- SSH Ed25519 recipient ----

#[test]
fn ssh_ed25519_recipient_roundtrip() {
    let pubkey = std::fs::read_to_string("tests/fixtures/test_ed25519.pub")
        .expect("test SSH pubkey fixture must exist");
    let privkey = std::fs::read("tests/fixtures/test_ed25519")
        .expect("test SSH privkey fixture must exist");

    let target = EncryptTarget::SshRecipient(pubkey.trim().to_string());
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt");
    assert!(is_age_armored(&armoured));

    let cred = DecryptTarget::SshIdentity(zero_vec(privkey));
    let plain = decrypt_share(&armoured, &cred).expect("decrypt");
    assert_eq!(plain.as_slice(), PLAINTEXT);
}

// ---- Armour detection ----

#[test]
fn is_age_armored_detects_header() {
    let target = EncryptTarget::Passphrase(zero_string("pw"));
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt");
    assert!(is_age_armored(&armoured), "armoured output detected");
    assert!(!is_age_armored(b"random bytes not age"), "non-armour rejected");
    assert!(!is_age_armored(b""), "empty rejected");
    assert!(!is_age_armored(PLAINTEXT), "plaintext share rejected");
}

// ---- Recipient parsing ----

#[test]
fn parse_recipient_autodetects() {
    // age1... -> AgeRecipient (use a real generated recipient so it parses).
    let identity = age::x25519::Identity::generate();
    let age_recip = identity.to_public().to_string();
    let parsed = parse_recipient(&age_recip).expect("age recipient parses");
    assert!(matches!(parsed, EncryptTarget::AgeRecipient(_)));

    // ssh-ed25519 ... -> SshRecipient
    let ssh_pub = "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAID5aeDRmMY0g/SvB3cmJ8bDrLLOvQ9EnhoVZjbadrOFR pellitory-test-only";
    let parsed = parse_recipient(ssh_pub).expect("ssh recipient parses");
    assert!(matches!(parsed, EncryptTarget::SshRecipient(_)));

    // ssh-rsa ... -> SshRecipient
    let ssh_rsa = "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ... user@host";
    // (This one has a truncated body; age's parser will reject it, so we
    // only assert the *dispatch* reaches ssh, not that it parses. Use a
    // full-length-key test only if we generate one — skip here.)
    let _ = ssh_rsa;

    // garbage -> Err
    assert!(parse_recipient("garbage not a key").is_err());
    assert!(parse_recipient("").is_err());
}

#[test]
fn parse_recipient_validates_age_recipient() {
    // A real age recipient string round-trips through the parser and can
    // actually encrypt.
    let identity = age::x25519::Identity::generate();
    let recipient_str = identity.to_public().to_string();
    let target = parse_recipient(&recipient_str).expect("valid age recipient");
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt with parsed recipient");
    assert!(is_age_armored(&armoured));
}

#[test]
fn parse_recipient_validates_ssh_recipient() {
    let pubkey = std::fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let target = parse_recipient(pubkey.trim()).expect("valid ssh recipient");
    let armoured = encrypt_share(PLAINTEXT, &target).expect("encrypt with parsed ssh recipient");
    assert!(is_age_armored(&armoured));
}

// ---- Fingerprint ----

#[test]
fn recipient_fingerprint_is_none_for_passphrase() {
    let target = EncryptTarget::Passphrase(zero_string("pw"));
    assert_eq!(recipient_fingerprint(&target), None);
}

#[test]
fn recipient_fingerprint_echoes_age_recipient() {
    let identity = age::x25519::Identity::generate();
    let recipient_str = identity.to_public().to_string();
    let target = EncryptTarget::AgeRecipient(recipient_str.clone());
    assert_eq!(recipient_fingerprint(&target).as_deref(), Some(recipient_str.as_str()));
}

#[test]
fn recipient_fingerprint_echoes_ssh_recipient() {
    let pubkey = std::fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let target = EncryptTarget::SshRecipient(pubkey.trim().to_string());
    let fp = recipient_fingerprint(&target).expect("ssh fingerprint");
    assert!(fp.starts_with("ssh-ed25519 "), "fingerprint should be the recipient line");
}

// ---- Helpers ----

fn zero_string(s: &str) -> zeroize::Zeroizing<String> {
    zeroize::Zeroizing::new(s.to_string())
}

fn zero_vec(v: Vec<u8>) -> zeroize::Zeroizing<Vec<u8>> {
    zeroize::Zeroizing::new(v)
}

