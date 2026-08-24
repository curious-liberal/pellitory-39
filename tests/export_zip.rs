//! Integration tests for `src/export.rs` (phase 002 of the age-encrypted
//! share export feature).
//!
//! These tests exercise the three export builders:
//!   • single-share `.age` file
//!   • bulk ZIP (per-share `.age` entries + README.txt)
//!   • one-file armoured blob (single credential)
//!
//! and the validation rules (wrong method counts, no plaintext on disk).

use std::io::{Cursor, Read};

use age::secrecy::ExposeSecret;

use pellitory_39::encrypt::{
    decrypt_share, DecryptTarget, EncryptTarget,
};
use pellitory_39::export::{build_export, build_readme, build_single_share_export, BulkPackage};
use zeroize::Zeroizing;

const SHARE_1: &str = "transfer flea ceramic round ajar abandon one";
const SHARE_2: &str = "transfer flea ceramic round beard abandon two";
const SHARE_3: &str = "transfer flea ceramic round deal abandon three";

fn shares() -> Vec<Zeroizing<String>> {
    vec![
        Zeroizing::new(SHARE_1.to_string()),
        Zeroizing::new(SHARE_2.to_string()),
        Zeroizing::new(SHARE_3.to_string()),
    ]
}

fn passphrase(s: &str) -> EncryptTarget {
    EncryptTarget::Passphrase(Zeroizing::new(s.to_string()))
}

fn decrypt_passphrase(s: &str) -> DecryptTarget {
    DecryptTarget::Passphrase(Zeroizing::new(s.to_string()))
}

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

// ---- Single-share export ----

#[test]
fn single_share_export_roundtrips() {
    let target = passphrase("s3cret");
    let bytes = build_single_share_export(SHARE_1.as_bytes(), &target).expect("build single");
    // A single-share export is a raw armoured `.age` blob (not a ZIP).
    assert!(bytes.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

    let plain = decrypt_share(&bytes, &decrypt_passphrase("s3cret")).expect("decrypt");
    assert_eq!(plain.as_slice(), SHARE_1.as_bytes());
}

// ---- ZIP: entries + README ----

#[test]
fn zip_has_named_entries_and_readme() {
    let methods = vec![passphrase("pw1"), passphrase("pw2"), passphrase("pw3")];
    let zip = build_export(&shares(), &methods, BulkPackage::Zip, 2).expect("build zip");
    let names = zip_names(&zip);
    assert!(names.contains(&"share1.txt.age".to_string()), "names: {names:?}");
    assert!(names.contains(&"share2.txt.age".to_string()));
    assert!(names.contains(&"share3.txt.age".to_string()));
    assert!(names.contains(&"README.txt".to_string()));

    let readme = read_zip_entry(&zip, "README.txt");
    let readme = String::from_utf8(readme).unwrap();
    assert!(readme.contains("2-of-3"), "README must mention threshold: {readme}");
    assert!(
        readme.contains("age -d") || readme.contains("pellitory-39 recover"),
        "README must mention a decrypt/recover command: {readme}"
    );
}

// ---- ZIP: mixed methods each decryptable ----

#[test]
fn zip_mixed_methods_each_decryptable() {
    // method 1: passphrase
    // method 2: age X25519 recipient
    // method 3: SSH Ed25519
    let identity = age::x25519::Identity::generate();
    let recipient_str = identity.to_public().to_string();
    let identity_str = identity.to_string().expose_secret().to_string();

    let ssh_pub = std::fs::read_to_string("tests/fixtures/test_ed25519.pub").unwrap();
    let ssh_priv = std::fs::read("tests/fixtures/test_ed25519").unwrap();

    let methods = vec![
        passphrase("mixed-pw"),
        EncryptTarget::AgeRecipient(recipient_str),
        EncryptTarget::SshRecipient(ssh_pub.trim().to_string()),
    ];
    let zip = build_export(&shares(), &methods, BulkPackage::Zip, 2).expect("build zip");

    // Share 1 — passphrase
    let s1 = read_zip_entry(&zip, "share1.txt.age");
    let p1 = decrypt_share(&s1, &decrypt_passphrase("mixed-pw")).expect("decrypt share1");
    assert_eq!(p1.as_slice(), SHARE_1.as_bytes());

    // Share 2 — age identity
    let s2 = read_zip_entry(&zip, "share2.txt.age");
    let p2 = decrypt_share(
        &s2,
        &DecryptTarget::AgeIdentity(Zeroizing::new(identity_str.into_bytes())),
    )
    .expect("decrypt share2");
    assert_eq!(p2.as_slice(), SHARE_2.as_bytes());

    // Share 3 — SSH identity
    let s3 = read_zip_entry(&zip, "share3.txt.age");
    let p3 = decrypt_share(
        &s3,
        &DecryptTarget::SshIdentity(Zeroizing::new(ssh_priv)),
    )
    .expect("decrypt share3");
    assert_eq!(p3.as_slice(), SHARE_3.as_bytes());
}

// ---- One-file export ----

#[test]
fn one_file_export_single_credential() {
    let methods = vec![passphrase("one-file-pw")];
    let blob = build_export(&shares(), &methods, BulkPackage::OneFile, 2).expect("build one-file");
    assert!(blob.starts_with(b"-----BEGIN AGE ENCRYPTED FILE-----"));

    let plain = decrypt_share(&blob, &decrypt_passphrase("one-file-pw")).expect("decrypt blob");
    let text = String::from_utf8(plain.to_vec()).unwrap();
    assert!(text.contains("# Share 1"), "one-file body should label shares: {text}");
    assert!(text.contains(SHARE_1), "share 1 mnemonic present");
    assert!(text.contains(SHARE_2), "share 2 mnemonic present");
    assert!(text.contains(SHARE_3), "share 3 mnemonic present");
    // Order preserved: share 1 before 2 before 3.
    let i1 = text.find(SHARE_1).unwrap();
    let i2 = text.find(SHARE_2).unwrap();
    let i3 = text.find(SHARE_3).unwrap();
    assert!(i1 < i2 && i2 < i3, "shares must be in order");
}

// ---- Validation ----

#[test]
fn one_file_rejects_per_share_methods() {
    let methods = vec![passphrase("a"), passphrase("b"), passphrase("c")];
    let err = build_export(&shares(), &methods, BulkPackage::OneFile, 2).expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("one") && msg.contains("credential") || msg.contains("OneFile"), "got: {msg}");
}

#[test]
fn zip_rejects_wrong_method_count() {
    // 3 shares + 2 methods (neither 1 nor 3) -> Err at this layer.
    let methods = vec![passphrase("a"), passphrase("b")];
    let err = build_export(&shares(), &methods, BulkPackage::Zip, 2).expect_err("must reject");
    let msg = format!("{err}");
    assert!(msg.contains("method") || msg.contains("share") || msg.contains("count"), "got: {msg}");
}

// ---- No plaintext on disk ----

#[test]
fn no_plaintext_share_in_zip() {
    let methods = vec![passphrase("pw1"), passphrase("pw2"), passphrase("pw3")];
    let zip = build_export(&shares(), &methods, BulkPackage::Zip, 2).expect("build zip");
    let names = zip_names(&zip);
    // No entry may end in plain `.txt` (only `.txt.age` and README.txt).
    for n in &names {
        assert!(
            n.ends_with(".txt.age") || n == "README.txt",
            "unexpected plaintext entry name: {n}"
        );
    }
    // No non-README entry body may contain a plaintext mnemonic.
    for n in &names {
        if n == "README.txt" {
            continue;
        }
        let body = read_zip_entry(&zip, n);
        let body = String::from_utf8_lossy(&body);
        assert!(!body.contains("transfer flea ceramic"), "entry {n} leaks plaintext mnemonic");
    }
}

// ---- README builder ----

#[test]
fn readme_mentions_threshold_and_commands() {
    let methods = vec![passphrase("a"), passphrase("b"), passphrase("c")];
    let readme = build_readme(3, 2, &methods, BulkPackage::Zip);
    assert!(readme.contains("2-of-3"));
    assert!(readme.contains("age -d") || readme.contains("pellitory-39 recover"));
    // Duress caveat (7a) should be mentioned.
    assert!(readme.to_lowercase().contains("duress") || readme.contains("method-matching"));
}

#[test]
fn readme_for_one_file_package() {
    let methods = vec![passphrase("only")];
    let readme = build_readme(3, 2, &methods, BulkPackage::OneFile);
    assert!(readme.contains("2-of-3"));
    assert!(readme.contains("one") && readme.contains("file") || readme.contains("armoured"));
}

// keep `Read` import used
#[allow(dead_code)]
fn _read_used<R: Read>(_r: R) {}