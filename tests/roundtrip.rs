//! Integration tests for the full split -> combine -> derive round-trip.

use pellitory_39::monero;
use pellitory_39::sharing;
use pellitory_39::{detect_and_normalise, InputKind};
use secrecy::ExposeSecret;
use zeroize::Zeroize;

const TEST_SPEND_KEY: &str =
    "af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206";
const EXPECTED_ADDRESS: &str =
    "46HSxE7KoiDaxWFWR1wmJfcrunNj4TLiPJqiCJkQn345A4JJzgBNhUvbkrYWJX4EVJZS4kJGfGj7CTW8GEUHsbEZCEupMt6";
const EXPECTED_MNEMONIC: &str = "spout midst duckling tepid odds glass enhanced \
    avatar ocean rarest eavesdrop egotistic oxygen trying future airport \
    session nanny tedious guru asylum superior cement cunning eavesdrop";

/// Split a hex secret, then combine the threshold shares and return recovered hex.
fn split_and_combine(hex_secret: &str, password: &str, group: (u8, u8)) -> String {
    let master = sharing::MasterSecret::from_hex(hex_secret).expect("valid hex");
    let output = sharing::Slip39Output::split(1, &[group], &master, password, 0, false)
        .expect("split should succeed");

    let json = output.to_json().expect("json");
    let parsed: serde_json::Value = serde_json::from_str(&json).expect("valid json");
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array()
        .expect("shares array")
        .iter()
        .take(group.0 as usize)
        .map(|s| {
            s["mnemonic"]
                .as_str()
                .expect("mnemonic string")
                .split_whitespace()
                .map(str::to_owned)
                .collect()
        })
        .collect();

    let mut recovered = sharing::combine(&shares, password).expect("combine should succeed");
    let hex = hex::encode(&*recovered);
    recovered.zeroize();
    hex
}

// ---- Monero round-trip tests ----

#[test]
fn monero_hex_roundtrip_2of3() {
    let recovered = split_and_combine(TEST_SPEND_KEY, "test", (2, 3));
    assert_eq!(recovered, TEST_SPEND_KEY);
}

#[test]
fn monero_hex_roundtrip_3of5() {
    let recovered = split_and_combine(TEST_SPEND_KEY, "pw", (3, 5));
    assert_eq!(recovered, TEST_SPEND_KEY);
}

#[test]
fn monero_hex_roundtrip_1of1() {
    let recovered = split_and_combine(TEST_SPEND_KEY, "", (1, 1));
    assert_eq!(recovered, TEST_SPEND_KEY);
}

#[test]
fn monero_wallet_survives_roundtrip() {
    let original = monero::derive_keys(TEST_SPEND_KEY).expect("derive");
    let recovered_hex = split_and_combine(TEST_SPEND_KEY, "wallet", (2, 3));
    let recovered = monero::derive_keys(&recovered_hex).expect("derive recovered");

    assert_eq!(recovered.address, original.address, "address mismatch");
    assert_eq!(
        recovered.private_spend_key.expose_secret(),
        original.private_spend_key.expose_secret(),
        "spend key mismatch"
    );
    assert_eq!(
        recovered.private_view_key.expose_secret(),
        original.private_view_key.expose_secret(),
        "view key mismatch"
    );
    assert_eq!(*recovered.mnemonic, *original.mnemonic, "mnemonic mismatch");
    assert_eq!(recovered.address, EXPECTED_ADDRESS, "address vs reference");
}

#[test]
fn monero_mnemonic_input_roundtrip() {
    let (kind, hex) = detect_and_normalise(EXPECTED_MNEMONIC).expect("detect");
    assert_eq!(kind, InputKind::MoneroMnemonic);
    assert_eq!(*hex, TEST_SPEND_KEY);

    let recovered_hex = split_and_combine(&hex, "mn-test", (2, 3));
    let keys = monero::derive_keys(&recovered_hex).expect("derive");
    assert_eq!(keys.address, EXPECTED_ADDRESS);
}

#[test]
fn monero_derive_matches_reference() {
    let keys = monero::derive_keys(TEST_SPEND_KEY).expect("derive");
    assert_eq!(keys.address, EXPECTED_ADDRESS);
    assert_eq!(*keys.mnemonic, EXPECTED_MNEMONIC);
    assert_eq!(
        keys.private_view_key.expose_secret(),
        "157874dc4e2961c872f87aaf4346146d0f596e2f116a51fbac01b693a8e3020a"
    );
    assert_eq!(keys.public_spend_key, "7aff30fbdc005ecb03f57a11e250e0d665621ffde1d44c6aa84a8212cc0d1236");
    assert_eq!(keys.public_view_key, "25c1b6920540fbcfcb0e36bd2c88f5c1e62e5ef1d621279e7230b47648e64a63");
}

// ---- BIP-39 round-trip tests ----

#[test]
fn bip39_roundtrip() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let mnemonic = bip39::Mnemonic::from_phrase(phrase, bip39::Language::English).expect("bip39");
    let entropy_hex = hex::encode(mnemonic.entropy());

    let recovered = split_and_combine(&entropy_hex, "btc", (2, 3));
    assert_eq!(recovered, entropy_hex);

    let recovered_bytes = hex::decode(&recovered).expect("hex");
    let recovered_mnemonic =
        bip39::Mnemonic::from_entropy(&recovered_bytes, bip39::Language::English).expect("from_entropy");
    assert_eq!(recovered_mnemonic.into_phrase(), phrase);
}

// ---- Detection tests ----

#[test]
fn detect_hex() {
    let (kind, hex) = detect_and_normalise(TEST_SPEND_KEY).expect("detect");
    assert_eq!(kind, InputKind::Hex);
    assert_eq!(*hex, TEST_SPEND_KEY);
}

#[test]
fn detect_monero_mnemonic() {
    let (kind, _) = detect_and_normalise(EXPECTED_MNEMONIC).expect("detect");
    assert_eq!(kind, InputKind::MoneroMnemonic);
}

#[test]
fn detect_bip39() {
    let phrase = "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
    let (kind, _) = detect_and_normalise(phrase).expect("detect");
    assert_eq!(kind, InputKind::Bip39Mnemonic);
}

// ---- Share inspection ----

#[test]
fn inspect_shows_threshold() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(1, &[(3, 5)], &master, "test", 0, false).expect("split");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let words: Vec<String> = parsed["groups"][0]["shares"][0]["mnemonic"]
        .as_str()
        .unwrap()
        .split_whitespace()
        .map(str::to_owned)
        .collect();
    let meta = sharing::inspect(&words).expect("inspect");
    assert_eq!(meta.member_threshold, 3);
    assert_eq!(meta.group_count, 1);
    assert_eq!(meta.group_threshold, 1);
}

// ---- Empty password (should work, not panic) ----

#[test]
fn empty_password_roundtrip() {
    let recovered = split_and_combine(TEST_SPEND_KEY, "", (2, 3));
    assert_eq!(recovered, TEST_SPEND_KEY);
}

// ---- Different passwords produce different shares ----

#[test]
fn different_passwords_different_shares() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let j1 = sharing::Slip39Output::split(1, &[(2, 3)], &master, "pass1", 0, false)
        .unwrap().to_json().unwrap();
    let j2 = sharing::Slip39Output::split(1, &[(2, 3)], &master, "pass2", 0, false)
        .unwrap().to_json().unwrap();
    assert_ne!(j1, j2);
}

// ---- Multi-group tests ----

#[test]
fn multi_group_2of3_groups() {
    // Two groups, need both (required_groups = 2).
    // Group 1: 2-of-3, Group 2: 1-of-1
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(
        2,              // need both groups
        &[(2, 3), (1, 1)],
        &master,
        "multi",
        0, false,
    ).expect("split");

    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Take 2 shares from group 1 + 1 share from group 2.
    let mut shares: Vec<Vec<String>> = vec![];
    for g in 0..2 {
        let group_shares = parsed["groups"][g]["shares"].as_array().unwrap();
        let take = if g == 0 { 2 } else { 1 };
        for s in group_shares.iter().take(take) {
            shares.push(
                s["mnemonic"].as_str().unwrap()
                    .split_whitespace().map(str::to_owned).collect()
            );
        }
    }

    let mut recovered = sharing::combine(&shares, "multi").expect("combine");
    let hex = hex::encode(&*recovered);
    recovered.zeroize();
    assert_eq!(hex, TEST_SPEND_KEY, "multi-group recovery failed");
}

#[test]
fn multi_group_wallet_recovery() {
    // Same as above but verify the full Monero wallet.
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(
        2, &[(2, 3), (2, 2)], &master, "org", 0, false,
    ).expect("split");

    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    let mut shares: Vec<Vec<String>> = vec![];
    for g in 0..2 {
        let group_shares = parsed["groups"][g]["shares"].as_array().unwrap();
        let threshold = parsed["groups"][g]["member_threshold"].as_u64().unwrap() as usize;
        for s in group_shares.iter().take(threshold) {
            shares.push(
                s["mnemonic"].as_str().unwrap()
                    .split_whitespace().map(str::to_owned).collect()
            );
        }
    }

    let mut recovered = sharing::combine(&shares, "org").expect("combine");
    let hex = hex::encode(&*recovered);
    let keys = monero::derive_keys(&hex).expect("derive");
    recovered.zeroize();
    assert_eq!(keys.address, EXPECTED_ADDRESS, "multi-group address mismatch");
}

// ---- KDF iteration tests ----

#[test]
fn iteration_exponent_1_roundtrip() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(1, &[(2, 3)], &master, "iter", 1, false)
        .expect("split with iterations=1");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array().unwrap().iter().take(2)
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();
    let mut recovered = sharing::combine(&shares, "iter").expect("combine");
    assert_eq!(hex::encode(&*recovered), TEST_SPEND_KEY);
    recovered.zeroize();
}

#[test]
fn iteration_exponent_2_roundtrip() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(1, &[(2, 3)], &master, "iter2", 2, false)
        .expect("split with iterations=2");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array().unwrap().iter().take(2)
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();
    let mut recovered = sharing::combine(&shares, "iter2").expect("combine");
    assert_eq!(hex::encode(&*recovered), TEST_SPEND_KEY);
    recovered.zeroize();
}

// ---- Wrong password must NOT recover the same secret ----

#[test]
fn wrong_password_produces_wrong_secret() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(1, &[(2, 3)], &master, "correct", 0, false)
        .expect("split");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array().unwrap().iter().take(2)
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();

    // Combine with the WRONG password — SLIP-0039 won't error,
    // it will silently produce the wrong secret.
    let mut recovered = sharing::combine(&shares, "wrong").expect("combine succeeds");
    let hex = hex::encode(&*recovered);
    recovered.zeroize();
    assert_ne!(hex, TEST_SPEND_KEY, "wrong password must not recover the right secret");
}

// ---- Insufficient shares must fail ----

#[test]
fn insufficient_shares_fails() {
    let master = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let output = sharing::Slip39Output::split(1, &[(3, 5)], &master, "test", 0, false)
        .expect("split");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();

    // Only take 2 shares when 3 are needed.
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array().unwrap().iter().take(2)
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();

    let result = sharing::combine(&shares, "test");
    assert!(result.is_err(), "combining insufficient shares must fail");
}

// ---- Fixed identifier (duress / plausible deniability) ----

/// Helper: split a hex secret with an optional fixed identifier and return
/// (first-two-words prefix of share 0, inspect metadata of share 0, all
/// share word-lists).
fn split_with_id(
    hex_secret: &str,
    password: &str,
    group: (u8, u8),
    identifier: Option<u16>,
) -> (String, sharing::ShareMetadata, Vec<Vec<String>>) {
    let master = sharing::MasterSecret::from_hex(hex_secret).expect("hex");
    let output = sharing::Slip39Output::split_with_identifier(
        1, &[group], &master, password, 0, false, identifier,
    )
    .expect("split should succeed");
    let json = output.to_json().unwrap();
    let parsed: serde_json::Value = serde_json::from_str(&json).unwrap();
    let shares: Vec<Vec<String>> = parsed["groups"][0]["shares"]
        .as_array().unwrap().iter()
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();
    let prefix = shares[0].iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    let meta = sharing::inspect(&shares[0]).expect("inspect");
    (prefix, meta, shares)
}

/// Helper: derive the decoy structure from reference share metadata, mirroring
/// the `decoy` subcommand's logic. Returns (groups, required, identifier,
/// iterations).
fn derive_decoy(metas: &[sharing::ShareMetadata]) -> (Vec<(u8, u8)>, u8, u16, u8) {
    let identifier = metas[0].identifier;
    let iterations = metas[0].iterations;
    let group_threshold = metas[0].group_threshold;
    let group_count = metas[0].group_count;
    let mut group_member_thresholds = vec![None; group_count as usize];
    for m in metas {
        group_member_thresholds[m.group_index as usize - 1] = Some(m.member_threshold);
    }
    let groups: Vec<(u8, u8)> = group_member_thresholds
        .iter()
        .map(|opt| {
            let mt = opt.expect("threshold for every group");
            (mt, mt)
        })
        .collect();
    (groups, group_threshold, identifier, iterations)
}

#[test]
fn fixed_identifier_round_trips() {
    // A forced identifier survives a split -> combine round trip.
    let (_prefix, _meta, shares) = split_with_id(TEST_SPEND_KEY, "id", (2, 3), Some(12345));
    let mut recovered = sharing::combine(&shares[..2], "id").expect("combine");
    assert_eq!(hex::encode(&*recovered), TEST_SPEND_KEY);
    recovered.zeroize();
}

#[test]
fn fixed_identifier_is_used_not_random() {
    // The identifier encoded into the share must be exactly the one requested.
    let (_prefix, meta, _shares) = split_with_id(TEST_SPEND_KEY, "id", (2, 3), Some(2024));
    assert_eq!(meta.identifier, 2024);
}

#[test]
fn fixed_identifier_matches_random_prefix_for_same_id() {
    // Core duress property: a Decoy wallet generated with the Real wallet's
    // identifier shares the same first-two-words prefix (identifier ||
    // iteration exponent) as the Real wallet, even though the secrets and
    // passwords differ. An attacker cannot distinguish the shares by their
    // metadata prefix.
    let real = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let real_out = sharing::Slip39Output::split(1, &[(5, 7)], &real, "real-pass", 0, false)
        .expect("real split");
    let real_json = real_out.to_json().unwrap();
    let real_parsed: serde_json::Value = serde_json::from_str(&real_json).unwrap();
    let real_words: Vec<String> = real_parsed["groups"][0]["shares"][0]["mnemonic"]
        .as_str().unwrap().split_whitespace().map(str::to_owned).collect();
    let real_meta = sharing::inspect(&real_words).expect("inspect real");

    // Decoy: different secret, different password, SAME identifier + exponent + group structure.
    let decoy_secret = "deadbeefdeadbeefdeadbeefdeadbeef"; // 16 bytes, valid 128-bit secret
    let (decoy_prefix, decoy_meta, _decoy_shares) =
        split_with_id(decoy_secret, "decoy-pass", (5, 7), Some(real_meta.identifier));

    let real_prefix: String = real_words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    assert_eq!(real_prefix, decoy_prefix,
        "Real and Decoy share prefixes must match for duress indistinguishability");
    assert_eq!(real_meta.identifier, decoy_meta.identifier);
    assert_eq!(real_meta.iterations, decoy_meta.iterations);
    assert_eq!(real_meta.group_threshold, decoy_meta.group_threshold);
    assert_eq!(real_meta.group_count, decoy_meta.group_count);
    assert_eq!(real_meta.member_threshold, decoy_meta.member_threshold);
}

#[test]
fn random_identifiers_differ_across_runs() {
    // Sanity: without --identifier, two splits produce different prefixes
    // (the default random behaviour is preserved).
    let (prefix_a, _, _) = split_with_id(TEST_SPEND_KEY, "a", (2, 3), None);
    let (prefix_b, _, _) = split_with_id(TEST_SPEND_KEY, "b", (2, 3), None);
    assert_ne!(prefix_a, prefix_b,
        "random identifiers should differ across independent splits");
}

// ---- Decoy subcommand logic (auto-derived structure) ----

#[test]
fn decoy_single_group_matches_real_metadata() {
    // The core duress property: a decoy generated from a Real share inherits
    // the Real wallet's identifier, iteration exponent, and group structure,
    // so share prefixes are identical even though secrets and passwords differ.
    let real = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let real_out = sharing::Slip39Output::split(1, &[(5, 7)], &real, "real-pass", 0, false)
        .expect("real split");
    let real_json = real_out.to_json().unwrap();
    let real_parsed: serde_json::Value = serde_json::from_str(&real_json).unwrap();
    let real_words: Vec<String> = real_parsed["groups"][0]["shares"][0]["mnemonic"]
        .as_str().unwrap().split_whitespace().map(str::to_owned).collect();
    let real_meta = sharing::inspect(&real_words).expect("inspect real");

    // Derive decoy structure from the Real share's metadata.
    let (groups, required, identifier, iterations) =
        derive_decoy(std::slice::from_ref(&real_meta));
    assert_eq!(required, 1);
    assert_eq!(groups, vec![(5, 5)]); // member_count defaults to threshold

    // Generate the decoy with a different secret + password.
    let decoy_secret = "deadbeefdeadbeefdeadbeefdeadbeef";
    let decoy_master = sharing::MasterSecret::from_hex(decoy_secret).expect("hex");
    let decoy_out = sharing::Slip39Output::split_with_identifier(
        required, &groups, &decoy_master, "decoy-pass", iterations, false, Some(identifier),
    )
    .expect("decoy split");
    let decoy_json = decoy_out.to_json().unwrap();
    let decoy_parsed: serde_json::Value = serde_json::from_str(&decoy_json).unwrap();
    let decoy_words: Vec<String> = decoy_parsed["groups"][0]["shares"][0]["mnemonic"]
        .as_str().unwrap().split_whitespace().map(str::to_owned).collect();
    let decoy_meta = sharing::inspect(&decoy_words).expect("inspect decoy");

    let real_prefix: String = real_words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    let decoy_prefix: String = decoy_words.iter().take(2).cloned().collect::<Vec<_>>().join(" ");
    assert_eq!(real_prefix, decoy_prefix,
        "Real and Decoy share prefixes must match");
    assert_eq!(real_meta.identifier, decoy_meta.identifier);
    assert_eq!(real_meta.iterations, decoy_meta.iterations);
    assert_eq!(real_meta.group_threshold, decoy_meta.group_threshold);
    assert_eq!(real_meta.group_count, decoy_meta.group_count);
    assert_eq!(real_meta.member_threshold, decoy_meta.member_threshold);
}

#[test]
fn decoy_round_trips_and_secret_differs() {
    let real = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let real_out = sharing::Slip39Output::split(1, &[(2, 3)], &real, "real-pass", 0, false)
        .expect("real split");
    let real_json = real_out.to_json().unwrap();
    let real_parsed: serde_json::Value = serde_json::from_str(&real_json).unwrap();
    let real_words: Vec<String> = real_parsed["groups"][0]["shares"][0]["mnemonic"]
        .as_str().unwrap().split_whitespace().map(str::to_owned).collect();
    let real_meta = sharing::inspect(&real_words).expect("inspect");

    let (groups, required, identifier, iterations) = derive_decoy(&[real_meta]);
    let decoy_secret = "deadbeefdeadbeefdeadbeefdeadbeef";
    let decoy_master = sharing::MasterSecret::from_hex(decoy_secret).expect("hex");
    let decoy_out = sharing::Slip39Output::split_with_identifier(
        required, &groups, &decoy_master, "decoy-pass", iterations, false, Some(identifier),
    )
    .expect("decoy split");
    let decoy_json = decoy_out.to_json().unwrap();
    let decoy_parsed: serde_json::Value = serde_json::from_str(&decoy_json).unwrap();
    let decoy_shares: Vec<Vec<String>> = decoy_parsed["groups"][0]["shares"]
        .as_array().unwrap().iter()
        .map(|s| s["mnemonic"].as_str().unwrap()
            .split_whitespace().map(str::to_owned).collect())
        .collect();

    // Decoy recovers to the decoy secret, NOT the real secret.
    let mut recovered = sharing::combine(&decoy_shares, "decoy-pass").expect("combine");
    let hex = hex::encode(&*recovered);
    recovered.zeroize();
    assert_eq!(hex, decoy_secret);
    assert_ne!(hex, TEST_SPEND_KEY);
}

#[test]
fn decoy_multi_group_one_share_per_group() {
    // Multi-group Real wallet: need one reference share per group to learn
    // each group's member threshold.
    let real = sharing::MasterSecret::from_hex(TEST_SPEND_KEY).expect("hex");
    let real_out = sharing::Slip39Output::split(
        2, &[(2, 3), (1, 1), (3, 5)], &real, "real-pass", 0, false,
    )
    .expect("real split");
    let real_json = real_out.to_json().unwrap();
    let real_parsed: serde_json::Value = serde_json::from_str(&real_json).unwrap();

    let mut metas = vec![];
    for g in 0..3 {
        let words: Vec<String> = real_parsed["groups"][g]["shares"][0]["mnemonic"]
            .as_str().unwrap().split_whitespace().map(str::to_owned).collect();
        metas.push(sharing::inspect(&words).expect("inspect"));
    }

    let (groups, required, identifier, iterations) = derive_decoy(&metas);
    assert_eq!(required, 2);
    assert_eq!(groups, vec![(2, 2), (1, 1), (3, 3)]);

    let decoy_secret = "deadbeefdeadbeefdeadbeefdeadbeef";
    let decoy_master = sharing::MasterSecret::from_hex(decoy_secret).expect("hex");
    let decoy_out = sharing::Slip39Output::split_with_identifier(
        required, &groups, &decoy_master, "decoy-pass", iterations, false, Some(identifier),
    )
    .expect("decoy split");
    let decoy_json = decoy_out.to_json().unwrap();
    let decoy_parsed: serde_json::Value = serde_json::from_str(&decoy_json).unwrap();

    // Each group's threshold matches the Real wallet's.
    for (i, g) in decoy_parsed["groups"].as_array().unwrap().iter().enumerate() {
        let real_thr = real_parsed["groups"][i]["member_threshold"].as_u64().unwrap();
        let decoy_thr = g["member_threshold"].as_u64().unwrap();
        assert_eq!(real_thr, decoy_thr, "group {} threshold mismatch", i);
    }

    // Prefixes match across all groups.
    for i in 0..3 {
        let rp: String = real_parsed["groups"][i]["shares"][0]["mnemonic"]
            .as_str().unwrap().split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        let dp: String = decoy_parsed["groups"][i]["shares"][0]["mnemonic"]
            .as_str().unwrap().split_whitespace().take(2).collect::<Vec<_>>().join(" ");
        assert_eq!(rp, dp, "group {} prefix mismatch", i);
    }
}
