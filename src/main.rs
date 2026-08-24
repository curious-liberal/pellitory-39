//! Pellitory-39: Secure backup and recovery for cryptocurrency wallets.
//!
//! Split spend keys and seed phrases into SLIP-0039 shares and recover
//! them later. Generate fresh Monero wallets with immediate splitting.
//! Supports Bitcoin (BIP-39), Monero (25-word), and raw hex secrets.

use anyhow::{anyhow, Result};
use clap::{CommandFactory, Parser, Subcommand};
use rand::rngs::OsRng;
use rand::RngCore;
use secrecy::ExposeSecret;
use std::io::{self, Read};
use zeroize::{Zeroize, Zeroizing};

use pellitory_39::monero;
use pellitory_39::sharing;
use pellitory_39::{detect_and_normalise, Coin, InputKind};

#[cfg(feature = "gui")]
mod gui;

/// Default KDF iteration exponent for SLIP-0039.
/// 1 matches the Trezor default (20,000 PBKDF2 iterations total).
/// Higher values make brute-force attacks on individual shares harder
/// at the cost of slower splitting and combining.
const DEFAULT_ITERATIONS: &str = "1";

/// Maximum number of bytes read from stdin when a command accepts the `-`
/// sentinel (e.g. `derive -s -`). Caps the allocation so a huge pipe (such
/// as `cat /dev/zero | pellitory-39 derive -s -`) cannot exhaust memory.
/// A Monero spend key is 64 hex chars and a 25-word mnemonic is a few
/// hundred bytes, so 4 KiB is ample headroom.
const MAX_STDIN_BYTES: usize = 4 * 1024;

/// Parse a `--coin`/`-c` value for clap's `value_parser`.
///
/// Accepts the case-insensitive aliases handled by [`Coin::parse`]
/// (bitcoin/btc, monero/xmr, hex), returning a `String` error that clap
/// surfaces to the user.
fn parse_coin(s: &str) -> Result<Coin, String> {
    Coin::parse(s).map_err(|e| e.to_string())
}

/// Parse a `--coin`/`-c` value for the `derive` command, which only
/// accepts bitcoin and monero (not hex). Hex input is valid for both —
/// `--coin` disambiguates whether the hex is entropy (bitcoin) or a
/// spend key (monero) — so `hex` is rejected at parse time with a clap
/// usage error (exit 2) rather than a runtime error.
fn parse_derive_coin(s: &str) -> Result<Coin, String> {
    match Coin::parse(s) {
        Ok(Coin::Hex) => Err(
            "--coin hex is not valid for derive. Use --coin bitcoin to turn \
             hex entropy into a BIP-39 phrase, or --coin monero to derive \
             Monero keys from a hex spend key."
                .to_string(),
        ),
        Ok(c) => Ok(c),
        Err(e) => Err(e.to_string()),
    }
}

// ─── CLI definitions ────────────────────────────────────────────────────────

/// Pellitory-39 — secure wallet backup using SLIP-0039 secret sharing.
///
/// Split a Bitcoin seed phrase, Monero spend key, or any hex secret into
/// threshold-recoverable SLIP-0039 shares. Distribute them across
/// multiple locations. Combine shares later to recover the original
/// secret and restore your wallet.
///
/// Supports:
///   • Bitcoin / Ethereum  — 12/15/18/21/24-word BIP-39 mnemonics
///   • Monero              — 25-word mnemonics or 64-char hex spend keys
///   • Any hex secret      — up to 64 bytes
///
/// QUICK START:
///
///   Generate a fresh Monero wallet and split it into 3-of-5 shares:
///     pellitory-39 generate --coin monero --group 3of5
///
///   Split an existing Monero spend key:
///     pellitory-39 split --coin monero --group 2of3
///
///   Split a Bitcoin seed phrase:
///     pellitory-39 split --coin bitcoin --group 2of3
///
///   Recover from shares:
///     pellitory-39 recover --coin monero
///
///   Derive Monero keys from a spend key:
///     pellitory-39 derive --coin monero
///
///   Generate a Decoy Wallet matching an existing Real wallet's shares:
///     pellitory-39 decoy --coin monero -m "<real share>"
///
///   Generate a Real + Decoy pair in one step (duress):
///     pellitory-39 generate --coin monero --decoy --group 3of5 \
///       -p realpass --decoy-password decoypass
#[derive(Parser)]
#[command(name = "pellitory-39", version, about, long_about = None)]
#[command(after_help = "\
SECURITY:
  All secrets are wiped from memory after use. Passwords and keys are
  prompted with hidden input by default — they never appear on screen,
  in terminal scrollback, or in shell history.

  For automation, use environment variables:
    PELLITORY_PASSWORD        SLIP-0039 password
    PELLITORY_DECOY_PASSWORD  Decoy wallet password (generate --decoy)
    PELLITORY_ENTROPY         Secret to split

SOURCE & DOCS:
  https://gitlab.com/curiio/pellitory-39")]
struct Cli {
    /// Launch the desktop GUI (eframe/egui) instead of a CLI command.
    ///
    /// When this flag is passed, all other CLI arguments are ignored and
    /// the application opens a window with a simple duress-compatible
    /// generate / recover interface for Bitcoin and Monero.
    #[arg(long)]
    gui: bool,

    #[command(subcommand)]
    command: Option<Commands>,
}

#[derive(Subcommand)]
enum Commands {
    /// Generate a fresh secret and immediately split it into shares.
    ///
    /// With --coin monero, this generates a cryptographically random
    /// Monero wallet (using OS entropy via OsRng) and splits the spend
    /// key into SLIP-0039 shares in a single step. The wallet address
    /// is displayed so you can verify it before distributing shares.
    ///
    /// With --coin bitcoin, generates random BIP-39-valid entropy (128 /
    /// 160 / 192 / 224 / 256 bits) and splits it; recover with
    /// `recover --coin bitcoin` to obtain the seed phrase.
    ///
    /// With --coin hex, generates random entropy of the specified bit
    /// length and splits it (recover as raw hex).
    ///
    /// EXAMPLES:
    ///
    ///   # Generate a fresh Monero wallet, split into 3-of-5 shares
    ///
    ///   pellitory-39 generate --coin monero --group 3of5
    ///
    ///   # Generate a fresh Monero wallet, 2-of-3 shares (shorthand)
    ///
    ///   pellitory-39 gen -c xmr --group 2of3
    ///
    ///   # Generate a 256-bit Bitcoin seed, 2-of-3 shares
    ///
    ///   pellitory-39 generate --coin bitcoin --group 2of3
    ///
    ///   # Generate 256 bits of random hex entropy (for any purpose)
    ///
    ///   pellitory-39 generate --coin hex --group 2of3
    ///
    ///   # Multiple groups — need any 2 of 3 groups to recover
    ///
    ///   pellitory-39 generate --coin monero --required-groups 2 --group 2of3 --group 1of1 --group 3of5
    ///
    ///   # Generate a Real + Decoy pair (duress / plausible deniability)
    ///
    ///   pellitory-39 generate --coin monero --decoy -p realpass --decoy-password decoypass --group 3of5
    ///
    ///   # Generate + encrypt both to age-armoured ZIPs (--decoy-out defaults to real-decoy.zip)
    ///
    ///   pellitory-39 generate --coin monero --decoy --group 3of5 --out real.zip --encrypt-with-slip-password --decoy-encrypt-with-slip-password
    #[command(alias = "gen")]
    Generate {
        /// Coin / secret family to generate: bitcoin, monero, or hex.
        /// Accepts the tickers btc / xmr. Determines what the secret
        /// represents and how it is recovered later.
        #[arg(short = 'c', long, value_parser = parse_coin)]
        coin: Coin,

        /// Bit length of the random secret. Ignored for --coin monero
        /// (spend keys are always 256 bits). For --coin bitcoin must be
        /// one of 128 / 160 / 192 / 224 / 256. For --coin hex must be a
        /// multiple of 16 and at least 128.
        #[arg(short, long, default_value = "256")]
        bits: u16,

        /// SLIP-0039 password for encrypting shares. You'll need this
        /// same password when combining shares later. Omit for a hidden
        /// interactive prompt.
        #[arg(short, long, env = "PELLITORY_PASSWORD", hide_env_values = true, conflicts_with = "no_password")]
        password: Option<String>,

        /// Use an empty password without prompting. Conflicts with -p /
        /// --password. Without a password, anyone with enough shares can
        /// recover the wallet — there is no second factor (a warning is
        /// printed). Valid per SLIP-0039 (matches Trezor).
        #[arg(long, conflicts_with = "password")]
        no_password: bool,

        /// Group specification: <threshold>of<total> (e.g. 2of3, 3of5).
        /// Repeat for multiple groups. At least one is required.
        #[arg(short, long = "group", required = true, num_args = 1)]
        groups: Vec<String>,

        /// Number of groups required to recover the secret.
        /// Default: all groups are required.
        #[arg(short, long)]
        required_groups: Option<u8>,

        /// KDF iteration exponent. Higher = slower but harder to
        /// brute-force. Default: 1 (matches Trezor). Recommended: 1–2.
        #[arg(short, long, default_value = DEFAULT_ITERATIONS)]
        iterations: u8,

        /// Force the SLIP-0039 15-bit identifier (0–32767) instead of
        /// generating a random one. The identifier is encoded into the
        /// first two mnemonic words (together with the iteration
        /// exponent).
        ///
        /// DURESS / PLAUSIBLE DENIABILITY: generate a Real Wallet, note
        /// its identifier (e.g. via `pellitory-39 inspect`), then
        /// generate a Decoy Wallet with the same `--identifier`, the
        /// same `--iterations`, the same `--extendable`, and the same
        /// group structure. Shares from both wallets will then start
        /// with identical words, so an attacker cannot distinguish Real
        /// shares from Decoy shares by their metadata prefix alone.
        #[arg(long)]
        identifier: Option<u16>,

        /// Use the SLIP-0039 extendable-backup format (`ext = 1`).
        ///
        /// With this flag the identifier is NOT used as PBKDF2 salt, so
        /// multiple share sets with distinct identifiers all recover the
        /// same master secret for a given passphrase. This lets you start
        /// with a 1-of-1 share and later upgrade to a multi-share scheme
        /// while keeping the same encrypted master secret and passphrase.
        ///
        /// OFF BY DEFAULT (`ext = 0`), which matches the original SLIP-0039
        /// format where the identifier is mixed into the salt. Shares
        /// created with `--extendable` are NOT compatible with `ext = 0`
        /// shares (the RS1024 customization string also differs).
        #[arg(long, default_value_t = false)]
        extendable: bool,

        /// Generate a Decoy wallet alongside the Real wallet (duress /
        /// plausible deniability). The decoy uses a different secret and
        /// password but inherits the Real wallet's identifier, iteration
        /// exponent, and group structure, so every Decoy share begins
        /// with the same words as the corresponding Real share — an
        /// attacker cannot tell them apart by their metadata prefix.
        ///
        /// The Decoy shares are printed as a second JSON object after
        /// the Real shares. Use `--decoy-password` to set the decoy
        /// password (or omit it for a hidden prompt).
        #[arg(long, default_value_t = false)]
        decoy: bool,

        /// Password for the DECOY wallet (only with --decoy). This
        /// should be DIFFERENT from the Real wallet's password. Omit
        /// for a hidden interactive prompt.
        #[arg(long, env = "PELLITORY_DECOY_PASSWORD", hide_env_values = true, conflicts_with = "no_decoy_password")]
        decoy_password: Option<String>,

        /// Use an empty decoy password without prompting. Conflicts with
        /// --decoy-password. Only meaningful with --decoy.
        #[arg(long, conflicts_with = "decoy_password")]
        no_decoy_password: bool,

        // ── Encrypted export (phase 003) ───────────────────────────────

        /// Output path for the encrypted share export. Use '-' for stdout
        /// (binary ZIP, or armoured blob for --package one-file). When set,
        /// JSON-to-stdout is suppressed — shares never appear in plaintext
        /// on stdout. If set without any --encrypt-* flags, an interactive
        /// prompt walks you through choosing an encryption method.
        #[arg(short, long)]
        out: Option<String>,

        /// Package format: 'zip' (per-share .age entries + README.txt) or
        /// 'one-file' (single armoured blob, one credential). Default: zip.
        #[arg(long, default_value = "zip")]
        package: String,

        /// Encrypt every share with this passphrase (bulk — all shares
        /// use the same passphrase). Set PELLITORY_ENCRYPT_PASSPHRASE for
        /// non-interactive use (recommended; avoids shell history). For
        /// per-share passphrases, use --encrypt-passphrase-file.
        #[arg(long, env = "PELLITORY_ENCRYPT_PASSPHRASE", hide_env_values = true)]
        encrypt_passphrase: Option<String>,

        /// Encrypt one share to this recipient ('age1...' / 'ssh-ed25519 ...'
        /// / 'ssh-rsa ...'). Repeatable for per-share. Count == 1 -> bulk,
        /// count == share count -> per-share, else error. In interactive
        /// mode (TTY), recipient fingerprints are shown and you are asked
        /// to confirm; in non-interactive mode, pass --confirm-recipient.
        #[arg(long = "encrypt-to")]
        encrypt_to: Vec<String>,

        /// Read one share's recipient from a file (first non-empty line).
        /// Repeatable for per-share. One file per share position.
        #[arg(long = "encrypt-to-file")]
        encrypt_to_file: Vec<String>,

        /// Read one share's passphrase from a file. Repeatable for
        /// per-share. One file per share position (file read once, in-memory
        /// copy zeroised; the file on disk is your responsibility).
        #[arg(long)]
        encrypt_passphrase_file: Vec<String>,

        /// Reuse the SLIP-0039 password as the age encryption passphrase
        /// (bulk — all shares). Avoids entering two passwords. Conflicts
        /// with --encrypt-passphrase and per-share --encrypt-* flags.
        #[arg(long)]
        encrypt_with_slip_password: bool,

        /// Acknowledge that you possess the matching private key for every
        /// --encrypt-to / --encrypt-to-file recipient. Prints fingerprints
        /// to stderr. Only needed in non-interactive mode (scripts, pipes);
        /// in a TTY you are prompted to confirm interactively instead.
        #[arg(long)]
        confirm_recipient: bool,

        // ── Decoy encrypted export parity (Generate only) ──────────────

        /// Output path for the DECOY wallet's encrypted export. Only with
        /// --decoy. Defaults to <real-out>-decoy.<ext> when --out is set.
        /// Real and Decoy are written as two separate files.
        #[arg(long, requires = "decoy")]
        decoy_out: Option<String>,

        /// Encrypt every Decoy share with this passphrase (bulk). Set
        /// PELLITORY_DECOY_ENCRYPT_PASSPHRASE for non-interactive use.
        #[arg(long, env = "PELLITORY_DECOY_ENCRYPT_PASSPHRASE", hide_env_values = true, requires = "decoy")]
        decoy_encrypt_passphrase: Option<String>,

        /// Encrypt one Decoy share to this recipient. Repeatable.
        #[arg(long = "decoy-encrypt-to", requires = "decoy")]
        decoy_encrypt_to: Vec<String>,

        /// Read one Decoy share's recipient from a file. Repeatable.
        #[arg(long = "decoy-encrypt-to-file", requires = "decoy")]
        decoy_encrypt_to_file: Vec<String>,

        /// Read one Decoy share's passphrase from a file. Repeatable.
        #[arg(long, requires = "decoy")]
        decoy_encrypt_passphrase_file: Vec<String>,

        /// Reuse the Decoy SLIP-0039 password as the age encryption
        /// passphrase (bulk) for the Decoy shares.
        #[arg(long, requires = "decoy")]
        decoy_encrypt_with_slip_password: bool,

        /// Acknowledge key possession for --decoy-encrypt-to /
        /// --decoy-encrypt-to-file. Only needed in non-interactive mode;
        /// in a TTY you are prompted to confirm interactively.
        #[arg(long, requires = "decoy")]
        decoy_confirm_recipient: bool,

        /// Package format for the Decoy export. Default: same as --package.
        #[arg(long, requires = "decoy")]
        decoy_package: Option<String>,
    },

    /// Split an existing secret into SLIP-0039 shares.
    ///
    /// Accepts any of the following as input:
    ///
    /// - A 64-char hex spend key (Monero) or any hex secret
    ///
    /// - A 25-word Monero mnemonic seed
    ///
    /// - A 12/15/18/21/24-word BIP-39 mnemonic (Bitcoin, Ethereum, etc.)
    ///
    /// The input format is auto-detected. If you don't pass --entropy,
    /// you'll be prompted with hidden input (nothing appears on screen).
    ///
    /// --coin selects how the secret is interpreted and what is shown for
    /// verification: --coin monero derives and displays the Monero address;
    /// --coin bitcoin and --coin hex split without coin-specific output.
    ///
    /// EXAMPLES:
    ///
    ///   # Interactive — split any secret into 2-of-3 shares
    ///
    ///   pellitory-39 split --coin hex --group 2of3
    ///
    ///   # Split a Monero spend key (shows address for verification)
    ///
    ///   pellitory-39 split --coin monero --group 2of3
    ///
    ///   # Split a 24-word Bitcoin seed phrase
    ///
    ///   pellitory-39 split --coin bitcoin --group 3of5
    ///
    ///   # Multiple groups — need any 2 of 3 groups to recover
    ///
    ///   pellitory-39 split --coin hex --required-groups 2 --group 2of3 --group 1of1 --group 3of5
    ///
    ///   # Via environment variables (for scripts)
    ///
    ///   PELLITORY_ENTROPY="af6082..." PELLITORY_PASSWORD="pass" pellitory-39 split --coin hex --group 2of3
    ///
    ///   # Encrypt shares to a ZIP (one password for both SLIP-0039 and age)
    ///
    ///   pellitory-39 split --coin hex --group 2of3 --out shares.zip --encrypt-with-slip-password
    ///
    ///   # Encrypt each share to a different recipient (per-share)
    ///
    ///   pellitory-39 split --coin hex --group 2of3 --out shares.zip --encrypt-to age1qz... --encrypt-to ssh-ed25519 AAAA... --encrypt-passphrase-file pass3.txt
    ///
    ///   # Interactive encrypt (just pass --out, pick a method at the prompt)
    ///
    ///   pellitory-39 split --coin hex --group 2of3 --out shares.zip
    Split {
        /// Secret to split: hex string, 25-word Monero mnemonic, or
        /// 12/15/18/21/24-word BIP-39 mnemonic. Auto-detected. Omit for a
        /// hidden interactive prompt (recommended). The prompt adapts to
        /// --coin: bitcoin hints at hex / BIP-39, monero at a hex spend
        /// key / 25-word Monero mnemonic, hex at a raw hex string. Any
        /// supported format is auto-detected regardless of --coin.
        #[arg(short, long, env = "PELLITORY_ENTROPY", hide_env_values = true)]
        entropy: Option<String>,

        /// SLIP-0039 password for encrypting shares. You'll need this
        /// same password when combining shares later. Omit for a hidden
        /// interactive prompt.
        #[arg(short, long, env = "PELLITORY_PASSWORD", hide_env_values = true)]
        password: Option<String>,

        /// Coin / secret family: bitcoin, monero, or hex. With monero,
        /// the Monero address is derived and displayed for verification.
        /// Accepts the tickers btc / xmr.
        #[arg(short = 'c', long, value_parser = parse_coin)]
        coin: Coin,

        /// Group specification: <threshold>of<total> (e.g. 2of3, 3of5).
        /// Repeat for multiple groups. At least one is required.
        #[arg(short, long = "group", required = true, num_args = 1)]
        groups: Vec<String>,

        /// Number of groups required to recover the secret.
        /// Default: all groups are required.
        #[arg(short, long)]
        required_groups: Option<u8>,

        /// KDF iteration exponent. Higher = slower but harder to
        /// brute-force. Default: 1 (matches Trezor). Recommended: 1–2.
        #[arg(short, long, default_value = DEFAULT_ITERATIONS)]
        iterations: u8,

        /// Force the SLIP-0039 15-bit identifier (0–32767) instead of
        /// generating a random one. See `generate --identifier` for the
        /// duress / plausible-deniability use case.
        #[arg(long)]
        identifier: Option<u16>,

        /// Use the SLIP-0039 extendable-backup format (`ext = 1`).
        /// See `generate --extendable` for details. Off by default.
        #[arg(long, default_value_t = false)]
        extendable: bool,

        // ── Encrypted export (phase 003) ───────────────────────────────

        /// Output path for the encrypted share export. Use '-' for stdout
        /// (binary ZIP, or armoured blob for --package one-file). When set,
        /// JSON-to-stdout is suppressed. If set without any --encrypt-*
        /// flags, an interactive prompt walks you through choosing an
        /// encryption method.
        #[arg(short, long)]
        out: Option<String>,

        /// Package format: 'zip' or 'one-file'. Default: zip.
        #[arg(long, default_value = "zip")]
        package: String,

        /// Encrypt every share with this passphrase (bulk).
        #[arg(long, env = "PELLITORY_ENCRYPT_PASSPHRASE", hide_env_values = true)]
        encrypt_passphrase: Option<String>,

        /// Encrypt one share to this recipient ('age1...' / 'ssh-ed25519 ...'
        /// / 'ssh-rsa ...'). Repeatable for per-share. Count == 1 -> bulk,
        /// count == share count -> per-share, else error. In interactive
        /// mode (TTY), recipient fingerprints are shown and you are asked
        /// to confirm; in non-interactive mode, pass --confirm-recipient.
        #[arg(long = "encrypt-to")]
        encrypt_to: Vec<String>,

        /// Read one share's recipient from a file (first non-empty line).
        /// Repeatable for per-share.
        #[arg(long = "encrypt-to-file")]
        encrypt_to_file: Vec<String>,

        /// Read one share's passphrase from a file. Repeatable.
        #[arg(long)]
        encrypt_passphrase_file: Vec<String>,

        /// Reuse the SLIP-0039 password as the age encryption passphrase
        /// (bulk — all shares).
        #[arg(long)]
        encrypt_with_slip_password: bool,

        /// Acknowledge key possession for --encrypt-to / --encrypt-to-file.
        /// Only needed in non-interactive mode; in a TTY you are prompted
        /// to confirm interactively.
        #[arg(long)]
        confirm_recipient: bool,
    },

    /// Generate a Decoy Wallet whose shares are indistinguishable from
    /// an existing Real Wallet's shares.
    ///
    /// Provide one or more Real shares as a metadata reference (`-m`).
    /// The decoy inherits the Real wallet's identifier, iteration
    /// exponent, and group structure, so every Decoy share begins with
    /// the same words as the corresponding Real share. The decoy secret
    /// itself is completely different and should use a different
    /// password.
    ///
    /// This is the recommended way to set up plausible deniability —
    /// it auto-derives the full metadata structure so you don't have to
    /// copy identifiers or retype group specs by hand.
    ///
    /// EXAMPLES:
    ///
    ///   # Generate a fresh Monero decoy matching an existing Real share
    ///
    ///   pellitory-39 decoy --coin monero -m "academic arcade academic acrobat ..."
    ///
    ///   # Generate random-entropy decoy (default 256 bits)
    ///
    ///   pellitory-39 decoy --coin hex -m "academic arcade ..."
    ///
    ///   # Split an existing low-value secret as a decoy
    ///
    ///   pellitory-39 decoy --coin hex -m "academic arcade ..." -e "<hex or mnemonic>"
    ///
    ///   # Multi-group: provide one reference share per group
    ///
    ///   pellitory-39 decoy --coin monero -m "academic arcade ..." -m "academic arcade beard ..."
    Decoy {
        /// Reference Real share(s). For a single-group wallet, one share
        /// is enough. For a multi-group wallet, provide one share per
        /// group (so each group's member threshold is learned), or
        /// supply `--group` for all groups. If omitted, you'll be
        /// prompted for a single share interactively.
        #[arg(short, long = "mnemonic")]
        mnemonics: Vec<String>,

        /// Decoy secret to split (hex, 25-word Monero mnemonic, or
        /// 12/15/18/21/24-word BIP-39 mnemonic). Auto-detected. Omit to
        /// generate fresh random entropy.
        #[arg(short, long, env = "PELLITORY_ENTROPY", hide_env_values = true)]
        entropy: Option<String>,

        /// Coin / secret family: bitcoin, monero, or hex. With monero,
        /// a fresh Monero wallet is generated (when no --entropy) and
        /// the address is displayed. With bitcoin, fresh BIP-39-valid
        /// entropy is generated. With hex, arbitrary --bits. Accepts
        /// btc / xmr.
        #[arg(short = 'c', long, value_parser = parse_coin)]
        coin: Coin,

        /// Bit length for random decoy entropy (ignored with --entropy,
        /// or with --coin monero). For --coin bitcoin must be one of
        /// 128/160/192/224/256; for --coin hex any multiple of 16 from
        /// 128 to 512. Default: 256.
        #[arg(short, long, default_value = "256")]
        bits: u16,

        /// SLIP-0039 password for the DECOY wallet. This should be
        /// DIFFERENT from the Real wallet's password. Omit for a hidden
        /// prompt.
        #[arg(short, long, env = "PELLITORY_PASSWORD", hide_env_values = true, conflicts_with = "no_password")]
        password: Option<String>,

        /// Use an empty password without prompting. Conflicts with -p /
        /// --password. Without a password, anyone with enough shares can
        /// recover the wallet — there is no second factor (a warning is
        /// printed). Valid per SLIP-0039 (matches Trezor).
        #[arg(long, conflicts_with = "password")]
        no_password: bool,

        /// Optional member counts per group (e.g. `--group 5of7`). By
        /// default the decoy generates exactly the threshold number of
        /// shares per group (enough to recover). Provide `--group` to
        /// generate more shares. The thresholds must match the Real
        /// wallet and are validated against the reference shares.
        #[arg(short, long = "group", num_args = 1)]
        groups: Vec<String>,

        // ── Encrypted export (phase 003) ───────────────────────────────

        /// Output path for the encrypted share export. Use '-' for stdout.
        /// If set without any --encrypt-* flags, an interactive prompt
        /// walks you through choosing an encryption method (TTY only).
        #[arg(short, long)]
        out: Option<String>,

        /// Package format: 'zip' or 'one-file'. Default: zip.
        #[arg(long, default_value = "zip")]
        package: String,

        /// Encrypt every share with this passphrase (bulk).
        #[arg(long, env = "PELLITORY_ENCRYPT_PASSPHRASE", hide_env_values = true)]
        encrypt_passphrase: Option<String>,

        /// Encrypt one share to this recipient ('age1...' / 'ssh-ed25519 ...'
        /// / 'ssh-rsa ...'). Repeatable for per-share. Count == 1 -> bulk,
        /// count == share count -> per-share, else error. In interactive
        /// mode (TTY), recipient fingerprints are shown and you are asked
        /// to confirm; in non-interactive mode, pass --confirm-recipient.
        #[arg(long = "encrypt-to")]
        encrypt_to: Vec<String>,

        /// Read one share's recipient from a file (first non-empty line).
        /// Repeatable for per-share.
        #[arg(long = "encrypt-to-file")]
        encrypt_to_file: Vec<String>,

        /// Read one share's passphrase from a file. Repeatable.
        #[arg(long)]
        encrypt_passphrase_file: Vec<String>,

        /// Reuse the SLIP-0039 password as the age encryption passphrase
        /// (bulk — all shares).
        #[arg(long)]
        encrypt_with_slip_password: bool,

        /// Acknowledge key possession for --encrypt-to / --encrypt-to-file.
        /// Only needed in non-interactive mode; in a TTY you are prompted
        /// to confirm interactively.
        #[arg(long)]
        confirm_recipient: bool,
    },

    /// Recover the original secret from SLIP-0039 shares.
    ///
    /// Provide the threshold number of shares and the password used
    /// during splitting. If you don't pass any --mnemonic flags, you'll
    /// be prompted to enter shares interactively (hidden input).
    ///
    /// OUTPUT FORMATS (selected by --coin):
    ///
    /// - --coin monero: Derive and display the full Monero wallet (keys + address)
    ///
    /// - --coin bitcoin: Output the recovered secret as a BIP-39 mnemonic
    ///
    /// - --coin hex: Output the recovered secret as raw hex
    ///
    /// NOTE: SLIP-0039 cannot verify the password. A wrong password yields a
    /// plausible but WRONG secret with no error (this also enables duress /
    /// plausible deniability — see `decoy` and SECURITY.md). Always compare
    /// the recovered address against the one recorded at generation time.
    ///
    /// EXAMPLES:
    ///
    ///   # Fully interactive — prompts for shares and password
    ///
    ///   pellitory-39 recover --coin monero
    ///
    ///   # Recover a Bitcoin seed phrase
    ///
    ///   pellitory-39 recover --coin bitcoin
    ///
    ///   # Recover as raw hex
    ///
    ///   pellitory-39 recover --coin hex
    ///
    ///   # Pass shares on the command line
    ///
    ///   pellitory-39 recover --coin monero -m "transfer flea ceramic round ..." -m "transfer flea ceramic scatter ..."
    ///
    ///   # Recover from age-armoured shares in files (auto-detects armour), reuse SLIP-0039 password
    ///
    ///   pellitory-39 recover --coin hex -m @share1.txt.age -m @share2.txt.age --decrypt-with-slip-password
    ///
    ///   # Recover with an age identity or SSH key file (auto-detected)
    ///
    ///   pellitory-39 recover --coin hex -m @share1.txt.age -m @share2.txt.age --decrypt-key key.txt
    ///
    ///   # Heterogeneous shares (each encrypted differently) — supply a credential pool
    ///
    ///   pellitory-39 recover --coin hex -m @share1.txt.age -m @share2.txt.age -m @share3.txt.age --decrypt-passphrase passA --decrypt-passphrase passB --decrypt-key ~/.ssh/keys/alice
    #[command(alias = "combine")]
    Recover {
        /// SLIP-0039 share mnemonics. Repeat -m for each share.
        /// If omitted, you'll be prompted to enter shares interactively.
        ///
        /// Each value may be:
        ///
        /// - A plain SLIP-0039 mnemonic
        ///
        /// - `@<PATH>` to load a share from a file (age-armoured files
        ///   are auto-detected and decrypted before SLIP-0039 combine;
        ///   plain text files are treated as raw mnemonics)
        #[arg(short, long = "mnemonic")]
        mnemonics: Vec<String>,

        /// SLIP-0039 password (must match the one used during split).
        /// Omit for a hidden interactive prompt.
        #[arg(short, long, env = "PELLITORY_PASSWORD", hide_env_values = true)]
        password: Option<String>,

        /// age decryption passphrase(s) for armoured shares. Repeatable:
        /// each value is added to a credential pool that is tried on every
        /// armoured share until one works. Use multiple times when shares
        /// were encrypted with different passphrases. Non-armoured shares
        /// skip decrypt. Omit entirely for the interactive per-share
        /// prompt loop.
        ///
        /// The env var PELLITORY_DECRYPT_PASSPHRASE supplies one value.
        #[arg(long, env = "PELLITORY_DECRYPT_PASSPHRASE", hide_env_values = true)]
        decrypt_passphrase: Vec<String>,

        /// Reuse the SLIP-0039 password (--password) as the age decryption
        /// passphrase. Parallel to --encrypt-with-slip-password on the
        /// split/generate side — one password for both layers.
        #[arg(long)]
        decrypt_with_slip_password: bool,

        /// age identity file (`AGE-SECRET-KEY-1...`) or SSH private key
        /// file (OpenSSH format) for decrypting armoured shares.
        /// Auto-detected by content. Repeatable: each path is added to the
        /// credential pool tried on every armoured share.
        ///
        /// Aliases: --decrypt-key (same behaviour, shorter name).
        #[arg(long, value_name = "PATH", alias = "decrypt-key")]
        decrypt_identity: Vec<String>,

        /// Coin / output format: bitcoin (BIP-39 mnemonic), monero (full
        /// Monero wallet), or hex (raw hex). Accepts btc / xmr.
        #[arg(short = 'c', long, value_parser = parse_coin)]
        coin: Coin,
    },

    /// Derive keys / a seed phrase from raw material.
    ///
    /// --coin monero: take a hex spend key or 25-word Monero mnemonic
    /// and derive the complete key set (private/public spend & view keys,
    /// and the wallet address).
    ///
    /// --coin bitcoin: take raw hex entropy (16 / 20 / 24 / 28 / 32
    /// bytes) and turn it into a BIP-39 mnemonic phrase.
    ///
    /// Hex input is valid for both coins: --coin disambiguates whether
    /// the hex is entropy (bitcoin) or a spend key (monero).
    ///
    /// EXAMPLES:
    ///
    ///   # Interactive hidden prompt (safest)
    ///
    ///   pellitory-39 derive --coin monero
    ///
    ///   # From a hex spend key
    ///
    ///   pellitory-39 derive --coin monero -s af6082...3206
    ///
    ///   # From a 25-word Monero mnemonic
    ///
    ///   pellitory-39 derive --coin monero -m "word1 word2 ... word25"
    ///
    ///   # Turn raw hex entropy into a BIP-39 seed phrase (Bitcoin)
    ///
    ///   pellitory-39 derive --coin bitcoin -s 0000...0000
    ///
    ///   # Piped from another command (never touches shell history)
    ///
    ///   echo "$SPEND_KEY" | pellitory-39 derive --coin monero -s -
    Derive {
        /// Private spend key (hex), or '-' to read from stdin. With
        /// --coin bitcoin this is instead the raw hex entropy.
        #[arg(short = 's', long = "spend-key", group = "input")]
        spend_key: Option<String>,

        /// 25-word Monero mnemonic, or '-' to read from stdin. Only used
        /// with --coin monero; with --coin bitcoin pass hex entropy via -s.
        #[arg(short, long, group = "input")]
        mnemonic: Option<String>,

        /// Prompt for key without echoing (default when no input given).
        #[arg(short, long, group = "input")]
        interactive: bool,

        /// Coin / output format: bitcoin (BIP-39 mnemonic from hex
        /// entropy) or monero (full key set from a spend key / mnemonic).
        /// Hex is not accepted — --coin disambiguates the hex input.
        /// Accepts the tickers btc / xmr.
        #[arg(short = 'c', long, value_parser = parse_derive_coin)]
        coin: Coin,
    },

    /// Inspect a SLIP-0039 share to see its metadata.
    ///
    /// Shows the share's group/member indices and thresholds without
    /// needing the password or other shares. Useful for checking which
    /// share you're looking at.
    ///
    /// The mnemonic is prompted with hidden input when `-m` is omitted,
    /// so the share never appears on screen, in terminal scrollback, or
    /// in shell history. (A share is secret-equivalent above the
    /// threshold, and for a 1-of-1 split it IS the secret.)
    ///
    /// EXAMPLE:
    ///
    ///   # Interactive (hidden input — recommended):
    ///   pellitory-39 inspect
    ///
    ///   # Or pass the share on the command line:
    ///   pellitory-39 inspect -m "transfer flea ceramic round ajar..."
    Inspect {
        /// SLIP-0039 share mnemonic to inspect. Omit for a hidden
        /// interactive prompt (recommended — a share is
        /// secret-equivalent above the threshold).
        #[arg(short, long)]
        mnemonic: Option<String>,
    },
    /// Print a shell completion script for `pellitory-39`.
    ///
    /// Generate tab-completion for bash, zsh, fish, elvish, or PowerShell
    /// and write it to stdout — redirect it into the right location for
    /// your shell, then start a new shell (or source the file) to enable it.
    ///
    /// EXAMPLES:
    ///
    ///   # Bash (system-wide, needs sudo):
    ///   pellitory-39 completions bash | sudo tee /etc/bash_completion.d/pellitory-39
    ///
    ///   # Bash (user-only, no sudo):
    ///   mkdir -p ~/.local/share/bash-completion/completions
    ///   pellitory-39 completions bash > ~/.local/share/bash-completion/completions/pellitory-39
    ///
    ///   # Zsh (user-only — make sure ~/.zsh is on $fpath):
    ///   mkdir -p ~/.zsh/completions
    ///   pellitory-39 completions zsh > ~/.zsh/completions/_pellitory-39
    ///
    ///   # Fish:
    ///   pellitory-39 completions fish > ~/.config/fish/completions/pellitory-39.fish
    ///
    ///   # PowerShell (append to $PROFILE):
    ///   pellitory-39 completions powershell >> $PROFILE
    ///
    ///   # Elvish:
    ///   pellitory-39 completions elvish > ~/.config/elvish/lib/pellitory-39.elv
    ///
    /// After installing, start a new shell (or `source` the file for
    /// bash/zsh) and tab-completion will work for every subcommand,
    /// option, and `--coin` value.
    Completions {
        /// Shell to generate completions for: bash, zsh, fish, elvish,
        /// or powershell.
        #[arg(value_parser = ["bash", "zsh", "fish", "elvish", "powershell"])]
        shell: String,
    },
}

// ─── Helpers ────────────────────────────────────────────────────────────────

/// Prompt for a password with hidden input, or take it from the CLI/env.
///
/// Emits a stderr warning when the resolved password is empty: an empty
/// password means the shares alone (above the threshold) recover the secret
/// with no second factor. This is valid per SLIP-0039 (and matches Trezor),
/// and the GUI guards it behind a modal; the CLI now warns symmetrically
/// rather than proceeding silently.
fn get_password(password_opt: Option<String>) -> Result<Zeroizing<String>> {
    get_password_labeled(password_opt, "Password: ")
}

/// Like [`get_password`] but with a caller-supplied prompt label, so the
/// decoy path can prompt for a distinct password without reusing the
/// default wording.
fn get_password_labeled(password_opt: Option<String>, label: &str) -> Result<Zeroizing<String>> {
    let secret = match password_opt {
        // Move the clap/env String directly into Zeroizing — no clone, no
        // un-wiped copy. Zeroizing zeroes the heap buffer on drop.
        Some(p) => Zeroizing::new(p),
        None => {
            let input = rpassword::prompt_password(label)?;
            Zeroizing::new(input)
        }
    };
    if secret.is_empty() {
        eprintln!(
            "Warning: empty password. Without a password, anyone with enough\
             \nshares can recover the wallet — there is no second factor.\
             \nThis is valid (and matches Trezor), but make sure it is intended."
        );
    }
    Ok(secret)
}

/// Prompt for a single SLIP-0039 share with hidden input.
///
/// The returned string is wrapped in `Zeroizing` so the share — which is
/// secret-equivalent above the threshold — is wiped from memory on drop.
/// The raw `String` returned by rpassword is zeroised before it goes out
/// of scope.
fn read_share(label: &str) -> Result<Zeroizing<String>> {
    let mut input = rpassword::prompt_password(label)?;
    let trimmed = Zeroizing::new(input.trim().to_string());
    input.zeroize();
    Ok(trimmed)
}

/// Zeroise every `String` in a slice of word lists.
///
/// Share words are secret-equivalent above the threshold. When we split a
/// share mnemonic into `Vec<String>` for the sssmc39 API (which borrows
/// `&[Vec<String>]`), the owned `String` copies live on the heap and are
/// not zeroised by ordinary `Drop`. Wipe them explicitly after the call.
fn zeroise_word_lists(lists: &mut [Vec<String>]) {
    for inner in lists.iter_mut() {
        for w in inner.iter_mut() {
            w.zeroize();
        }
    }
}

/// Zeroise every `String` in a slice of words (single share).
fn zeroise_words(words: &mut [String]) {
    for w in words.iter_mut() {
        w.zeroize();
    }
}

/// Prompt for entropy with hidden input, or take it from the CLI/env.
fn get_entropy(entropy_opt: Option<String>, coin: Coin) -> Result<Zeroizing<String>> {
    match entropy_opt {
        // Move the clap/env String directly into Zeroizing — no clone, no
        // un-wiped copy. Zeroizing zeroes the heap buffer on drop.
        Some(e) => Ok(Zeroizing::new(e)),
        None => {
            // The prompt adapts to --coin so the user is hinted toward the
            // format that matches their workflow. Input is always
            // auto-detected by `detect_and_normalise` regardless of --coin,
            // so any supported format is accepted even if not listed.
            let label = match coin {
                Coin::Monero => {
                    eprintln!("Enter your Monero spend key or mnemonic:");
                    eprintln!("  • A 64-char hex spend key");
                    eprintln!("  • A 25-word Monero mnemonic");
                    eprintln!();
                    "Spend key or mnemonic: "
                }
                Coin::Bitcoin => {
                    eprintln!("Enter your Bitcoin secret. This can be:");
                    eprintln!("  • A hex secret (any even number of hex digits)");
                    eprintln!("  • A 12/15/18/21/24-word BIP-39 mnemonic (Bitcoin/Ethereum)");
                    eprintln!();
                    "Secret: "
                }
                Coin::Hex => {
                    eprintln!("Enter your hex secret (any even number of hex digits):");
                    eprintln!();
                    "Hex secret: "
                }
            };
            let input = rpassword::prompt_password(label)?;
            Ok(Zeroizing::new(input))
        }
    }
}

/// Interactively prompt for SLIP-0039 share mnemonics.
///
/// After the first share is entered, the tool inspects it to determine
/// how many shares are needed and guides the user accordingly.
fn get_shares_interactive() -> Result<Vec<Zeroizing<String>>> {
    eprintln!("Enter your first SLIP-0039 share (input is hidden):");
    eprintln!();

    let first = read_share("Share 1: ")?;
    if first.is_empty() {
        return Err(anyhow!("you must enter at least one share"));
    }

    // Inspect the first share to learn the recovery requirements.
    let mut words: Vec<String> = first.split_whitespace().map(str::to_owned).collect();
    let meta = sharing::inspect(&words)
        .map_err(|e| anyhow!("could not read share: {e}"))?;
    // Wipe the split word copies — they are heap-allocated owned Strings
    // holding the full first share, which is secret-equivalent.
    zeroise_words(&mut words);

    let mut shares = vec![first];

    if meta.group_count == 1 {
        // Single group — we know exactly how many shares are needed.
        let needed = meta.member_threshold as usize;
        if needed == 1 {
            eprintln!("This share is sufficient on its own (1-of-N).");
        } else {
            eprintln!(
                "This share is from a {}-of-N split. Enter {} more share(s):",
                needed, needed - 1,
            );
            eprintln!();
            for i in 2..=needed {
                let label = format!("Share {i}: ");
                let trimmed = read_share(&label)?;
                if trimmed.is_empty() {
                    return Err(anyhow!(
                        "need {} shares to recover but only got {}",
                        needed,
                        i - 1,
                    ));
                }
                shares.push(trimmed);
            }
        }
    } else {
        // Multiple groups — threshold structure is more complex.
        eprintln!(
            "This share is from group {} of {} (requires {} group(s) to recover).",
            meta.group_index, meta.group_count, meta.group_threshold,
        );
        eprintln!(
            "Group {} needs {} share(s). Enter remaining shares from enough groups.",
            meta.group_index, meta.member_threshold,
        );
        eprintln!("Press Enter on a blank line when done.");
        eprintln!();

        loop {
            let n = shares.len() + 1;
            let label = format!("Share {n}: ");
            let trimmed = read_share(&label)?;
            if trimmed.is_empty() {
                break;
            }
            shares.push(trimmed);
        }
    }

    Ok(shares)
}

/// Prompt for a Monero spend key or mnemonic with hidden input.
fn get_derive_input(
    spend_key: Option<String>,
    mnemonic: Option<String>,
    interactive: bool,
) -> Result<Zeroizing<String>> {
    get_derive_input_with_label(spend_key, mnemonic, interactive, "Spend key or Monero mnemonic: ")
}

/// Like [`get_derive_input`] but with a caller-supplied prompt label, so
/// the `derive --coin bitcoin` path can prompt for hex entropy without
/// reusing the Monero wording.
fn get_derive_input_with_label(
    mut spend_key: Option<String>,
    mut mnemonic: Option<String>,
    interactive: bool,
    label: &str,
) -> Result<Zeroizing<String>> {
    // Take ownership of the clap-provided secret so we can zeroise the
    // application-level copy after copying it into `Zeroizing`. Every
    // other CLI secret path (`get_password`, `get_entropy`, `cmd_recover`,
    // `cmd_decoy`, `cmd_inspect`) does the same; without this the original
    // `String` would be dropped un-wiped by ordinary `String::Drop` (which
    // frees the heap buffer without overwriting it), leaving one un-wiped
    // copy of the spend key / mnemonic in freed heap memory.
    let mut raw_owned = mnemonic.take().or(spend_key.take());
    let raw = raw_owned.as_deref();

    if interactive || raw.is_none() {
        // `spend_key` / `mnemonic` were already moved into `raw_owned` by
        // the `take()` above, so they are `None` here; zeroising them is a
        // defensive no-op. `raw_owned` may still hold the secret if this
        // branch was reached via `-i` together with `-s`/`-m` (today clap's
        // `ArgGroup("input")` makes that unreachable, but zeroise it anyway
        // so the invariant survives a future change — I-4).
        spend_key.zeroize();
        mnemonic.zeroize();
        raw_owned.zeroize();
        let input = rpassword::prompt_password(label)?;
        return Ok(Zeroizing::new(input));
    }

    // "-" sentinel — read from stdin (pipe or redirect). Cap the read so a
    // huge pipe cannot exhaust memory (L-2). A spend key / mnemonic is at
    // most a few hundred bytes; MAX_STDIN_BYTES gives generous headroom.
    if raw == Some("-") {
        // `raw_owned` holds "-" here; zeroise it before the stdin read.
        if let Some(mut s) = raw_owned { s.zeroize(); }
        let buf = read_bounded_stdin()?;
        return Ok(Zeroizing::new(buf.trim().to_string()));
    }

    // Copy the secret into `Zeroizing`, then zeroise the original owned
    // `String` so the application-level copy does not linger un-wiped in
    // freed heap memory (it is secret-equivalent to the spend key).
    let mut s = raw_owned.unwrap();
    let out = Zeroizing::new(s.trim().to_string());
    s.zeroize();
    Ok(out)
}

/// Read up to [`MAX_STDIN_BYTES`] + 1 bytes from stdin into a `Zeroizing`
/// buffer. If the input exceeds the cap, an error is returned so the caller
/// cannot be forced to allocate unbounded memory from a hostile pipe. The
/// extra +1 byte lets us distinguish "exactly at cap" from "over cap".
fn read_bounded_stdin() -> Result<Zeroizing<String>> {
    let mut buf = Zeroizing::new(String::with_capacity(MAX_STDIN_BYTES));
    let stdin = io::stdin();
    let mut handle = stdin.lock();
    // Wrap the read chunk in `Zeroizing` so the last stdin bytes read
    // (which may include secret material) are wiped from the stack on
    // every exit path — success *and* error — rather than lingering until
    // the frame is reused (I-6). `Zeroizing`'s `Drop` performs a volatile
    // write, which is harder for the compiler to elide than a plain
    // stack-array overwrite.
    let mut chunk = Zeroizing::new([0u8; 1024]);
    loop {
        let n = handle.read(&mut *chunk)?;
        if n == 0 {
            break;
        }
        if buf.len() + n > MAX_STDIN_BYTES {
            return Err(anyhow!(
                "stdin input exceeds the {} byte limit; expected a spend key or mnemonic",
                MAX_STDIN_BYTES
            ));
        }
        // SAFETY: stdin bytes are treated as opaque text and only decoded by
        // downstream parsers; we push them as raw bytes via a string view.
        buf.push_str(std::str::from_utf8(&chunk[..n])
            .map_err(|e| anyhow!("stdin is not valid UTF-8: {e}"))?);
    }
    Ok(buf)
}

/// Parse group specifications and return the parsed tuples.
fn parse_groups(group_specs: &[String]) -> Result<Vec<(u8, u8)>> {
    group_specs
        .iter()
        .map(|s| sharing::parse_group_spec(s))
        .collect()
}

/// Parse group specifications and return the parsed tuples, validating
/// the required-groups count against the number of groups.
///
/// This is called before any secret material is generated or printed so
/// that an invalid group configuration fails fast — for `generate --coin monero`,
/// printing a freshly generated wallet's keys and *then* failing the split
/// would leak keys the user was told they'd never see again, while leaving
/// them with no shares to recover from.
fn parse_groups_and_required(
    group_specs: &[String],
    required_groups: Option<u8>,
) -> Result<(Vec<(u8, u8)>, u8)> {
    let groups = parse_groups(group_specs)?;
    let required = required_groups.unwrap_or(groups.len() as u8);
    if required == 0 {
        return Err(anyhow!(
            "--required-groups must be at least 1 (got 0)"
        ));
    }
    if required as usize > groups.len() {
        return Err(anyhow!(
            "--required-groups ({}) cannot exceed the number of groups ({})",
            required,
            groups.len(),
        ));
    }
    Ok((groups, required))
}

/// Maximum valid SLIP-0039 iteration exponent.
///
/// SLIP-0039 encodes the exponent in a 5-bit field, but the highest bit is
/// the extendable-backup flag (`ext`). The exponent itself is therefore 4
/// bits, giving a valid range of 0–15 regardless of the `ext` value. The
/// `--extendable` flag controls `ext` separately; values ≥16 on the
/// `--iterations` flag would silently set the `ext` bit rather than raising
/// the exponent, which is never what the user asked for.
const MAX_ITERATIONS: u8 = 15;

/// Maximum valid SLIP-0039 identifier (15 bits).
const MAX_IDENTIFIER: u32 = 32767;

/// Maximum accepted `--bits` value for random-entropy generation.
///
/// `MasterSecret::generate` only enforces `>= 128` and a multiple of 16,
/// so without an upper cap a `u16` `--bits` value of up to ~65 520 would
/// build an unwieldy multi-thousand-word mnemonic (and a large heap
/// allocation). 512 bits is already far beyond any realistic wallet need;
/// cap there to prevent an accidental footgun. SLIP-0039 itself supports
/// master secrets up to 1024 bits, so this is a UX guardrail, not a
/// protocol limit.
const MAX_BITS: u16 = 512;

/// Render a [`Coin`] as the `--coin` value a user would pass on the
/// command line, for "to recover, run ..." hints.
fn coin_arg_hint(coin: Coin) -> &'static str {
    match coin {
        Coin::Bitcoin => "bitcoin",
        Coin::Monero => "monero",
        Coin::Hex => "hex",
    }
}

/// Validate the KDF iteration exponent is within the supported range.
fn validate_iterations(iterations: u8) -> Result<()> {
    if iterations > MAX_ITERATIONS {
        return Err(anyhow!(
            "--iterations must be between 0 and {} (got {}); the 5-bit SLIP-0039 \
             field reserves the top bit for the extendable-backup flag (use \
             --extendable to set it)",
            MAX_ITERATIONS,
            iterations,
        ));
    }
    Ok(())
}

/// Validate the SLIP-0039 identifier fits in 15 bits.
///
/// The identifier is encoded in the first mnemonic word (along with the
/// iteration exponent) and is also used as the PBKDF2 salt. Forcing it to
/// a specific value lets a Decoy Wallet share the same metadata prefix as
/// a Real Wallet — see `--identifier`.
fn validate_identifier(identifier: u16) -> Result<()> {
    if identifier as u32 > MAX_IDENTIFIER {
        // Defensive: u16 can't exceed 32767, but keep the check explicit so
        // the constraint is documented in code and survives a future type
        // widening.
        return Err(anyhow!(
            "--identifier must fit in 15 bits (0..={}, got {})",
            MAX_IDENTIFIER,
            identifier,
        ));
    }
    Ok(())
}

/// Validate the `--bits` value is within the accepted range.
///
/// `MasterSecret::generate` enforces `>= 128` and a multiple of 16; this
/// adds an upper cap ([`MAX_BITS`]) so a typoed large value does not build
/// an unwieldy mnemonic and a large heap allocation.
fn validate_bits(bits: u16) -> Result<()> {
    if bits > MAX_BITS {
        return Err(anyhow!(
            "--bits must be at most {} (got {}); use a smaller value. \
             256 bits is the standard for wallet seeds",
            MAX_BITS,
            bits,
        ));
    }
    Ok(())
}

/// Validate the `--bits` value for `--coin bitcoin` (BIP-39 entropy).
///
/// BIP-39 only supports 128 / 160 / 192 / 224 / 256 bits (yielding 12 /
/// 15 / 18 / 21 / 24-word mnemonics). `generate --coin bitcoin` must
/// produce a recoverable BIP-39 phrase, so the bit length is restricted
/// to these values (the generic `--coin hex` path allows any multiple of
/// 16 up to [`MAX_BITS`]).
fn validate_bip39_bits(bits: u16) -> Result<()> {
    if !matches!(bits, 128 | 160 | 192 | 224 | 256) {
        return Err(anyhow!(
            "--bits for --coin bitcoin must be one of 128/160/192/224/256 \
             (got {}); these are the BIP-39 entropy sizes that produce \
             12/15/18/21/24-word seed phrases. Use --coin hex for arbitrary \
             bit lengths.",
            bits,
        ));
    }
    Ok(())
}

// ─── Encrypted export helpers (phase 003) ───────────────────────────────────

/// The outcome of resolving encryption configuration.
///
/// [`EncryptArgs::resolve`] validates all config (fail-fast, before any
/// secret is generated) and returns one of:
/// - [`EncryptPlan::None`] — no encryption requested (no `--out`).
/// - [`EncryptPlan::Targets`] — fully-resolved targets ready for export.
/// - [`EncryptPlan::SlipPasswordBulk`] — bulk passphrase, but the value
///   comes from the SLIP-0039 password (prompted after `resolve`, so the
///   fail-fast invariant is preserved). The caller builds
///   `vec![Passphrase(slip_password)]` after prompting.
enum EncryptPlan {
    None,
    Targets(Vec<pellitory_39::encrypt::EncryptTarget>),
    SlipPasswordBulk,
}

/// CLI arguments for the encrypted-share-export feature, collected into a
/// struct so `cmd_gen`/`cmd_split`/`cmd_decoy` signatures stay manageable.
/// One instance covers the Real wallet; a second (optional) covers the
/// Decoy wallet in `generate --decoy`.
#[derive(Clone, Default)]
struct EncryptArgs {
    /// Output path. `None` = no file export. `Some("-")` = stdout (binary).
    out: Option<String>,
    /// Package format: "zip" or "one-file".
    package: String,
    /// Bulk passphrase (from `--encrypt-passphrase` or env). `None` = not set.
    /// SECRET — zeroised on drop via the `Drop` impl below.
    encrypt_passphrase: Option<String>,
    /// Per-share recipients (`--encrypt-to`).
    encrypt_to: Vec<String>,
    /// Per-share recipient files (`--encrypt-to-file`). Each file holds one
    /// recipient string (`age1...` or `ssh-...`), read and zeroised after
    /// parsing.
    encrypt_to_file: Vec<String>,
    /// Per-share passphrase files (`--encrypt-passphrase-file`).
    encrypt_passphrase_file: Vec<String>,
    /// `--confirm-recipient` flag.
    confirm_recipient: bool,
    /// `--encrypt-with-slip-password` flag: reuse the SLIP-0039 password as
    /// the age passphrase (bulk). Avoids entering two passwords.
    encrypt_with_slip_password: bool,
}

impl EncryptArgs {
    /// Returns true if any `--encrypt-*` flag is set (encryption requested).
    fn wants_encryption(&self) -> bool {
        self.encrypt_passphrase.is_some()
            || !self.encrypt_to.is_empty()
            || !self.encrypt_to_file.is_empty()
            || !self.encrypt_passphrase_file.is_empty()
            || self.encrypt_with_slip_password
    }
}

/// Zeroise the bulk passphrase on drop so it never lingers un-wiped in
/// freed heap memory — even if `resolve()` returns early (e.g. a config
/// error) before `take()` consumes it. The other fields hold file paths
/// and public keys, not secrets, so they are dropped normally.
impl Drop for EncryptArgs {
    fn drop(&mut self) {
        self.encrypt_passphrase.zeroize();
    }
}

impl EncryptArgs {
    /// Resolve the encryption targets and validate the configuration.
    ///
    /// Returns [`EncryptPlan::None`] when no encryption is requested.
    /// All validation runs before any secret is generated (fail-fast).
    ///
    /// `share_count` is the total number of shares (sum of group totals),
    /// computed from the group specs by the caller. `label` is "Real",
    /// "Decoy", or "Split" for error messages.
    ///
    /// If `--out` is set without any `--encrypt-*` flags and stdin is a TTY,
    /// an interactive prompt walks the user through choosing a method.
    fn resolve(&mut self, share_count: usize, label: &str) -> Result<EncryptPlan> {
        use pellitory_39::encrypt::{parse_recipient, EncryptTarget};

        if !self.wants_encryption() {
            // No explicit --encrypt-* flags.
            if self.out.is_some() {
                // --out set without --encrypt-*: interactive prompt (if TTY)
                // or error (if non-interactive).
                return interactive_encrypt(share_count, label);
            }
            return Ok(EncryptPlan::None);
        }

        // --encrypt-* requires --out.
        if self.out.is_none() {
            return Err(anyhow!(
                "{label}: encryption requires --out (use a file path or '-' for stdout)"
            ));
        }

        // --encrypt-passphrase and --encrypt-with-slip-password are bulk-only;
        // cannot mix with per-share flags.
        let has_pass = self.encrypt_passphrase.is_some();
        let has_slip = self.encrypt_with_slip_password;
        let has_recipients = !self.encrypt_to.is_empty() || !self.encrypt_to_file.is_empty();
        let has_pass_files = !self.encrypt_passphrase_file.is_empty();
        if (has_pass || has_slip) && (has_recipients || has_pass_files) {
            return Err(anyhow!(
                "{label}: --encrypt-passphrase / --encrypt-with-slip-password (bulk) cannot \
                 be combined with --encrypt-to / --encrypt-to-file / --encrypt-passphrase-file. \
                 Use one bulk credential alone, or per-share credentials."
            ));
        }
        if has_pass && has_slip {
            return Err(anyhow!(
                "{label}: --encrypt-passphrase and --encrypt-with-slip-password conflict; \
                 choose one"
            ));
        }

        // --encrypt-with-slip-password: bulk passphrase from the SLIP password.
        // The value is not available yet (prompted after resolve), so return
        // the plan and let the caller fill it in.
        if has_slip {
            // Validate package now (fail-fast); count is 1 (bulk) so one-file is OK.
            let _ = self.parse_package()?;
            return Ok(EncryptPlan::SlipPasswordBulk);
        }

        // --encrypt-to / --encrypt-to-file requires --confirm-recipient
        // (or interactive confirmation if stdin is a TTY).
        if has_recipients && !self.confirm_recipient {
            interactive_confirm_recipient(&self.encrypt_to, &self.encrypt_to_file, label)?;
        }

        // Build the target list.
        let targets: Vec<EncryptTarget> = if has_pass {
            // Bulk passphrase: one target. `take()` moves the String out of
            // `self` directly into `Zeroizing` — no clone, no un-wiped copy.
            // Any remaining value is caught by the `Drop` impl.
            let pass = self.encrypt_passphrase.take().unwrap();
            vec![EncryptTarget::Passphrase(Zeroizing::new(pass))]
        } else {
            let mut t = Vec::new();
            // Order: --encrypt-to values first, then --encrypt-to-file,
            // then --encrypt-passphrase-file.
            for r in &self.encrypt_to {
                t.push(parse_recipient(r)?);
            }
            for f in &self.encrypt_to_file {
                let recipient = read_recipient_file(f)?;
                t.push(parse_recipient(&recipient)?);
            }
            for f in &self.encrypt_passphrase_file {
                let mut content = std::fs::read_to_string(f)
                    .map_err(|e| anyhow!("cannot read passphrase file '{f}': {e}"))?;
                let pass = Zeroizing::new(content.trim().to_string());
                content.zeroize();
                t.push(EncryptTarget::Passphrase(pass));
            }
            t
        };

        // --package one-file requires exactly 1 method.
        let pkg = self.parse_package()?;
        if matches!(pkg, pellitory_39::export::BulkPackage::OneFile) && targets.len() != 1 {
            return Err(anyhow!(
                "{label}: --package one-file takes exactly one encryption credential \
                 (got {}); per-share credentials require --package zip",
                targets.len()
            ));
        }

        // Validate method count: 1 (bulk) or == share_count (per-share).
        if targets.len() != 1 && targets.len() != share_count {
            return Err(anyhow!(
                "{label}: encryption method count ({}) must be 1 (bulk, applied to \
                 all shares) or equal to the total share count ({}). Use exactly \
                 one --encrypt-* for bulk, or one per share for per-share.",
                targets.len(), share_count
            ));
        }

        Ok(EncryptPlan::Targets(targets))
    }

    /// Parse the package format string.
    fn parse_package(&self) -> Result<pellitory_39::export::BulkPackage> {
        match self.package.as_str() {
            "zip" => Ok(pellitory_39::export::BulkPackage::Zip),
            "one-file" => Ok(pellitory_39::export::BulkPackage::OneFile),
            other => Err(anyhow!(
                "invalid --package '{other}' — expected 'zip' or 'one-file'"
            )),
        }
    }
}

/// Read a recipient string from a file (first non-empty line, trimmed).
/// The file contents are zeroised after extracting the recipient.
fn read_recipient_file(path: &str) -> Result<String> {
    let mut content = std::fs::read_to_string(path)
        .map_err(|e| anyhow!("cannot read recipient file '{path}': {e}"))?;
    let recipient = content
        .lines()
        .find(|l| !l.trim().is_empty())
        .unwrap_or("")
        .trim()
        .to_string();
    content.zeroize();
    Ok(recipient)
}

/// Interactive encryption method chooser, invoked when `--out` is set
/// without any `--encrypt-*` flags and stdin is a TTY.
///
/// Walks the user through choosing bulk passphrase, age recipient, SSH
/// recipient, per-share mixed, or reusing the SLIP-0039 password. Returns
/// the resolved plan (or `SlipPasswordBulk` if the user chooses to reuse
/// the SLIP password, which is prompted later by the caller).
fn interactive_encrypt(share_count: usize, label: &str) -> Result<EncryptPlan> {
    use std::io::{IsTerminal, Write};
    use pellitory_39::encrypt::{parse_recipient, EncryptTarget};

    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "{label}: --out requires --encrypt-* flags (or set PELLITORY_ENCRYPT_PASSPHRASE). \
             In non-interactive mode you must specify the encryption method explicitly. \
             All file exports are age-armoured; there is no plaintext-to-disk path."
        ));
    }

    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "\n{label}: --out is set but no --encrypt-* flags were given.");
    let _ = writeln!(stderr, "Every share file is age-encrypted. Choose a method:");
    let _ = writeln!(stderr, "  (1) Passphrase (reuses the SLIP-0039 password — one password for both)");
    let _ = writeln!(stderr, "  (2) Separate passphrase (bulk — all shares, same passphrase)");
    let _ = writeln!(stderr, "  (3) age recipient (bulk — all shares, same age1... key)");
    let _ = writeln!(stderr, "  (4) SSH recipient (bulk — all shares, same SSH key)");
    let _ = writeln!(stderr, "  (5) Per-share mixed (one method per share)");
    let _ = writeln!(stderr, "  (6) Cancel");
    let _ = write!(stderr, "Choice [1-6]: ");
    let _ = stderr.flush();

    let mut choice = String::new();
    std::io::stdin()
        .read_line(&mut choice)
        .map_err(|e| anyhow!("could not read choice: {e}"))?;
    let choice = choice.trim();

    match choice {
        "1" => Ok(EncryptPlan::SlipPasswordBulk),
        "2" => {
            let _ = write!(stderr, "Passphrase (bulk, all shares): ");
            let _ = stderr.flush();
            let pass = rpassword::prompt_password("")?;
            let target = EncryptTarget::Passphrase(Zeroizing::new(pass));
            Ok(EncryptPlan::Targets(vec![target]))
        }
        "3" | "4" => {
            let kind = if choice == "3" { "age1..." } else { "ssh-ed25519 ... / ssh-rsa ..." };
            let _ = writeln!(stderr, "Recipient ({kind}, bulk):");
            let _ = stderr.flush();
            let mut recipient = String::new();
            std::io::stdin()
                .read_line(&mut recipient)
                .map_err(|e| anyhow!("could not read recipient: {e}"))?;
            let recipient = recipient.trim().to_string();
            let target = parse_recipient(&recipient)?;
            Ok(EncryptPlan::Targets(vec![target]))
        }
        "5" => {
            let _ = writeln!(stderr, "Per-share mixed: enter one method for each of {share_count} shares.");
            let mut targets = Vec::with_capacity(share_count);
            for i in 1..=share_count {
                let _ = writeln!(stderr, "\nShare {i}/{share_count}:");
                let _ = writeln!(stderr, "  (1) Passphrase (reuses SLIP-0039 password)");
                let _ = writeln!(stderr, "  (2) Separate passphrase");
                let _ = writeln!(stderr, "  (3) age recipient");
                let _ = writeln!(stderr, "  (4) SSH recipient");
                let _ = write!(stderr, "Choice [1-4]: ");
                let _ = stderr.flush();
                let mut c = String::new();
                std::io::stdin()
                    .read_line(&mut c)
                    .map_err(|e| anyhow!("could not read choice: {e}"))?;
                match c.trim() {
                    "1" => {
                        // Per-share reuse of SLIP password is only valid if
                        // this is the only share (share_count == 1), since
                        // SlipPasswordBulk is a single bulk target.
                        if share_count != 1 {
                            return Err(anyhow!(
                                "{label}: reusing the SLIP-0039 password is bulk-only \
                                 (one passphrase for all shares); for per-share reuse, \
                                 pass --encrypt-with-slip-password"
                            ));
                        }
                        return Ok(EncryptPlan::SlipPasswordBulk);
                    }
                    "2" => {
                        let _ = write!(stderr, "Passphrase for share {i}: ");
                        let _ = stderr.flush();
                        let pass = rpassword::prompt_password("")?;
                        targets.push(EncryptTarget::Passphrase(Zeroizing::new(pass)));
                    }
                    "3" | "4" => {
                        let kind = if c.trim() == "3" { "age1..." } else { "ssh-..." };
                        let _ = writeln!(stderr, "Recipient for share {i} ({kind}):");
                        let _ = stderr.flush();
                        let mut recipient = String::new();
                        std::io::stdin()
                            .read_line(&mut recipient)
                            .map_err(|e| anyhow!("could not read recipient: {e}"))?;
                        let recipient = recipient.trim().to_string();
                        targets.push(parse_recipient(&recipient)?);
                    }
                    other => {
                        return Err(anyhow!("{label}: unknown choice `{other}` for share {i}"));
                    }
                }
            }
            Ok(EncryptPlan::Targets(targets))
        }
        "6" => Err(anyhow!("{label}: encryption cancelled by user")),
        other => Err(anyhow!("{label}: unknown choice `{other}`; use 1-6")),
    }
}

/// Confirm recipient possession interactively (when `--encrypt-to` /
/// `--encrypt-to-file` is used without `--confirm-recipient` and stdin
/// is a TTY). Prints fingerprints and asks "Continue? [y/N]".
///
/// In non-interactive mode (no TTY), returns an error requiring
/// `--confirm-recipient`.
fn interactive_confirm_recipient(
    encrypt_to: &[String],
    encrypt_to_file: &[String],
    label: &str,
) -> Result<()> {
    use std::io::{IsTerminal, Write};
    use pellitory_39::encrypt::{parse_recipient, recipient_fingerprint};

    let mut all_recipients: Vec<String> = encrypt_to.to_vec();
    for f in encrypt_to_file {
        all_recipients.push(read_recipient_file(f)?);
    }

    let fingerprints: Vec<String> = all_recipients
        .iter()
        .filter_map(|s| parse_recipient(s).ok())
        .filter_map(|t| recipient_fingerprint(&t))
        .collect();

    if !std::io::stdin().is_terminal() {
        return Err(anyhow!(
            "{label}: --encrypt-to / --encrypt-to-file requires --confirm-recipient to \
             acknowledge that you possess the matching private key (non-interactive \
             mode). Recipients:\n{}",
            fingerprints.iter().map(|f| format!("  {f}")).collect::<Vec<_>>().join("\n")
        ));
    }

    let mut stderr = std::io::stderr();
    let _ = writeln!(stderr, "\n{label}: encrypting to the following recipients:");
    for f in &fingerprints {
        let _ = writeln!(stderr, "  {f}");
    }
    let _ = write!(stderr, "Do you possess the matching private key(s)? Continue? [y/N]: ");
    let _ = stderr.flush();

    let mut answer = String::new();
    std::io::stdin()
        .read_line(&mut answer)
        .map_err(|e| anyhow!("could not read confirmation: {e}"))?;

    if answer.trim().eq_ignore_ascii_case("y") {
        Ok(())
    } else {
        Err(anyhow!("{label}: recipient confirmation declined; aborting"))
    }
}

/// Derive a default decoy output path from the Real output path by
/// inserting `-decoy` before the extension.
///
/// `shares.zip` -> `shares-decoy.zip`, `out.age` -> `out-decoy.age`.
fn default_decoy_out(real_out: &str) -> String {
    match real_out.rfind('.') {
        Some(pos) if pos > 0 => format!("{}-decoy{}", &real_out[..pos], &real_out[pos..]),
        _ => format!("{real_out}-decoy"),
    }
}

/// Resolve an [`EncryptPlan`] into concrete targets, using the SLIP-0039
/// password when the plan is [`EncryptPlan::SlipPasswordBulk`].
///
/// Returns `None` when the plan is [`EncryptPlan::None`]. Panics if the
/// plan is `SlipPasswordBulk` but no password is available (the caller is
/// expected to have prompted for it before calling).
fn plan_to_targets(
    plan: EncryptPlan,
    slip_password: Option<&str>,
) -> Option<Vec<pellitory_39::encrypt::EncryptTarget>> {
    use pellitory_39::encrypt::EncryptTarget;
    match plan {
        EncryptPlan::None => None,
        EncryptPlan::Targets(ts) => Some(ts),
        EncryptPlan::SlipPasswordBulk => {
            let pass = slip_password
                .expect("--encrypt-with-slip-password requires the SLIP-0039 password");
            Some(vec![EncryptTarget::Passphrase(Zeroizing::new(pass.to_string()))])
        }
    }
}

/// Compute the total number of shares across all groups.
/// Used for encryption method-count validation before any secret is generated.
fn total_share_count(groups: &[(u8, u8)]) -> usize {
    groups.iter().map(|(_, total)| *total as usize).sum()
}

/// Write an encrypted export to disk (or stdout). Suppresses JSON-to-stdout.
///
/// For bulk mode (1 target, N shares, ZIP), the single target is replicated
/// to N copies before calling `build_export`. For OneFile, the single target
/// is passed as-is.
fn write_export(
    out_path: &str,
    shares: &[Zeroizing<String>],
    targets: &[pellitory_39::encrypt::EncryptTarget],
    package: pellitory_39::export::BulkPackage,
    threshold: u8,
) -> Result<()> {
    use std::io::Write;

    let share_count = shares.len();
    let methods: Vec<_> = match package {
        pellitory_39::export::BulkPackage::OneFile => targets.to_vec(),
        pellitory_39::export::BulkPackage::Zip => {
            if targets.len() == 1 && share_count > 1 {
                // Bulk: replicate the single method for all shares.
                vec![targets[0].clone(); share_count]
            } else {
                targets.to_vec()
            }
        }
    };

    let bytes = pellitory_39::export::build_export(shares, &methods, package, threshold)?;

    if out_path == "-" {
        // Binary-safe stdout: write raw bytes, no text transform.
        io::stdout().write_all(&bytes)?;
    } else {
        std::fs::write(out_path, &bytes)
            .map_err(|e| anyhow!("cannot write export to '{out_path}': {e}"))?;
    }
    Ok(())
}

/// The duress notice. Printed to stderr on every
/// `generate --decoy` run that uses encryption.
const DURESS_NOTICE: &str =
    "Duress notice: age armour stanza headers reveal the recipient type\n\
     (scrypt / X25519 / ssh-ed25519 / ssh-rsa). For Real and Decoy shares\n\
     to be indistinguishable, use matching encryption methods in matching\n\
     share positions for both wallets. Different methods produce\n\
     distinguishable armour and break plausible deniability.";

/// Print derived Monero keys in a formatted block to **stderr**.
///
/// The key block is human-readable and belongs on stderr so that stdout
/// carries only the machine-readable JSON share output, letting users pipe
/// `pellitory-39 generate --coin monero` directly into a JSON parser
/// (SECURITY_REVIEW.md LOW-5).
fn print_monero_keys(keys: &monero::DerivedKeys) {
    eprintln!();
    eprintln!("  Mnemonic         : {}", *keys.mnemonic);
    eprintln!();
    eprintln!("  Hexadecimal seed : {}", *keys.hex_seed);
    eprintln!();
    eprintln!(
        "  Private spend key: {}",
        keys.private_spend_key.expose_secret()
    );
    eprintln!("  Public spend key : {}", keys.public_spend_key);
    eprintln!();
    eprintln!(
        "  Private view key : {}",
        keys.private_view_key.expose_secret()
    );
    eprintln!("  Public view key  : {}", keys.public_view_key);
    eprintln!();
    eprintln!("  Monero address   : {}", keys.address);
}

/// Generate 32 bytes of cryptographically secure random entropy using
/// OsRng (operating system CSPRNG). The buffer is wrapped in Zeroizing
/// so it is wiped from memory on drop.
fn generate_random_seed() -> Zeroizing<[u8; 32]> {
    let mut seed = Zeroizing::new([0u8; 32]);
    OsRng.fill_bytes(&mut *seed);
    seed
}

/// Generate a fresh secret for the given coin, returning the master
/// secret and (for Monero) the derived key set for display.
///
/// Used by both the Real and Decoy paths of `generate --decoy` so they
/// produce independent secrets of the same coin family.
fn generate_fresh_secret(
    coin: Coin,
    bits: u16,
) -> Result<(sharing::MasterSecret, Option<monero::DerivedKeys>)> {
    match coin {
        Coin::Monero => {
            let seed = generate_random_seed();
            let hex_secret = Zeroizing::new(hex::encode(*seed));
            let keys = monero::derive_keys(&hex_secret)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            let master = sharing::MasterSecret::from_hex(&hex_secret)?;
            Ok((master, Some(keys)))
        }
        Coin::Bitcoin | Coin::Hex => {
            let master = sharing::MasterSecret::generate(bits)?;
            Ok((master, None))
        }
    }
}

// ─── Commands ───────────────────────────────────────────────────────────────

#[allow(clippy::too_many_arguments)]
fn cmd_gen(
    coin: Coin,
    bits: u16,
    password_opt: Option<String>,
    no_password: bool,
    group_specs: Vec<String>,
    required_groups: Option<u8>,
    iterations: u8,
    identifier: Option<u16>,
    extendable: bool,
    decoy: bool,
    decoy_password_opt: Option<String>,
    no_decoy_password: bool,
    real_encrypt: EncryptArgs,
    decoy_encrypt: EncryptArgs,
) -> Result<()> {
    // Validate all configuration BEFORE prompting for the password or
    // generating any secret, so the user never types a password only to hit
    // a config error, and `generate --coin monero` never shows a wallet it
    // then fails to back up. Mirrors `cmd_split`'s fail-fast ordering.
    validate_iterations(iterations)?;
    if let Some(id) = identifier {
        validate_identifier(id)?;
    }
    match coin {
        Coin::Monero => {} // bits ignored — Monero spend keys are always 256 bits
        Coin::Bitcoin => validate_bip39_bits(bits)?,
        Coin::Hex => validate_bits(bits)?,
    }
    let (groups, required) = parse_groups_and_required(&group_specs, required_groups)?;

    // Validate the encrypt config BEFORE prompting for the password or
    // generating any secret (fail-fast: no key material leaked before a
    // config error, matching the existing L-1 invariant).
    let share_count = total_share_count(&groups);

    // Default --decoy-out to <real_out>-decoy.<ext> when --decoy is set
    // and --out is set but --decoy-out is not. This is a convenience so
    // the user doesn't have to spell out both paths.
    let mut real_encrypt = real_encrypt;
    let mut decoy_encrypt = decoy_encrypt;
    if decoy && decoy_encrypt.out.is_none() {
        if let Some(real_out) = &real_encrypt.out {
            let defaulted = default_decoy_out(real_out);
            decoy_encrypt.out = Some(defaulted.clone());
            eprintln!("Decoy output defaulting to: {defaulted}");
        }
    }
    // Decoy package defaults to the Real package if --decoy-package not set.
    if decoy && decoy_encrypt.package.is_empty() {
        decoy_encrypt.package = real_encrypt.package.clone();
    }

    let real_plan = real_encrypt.resolve(share_count, "Real")?;
    let decoy_plan = if decoy {
        decoy_encrypt.resolve(share_count, "Decoy")?
    } else {
        EncryptPlan::None
    };

    let password = if no_password {
        // --no-password: empty password, no prompt, but still warn.
        get_password(Some(String::new()))?
    } else {
        get_password(password_opt)?
    };
    // Resolve the decoy password up front (only when --decoy is set) so a
    // prompt failure happens before any Real secret is generated.
    let decoy_password = if decoy {
        if no_decoy_password {
            Some(get_password_labeled(Some(String::new()), "Decoy password: ")?)
        } else {
            Some(get_password_labeled(decoy_password_opt, "Decoy password: ")?)
        }
    } else {
        None
    };

    // Resolve the encrypt plans to concrete targets now that passwords are
    // available (needed for --encrypt-with-slip-password).
    let real_targets = plan_to_targets(real_plan, Some(password.as_str()));
    let decoy_targets = plan_to_targets(decoy_plan, decoy_password.as_deref().map(String::as_str));

    // ── Real wallet ──
    let (real_master, real_keys) = generate_fresh_secret(coin, bits)?;

    // Split FIRST, before printing any keys: a split failure must never
    // leave the user holding keys they were told they'd never see again,
    // with no shares to recover from (L-1). After validated config + a
    // valid master secret the split is essentially infallible (pure
    // GF(2⁸) arithmetic, no I/O), but we honour the invariant regardless.
    let real_output = sharing::Slip39Output::split_with_identifier(
        required, &groups, &real_master, &password, iterations, extendable, identifier,
    )?;
    // Capture the Real wallet's identifier so the Decoy can reuse it, making
    // the first two mnemonic words match across both wallets.
    let real_identifier = real_output.identifier();

    match coin {
        Coin::Monero => {
            let keys = real_keys.as_ref().expect("Monero fresh secret has keys");
            eprintln!();
            eprintln!("Generated fresh Monero wallet (32 bytes from OsRng):");
            print_monero_keys(keys);
        }
        Coin::Bitcoin => {
            eprintln!();
            eprintln!("Generated {} bits of fresh Bitcoin seed entropy (from OsRng).", bits);
        }
        Coin::Hex => {
            eprintln!();
            eprintln!("Generated {} bits of random entropy (from OsRng).", bits);
        }
    }
    eprintln!();
    eprintln!("IMPORTANT: The keys above will NOT be shown again.");
    eprintln!("Your only way to recover this wallet is from the shares below.");
    eprintln!("To recover, run: pellitory-39 recover --coin {}", coin_arg_hint(coin));

    if let Some(targets) = &real_targets {
        // Export to file (suppress JSON to stdout).
        let pkg = real_encrypt.parse_package()?;
        let mnemonics = real_output.all_mnemonics();
        // For the README threshold: use the first group's member threshold
        // for single-group wallets (the common case), else the group threshold.
        let readme_threshold = if groups.len() == 1 { groups[0].0 } else { required };
        write_export(real_encrypt.out.as_deref().unwrap(), &mnemonics, targets, pkg, readme_threshold)?;
        eprintln!();
        eprintln!("Real shares exported (age-armoured, {} entries).", mnemonics.len());
    } else {
        eprintln!();
        let json = real_output.to_json()?; println!("{}", json.as_str()); drop(json);
    }

    // ── Decoy wallet (optional, --decoy) ──
    if decoy {
        let dpass = decoy_password.expect("resolved above when --decoy is set");
        let (decoy_master, decoy_keys) = generate_fresh_secret(coin, bits)?;

        eprintln!();
        eprintln!("── Decoy wallet ──");
        if coin == Coin::Monero {
            let keys = decoy_keys.as_ref().expect("Monero decoy has keys");
            eprintln!();
            eprintln!("Generated fresh Decoy Monero wallet (32 bytes from OsRng):");
            print_monero_keys(keys);
        } else {
            eprintln!();
            eprintln!("Generated {} bits of Decoy entropy (from OsRng).", bits);
        }
        eprintln!();
        eprintln!("Decoy shares are indistinguishable from Real shares by metadata prefix.");

        let decoy_output = sharing::Slip39Output::split_with_identifier(
            required, &groups, &decoy_master, &dpass, iterations, extendable, Some(real_identifier),
        )?;

        if let Some(dt) = &decoy_targets {
            // Emit the duress notice (static, no session state).
            eprintln!();
            eprintln!("{}", DURESS_NOTICE);
            let dpkg = decoy_encrypt.parse_package()?;
            let dmnemonics = decoy_output.all_mnemonics();
            let readme_threshold = if groups.len() == 1 { groups[0].0 } else { required };
            write_export(decoy_encrypt.out.as_deref().unwrap(), &dmnemonics, dt, dpkg, readme_threshold)?;
            eprintln!();
            eprintln!("Decoy shares exported (age-armoured, {} entries).", dmnemonics.len());
        } else {
            eprintln!();
            let json = decoy_output.to_json()?; println!("{}", json.as_str()); drop(json);
        }
    }

    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn cmd_split(
    entropy_opt: Option<String>,
    password_opt: Option<String>,
    coin: Coin,
    group_specs: Vec<String>,
    required_groups: Option<u8>,
    iterations: u8,
    identifier: Option<u16>,
    extendable: bool,
    mut encrypt: EncryptArgs,
) -> Result<()> {
    // Validate group config and iterations BEFORE prompting for the secret,
    // so the user never enters a spend key only to hit a configuration error.
    validate_iterations(iterations)?;
    if let Some(id) = identifier {
        validate_identifier(id)?;
    }
    let (groups, required) = parse_groups_and_required(&group_specs, required_groups)?;

    // Validate the encrypt config BEFORE prompting for the secret (fail-fast).
    let share_count = total_share_count(&groups);
    let enc_plan = encrypt.resolve(share_count, "Split")?;

    let entropy_raw = get_entropy(entropy_opt, coin)?;
    let password = get_password(password_opt)?;

    // Now that the SLIP-0039 password is available, resolve the plan to
    // concrete targets (needed for --encrypt-with-slip-password).
    let enc_targets = plan_to_targets(enc_plan, Some(password.as_str()));

    // Auto-detect and normalise input to hex.
    let (kind, hex_secret) = detect_and_normalise(&entropy_raw)?;

    match kind {
        InputKind::Hex => eprintln!("Detected: hex secret ({} bytes)", hex_secret.len() / 2),
        InputKind::MoneroMnemonic => eprintln!("Detected: 25-word Monero mnemonic"),
        InputKind::Bip39Mnemonic => eprintln!("Detected: BIP-39 mnemonic"),
    }

    // If --coin monero, derive and show the address for verification.
    if coin == Coin::Monero {
        let keys = monero::derive_keys(&hex_secret)
            .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
        eprintln!();
        eprintln!("Monero address (verify this matches your wallet):");
        eprintln!("  {}", keys.address);
    }

    // Split.
    let master = sharing::MasterSecret::from_hex(&hex_secret)?;
    let output = sharing::Slip39Output::split_with_identifier(
        required, &groups, &master, &password, iterations, extendable, identifier,
    )?;

    if let Some(targets) = enc_targets {
        let pkg = encrypt.parse_package()?;
        let mnemonics = output.all_mnemonics();
        let readme_threshold = if groups.len() == 1 { groups[0].0 } else { required };
        write_export(encrypt.out.as_deref().unwrap(), &mnemonics, &targets, pkg, readme_threshold)?;
        eprintln!();
        eprintln!("Shares exported (age-armoured, {} entries).", mnemonics.len());
    } else {
        eprintln!();
        let json = output.to_json()?; println!("{}", json.as_str()); drop(json);
    }

    Ok(())
}

/// Derived structure for a decoy split: per-group `(member_threshold, member_count)`,
/// required group threshold, 15-bit identifier, iteration exponent, and
/// extendable-backup flag.
type DecoyStructure = (Vec<(u8, u8)>, u8, u16, u8, bool);

/// Derive the per-group member thresholds and counts for a decoy split
/// from reference Real shares and optional `--group` overrides.
///
/// Returns `(groups, required, identifier, iterations, extendable)` ready
/// to pass to `Slip39Output::split_with_identifier`.
fn derive_decoy_structure(
    metas: &[sharing::ShareMetadata],
    group_specs: &[String],
) -> Result<DecoyStructure> {
    if metas.is_empty() {
        return Err(anyhow!("no reference shares provided"));
    }

    // All reference shares must come from the same wallet.
    let first = &metas[0];
    for m in &metas[1..] {
        if m.identifier != first.identifier
            || m.iterations != first.iterations
            || m.extendable != first.extendable
            || m.group_threshold != first.group_threshold
            || m.group_count != first.group_count
        {
            return Err(anyhow!(
                "reference shares must come from the same wallet \
                 (identifier, iterations, extendable, or group structure differ)"
            ));
        }
    }

    let identifier = first.identifier;
    let iterations = first.iterations;
    let extendable = first.extendable;
    let group_threshold = first.group_threshold;
    let group_count = first.group_count;
    validate_iterations(iterations)?;

    // Build per-group member_threshold (0-based group index → threshold).
    // ShareMetadata.group_index is 1-based.
    let mut group_member_thresholds: Vec<Option<u8>> = vec![None; group_count as usize];
    for m in metas {
        let idx = m.group_index as usize;
        if idx == 0 || idx > group_count as usize {
            return Err(anyhow!(
                "reference share has group index {} but group count is {}",
                m.group_index, group_count
            ));
        }
        let idx0 = idx - 1;
        match group_member_thresholds[idx0] {
            Some(existing) if existing != m.member_threshold => {
                return Err(anyhow!(
                    "conflicting member thresholds ({}) for group {}",
                    m.member_threshold, m.group_index
                ));
            }
            _ => group_member_thresholds[idx0] = Some(m.member_threshold),
        }
    }

    // Determine group specs: (member_threshold, member_count) per group.
    let groups: Vec<(u8, u8)> = if group_specs.is_empty() {
        // Default: member_count = member_threshold. Need threshold for every group.
        let mut specs = Vec::new();
        for (i, opt) in group_member_thresholds.iter().enumerate() {
            match opt {
                Some(mt) => specs.push((*mt, *mt)),
                None => {
                    return Err(anyhow!(
                        "no reference share for group {} of {}. \
                         Provide one reference share per group with -m, \
                         or specify all groups with --group.",
                        i + 1, group_count
                    ));
                }
            }
        }
        specs
    } else {
        let parsed = parse_groups(group_specs)?;
        if parsed.len() != group_count as usize {
            return Err(anyhow!(
                "number of --group specs ({}) must match the reference wallet's group count ({})",
                parsed.len(), group_count
            ));
        }
        // Validate thresholds against reference shares where available.
        for (i, (threshold, _count)) in parsed.iter().enumerate() {
            if let Some(ref_mt) = group_member_thresholds[i] {
                if *threshold != ref_mt {
                    return Err(anyhow!(
                        "group {} --group threshold ({}) does not match the \
                         reference share's member threshold ({})",
                        i + 1, threshold, ref_mt
                    ));
                }
            }
        }
        parsed
    };

    Ok((groups, group_threshold, identifier, iterations, extendable))
}

#[allow(clippy::too_many_arguments)]
fn cmd_decoy(
    mnemonics_opt: Vec<String>,
    entropy_opt: Option<String>,
    coin: Coin,
    bits: u16,
    password_opt: Option<String>,
    no_password: bool,
    group_specs: Vec<String>,
    mut encrypt: EncryptArgs,
) -> Result<()> {
    // Validate `--bits` before prompting for the password, matching the
    // fail-fast ordering of `cmd_gen`/`cmd_split`.
    match coin {
        Coin::Monero => {} // bits ignored — Monero spend keys are always 256 bits
        Coin::Bitcoin => validate_bip39_bits(bits)?,
        Coin::Hex => validate_bits(bits)?,
    }

    let password = if no_password {
        get_password(Some(String::new()))?
    } else {
        get_password(password_opt)?
    };

    // Gather reference Real share(s).
    let mut refs: Vec<Zeroizing<String>> = if mnemonics_opt.is_empty() {
        eprintln!("Enter a Real SLIP-0039 share to use as the metadata reference:");
        eprintln!("  The decoy will inherit its identifier, iteration exponent,");
        eprintln!("  and group structure so its shares are indistinguishable.");
        eprintln!();
        let s = read_share("Real share: ")?;
        if s.is_empty() {
            return Err(anyhow!("you must enter at least one reference share"));
        }
        vec![s]
    } else {
        mnemonics_opt
            .into_iter()
            .map(|mut m| {
                let z = Zeroizing::new(m.trim().to_string());
                m.zeroize();
                z
            })
            .collect()
    };

    // Inspect each reference share and collect metadata. The share words
    // are secret-equivalent above the threshold, so wipe the split copies.
    let mut all_words: Vec<Vec<String>> = Vec::new();
    let mut metas: Vec<sharing::ShareMetadata> = Vec::new();
    for r in &refs {
        let words: Vec<String> = r.split_whitespace().map(str::to_owned).collect();
        let meta = sharing::inspect(&words)
            .map_err(|e| anyhow!("could not read reference share: {e}"))?;
        metas.push(meta);
        all_words.push(words);
    }
    zeroise_word_lists(&mut all_words);
    refs.zeroize();

    let (groups, required, identifier, iterations, extendable) =
        derive_decoy_structure(&metas, &group_specs)?;

    // Validate the encrypt config BEFORE generating any decoy secret.
    let share_count = total_share_count(&groups);
    let enc_plan = encrypt.resolve(share_count, "Decoy")?;
    let enc_targets = plan_to_targets(enc_plan, Some(password.as_str()));

    eprintln!();
    eprintln!(
        "Real wallet metadata: identifier={}, iterations={}, extendable={}, groups={}",
        identifier, iterations, extendable, groups.len()
    );

    // Obtain the decoy secret and split it with the Real wallet's metadata.
    let entropy_provided = entropy_opt.is_some();
    let output = if entropy_provided {
        // Split a user-supplied low-value secret as the decoy.
        let mut e = entropy_opt.unwrap();
        let entropy = Zeroizing::new(e.trim().to_string());
        e.zeroize();

        let (kind, hex_secret) = detect_and_normalise(&entropy)?;
        match kind {
            InputKind::Hex => eprintln!("Detected decoy secret: hex ({} bytes)", hex_secret.len() / 2),
            InputKind::MoneroMnemonic => eprintln!("Detected decoy secret: 25-word Monero mnemonic"),
            InputKind::Bip39Mnemonic => eprintln!("Detected decoy secret: BIP-39 mnemonic"),
        }

        if coin == Coin::Monero {
            let keys = monero::derive_keys(&hex_secret)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
            eprintln!();
            eprintln!("Decoy Monero address (verify):");
            eprintln!("  {}", keys.address);
        }

        let master = sharing::MasterSecret::from_hex(&hex_secret)?;
        let output = sharing::Slip39Output::split_with_identifier(
            required, &groups, &master, &password, iterations, extendable, Some(identifier),
        )?;
        eprintln!();
        eprintln!("Decoy shares — metadata prefix matches the Real wallet.");
        output
    } else if coin == Coin::Monero {
        let seed = generate_random_seed();
        let hex_secret = Zeroizing::new(hex::encode(*seed));

        let keys = monero::derive_keys(&hex_secret)
            .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;
        eprintln!();
        eprintln!("Generated fresh Decoy Monero wallet (32 bytes from OsRng):");
        print_monero_keys(&keys);
        eprintln!();
        eprintln!("IMPORTANT: The keys above will NOT be shown again.");
        eprintln!("Decoy shares are indistinguishable from Real shares by metadata prefix.");

        let master = sharing::MasterSecret::from_hex(&hex_secret)?;
        sharing::Slip39Output::split_with_identifier(
            required, &groups, &master, &password, iterations, extendable, Some(identifier),
        )?
    } else {
        // --coin bitcoin or --coin hex: generate fresh entropy.
        let master = sharing::MasterSecret::generate(bits)?;
        eprintln!();
        eprintln!("Generated {} bits of Decoy entropy (from OsRng).", bits);
        eprintln!("Decoy shares are indistinguishable from Real shares by metadata prefix.");

        sharing::Slip39Output::split_with_identifier(
            required, &groups, &master, &password, iterations, extendable, Some(identifier),
        )?
    };

    // Handle output: encrypted export or JSON to stdout.
    if let Some(targets) = enc_targets {
        let pkg = encrypt.parse_package()?;
        let mnemonics = output.all_mnemonics();
        let readme_threshold = if groups.len() == 1 { groups[0].0 } else { required };
        write_export(encrypt.out.as_deref().unwrap(), &mnemonics, &targets, pkg, readme_threshold)?;
        eprintln!();
        eprintln!("Decoy shares exported (age-armoured, {} entries).", mnemonics.len());
    } else {
        eprintln!();
        let json = output.to_json()?; println!("{}", json.as_str()); drop(json);
    }

    Ok(())
}

/// Load an age identity file or SSH private key file into a [`DecryptTarget`].
///
/// Auto-detects by content: if the file contains `AGE-SECRET-KEY-`, it is
/// parsed as an age identity file; otherwise it is treated as an SSH private
/// key (OpenSSH format). The file bytes are wrapped in `Zeroizing`.
fn load_identity_file(path: &str) -> Result<pellitory_39::encrypt::DecryptTarget> {
    let bytes = std::fs::read(path)
        .map_err(|e| anyhow!("could not read identity file `{path}`: {e}"))?;
    let bytes = Zeroizing::new(bytes);
    if String::from_utf8_lossy(bytes.as_slice()).contains("AGE-SECRET-KEY-") {
        Ok(pellitory_39::encrypt::DecryptTarget::AgeIdentity(bytes))
    } else {
        Ok(pellitory_39::encrypt::DecryptTarget::SshIdentity(bytes))
    }
}

/// Interactive per-share decrypt loop (used when no `--decrypt-*` flag is
/// supplied and at least one share is age-armoured).
///
/// Reads the method choice from `reader` (stdin). The passphrase is
/// read with hidden input when stdin is a TTY (via `rpassword`, reading
/// from /dev/tty so it is not echoed); when stdin is piped (scripts,
/// tests), it falls back to `reader` and is echoed — use
/// `--decrypt-passphrase` for non-interactive hidden input. Identity /
/// SSH key file paths are read from `reader` (not secret).
///
/// Prompts for:
///   - Method: (p)assphrase / (a)ge identity file / (s)sh private key
///   - Credential: passphrase (hidden) or file path (one line)
///
/// The decrypted plaintext is returned in `Zeroizing` and wiped on drop;
/// the in-memory passphrase copy is zeroised once consumed.
fn decrypt_share_interactive<R: std::io::BufRead>(
    ciphertext: &[u8],
    share_num: usize,
    reader: &mut R,
) -> Result<Zeroizing<Vec<u8>>> {
    use pellitory_39::encrypt::{decrypt_share, DecryptTarget};
    use std::io::{IsTerminal, Write};

    let mut stderr = std::io::stderr();
    let _ = writeln!(
        stderr,
        "Share #{share_num} is age-armoured. Choose a decryption method:"
    );
    let _ = writeln!(stderr, "  (p) passphrase\n  (a) age identity file\n  (s) SSH private key file");
    let _ = write!(stderr, "Method for share #{share_num}: ");
    let _ = stderr.flush();

    let mut method = String::new();
    let n = reader.read_line(&mut method).map_err(|e| anyhow!("could not read method choice: {e}"))?;
    if n == 0 {
        return Err(anyhow!(
            "share #{share_num} is armoured but no decrypt credential was supplied (EOF on stdin)"
        ));
    }

    let method = method.trim().to_lowercase();
    let target = match method.as_str() {
        "p" | "passphrase" => {
            // Hidden input: when stdin is a TTY, read the passphrase from
            // /dev/tty via rpassword so it is not echoed to the screen,
            // terminal scrollback, or shell history. When stdin is piped
            // (scripts, tests), fall back to `reader.read_line` — the
            // passphrase WILL be visible in that mode; use
            // --decrypt-passphrase for non-interactive hidden input.
            let _ = write!(stderr, "Passphrase for share #{share_num}: ");
            let _ = stderr.flush();
            let pass = if std::io::stdin().is_terminal() {
                let mut p = rpassword::prompt_password("")?;
                let out = Zeroizing::new(p.clone());
                p.zeroize();
                out
            } else {
                let mut p = String::new();
                reader.read_line(&mut p).map_err(|e| anyhow!("could not read passphrase: {e}"))?;
                let trimmed = p.trim_end_matches(['\r', '\n']).to_string();
                p.zeroize();
                Zeroizing::new(trimmed)
            };
            DecryptTarget::Passphrase(pass)
        }
        "a" | "age" | "age identity" => {
            let _ = write!(stderr, "Age identity file path for share #{share_num}: ");
            let _ = stderr.flush();
            let mut path = String::new();
            reader.read_line(&mut path).map_err(|e| anyhow!("could not read identity file path: {e}"))?;
            let path = path.trim();
            load_identity_file(path)?
        }
        "s" | "ssh" | "ssh key" => {
            let _ = write!(stderr, "SSH private key file path for share #{share_num}: ");
            let _ = stderr.flush();
            let mut path = String::new();
            reader.read_line(&mut path).map_err(|e| anyhow!("could not read SSH key path: {e}"))?;
            let path = path.trim();
            load_identity_file(path)?
        }
        other => {
            return Err(anyhow!(
                "unknown method `{other}` for share #{share_num}; use p, a, or s"
            ));
        }
    };

    decrypt_share(ciphertext, &target).map_err(|e| {
        anyhow!("could not decrypt share #{share_num}: {e}")
    })
}

fn cmd_recover(
    mnemonics_opt: Vec<String>,
    mut password_opt: Option<String>,
    decrypt_passphrase_opts: Vec<String>,
    decrypt_with_slip_password: bool,
    decrypt_identity_opts: Vec<String>,
    coin: Coin,
) -> Result<()> {
    use pellitory_39::encrypt::{is_age_armored, decrypt_share, DecryptTarget};

    // ── Stage 1: load each -m value into (raw_bytes, share_label) ───────
    //
    // Each -m value is either:
    //   - `@<PATH>`  -> read the file bytes (armour autodetected later)
    //   - `<text>`   -> the raw mnemonic string (may be armoured if pasted)
    //
    // If no -m flags were given, fall back to the interactive share prompt.
    let mut raw_shares: Vec<Zeroizing<Vec<u8>>> = if mnemonics_opt.is_empty() {
        // Interactive: prompt for shares as before (plain text, hidden input).
        get_shares_interactive()?
            .into_iter()
            .map(|s| Zeroizing::new(s.as_bytes().to_vec()))
            .collect()
    } else {
        let mut loaded = Vec::with_capacity(mnemonics_opt.len());
        for (i, mut m) in mnemonics_opt.into_iter().enumerate() {
            if let Some(path_str) = m.strip_prefix('@') {
                let path = std::path::Path::new(path_str);
                let bytes = std::fs::read(path).map_err(|e| {
                    anyhow!("could not read share file #{} `{}`: {e}", i + 1, path_str)
                })?;
                loaded.push(Zeroizing::new(bytes));
            } else {
                let trimmed = m.trim();
                let bytes = Zeroizing::new(trimmed.as_bytes().to_vec());
                m.zeroize();
                loaded.push(bytes);
            }
        }
        loaded
    };

    if raw_shares.is_empty() {
        return Err(anyhow!("no shares provided"));
    }

    // ── Stage 2: identify which shares are armoured ─────────────────────
    //
    // For each share, `is_age_armored` does a cheap prefix check. Armoured
    // shares need a decrypt credential before SLIP-0039 combine.
    let armoured_count = raw_shares.iter().filter(|s| is_age_armored(s)).count();

    // ── Stage 3: resolve decrypt credentials ────────────────────────────
    //
    // If there are no armoured shares, skip decrypt entirely (today's path).
    // If armoured shares exist:
    //   (a) Single-method fast path: if --decrypt-passphrase and/or
    //       --decrypt-identity is supplied, auto-try on each armoured share.
    //   (b) Interactive per-share loop: prompt for each armoured share via
    //       stdin (method choice + credential), so tests can pipe input.
    let mut mnemonics: Vec<Zeroizing<String>> = Vec::with_capacity(raw_shares.len());

    if armoured_count == 0 {
        // No armoured shares — all plain text.
        for raw in raw_shares.iter() {
            let s = std::str::from_utf8(raw)
                .map_err(|e| anyhow!("share is not valid UTF-8: {e}"))?;
            mnemonics.push(Zeroizing::new(s.trim().to_string()));
        }
        raw_shares.zeroize();
    } else {
        // We have armoured shares. Build the list of fast-path credentials.
        let mut fast_path: Vec<DecryptTarget> = Vec::new();
        for pass in decrypt_passphrase_opts {
            fast_path.push(DecryptTarget::Passphrase(Zeroizing::new(pass)));
        }
        if decrypt_with_slip_password {
            // Reuse the SLIP-0039 password as the age decryption passphrase.
            // Resolve it now (prompt if not provided) and stash it back into
            // password_opt so the later get_password() call reuses it
            // instead of prompting a second time.
            if fast_path.iter().any(|c| matches!(c, DecryptTarget::Passphrase(_))) {
                return Err(anyhow!(
                    "--decrypt-with-slip-password conflicts with --decrypt-passphrase; choose one"
                ));
            }
            // Take ownership of the clap/env password String without
            // cloning — `take()` moves it into `Zeroizing` so no un-wiped
            // copy lingers in `password_opt`. It is stashed back below for
            // the later `get_password()` call (which zeroises its input).
            let slip_pass = match password_opt.take() {
                Some(p) => Zeroizing::new(p),
                None => get_password(None)?,
            };
            fast_path.push(DecryptTarget::Passphrase(Zeroizing::new(slip_pass.as_str().to_string())));
            password_opt = Some(slip_pass.as_str().to_string());
        }
        for id_path in &decrypt_identity_opts {
            let cred = load_identity_file(id_path)?;
            fast_path.push(cred);
        }

        let use_interactive = fast_path.is_empty();

        for (i, raw) in raw_shares.iter().enumerate() {
            let share_num = i + 1;
            if !is_age_armored(raw) {
                // Plain text share — pass through.
                let s = std::str::from_utf8(raw)
                    .map_err(|e| anyhow!("share #{share_num} is not valid UTF-8: {e}"))?;
                mnemonics.push(Zeroizing::new(s.trim().to_string()));
                continue;
            }

            // Armoured share — decrypt.
            let plaintext = if use_interactive {
                decrypt_share_interactive(raw, share_num, &mut std::io::stdin().lock())?
            } else {
                // Fast path: try each supplied credential until one works.
                let mut last_err = None;
                let mut decrypted = None;
                for cred in &fast_path {
                    match decrypt_share(raw, cred) {
                        Ok(p) => { decrypted = Some(p); break; }
                        Err(e) => { last_err = Some(e); }
                    }
                }
                match decrypted {
                    Some(p) => p,
                    None => return Err(anyhow!(
                        "could not decrypt share #{share_num}: {}",
                        last_err.map(|e| e.to_string()).unwrap_or_else(|| "no credentials supplied".to_string())
                    )),
                }
            };

            let s = String::from_utf8(plaintext.to_vec())
                .map_err(|e| anyhow!("decrypted share #{share_num} is not valid UTF-8: {e}"))?;
            mnemonics.push(Zeroizing::new(s.trim().to_string()));
        }
        raw_shares.zeroize();
    }

    let password = get_password(password_opt)?;

    let mut word_lists: Vec<Vec<String>> = mnemonics
        .iter()
        .map(|m| m.split_whitespace().map(str::to_owned).collect())
        .collect();

    // The shares have been parsed into Share structs (which zeroise their
    // share_value on drop) inside the combine path; wipe the raw strings now.
    mnemonics.zeroize();

    let mut recovered = sharing::combine(&word_lists, &password)?;

    // Wipe the split word copies — they are heap-allocated owned Strings
    // holding share words, which are secret-equivalent above the threshold.
    zeroise_word_lists(&mut word_lists);

    match coin {
        Coin::Monero => {
            // Derive and show full Monero wallet.
            let hex_str = Zeroizing::new(hex::encode(&*recovered));
            let keys = monero::derive_keys(&hex_str)
                .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;

            eprintln!();
            eprintln!("Recovered Monero wallet:");
            print_monero_keys(&keys);
            eprintln!();
        }
        Coin::Bitcoin => {
            // Output as BIP-39 mnemonic.
            let bip39_mnemonic = bip39::Mnemonic::from_entropy(&recovered, bip39::Language::English)
                .map_err(|e| anyhow!("BIP-39 encoding failed: {e}"))?;
            let mut phrase = bip39_mnemonic.into_phrase();
            eprintln!();
            eprintln!("Recovered BIP-39 mnemonic:");
            println!("{}", phrase);
            phrase.zeroize();
        }
        Coin::Hex => {
            // Output as hex.
            let mut hex_output = hex::encode(&*recovered);
            eprintln!();
            eprintln!("Recovered secret (hex):");
            println!("{}", hex_output);
            eprintln!();
            eprintln!("Tip: use --coin monero to derive a Monero wallet, or --coin bitcoin for a BIP-39 seed phrase.");
            hex_output.zeroize();
        }
    }

    recovered.zeroize();
    Ok(())
}

fn cmd_derive(
    spend_key: Option<String>,
    mnemonic: Option<String>,
    interactive: bool,
    coin: Coin,
) -> Result<()> {
    match coin {
        Coin::Bitcoin => cmd_derive_bip39(spend_key, mnemonic, interactive),
        Coin::Monero => cmd_derive_monero(spend_key, mnemonic, interactive),
        // Unreachable: parse_derive_coin rejects Coin::Hex at parse time.
        Coin::Hex => unreachable!("parse_derive_coin rejects --coin hex for derive"),
    }
}

/// Derive a BIP-39 mnemonic (Bitcoin / Ethereum) from raw hex entropy.
///
/// The input is hex; any of `-s`, `-m`, `-i`, or a hidden prompt is
/// accepted exactly as in the Monero path, so the `derive --coin bitcoin`
/// workflow mirrors the existing one. The hex is decoded into a
/// `Zeroizing` byte buffer and passed to [`pellitory_39::derive_bip39_mnemonic`].
fn cmd_derive_bip39(
    spend_key: Option<String>,
    mnemonic: Option<String>,
    interactive: bool,
) -> Result<()> {
    let raw = get_derive_input_with_label(
        spend_key,
        mnemonic,
        interactive,
        "Hex entropy (e.g. 64 hex chars for a 24-word phrase): ",
    )?;

    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(anyhow!("no entropy provided"));
    }
    if !trimmed.len().is_multiple_of(2) || !trimmed.chars().all(|c| c.is_ascii_hexdigit()) {
        return Err(anyhow!(
            "BIP-39 entropy must be an even number of hex digits (got {} chars)",
            trimmed.len()
        ));
    }

    let mut bytes = Zeroizing::new(hex::decode(trimmed)?);
    let phrase = pellitory_39::derive_bip39_mnemonic(&bytes)?;
    bytes.zeroize();

    eprintln!();
    eprintln!("Derived BIP-39 mnemonic ({} words):", phrase.split_whitespace().count());
    println!("{}", phrase.as_str());
    eprintln!();
    eprintln!("Use this phrase with any BIP-39 wallet (Bitcoin, Ethereum, etc.).");
    eprintln!("WARNING: this phrase IS the entropy — anyone who reads it owns the wallet.");
    Ok(())
}

/// Derive the full Monero key set from a spend key or 25-word mnemonic.
fn cmd_derive_monero(
    spend_key: Option<String>,
    mnemonic: Option<String>,
    interactive: bool,
) -> Result<()> {
    let phrase = get_derive_input(spend_key, mnemonic, interactive)?;

    let keys = monero::derive_keys(&phrase)
        .map_err(|e| anyhow!("Monero key derivation failed: {e}"))?;

    print_monero_keys(&keys);
    eprintln!();

    Ok(())
}

fn cmd_completions(shell: &str) -> Result<()> {
    let mut cmd = Cli::command();
    // clap_complete walks the live `Command` tree, so completion stays in
    // sync with the subcommands, aliases (`gen`, `combine`), options, and
    // `value_parser` hints (e.g. the accepted `--coin` / `--shell` values)
    // without any hand-maintained script. The accepted shell strings are
    // already restricted by the `value_parser` on the `Completions` arg, so
    // `Shell::from` here is infallible in practice.
    let shell: clap_complete::Shell = shell
        .parse()
        .map_err(|e: String| anyhow!("{e}"))?;
    // The binary name in the generated script must match what users type
    // so completion triggers on `pellitory-39 <TAB>`.
    clap_complete::generate(shell, &mut cmd, "pellitory-39", &mut io::stdout());
    Ok(())
}

fn cmd_inspect(mnemonic_opt: Option<String>) -> Result<()> {
    // Prompt with hidden input when no `-m` is given, so the share (which is
    // secret-equivalent above the threshold) never hits argv / `ps` / shell
    // history. The raw prompt String is zeroised before it goes out of scope.
    let mut mnemonic: String = match mnemonic_opt {
        Some(m) => m,
        None => {
            eprintln!("Enter the SLIP-0039 share to inspect (input is hidden):");
            let mut raw = rpassword::prompt_password("Share: ")?;
            let trimmed = raw.trim().to_string();
            raw.zeroize();
            trimmed
        }
    };
    let mut words: Vec<String> = mnemonic.split_whitespace().map(str::to_owned).collect();
    mnemonic.zeroize();
    let meta = sharing::inspect(&words)?;
    zeroise_words(&mut words);
    println!("{}", serde_json::to_string_pretty(&meta)?);
    Ok(())
}

// ─── Main ───────────────────────────────────────────────────────────────────

fn main() {
    let cli = Cli::parse();

    // The --gui flag intercepts the run flow and launches the desktop GUI
    // instead of any CLI subcommand.
    if cli.gui {
        run_gui_mode();
        return;
    }

    let result = match cli.command {
        Some(Commands::Generate {
            coin,
            bits,
            password,
            no_password,
            groups,
            required_groups,
            iterations,
            identifier,
            extendable,
            decoy,
            decoy_password,
            no_decoy_password,
            out,
            package,
            encrypt_passphrase,
            encrypt_to,
            encrypt_to_file,
            encrypt_passphrase_file,
            encrypt_with_slip_password,
            confirm_recipient,
            decoy_out,
            decoy_encrypt_passphrase,
            decoy_encrypt_to,
            decoy_encrypt_to_file,
            decoy_encrypt_passphrase_file,
            decoy_encrypt_with_slip_password,
            decoy_confirm_recipient,
            decoy_package,
        }) => cmd_gen(
            coin, bits, password, no_password, groups, required_groups,
            iterations, identifier, extendable, decoy, decoy_password, no_decoy_password,
            EncryptArgs { out, package, encrypt_passphrase, encrypt_to, encrypt_to_file, encrypt_passphrase_file, encrypt_with_slip_password, confirm_recipient },
            EncryptArgs {
                out: decoy_out,
                package: decoy_package.unwrap_or_default(),
                encrypt_passphrase: decoy_encrypt_passphrase,
                encrypt_to: decoy_encrypt_to,
                encrypt_to_file: decoy_encrypt_to_file,
                encrypt_passphrase_file: decoy_encrypt_passphrase_file,
                encrypt_with_slip_password: decoy_encrypt_with_slip_password,
                confirm_recipient: decoy_confirm_recipient,
            },
        ),

        Some(Commands::Split {
            entropy,
            password,
            coin,
            groups,
            required_groups,
            iterations,
            identifier,
            extendable,
            out,
            package,
            encrypt_passphrase,
            encrypt_to,
            encrypt_to_file,
            encrypt_passphrase_file,
            encrypt_with_slip_password,
            confirm_recipient,
        }) => cmd_split(entropy, password, coin, groups, required_groups, iterations, identifier, extendable, EncryptArgs { out, package, encrypt_passphrase, encrypt_to, encrypt_to_file, encrypt_passphrase_file, encrypt_with_slip_password, confirm_recipient }),

        Some(Commands::Decoy {
            mnemonics,
            entropy,
            coin,
            bits,
            password,
            no_password,
            groups,
            out,
            package,
            encrypt_passphrase,
            encrypt_to,
            encrypt_to_file,
            encrypt_passphrase_file,
            encrypt_with_slip_password,
            confirm_recipient,
        }) => cmd_decoy(mnemonics, entropy, coin, bits, password, no_password, groups, EncryptArgs { out, package, encrypt_passphrase, encrypt_to, encrypt_to_file, encrypt_passphrase_file, encrypt_with_slip_password, confirm_recipient }),

        Some(Commands::Recover {
            mnemonics,
            password,
            decrypt_passphrase,
            decrypt_with_slip_password,
            decrypt_identity,
            coin,
        }) => cmd_recover(mnemonics, password, decrypt_passphrase, decrypt_with_slip_password, decrypt_identity, coin),

        Some(Commands::Derive {
            spend_key,
            mnemonic,
            interactive,
            coin,
        }) => cmd_derive(spend_key, mnemonic, interactive, coin),

        Some(Commands::Inspect { mnemonic }) => cmd_inspect(mnemonic),

        Some(Commands::Completions { shell }) => cmd_completions(&shell),

        None => {
            // No subcommand given. With the `gui-default` feature, launch the
            // desktop GUI so `pellitory-39` (no args) opens a window. Otherwise
            // print help and exit, preserving the pure-CLI behaviour.
            #[cfg(feature = "gui-default")]
            {
                run_gui_mode();
                return;
            }
            // `gui-default` is off: fall through to printing help. The
            // `#[allow]` silences the unreachable-pattern lint for builds
            // where `gui-default` is enabled (the arm above returns).
            #[cfg(not(feature = "gui-default"))]
            {
                Cli::parse_from(["pellitory-39", "--help"]);
                return;
            }
        }
    };

    if let Err(e) = result {
        eprintln!("Error: {e}");
        std::process::exit(1);
    }
}

/// Launch the desktop GUI. When the `gui` feature is disabled, print a
/// helpful message and exit so the binary still works as a pure CLI.
#[cfg(feature = "gui")]
fn run_gui_mode() {
    if let Err(e) = gui::run_gui() {
        eprintln!("GUI error: {e}");
        std::process::exit(1);
    }
}

#[cfg(not(feature = "gui"))]
fn run_gui_mode() {
    eprintln!(
        "Error: This binary was compiled without GUI support. \
         Rebuild with `cargo build --release --features gui`."
    );
    std::process::exit(1);
}
