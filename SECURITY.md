# Security

This document explains the security model of Pellitory-39, what it protects against, what it doesn't, and why it exists.

## Why Pellitory-39 exists

This project was born from two observations.

### Problem 1: No tooling for splitting Monero keys

SLIP-0039 was designed with Bitcoin's BIP-39 ecosystem in mind. If you hold Bitcoin, there are mature tools for splitting your 24-word seed phrase into SLIP-0039 shares and recovering it later. But if you hold Monero, your options were limited.

Monero's wallet is fully described by a single 32-byte private spend key (or its equivalent 25-word mnemonic). Everything else — the view key, public keys, and wallet address — is deterministically derived from it. The original [spendkey](https://github.com/moneroexamples/spendkey) C++ tool made this derivation explicit, and [slip39-rust](https://github.com/Internet-of-People/slip39-rust) handled the SLIP-0039 splitting side, but nothing combined the two workflows. If you wanted to split a Monero spend key into shares and later recover the full wallet, you had to chain two separate tools together manually, keeping track of hex strings along the way.

### Problem 2: Python implementations don't handle secrets safely

The Python implementations of both spendkey and SLIP-0039 share a fundamental problem: **Python cannot guarantee that secrets are erased from memory.**

Here's why that matters:

- **No zeroisation.** When a Python `str` or `bytes` object holding your private key goes out of scope, the garbage collector *eventually* frees the memory — but it doesn't zero the contents first. Your spend key sits in freed heap memory, recoverable by anything that scans RAM.

- **Immutable strings.** Python strings are immutable. You can't overwrite the contents of a `str` in place. Even if you set the variable to `None`, the original string data is still floating about on the heap until the allocator happens to reuse that page.

- **No `SecretBox` equivalent.** There's no way to prevent a Python object from appearing in a stack trace, a log statement, or a `repr()` call. If an exception is raised whilst your spend key is in scope, the default exception handler will cheerfully print it.

- **Reference counting and copies.** Python's memory model creates copies freely — string concatenation, function arguments, dictionary lookups. Each copy is another fragment of your secret that won't be zeroed.

Rust solves these problems at the language level. Pellitory-39 uses the `zeroize` crate to wipe secrets from memory deterministically (on drop, not "whenever the GC gets round to it"), and the `secrecy` crate to prevent secrets from leaking through `Debug`, `Display`, or logging.

## Dependency audit

Every dependency that touches secret material has been reviewed. Here is the full picture:

| Crate | Handles secrets? | Zeroises? | Notes |
|-------|-----------------|-----------|-------|
| `curve25519-dalek` | ✅ Private key scalars | ✅ Yes | `Scalar` implements `Zeroize`; the `zeroize` feature is pinned explicitly in `Cargo.toml` so it stays on even if `default-features` is later turned off. We call `.zeroize()` explicitly after use. |
| `sssmc39` (local fork) | ✅ Master secret, passphrase, intermediates | ✅ Yes | **Hardened fork** — all Feistel cipher intermediates (including the per-round half-secret `l`/`r` buffers, which are zeroised before reassignment, not just on final drop), passphrase copies, share values, and encrypted master secret wrapped in `Zeroizing` or explicitly zeroised. `Share` has a custom `Drop` that zeroises `share_value`. `BitPacker` (which holds the packed `identifier || ext||exp || indices || share_value || checksum` during encode/decode) has a custom `Drop` that zeroes every in-range bit, wiping the packed share value that ordinary `BitVec::Drop` would leave in freed heap memory. |
| `tiny-bip39` | ✅ Mnemonic entropy | ✅ Yes | `Mnemonic` holds `phrase: Zeroizing<String>` and `entropy: Zeroizing<Vec<u8>>`; both are zeroed on drop. |
| `tiny-keccak` (vendored fork) | Passes through secrets | ✅ Yes | **Hardened fork** — upstream's `Keccak` sponge state (`Buffer([u64; 25])`) absorbs the Monero spend key but implements neither `Zeroize` nor `Drop` and exposes the bytes via `unsafe { transmute }`. Our fork adds `impl Zeroize for Buffer` + `impl Drop for KeccakState` (wipes the sponge on drop), rewrites the sponge I/O (`Buffer::execute`/`xorin`) in safe Rust (no `transmute`, no raw-pointer loop), and sets `#![forbid(unsafe_code)]` crate-wide. The hashing algorithm is unchanged (verified by `matches_reference_vector`). See residual risk 5 below. |
| `sha2` / `hmac` (RustCrypto) | Passes through secrets | ⚠️ No | Used by `sssmc39`'s `rust_crypto_pbkdf2` feature and `tiny-bip39`'s checksum. Internal block buffer / hash state is not zeroised on drop. See residual risk 6 below. |
| `ring` (PBKDF2) | ✅ Derives keys from passphrase | ✅ Yes | BoringSSL-derived; cleanses its internal HMAC state via `OPENSSL_cleanse` on drop. |
| `secrecy` | ✅ Wraps private keys | ✅ Yes | `SecretBox<T>` zeroises on drop and blocks `Debug`/`Display`. |
| `rpassword` | ✅ Reads passwords from terminal | ⚠️ Partial | Returns `String` which we immediately wrap in `Zeroizing`. The internal read buffer is stack-allocated and overwritten quickly, but not explicitly zeroed. |
| `clap` | ⚠️ Parses `--entropy`/`--password` from argv | ⚠️ Partial | We zeroize the parsed strings in `get_password()` and `get_entropy()`, but clap's own internal argv parsing buffers are not under our control. Using hidden interactive prompts (the default) avoids this entirely. |
| `hex` | Encodes/decodes secrets | N/A | Pure conversion functions, no internal state. We wrap all returned values. |
| `serde_json` | Serialises shares (not secrets) | N/A | Only touches the output shares, never the master secret or password. |
| `age` | Encrypts share exports (scrypt passphrase, X25519, SSH) | Mostly yes | Third-party crate (not vendored like sssmc39/tiny-keccak). All passphrases and identity-file bytes are wrapped in `Zeroizing` at Pellitory's boundary. `age` 0.12 zeroises most of its internal state via `secrecy::SecretBox`/`SecretString` (`Drop`) and manual `Drop` impls: passphrase (`SecretString`), `FileKey` (`SecretBox`), `HmacKey` (`SecretBox`), `PayloadKey`/ChaCha20Poly1305 stream key (manual `Drop`), SSH Ed25519 key material (`SecretBox<[u8;64]>`), and RSA keys (`rsa::RsaPrivateKey::Drop`). **Gap:** `age` depends on `x25519-dalek` with `features=["static_secrets"]` but does **not** enable the `zeroize` feature, so `StaticSecret` (X25519 private scalar) and `SharedSecret` (DH output) are not zeroised on drop — affects the X25519 and SSH-Ed25519 paths. See residual risk 7. |
| `zip` | Packages armoured shares into a ZIP | N/A | Pure container -- no secret material. ZIP entries use `Stored` (no compression); contents are already age-armoured ASCII. The ZIP itself is unencrypted (residual risk 9). |
| `rand` (OsRng) | Generates key material | N/A | Draws from OS CSPRNG. No internal secret state. |

### Residual risks

Four minor residual risks remain, all mitigated by using interactive prompts (the default) or an air-gapped machine for high-value operations:

1. **clap's argv parsing.** When secrets are passed via `--entropy` or `--password` CLI flags, clap internally copies the argument strings during parsing. These copies live in heap memory and are not zeroised. Share mnemonics passed via `--mnemonic` / `-m` are wrapped in `Zeroizing` after parsing, but clap's own argv buffers are not under our control. **Mitigation:** Don't pass secrets or shares as CLI arguments. Use the default hidden prompts, or environment variables (`PELLITORY_ENTROPY`, `PELLITORY_PASSWORD`).

2. **Stack copies.** Rust may create temporary copies of small values (like `[u8; 32]` arrays) on the stack during function calls. These are overwritten as the stack is reused, but are not explicitly zeroed. **Mitigation:** Use an air-gapped machine for high-value operations (see below).

3. **Heap clones of shares during split/combine.** The `Share` type derives `Clone`, and the SLIP-0039 split and combine paths clone share values several times (proto-share templates, base-share sets, group-index maps). Each clone is a separate copy of the share value in heap memory; all copies are zeroised on drop by `Share`'s custom `Drop`, but several transient copies coexist during execution, widening the window for a memory-dump or cold-boot attacker. This is inherent to the upstream `sssmc39` design. **Mitigation:** Use an air-gapped machine (which clears RAM on shutdown) for high-value operations.

4. **Environment variables persist for the process lifetime.** The `PELLITORY_PASSWORD` and `PELLITORY_ENTROPY` environment variables are a safer alternative to CLI flags (which appear in `ps` output and shell history), but they are not zeroised: they remain readable via `/proc/<pid>/environ` on Linux, the `ps e` command on some systems, and are inherited by any child process for the entire lifetime of the programme. There is no portable way to scrub an environment variable from another process's view. **Mitigation:** Prefer the default hidden interactive prompts for high-value operations. Reserve environment variables for automation on trusted, single-user, or air-gapped machines.

5. **`tiny-keccak` sponge state (fixed in vendored fork).** `src/monero/mod.rs` absorbs the Monero private spend key into a `Keccak::v256()` sponge for view-key derivation, and public keys into one for the address checksum. Upstream `tiny-keccak`'s `Keccak` sponge state (`Buffer([u64; 25])`, holding absorbed input) is in a private field with no public accessor and implements neither `Zeroize` nor `Drop`, so it was dropped un-cleansed. This is now fixed in our vendored fork (`tiny-keccak/`): `impl Zeroize for Buffer` and `impl Drop for KeccakState` wipe the sponge on drop, so the absorbed spend key is overwritten before the heap page is freed. The hashing algorithm is unchanged (verified by the `matches_reference_vector` test pinning the exact derived Monero keys/address). The fork also rewrites upstream's `unsafe` sponge I/O (the `core::mem::transmute` in `Buffer::execute` and the raw-pointer loop in `xorin`) in safe Rust and sets `#![forbid(unsafe_code)]` crate-wide, so no `unsafe` remains under any feature gate (verified by `cargo build --all-features` on the fork). **Residual:** the OS may still have paged the sponge out to swap before drop; use an amnesic OS such as Tails, which wipes all RAM at shutdown regardless of in-process zeroisation.

6. **`sha2` / `hmac` internal state.** The RustCrypto `sha2` and `hmac` crates (used by `sssmc39`'s optional `rust_crypto_pbkdf2` feature and `tiny-bip39`'s BIP-39 checksum) do not zeroise their internal block buffer / hash state on drop in the configuration pellitory pulls in. These absorb small fragments (BIP-39 entropy, 4-byte SLIP-39 share-digest fragments). **Mitigation:** Low individual sensitivity; same Tails recommendation as (5). The default `ring_pbkdf2` feature uses `ring` (which does cleanse) instead of `rust_crypto_pbkdf2`, so this only affects the BIP-39 checksum path in practice.

7. **`age` X25519 scalar / shared secret (third-party, not vendored).** The `age` crate (used for encrypted share export) is third-party and audited but not vendored or patched like `sssmc39` / `tiny-keccak`. `age` 0.12 zeroises most of its internal state via the `secrecy` crate (`SecretBox`/`SecretString` with `Drop`) and manual `Drop` impls: the passphrase (`SecretString`), `FileKey` (`SecretBox<[u8;16]>`), `HmacKey` (`SecretBox<[u8;32]>`), `PayloadKey`/ChaCha20Poly1305 stream key (manual `Drop` + `zeroize`), SSH Ed25519 key material (`SecretBox<[u8;64]>`), and RSA private keys (`rsa::RsaPrivateKey::Drop`). It also manually `.zeroize()`s the bech32 decode buffer and the decrypted file-key plaintext. **The one gap:** `age` depends on `x25519-dalek` with `features=["static_secrets"]` but does **not** enable the `zeroize` cargo feature, so `x25519_dalek::StaticSecret` (the 32-byte private scalar, held inside `age::x25519::Identity`) and `SharedSecret` (the DH output) are **not** zeroised on drop — their `#[cfg_attr(feature="zeroize", zeroize(drop))]` attributes are inactive. This affects the X25519 (`age1...`) and SSH-Ed25519 recipient paths (both perform an X25519 DH). Pellitory wraps all passphrases and identity-file bytes in `Zeroizing` at its boundary (`src/encrypt.rs`), so the credential you supply is wiped on drop, but the X25519 scalar and shared secret may linger in freed heap pages until the OS reclaims them. This is consistent with the "do not fork upstream" constraint (we do not patch `age` or `x25519-dalek`). **Mitigation:** Use an air-gapped / amnesic OS (Tails) for high-value operations, same as all other residual risks.

8. **`rsa` crate Marvin Attack (RUSTSEC-2023-0071).** The `age` crate's `ssh` feature pulls in `rsa 0.9.10`, which carries a known advisory for potential key recovery through timing side-channels (the Marvin Attack). This affects SSH-RSA recipients only (Ed25519 SSH keys are not affected). Pellitory itself does not perform RSA operations -- the timing side-channel is in `age`'s SSH-RSA decryption path. **Mitigation:** Prefer SSH Ed25519 keys over SSH-RSA keys for share encryption. For high-value operations, use an air-gapped machine (the timing attack requires physical proximity or a compromised OS, both of which already defeat any software defence). No fixed upgrade is currently available upstream.

9. **ZIP container is unencrypted.** The ZIP container produced by `--out` is a standard unencrypted ZIP. Each share's *content* is age-armoured, but a found ZIP reveals the share count and each entry's age armour stanza type (`-> scrypt` / `-> X25519` / `-> ssh-ed25519` / `-> ssh-rsa`). This is a metadata leak, not a secret leak -- the share values remain encrypted. For duress indistinguishability, Real and Decoy must use matching encryption methods in matching share positions (decision 7a, user responsibility). **Mitigation:** The ZIP is a transport container, not a vault. Store it on encrypted media (e.g. a LUKS-encrypted USB stick) and distribute shares separately.

10. **`--encrypt-passphrase-file` files on disk.** When using `--encrypt-passphrase-file`, the passphrase file on disk is the user's responsibility (like the existing `@file` and stdin conventions). Pellitory reads the file, wraps the passphrase in `Zeroizing`, and zeroises its in-memory copy of the file contents after use, but the file itself is not wiped. **Mitigation:** Store passphrase files on encrypted media or enter passphrases interactively (the default). Never commit passphrase files to version control.

### Supply-chain hygiene

The upstream `rust-sssmc39` crate depended on [`failure`](https://crates.io/crates/failure), a crate that has been **deprecated and unmaintained since 2019**. Unmaintained dependencies are a supply-chain risk: they receive no security patches and pull in old transitive dependencies. Our hardened fork removes `failure` entirely and replaces it with `thiserror` (which the rest of the project already uses). This also eliminates the `non_local_definitions` compiler warnings that newer versions of `rustc` emit for `failure`'s derive macros.

## What Pellitory-39 does to protect your secrets

### Memory zeroisation

Every type that holds secret material uses `Zeroizing<T>` from the `zeroize` crate. When the value is dropped (goes out of scope), its memory is overwritten with zeroes before being freed. This includes:

- The master secret / spend key
- Passwords
- Entropy input (hex, mnemonics)
- Intermediate buffers during encoding and decoding
- The recovered secret after combining shares
- Ed25519 scalars holding private keys (via `Scalar::zeroize()`)
- All intermediates inside the SLIP-0039 Feistel cipher
- The packed-bit buffer used while serialising / parsing shares (`BitPacker`, which holds the share value; wiped on drop via a custom `Drop` impl)
- The CLI JSON share output — `Slip39Output::to_json()` returns `Zeroizing<String>` and zeroises the intermediate `ShareFormatter` / `GroupFormatter` mnemonic strings after serialisation, so the full share set does not linger un-wiped in the `println!` temporary
- Individual share words — `Share::to_mnemonic()` returns `Vec<Zeroizing<String>>`, so each per-word `String` (secret-equivalent above the threshold) is wiped on drop rather than being freed un-wiped by ordinary `String::Drop`. `Slip39Output::all_mnemonics()` and `GroupShare::mnemonic_list()` / `mnemonic_list_flat()` propagate the same `Zeroizing` wrapper to their callers.

The `MasterSecret` type is explicitly **not `Clone`**, preventing untracked copies of secret material from accumulating in memory.

### Debug and Display blocking

Private keys are wrapped in `SecretBox<T>` from the `secrecy` crate. This type implements `Debug` and `Display` to print `[REDACTED]` instead of the actual value. You must call `.expose_secret()` explicitly to access the contents — a compile-time guarantee that you won't accidentally log a private key.

### Cryptographic random number generation

Key generation uses `rand::rngs::OsRng`, which draws entropy directly from the operating system's CSPRNG (`/dev/urandom` on Linux, `BCryptGenRandom` on Windows). We never use `thread_rng()` or any userspace PRNG for cryptographic material.

### Hidden interactive input

By default, all secrets and passwords are entered via hidden interactive prompts (using `rpassword`). The input is not echoed to the terminal, does not appear in scrollback, and is not recorded in shell history.

### GUI memory hygiene (`--gui`)

The desktop GUI (`eframe`/`egui`, enabled with `--features gui`) extends the same zeroisation discipline to its background-worker threads, file-save path, and shutdown:

- **Worker threads.** Every `start_*` helper clones the password / input secret into a `Zeroizing<String>` and moves that owned copy into the `std::thread::spawn` closure. When the worker thread finishes, the closure (and its secret buffer) is dropped, overwriting the buffer with zeroes before it is freed. This prevents the plain-`String` heap residue that an earlier version left in freed pages after each Generate / Split / Recover / Derive action. The Derive tab's worker applies the same discipline to its raw-input `Zeroizing<String>` and the resulting BIP-39 phrase / Monero key set (the phrase is produced by `derive_bip39_mnemonic`, which returns `Zeroizing<String>`; the Monero keys come from `monero::derive_keys` wrapped in `MoneroRecovery`).
- **Share mnemonics.** `Share::to_mnemonic()` returns `Vec<Zeroizing<String>>`, so each per-word `String` is wiped on drop; `Slip39Output::all_mnemonics()` and `GroupShare::mnemonic_list()` / `mnemonic_list_flat()` propagate the same `Zeroizing` wrapper. The CLI's `Slip39Output::to_json()` path returns `Zeroizing<String>` and zeroises the `ShareFormatter` mnemonic strings after serialisation. The GUI's `format_shares` takes `&[Zeroizing<String>]`, so the share buffers it holds while waiting for the OS save dialog are wiped on drop. (The on-disk file itself is plaintext by user action — see below.)
- **File save.** The "Save … to TXT" path wraps the in-memory content in `Zeroizing<String>` so the buffer that holds the shares while waiting for the OS save dialog is zeroised after the write. (The on-disk file itself is plaintext by user action — see below.)
- **Shutdown.** `App::on_exit` calls `wipe_all()` to drop all `Zeroizing` UI fields, then clears egui's widget-state store (`Memory::data`, which includes `TextEdit` undo stacks holding copies of the text entered into the password / share input fields), replaces egui's galley cache (`Memory::caches`, whose `LayoutJob.text: String` holds the full source of every laid-out label — including the selectable share / key labels) with an empty store, and overwrites the system clipboard with an empty string.
- **Navigation.** Switching the coin or mode tab (when result persistence is off) wipes the `output`, `error`, and input `Zeroizing` fields of the tab being left, then clears egui's widget-state store (`Memory::data`, which includes `TextEdit` undo stacks — Ctrl+Z history — holding copies of the text typed into the password / share input fields) and replaces the galley cache (`Memory::caches`, whose `LayoutJob.text: String` holds the laid-out result-label strings) with an empty store. Without clearing `Memory::data` the underlying buffers could be recovered by pressing Ctrl+Z on the new tab. Only the currently-visible tab is allowed to hold result material.
- **Error messages.** The per-tab `error` fields are `Option<Zeroizing<String>>`, so even error strings (which may echo fragments of an internal error chain) are wiped on drop.

**Residual GUI risks that cannot be fully eliminated in-process:**

- **Clipboard persistence.** Copy buttons place secrets on the system clipboard. `on_exit` overwrites the live clipboard with an empty string, but OS-level clipboard-history managers may still retain a copy. Do not copy secrets on a shared machine.
- **egui caches mid-session.** egui caches laid-out text galleys in `Memory::caches` for CPU efficiency; these hold the source `String` of rendered labels. They are cleared on exit, but live in RAM during the session. Clearing them mid-session would re-layout text every frame; we accept the session-resident copy and clear it on shutdown.
- **Process crash / `SIGKILL`.** `on_exit` and `Drop` implementations do not run if the process is killed forcibly or panics with `panic = "abort"`. In those cases secrets may remain in RAM until the OS reclaims the pages. The reliable way to guarantee a clean memory state is to run on an amnesic OS such as Tails, which wipes all RAM at shutdown regardless of how the application exits.

### KDF iteration default

The SLIP-0039 key derivation function (KDF) iteration exponent defaults to **1**, matching the Trezor hardware wallet. This means 20,000 total PBKDF2-HMAC-SHA256 iterations (5,000 per Feistel round × 4 rounds), providing meaningful key-stretching against brute-force password attacks.

The iteration exponent does **not** affect the security of the secret sharing itself. The SLIP-0039 secret sharing is information-theoretically secure: an attacker with fewer than the threshold number of shares learns absolutely nothing about the secret, regardless of the iteration exponent. The exponent only provides defence-in-depth against the specific scenario where an attacker obtains enough shares AND attempts to brute-force a weak password.

Note: we found and fixed a pre-existing bug in the upstream `sssmc39` crate where the `iteration_exponent` parameter was never written to the `proto_share` used as a template for member shares. This caused shares to always encode `e=0` regardless of the requested exponent, making the decryption use different PBKDF2 iterations than the encryption. The upstream tests never caught this because they all use `e=0`.

### Wallet generation

The `gen --monero` command generates fresh Monero wallets using `OsRng`. The raw 32 bytes are passed through `Scalar::from_bytes_mod_order` (from `curve25519-dalek`) to produce a valid ed25519 scalar — standard Monero key derivation, nothing custom.

### Compiler hardening

The release profile enables:

- `overflow-checks = true` — integer overflow panics instead of wrapping, even in release builds
- `opt-level = 2` — standard optimisation (higher levels can sometimes optimise away zeroisation; level 2 is the safe default)
- `strip = "symbols"` — removes debug symbols from the binary

### SLIP-0039 format version (ext flag)

Pellitory-39 supports both SLIP-0039 format versions. The default is `ext=0`
(the original format); pass `--extendable` to `gen`/`split` to create `ext=1`
shares. The spec repurposes the highest bit of the 5-bit iteration-exponent
field as a 1-bit extendable backup flag, reducing the exponent to 4 bits.

When `ext=0` (default): the share's random identifier is included in the
PBKDF2 encryption salt, and the RS-1024 checksum uses the customisation
string `"shamir"`. When `ext=1` (`--extendable`): the identifier is
excluded from the salt (allowing multiple share sets with different
identifiers to decrypt to the same master secret), and the checksum uses
`"shamir_extendable"`.

`ext=0` is universally compatible — the spec explicitly requires all
implementations to support `ext=0` for backwards compatibility. `ext=1`
shares interoperate with Trezor firmware 2.7.2+ and other ext=1 tools.
The two formats are not interchangeable: they differ in both the checksum
and the encryption salt, so `combine` rejects mixed-format share sets.

On decode, the ext bit is read from bit 4 of the 5-bit field *before*
RS-1024 verification (since the customisation string depends on it), and
the exponent is masked to 4 bits. This means a crafted share can no longer
trigger the HIGH-1 panic/DoS via a high 5-bit exponent value — the exponent
is always 0..=15 regardless of the raw field.

### age encryption (encrypted share export)

Every share that leaves Pellitory-39 via a file is encrypted with
[age](https://age-encryption.org) before it is written to disk. This is a
transport-layer encryption on top of SLIP-0039 — SLIP-0039's own password
(set at split time) is still required for combine.

- **Three recipient types:** scrypt passphrase, X25519 (`age1...`), and
  SSH (Ed25519/RSA). No PGP. Per-share mixed methods are supported (each
  share in a ZIP can use a different recipient type).
- **ASCII armour:** all exports are age ASCII-armoured
  (`-----BEGIN AGE ENCRYPTED FILE-----`), so every share is text-safe and
  self-describing on disk. The recover path auto-detects armour on paste
  or file load via a cheap prefix check (`is_age_armored`).
- **In-memory ZIP:** the ZIP container is built entirely in memory
  (`Cursor<Vec<u8>>`) and written to disk only after all shares are
  encrypted. No plaintext share ever touches disk. The sole in-memory
  plaintext exception is stdout JSON (no `--out`), documented as
  "in-memory only, never to disk."
- **Passphrase round-trip test:** before any passphrase-encrypted file is
  written, `passphrase_roundtrip_check` encrypts a known test vector with
  the passphrase, decrypts it, and verifies the plaintext matches. This is
  a pipeline sanity check that catches age encrypt/decrypt breakage before
  a file is written. It does not catch a passphrase typed identically wrong
  in both fields — that is the confirm field's job.
- **Authenticated decryption:** age authenticates. A wrong passphrase or a
  mismatched identity produces age's `DecryptError` — a genuine hard error,
  not silent garbage. This contrasts with SLIP-0039, where a wrong password
  yields a plausible but wrong secret. The trade-off: losing an age key
  permanently destroys that share even with the correct SLIP-0039 password.
- **All `age` API surface confined to `src/encrypt.rs`;** all `zip` API
  surface confined to `src/export.rs`. This keeps `#![forbid(unsafe_code)]`
  in `src/lib.rs` clean and makes the audited crypto boundary a single file.
  The GUI never imports `age` directly — it goes through `src/gui_support.rs`
  wrappers.

### Audited cryptographic dependencies

| Operation | Crate | Notes |
|-----------|-------|-------|
| Ed25519 curve operations | `curve25519-dalek` | Monero key derivation |
| Keccak-256 hashing | `tiny-keccak` (vendored, `#![forbid(unsafe_code)]`) | Monero uses Keccak, not SHA-3; sponge wiped on drop |
| SLIP-0039 secret sharing | `sssmc39` | Hardened local fork with `zeroize` on all intermediates |
| BIP-39 mnemonics | `tiny-bip39` | Bitcoin/Ethereum seed encoding |
| PBKDF2 key derivation | `ring` | Used inside sssmc39 for SLIP-0039 encryption |
| Share file encryption | `age` (scrypt, X25519, SSH) | ASCII-armoured; all API surface in `src/encrypt.rs`; credentials wrapped in `Zeroizing` (residual risk 7) |
| Share file packaging | `zip` (deflate only) | Unencrypted container; contents age-armoured; all API surface in `src/export.rs` (residual risk 9) |
| Memory zeroisation | `zeroize` | Wipe secrets on drop |
| Secret wrapping | `secrecy` | Block Debug/Display of secrets |

No hand-rolled cryptography is used anywhere in the codebase.

## Recommended: use an air-gapped machine

Despite all the hardening above, **no software can fully protect secrets on a compromised machine**. If your computer has a keylogger, malware, or a compromised operating system, no amount of memory zeroisation will help.

For high-value wallets, we strongly recommend running Pellitory-39 on an **air-gapped machine** — a computer that has never been and will never be connected to the internet.

### Using Tails OS

[Tails](https://tails.net) is an excellent choice for this. It's a portable Linux distribution that:

- Boots from a USB stick
- Routes nothing over the network by default (you can disconnect entirely)
- Is **amnesic** — all RAM is wiped on shutdown, leaving no trace
- Runs entirely in RAM, so nothing touches the hard drive

**Workflow for Tails:**

1. Build Pellitory-39 on a trusted, internet-connected machine (see install instructions in README)
2. Copy the compiled binary (`target/release/pellitory-39`) to a USB stick
3. Boot Tails on the air-gapped machine (with networking disabled)
4. Mount the USB stick and run the binary
5. Write your shares on paper
6. Shut down Tails — all RAM is automatically wiped

This gives you the strongest possible guarantee: secrets only ever exist in RAM on a machine that has no network connection, and that RAM is zeroed on shutdown.

### Other air-gapped options

Any live Linux distribution works. The key requirements are:

- **No network connection** during use
- **RAM-only operation** (no swap, no disc writes)
- **Power off when done** to clear RAM

## Duress / plausible deniability (`decoy` / `--identifier`)

Pellitory-39 provides two ways to create a Decoy Wallet whose shares are indistinguishable from an existing Real Wallet's shares, so an attacker cannot distinguish Real shares from Decoy shares by inspection:

- **`pellitory-39 decoy` (recommended)** — give it one or more Real shares as a metadata reference and it auto-derives the Real wallet's identifier, iteration exponent, and full group structure.
- **`--identifier <N>` on `gen` / `split`** — manually force the 15-bit identifier; you must match the iteration exponent and group structure yourself.

This is a **metadata-matching** feature, not a cryptographic one.

- **No weakening of encryption.** The identifier is a public PBKDF2 salt. Forcing it to a known value does not reduce brute-force cost — security still rests on the password and the information-theoretic Shamir threshold.
- **No cross-wallet leakage.** Real and Decoy wallets use independent master secrets and independent passwords. Matching the identifier matches only the prefix; the Shamir share values are unrelated, and mixing Real and Decoy shares cannot recover either secret.
- **Operational discipline required.** Because the shares are now visually indistinguishable, you must label and track them yourself. The tool cannot tell a Real share from a Decoy share.
- **Structure must match.** For full indistinguishability, both wallets must use the same `--iterations`, `--group`, and `--required-groups`. The `decoy` command enforces this automatically by deriving the structure from the reference shares; with `--identifier` you must do it manually.
- **Encrypted exports: method matching (7a).** Matching the SLIP-0039 identifier is necessary but **not sufficient** for plausible deniability when shares are encrypted with age. Age armour stanza headers reveal the recipient type (`-> scrypt` / `-> X25519` / `-> ssh-ed25519` / `-> ssh-rsa`), so Real and Decoy must also use **matching encryption methods in matching share positions**. Different methods produce distinguishable armour and break deniability. This is your responsibility, like labelling shares. The CLI prints a duress notice on every `generate --decoy` run that uses encryption; the GUI shows an amber warning card in the decoy save popup.

## Wrong password → plausible-deniability output (not an error)

SLIP-0039's integrity digest (the `digest_index` share) is computed over the
**encrypted** master secret — the quantity that the Shamir shares reconstruct —
*not* over the decrypted master secret. As a result, **`combine` cannot verify
the password**: a wrong passphrase feeds wrong PBKDF2 output into the Feistel
decryption and produces a well-formed but *different* master secret, returned
with no error (exit code 0). This is true at **every** threshold, including
2-of-3 and above — the digest catches corrupted or mismatched shares, not a
mistyped passphrase.

This is inherent to SLIP-0039 (it affects Trezor and every conforming
implementation), and it cuts both ways:

- **As a feature — plausible deniability.** Under duress you can hand over
  your shares and a *wrong* password; `combine --monero` will dutifully emit a
  syntactically valid Monero wallet (a real 95-char mainnet address starting
  with `4`, plausible spend/view keys, and a 25-word mnemonic) that has no
  relation to your real wallet. There is no way for the attacker to tell it is
  not the real one without independently knowing the address. This complements
  the `decoy` command above: the Decoy Wallet gives you a *prepared* wrong
  wallet with a password you can surrender; a wrong password gives you an
  *improvised* wrong wallet on the spot.
- **As a footgun — verify your address.** If you mistype your password during
  a genuine recovery, the tool will report success and display a
  plausible-looking but wrong wallet. You could be fooled into treating the
  garbage wallet as real (e.g. sending funds to the wrong address, or
  discarding shares believing the recovery "succeeded"). **Always compare the
  recovered address against the one you recorded when generating the wallet.**
  The `gen`/`split` commands display the address for exactly this reason.

The GUI surfaces a reminder banner on every successful recovery; the CLI
prints the recovered address/keys so you can cross-check. The GUI's Recover
tab additionally requires the password to be typed twice (a confirm field,
mirroring the Generate and Split tabs): because SLIP-0039 cannot reject a
wrong password, the only defence against a typo is to catch it before the
combine runs, and the confirm field does exactly that. There is no way to
make SLIP-0039 itself reject a wrong password without weakening the
plausible-deniability property above.

## Constant-time considerations

The GF(256) Lagrange interpolation (in `sssmc39/src/field/`) and the Feistel
round function are **not constant-time**: the field arithmetic uses
variable-time table lookups and conditional branches, and PBKDF2 output
depends on the (attacker-visible) iteration exponent. This is acceptable for
the intended deployment model — an **offline, air-gapped** tool where a
timing side channel requires physical proximity to the machine or a
compromised OS, both of which already defeat any software defence (see
“What Pellitory-39 does NOT protect against” above).

If Pellitory-39 were ever used **interactively on a networked machine**, a
timing attacker who can measure combine latency could in principle learn
information about the share values. This is explicitly **out of scope** for
the current design. Do not run combine/split on a networked machine for
high-value operations; use an air-gapped machine as recommended above.

## What Pellitory-39 does NOT protect against

- **A compromised machine.** Keyloggers, malware, compromised kernels. Use an air-gapped device.
- **Shoulder surfing.** Shares are printed to stdout. Distribute them in private.
- **Weak passwords.** The SLIP-0039 password is used to encrypt shares. Use a strong, unique passphrase. A wrong password is never rejected (see "Wrong password → plausible-deniability output" above) — verify the recovered address against your records. The GUI's Recover tab requires the password to be typed twice (a confirm field) so a typo is caught before the combine runs; the CLI has no such guard, so take extra care.
- **Swap and hibernation.** If your OS swaps memory to disc, secrets could persist. Disable swap or use encrypted swap on the machine you use for key management.
- **Cold-boot attacks.** RAM contents can persist for seconds after power-off, especially at low temperatures. Tails mitigates this by overwriting RAM on shutdown.

## Security audit status

Pellitory-39 has not undergone a formal security audit. The cryptographic primitives are delegated to audited crates, and the SLIP-0039 core has been hardened with `zeroize`, but the integration code has been reviewed informally only. If you are protecting significant funds, please review the source code yourself or commission an audit.

## Reporting vulnerabilities

If you find a security issue, please report it privately via [GitHub](https://github.com/curious-liberal/pellitory-39) rather than opening a public issue.
