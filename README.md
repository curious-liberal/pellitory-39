# Pellitory-39

Secure backup and recovery for cryptocurrency wallets using [SLIP-0039](https://github.com/satoshilabs/slips/blob/master/slip-0039.md) secret sharing.

*Named after Pellitory-of-the-wall — a wind-pollinated plant that spreads its seed far and wide. Like the plant, this tool lets you scatter your secret across multiple locations, safe in the knowledge that any threshold subset can regrow the whole.*

## What is this?

Pellitory-39 takes your wallet seed — be it a **Bitcoin** 24-word recovery phrase, a **Monero** spend key, or any other hex-encoded secret — and splits it into **threshold-recoverable SLIP-0039 shares**.

A **2-of-3 split**, for example, gives you three shares where:

- Any **2 shares** can recover the full secret
- Any **1 share** on its own reveals absolutely nothing
- **Losing 1 share** doesn't destroy the key — you still have two

It also includes built-in **Monero key derivation**, so you can generate a fresh Monero wallet or verify your wallet address without needing a full wallet binary.

## Background

This project was born from two observations:

1. **There was no good tool for splitting Monero keys.** The SLIP-0039 ecosystem grew up around Bitcoin and BIP-39 mnemonics, leaving Monero users without a straightforward way to split their spend keys into recoverable shares. The original [spendkey](https://github.com/moneroexamples/spendkey) C++ tool could derive Monero keys from a spend key, and [slip39-rust](https://github.com/Internet-of-People/slip39-rust) could split BIP-39 seeds, but nothing combined the two workflows or handled Monero's 25-word mnemonics natively and the C++ tool didn't compile easily due to being over 10 years out of date.

2. **The existing Python implementations for SLIP-0039 don't handle secrets securely.** Python's garbage collector decides when to free memory, and when it does, it doesn't zero the contents — your private keys can linger in RAM long after the programme has finished. There's no equivalent of Rust's `Zeroize` or `SecretBox`; no way to guarantee that a `str` holding your spend key gets scrubbed from the heap. If your machine is compromised, a memory dump could expose secrets that a careful Rust programme would have already destroyed.

Pellitory-39 solves both problems. It's a single Rust binary that:

- Accepts Monero 25-word mnemonics, Bitcoin/Ethereum BIP-39 seed phrases, or raw hex
- Generates fresh Monero wallets with immediate splitting
- Splits secrets into SLIP-0039 shares
- Recovers the original secret and (optionally) derives the full Monero key set
- Derives a BIP-39 seed phrase from raw hex entropy, or full Monero keys from a spend key
- **Zeroises secret material from RAM on drop** — passwords, keys, intermediate buffers, the lot

## Install

Pellitory-39 is built from source using the Rust toolchain. If you already have `cargo` on your PATH, skip to [Building](#building).

### Installing Rust

#### Linux/ MacOS

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
```

Follow the prompts (the defaults are fine). When it finishes, either restart your terminal or run:

```sh
source "$HOME/.cargo/env"
```

Verify it worked:

```sh
cargo --version
```

#### Windows

If you're running Windows then please ask yourself why. Note this hasn't tested this on Windows and it's likely nobody really intend to. In fact if you're using Windows this is all pointless, you might as well publish your private key on Twitter! \*For legal reasons I've made up but are probably true it should be noted that it's not wise to publish any sensitive information to Twitter.

1. **Install Visual Studio Build Tools.** Rust on Windows needs the MSVC C++ toolchain. Download [Build Tools for Visual Studio](https://visualstudio.microsoft.com/visual-cpp-build-tools/) and install the **"Desktop development with C++"** workload. If you already have Visual Studio installed with C++ support, you can skip this step.

2. **Install Rust.** Download and run the installer from [rustup.rs](https://rustup.rs), or if you have `winget`:

```powershell
winget install Rustlang.Rustup
```

3. **Restart your terminal** (Command Prompt, PowerShell, or Windows Terminal) so the PATH changes take effect. Verify with:

```powershell
cargo --version
```

### Building

```sh
git clone https://github.com/curious-liberal/pellitory-39.git
cd pellitory-39
```

There are three build configurations, depending on how you want to use Pellitory-39:

#### 1. GUI-first (recommended for most users)

Builds a binary that opens the desktop GUI when run with no arguments. The GUI covers the common cases — generating a duress-compatible Real + Decoy wallet pair, splitting an existing secret, recovering from shares, and deriving keys.

```sh
cargo install --path . --features gui-default
```

Now `pellitory-39` (no arguments) opens the GUI. Explicit CLI subcommands (`generate`, `split`, `recover`, …) still work, so you get both interfaces in one binary.

#### 2. GUI with explicit `--gui` flag

Same as above, but running `pellitory-39` with no arguments prints `--help` instead of opening the GUI. Useful if you want the GUI available but prefer CLI by default.

```sh
cargo install --path . --features gui
pellitory-39 --gui
```

#### 3. CLI-only

The default build — no GUI dependencies, smaller binary, for headless servers or automation.

```sh
cargo install --path .
```

**Alternatively**, to build without installing system-wide (any of the above):

```sh
cargo build --release --features gui-default   # or --features gui, or nothing
./target/release/pellitory-39 --help
```

### Air-gapped machines (Tails OS)

For high-value wallets, we recommend running Pellitory-39 on an air-gapped machine. The simplest way is with [Tails OS](https://tails.net):

1. **Build on a trusted, internet-connected machine** using the steps above
2. **Copy the binary** (`target/release/pellitory-39`) to a USB stick
3. **Boot Tails** on the air-gapped machine with networking disabled
4. **Run the binary** from the USB stick — no Rust installation needed on Tails
5. **Write your shares on paper**
6. **Shut down Tails** — all RAM is automatically wiped

See [SECURITY.md](./SECURITY.md) for a full discussion of the threat model.

## Quick start

**Easiest:** build with `--features gui-default` and run `pellitory-39` (no arguments) to open the desktop GUI. The GUI walks you through generating a wallet, splitting it into shares, and recovering from shares — no command-line knowledge required.

**CLI:** the full command reference, including every option and worked examples, is built into the binary:

```sh
pellitory-39 --help                  # top-level help and command list
pellitory-39 generate --help         # help for a specific command
pellitory-39 recover --help
```

Every command takes a `--coin`/`-c` flag (`bitcoin`/`btc`, `monero`/`xmr`, `hex`) that selects how input is interpreted and how output is formatted — the same coin tabs the GUI exposes. The CLI exposes the full feature set, including options not surfaced in the GUI: multi-group splits, custom identifiers, `--extendable` (ext=1) shares, `inspect`, `decoy`, `--decoy` (Real + Decoy pairs), `--no-password`, stdin input, and environment variables for automation.

### Shell completion

`pellitory-39` can generate tab-completion scripts for bash, zsh, fish, elvish, and PowerShell from the `completions` subcommand. Redirect the output into the right location for your shell, then start a new shell (or `source` it for bash/zsh):

```sh
# Bash (user-only, no sudo):
mkdir -p ~/.local/share/bash-completion/completions
pellitory-39 completions bash > ~/.local/share/bash-completion/completions/pellitory-39

# Zsh (make sure ~/.zsh/completions is on your $fpath):
mkdir -p ~/.zsh/completions
pellitory-39 completions zsh > ~/.zsh/completions/_pellitory-39

# Fish:
pellitory-39 completions fish > ~/.config/fish/completions/pellitory-39.fish

# PowerShell (append to your $PROFILE):
pellitory-39 completions powershell >> $PROFILE

# Elvish:
pellitory-39 completions elvish > ~/.config/elvish/lib/pellitory-39.elv
```

After installing, tab-completion works for every subcommand, option, and the `--coin` value's accepted names. Run `pellitory-39 completions --help` for the full list of supported shells.

## Supported input formats

| Input | Word count | Example |
|-------|-----------|---------|
| **Hex secret** | 1 (even hex digits) | `af6082af29108abd...` |
| **Monero mnemonic** | 25 words | `abbey acrobat ability ...` |
| **BIP-39 mnemonic** | 12, 15, 18, 21, or 24 words | `abandon ability able ...` |

All formats are **auto-detected** — you don't need to tell Pellitory-39 which type you're entering.

## KDF iterations

The `--iterations` flag controls the SLIP-0039 key derivation function (KDF) strength. This determines how much work is required to brute-force the password if an attacker obtains enough shares.

| Value | PBKDF2 total | Use case |
|-------|-------------|----------|
| 0 | 10,000 | Faster, still secure with strong passwords |
| **1** | **20,000** | **Default — matches Trezor** |
| 2 | 40,000 | High-value cold storage |

The iteration exponent does **not** affect the security of the secret sharing itself — that is information-theoretically secure regardless. It only affects the PBKDF2 password stretching applied before splitting. With a strong password, brute-force is infeasible at any exponent.

## Duress & plausible deniability

Pellitory-39 supports a **Real Wallet / Decoy Wallet** setup for duress scenarios (e.g. a "$5 wrench attack"). The goal: if you are forced to surrender shares, you hand over Decoy shares, and an attacker cannot tell them apart from Real shares just by looking at them.

### The problem

Every SLIP-0039 share begins with two words that encode the secret's **identifier** (15 bits) and **iteration exponent** (5 bits). Because the identifier is normally random, a Real Wallet and a Decoy Wallet — generated separately — get different identifiers, so their first two words differ. An attacker comparing a Real share and a Decoy share would instantly see they belong to two different secrets, breaking the deniability and putting you at greater risk.

### The solution

There are two ways to make a Decoy Wallet's shares indistinguishable from a Real Wallet's:

1. **`pellitory-39 generate --decoy` (recommended).** Generate a Real + Decoy pair in one step — the decoy inherits the Real wallet's identifier, iteration exponent, and group structure automatically. For a decoy matching an *existing* wallet's shares, use `pellitory-39 decoy --coin <COIN>` with one or more Real shares as a reference. Run `pellitory-39 generate --help` or `pellitory-39 decoy --help` for usage.

2. **`--identifier <N>` on `generate` / `split` (manual).** Force the 15-bit identifier to a specific value (0–32767). You must manually match the Real wallet's identifier, `--iterations`, and group structure yourself.

In both cases the first two words of every share will match across both wallets, and the `Group Threshold` and `Group Index` (encoded in word 3) will also match, so the metadata prefix is indistinguishable. The GUI's Generate tab produces a Real + Decoy pair in one step; the CLI mirrors this with `generate --decoy`.

### Important caveats

- **Keep the structure identical.** The group threshold, group count, and member threshold are also visible in the share metadata (word 3 onward). `generate --decoy` and `decoy` handle this for you; with `--identifier` you must use the same `--group` / `--required-groups` / `--iterations` manually.
- **Different passwords, different secrets.** The Real and Decoy wallets remain cryptographically independent: different master secrets, different PBKDF2 passwords. Matching the identifier only matches the *prefix*; the share values (the actual Shamir fragments) are unrelated.
- **The identifier is not secret.** It is a public salt. Forcing it to a known value does not weaken the encryption — security rests on the password and the information-theoretic threshold, exactly as before.
- **Don't mix shares.** Real and Decoy shares have the same prefix, so you must label them yourself. Combining a mix of Real and Decoy shares will simply fail the digest check (or in a very unlikely scenario, recover the wrong this), never the Real secret.
- **Label your shares.** Because the shares are now visually indistinguishable, the tool cannot tell a Real share from a Decoy share. Keep your own records.

### Wrong-password deniability

SLIP-0039 cannot verify the password — a wrong passphrase produces a well-formed but *different* master secret with no error. This cuts both ways:

- **As a feature:** under duress you can hand over your shares and a *wrong* password; `recover --coin monero` will emit a syntactically valid but unrelated Monero wallet. This complements the Decoy Wallet: the Decoy gives you a *prepared* wrong wallet with a password you can surrender; a wrong password gives you an *improvised* wrong wallet on the spot.
- **As a footgun that will ruin everything:** if you mistype your password during a genuine recovery, the tool will report success and display a plausible-looking but wrong wallet. **Always compare the recovered address against the one you recorded when generating the wallet.** The `generate`/`split` commands display the address for exactly this reason, the GUI surfaces a reminder banner on every recovery, and the GUI's Recover tab requires you to type the password twice (a confirm field, mirroring Generate / Split) so a single typo cannot silently send you to the wrong wallet. Imagine sending all your funds to the wrong wallet!! That would be a disaster, so please don't do that!

## Encrypted share export

Pellitory-39 supports exporting your shares in an encrypted format. It uses [age](https://age-encryption.org) to do this and exports as armoured files. Note that SLIP-0039 itself is not replaced; age protects each share on disk, while SLIP-0039's own password (set at split time) is still required for combine. No plaintext share is ever written to disk without your explicit permission and instruction.

### Recipients

Three recipient types are supported, matching the age spec:

- **Passphrase** (age scrypt) — encrypt with a passphrase, decrypt with the
  same passphrase. The simplest option; no key management.
- **X25519** (`age1...`) — encrypt to an age public key. Use upstream
  `age-keygen` to generate a keypair (Pellitory-39 does not generate age
  keys):
  ```sh
  age-keygen -o key.txt   # produces AGE-SECRET-KEY-1... (identity) + age1... (recipient)
  ```
  Pellitory consumes the recipient string (`age1...`) for encryption and the
  identity file for decryption.
- **SSH** (Ed25519/RSA) — encrypt to an SSH public key. Use your existing
  `~/.ssh/id_ed25519.pub` (recipient) and `~/.ssh/id_ed25519` (identity).

### CLI examples

```sh
# Bulk passphrase ZIP (all shares, same passphrase):
pellitory-39 split --coin hex --group 2of3 \
  --encrypt-passphrase -p slip-pass \
  --out shares.zip

# Per-share mixed methods (share 1 = age recipient, share 2 = passphrase file):
pellitory-39 split --coin hex --group 2of3 \
  --encrypt-to age1... --encrypt-to age1... \
  --encrypt-passphrase-file pass2.txt \
  --out shares.zip

# One-file armoured blob (single credential, all shares concatenated):
pellitory-39 split --coin hex --group 2of3 \
  --encrypt-passphrase -p slip-pass \
  --package one-file --out shares.txt.age

# Binary-safe stdout (pipe to a file or another command):
pellitory-39 split --coin hex --group 2of3 \
  --encrypt-passphrase -p slip-pass --out - > shares.zip

# Recover from encrypted shares (auto-detected at file load):
pellitory-39 recover --coin hex \
  -m @share1.txt.age -m @share2.txt.age \
  --decrypt-passphrase -p slip-pass

# Recover with an age identity file:
pellitory-39 recover --coin hex \
  -m @share1.txt.age -m @share2.txt.age \
  --decrypt-identity key.txt

# Recover with an SSH private key:
pellitory-39 recover --coin hex \
  -m @share1.txt.age -m @share2.txt.age \
  --decrypt-identity ~/.ssh/id_ed25519
```

### GUI

The GUI exposes the same encrypt/decrypt pipeline through popups:

- **Per-share Save** — each share card has a Save button that writes a
  single `.age` file (age-armoured).
- **Bulk Save ZIP** — the Generate and Split tabs offer a bulk "Save ZIP"
  button that writes `share1.txt.age`, `share2.txt.age`, ... + `README.txt`
  into one ZIP.
- **Recover decrypt-in-place** — the Recover tab auto-detects age armour
  on paste or file load and prompts for the decryption credential before
  SLIP-0039 combine.
- **Recover confirm-password** — the Recover tab asks for the SLIP-0039
  password twice (a confirm field, like Generate and Split). A mistyped
  recovery password yields a valid-looking but *wrong* wallet with no
  error from SLIP-0039; the confirm field catches the typo *before* the
  combine runs, so you cannot accidentally fund the wrong wallet because
  your fingers slipped.

### ZIP is a container, not encryption

The ZIP container itself is **unencrypted**. Each share's *content* is
age-armoured, but a found ZIP reveals the share count and each entry's age
armour stanza type (`-> scrypt` / `-> X25519` / `-> ssh-ed25519` /
`-> ssh-rsa`). This is a metadata leak, not a secret leak — the share
values remain encrypted.

### Duress caveat

Age armour stanza headers reveal the recipient type. For Real and Decoy
shares to be indistinguishable, you must use **matching encryption methods
in matching share positions** for both wallets. Different methods produce
distinguishable armour and break plausible deniability. This is your
responsibility, like labelling shares. The CLI prints a duress notice on
every `generate --decoy` run that uses encryption; the GUI shows an amber
warning card in the decoy save popup.


## How it works

```
                         ┌─────────────────────────┐
                         │  Your secret             │
                         │  (Monero/BTC/hex)         │
                         └────────────┬────────────┘
                                      │
              ┌───────────────────────┬┴───────────────────────┐
              ▼                       ▼                         ▼
    ┌──────────────────┐   ┌──────────────────┐     ┌──────────────────┐
    │  pellitory-39    │   │  pellitory-39    │     │  pellitory-39    │
    │  generate        │   │  split           │     │  derive          │
    │  --coin monero   │   │  --coin monero   │     │  --coin monero   │
    │ (new wallet +    │   │ (existing key)   │     │ (BTC phrase /    │
    │  split in one)   │   │                  │     │  Monero keys)    │
    └────────┬─────────┘   └────────┬─────────┘     └──────────────────┘
             │                      │
             └──────────┬───────────┘
                        ▼
               ┌──────────────────┐
               │  SLIP-0039       │
               │  shares          │
               └────────┬─────────┘
                        │
          ┌─────────────┼─────────────┐
          ▼             ▼             ▼
    ┌──────────┐  ┌──────────┐  ┌──────────┐
    │ Share 1  │  │ Share 2  │  │ Share 3  │
    │ (home)   │  │ (bank)   │  │ (family) │
    └──────────┘  └──────────┘  └──────────┘
          │             │
          └──────┬──────┘
                 ▼
       ┌──────────────────┐
       │  pellitory-39    │
       │    recover       │
       │  --coin monero   │
       │  --coin bitcoin  │
       │  --coin hex      │
       └────────┬─────────┘
                ▼
       ┌──────────────────┐
       │  Full wallet     │
       │  recovered ✓     │
       └──────────────────┘
```

## Compatibility

Pellitory-39 supports both SLIP-0039 formats. The default is the original
`ext=0` format (universally compatible). Pass `--extendable` to use the
newer `ext=1` "extendable backup" format, which excludes the identifier
from the encryption salt so multiple share sets with distinct ids recover
the same master secret for a given passphrase.

| | Pellitory-39 shares → other tools | Other tools' shares → Pellitory-39 |
|---|---|---|
| **ext=0** (original format, default) | ✅ All tools must accept | ✅ Works |
| **ext=1** (extendable backup, `--extendable`) | ✅ Trezor 2.7.2+ and other ext=1 tools | ✅ Works |

**In practice:** Shares you create with Pellitory-39 (default `ext=0`) are
universally compatible — the spec requires all implementations to support
`ext=0`. Shares from newer Trezor firmware (2.7.2+) that use `ext=1` can
be imported directly. Use `--extendable` on `generate`/`split` to create
`ext=1` shares if you need the extendable-backup property (e.g. upgrading
a 1-of-1 scheme to a multi-share scheme later while keeping the same
encrypted master secret and passphrase). `ext=0` and `ext=1` shares are
not interchangeable — they differ in both the checksum and the encryption
salt.

## Security

See [SECURITY.md](./SECURITY.md) for the full dependency audit and threat model. In brief:

- **Best effort memory zeroisation** — All secrets are wiped from RAM on drop using `zeroize`, including inside the bundled SLIP-0039 fork. \* Zeroisation is best effort. See [SECURITY.md](./SECURITY.md) for more details
- **Full dependency audit** — Every crate that touches secrets has been reviewed and hardened where needed
- **Debug blocking** — Private keys use `SecretBox`, preventing accidental logging
- **Cryptographic RNG** — `OsRng` (OS entropy) for all key generation
- **Hidden input** — Secrets, passwords, and shares are never displayed on screen
- **Recover confirm-password** — the GUI Recover tab requires the password to be typed twice, so a typo cannot silently recover (and fund) the wrong wallet
- **KDF default 1** — matches Trezor, 20,000 PBKDF2 iterations for brute-force resistance
- **Duress support** — `generate --decoy` / `decoy` command and `--identifier` flag produce shares indistinguishable from a Real Wallet's
- **Overflow checks** — Enabled even in release builds
- **No Python** — No garbage collector deciding when (or whether) to scrub your keys

**For high-value wallets, use an air-gapped machine.** No software can protect secrets on a compromised computer. See the [install instructions](#air-gapped-machines-tails-os) for a recommended Tails OS workflow.

## Acknowledgements

Pellitory-39 builds on the work of several projects. Noteably:

- [spendkey](https://github.com/moneroexamples/spendkey) — Monero key derivation from spend keys (original C++ implementation)
- [slip39-rust](https://github.com/Internet-of-People/slip39-rust) — SLIP-0039 secret sharing CLI in Rust
- [rust-sssmc39](https://github.com/yeastplume/rust-sssmc39) — SLIP-0039 core implementation (included as a hardened local fork with memory zeroisation)

## Licence and disclaimer

MIT — see [LICENSE](./LICENSE).

This software comes 'as is' and does not take any responsibility or liability of any form. It is down to you to check and audit this tool. If you do find something please get in contact discretely to ensure we can protect everyone.
