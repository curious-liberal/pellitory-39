#!/usr/bin/env bash
# End-to-end CLI tests for pellitory-39 age-encrypted share export.
#
# Drives the compiled binary through the full encrypt/export/recover
# workflow, plus a grep-based no-emoji assertion over CLI output.
#
# Requires: age, age-keygen, unzip, perl on PATH.
# Run: ./tests/e2e_encrypt.sh [path/to/binary]
#
# Exits non-zero on the first failure. Prints a summary at the end.

set -u
BIN="${1:-./target/release/pellitory-39}"

PASS=0
FAIL=0
FAILED_TESTS=()

# Colours (disabled if not a tty).
if [ -t 1 ]; then
    GREEN=$'\033[32m'; RED=$'\033[31m'; YELLOW=$'\033[33m'; RESET=$'\033[0m'
else
    GREEN=""; RED=""; YELLOW=""; RESET=""
fi

ok()   { PASS=$((PASS+1)); printf "${GREEN}  PASS${RESET}: %s\n" "$1"; }
bad()  { FAIL=$((FAIL+1)); FAILED_TESTS+=("$1"); printf "${RED}  FAIL${RESET}: %s\n" "$1"; printf "    %s\n" "$2"; }
note() { printf "${YELLOW}  ....${RESET} %s\n" "$1"; }

assert_eq() { # name expected actual
    if [ "$2" = "$3" ]; then ok "$1"; else bad "$1" "expected [$2] got [$3]"; fi
}
assert_contains() { # name haystack needle
    if printf '%s' "$2" | grep -qF "$3"; then ok "$1"; else bad "$1" "expected to contain [$3] in output"; fi
}
assert_not_contains() { # name haystack needle
    if printf '%s' "$2" | grep -qF "$3"; then bad "$1" "did NOT expect [$3] in output"; else ok "$1"; fi
}
assert_exit() { # name expected_code cmd...
    local name="$1"; local exp="$2"; shift 2
    "$@" >/tmp/p39_e2e_out 2>/tmp/p39_e2e_err; local code=$?
    if [ "$code" = "$exp" ]; then ok "$name"; else bad "$name" "expected exit $exp got $code"; cat /tmp/p39_e2e_err; fi
}

# Recovered hex is printed to stdout (label on stderr). Trim stdout to the hex line.
recovered_hex() { # combined_stdout
    printf '%s' "$1" | grep -E '^[0-9a-f]+$' | tail -1
}

# Extract a share mnemonic from JSON output (group 1, share N, 1-based).
share_mnemonic() { # json share_index(1-based)
    python3 -c "
import json,sys,re
t=sys.stdin.read()
m=list(re.finditer(r'\{.*\}', t, re.S))
d=json.loads(m[-1].group(0))
print(d['groups'][0]['shares'][$2-1]['mnemonic'])
" <<<"$1"
}

echo "=== pellitory-39 age-encrypt end-to-end CLI tests ==="
echo "Binary: $BIN"
[ -x "$BIN" ] || { echo "Binary not found / not executable"; exit 2; }

# Check required tools.
for tool in age age-keygen unzip perl python3; do
    if ! command -v "$tool" >/dev/null 2>&1; then
        echo "Missing required tool: $tool"
        exit 3
    fi
done
note "all required tools present (age, age-keygen, unzip, perl, python3)"

SPEND_KEY="af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206"
SSH_PUBKEY=$(cat tests/fixtures/test_ed25519.pub)
SSH_PRIVKEY="tests/fixtures/test_ed25519"
WORK=$(mktemp -d /tmp/p39_e2e.XXXXXX)
trap 'rm -rf "$WORK"' EXIT

# ─── 1. split --encrypt-passphrase → ZIP → recover --decrypt-passphrase ─────
echo "── 1. passphrase ZIP round-trip ──"
ZIP="$WORK/pass.zip"
OUT=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-passphrase agepass --out "$ZIP" 2>&1)
assert_contains "split passphrase ZIP exported" "$OUT" "3 entries"
unzip -o "$ZIP" -d "$WORK/pass" >/dev/null 2>&1
REC=$("$BIN" recover --coin hex \
    -m "@$WORK/pass/share1.txt.age" \
    -m "@$WORK/pass/share2.txt.age" \
    -p slip --decrypt-passphrase agepass 2>/dev/null)
assert_eq "passphrase ZIP round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 2. split --encrypt-to age1 → recover --decrypt-identity (age interop) ──
echo "── 2. X25519 recipient ZIP (age CLI interop) ──"
AGE_ID="$WORK/age_identity.txt"
age-keygen -o "$AGE_ID" 2>/dev/null
AGE_PUB=$(grep -oE 'age1[a-z0-9]+' "$AGE_ID" | head -1)
[ -n "$AGE_PUB" ] && ok "age-keygen produced identity" || bad "age-keygen" "no identity generated"
ZIP="$WORK/x25519.zip"
OUT=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-to "$AGE_PUB" --confirm-recipient --out "$ZIP" 2>&1)
assert_contains "split X25519 ZIP exported" "$OUT" "3 entries"
unzip -o "$ZIP" -d "$WORK/x25519" >/dev/null 2>&1
# age CLI interop: decrypt share1 with the age identity file.
PLAIN1=$(age -d -i "$AGE_ID" < "$WORK/x25519/share1.txt.age" 2>/dev/null)
[ -n "$PLAIN1" ] && ok "age CLI decrypts pellitory-39 share" || bad "age CLI interop" "age -d failed"
# pellitory-39 round-trip.
REC=$("$BIN" recover --coin hex \
    -m "@$WORK/x25519/share1.txt.age" \
    -m "@$WORK/x25519/share2.txt.age" \
    -p slip --decrypt-identity "$AGE_ID" 2>/dev/null)
assert_eq "X25519 ZIP round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 3. split --encrypt-to ssh-ed25519 → recover --decrypt-identity ─────────
echo "── 3. SSH recipient ZIP ──"
ZIP="$WORK/ssh.zip"
OUT=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-to "$SSH_PUBKEY" --confirm-recipient --out "$ZIP" 2>&1)
assert_contains "split SSH ZIP exported" "$OUT" "3 entries"
unzip -o "$ZIP" -d "$WORK/ssh" >/dev/null 2>&1
REC=$("$BIN" recover --coin hex \
    -m "@$WORK/ssh/share1.txt.age" \
    -m "@$WORK/ssh/share2.txt.age" \
    -p slip --decrypt-identity "$SSH_PRIVKEY" 2>/dev/null)
assert_eq "SSH ZIP round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 4. per-share mixed targets → interactive recover loop ──────────────────
echo "── 4. per-share mixed targets (interactive loop) ──"
# 3 shares. --encrypt-to targets are resolved before --encrypt-passphrase-file
# targets (see EncryptArgs::resolve), so the actual per-share mapping is:
#   share 1 = age recipient, share 2 = ssh recipient, share 3 = passphrase.
PASSFILE="$WORK/share3_pass.txt"
printf 'mixedpass' > "$PASSFILE"
ZIP="$WORK/mixed.zip"
OUT=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 3of3 \
    --encrypt-to "$AGE_PUB" \
    --encrypt-to "$SSH_PUBKEY" \
    --encrypt-passphrase-file "$PASSFILE" \
    --confirm-recipient --out "$ZIP" 2>&1)
assert_contains "split mixed ZIP exported" "$OUT" "3 entries"
unzip -o "$ZIP" -d "$WORK/mixed" >/dev/null 2>&1
# Drive the interactive loop via heredoc stdin.
# Share 1: age identity → "a\n<path>\n"
# Share 2: ssh key → "s\n<ssh_key_path>\n"
# Share 3: passphrase → "p\nmixedpass\n"
REC=$(printf 'a\n%s\ns\n%s\np\nmixedpass\n' "$AGE_ID" "$SSH_PRIVKEY" | \
    "$BIN" recover --coin hex \
        -m "@$WORK/mixed/share1.txt.age" \
        -m "@$WORK/mixed/share2.txt.age" \
        -m "@$WORK/mixed/share3.txt.age" \
        -p slip 2>/dev/null)
assert_eq "per-share mixed interactive round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 5. --package one-file --encrypt-to → age -d → recover ────────────────
echo "── 5. one-file armoured blob (X25519, age CLI decrypt) ──"
BLOB="$WORK/blob.age"
OUT=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-to "$AGE_PUB" --confirm-recipient \
    --package one-file --out "$BLOB" 2>&1)
assert_contains "split one-file exported" "$OUT" "3 entries"
# one-file produces a single concatenated armoured blob. Decrypt with age CLI
# (X25519 is non-interactive), then parse the plaintext to extract shares.
PLAIN=$(age -d -i "$AGE_ID" < "$BLOB" 2>/dev/null)
[ -n "$PLAIN" ] && ok "age CLI decrypts one-file blob" || bad "age CLI one-file decrypt" "empty output"
# Extract share mnemonics from the plaintext (lines after "# Share N").
SH1_OF=$(printf '%s\n' "$PLAIN" | awk '/^# Share 1/{getline; print}')
SH2_OF=$(printf '%s\n' "$PLAIN" | awk '/^# Share 2/{getline; print}')
[ -n "$SH1_OF" ] && [ -n "$SH2_OF" ] && ok "one-file shares extracted" || bad "one-file shares extracted" "could not parse shares"
REC=$("$BIN" recover --coin hex -m "$SH1_OF" -m "$SH2_OF" -p slip 2>/dev/null)
assert_eq "one-file blob round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 6. --out - writes binary ZIP to stdout ────────────────────────────────
echo "── 6. --out - (stdout binary ZIP) ──"
"$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-passphrase stdoutpass --out - 2>/dev/null > "$WORK/stdout.zip"
# Verify it's a valid ZIP.
if unzip -l "$WORK/stdout.zip" >/dev/null 2>&1; then
    ok "stdout ZIP is valid"
else
    bad "stdout ZIP is valid" "not a valid ZIP"
fi
unzip -o "$WORK/stdout.zip" -d "$WORK/stdout" >/dev/null 2>&1
REC=$("$BIN" recover --coin hex \
    -m "@$WORK/stdout/share1.txt.age" \
    -m "@$WORK/stdout/share2.txt.age" \
    -p slip --decrypt-passphrase stdoutpass 2>/dev/null)
assert_eq "stdout ZIP round-trip" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 7. --encrypt-* without --out errors ───────────────────────────────────
echo "── 7. encryption without --out errors ──"
assert_exit "encrypt without --out errors" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 \
    --encrypt-passphrase y 2>/dev/null

# ─── 8. per-share count mismatch errors before secret generation ───────────
echo "── 8. count mismatch fail-fast (no secret leaked) ──"
# 2of3 = 3 shares. Supply 2 --encrypt-to targets (not 1=bulk, not 3=per-share)
# to trigger the count mismatch.
ERR=$("$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 \
    --encrypt-to "$AGE_PUB" --encrypt-to "$SSH_PUBKEY" --confirm-recipient \
    --out "$WORK/should_not_exist.zip" 2>&1)
CODE=$?
if [ "$CODE" -ne 0 ]; then ok "count mismatch exits non-zero ($CODE)"; else bad "count mismatch exits non-zero" "exited 0"; fi
assert_not_contains "count mismatch leaks no wallet" "$ERR" "Private spend key"
assert_contains "count mismatch mentions method count" "$ERR" "method count"
[ ! -f "$WORK/should_not_exist.zip" ] && ok "no file written on failure" || bad "no file on failure" "ZIP was created"

# ─── 9. generate --decoy → two ZIPs + duress notice ────────────────────────
echo "── 9. generate --decoy (two ZIPs + duress notice) ──"
RZIP="$WORK/real_decoy.zip"
DZIP="$WORK/decoy_decoy.zip"
ERR=$("$BIN" generate --coin monero --decoy -p realpass --decoy-password decoypass \
    --group 2of3 \
    --encrypt-passphrase rpass --out "$RZIP" \
    --decoy-encrypt-passphrase dpass --decoy-out "$DZIP" 2>&1)
assert_contains "decoy shows duress notice" "$ERR" "Duress notice"
assert_contains "decoy notice mentions recipient type" "$ERR" "recipient type"
[ -f "$RZIP" ] && ok "real ZIP created" || bad "real ZIP created" "file missing"
[ -f "$DZIP" ] && ok "decoy ZIP created" || bad "decoy ZIP created" "file missing"
# Both round-trip.
unzip -o "$RZIP" -d "$WORK/rd" >/dev/null 2>&1
unzip -o "$DZIP" -d "$WORK/dd" >/dev/null 2>&1
REAL_ADDR=$(printf '%s' "$ERR" | grep -oE '4[0-9A-Za-z]{94}' | head -1)
DECOY_ADDR=$(printf '%s' "$ERR" | grep -oE '4[0-9A-Za-z]{94}' | tail -1)
RREC=$("$BIN" recover --coin monero \
    -m "@$WORK/rd/share1.txt.age" \
    -m "@$WORK/rd/share2.txt.age" \
    -p realpass --decrypt-passphrase rpass 2>&1 1>/dev/null)
assert_contains "decoy real ZIP round-trips to address" "$RREC" "$REAL_ADDR"
DREC=$("$BIN" recover --coin monero \
    -m "@$WORK/dd/share1.txt.age" \
    -m "@$WORK/dd/share2.txt.age" \
    -p decoypass --decrypt-passphrase dpass 2>&1 1>/dev/null)
assert_contains "decoy decoy ZIP round-trips to address" "$DREC" "$DECOY_ADDR"
if [ "$REAL_ADDR" != "$DECOY_ADDR" ]; then ok "real and decoy wallets differ"; else bad "real vs decoy" "addresses are identical"; fi

# ─── 10. wrong passphrase exits 1 (not silent garbage) ─────────────────────
echo "── 10. wrong passphrase fails ──"
ZIP="$WORK/wrongpass.zip"
"$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 \
    --encrypt-passphrase correctpass --out "$ZIP" 2>/dev/null
unzip -o "$ZIP" -d "$WORK/wrongpass" >/dev/null 2>&1
ERR=$("$BIN" recover --coin hex \
    -m "@$WORK/wrongpass/share1.txt.age" \
    -m "@$WORK/wrongpass/share2.txt.age" \
    -p slip --decrypt-passphrase wrongpass 2>&1)
CODE=$?
if [ "$CODE" -ne 0 ]; then ok "wrong passphrase exits non-zero ($CODE)"; else bad "wrong passphrase exits non-zero" "exited 0 — silent garbage!"; fi
assert_contains "wrong passphrase error mentions decrypt/share" "$ERR" "decrypt"
assert_not_contains "wrong passphrase leaks no secret" "$ERR" "$SPEND_KEY"

# ─── 11. -m @file.age loads and autodetects ───────────────────────────────
echo "── 11. -m @file.age autodetect ──"
# Split without encryption to get plain shares, then manually encrypt share 1
# with the age CLI (X25519). recover -m @share1.age (armoured) -m @share2.txt
# (plain) tests autodetect.
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p slip --group 2of3 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1)
SH2=$(share_mnemonic "$JSON" 2)
printf '%s' "$SH1" | age -e -a -r "$AGE_PUB" -o "$WORK/sh1_armoured.age" 2>/dev/null
printf '%s' "$SH2" > "$WORK/sh2_plain.txt"
REC=$("$BIN" recover --coin hex \
    -m "@$WORK/sh1_armoured.age" \
    -m "@$WORK/sh2_plain.txt" \
    -p slip --decrypt-identity "$AGE_ID" 2>/dev/null)
assert_eq "mixed @armoured + @plain autodetect" "$SPEND_KEY" "$(recovered_hex "$REC")"

# ─── 12. no-emoji assertion ────────────────────────────────────────────────
echo "── 12. no-emoji assertion ──"
# Collect all CLI text surfaces: --help for every subcommand + a representative
# error path.
ALL_TEXT=""
ALL_TEXT="$("$BIN" --help 2>&1)"
for sub in generate split decoy recover derive inspect completions; do
    ALL_TEXT="$ALL_TEXT"$'\n'"$("$BIN" "$sub" --help 2>&1 || true)"
done
# Representative error / success output (exercises eprintln paths).
ALL_TEXT="$ALL_TEXT"$'\n'"$("$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 \
    --encrypt-passphrase y --out "$WORK/emoji_check.zip" 2>&1 || true)"
ALL_TEXT="$ALL_TEXT"$'\n'"$("$BIN" recover --coin hex -m x -p x --decrypt-passphrase y 2>&1 || true)"

# Use perl for Unicode regex (portable on macOS, unlike grep -P \x{}).
# Ranges: emoji supplemental (1F000-1FAFF), misc symbols + dingbats
# (2600-27BF), arrows (2190-21FF), misc symbols arrows (2B00-2BFF).
# Box-drawing (U+2500-U+257F) is intentionally EXCLUDED — the existing
# CLI uses ── (U+2500) for section dividers and that is not emoji.
EMOJI_HITS=$(printf '%s' "$ALL_TEXT" | \
    perl -ne 'print if /[\x{1F000}-\x{1FAFF}\x{2600}-\x{27BF}\x{2190}-\x{21FF}\x{2B00}-\x{2BFF}]/')
if [ -z "$EMOJI_HITS" ]; then
    ok "no emoji codepoints in CLI output"
else
    bad "no-emoji" "found emoji codepoints:"
    printf '%s\n' "$EMOJI_HITS" | head -5 | sed 's/^/      /'
fi

# ─── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do echo "  - $t"; done
    exit 1
fi
