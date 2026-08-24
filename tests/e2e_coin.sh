#!/usr/bin/env bash
# End-to-end CLI tests for the pellitory-39 --coin redesign.
#
# Drives the compiled binary through every redesigned workflow:
#   generate (gen), split, recover (combine), derive, inspect, decoy
# using the new --coin/-c flag (bitcoin/btc, monero/xmr, hex).
#
# Run: ./tests/e2e_coin.sh [path/to/binary]
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
    "$@" >/tmp/p39_out 2>/tmp/p39_err; local code=$?
    if [ "$code" = "$exp" ]; then ok "$name"; else bad "$name" "expected exit $exp got $code"; cat /tmp/p39_err; fi
}

# Extract the JSON object from possibly-mixed stdout (generate/decoy print a
# human-readable key block to stderr, JSON to stdout). Find the last {...}.
_extract_json() { python3 -c "import sys,re; t=sys.stdin.read(); m=list(re.finditer(r'\{.*\}', t, re.S)); print(m[-1].group(0) if m else '')"; }

# Extract the Nth share's mnemonic from a JSON output (group g, share s, 1-based).
share_mnemonic() { # json group_index(1-based) share_index(1-based)
    python3 -c "
import json,sys,re
t=sys.stdin.read()
m=list(re.finditer(r'\{.*\}', t, re.S))
d=json.loads(m[-1].group(0))
print(d['groups'][$2-1]['shares'][$3-1]['mnemonic'])
" <<<"$1"
}
group_count()    { _extract_json <<<"$1" | python3 -c "import json,sys;print(json.load(sys.stdin)['group_count'])"; }
group_threshold(){ _extract_json <<<"$1" | python3 -c "import json,sys;print(json.load(sys.stdin)['group_threshold'])"; }

# Recovered hex is printed to stdout (label on stderr). Trim stdout to the hex line.
recovered_hex() { # combined_stdout
    printf '%s' "$1" | grep -E '^[0-9a-f]+$' | tail -1
}

echo "=== pellitory-39 --coin end-to-end CLI tests ==="
echo "Binary: $BIN"
[ -x "$BIN" ] || { echo "Binary not found / not executable"; exit 2; }

# Known Monero reference vector (verified against independent implementation).
SPEND_KEY="af6082af29108abda69cc385dfed2102b892a871695367cb22a4b9b6df8b3206"
EXPECTED_ADDR="46HSxE7KoiDaxWFWR1wmJfcrunNj4TLiPJqiCJkQn345A4JJzgBNhUvbkrYWJX4EVJZS4kJGfGj7CTW8GEUHsbEZCEupMt6"
EXPECTED_MNEMONIC="spout midst duckling tepid odds glass enhanced avatar ocean rarest eavesdrop egotistic oxygen trying future airport session nanny tedious guru asylum superior cement cunning eavesdrop"

# ─── derive: --coin monero (hex spend key → full key set) ────────────────────
echo "── derive --coin monero (hex spend key) ──"
OUT=$("$BIN" derive --coin monero -s "$SPEND_KEY" 2>&1 1>/dev/null)
assert_contains "derive monero shows expected address" "$OUT" "$EXPECTED_ADDR"
assert_contains "derive monero shows expected mnemonic" "$OUT" "${EXPECTED_MNEMONIC%% *}"
assert_contains "derive monero shows private view key" "$OUT" "157874dc4e2961c872f87aaf4346146d0f596e2f116a51fbac01b693a8e3020a"
assert_contains "derive monero shows public spend key" "$OUT" "7aff30fbdc005ecb03f57a11e250e0d665621ffde1d44c6aa84a8212cc0d1236"
assert_contains "derive monero shows public view key"  "$OUT" "25c1b6920540fbcfcb0e36bd2c88f5c1e62e5ef1d621279e7230b47648e64a63"

# ─── derive: --coin monero (25-word mnemonic → full key set) ─────────────────
echo "── derive --coin monero (25-word mnemonic) ──"
OUT=$("$BIN" derive --coin monero -m "$EXPECTED_MNEMONIC" 2>&1 1>/dev/null)
assert_contains "derive monero from mnemonic matches address" "$OUT" "$EXPECTED_ADDR"
assert_contains "derive monero from mnemonic shows spend key" "$OUT" "$SPEND_KEY"

# ─── derive: --coin monero (stdin pipe) ──────────────────────────────────────
echo "── derive --coin monero (stdin pipe) ──"
OUT=$(printf '%s' "$SPEND_KEY" | "$BIN" derive --coin monero -s - 2>&1 1>/dev/null)
assert_contains "derive monero via stdin matches address" "$OUT" "$EXPECTED_ADDR"

# ─── derive: --coin monero (invalid input errors cleanly) ───────────────────
echo "── derive --coin monero (invalid input) ──"
assert_exit "derive monero rejects 63-char hex" 1 "$BIN" derive --coin monero -s "${SPEND_KEY%?}" 2>/dev/null
assert_exit "derive monero rejects non-hex" 1 "$BIN" derive --coin monero -s "not-a-hex-key-but-64-chars-long-zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz" 2>/dev/null

# ─── derive: --coin bitcoin (raw hex entropy → BIP-39 phrase) ────────────────
echo "── derive --coin bitcoin (hex entropy) ──"
ZERO16="00000000000000000000000000000000"
OUT=$("$BIN" derive --coin bitcoin -s "$ZERO16" 2>/dev/null)
assert_eq "derive bitcoin 16-byte all-zero phrase" \
    "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "$OUT"
ENT32="abababababababababababababababababababababababababababababababab"
OUT=$("$BIN" derive --coin bitcoin -s "$ENT32" 2>/dev/null)
NW=$(printf '%s' "$OUT" | wc -w | tr -d ' ')
assert_eq "derive bitcoin 32-byte yields 24 words" "24" "$NW"
assert_exit "derive bitcoin rejects odd hex" 1 "$BIN" derive --coin bitcoin -s "abc" 2>/dev/null
assert_exit "derive bitcoin rejects too-short entropy" 1 "$BIN" derive --coin bitcoin -s "0011" 2>/dev/null
assert_exit "derive bitcoin rejects too-long entropy" 1 "$BIN" derive --coin bitcoin -s "$(printf '00%.0s' {1..66})" 2>/dev/null

# ─── derive: --coin required, hex invalid for derive ─────────────────────────
echo "── derive --coin required ──"
assert_exit "derive without --coin errors" 2 "$BIN" derive -s "$SPEND_KEY" 2>/dev/null
assert_exit "derive with --coin hex errors" 2 "$BIN" derive --coin hex -s "$SPEND_KEY" 2>/dev/null

# ─── split → recover round-trip (hex, 2-of-3) ────────────────────────────────
echo "── split → recover (hex 2-of-3) ──"
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p testpass --group 2of3 2>/dev/null)
[ -n "$JSON" ] && ok "split hex produced JSON" || bad "split hex produced JSON" "empty output"
SH1=$(share_mnemonic "$JSON" 1 1)
SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin hex -m "$SH1" -m "$SH2" -p testpass 2>/dev/null)
REC_HEX=$(recovered_hex "$REC")
assert_eq "hex round-trip 2of3" "$SPEND_KEY" "$REC_HEX"

# ─── split → recover --coin monero derives full wallet ───────────────────────
echo "── split → recover monero (2-of-3) ──"
JSON=$("$BIN" split --coin monero -e "$SPEND_KEY" -p mpass --group 2of3 2>/dev/null)
assert_contains "split monero shows address for verification" "$("$BIN" split --coin monero -e "$SPEND_KEY" -p mpass --group 2of3 2>&1 >/dev/null)" "$EXPECTED_ADDR"
SH1=$(share_mnemonic "$JSON" 1 1)
SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin monero -m "$SH1" -m "$SH2" -p mpass 2>&1 1>/dev/null)
assert_contains "recover monero recovers address" "$REC" "$EXPECTED_ADDR"
assert_contains "recover monero recovers spend key" "$REC" "$SPEND_KEY"
assert_contains "recover monero recovers mnemonic" "$REC" "${EXPECTED_MNEMONIC%% *}"

# ─── split Monero mnemonic input (auto-detected) ─────────────────────────────
echo "── split monero mnemonic input ──"
JSON=$("$BIN" split --coin monero -e "$EXPECTED_MNEMONIC" -p mnpass --group 3of5 2>/dev/null)
assert_contains "split monero detects Monero mnemonic" "$("$BIN" split --coin monero -e "$EXPECTED_MNEMONIC" -p mnpass --group 3of5 2>&1 >/dev/null)" "Detected: 25-word Monero mnemonic"
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2); SH3=$(share_mnemonic "$JSON" 1 3)
REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$SH1" -m "$SH2" -m "$SH3" -p mnpass 2>/dev/null)")
assert_eq "monero mnemonic round-trip 3of5" "$SPEND_KEY" "$REC_HEX"

# ─── split BIP-39 mnemonic input ─────────────────────────────────────────────
echo "── split → recover bitcoin (BIP-39) ──"
BIP="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"
JSON=$("$BIN" split --coin bitcoin -e "$BIP" -p btcpass --group 2of3 2>/dev/null)
assert_contains "split bitcoin detects BIP-39" "$("$BIN" split --coin bitcoin -e "$BIP" -p btcpass --group 2of3 2>&1 >/dev/null)" "Detected: BIP-39 mnemonic"
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin bitcoin -m "$SH1" -m "$SH2" -p btcpass 2>/dev/null)
assert_contains "recover bitcoin recovers mnemonic" "$REC" "abandon abandon abandon"

# ─── generate --coin monero (fresh wallet round-trip) ────────────────────────
echo "── generate --coin monero (fresh wallet round-trip) ──"
JSON=$("$BIN" generate --coin monero -p genpass --group 2of3 2>/tmp/p39_generr)
GEN_ADDR=$(grep -oE '4[0-9A-Za-z]{94}' /tmp/p39_generr | head -1)
GEN_SPEND=$(grep -oE 'Private spend key: [0-9a-f]{64}' /tmp/p39_generr | grep -oE '[0-9a-f]{64}' | head -1)
[ ${#GEN_ADDR} -eq 95 ] && ok "generate monero produced 95-char address" || bad "generate monero address length" "got len ${#GEN_ADDR}"
[ ${#GEN_SPEND} -eq 64 ] && ok "generate monero produced 64-char spend key" || bad "generate monero spend key length" "got len ${#GEN_SPEND}"
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin monero -m "$SH1" -m "$SH2" -p genpass 2>&1 1>/dev/null)
assert_contains "generate monero wallet round-trips to same address" "$REC" "$GEN_ADDR"
assert_contains "generate monero wallet round-trips to same spend key" "$REC" "$GEN_SPEND"

# ─── generate --coin bitcoin (BIP-39-valid 256-bit seed) ─────────────────────
echo "── generate --coin bitcoin ──"
JSON=$("$BIN" generate --coin bitcoin -p bpass --group 2of3 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin bitcoin -m "$SH1" -m "$SH2" -p bpass 2>/dev/null)
NW=$(printf '%s' "$REC" | wc -w | tr -d ' ')
assert_eq "generate bitcoin recovers 24-word phrase" "24" "$NW"

# ─── generate --coin hex (arbitrary bits) ───────────────────────────────────
echo "── generate --coin hex ──"
JSON=$("$BIN" generate --coin hex --bits 128 -p rpass --group 1of1 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1)
REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$SH1" -p rpass 2>/dev/null)")
[ ${#REC_HEX} -eq 32 ] && ok "generate hex 128-bit round-trips (32 hex chars)" || bad "generate hex 128-bit" "got len ${#REC_HEX}"

# ─── generate --coin required ───────────────────────────────────────────────
echo "── generate --coin required ──"
assert_exit "generate without --coin errors" 2 "$BIN" generate -p x --group 2of3 2>/dev/null

# ─── generate --decoy (Real + Decoy pair) ───────────────────────────────────
echo "── generate --decoy ──"
JSON=$("$BIN" generate --coin monero --decoy -p realpass --decoy-password decoypass --group 3of5 2>/tmp/p39_decoyerr)
# Two JSON objects are printed: real first, decoy second. Parse them with
# raw_decode (handles pretty-printed multi-line objects) and extract a share
# by object index (0 = real, 1 = decoy).
share_mnemonic_n() { # json_obj_index group_index(1-based) share_index(1-based)
    python3 -c "
import json,sys
t=sys.stdin.read()
dec=json.JSONDecoder()
objs=[]; i=0
while i < len(t):
    if t[i] == '{':
        obj,end=dec.raw_decode(t,i); objs.append(obj); i=end
    else:
        i+=1
print(objs[$1]['groups'][$2-1]['shares'][$3-1]['mnemonic'])
" <<<"$JSON"
}
REAL_SH=$(share_mnemonic_n 0 1 1)
DECOY_SH=$(share_mnemonic_n 1 1 1)
[ -n "$REAL_SH" ] && [ -n "$DECOY_SH" ] && ok "generate --decoy produced real + decoy shares" || bad "generate --decoy shares" "could not extract both shares"
# A decoy Monero address should appear in stderr.
DECOY_ADDR=$(grep -oE '4[0-9A-Za-z]{94}' /tmp/p39_decoyerr | tail -1)
[ -n "$DECOY_ADDR" ] && ok "generate --decoy produced decoy wallet" || bad "generate --decoy" "no decoy address found"
# Real and decoy must be DIFFERENT shares (different 3rd word onward) but
# SHARE the same 2-word metadata prefix (identifier || ext || iterations).
REAL_PREFIX=$(printf '%s' "$REAL_SH" | awk '{print $1" "$2}')
DECOY_PREFIX=$(printf '%s' "$DECOY_SH" | awk '{print $1" "$2}')
assert_eq "generate --decoy prefix matches real prefix" "$REAL_PREFIX" "$DECOY_PREFIX"
if [ "$REAL_SH" != "$DECOY_SH" ]; then ok "generate --decoy shares differ beyond prefix"; else bad "generate --decoy shares differ" "real and decoy shares are identical"; fi
# The decoy wallet recovers with the decoy password (not the real one).
SH2=$(share_mnemonic_n 1 1 2); SH3=$(share_mnemonic_n 1 1 3)
REC=$("$BIN" recover --coin monero -m "$DECOY_SH" -m "$SH2" -m "$SH3" -p decoypass 2>&1 1>/dev/null)
assert_contains "generate --decoy recovers with decoy password" "$REC" "$DECOY_ADDR"

# ─── generate --no-password ──────────────────────────────────────────────────
echo "── generate --no-password ──"
JSON=$("$BIN" generate --coin monero --no-password --group 2of3 2>/tmp/p39_nopw)
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC=$("$BIN" recover --coin monero -m "$SH1" -m "$SH2" -p "" 2>&1 1>/dev/null)
assert_contains "generate --no-password round-trips with empty password" "$REC" "Recovered Monero wallet"

# ─── inspect shows share metadata ────────────────────────────────────────────
echo "── inspect ──"
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p ipass --group 3of5 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1)
META=$("$BIN" inspect -m "$SH1" 2>/dev/null)
assert_contains "inspect shows member_threshold 3" "$META" '"member_threshold": 3'
assert_contains "inspect shows group_count 1" "$META" '"group_count": 1'

# ─── insufficient shares fail ───────────────────────────────────────────────
echo "── insufficient shares ──"
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p spass --group 3of5 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
assert_exit "recover with 2 of 3 shares fails" 1 "$BIN" recover --coin hex -m "$SH1" -m "$SH2" -p spass 2>/dev/null

# ─── wrong password produces different secret (not an error) ─────────────────
echo "── wrong password ──"
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p correct --group 2of3 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$SH1" -m "$SH2" -p wrong 2>/dev/null)")
if [ "$REC_HEX" != "$SPEND_KEY" ]; then ok "wrong password yields different secret"; else bad "wrong password yields different secret" "recovered the real key with wrong password!"; fi

# ─── iteration exponent round-trips at 0,1,2 ───────────────────────────────
echo "── iteration exponents ──"
for e in 0 1 2; do
    JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p "iter$e" --group 2of3 -i "$e" 2>/dev/null)
    SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
    REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$SH1" -m "$SH2" -p "iter$e" 2>/dev/null)")
    assert_eq "iteration exponent $e round-trip" "$SPEND_KEY" "$REC_HEX"
done

# ─── iteration exponent > 15 is rejected (ext bit) ──────────────────────────
echo "── iteration exponent bounds ──"
assert_exit "iterations=16 rejected" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 -i 16 2>/dev/null
assert_exit "iterations=255 rejected" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 -i 255 2>/dev/null
# And generate validates BEFORE generating the wallet (no keys leaked on failure).
GEN_ERR=$("$BIN" generate --coin monero -p x --group 2of3 -i 16 2>&1 >/dev/null)
assert_not_contains "generate with bad iterations leaks no wallet" "$GEN_ERR" "Private spend key"
assert_contains "generate with bad iterations errors" "$GEN_ERR" "iterations"

# ─── identifier bounds ──────────────────────────────────────────────────────
echo "── identifier bounds ──"
assert_exit "identifier 32767 accepted" 0 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 2of3 --identifier 32767 2>/dev/null

# ─── group spec validation ──────────────────────────────────────────────────
echo "── group spec validation ──"
assert_exit "threshold 0 rejected" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 0of3 2>/dev/null
assert_exit "threshold > total rejected" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group 5of3 2>/dev/null
assert_exit "invalid spec rejected" 1 "$BIN" split --coin hex -e "$SPEND_KEY" -p x --group "notaspec" 2>/dev/null

# ─── multi-group wallet ─────────────────────────────────────────────────────
echo "── multi-group ──"
JSON=$("$BIN" split --coin hex -e "$SPEND_KEY" -p multi --required-groups 2 --group 2of3 --group 2of2 2>/dev/null)
GC=$(group_count "$JSON"); GT=$(group_threshold "$JSON")
assert_eq "multi-group group_count" "2" "$GC"
assert_eq "multi-group group_threshold" "2" "$GT"
G1S1=$(share_mnemonic "$JSON" 1 1); G1S2=$(share_mnemonic "$JSON" 1 2)
G2S1=$(share_mnemonic "$JSON" 2 1); G2S2=$(share_mnemonic "$JSON" 2 2)
REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$G1S1" -m "$G1S2" -m "$G2S1" -m "$G2S2" -p multi 2>/dev/null)")
assert_eq "multi-group round-trip" "$SPEND_KEY" "$REC_HEX"
assert_exit "single group insufficient" 1 "$BIN" recover --coin hex -m "$G1S1" -m "$G1S2" -p multi 2>/dev/null

# ─── decoy wallet: metadata prefix matches real wallet ───────────────────────
echo "── decoy (plausible deniability) ──"
REAL_JSON=$("$BIN" generate --coin monero -p realpass --group 3of5 2>/tmp/p39_realerr)
REAL_ADDR=$(grep -oE '4[0-9A-Za-z]{94}' /tmp/p39_realerr | head -1)
REAL_SH=$(share_mnemonic "$REAL_JSON" 1 1)
REAL_PREFIX=$(printf '%s' "$REAL_SH" | awk '{print $1" "$2}')
DECOY_JSON=$("$BIN" decoy --coin monero -m "$REAL_SH" -p decoypass 2>/tmp/p39_decoyerr2)
DECOY_ADDR=$(grep -oE '4[0-9A-Za-z]{94}' /tmp/p39_decoyerr2 | head -1)
DECOY_SH=$(share_mnemonic "$DECOY_JSON" 1 1)
DECOY_PREFIX=$(printf '%s' "$DECOY_SH" | awk '{print $1" "$2}')
assert_eq "decoy prefix matches real prefix" "$REAL_PREFIX" "$DECOY_PREFIX"

# ─── --coin aliases (btc/xmr/hex) ───────────────────────────────────────────
echo "── --coin aliases ──"
OUT=$("$BIN" derive -c btc -s "$ZERO16" 2>/dev/null)
assert_eq "derive -c btc works" "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about" "$OUT"
OUT=$("$BIN" derive -c xmr -s "$SPEND_KEY" 2>&1 1>/dev/null)
assert_contains "derive -c xmr works" "$OUT" "$EXPECTED_ADDR"
assert_exit "split -c hex works" 0 "$BIN" split -c hex -e "$SPEND_KEY" -p x --group 2of3 2>/dev/null

# ─── --coin required on split/recover/decoy ─────────────────────────────────
echo "── --coin required ──"
assert_exit "split without --coin errors" 2 "$BIN" split -e "$SPEND_KEY" -p x --group 2of3 2>/dev/null
assert_exit "recover without --coin errors" 2 "$BIN" recover -m "x" -p x 2>/dev/null
assert_exit "decoy without --coin errors" 2 "$BIN" decoy -m "x" -p x 2>/dev/null

# ─── --no-password on decoy ─────────────────────────────────────────────────
echo "── decoy --no-password ──"
assert_exit "decoy --no-password accepted" 0 "$BIN" decoy --coin hex --no-password -m "$REAL_SH" --group 3of5 2>/dev/null

# ─── --extendable (ext=1) CLI round-trip ────────────────────────────────────
echo "── --extendable round-trip ──"
JSON=$("$BIN" split --coin hex --extendable -e "$SPEND_KEY" -p ext --group 2of3 2>/dev/null)
SH1=$(share_mnemonic "$JSON" 1 1); SH2=$(share_mnemonic "$JSON" 1 2)
REC_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$SH1" -m "$SH2" -p ext 2>/dev/null)")
assert_eq "--extendable round-trip" "$SPEND_KEY" "$REC_HEX"

# ─── generate --coin bitcoin end-to-end ─────────────────────────────────────
echo "── generate --coin bitcoin ──"
GEN_JSON=$("$BIN" generate --coin bitcoin --group 2of3 -p bp 2>/dev/null)
GEN_SH1=$(share_mnemonic "$GEN_JSON" 1 1); GEN_SH2=$(share_mnemonic "$GEN_JSON" 1 2)
REC_BTC=$("$BIN" recover --coin bitcoin -m "$GEN_SH1" -m "$GEN_SH2" -p bp 2>/dev/null)
NW=$(printf '%s' "$REC_BTC" | wc -w | tr -d ' ')
[ "$NW" -ge 12 ] && [ "$NW" -le 24 ] && ok "generate bitcoin yields 12-24 word mnemonic" || bad "generate bitcoin word count" "got $NW words"
[ -n "$REC_BTC" ] && ok "generate bitcoin recovers a non-empty mnemonic" || bad "generate bitcoin recovery" "empty output"

# ─── inspect with invalid input ─────────────────────────────────────────────
echo "── inspect invalid input ──"
assert_exit "inspect rejects garbage" 1 "$BIN" inspect -m "not a valid share" 2>/dev/null

# ─── completions output validity ────────────────────────────────────────────
echo "── completions ──"
BASH_OUT=$("$BIN" completions bash 2>/dev/null)
assert_exit "completions bash exits 0" 0 "$BIN" completions bash 2>/dev/null
assert_contains "completions bash mentions pellitory-39" "$BASH_OUT" "pellitory-39"
ZSH_OUT=$("$BIN" completions zsh 2>/dev/null)
assert_contains "completions zsh mentions pellitory-39" "$ZSH_OUT" "pellitory-39"

# ─── split --coin monero shows address for verification ─────────────────────
echo "── split --coin monero shows address ──"
SPLIT_ERR=$("$BIN" split --coin monero -e "$SPEND_KEY" -p x --group 2of3 2>&1 1>/dev/null)
assert_contains "split monero shows address for verification" "$SPLIT_ERR" "$EXPECTED_ADDR"

# ─── --no-password on generate ──────────────────────────────────────────────
echo "── generate --no-password ──"
NOPASS_JSON=$("$BIN" generate --coin hex --no-password --group 2of3 2>/dev/null)
NOPASS_SH1=$(share_mnemonic "$NOPASS_JSON" 1 1); NOPASS_SH2=$(share_mnemonic "$NOPASS_JSON" 1 2)
NOPASS_HEX=$(recovered_hex "$("$BIN" recover --coin hex -m "$NOPASS_SH1" -m "$NOPASS_SH2" -p "" 2>/dev/null)")
[ -n "$NOPASS_HEX" ] && ok "generate --no-password recovers with empty password" || bad "generate --no-password" "empty recovery failed"

# ─── Summary ───────────────────────────────────────────────────────────────
echo ""
echo "=== Summary: $PASS passed, $FAIL failed ==="
if [ "$FAIL" -gt 0 ]; then
    echo "Failed tests:"
    for t in "${FAILED_TESTS[@]}"; do echo "  - $t"; done
    exit 1
fi
