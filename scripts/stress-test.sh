#!/usr/bin/env bash
# Cerulean Ledger — Ramp-up Stress Test
# Finds the throughput ceiling by increasing load until errors appear.
# Usage: ./scripts/stress-test.sh [node_url]

set -euo pipefail

NODE="${1:-http://localhost:8080}"
VERIFY_SAMPLE=10

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

now_ms() { perl -MTime::HiRes=time -e 'printf "%.0f\n", time*1000'; }

echo ""
echo -e "${CYAN}============================================${NC}"
echo -e "${CYAN} Cerulean Ledger — Ramp-up Stress Test${NC}"
echo -e "${CYAN}============================================${NC}"
echo " Node: $NODE"
echo ""

# ── Health check ──────────────────────────────────────────────────────────────

echo -n "Health check... "
if ! curl -sf "$NODE/api/v1/health" > /dev/null 2>&1; then
    echo -e "${RED}FAILED${NC} — start node first"
    exit 1
fi
echo -e "${GREEN}OK${NC}"
echo ""

# ── Seed identities (once) ───────────────────────────────────────────────────

TMPDIR=$(mktemp -d)
trap "rm -rf $TMPDIR" EXIT

ACCOUNT_TOOL="$(cd "$(dirname "$0")" && pwd)/ledger-account/account.mjs"
[[ -d "$(dirname "$ACCOUNT_TOOL")/node_modules" ]] || npm ci --silent --prefix "$(dirname "$ACCOUNT_TOOL")"

account() {
    local name="$1"
    shift
    NODE_URL="$NODE/api/v1" SEED_PATH="$TMPDIR/$name.hex" node "$ACCOUNT_TOOL" "$@"
}

SEED_IDENTITIES=100
echo -n "Seeding $SEED_IDENTITIES identities... "
seed_errors=0
for i in $(seq 1 $SEED_IDENTITIES); do
    account "s-$i" keygen > /dev/null
    account "s-$i" register > /dev/null 2>&1 || seed_errors=$((seed_errors + 1))
done
echo -e "${GREEN}done${NC} ($seed_errors errors)"
echo ""

sign_level_credentials() {
    local level="$1" count="$2" offset="$3" idx global_idx hash
    rm -rf "$TMPDIR/lines" && mkdir "$TMPDIR/lines"
    for idx in $(seq 1 "$count"); do
        global_idx=$((offset + idx))
        hash=$(printf '%064d' $((global_idx * 7)))
        printf 'sig-r%s-%06d\tdid:goya:doc:%s\tDigitalSignature\t{"document":"%s"}\t0\n' \
            "$level" "$idx" "$hash" "$hash" >> "$TMPDIR/lines/s-$(( (global_idx % SEED_IDENTITIES) + 1 )).tsv"
    done
    for lines in "$TMPDIR"/lines/*.tsv; do
        account "$(basename "$lines" .tsv)" credentials < "$lines"
    done > "$TMPDIR/bodies.jsonl"
}

# ── Ramp levels ───────────────────────────────────────────────────────────────
#        credentials  concurrency
LEVELS=( "500         10"
         "1000        20"
         "2000        50"
         "5000        100"
         "10000       200" )

echo -e "${CYAN}Level  Creds  Conc   TPS      p50    p95    p99    max    Errors${NC}"
echo "-----  -----  ----   ------   -----  -----  -----  -----  ------"

CRED_OFFSET=0
BREAK_LEVEL=""

for level_idx in "${!LEVELS[@]}"; do
    read -r SIGS CONC <<< "${LEVELS[$level_idx]}"
    LEVEL=$((level_idx + 1))

    # Clear results
    > "$TMPDIR/results.txt"

    sign_level_credentials "$LEVEL" "$SIGS" "$CRED_OFFSET"

    T_START=$(now_ms)

    running=0
    while IFS= read -r body; do
        (
            t0=$(now_ms)
            code=$(curl -s -o /dev/null -w "%{http_code}" \
                --max-time 10 \
                -X POST "$NODE/api/v1/store/credentials" \
                -H "Content-Type: application/json" \
                -H "X-Org-Id: stress" -H "X-Msp-Role: client" \
                -d "$body" 2>/dev/null || echo "000")
            t1=$(now_ms)
            echo "$((t1 - t0)) $code" >> "$TMPDIR/results.txt"
        ) &
        running=$((running + 1))
        if (( running >= CONC )); then
            wait -n 2>/dev/null || wait
            running=$((running - 1))
        fi
    done < "$TMPDIR/bodies.jsonl"
    wait

    T_END=$(now_ms)
    ELAPSED=$((T_END - T_START))
    TPS=$(echo "scale=1; $SIGS * 1000 / $ELAPSED" | bc 2>/dev/null || echo "?")

    # Parse latencies
    ERRORS=0
    P50="-"; P95="-"; P99="-"; MINL="-"; MAXL="-"
    if [[ -s "$TMPDIR/results.txt" ]]; then
        TOTAL_RESP=$(wc -l < "$TMPDIR/results.txt" | tr -d ' \n')
        OK_COUNT=$(grep -cE " (200|201)" "$TMPDIR/results.txt" 2>/dev/null | tr -d ' \n' || echo 0)
        THROTTLED=$(grep -cE " 429" "$TMPDIR/results.txt" 2>/dev/null | tr -d ' \n' || echo 0)
        if ! [[ "$OK_COUNT" =~ ^[0-9]+$ ]]; then OK_COUNT=0; fi
        if ! [[ "$TOTAL_RESP" =~ ^[0-9]+$ ]]; then TOTAL_RESP=0; fi
        if ! [[ "$THROTTLED" =~ ^[0-9]+$ ]]; then THROTTLED=0; fi
        ERRORS=$((TOTAL_RESP - OK_COUNT - THROTTLED))

        SORTED=$(awk '{print $1}' "$TMPDIR/results.txt" | sort -n)
        N=$(echo "$SORTED" | wc -l | tr -d ' ')
        if (( N > 0 )); then
            MINL=$(echo "$SORTED" | head -1)
            MAXL=$(echo "$SORTED" | tail -1)
            P50=$(echo "$SORTED" | sed -n "$((N * 50 / 100))p")
            P95=$(echo "$SORTED" | sed -n "$((N * 95 / 100))p")
            P99=$(echo "$SORTED" | sed -n "$((N * 99 / 100))p")
        fi
    fi

    # Build error display
    ERR_PARTS=""
    if (( ERRORS > 0 )); then
        ERR_PARTS="${RED}${ERRORS}err${NC}"
    fi
    if (( THROTTLED > 0 )); then
        if [[ -n "$ERR_PARTS" ]]; then ERR_PARTS="$ERR_PARTS "; fi
        ERR_PARTS="${ERR_PARTS}${YELLOW}${THROTTLED}x429${NC}"
    fi
    if [[ -z "$ERR_PARTS" ]]; then
        ERR_PARTS="${GREEN}0${NC}"
    fi

    printf "  %-4d  %-5d  %-4d   %-6s   %-5s  %-5s  %-5s  %-5s  " \
        "$LEVEL" "$SIGS" "$CONC" "${TPS}" "${P50}ms" "${P95}ms" "${P99}ms" "${MAXL}ms"
    echo -e "$ERR_PARTS"

    CRED_OFFSET=$((CRED_OFFSET + SIGS))

    # Stop if real error rate (not 429) > 5%
    ERROR_PCT=0
    if (( SIGS > 0 && ERRORS > 0 )); then
        ERROR_PCT=$((ERRORS * 100 / SIGS))
    fi
    if (( ERROR_PCT > 5 )); then
        BREAK_LEVEL=$LEVEL
        break
    fi

    # Brief cooldown between levels
    sleep 1
done

echo ""

# ── Verify sample ────────────────────────────────────────────────────────────

echo -n "Verifying $VERIFY_SAMPLE random credentials... "
verify_ok=0
for i in $(seq 1 $VERIFY_SAMPLE); do
    # Pick a random credential from the last completed level
    ridx=$(( (RANDOM % 200) + 1 ))
    for lvl in $(seq 1 5); do
        cred_id="sig-r${lvl}-$(printf '%06d' $ridx)"
        code=$(curl -s -o /dev/null -w "%{http_code}" \
            "$NODE/api/v1/store/credentials/$cred_id" 2>/dev/null)
        if [[ "$code" -ge 200 && "$code" -le 299 ]]; then
            verify_ok=$((verify_ok + 1))
            break
        fi
    done
done
echo -e "${GREEN}${verify_ok}/${VERIFY_SAMPLE}${NC} verified"

echo ""
echo -e "${CYAN}============================================${NC}"
if [[ -n "$BREAK_LEVEL" ]]; then
    echo -e " Ceiling hit at level ${RED}${BREAK_LEVEL}${NC} (>5% errors)"
else
    echo -e " ${GREEN}All levels passed — ceiling not reached${NC}"
fi
echo -e "${CYAN}============================================${NC}"
echo ""
