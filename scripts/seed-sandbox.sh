#!/usr/bin/env bash
# Cerulean Ledger — Sandbox Seed Data
#
# Pre-loads the sandbox node with demo data for institutional demo.
# Compatible with bash 3+ (macOS) and bash 5+ (Linux/Docker).
#
# Usage:
#   ./scripts/seed-sandbox.sh                          # Uses localhost:9600
#   ./scripts/seed-sandbox.sh http://host:port          # Positional arg
#   API_URL=http://host:port ./scripts/seed-sandbox.sh  # Env var
#
# Idempotent: safe to run multiple times.

set -euo pipefail

BASE="${1:-${API_URL:-http://localhost:9600}}"
API="$BASE/api/v1"

GREEN='\033[0;32m'
CYAN='\033[0;36m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

ok()   { echo -e "  ${GREEN}[OK]${NC} $1"; }
fail() { echo -e "  ${RED}[FAIL]${NC} $1"; }
skip() { echo -e "  ${YELLOW}[SKIP]${NC} $1"; }

# Headers for permissive ACL mode
H1="-H Content-Type:application/json -H X-Org-Id:org1 -H X-Msp-Role:admin"
H2="-H Content-Type:application/json -H X-Org-Id:org2 -H X-Msp-Role:admin"

post() {
    curl -sf -X POST $H1 "$@" 2>/dev/null || echo ""
}

ACCOUNT_TOOL="$(cd "$(dirname "$0")" && pwd)/ledger-account/account.mjs"
SEED_DIR="${SEED_DIR:-$HOME/.goya/sandbox-seeds}"
mkdir -p "$SEED_DIR"
[ -d "$(dirname "$ACCOUNT_TOOL")/node_modules" ] || npm ci --silent --prefix "$(dirname "$ACCOUNT_TOOL")"

account() {
    local name="$1"
    shift
    NODE_URL="$API" SEED_PATH="$SEED_DIR/$name.hex" node "$ACCOUNT_TOOL" "$@"
}

MINER_ADDR=""
COUNTS_WALLETS=0
COUNTS_IDS=0
COUNTS_CREDS=0
COUNTS_BLOCKS=0

echo -e "${CYAN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${CYAN}║   Cerulean Sandbox Seeder                 ║${NC}"
echo -e "${CYAN}╚═══════════════════════════════════════════╝${NC}"
echo -e "  Target: ${CYAN}$API${NC}"
echo ""

# ── 1. Health check ──────────────────────────────────────────────────────────

echo -e "${CYAN}1. Health check${NC}"
if curl -sf "$API/health" > /dev/null 2>&1; then
    ok "Node is healthy"
else
    fail "Node not reachable at $API/health"
    exit 1
fi

# ── 2. Organizations ─────────────────────────────────────────────────────────

echo -e "${CYAN}2. Organizations${NC}"
for org_json in \
    '{"org_id":"org1","name":"Universidad de Chile","msp_id":"Org1MSP"}' \
    '{"org_id":"org2","name":"Banco Central","msp_id":"Org2MSP"}'; do
    resp=$(post "$API/organizations" -d "$org_json")
    org_name=$(echo "$org_json" | grep -o '"name":"[^"]*"' | cut -d'"' -f4)
    if [ -n "$resp" ]; then ok "$org_name"; else skip "$org_name (may exist)"; fi
done

# ── 3. Channels ──────────────────────────────────────────────────────────────

echo -e "${CYAN}3. Channels${NC}"
for ch in academic financial; do
    resp=$(post "$API/channels" -d "{\"channel_id\":\"$ch\",\"org_ids\":[\"org1\",\"org2\"]}")
    if [ -n "$resp" ]; then ok "$ch"; else skip "$ch"; fi
done

# ── 4. Wallets + mining ─────────────────────────────────────────────────────

echo -e "${CYAN}4. Wallets${NC}"
for name in alice bob carlos diana sandbox-miner banco-central tesoreria; do
    resp=$(post "$API/wallets/create" -d "{}")
    if echo "$resp" | grep -q '"address"'; then
        addr=$(echo "$resp" | grep -o '"address":"[^"]*"' | head -1 | cut -d'"' -f4)
        ok "Wallet: $name ($addr)"
        COUNTS_WALLETS=$((COUNTS_WALLETS + 1))
        if [ "$name" = "sandbox-miner" ]; then MINER_ADDR="$addr"; fi
    else
        skip "Wallet: $name"
    fi
done

echo -e "${CYAN}5. Mining blocks${NC}"
if [ -n "$MINER_ADDR" ]; then
    for i in 1 2 3 4 5 6 7 8; do
        resp=$(post "$API/mine" -d "{\"miner_address\":\"$MINER_ADDR\"}")
        if [ -n "$resp" ]; then
            COUNTS_BLOCKS=$((COUNTS_BLOCKS + 1))
        fi
    done
    ok "$COUNTS_BLOCKS blocks mined"
else
    skip "No miner address — skipping"
fi

# ── 5. Identities (DIDs) ────────────────────────────────────────────────────

echo -e "${CYAN}6. Identities${NC}"
for name in universidad-chile registro-civil servicio-salud banco-central alice-persona bob-empresa carlos-auditor; do
    [ -f "$SEED_DIR/$name.hex" ] || account "$name" keygen > /dev/null
    if account "$name" register > /dev/null 2>&1; then
        ok "$name ($(account "$name" did | cut -c1-24)…)"
        COUNTS_IDS=$((COUNTS_IDS + 1))
    else
        skip "$name (already registered)"
    fi
done

# ── 6. Credentials (signed documents) ───────────────────────────────────────

echo -e "${CYAN}7. Documents & credentials${NC}"

seed_cred() {
    local id="$1" issuer="$2" subject="$3" ctype="$4" claims="$5" expires="${6:-0}" body
    body=$(printf '%s\t%s\t%s\t%s\t%s\n' "$id" "$(account "$subject" did)" "$ctype" "$claims" "$expires" | account "$issuer" credentials)
    resp=$(post "$API/store/credentials" -d "$body")
    if [ -n "$resp" ]; then
        ok "$ctype ($id)"
        COUNTS_CREDS=$((COUNTS_CREDS + 1))
    else
        skip "$id"
    fi
}

seed_cred "doc-titulo-001" "universidad-chile" "alice-persona" \
    "Titulo Profesional" '{"grado":"Ingenieria Civil Informatica","institucion":"Universidad de Chile","mencion":"Cum Laude"}' 0

seed_cred "doc-contrato-001" "universidad-chile" "alice-persona" \
    "Contrato de Trabajo" '{"cargo":"Investigadora Asociada","departamento":"Ciencias de la Computacion","tipo":"Indefinido"}' 0

seed_cred "doc-salud-001" "servicio-salud" "alice-persona" \
    "Certificado de Vacunacion" '{"esquema":"Completo","dosis":3,"vacuna":"COVID-19"}' 1810000000

seed_cred "doc-kyc-001" "banco-central" "bob-empresa" \
    "Verificacion KYC" '{"nivel":"Enhanced Due Diligence","pais":"CL","razon_social":"Bob Empresa SpA"}' 1800000000

seed_cred "doc-sociedad-001" "registro-civil" "carlos-auditor" \
    "Constitucion de Sociedad" '{"tipo":"SpA","nombre":"Cerulean Consulting SpA","capital":"10.000.000 CLP","socios":"Carlos Auditor, Maria Fernandez"}' 0

seed_cred "doc-poder-001" "registro-civil" "bob-empresa" \
    "Poder Notarial" '{"otorgante":"Bob Empresa SpA","apoderado":"Carlos Auditor","alcance":"Representacion legal amplia"}' 1820000000

seed_cred "doc-audit-001" "banco-central" "carlos-auditor" \
    "Licencia de Auditor" '{"tipo":"Auditor Financiero","alcance":"Nacional","registro":"AUD-2024-789"}' 1800000000

# ── 7. Governance ────────────────────────────────────────────────────────────

echo -e "${CYAN}8. Governance${NC}"

# Proposal 1
resp=$(post "$API/governance/proposals" -d '{"proposer":"ciudadano","description":"Reducir tiempo de bloque a 2 segundos para mejorar experiencia de usuario","deposit":10000,"action":{"type":"text","title":"Reducir block time a 2 segundos","description":"Propuesta para mejorar UX en la plataforma"}}')
if [ -n "$resp" ]; then ok "Proposal: Block time reduction"; else skip "Proposal 1"; fi

# Proposal 2
resp=$(post "$API/governance/proposals" -d '{"proposer":"auditor","description":"Activar firma post-cuantica obligatoria para todos los nodos validadores","deposit":10000,"action":{"type":"text","title":"Activar PQC obligatorio","description":"Migrar a ML-DSA-65 como unico algoritmo de firma"}}')
if [ -n "$resp" ]; then ok "Proposal: PQC enforcement"; else skip "Proposal 2"; fi

# Votes on proposal 1
for voter in alice bob carlos; do
    resp=$(post "$API/governance/proposals/1/vote" -d "{\"voter\":\"$voter\",\"option\":\"Yes\"}")
    if [ -n "$resp" ]; then ok "Vote: $voter → Yes on #1"; else skip "Vote: $voter"; fi
done

# ── 8. Channel state ─────────────────────────────────────────────────────────

echo -e "${CYAN}9. Channel state${NC}"
resp=$(post "$API/channels/academic/state" -d '{"key":"enrollment:2024:alice","value":"active"}')
if [ -n "$resp" ]; then ok "academic/enrollment:alice"; else skip "academic state"; fi

resp=$(curl -sf -X POST $H2 "$API/channels/financial/state" -d '{"key":"balance:org2:reserve","value":"50000000"}' 2>/dev/null || echo "")
if [ -n "$resp" ]; then ok "financial/balance:org2"; else skip "financial state"; fi

# ── Summary ──────────────────────────────────────────────────────────────────

echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║         Seed Complete                     ║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Wallets:      ${CYAN}${COUNTS_WALLETS}${NC}"
echo -e "  Blocks:       ${CYAN}${COUNTS_BLOCKS}${NC}"
echo -e "  Identities:   ${CYAN}${COUNTS_IDS}${NC}"
echo -e "  Credentials:  ${CYAN}${COUNTS_CREDS}${NC}"
echo -e "  Proposals:    ${CYAN}2${NC}"
echo -e "  Channels:     ${CYAN}2${NC} (academic, financial)"
echo ""
echo -e "  API:          ${CYAN}$API${NC}"
echo ""
