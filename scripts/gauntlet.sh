#!/usr/bin/env bash
# Gauntlet — hard quality gate. Agent-written code must survive all of it.
#
#   ./scripts/gauntlet.sh          # tiers 0-4 (pre-commit / pre-push)
#   ./scripts/gauntlet.sh full     # everything, including mutation + fuzz (slow)
#   ./scripts/gauntlet.sh 0        # single tier
#
# Thresholds are env-overridable so tightening them is a one-line change.
#
# NOTE: tests/service_e2e.rs (13 tests) is deliberately excluded from all
# tiers. Those tests write to a live node (notarize documents, create
# on-chain records) and require explicit opt-in:
#
#   GOYA_E2E_URL=https://goya-node.fly.dev cargo test --test service_e2e -- --ignored
set -uo pipefail

# Measured baseline on 2026-07-27: 66.51% lines (58.81% fn, 63.03% region).
# Set at the measured floor so the gate catches regressions today; raise it as
# coverage climbs rather than picking an aspirational number that just fails.
COV_MIN="${COV_MIN:-66}"            # % line coverage required
MUTANTS_MIN="${MUTANTS_MIN:-80}"    # % mutants that must be caught
FUZZ_SECS="${FUZZ_SECS:-60}"        # per fuzz target
# Mutant counts in this tree: signature 88, identity 266, consensus 736.
# Each mutant reruns the suite, so the full 1090 is a many-hour job — scoped to
# the signature core by default (FES/FEA is what carries the legal claims).
# Widen deliberately: MUTANTS_SCOPE="src/signature src/identity" ./scripts/gauntlet.sh 5
MUTANTS_SCOPE="${MUTANTS_SCOPE:-src/signature}"

# ── RAM budget ────────────────────────────────────────────────────────────
# Cargo defaults to one rustc per core; on this tree (wasmtime, revm, rocksdb)
# that peaks well past 16GB and swaps the machine. Three concurrent jobs is
# the calibrated middle: it only became safe once incremental caching and full
# debuginfo were switched off below, which is where most of the memory went.
# Drop to JOBS=1 if the machine still struggles.
JOBS="${JOBS:-3}"
export CARGO_BUILD_JOBS="$JOBS"
export RUST_TEST_THREADS="${TEST_THREADS:-1}"
export CARGO_PROFILE_TEST_DEBUG="${CARGO_PROFILE_TEST_DEBUG:-line-tables-only}"
# Incremental caching only pays off in an interactive edit loop; for a
# full-tree gate it is dead weight. It grew target/debug/incremental to 37GB
# and filled the disk, which surfaces as bogus exit-101 "compile failures".
export CARGO_INCREMENTAL=0

cd "$(dirname "$0")/.."
FAILED=()
STARTED=$(date +%s)

run() { # run <tier> <label> <cmd...>
  local tier=$1 label=$2; shift 2
  printf '\n\033[1m▶ [T%s] %s\033[0m\n' "$tier" "$label"
  local t0; t0=$(date +%s)
  if "$@"; then
    printf '\033[32m  ✓ %s (%ss)\033[0m\n' "$label" "$(( $(date +%s) - t0 ))"
  else
    printf '\033[31m  ✗ %s\033[0m\n' "$label"
    FAILED+=("T$tier $label")
  fi
}

want() { # want <tier> -> should this tier run?
  case "$MODE" in
    full) return 0 ;;
    # T3 is excluded from the default run: llvm-cov compiles with its own
    # instrumentation flags, so it builds a second full set of artifacts and
    # roughly doubles target/. It is the slowest tier and the one that changes
    # least between runs — ask for it explicitly with `gauntlet.sh 3`.
    default) [ "$1" -le 4 ] && [ "$1" -ne 3 ] ;;
    *) [ "$MODE" = "$1" ] ;;
  esac
}

MODE="${1:-default}"
[ "$MODE" = "all" ] && MODE=full

# ── T0: static ────────────────────────────────────────────────────────────
if want 0; then
  run 0 "rustfmt"        cargo fmt --check
  run 0 "clippy"         cargo clippy --all-targets -- -D warnings
  run 0 "crypto boundary" cargo test --test crypto_boundary
  run 0 "lean proofs"    sh -c 'cd formal && lake build && ! grep -rnwE "sorry|admit|axiom" Formal'
fi

# ── T1: unit ──────────────────────────────────────────────────────────────
if want 1; then
  run 1 "unit tests" cargo test --lib
  run 1 "doc tests"  cargo test --doc
fi

# ── T2: integration + property + E2E ──────────────────────────────────────
if want 2; then
  # ponytail: one --test at a time. `cargo test --tests` links all 36
  # integration binaries concurrently and is what actually OOMs the box.
  integration_gate() {
    local t rc=0
    for t in tests/*.rs; do
      t=$(basename "$t" .rs)
      printf '  · %s\n' "$t"
      cargo test --test "$t" -- --test-threads="$RUST_TEST_THREADS" >/dev/null 2>&1 || {
        printf '\033[31m    failed: %s\033[0m\n' "$t"; rc=1
      }
    done
    return $rc
  }
  run 2 "integration suite (serialized)" integration_gate
fi

# ── T3: coverage ──────────────────────────────────────────────────────────
if want 3; then
  cov_gate() {
    command -v cargo-llvm-cov >/dev/null || { echo "  cargo-llvm-cov missing: cargo install cargo-llvm-cov"; return 1; }
    cargo llvm-cov --lib --summary-only --fail-under-lines "$COV_MIN"
  }
  run 3 "coverage >= ${COV_MIN}%" cov_gate
fi

# ── T4: supply chain ──────────────────────────────────────────────────────
if want 4; then
  command -v cargo-audit >/dev/null && run 4 "cargo audit" cargo audit
  cargo deny --version >/dev/null 2>&1 && run 4 "cargo deny" cargo deny check
fi

# ── T5: mutation testing ──────────────────────────────────────────────────
if want 5; then
  mutants_gate() {
    command -v cargo-mutants >/dev/null || { echo "  cargo-mutants missing: cargo install cargo-mutants"; return 1; }
    local args=() d
    for d in $MUTANTS_SCOPE; do args+=(--file "$d/**/*.rs"); done
    # ponytail: parse the summary line rather than the JSON; upgrade to
    # mutants.out/outcomes.json if per-mutant triage is ever needed.
    # `-- --lib` matters: without it every mutant also builds and runs all 36
    # integration suites, which turns an hour into a week.
    cargo mutants --no-shuffle --jobs 1 --timeout 300 "${args[@]}" -- --lib 2>&1 | tee /tmp/mutants.log
    local caught missed
    caught=$(grep -oE '[0-9]+ caught' /tmp/mutants.log | tail -1 | grep -oE '[0-9]+') || caught=0
    missed=$(grep -oE '[0-9]+ missed' /tmp/mutants.log | tail -1 | grep -oE '[0-9]+') || missed=0
    [ $((caught + missed)) -eq 0 ] && { echo "  no mutants generated"; return 1; }
    local pct=$(( caught * 100 / (caught + missed) ))
    echo "  mutation score: ${pct}% (${caught} caught / ${missed} missed), min ${MUTANTS_MIN}%"
    [ "$pct" -ge "$MUTANTS_MIN" ]
  }
  run 5 "mutation score >= ${MUTANTS_MIN}%" mutants_gate
fi

# ── T6: fuzzing ───────────────────────────────────────────────────────────
if want 6; then
  fuzz_gate() {
    command -v cargo-fuzz >/dev/null || { echo "  cargo-fuzz missing: cargo install cargo-fuzz"; return 1; }
    local t rc=0
    for t in fuzz/fuzz_targets/*.rs; do
      t=$(basename "$t" .rs)
      echo "  fuzzing $t for ${FUZZ_SECS}s"
      cargo fuzz run "$t" -- -max_total_time="$FUZZ_SECS" || rc=1
    done
    return $rc
  }
  run 6 "fuzz targets" fuzz_gate
fi

# ── verdict ───────────────────────────────────────────────────────────────
printf '\n\033[1m── gauntlet (%ss) ──\033[0m\n' "$(( $(date +%s) - STARTED ))"
if [ ${#FAILED[@]} -eq 0 ]; then
  printf '\033[32mPASS\033[0m\n'; exit 0
fi
printf '\033[31mFAIL (%d)\033[0m\n' "${#FAILED[@]}"
printf '  %s\n' "${FAILED[@]}"
exit 1
