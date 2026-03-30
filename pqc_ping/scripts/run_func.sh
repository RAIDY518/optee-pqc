#!/bin/bash
# run_func.sh — Day 13: one-click functional validation
#
# Runs all core functional tests and saves logs + summary.
# Exit code is non-zero if any critical test fails.
#
# Usage:
#   ./scripts/run_func.sh                # default output to ./results/
#   ./scripts/run_func.sh /tmp/results   # custom output directory

set -euo pipefail

BINARY="${BINARY:-pqc_ping}"
OUTDIR="${1:-results}"
LOGDIR="$OUTDIR/logs"
SUMDIR="$OUTDIR/summary"

mkdir -p "$LOGDIR" "$SUMDIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="$LOGDIR/func_${TIMESTAMP}.log"
SUMMARY="$SUMDIR/func_${TIMESTAMP}.txt"

pass=0
fail=0
total=0

log() { echo "$*" | tee -a "$LOGFILE"; }
sep() { log "------------------------------------------------------------"; }

run_test() {
    local name="$1"
    shift
    local cmd="$BINARY $*"

    total=$((total + 1))
    log ""
    log "[$total] $name"
    log "  cmd: $cmd"

    local tmpout
    tmpout=$(mktemp)

    set +e
    $BINARY "$@" >"$tmpout" 2>&1
    local rc=$?
    set -e

    cat "$tmpout" >> "$LOGFILE"
    cat "$tmpout"

    if [ $rc -eq 0 ]; then
        log "  => PASS (exit 0)"
        pass=$((pass + 1))
    else
        log "  => FAIL (exit $rc)"
        fail=$((fail + 1))
    fi

    rm -f "$tmpout"
    sep
    return $rc
}

# ============================================================
log "=== pqc_ping functional validation ==="
log "  timestamp: $TIMESTAMP"
log "  binary:    $BINARY"
log "  output:    $OUTDIR"
sep

# --- info ---
run_test "info" --cmd info --loop 1 || true

# --- kem-selftest ---
run_test "kem-selftest" --cmd kem-selftest --loop 1 || true

# --- kem-crosstest ---
run_test "kem-crosstest" --cmd kem-crosstest --loop 10 --warmup 2 || true

# --- sig-crosstest ---
run_test "sig-crosstest" --cmd sig-crosstest --loop 10 --warmup 2 || true

# --- kem key lifecycle: save -> status -> validate -> destroy ---
run_test "kem-keygen-save" --cmd kem-keygen-save --loop 1 || true
run_test "kem-status" --cmd kem-status --loop 1 || true
run_test "kem-validate" --cmd kem-validate --loop 1 || true
run_test "kem-destroy" --cmd kem-destroy --loop 1 || true

# --- sig key lifecycle: save -> status -> validate -> destroy ---
run_test "sig-keygen-save" --cmd sig-keygen-save --loop 1 || true
run_test "sig-status" --cmd sig-status --loop 1 || true
run_test "sig-validate" --cmd sig-validate --loop 1 || true
run_test "sig-destroy" --cmd sig-destroy --loop 1 || true

# --- kem-stress / sig-stress ---
run_test "kem-stress" --cmd kem-stress --loop 5 --warmup 1 || true
run_test "sig-stress" --cmd sig-stress --loop 5 --warmup 1 || true

# --- harden-test (critical: must pass) ---
HARDEN_FAIL=0
run_test "harden-test" --cmd harden-test || HARDEN_FAIL=1

# ============================================================
log ""
log "=== SUMMARY ==="
log "  total: $total"
log "  pass:  $pass"
log "  fail:  $fail"
log "  log:   $LOGFILE"
log ""

# Write summary file
cat > "$SUMMARY" <<SUMEOF
pqc_ping functional validation — $TIMESTAMP
  total: $total
  pass:  $pass
  fail:  $fail
  log:   $LOGFILE
SUMEOF

if [ $fail -gt 0 ]; then
    log "RESULT: FAIL ($fail failures)"
    echo "RESULT: FAIL" >> "$SUMMARY"
    exit 1
fi

log "RESULT: ALL PASS"
echo "RESULT: ALL PASS" >> "$SUMMARY"
exit 0
