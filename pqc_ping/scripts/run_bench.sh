#!/bin/bash
# run_bench.sh — Day 13: one-click benchmark suite
#
# Runs micro-benchmarks (TA-internal) and path-benchmarks (REE-TEE),
# saves CSV files, logs, and a summary.
# Exit code is non-zero if any benchmark fails.
#
# Usage:
#   ./scripts/run_bench.sh                    # defaults
#   ./scripts/run_bench.sh /tmp/results       # custom output directory
#   LOOP=200 WARMUP=20 ./scripts/run_bench.sh # custom iteration counts

set -euo pipefail

BINARY="${BINARY:-pqc_ping}"
OUTDIR="${1:-results}"
LOOP="${LOOP:-100}"
WARMUP="${WARMUP:-10}"
MICRO_LOOP="${MICRO_LOOP:-20}"
MICRO_WARMUP="${MICRO_WARMUP:-5}"

LOGDIR="$OUTDIR/logs"
CSVDIR="$OUTDIR/csv"
SUMDIR="$OUTDIR/summary"

mkdir -p "$LOGDIR" "$CSVDIR" "$SUMDIR"

TIMESTAMP=$(date +%Y%m%d_%H%M%S)
LOGFILE="$LOGDIR/bench_${TIMESTAMP}.log"
SUMMARY="$SUMDIR/bench_${TIMESTAMP}.txt"

pass=0
fail=0
total=0

log() { echo "$*" | tee -a "$LOGFILE"; }
sep() { log "------------------------------------------------------------"; }

run_bench() {
    local name="$1"
    local csv_name="$2"
    shift 2
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
log "=== pqc_ping benchmark suite ==="
log "  timestamp:    $TIMESTAMP"
log "  binary:       $BINARY"
log "  output:       $OUTDIR"
log "  path loop:    $LOOP  warmup: $WARMUP"
log "  micro loop:   $MICRO_LOOP  warmup: $MICRO_WARMUP"
sep

# --- Path benchmarks (REE-TEE round-trip) -----------------------
log ""
log "=== Path benchmarks (REE-TEE) ==="

run_bench "empty (baseline)" "empty" \
    --cmd empty --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/empty_${TIMESTAMP}.csv" || true

run_bench "ping" "ping" \
    --cmd ping --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/ping_${TIMESTAMP}.csv" || true

run_bench "kem-selftest" "kem-selftest" \
    --cmd kem-selftest --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_selftest_${TIMESTAMP}.csv" || true

run_bench "kem-keygen" "kem-keygen" \
    --cmd kem-keygen --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_keygen_${TIMESTAMP}.csv" || true

run_bench "kem-encaps" "kem-encaps" \
    --cmd kem-encaps --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_encaps_${TIMESTAMP}.csv" || true

run_bench "kem-decaps" "kem-decaps" \
    --cmd kem-decaps --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_decaps_${TIMESTAMP}.csv" || true

run_bench "kem-crosstest" "kem-crosstest" \
    --cmd kem-crosstest --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_crosstest_${TIMESTAMP}.csv" || true

run_bench "sig-keygen" "sig-keygen" \
    --cmd sig-keygen --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/sig_keygen_${TIMESTAMP}.csv" || true

run_bench "sig-sign" "sig-sign" \
    --cmd sig-sign --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/sig_sign_${TIMESTAMP}.csv" || true

run_bench "sig-crosstest" "sig-crosstest" \
    --cmd sig-crosstest --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/sig_crosstest_${TIMESTAMP}.csv" || true

run_bench "kem-stress" "kem-stress" \
    --cmd kem-stress --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/kem_stress_${TIMESTAMP}.csv" || true

run_bench "sig-stress" "sig-stress" \
    --cmd sig-stress --loop "$LOOP" --warmup "$WARMUP" \
    --csv "$CSVDIR/sig_stress_${TIMESTAMP}.csv" || true

# --- Micro benchmarks (TA-internal timing) ----------------------
log ""
log "=== Micro benchmarks (TA-internal) ==="

run_bench "kem-keygen-micro" "kem-keygen-micro" \
    --cmd kem-keygen-micro --loop "$MICRO_LOOP" --warmup "$MICRO_WARMUP" \
    --csv "$CSVDIR/kem_keygen_micro_${TIMESTAMP}.csv" || true

run_bench "kem-decaps-micro" "kem-decaps-micro" \
    --cmd kem-decaps-micro --loop "$MICRO_LOOP" --warmup "$MICRO_WARMUP" \
    --csv "$CSVDIR/kem_decaps_micro_${TIMESTAMP}.csv" || true

run_bench "sig-keygen-micro" "sig-keygen-micro" \
    --cmd sig-keygen-micro --loop "$MICRO_LOOP" --warmup "$MICRO_WARMUP" \
    --csv "$CSVDIR/sig_keygen_micro_${TIMESTAMP}.csv" || true

run_bench "sig-sign-micro" "sig-sign-micro" \
    --cmd sig-sign-micro --loop "$MICRO_LOOP" --warmup "$MICRO_WARMUP" \
    --csv "$CSVDIR/sig_sign_micro_${TIMESTAMP}.csv" || true

# ============================================================
log ""
log "=== SUMMARY ==="
log "  total:   $total"
log "  pass:    $pass"
log "  fail:    $fail"
log "  log:     $LOGFILE"
log "  csv dir: $CSVDIR"
log ""

# List CSV files
CSV_COUNT=$(find "$CSVDIR" -name "*_${TIMESTAMP}.csv" | wc -l)
log "  csv files produced: $CSV_COUNT"

# Write summary file
cat > "$SUMMARY" <<SUMEOF
pqc_ping benchmark suite — $TIMESTAMP
  path loop:  $LOOP  warmup: $WARMUP
  micro loop: $MICRO_LOOP  warmup: $MICRO_WARMUP
  total:   $total
  pass:    $pass
  fail:    $fail
  log:     $LOGFILE
  csv dir: $CSVDIR
  csv count: $CSV_COUNT
SUMEOF

if [ $fail -gt 0 ]; then
    log "RESULT: FAIL ($fail failures)"
    echo "RESULT: FAIL" >> "$SUMMARY"
    exit 1
fi

log "RESULT: ALL PASS"
echo "RESULT: ALL PASS" >> "$SUMMARY"
exit 0
