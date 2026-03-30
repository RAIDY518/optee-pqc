#!/bin/bash
# memprof.sh — Day 10 memory profiling helper
#
# Patches TA_STACK_SIZE / TA_DATA_SIZE in user_ta_header_defines.h,
# with automatic backup and restore support.
#
# Usage:
#   ./memprof.sh --stack 64 --data 32      # set stack=64KB, data=32KB, rebuild TA
#   ./memprof.sh --stack 16                 # set stack=16KB only, keep current data
#   ./memprof.sh --data 8                   # set data=8KB only, keep current stack
#   ./memprof.sh --restore                  # restore original header from backup
#   ./memprof.sh --show                     # show current values without changing

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
HEADER="$SCRIPT_DIR/user_ta_header_defines.h"
BACKUP="$HEADER.memprof.bak"

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo ":: $*"; }

# ── Parse arguments ───────────────────────────────────────────────
STACK_KB=""
DATA_KB=""
DO_RESTORE=0
DO_SHOW=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stack)   STACK_KB="$2"; shift 2 ;;
        --data)    DATA_KB="$2";  shift 2 ;;
        --restore) DO_RESTORE=1;  shift   ;;
        --show)    DO_SHOW=1;     shift   ;;
        -h|--help)
            echo "Usage: $0 [--stack KB] [--data KB] [--restore] [--show]"
            exit 0 ;;
        *) die "unknown arg: $1" ;;
    esac
done

# ── Show current values ──────────────────────────────────────────
show_current() {
    local s d
    s=$(grep -oP 'TA_STACK_SIZE\s+\(\K[0-9]+' "$HEADER" || echo "?")
    d=$(grep -oP 'TA_DATA_SIZE\s+\(\K[0-9]+' "$HEADER" || echo "?")
    echo "  TA_STACK_SIZE = ${s} KB  ($(( s * 1024 )) bytes)"
    echo "  TA_DATA_SIZE  = ${d} KB  ($(( d * 1024 )) bytes)"
}

if [[ $DO_SHOW -eq 1 ]]; then
    info "Current header values:"
    show_current
    if [[ -f "$BACKUP" ]]; then
        info "Backup exists at: $BACKUP"
    else
        info "No backup file found."
    fi
    exit 0
fi

# ── Restore ──────────────────────────────────────────────────────
if [[ $DO_RESTORE -eq 1 ]]; then
    [[ -f "$BACKUP" ]] || die "no backup found at $BACKUP"
    cp "$BACKUP" "$HEADER"
    info "Restored original header from backup."
    show_current
    exit 0
fi

# ── Patch ────────────────────────────────────────────────────────
[[ -n "$STACK_KB" || -n "$DATA_KB" ]] || die "nothing to do (use --stack KB, --data KB, --restore, or --show)"

# Auto-backup before first patch
if [[ ! -f "$BACKUP" ]]; then
    cp "$HEADER" "$BACKUP"
    info "Backed up original header to $BACKUP"
fi

if [[ -n "$STACK_KB" ]]; then
    sed -i "s/^#define TA_STACK_SIZE.*/#define TA_STACK_SIZE\t\t\t(${STACK_KB} * 1024)/" "$HEADER"
    info "Set TA_STACK_SIZE = ${STACK_KB} KB"
fi

if [[ -n "$DATA_KB" ]]; then
    sed -i "s/^#define TA_DATA_SIZE.*/#define TA_DATA_SIZE\t\t\t(${DATA_KB} * 1024)/" "$HEADER"
    info "Set TA_DATA_SIZE = ${DATA_KB} KB"
fi

info "Current values after patch:"
show_current

# ── Rebuild TA ───────────────────────────────────────────────────
info "Rebuilding TA ..."
make -C "$SCRIPT_DIR" clean >/dev/null 2>&1 || true
make -C "$SCRIPT_DIR" 2>&1
BUILD_RC=$?

if [[ $BUILD_RC -eq 0 ]]; then
    info "TA build succeeded."
else
    info "TA build FAILED (exit $BUILD_RC) — this is a build_fail boundary."
fi

exit $BUILD_RC
