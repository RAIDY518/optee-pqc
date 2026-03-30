#!/bin/bash
# sizeprof.sh — Day 11: measure TA code size across 4 PQC configurations
#
# Usage:
#   ./sizeprof.sh              # build all 4 configs and print comparison table
#
# Requires: CROSS_COMPILE, TA_DEV_KIT_DIR set in environment.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
SUBMK="$SCRIPT_DIR/sub.mk"
SUBMK_ORIG="$SUBMK.sizeprof.bak"
UUID=49d90b2c-dcb4-4f62-8bdf-ce538fc14dca
ELF="$SCRIPT_DIR/$UUID.elf"
TA="$SCRIPT_DIR/$UUID.ta"
SIZE=${CROSS_COMPILE}size
READELF=${CROSS_COMPILE}readelf

die()  { echo "ERROR: $*" >&2; exit 1; }
info() { echo ":: $*"; }

[[ -n "${CROSS_COMPILE:-}" ]]   || die "CROSS_COMPILE not set"
[[ -n "${TA_DEV_KIT_DIR:-}" ]]  || die "TA_DEV_KIT_DIR not set"

# Save original sub.mk
cp "$SUBMK" "$SUBMK_ORIG"
trap 'cp "$SUBMK_ORIG" "$SUBMK"; rm -f "$SUBMK_ORIG"; info "Restored original sub.mk"' EXIT

# Common header for all sub.mk variants
COMMON='global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common
srcs-y += pqc_ping_ta.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c
'

# -- Generate sub.mk for each config --
gen_submk() {
    local config="$1"
    case "$config" in
        baseline)
            cat > "$SUBMK" <<'MK'
global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common
srcs-y += pqc_ping_ta.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c
MK
            ;;
        kem)
            cat > "$SUBMK" <<'MK'
global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common
cflags-y += -DPQC_ENABLE_KEM
srcs-y += pqc_ping_ta.c
srcs-y += cmd_kem.c
srcs-y += cmd_store.c
srcs-y += cmd_bench.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c
subdirs-y += pqclean/kem
MK
            ;;
        sig)
            cat > "$SUBMK" <<'MK'
global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common
cflags-y += -DPQC_ENABLE_SIG
srcs-y += pqc_ping_ta.c
srcs-y += cmd_sig.c
srcs-y += cmd_store.c
srcs-y += cmd_bench.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c
subdirs-y += pqclean/sig
MK
            ;;
        kem+sig)
            cat > "$SUBMK" <<'MK'
global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common
cflags-y += -DPQC_ENABLE_KEM
cflags-y += -DPQC_ENABLE_SIG
srcs-y += pqc_ping_ta.c
srcs-y += cmd_kem.c
srcs-y += cmd_sig.c
srcs-y += cmd_store.c
srcs-y += cmd_bench.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c
subdirs-y += pqclean/kem pqclean/sig
MK
            ;;
    esac
}

# -- Build and measure one config --
declare -A TEXT RODATA DATA BSS TASIZE

build_and_measure() {
    local config="$1"
    info "Building config: $config"

    gen_submk "$config"
    make -C "$SCRIPT_DIR" clean >/dev/null 2>&1 || true
    make -C "$SCRIPT_DIR" 2>&1 | grep -E '(error|warning:.*error)' && die "build failed for $config" || true

    if [[ ! -f "$ELF" ]]; then
        die "ELF not found after build: $ELF"
    fi

    # Extract section sizes via size -A (SysV format: section size addr)
    local text rodata data bss
    text=$($SIZE -A "$ELF"   | awk '/^\.text /   {print $2}')
    rodata=$($SIZE -A "$ELF" | awk '/^\.rodata / {print $2}')
    data=$($SIZE -A "$ELF"   | awk '/^\.data /   {print $2}')
    bss=$($SIZE -A "$ELF"    | awk '/^\.bss /    {print $2}')
    local ta_size=$(stat -c%s "$TA")

    TEXT[$config]=${text:-0}
    RODATA[$config]=${rodata:-0}
    DATA[$config]=${data:-0}
    BSS[$config]=${bss:-0}
    TASIZE[$config]=$ta_size

    info "$config: .text=${TEXT[$config]}  .rodata=${RODATA[$config]}  .data=${DATA[$config]}  .bss=${BSS[$config]}  .ta=${TASIZE[$config]}"
}

# -- Build all 4 configs --
for cfg in baseline kem sig kem+sig; do
    build_and_measure "$cfg"
done

# -- Print comparison table --
fmt_delta() {
    local val=$1 base=$2
    local delta=$((val - base))
    if [[ $delta -eq 0 ]]; then
        echo "—"
    else
        printf "+%d" "$delta"
    fi
}

echo ""
echo "============================================================"
echo "  Day 11 — TA Code Size Comparison (bytes)"
echo "============================================================"
printf "%-10s %8s %8s %8s %8s %8s\n" "Config" ".text" ".rodata" ".data" ".bss" ".ta file"
echo "------------------------------------------------------------"

for cfg in baseline kem sig kem+sig; do
    printf "%-10s %8d %8d %8d %8d %8d\n" \
        "$cfg" "${TEXT[$cfg]}" "${RODATA[$cfg]}" "${DATA[$cfg]}" "${BSS[$cfg]}" "${TASIZE[$cfg]}"
done

echo ""
echo "Delta vs baseline:"
echo "------------------------------------------------------------"
printf "%-10s %8s %8s %8s %8s %8s\n" "Config" ".text" ".rodata" ".data" ".bss" ".ta file"
echo "------------------------------------------------------------"

BT=${TEXT[baseline]}
BR=${RODATA[baseline]}
BD=${DATA[baseline]}
BB=${BSS[baseline]}
BF=${TASIZE[baseline]}

for cfg in kem sig kem+sig; do
    printf "%-10s %8s %8s %8s %8s %8s\n" \
        "$cfg" \
        "$(fmt_delta ${TEXT[$cfg]} $BT)" \
        "$(fmt_delta ${RODATA[$cfg]} $BR)" \
        "$(fmt_delta ${DATA[$cfg]} $BD)" \
        "$(fmt_delta ${BSS[$cfg]} $BB)" \
        "$(fmt_delta ${TASIZE[$cfg]} $BF)"
done

echo "============================================================"
echo ""

info "Done. Restored original sub.mk via trap."
