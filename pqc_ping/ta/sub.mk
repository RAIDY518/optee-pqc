global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common

# Algorithm selection flags (comment out to disable)
cflags-y += -DPQC_ENABLE_KEM
cflags-y += -DPQC_ENABLE_SIG

# Core TA sources (always built)
srcs-y += pqc_ping_ta.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c

# KEM sources
ifneq ($(filter -DPQC_ENABLE_KEM,$(cflags-y)),)
srcs-y += cmd_kem.c
subdirs-y += pqclean/kem
endif

# SIG sources
ifneq ($(filter -DPQC_ENABLE_SIG,$(cflags-y)),)
srcs-y += cmd_sig.c
subdirs-y += pqclean/sig
endif

# Shared sources (needed by either KEM or SIG)
ifneq ($(filter -DPQC_ENABLE_KEM -DPQC_ENABLE_SIG,$(cflags-y)),)
srcs-y += cmd_store.c
srcs-y += cmd_bench.c
endif