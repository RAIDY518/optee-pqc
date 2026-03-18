global-incdirs-y += include
global-incdirs-y += .
global-incdirs-y += pqclean/common

srcs-y += pqc_ping_ta.c
srcs-y += cmd_kem.c
srcs-y += cmd_sig.c
srcs-y += pqclean/common/randombytes.c
srcs-y += pqclean/common/fips202.c

subdirs-y += pqclean/kem pqclean/sig