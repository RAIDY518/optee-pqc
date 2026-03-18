/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Stub for normal-world builds: maps TEE primitives used by vendored
 * PQClean common sources (fips202.c) to libc equivalents.
 */
#ifndef TEE_INTERNAL_API_H
#define TEE_INTERNAL_API_H

#include <stdint.h>
#include <stdlib.h>

static inline void TEE_Panic(uint32_t code) { (void)code; abort(); }

#endif /* TEE_INTERNAL_API_H */
