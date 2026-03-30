// SPDX-License-Identifier: BSD-2-Clause
#include <tee_internal_api.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"

/*
 * Timer: TEE_GetSystemTime() — 1 ms granularity, always safe from S-EL0.
 * (cntvct_el0 causes a synchronous abort in this OP-TEE build because
 *  CNTKCTL_EL1.EL0VCTEN is not set; raw cycle counts are unavailable.)
 *
 * Resolution strategy: each outer sample times N_INNER back-to-back calls.
 * The host receives ticks[i] = total_ms_for_N_INNER_calls and
 * params[2].value.a = 1000 * N_INNER, so the standard formula
 *   ns = ticks * 1_000_000_000 / freq
 * yields per-operation nanoseconds with ~(1ms / N_INNER) resolution.
 *
 * N_INNER values chosen so that one outer sample ≈ 50–500 ms on QEMU:
 *   KEM keygen / decaps : N_INNER = 100  →  ~10 µs resolution
 *   SIG keygen / sign   : N_INNER =   5  →  ~200 µs resolution
 */
#define N_INNER_KEM  100u
#define N_INNER_SIG    5u

static inline uint64_t now_ms(void)
{
	TEE_Time t;
	TEE_GetSystemTime(&t);
	return (uint64_t)t.seconds * 1000 + t.millis;
}

TEE_Result ta_cmd_bench(uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[4])
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INPUT,
				       TEE_PARAM_TYPE_MEMREF_OUTPUT,
				       TEE_PARAM_TYPE_VALUE_OUTPUT,
				       TEE_PARAM_TYPE_NONE);
	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	uint32_t  loop   = params[0].value.a;
	uint32_t  warmup = params[0].value.b;
	uint64_t *ticks  = (uint64_t *)params[1].memref.buffer;

	if (!loop || loop > 10000)
		return TEE_ERROR_BAD_PARAMETERS;
	if (params[1].memref.size < loop * sizeof(uint64_t))
		return TEE_ERROR_SHORT_BUFFER;

	/* Determine inner-loop count and tell the host */
	uint32_t n_inner = (cmd_id == TA_PQC_PING_CMD_KEM_KEYGEN_MICRO ||
			    cmd_id == TA_PQC_PING_CMD_KEM_DECAPS_MICRO)
				? N_INNER_KEM : N_INNER_SIG;

	/* freq = 1000 * n_inner  →  ns = total_ms * 1e9 / (1000*n_inner)
	 *                              = total_ms * 1e6 / n_inner            */
	params[2].value.a = 1000u * n_inner;
	params[2].value.b = n_inner; /* informational */

	switch (cmd_id) {

#ifdef PQC_ENABLE_KEM
	/* ---- ML-KEM-512 keygen ----------------------------------------- */
	case TA_PQC_PING_CMD_KEM_KEYGEN_MICRO:
	{
		uint8_t *pk = TEE_Malloc(TEE_PQC_KEM_PUBLICKEYBYTES, 0);
		uint8_t *sk = TEE_Malloc(TEE_PQC_KEM_SECRETKEYBYTES, 0);
		if (!pk || !sk) {
			TEE_Free(pk); TEE_Free(sk);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* Warmup: single iterations, not batched */
		for (uint32_t w = 0; w < warmup; w++)
			TEE_PQC_KEM_KEYPAIR(pk, sk);

		/* Measured: each sample = n_inner consecutive keypairs */
		for (uint32_t i = 0; i < loop; i++) {
			uint64_t t0 = now_ms();
			for (uint32_t j = 0; j < n_inner; j++)
				TEE_PQC_KEM_KEYPAIR(pk, sk);
			ticks[i] = now_ms() - t0;
		}
		TEE_MemFill(sk, 0, TEE_PQC_KEM_SECRETKEYBYTES);
		TEE_Free(pk);
		TEE_Free(sk);
		break;
	}

	/* ---- ML-KEM-512 decaps ----------------------------------------- */
	case TA_PQC_PING_CMD_KEM_DECAPS_MICRO:
	{
		uint8_t *pk = TEE_Malloc(TEE_PQC_KEM_PUBLICKEYBYTES,  0);
		uint8_t *sk = TEE_Malloc(TEE_PQC_KEM_SECRETKEYBYTES,  0);
		uint8_t *ct = TEE_Malloc(TEE_PQC_KEM_CIPHERTEXTBYTES, 0);
		uint8_t *ss = TEE_Malloc(TEE_PQC_KEM_BYTES,            0);
		if (!pk || !sk || !ct || !ss) {
			TEE_Free(pk); TEE_Free(sk);
			TEE_Free(ct); TEE_Free(ss);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* Setup: one keypair + one encaps — not timed */
		TEE_PQC_KEM_KEYPAIR(pk, sk);
		TEE_PQC_KEM_ENCAPS(ct, ss, pk);

		for (uint32_t w = 0; w < warmup; w++)
			TEE_PQC_KEM_DECAPS(ss, ct, sk);

		for (uint32_t i = 0; i < loop; i++) {
			uint64_t t0 = now_ms();
			for (uint32_t j = 0; j < n_inner; j++)
				TEE_PQC_KEM_DECAPS(ss, ct, sk);
			ticks[i] = now_ms() - t0;
		}
		TEE_MemFill(sk, 0, TEE_PQC_KEM_SECRETKEYBYTES);
		TEE_MemFill(ss, 0, TEE_PQC_KEM_BYTES);
		TEE_Free(pk); TEE_Free(sk);
		TEE_Free(ct); TEE_Free(ss);
		break;
	}

#endif /* PQC_ENABLE_KEM */

#ifdef PQC_ENABLE_SIG
	/* ---- ML-DSA-44 keygen ------------------------------------------ */
	case TA_PQC_PING_CMD_SIG_KEYGEN_MICRO:
	{
		uint8_t *pk = TEE_Malloc(TEE_PQC_SIG_PUBLICKEYBYTES, 0);
		uint8_t *sk = TEE_Malloc(TEE_PQC_SIG_SECRETKEYBYTES, 0);
		if (!pk || !sk) {
			TEE_Free(pk); TEE_Free(sk);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		for (uint32_t w = 0; w < warmup; w++)
			TEE_PQC_SIG_KEYPAIR(pk, sk);

		for (uint32_t i = 0; i < loop; i++) {
			uint64_t t0 = now_ms();
			for (uint32_t j = 0; j < n_inner; j++)
				TEE_PQC_SIG_KEYPAIR(pk, sk);
			ticks[i] = now_ms() - t0;
		}
		TEE_MemFill(sk, 0, TEE_PQC_SIG_SECRETKEYBYTES);
		TEE_Free(pk);
		TEE_Free(sk);
		break;
	}

	/* ---- ML-DSA-44 sign -------------------------------------------- */
	case TA_PQC_PING_CMD_SIG_SIGN_MICRO:
	{
		static const uint8_t msg[] = "pqc-day8-bench-msg";
		uint8_t *pk  = TEE_Malloc(TEE_PQC_SIG_PUBLICKEYBYTES, 0);
		uint8_t *sk  = TEE_Malloc(TEE_PQC_SIG_SECRETKEYBYTES, 0);
		uint8_t *sig = TEE_Malloc(TEE_PQC_SIG_BYTES,           0);
		if (!pk || !sk || !sig) {
			if (sk) TEE_MemFill(sk, 0, TEE_PQC_SIG_SECRETKEYBYTES);
			TEE_Free(pk); TEE_Free(sk); TEE_Free(sig);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		/* Setup: one keypair — not timed */
		TEE_PQC_SIG_KEYPAIR(pk, sk);

		size_t siglen;
		for (uint32_t w = 0; w < warmup; w++) {
			siglen = TEE_PQC_SIG_BYTES;
			TEE_PQC_SIG_SIGN(sig, &siglen, msg, sizeof(msg) - 1, sk);
		}

		for (uint32_t i = 0; i < loop; i++) {
			uint64_t t0 = now_ms();
			for (uint32_t j = 0; j < n_inner; j++) {
				siglen = TEE_PQC_SIG_BYTES;
				TEE_PQC_SIG_SIGN(sig, &siglen,
						 msg, sizeof(msg) - 1, sk);
			}
			ticks[i] = now_ms() - t0;
		}
		TEE_MemFill(sk, 0, TEE_PQC_SIG_SECRETKEYBYTES);
		TEE_Free(pk); TEE_Free(sk); TEE_Free(sig);
		break;
	}

#endif /* PQC_ENABLE_SIG */

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}

	params[1].memref.size = loop * sizeof(uint64_t);
	return TEE_SUCCESS;
}
