// SPDX-License-Identifier: BSD-2-Clause
/*
 * Day 12 — malformed-input hardening tests.
 *
 * Each sub-test sends a deliberately bad request to the TA and verifies
 * that the TA returns a controlled error (no crash, no panic, no hang).
 */
#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include <tee_client_api.h>
#include <pqc_ping_ta.h>

#include "../ta/pqclean/kem/api.h"
#include "../ta/pqclean/sig/api.h"
#include "bench.h"
#include "cmd_harden.h"

/* Size constants (host side) */
#define H_KEM_PK   PQCLEAN_MLKEM512_CLEAN_CRYPTO_PUBLICKEYBYTES
#define H_KEM_CT   PQCLEAN_MLKEM512_CLEAN_CRYPTO_CIPHERTEXTBYTES
#define H_KEM_SS   PQCLEAN_MLKEM512_CLEAN_CRYPTO_BYTES
#define H_SIG_PK   PQCLEAN_MLDSA44_CLEAN_CRYPTO_PUBLICKEYBYTES
#define H_SIG_BYTES PQCLEAN_MLDSA44_CLEAN_CRYPTO_BYTES

static int pass_count;
static int fail_count;

static void check(const char *name, TEEC_Result res, TEEC_Result expected)
{
	int ok = (res == expected);
	printf("  %-35s %s  (got 0x%x, want 0x%x)\n",
	       name, ok ? "PASS" : "FAIL", res, expected);
	if (ok) pass_count++; else fail_count++;
}

/* Helper: invoke with given param types and expect a specific result. */
static TEEC_Result invoke(TEEC_Session *sess, uint32_t cmd,
			  TEEC_Operation *op, uint32_t *origin)
{
	return TEEC_InvokeCommand(sess, cmd, op, origin);
}

/* --- KEM init: generate session key for subsequent tests --- */
static void kem_init(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->kem_pk;
	op.params[0].tmpref.size   = H_KEM_PK;
	TEEC_Result res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_INIT,
				 &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "harden: kem-init failed 0x%x", res);
}

/* --- SIG keygen: generate session key for subsequent tests --- */
static void sig_init(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->sig_pk;
	op.params[0].tmpref.size   = H_SIG_PK;
	TEEC_Result res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_KEYGEN,
				 &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "harden: sig-keygen failed 0x%x", res);
}

void run_harden_test(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result res;

	pass_count = 0;
	fail_count = 0;

	printf("=== Day 12 hardening tests ===\n\n");

	/* ---- KEM tests ------------------------------------------------ */
	printf("[KEM malformed-input]\n");

	kem_init(ctx);

	/* 1. Short ciphertext (half size) */
	{
		uint8_t short_ct[H_KEM_CT / 2];
		uint8_t ss[H_KEM_SS];
		memset(short_ct, 0xAA, sizeof(short_ct));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = short_ct;
		op.params[0].tmpref.size   = sizeof(short_ct);
		op.params[1].tmpref.buffer = ss;
		op.params[1].tmpref.size   = H_KEM_SS;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
			     &op, &ctx->origin);
		check("short ciphertext", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 2. Oversized ciphertext */
	{
		uint8_t big_ct[H_KEM_CT + 64];
		uint8_t ss[H_KEM_SS];
		memset(big_ct, 0xBB, sizeof(big_ct));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = big_ct;
		op.params[0].tmpref.size   = sizeof(big_ct);
		op.params[1].tmpref.buffer = ss;
		op.params[1].tmpref.size   = H_KEM_SS;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
			     &op, &ctx->origin);
		check("oversized ciphertext", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 3. Wrong param types to KEM_DEC_HOST */
	{
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].value.a = 42;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
			     &op, &ctx->origin);
		check("wrong param types (KEM)", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 4. KEM decaps without session key (use-after-destroy) */
	{
		/* Destroy session key first */
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DESTROY,
		       &op, &ctx->origin);

		/* Now try to decaps — should fail with BAD_STATE */
		uint8_t ct[H_KEM_CT];
		uint8_t ss[H_KEM_SS];
		memset(ct, 0, sizeof(ct));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ct;
		op.params[0].tmpref.size   = H_KEM_CT;
		op.params[1].tmpref.buffer = ss;
		op.params[1].tmpref.size   = H_KEM_SS;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
			     &op, &ctx->origin);
		check("use-after-destroy (KEM)", res, TEEC_ERROR_BAD_STATE);
	}

	/* ---- SIG tests ------------------------------------------------ */
	printf("\n[SIG malformed-input]\n");

	sig_init(ctx);

	/* 5. Empty message */
	{
		uint8_t sig[H_SIG_BYTES];
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = (void *)"";
		op.params[0].tmpref.size   = 0;
		op.params[1].tmpref.buffer = sig;
		op.params[1].tmpref.size   = H_SIG_BYTES;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
			     &op, &ctx->origin);
		check("empty message", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 6. Oversized message (> 4096) */
	{
		uint8_t big_msg[4097];
		uint8_t sig[H_SIG_BYTES];
		memset(big_msg, 'X', sizeof(big_msg));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = big_msg;
		op.params[0].tmpref.size   = sizeof(big_msg);
		op.params[1].tmpref.buffer = sig;
		op.params[1].tmpref.size   = H_SIG_BYTES;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
			     &op, &ctx->origin);
		check("oversized message (4097)", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 7. Wrong param types to SIG_SIGN */
	{
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].value.a = 42;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
			     &op, &ctx->origin);
		check("wrong param types (SIG)", res, TEEC_ERROR_BAD_PARAMETERS);
	}

	/* 8. SIG sign without session key (use-after-destroy) */
	{
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
						 TEEC_NONE, TEEC_NONE);
		invoke(ctx->sess, TA_PQC_PING_CMD_SIG_DESTROY,
		       &op, &ctx->origin);

		uint8_t sig[H_SIG_BYTES];
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = (void *)"test";
		op.params[0].tmpref.size   = 4;
		op.params[1].tmpref.buffer = sig;
		op.params[1].tmpref.size   = H_SIG_BYTES;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
			     &op, &ctx->origin);
		check("use-after-destroy (SIG)", res, TEEC_ERROR_BAD_STATE);
	}

	/* ---- Normal paths still work ---------------------------------- */
	printf("\n[Normal paths after hardening]\n");

	/* 9. KEM crosstest (re-init + one round) */
	{
		kem_init(ctx);
		uint8_t ct[H_KEM_CT], ss_host[H_KEM_SS], ss_ta[H_KEM_SS];
		PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(ct, ss_host, ctx->kem_pk);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ct;
		op.params[0].tmpref.size   = H_KEM_CT;
		op.params[1].tmpref.buffer = ss_ta;
		op.params[1].tmpref.size   = H_KEM_SS;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
			     &op, &ctx->origin);
		int match = (res == TEEC_SUCCESS &&
			     memcmp(ss_host, ss_ta, H_KEM_SS) == 0);
		check("kem-crosstest round", match ? TEEC_SUCCESS : (TEEC_Result)1,
		      TEEC_SUCCESS);
		memset(ss_host, 0, sizeof(ss_host));
		memset(ss_ta, 0, sizeof(ss_ta));
	}

	/* 10. SIG crosstest (re-init + one round) */
	{
		sig_init(ctx);
		static const uint8_t msg[] = "harden-test-msg";
		uint8_t sig[H_SIG_BYTES];

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = (void *)msg;
		op.params[0].tmpref.size   = sizeof(msg) - 1;
		op.params[1].tmpref.buffer = sig;
		op.params[1].tmpref.size   = H_SIG_BYTES;
		res = invoke(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
			     &op, &ctx->origin);
		if (res != TEEC_SUCCESS) {
			check("sig-crosstest round", res, TEEC_SUCCESS);
		} else {
			size_t siglen = op.params[1].tmpref.size;
			int vret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
					sig, siglen, msg, sizeof(msg) - 1,
					ctx->sig_pk);
			check("sig-crosstest round",
			      vret == 0 ? TEEC_SUCCESS : (TEEC_Result)1,
			      TEEC_SUCCESS);
		}
	}

	printf("\n=== Results: %d passed, %d failed ===\n",
	       pass_count, fail_count);
}
