#include <err.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "../ta/pqclean/kem/api.h"
#include "bench.h"
#include "cmd_kem.h"

void setup_kem_op(TEEC_Operation *op, int cmd,
		  uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss)
{
	memset(op, 0, sizeof(*op));
	switch (cmd) {
	case TA_PQC_PING_CMD_PING:
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INOUT,
						  TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op->params[0].value.a = 41;
		break;
	case TA_PQC_PING_CMD_KEM_SELFTEST:
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
						  TEEC_NONE, TEEC_NONE, TEEC_NONE);
		break;
	case TA_PQC_PING_CMD_KEM_KEYGEN:
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE, TEEC_NONE);
		op->params[0].tmpref.buffer = pk;
		op->params[0].tmpref.size   = PQC_KEM_PUBLICKEYBYTES;
		op->params[1].tmpref.buffer = sk;
		op->params[1].tmpref.size   = PQC_KEM_SECRETKEYBYTES;
		break;
	case TA_PQC_PING_CMD_KEM_ENCAPS:
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE);
		op->params[0].tmpref.buffer = pk;
		op->params[0].tmpref.size   = PQC_KEM_PUBLICKEYBYTES;
		op->params[1].tmpref.buffer = ct;
		op->params[1].tmpref.size   = PQC_KEM_CIPHERTEXTBYTES;
		op->params[2].tmpref.buffer = ss;
		op->params[2].tmpref.size   = PQC_KEM_SHARED_BYTES;
		break;
	case TA_PQC_PING_CMD_KEM_DECAPS:
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_INPUT,
						  TEEC_MEMREF_TEMP_OUTPUT,
						  TEEC_NONE);
		op->params[0].tmpref.buffer = sk;
		op->params[0].tmpref.size   = PQC_KEM_SECRETKEYBYTES;
		op->params[1].tmpref.buffer = ct;
		op->params[1].tmpref.size   = PQC_KEM_CIPHERTEXTBYTES;
		op->params[2].tmpref.buffer = ss;
		op->params[2].tmpref.size   = PQC_KEM_SHARED_BYTES;
		break;
	default: /* empty */
		op->paramTypes = TEEC_PARAM_TYPES(TEEC_NONE,
						  TEEC_NONE, TEEC_NONE, TEEC_NONE);
		break;
	}
}

void run_kem_crosstest(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result    res;

	/* Pre-bench: TA keygen; sk stays in session, pk returned here */
	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->kem_pk;
	op.params[0].tmpref.size   = PQC_KEM_PUBLICKEYBYTES;
	res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_KEM_INIT,
				 &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "kem-init failed 0x%x origin 0x%x", res, ctx->origin);

	/* Warmup */
	for (int i = 0; i < ctx->warmup; i++) {
		PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
			ctx->cross_ct, ctx->cross_ss_host, ctx->kem_pk);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ctx->cross_ct;
		op.params[0].tmpref.size   = PQC_KEM_CIPHERTEXTBYTES;
		op.params[1].tmpref.buffer = ctx->cross_ss_ta;
		op.params[1].tmpref.size   = PQC_KEM_SHARED_BYTES;
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
					 &op, &ctx->origin);
		if (res != TEEC_SUCCESS)
			errx(1, "warmup kem-crosstest failed 0x%x", res);
	}

	/* Measured loop */
	for (int i = 0; i < ctx->loop; i++) {
		struct timespec t1, t2;

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

		PQCLEAN_MLKEM512_CLEAN_crypto_kem_enc(
			ctx->cross_ct, ctx->cross_ss_host, ctx->kem_pk);

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ctx->cross_ct;
		op.params[0].tmpref.size   = PQC_KEM_CIPHERTEXTBYTES;
		op.params[1].tmpref.buffer = ctx->cross_ss_ta;
		op.params[1].tmpref.size   = PQC_KEM_SHARED_BYTES;
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_KEM_DEC_HOST,
					 &op, &ctx->origin);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		if (res != TEEC_SUCCESS)
			errx(1, "kem-crosstest invoke failed 0x%x", res);

		ctx->samples[i] = diff_ns(&t1, &t2);

		uint32_t pass = (memcmp(ctx->cross_ss_host, ctx->cross_ss_ta,
					PQC_KEM_SHARED_BYTES) == 0) ? 1 : 0;
		if (!pass)
			ctx->fail_count++;

		if (ctx->csv)
			fprintf(ctx->csv, "%d,kem-crosstest,%" PRIu64 ",%u\n",
				i, ctx->samples[i], pass);
	}

	print_stats(ctx->samples, (size_t)ctx->loop, "KEM-CROSSTEST");
	printf("  pass  = %u/%d\n",
	       (unsigned)(ctx->loop - ctx->fail_count), ctx->loop);
}
