#include <err.h>
#include <inttypes.h>
#include <string.h>
#include <time.h>

#include "../ta/pqclean/sig/api.h"
#include "bench.h"
#include "cmd_sig.h"

static const uint8_t SIG_TEST_MSG[]  = "pqc-day6-test-message";
#define SIG_TEST_MSG_LEN (sizeof(SIG_TEST_MSG) - 1)

/* Helper: call TA SIG_KEYGEN and store pk in ctx->sig_pk. */
static void prebench_sig_keygen(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result    res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = ctx->sig_pk;
	op.params[0].tmpref.size   = PQC_SIG_PUBLICKEYBYTES;
	res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_KEYGEN,
				 &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "sig-keygen pre-bench failed 0x%x", res);
}

/* Helper: build the SIG_SIGN operation. */
static void setup_sig_sign_op(TEEC_Operation *op, struct bench_ctx *ctx)
{
	memset(op, 0, sizeof(*op));
	op->paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
					  TEEC_MEMREF_TEMP_OUTPUT,
					  TEEC_NONE, TEEC_NONE);
	op->params[0].tmpref.buffer = (void *)SIG_TEST_MSG;
	op->params[0].tmpref.size   = SIG_TEST_MSG_LEN;
	op->params[1].tmpref.buffer = ctx->sig_buf;
	op->params[1].tmpref.size   = PQC_SIG_BYTES;
}

void run_sig_keygen(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result    res;

	for (int i = 0; i < ctx->warmup; i++) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ctx->sig_pk;
		op.params[0].tmpref.size   = PQC_SIG_PUBLICKEYBYTES;
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_KEYGEN,
					 &op, &ctx->origin);
		if (res != TEEC_SUCCESS)
			errx(1, "sig-keygen warmup failed 0x%x", res);
	}

	for (int i = 0; i < ctx->loop; i++) {
		struct timespec t1, t2;

		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = ctx->sig_pk;
		op.params[0].tmpref.size   = PQC_SIG_PUBLICKEYBYTES;

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_KEYGEN,
					 &op, &ctx->origin);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		if (res != TEEC_SUCCESS)
			errx(1, "sig-keygen invoke failed 0x%x", res);

		ctx->samples[i] = diff_ns(&t1, &t2);
		if (ctx->csv)
			fprintf(ctx->csv, "%d,sig-keygen,%" PRIu64 ",1\n",
				i, ctx->samples[i]);
	}

	print_stats(ctx->samples, (size_t)ctx->loop, "SIG-KEYGEN");
}

void run_sig_sign(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result    res;

	prebench_sig_keygen(ctx);

	for (int i = 0; i < ctx->warmup; i++) {
		setup_sig_sign_op(&op, ctx);
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
					 &op, &ctx->origin);
		if (res != TEEC_SUCCESS)
			errx(1, "sig-sign warmup failed 0x%x", res);
	}

	for (int i = 0; i < ctx->loop; i++) {
		struct timespec t1, t2;

		setup_sig_sign_op(&op, ctx);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
					 &op, &ctx->origin);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		if (res != TEEC_SUCCESS)
			errx(1, "sig-sign invoke failed 0x%x", res);

		ctx->samples[i] = diff_ns(&t1, &t2);
		if (ctx->csv)
			fprintf(ctx->csv, "%d,sig-sign,%" PRIu64 ",1\n",
				i, ctx->samples[i]);
	}

	print_stats(ctx->samples, (size_t)ctx->loop, "SIG-SIGN");
}

void run_sig_crosstest(struct bench_ctx *ctx)
{
	TEEC_Operation op;
	TEEC_Result    res;

	prebench_sig_keygen(ctx);

	/* Warmup */
	for (int i = 0; i < ctx->warmup; i++) {
		setup_sig_sign_op(&op, ctx);
		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
					 &op, &ctx->origin);
		if (res != TEEC_SUCCESS)
			errx(1, "sig-crosstest warmup failed 0x%x", res);
	}

	/* Measured loop */
	for (int i = 0; i < ctx->loop; i++) {
		struct timespec t1, t2;
		size_t siglen;

		setup_sig_sign_op(&op, ctx);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);

		res = TEEC_InvokeCommand(ctx->sess, TA_PQC_PING_CMD_SIG_SIGN,
					 &op, &ctx->origin);
		if (res != TEEC_SUCCESS)
			errx(1, "sig-crosstest sign failed 0x%x", res);

		siglen = op.params[1].tmpref.size;
		int vret = PQCLEAN_MLDSA44_CLEAN_crypto_sign_verify(
				ctx->sig_buf, siglen,
				SIG_TEST_MSG, SIG_TEST_MSG_LEN,
				ctx->sig_pk);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		ctx->samples[i] = diff_ns(&t1, &t2);
		uint32_t pass = (vret == 0) ? 1 : 0;
		if (!pass)
			ctx->fail_count++;

		if (ctx->csv)
			fprintf(ctx->csv, "%d,sig-crosstest,%" PRIu64 ",%u\n",
				i, ctx->samples[i], pass);
	}

	print_stats(ctx->samples, (size_t)ctx->loop, "SIG-CROSSTEST");
	printf("  pass  = %u/%d\n",
	       (unsigned)(ctx->loop - ctx->fail_count), ctx->loop);
}
