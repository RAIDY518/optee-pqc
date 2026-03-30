#include <err.h>
#include <inttypes.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bench.h"
#include "cmd_bench.h"

/*
 * Single helper drives all four micro-benchmark TA commands.
 *
 * TA protocol (3 params):
 *   params[0] VALUE_INPUT  : a=loop, b=warmup
 *   params[1] MEMREF_OUTPUT: loop×uint64_t — each entry is total_ms for
 *                            n_inner back-to-back primitive calls
 *   params[2] VALUE_OUTPUT : a = 1000*n_inner (pseudo-freq for conversion)
 *                            b = n_inner (batch size, for CSV annotation)
 *
 * Conversion: ns_per_op = total_ms * 1_000_000_000 / (1000 * n_inner)
 *                       = total_ms * 1_000_000 / n_inner
 * Resolution: 1 ms / n_inner  (10 µs for KEM, 200 µs for SIG on QEMU)
 */
static void run_micro(struct bench_ctx *ctx, uint32_t cmd, const char *name)
{
	TEEC_Operation op;
	TEEC_Result    res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
					 TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_VALUE_OUTPUT,
					 TEEC_NONE);
	op.params[0].value.a        = (uint32_t)ctx->loop;
	op.params[0].value.b        = (uint32_t)ctx->warmup;
	op.params[1].tmpref.buffer  = ctx->samples;
	op.params[1].tmpref.size    = (uint32_t)((size_t)ctx->loop
						  * sizeof(uint64_t));

	res = TEEC_InvokeCommand(ctx->sess, cmd, &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "%s failed 0x%x origin 0x%x", name, res, ctx->origin);

	uint32_t freq    = op.params[2].value.a; /* 1000 * n_inner */
	uint32_t n_inner = op.params[2].value.b; /* batch size */
	if (!freq) freq = 1000;

	/* Save raw batch_ms before conversion (for CSV) */
	uint64_t *raw_ms = NULL;
	if (ctx->csv) {
		raw_ms = malloc((size_t)ctx->loop * sizeof(uint64_t));
		if (raw_ms)
			memcpy(raw_ms, ctx->samples,
			       (size_t)ctx->loop * sizeof(uint64_t));
	}

	/* Convert total_ms → per-op nanoseconds in-place */
	for (int i = 0; i < ctx->loop; i++)
		ctx->samples[i] = ctx->samples[i] * 1000000000ULL / freq;

	/* CSV: rewrite header then emit rows */
	if (ctx->csv) {
		rewind(ctx->csv);
		fprintf(ctx->csv, "iter,cmd,delta_ns,raw_batch_ms,n_inner\n");
		for (int i = 0; i < ctx->loop; i++) {
			uint64_t rms = raw_ms ? raw_ms[i] : 0;
			fprintf(ctx->csv,
				"%d,%s,%" PRIu64 ",%" PRIu64 ",%u\n",
				i, name, ctx->samples[i], rms, n_inner);
		}
		free(raw_ms);
	}

	print_stats(ctx->samples, (size_t)ctx->loop, name);
}

void run_kem_keygen_micro(struct bench_ctx *ctx)
{
	run_micro(ctx, TA_PQC_PING_CMD_KEM_KEYGEN_MICRO, "kem-keygen-micro");
}

void run_kem_decaps_micro(struct bench_ctx *ctx)
{
	run_micro(ctx, TA_PQC_PING_CMD_KEM_DECAPS_MICRO, "kem-decaps-micro");
}

void run_sig_keygen_micro(struct bench_ctx *ctx)
{
	run_micro(ctx, TA_PQC_PING_CMD_SIG_KEYGEN_MICRO, "sig-keygen-micro");
}

void run_sig_sign_micro(struct bench_ctx *ctx)
{
	run_micro(ctx, TA_PQC_PING_CMD_SIG_SIGN_MICRO, "sig-sign-micro");
}
