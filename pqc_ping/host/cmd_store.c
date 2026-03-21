#include <err.h>
#include <stdio.h>
#include <string.h>

#include "bench.h"
#include "cmd_store.h"

static const char *key_status_str(uint32_t s)
{
	switch (s) {
	case 0: return "absent";
	case 1: return "memory-only";
	case 2: return "persisted-only";
	case 3: return "ready (memory + persisted)";
	default: return "unknown";
	}
}

/* Helper: invoke a no-param command (load/destroy). */
static void invoke_none(struct bench_ctx *ctx, uint32_t cmd, const char *name)
{
	TEEC_Operation op;
	TEEC_Result    res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_NONE, TEEC_NONE,
					 TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(ctx->sess, cmd, &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "%s failed 0x%x origin 0x%x", name, res, ctx->origin);
	printf("%s: OK\n", name);
}

/* Helper: invoke a keygen-save command (returns pk, prints pk_bytes). */
static void invoke_keygen_save(struct bench_ctx *ctx, uint32_t cmd,
			       void *pk_buf, uint32_t pk_size,
			       const char *name)
{
	TEEC_Operation op;
	TEEC_Result    res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	op.params[0].tmpref.buffer = pk_buf;
	op.params[0].tmpref.size   = pk_size;
	res = TEEC_InvokeCommand(ctx->sess, cmd, &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "%s failed 0x%x origin 0x%x", name, res, ctx->origin);
	printf("%s: OK (pk_bytes=%u)\n", name,
	       (unsigned)op.params[0].tmpref.size);
}

/* Helper: invoke a status command and print result. */
static void invoke_status(struct bench_ctx *ctx, uint32_t cmd,
			  const char *label)
{
	TEEC_Operation op;
	TEEC_Result    res;

	memset(&op, 0, sizeof(op));
	op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
					 TEEC_NONE, TEEC_NONE, TEEC_NONE);
	res = TEEC_InvokeCommand(ctx->sess, cmd, &op, &ctx->origin);
	if (res != TEEC_SUCCESS)
		errx(1, "%s-status failed 0x%x origin 0x%x",
		     label, res, ctx->origin);
	printf("%s status: %s (%u)\n",
	       label, key_status_str(op.params[0].value.a),
	       op.params[0].value.a);
}

void run_kem_keygen_save(struct bench_ctx *ctx)
{
	uint8_t pk[PQC_KEM_PUBLICKEYBYTES];
	invoke_keygen_save(ctx, TA_PQC_PING_CMD_KEM_KEYGEN_SAVE,
			   pk, sizeof(pk), "kem-keygen-save");
}

void run_kem_load(struct bench_ctx *ctx)
{
	invoke_none(ctx, TA_PQC_PING_CMD_KEM_LOAD, "kem-load");
}

void run_kem_status(struct bench_ctx *ctx)
{
	invoke_status(ctx, TA_PQC_PING_CMD_KEM_STATUS, "KEM");
}

void run_kem_destroy(struct bench_ctx *ctx)
{
	invoke_none(ctx, TA_PQC_PING_CMD_KEM_DESTROY, "kem-destroy");
}

void run_sig_keygen_save(struct bench_ctx *ctx)
{
	uint8_t pk[PQC_SIG_PUBLICKEYBYTES];
	invoke_keygen_save(ctx, TA_PQC_PING_CMD_SIG_KEYGEN_SAVE,
			   pk, sizeof(pk), "sig-keygen-save");
}

void run_sig_load(struct bench_ctx *ctx)
{
	invoke_none(ctx, TA_PQC_PING_CMD_SIG_LOAD, "sig-load");
}

void run_sig_status(struct bench_ctx *ctx)
{
	invoke_status(ctx, TA_PQC_PING_CMD_SIG_STATUS, "SIG");
}

void run_sig_destroy(struct bench_ctx *ctx)
{
	invoke_none(ctx, TA_PQC_PING_CMD_SIG_DESTROY, "sig-destroy");
}
