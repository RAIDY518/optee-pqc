#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>
#include <pqc_ping_ta.h>

#define DEFAULT_LOOP   100
#define DEFAULT_WARMUP 10

static int cmp_u64(const void *a, const void *b)
{
	uint64_t x = *(const uint64_t *)a;
	uint64_t y = *(const uint64_t *)b;
	return (x > y) - (x < y);
}

static uint64_t diff_ns(const struct timespec *s, const struct timespec *e)
{
	return (uint64_t)(e->tv_sec - s->tv_sec) * 1000000000ULL +
	       (uint64_t)(e->tv_nsec - s->tv_nsec);
}

static void print_stats(uint64_t *arr, size_t n, const char *tag)
{
	uint64_t min = arr[0], max = arr[0];
	__uint128_t sum = 0;

	for (size_t i = 0; i < n; i++) {
		if (arr[i] < min) min = arr[i];
		if (arr[i] > max) max = arr[i];
		sum += arr[i];
	}

	qsort(arr, n, sizeof(arr[0]), cmp_u64);

	uint64_t p50 = arr[(size_t)(0.50 * (n - 1))];
	uint64_t p95 = arr[(size_t)(0.95 * (n - 1))];
	uint64_t p99 = arr[(size_t)(0.99 * (n - 1))];
	double avg = (double)sum / (double)n;

	printf("[%s] n=%zu\n", tag, n);
	printf("  min   = %" PRIu64 " ns\n", min);
	printf("  avg   = %.2f ns\n", avg);
	printf("  p50   = %" PRIu64 " ns\n", p50);
	printf("  p95   = %" PRIu64 " ns\n", p95);
	printf("  p99   = %" PRIu64 " ns\n", p99);
	printf("  max   = %" PRIu64 " ns\n", max);
}

/* Fill op for a single benchmark invocation of cmd. */
static void setup_op(TEEC_Operation *op, int cmd,
		     uint8_t *pk, uint8_t *sk,
		     uint8_t *ct, uint8_t *ss)
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

int main(int argc, char *argv[])
{
	TEEC_Result res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	uint32_t origin;
	TEEC_UUID uuid = TA_PQC_PING_UUID;

	int cmd = TA_PQC_PING_CMD_PING;
	int loop = DEFAULT_LOOP;
	int warmup = DEFAULT_WARMUP;
	const char *csv_path = NULL;
	uint32_t fail_count = 0;

	/* KEM key/ciphertext buffers (used by keygen/encaps/decaps commands) */
	uint8_t kem_pk[PQC_KEM_PUBLICKEYBYTES];
	uint8_t kem_sk[PQC_KEM_SECRETKEYBYTES];
	uint8_t kem_ct[PQC_KEM_CIPHERTEXTBYTES];
	uint8_t kem_ss[PQC_KEM_SHARED_BYTES];

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--cmd") && i + 1 < argc) {
			i++;
			if (!strcmp(argv[i], "empty"))
				cmd = TA_PQC_PING_CMD_EMPTY;
			else if (!strcmp(argv[i], "ping"))
				cmd = TA_PQC_PING_CMD_PING;
			else if (!strcmp(argv[i], "info"))
				cmd = TA_PQC_PING_CMD_INFO;
			else if (!strcmp(argv[i], "kem-selftest"))
				cmd = TA_PQC_PING_CMD_KEM_SELFTEST;
			else if (!strcmp(argv[i], "kem-keygen"))
				cmd = TA_PQC_PING_CMD_KEM_KEYGEN;
			else if (!strcmp(argv[i], "kem-encaps"))
				cmd = TA_PQC_PING_CMD_KEM_ENCAPS;
			else if (!strcmp(argv[i], "kem-decaps"))
				cmd = TA_PQC_PING_CMD_KEM_DECAPS;
			else
				errx(1, "unknown --cmd: %s", argv[i]);
		} else if (!strcmp(argv[i], "--loop") && i + 1 < argc) {
			loop = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) {
			warmup = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
			csv_path = argv[++i];
		} else {
			errx(1, "usage: %s [--cmd empty|ping|info|kem-selftest|kem-keygen|kem-encaps|kem-decaps]"
				" [--loop N] [--warmup M] [--csv path]", argv[0]);
		}
	}

	if (loop <= 0 || warmup < 0)
		errx(1, "bad loop/warmup");

	uint64_t *samples = calloc((size_t)loop, sizeof(uint64_t));
	if (!samples)
		errx(1, "calloc failed");

	FILE *csv = NULL;
	if (csv_path) {
		csv = fopen(csv_path, "w");
		if (!csv)
			err(1, "fopen csv");
		fprintf(csv, "iter,cmd,delta_ns,pass\n");
	}

	res = TEEC_InitializeContext(NULL, &ctx);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_InitializeContext failed 0x%x", res);

	res = TEEC_OpenSession(&ctx, &sess, &uuid, TEEC_LOGIN_PUBLIC,
			       NULL, NULL, &origin);
	if (res != TEEC_SUCCESS)
		errx(1, "TEEC_OpenSession failed 0x%x origin 0x%x", res, origin);

	/* --cmd info: one-shot, not benchmarked */
	if (cmd == TA_PQC_PING_CMD_INFO) {
		struct pqc_info_out info;

		memset(&info, 0, sizeof(info));
		memset(&op, 0, sizeof(op));

		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = &info;
		op.params[0].tmpref.size   = sizeof(info);

		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "info invoke failed 0x%x origin 0x%x", res, origin);

		printf("KEM pk=%" PRIu32 " sk=%" PRIu32 " ct=%" PRIu32 " ss=%" PRIu32 "\n",
		       info.kem_pk, info.kem_sk, info.kem_ct, info.kem_ss);
		printf("SIG pk=%" PRIu32 " sk=%" PRIu32 " sig=%" PRIu32 "\n",
		       info.sig_pk, info.sig_sk, info.sig_sig);

		TEEC_CloseSession(&sess);
		TEEC_FinalizeContext(&ctx);
		free(samples);
		return 0;
	}

	/*
	 * Pre-bench setup for encaps/decaps: generate one keypair (and one
	 * ciphertext for decaps) that will be reused across all iterations.
	 * This way the loop measures only the target operation.
	 */
	if (cmd == TA_PQC_PING_CMD_KEM_ENCAPS ||
	    cmd == TA_PQC_PING_CMD_KEM_DECAPS) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = kem_pk;
		op.params[0].tmpref.size   = sizeof(kem_pk);
		op.params[1].tmpref.buffer = kem_sk;
		op.params[1].tmpref.size   = sizeof(kem_sk);
		res = TEEC_InvokeCommand(&sess, TA_PQC_PING_CMD_KEM_KEYGEN,
					 &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "pre-bench keygen failed 0x%x origin 0x%x",
			     res, origin);
	}

	if (cmd == TA_PQC_PING_CMD_KEM_DECAPS) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE);
		op.params[0].tmpref.buffer = kem_pk;
		op.params[0].tmpref.size   = sizeof(kem_pk);
		op.params[1].tmpref.buffer = kem_ct;
		op.params[1].tmpref.size   = sizeof(kem_ct);
		op.params[2].tmpref.buffer = kem_ss;
		op.params[2].tmpref.size   = sizeof(kem_ss);
		res = TEEC_InvokeCommand(&sess, TA_PQC_PING_CMD_KEM_ENCAPS,
					 &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "pre-bench encaps failed 0x%x origin 0x%x",
			     res, origin);
	}

	/* Warmup */
	for (int i = 0; i < warmup; i++) {
		setup_op(&op, cmd, kem_pk, kem_sk, kem_ct, kem_ss);
		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "warmup invoke failed 0x%x origin 0x%x",
			     res, origin);
	}

	/* Measured loop */
	const char *cmd_str;
	switch (cmd) {
	case TA_PQC_PING_CMD_EMPTY:        cmd_str = "empty";        break;
	case TA_PQC_PING_CMD_KEM_SELFTEST: cmd_str = "kem-selftest"; break;
	case TA_PQC_PING_CMD_KEM_KEYGEN:   cmd_str = "kem-keygen";   break;
	case TA_PQC_PING_CMD_KEM_ENCAPS:   cmd_str = "kem-encaps";   break;
	case TA_PQC_PING_CMD_KEM_DECAPS:   cmd_str = "kem-decaps";   break;
	default:                           cmd_str = "ping";          break;
	}

	for (int i = 0; i < loop; i++) {
		struct timespec t1, t2;

		setup_op(&op, cmd, kem_pk, kem_sk, kem_ct, kem_ss);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		if (res != TEEC_SUCCESS)
			errx(1, "invoke failed 0x%x origin 0x%x", res, origin);

		samples[i] = diff_ns(&t1, &t2);

		uint32_t pass = 1;
		if (cmd == TA_PQC_PING_CMD_KEM_SELFTEST) {
			pass = (op.params[0].value.a == 0) ? 1 : 0;
			if (!pass)
				fail_count++;
		}

		if (csv)
			fprintf(csv, "%d,%s,%" PRIu64 ",%u\n",
				i, cmd_str, samples[i], pass);
	}

	if (csv)
		fclose(csv);

	print_stats(samples, (size_t)loop, cmd_str);
	if (cmd == TA_PQC_PING_CMD_KEM_SELFTEST)
		printf("  pass  = %u/%d\n", (unsigned)(loop - fail_count), loop);

	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	free(samples);
	return 0;
}
