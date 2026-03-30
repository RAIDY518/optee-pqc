#include <err.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include <tee_client_api.h>
#include <pqc_ping_ta.h>

#include "bench.h"
#include "cmd_kem.h"
#include "cmd_sig.h"
#include "cmd_store.h"
#include "cmd_bench.h"

#define DEFAULT_LOOP   100
#define DEFAULT_WARMUP 10

int main(int argc, char *argv[])
{
	TEEC_Result  res;
	TEEC_Context ctx;
	TEEC_Session sess;
	TEEC_Operation op;
	TEEC_UUID    uuid = TA_PQC_PING_UUID;

	int          cmd    = TA_PQC_PING_CMD_PING;
	int          loop   = DEFAULT_LOOP;
	int          warmup = DEFAULT_WARMUP;
	const char  *csv_path = NULL;

	/* KEM buffers */
	uint8_t kem_pk[PQC_KEM_PUBLICKEYBYTES];
	uint8_t kem_sk[PQC_KEM_SECRETKEYBYTES];
	uint8_t kem_ct[PQC_KEM_CIPHERTEXTBYTES];
	uint8_t kem_ss[PQC_KEM_SHARED_BYTES];
	uint8_t cross_ct[PQC_KEM_CIPHERTEXTBYTES];
	uint8_t cross_ss_host[PQC_KEM_SHARED_BYTES];
	uint8_t cross_ss_ta[PQC_KEM_SHARED_BYTES];
	/* SIG buffers */
	uint8_t sig_pk[PQC_SIG_PUBLICKEYBYTES];
	uint8_t sig_buf[PQC_SIG_BYTES];

	for (int i = 1; i < argc; i++) {
		if (!strcmp(argv[i], "--cmd") && i + 1 < argc) {
			i++;
			if      (!strcmp(argv[i], "empty"))         cmd = TA_PQC_PING_CMD_EMPTY;
			else if (!strcmp(argv[i], "ping"))          cmd = TA_PQC_PING_CMD_PING;
			else if (!strcmp(argv[i], "info"))          cmd = TA_PQC_PING_CMD_INFO;
			else if (!strcmp(argv[i], "kem-selftest"))  cmd = TA_PQC_PING_CMD_KEM_SELFTEST;
			else if (!strcmp(argv[i], "kem-keygen"))    cmd = TA_PQC_PING_CMD_KEM_KEYGEN;
			else if (!strcmp(argv[i], "kem-encaps"))    cmd = TA_PQC_PING_CMD_KEM_ENCAPS;
			else if (!strcmp(argv[i], "kem-decaps"))    cmd = TA_PQC_PING_CMD_KEM_DECAPS;
			else if (!strcmp(argv[i], "kem-crosstest")) cmd = HOST_CMD_KEM_CROSSTEST;
			else if (!strcmp(argv[i], "sig-keygen"))    cmd = TA_PQC_PING_CMD_SIG_KEYGEN;
			else if (!strcmp(argv[i], "sig-sign"))      cmd = TA_PQC_PING_CMD_SIG_SIGN;
			else if (!strcmp(argv[i], "sig-crosstest"))    cmd = HOST_CMD_SIG_CROSSTEST;
			else if (!strcmp(argv[i], "kem-keygen-save")) cmd = TA_PQC_PING_CMD_KEM_KEYGEN_SAVE;
			else if (!strcmp(argv[i], "kem-load"))        cmd = TA_PQC_PING_CMD_KEM_LOAD;
			else if (!strcmp(argv[i], "kem-status"))      cmd = TA_PQC_PING_CMD_KEM_STATUS;
			else if (!strcmp(argv[i], "kem-destroy"))     cmd = TA_PQC_PING_CMD_KEM_DESTROY;
			else if (!strcmp(argv[i], "sig-keygen-save")) cmd = TA_PQC_PING_CMD_SIG_KEYGEN_SAVE;
			else if (!strcmp(argv[i], "sig-load"))        cmd = TA_PQC_PING_CMD_SIG_LOAD;
			else if (!strcmp(argv[i], "sig-status"))      cmd = TA_PQC_PING_CMD_SIG_STATUS;
			else if (!strcmp(argv[i], "sig-destroy"))     cmd = TA_PQC_PING_CMD_SIG_DESTROY;
			else if (!strcmp(argv[i], "kem-validate"))       cmd = HOST_CMD_KEM_VALIDATE;
			else if (!strcmp(argv[i], "sig-validate"))       cmd = HOST_CMD_SIG_VALIDATE;
			else if (!strcmp(argv[i], "kem-keygen-micro"))   cmd = TA_PQC_PING_CMD_KEM_KEYGEN_MICRO;
			else if (!strcmp(argv[i], "kem-decaps-micro"))   cmd = TA_PQC_PING_CMD_KEM_DECAPS_MICRO;
			else if (!strcmp(argv[i], "sig-keygen-micro"))   cmd = TA_PQC_PING_CMD_SIG_KEYGEN_MICRO;
			else if (!strcmp(argv[i], "sig-sign-micro"))     cmd = TA_PQC_PING_CMD_SIG_SIGN_MICRO;
			else if (!strcmp(argv[i], "mem-info"))              cmd = TA_PQC_PING_CMD_MEM_INFO;
			else if (!strcmp(argv[i], "kem-stress"))            cmd = TA_PQC_PING_CMD_KEM_STRESS;
			else if (!strcmp(argv[i], "sig-stress"))            cmd = TA_PQC_PING_CMD_SIG_STRESS;
			else errx(1, "unknown --cmd: %s", argv[i]);
		} else if (!strcmp(argv[i], "--loop") && i + 1 < argc) {
			loop = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--warmup") && i + 1 < argc) {
			warmup = atoi(argv[++i]);
		} else if (!strcmp(argv[i], "--csv") && i + 1 < argc) {
			csv_path = argv[++i];
		} else {
			errx(1, "usage: %s [--cmd empty|ping|info|kem-selftest|"
				"kem-keygen|kem-encaps|kem-decaps|kem-crosstest|"
				"sig-keygen|sig-sign|sig-crosstest]"
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

	uint32_t origin;
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
		printf("KEM pk=%" PRIu32 " sk=%" PRIu32
		       " ct=%" PRIu32 " ss=%" PRIu32 "\n",
		       info.kem_pk, info.kem_sk, info.kem_ct, info.kem_ss);
		printf("SIG pk=%" PRIu32 " sk=%" PRIu32 " sig=%" PRIu32 "\n",
		       info.sig_pk, info.sig_sk, info.sig_sig);
		goto done;
	}

	/* --cmd mem-info: one-shot, report TA memory configuration */
	if (cmd == TA_PQC_PING_CMD_MEM_INFO) {
		struct pqc_mem_info mi;
		memset(&mi, 0, sizeof(mi));
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = &mi;
		op.params[0].tmpref.size   = sizeof(mi);
		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "mem-info invoke failed 0x%x origin 0x%x",
			     res, origin);
		printf("TA_STACK_SIZE = %" PRIu32 " (%u KB)\n",
		       mi.stack_size, mi.stack_size / 1024);
		printf("TA_DATA_SIZE  = %" PRIu32 " (%u KB)\n",
		       mi.data_size, mi.data_size / 1024);
		printf("heap_avail    = %" PRIu32 " (%u KB)\n",
		       mi.heap_avail, mi.heap_avail / 1024);
		goto done;
	}

	/* --cmd kem-stress / sig-stress: benchmarked stack stress test */
	if (cmd == TA_PQC_PING_CMD_KEM_STRESS ||
	    cmd == TA_PQC_PING_CMD_SIG_STRESS) {
		const char *tag = (cmd == TA_PQC_PING_CMD_KEM_STRESS)
				  ? "KEM-STRESS" : "SIG-STRESS";
		const char *csv_tag = (cmd == TA_PQC_PING_CMD_KEM_STRESS)
				      ? "kem-stress" : "sig-stress";
		uint32_t fail_count = 0;

		/* Warmup */
		for (int i = 0; i < warmup; i++) {
			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
							 TEEC_NONE, TEEC_NONE, TEEC_NONE);
			res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
			if (res != TEEC_SUCCESS)
				errx(1, "warmup %s failed 0x%x", csv_tag, res);
		}

		/* Measured loop */
		for (int i = 0; i < loop; i++) {
			struct timespec t1, t2;

			memset(&op, 0, sizeof(op));
			op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_OUTPUT,
							 TEEC_NONE, TEEC_NONE, TEEC_NONE);

			clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
			res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
			clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

			if (res != TEEC_SUCCESS)
				errx(1, "%s invoke failed 0x%x", csv_tag, res);

			samples[i] = diff_ns(&t1, &t2);

			if (op.params[0].value.a != 0)
				fail_count++;

			if (csv)
				fprintf(csv, "%d,%s,%" PRIu64 ",%u\n",
					i, csv_tag, samples[i],
					(op.params[0].value.a == 0) ? 1u : 0u);
		}

		print_stats(samples, (size_t)loop, tag);
		printf("  pass  = %u/%d\n", (unsigned)(loop - fail_count), loop);
		goto done;
	}

	/* Build shared benchmark context */
	struct bench_ctx bctx = {
		.sess         = &sess,
		.samples      = samples,
		.csv          = csv,
		.loop         = loop,
		.warmup       = warmup,
		.fail_count   = 0,
		.kem_pk       = kem_pk,
		.kem_sk       = kem_sk,
		.kem_ct       = kem_ct,
		.kem_ss       = kem_ss,
		.cross_ct     = cross_ct,
		.cross_ss_host = cross_ss_host,
		.cross_ss_ta   = cross_ss_ta,
		.sig_pk       = sig_pk,
		.sig_buf      = sig_buf,
	};
	bctx.origin = origin;

	/* Dispatch cross-boundary and sig commands */
	if (cmd == HOST_CMD_KEM_CROSSTEST)      { run_kem_crosstest(&bctx);  goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_KEYGEN) { run_sig_keygen(&bctx);     goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_SIGN)   { run_sig_sign(&bctx);       goto done; }
	if (cmd == HOST_CMD_SIG_CROSSTEST)     { run_sig_crosstest(&bctx);   goto done; }

	/* Dispatch key lifecycle commands */
	if (cmd == TA_PQC_PING_CMD_KEM_KEYGEN_SAVE) { run_kem_keygen_save(&bctx); goto done; }
	if (cmd == TA_PQC_PING_CMD_KEM_LOAD)        { run_kem_load(&bctx);        goto done; }
	if (cmd == TA_PQC_PING_CMD_KEM_STATUS)      { run_kem_status(&bctx);      goto done; }
	if (cmd == TA_PQC_PING_CMD_KEM_DESTROY)     { run_kem_destroy(&bctx);     goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_KEYGEN_SAVE) { run_sig_keygen_save(&bctx); goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_LOAD)        { run_sig_load(&bctx);        goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_STATUS)      { run_sig_status(&bctx);      goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_DESTROY)     { run_sig_destroy(&bctx);     goto done; }
	if (cmd == HOST_CMD_KEM_VALIDATE)                { run_kem_validate(&bctx);    goto done; }
	if (cmd == HOST_CMD_SIG_VALIDATE)                { run_sig_validate(&bctx);    goto done; }
	if (cmd == TA_PQC_PING_CMD_KEM_KEYGEN_MICRO)     { run_kem_keygen_micro(&bctx); goto done; }
	if (cmd == TA_PQC_PING_CMD_KEM_DECAPS_MICRO)     { run_kem_decaps_micro(&bctx); goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_KEYGEN_MICRO)     { run_sig_keygen_micro(&bctx); goto done; }
	if (cmd == TA_PQC_PING_CMD_SIG_SIGN_MICRO)       { run_sig_sign_micro(&bctx);   goto done; }

	/* Regular KEM benchmark commands (empty/ping/kem-selftest/keygen/encaps/decaps) */
	if (cmd == TA_PQC_PING_CMD_KEM_ENCAPS ||
	    cmd == TA_PQC_PING_CMD_KEM_DECAPS) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE, TEEC_NONE);
		op.params[0].tmpref.buffer = kem_pk; op.params[0].tmpref.size = sizeof(kem_pk);
		op.params[1].tmpref.buffer = kem_sk; op.params[1].tmpref.size = sizeof(kem_sk);
		res = TEEC_InvokeCommand(&sess, TA_PQC_PING_CMD_KEM_KEYGEN, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "pre-bench keygen failed 0x%x", res);
	}
	if (cmd == TA_PQC_PING_CMD_KEM_DECAPS) {
		memset(&op, 0, sizeof(op));
		op.paramTypes = TEEC_PARAM_TYPES(TEEC_MEMREF_TEMP_INPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_MEMREF_TEMP_OUTPUT,
						 TEEC_NONE);
		op.params[0].tmpref.buffer = kem_pk; op.params[0].tmpref.size = sizeof(kem_pk);
		op.params[1].tmpref.buffer = kem_ct; op.params[1].tmpref.size = sizeof(kem_ct);
		op.params[2].tmpref.buffer = kem_ss; op.params[2].tmpref.size = sizeof(kem_ss);
		res = TEEC_InvokeCommand(&sess, TA_PQC_PING_CMD_KEM_ENCAPS, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "pre-bench encaps failed 0x%x", res);
	}

	for (int i = 0; i < warmup; i++) {
		setup_kem_op(&op, cmd, kem_pk, kem_sk, kem_ct, kem_ss);
		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		if (res != TEEC_SUCCESS)
			errx(1, "warmup invoke failed 0x%x", res);
	}

	const char *cmd_str;
	switch (cmd) {
	case TA_PQC_PING_CMD_EMPTY:        cmd_str = "empty";        break;
	case TA_PQC_PING_CMD_KEM_SELFTEST: cmd_str = "kem-selftest"; break;
	case TA_PQC_PING_CMD_KEM_KEYGEN:   cmd_str = "kem-keygen";   break;
	case TA_PQC_PING_CMD_KEM_ENCAPS:   cmd_str = "kem-encaps";   break;
	case TA_PQC_PING_CMD_KEM_DECAPS:   cmd_str = "kem-decaps";   break;
	default:                           cmd_str = "ping";          break;
	}

	uint32_t fail_count = 0;
	for (int i = 0; i < loop; i++) {
		struct timespec t1, t2;
		setup_kem_op(&op, cmd, kem_pk, kem_sk, kem_ct, kem_ss);

		clock_gettime(CLOCK_MONOTONIC_RAW, &t1);
		res = TEEC_InvokeCommand(&sess, cmd, &op, &origin);
		clock_gettime(CLOCK_MONOTONIC_RAW, &t2);

		if (res != TEEC_SUCCESS)
			errx(1, "invoke failed 0x%x", res);

		samples[i] = diff_ns(&t1, &t2);

		uint32_t pass = 1;
		if (cmd == TA_PQC_PING_CMD_KEM_SELFTEST) {
			pass = (op.params[0].value.a == 0) ? 1 : 0;
			if (!pass) fail_count++;
		}
		if (csv)
			fprintf(csv, "%d,%s,%" PRIu64 ",%u\n",
				i, cmd_str, samples[i], pass);
	}

	print_stats(samples, (size_t)loop, cmd_str);
	if (cmd == TA_PQC_PING_CMD_KEM_SELFTEST)
		printf("  pass  = %u/%d\n", (unsigned)(loop - fail_count), loop);

done:
	if (csv)
		fclose(csv);
	TEEC_CloseSession(&sess);
	TEEC_FinalizeContext(&ctx);
	free(samples);
	return 0;
}
