#ifndef BENCH_H
#define BENCH_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <tee_client_api.h>
#include <pqc_ping_ta.h>

/* Host-side synthetic command IDs (not TA command IDs) */
#define HOST_CMD_KEM_CROSSTEST  100
#define HOST_CMD_SIG_CROSSTEST  101

/* All shared state for a benchmark run */
struct bench_ctx {
	TEEC_Session *sess;
	uint32_t      origin;
	uint64_t     *samples;
	FILE         *csv;
	int           loop;
	int           warmup;
	uint32_t      fail_count;
	/* KEM buffers */
	uint8_t      *kem_pk;
	uint8_t      *kem_sk;
	uint8_t      *kem_ct;
	uint8_t      *kem_ss;
	uint8_t      *cross_ct;
	uint8_t      *cross_ss_host;
	uint8_t      *cross_ss_ta;
	/* SIG buffers */
	uint8_t      *sig_pk;
	uint8_t      *sig_buf;
};

uint64_t diff_ns(const struct timespec *s, const struct timespec *e);
void     print_stats(uint64_t *arr, size_t n, const char *tag);

#endif /* BENCH_H */
