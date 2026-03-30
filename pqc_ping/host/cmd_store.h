#ifndef CMD_STORE_H
#define CMD_STORE_H

#include "bench.h"

/* Key lifecycle commands — one-shot, print result to stdout. */
void run_kem_keygen_save(struct bench_ctx *ctx);
void run_kem_load(struct bench_ctx *ctx);
void run_kem_status(struct bench_ctx *ctx);
void run_kem_destroy(struct bench_ctx *ctx);

void run_sig_keygen_save(struct bench_ctx *ctx);
void run_sig_load(struct bench_ctx *ctx);
void run_sig_status(struct bench_ctx *ctx);
void run_sig_destroy(struct bench_ctx *ctx);

/* Validate that the loaded session key works end-to-end. */
void run_kem_validate(struct bench_ctx *ctx);
void run_sig_validate(struct bench_ctx *ctx);

#endif /* CMD_STORE_H */
