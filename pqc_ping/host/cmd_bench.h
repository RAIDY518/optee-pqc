#ifndef CMD_BENCH_H
#define CMD_BENCH_H

#include "bench.h"

void run_kem_keygen_micro(struct bench_ctx *ctx);
void run_kem_decaps_micro(struct bench_ctx *ctx);
void run_sig_keygen_micro(struct bench_ctx *ctx);
void run_sig_sign_micro(struct bench_ctx *ctx);

#endif /* CMD_BENCH_H */
