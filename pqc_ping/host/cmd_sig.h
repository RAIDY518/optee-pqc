#ifndef CMD_SIG_H
#define CMD_SIG_H

#include "bench.h"

void run_sig_keygen(struct bench_ctx *ctx);
void run_sig_sign(struct bench_ctx *ctx);
void run_sig_crosstest(struct bench_ctx *ctx);

#endif /* CMD_SIG_H */
