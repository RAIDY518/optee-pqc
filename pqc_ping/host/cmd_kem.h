#ifndef CMD_KEM_H
#define CMD_KEM_H

#include <tee_client_api.h>
#include <stdint.h>
#include "bench.h"

/* Build a TEEC_Operation for the regular KEM benchmark commands. */
void setup_kem_op(TEEC_Operation *op, int cmd,
		  uint8_t *pk, uint8_t *sk, uint8_t *ct, uint8_t *ss);

/* Run the KEM cross-boundary workflow benchmark. */
void run_kem_crosstest(struct bench_ctx *ctx);

#endif /* CMD_KEM_H */
