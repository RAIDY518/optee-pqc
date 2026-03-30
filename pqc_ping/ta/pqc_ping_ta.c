// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"
#include "user_ta_header_defines.h"

TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");
	return TEE_SUCCESS;
}

void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void **sess_ctx)
{
	uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE,
				       TEE_PARAM_TYPE_NONE, TEE_PARAM_TYPE_NONE);
	if (param_types != exp)
		return TEE_ERROR_BAD_PARAMETERS;

	struct pqc_session *session = TEE_Malloc(sizeof(*session), 0);
	if (!session)
		return TEE_ERROR_OUT_OF_MEMORY;

	session->kem_sk_valid = 0;
	session->sig_sk_valid = 0;
	*sess_ctx = session;

	IMSG("Hello World!\n");
	return TEE_SUCCESS;
}

void TA_CloseSessionEntryPoint(void *sess_ctx)
{
	TEE_Free(sess_ctx);
	IMSG("Goodbye!\n");
}

TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	struct pqc_session *session = (struct pqc_session *)sess_ctx;

	switch (cmd_id) {
	case TA_PQC_PING_CMD_EMPTY:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_PING:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		params[0].value.a += 1;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_INFO:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < sizeof(struct pqc_info_out))
			return TEE_ERROR_SHORT_BUFFER;

		struct pqc_info_out *out =
			(struct pqc_info_out *)params[0].memref.buffer;
		out->kem_pk  = TEE_PQC_KEM_PUBLICKEYBYTES;
		out->kem_sk  = TEE_PQC_KEM_SECRETKEYBYTES;
		out->kem_ct  = TEE_PQC_KEM_CIPHERTEXTBYTES;
		out->kem_ss  = TEE_PQC_KEM_BYTES;
		out->sig_pk  = TEE_PQC_SIG_PUBLICKEYBYTES;
		out->sig_sk  = TEE_PQC_SIG_SECRETKEYBYTES;
		out->sig_sig = TEE_PQC_SIG_BYTES;
		params[0].memref.size = sizeof(struct pqc_info_out);
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_MEM_INFO:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < sizeof(struct pqc_mem_info))
			return TEE_ERROR_SHORT_BUFFER;

		struct pqc_mem_info *mi =
			(struct pqc_mem_info *)params[0].memref.buffer;
		mi->stack_size = TA_STACK_SIZE;
		mi->data_size  = TA_DATA_SIZE;

		/* Probe available heap: binary search for largest allocation */
		uint32_t lo = 0, hi = TA_DATA_SIZE;
		while (lo < hi) {
			uint32_t mid = lo + (hi - lo + 1) / 2;
			void *p = TEE_Malloc(mid, 0);
			if (p) {
				lo = mid;
				TEE_Free(p);
			} else {
				hi = mid - 1;
			}
		}
		mi->heap_avail = lo;

		params[0].memref.size = sizeof(struct pqc_mem_info);
		return TEE_SUCCESS;
	}

	/*
	 * Stress commands — all buffers on TA stack (not heap).
	 * These represent peak stack pressure for memory profiling.
	 *
	 * KEM stack footprint: pk(800) + sk(1632) + ct(768) + ss_enc(32) + ss_dec(32) = 3264 B
	 * SIG stack footprint: pk(1312) + sk(2560) + sig(2420) = 6292 B
	 * Plus internal call-chain stack usage from the crypto library.
	 */
	case TA_PQC_PING_CMD_KEM_STRESS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		uint8_t pk[TEE_PQC_KEM_PUBLICKEYBYTES];
		uint8_t sk[TEE_PQC_KEM_SECRETKEYBYTES];
		uint8_t ct[TEE_PQC_KEM_CIPHERTEXTBYTES];
		uint8_t ss_enc[TEE_PQC_KEM_BYTES];
		uint8_t ss_dec[TEE_PQC_KEM_BYTES];

		TEE_PQC_KEM_KEYPAIR(pk, sk);
		TEE_PQC_KEM_ENCAPS(ct, ss_enc, pk);
		TEE_PQC_KEM_DECAPS(ss_dec, ct, sk);

		params[0].value.a =
			(TEE_MemCompare(ss_enc, ss_dec, TEE_PQC_KEM_BYTES) == 0)
			? 0 : 1;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_SIG_STRESS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		static const uint8_t msg[] = "pqc-day10-stress";
		uint8_t pk[TEE_PQC_SIG_PUBLICKEYBYTES];
		uint8_t sk[TEE_PQC_SIG_SECRETKEYBYTES];
		uint8_t sig[TEE_PQC_SIG_BYTES];

		TEE_PQC_SIG_KEYPAIR(pk, sk);

		size_t siglen = TEE_PQC_SIG_BYTES;
		TEE_PQC_SIG_SIGN(sig, &siglen, msg, sizeof(msg) - 1, sk);

		int vret = TEE_PQC_SIG_VERIFY(sig, siglen,
					       msg, sizeof(msg) - 1, pk);

		params[0].value.a = (vret == 0) ? 0 : 1;
		return TEE_SUCCESS;
	}

	default:
		if (cmd_id >= TA_PQC_PING_CMD_KEM_SELFTEST &&
		    cmd_id <= TA_PQC_PING_CMD_KEM_DEC_HOST)
			return ta_cmd_kem(cmd_id, param_types, params, session);
		if (cmd_id == TA_PQC_PING_CMD_SIG_KEYGEN ||
		    cmd_id == TA_PQC_PING_CMD_SIG_SIGN)
			return ta_cmd_sig(cmd_id, param_types, params, session);
		if (cmd_id >= TA_PQC_PING_CMD_KEM_KEYGEN_SAVE &&
		    cmd_id <= TA_PQC_PING_CMD_SIG_GET_PK)
			return ta_cmd_store(cmd_id, param_types, params, session);
		if (cmd_id >= TA_PQC_PING_CMD_KEM_KEYGEN_MICRO &&
		    cmd_id <= TA_PQC_PING_CMD_SIG_SIGN_MICRO)
			return ta_cmd_bench(cmd_id, param_types, params);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
