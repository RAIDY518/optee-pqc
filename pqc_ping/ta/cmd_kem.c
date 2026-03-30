// SPDX-License-Identifier: BSD-2-Clause
#include <tee_internal_api.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"

TEE_Result ta_cmd_kem(uint32_t cmd_id, uint32_t param_types,
		      TEE_Param params[4], struct pqc_session *session)
{
	switch (cmd_id) {
	case TA_PQC_PING_CMD_KEM_SELFTEST:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		uint8_t *pk     = TEE_Malloc(TEE_PQC_KEM_PUBLICKEYBYTES,  0);
		uint8_t *sk     = TEE_Malloc(TEE_PQC_KEM_SECRETKEYBYTES,  0);
		uint8_t *ct     = TEE_Malloc(TEE_PQC_KEM_CIPHERTEXTBYTES, 0);
		uint8_t *ss_enc = TEE_Malloc(TEE_PQC_KEM_BYTES,           0);
		uint8_t *ss_dec = TEE_Malloc(TEE_PQC_KEM_BYTES,           0);

		if (!pk || !sk || !ct || !ss_enc || !ss_dec) {
			if (sk) TEE_MemFill(sk, 0, TEE_PQC_KEM_SECRETKEYBYTES);
			TEE_Free(pk); TEE_Free(sk); TEE_Free(ct);
			TEE_Free(ss_enc); TEE_Free(ss_dec);
			return TEE_ERROR_OUT_OF_MEMORY;
		}

		TEE_PQC_KEM_KEYPAIR(pk, sk);
		TEE_PQC_KEM_ENCAPS(ct, ss_enc, pk);
		TEE_PQC_KEM_DECAPS(ss_dec, ct, sk);

		params[0].value.a =
			(TEE_MemCompare(ss_enc, ss_dec, TEE_PQC_KEM_BYTES) == 0)
			? 0 : 1;

		TEE_MemFill(sk, 0, TEE_PQC_KEM_SECRETKEYBYTES);
		TEE_MemFill(ss_enc, 0, TEE_PQC_KEM_BYTES);
		TEE_MemFill(ss_dec, 0, TEE_PQC_KEM_BYTES);
		TEE_Free(pk); TEE_Free(sk); TEE_Free(ct);
		TEE_Free(ss_enc); TEE_Free(ss_dec);
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_KEYGEN:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_KEM_PUBLICKEYBYTES ||
		    params[1].memref.size < TEE_PQC_KEM_SECRETKEYBYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_KEM_KEYPAIR(params[0].memref.buffer,
				    params[1].memref.buffer);
		params[0].memref.size = TEE_PQC_KEM_PUBLICKEYBYTES;
		params[1].memref.size = TEE_PQC_KEM_SECRETKEYBYTES;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_ENCAPS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_KEM_PUBLICKEYBYTES  ||
		    params[1].memref.size < TEE_PQC_KEM_CIPHERTEXTBYTES ||
		    params[2].memref.size < TEE_PQC_KEM_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_KEM_ENCAPS(params[1].memref.buffer,
				   params[2].memref.buffer,
				   params[0].memref.buffer);
		params[1].memref.size = TEE_PQC_KEM_CIPHERTEXTBYTES;
		params[2].memref.size = TEE_PQC_KEM_BYTES;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_DECAPS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_KEM_SECRETKEYBYTES  ||
		    params[1].memref.size < TEE_PQC_KEM_CIPHERTEXTBYTES ||
		    params[2].memref.size < TEE_PQC_KEM_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_KEM_DECAPS(params[2].memref.buffer,
				   params[1].memref.buffer,
				   params[0].memref.buffer);
		params[2].memref.size = TEE_PQC_KEM_BYTES;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_INIT:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_KEM_PUBLICKEYBYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_KEM_KEYPAIR(params[0].memref.buffer, session->kem_sk);
		session->kem_sk_valid = 1;
		params[0].memref.size = TEE_PQC_KEM_PUBLICKEYBYTES;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_DEC_HOST:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (!session->kem_sk_valid)
			return TEE_ERROR_BAD_STATE;
		/* Reject wrong-sized ciphertext (short or oversized) */
		if (params[0].memref.size != TEE_PQC_KEM_CIPHERTEXTBYTES)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[1].memref.size < TEE_PQC_KEM_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_KEM_DECAPS(params[1].memref.buffer,
				   params[0].memref.buffer,
				   session->kem_sk);
		params[1].memref.size = TEE_PQC_KEM_BYTES;
		return TEE_SUCCESS;
	}

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
