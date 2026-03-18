// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"

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

	default:
		if (cmd_id >= TA_PQC_PING_CMD_KEM_SELFTEST &&
		    cmd_id <= TA_PQC_PING_CMD_KEM_DEC_HOST)
			return ta_cmd_kem(cmd_id, param_types, params, session);
		if (cmd_id == TA_PQC_PING_CMD_SIG_KEYGEN ||
		    cmd_id == TA_PQC_PING_CMD_SIG_SIGN)
			return ta_cmd_sig(cmd_id, param_types, params, session);
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
