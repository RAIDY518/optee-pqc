// SPDX-License-Identifier: BSD-2-Clause
#include <tee_internal_api.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"

TEE_Result ta_cmd_sig(uint32_t cmd_id, uint32_t param_types,
		      TEE_Param params[4], struct pqc_session *session)
{
	switch (cmd_id) {
	case TA_PQC_PING_CMD_SIG_KEYGEN:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_SIG_PUBLICKEYBYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_PQC_SIG_KEYPAIR(params[0].memref.buffer, session->sig_sk);
		session->sig_sk_valid = 1;
		params[0].memref.size = TEE_PQC_SIG_PUBLICKEYBYTES;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_SIG_SIGN:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_INPUT,
					       TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (!session->sig_sk_valid)
			return TEE_ERROR_BAD_STATE;
		/* Reject empty or oversized messages */
		if (params[0].memref.size == 0 ||
		    params[0].memref.size > 4096)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[1].memref.size < TEE_PQC_SIG_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		size_t siglen = TEE_PQC_SIG_BYTES;
		TEE_PQC_SIG_SIGN(params[1].memref.buffer, &siglen,
				 params[0].memref.buffer,
				 params[0].memref.size,
				 session->sig_sk);
		params[1].memref.size = (uint32_t)siglen;
		return TEE_SUCCESS;
	}

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
