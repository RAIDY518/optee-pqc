// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pqc_ping_ta.h>
#include <pqc_algo.h>

/*
 * Called when the instance of the TA is created. This is the first call in
 * the TA.
 */
TEE_Result TA_CreateEntryPoint(void)
{
	DMSG("has been called");

	return TEE_SUCCESS;
}

/*
 * Called when the instance of the TA is destroyed if the TA has not
 * crashed or panicked. This is the last call in the TA.
 */
void TA_DestroyEntryPoint(void)
{
	DMSG("has been called");
}

/*
 * Called when a new session is opened to the TA. *sess_ctx can be updated
 * with a value to be able to identify this session in subsequent calls to the
 * TA. In this function you will normally do the global initialization for the
 * TA.
 */
TEE_Result TA_OpenSessionEntryPoint(uint32_t param_types,
				    TEE_Param __unused params[4],
				    void __unused **sess_ctx)
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	/*
	 * The DMSG() macro is non-standard, TEE Internal API doesn't
	 * specify any means to logging from a TA.
	 */
	IMSG("Hello World!\n");

	/* If return value != TEE_SUCCESS the session will not be created. */
	return TEE_SUCCESS;
}

/*
 * Called when a session is closed, sess_ctx hold the value that was
 * assigned by TA_OpenSessionEntryPoint().
 */
void TA_CloseSessionEntryPoint(void __unused *sess_ctx)
{
	IMSG("Goodbye!\n");
}

static TEE_Result inc_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a++;
	IMSG("Increase value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}

static TEE_Result dec_value(uint32_t param_types, TEE_Param params[4])
{
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_INOUT,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);

	DMSG("has been called");

	if (param_types != exp_param_types)
		return TEE_ERROR_BAD_PARAMETERS;

	IMSG("Got value: %u from NW", params[0].value.a);
	params[0].value.a--;
	IMSG("Decrease value to: %u", params[0].value.a);

	return TEE_SUCCESS;
}
/*
 * Called when a TA is invoked. sess_ctx hold that value that was
 * assigned by TA_OpenSessionEntryPoint(). The rest of the paramters
 * comes from normal world.
 */
TEE_Result TA_InvokeCommandEntryPoint(void *sess_ctx, uint32_t cmd_id,
				      uint32_t param_types, TEE_Param params[4])
{
	(void)sess_ctx;

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
		uint32_t exp = TEE_PARAM_TYPES(
			TEE_PARAM_TYPE_MEMREF_OUTPUT,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE,
			TEE_PARAM_TYPE_NONE);

		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		if (params[0].memref.size < sizeof(struct pqc_info_out))
			return TEE_ERROR_SHORT_BUFFER;

		struct pqc_info_out *out = (struct pqc_info_out *)params[0].memref.buffer;

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

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
