// SPDX-License-Identifier: BSD-2-Clause
/*
 * Copyright (c) 2016, Linaro Limited
 * All rights reserved.
 */

#include <tee_internal_api.h>
#include <tee_internal_api_extensions.h>

#include <pqc_ping_ta.h>
#include <pqc_algo.h>

/* Per-session state: holds KEM and SIG secret keys for cross-boundary
 * workflows.  Neither sk ever leaves the TA — only pk is returned to
 * the host. */
struct pqc_session {
	uint8_t  kem_sk[TEE_PQC_KEM_SECRETKEYBYTES];
	uint32_t kem_sk_valid;
	uint8_t  sig_sk[TEE_PQC_SIG_SECRETKEYBYTES];
	uint32_t sig_sk_valid;
};

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
	uint32_t exp_param_types = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE,
						   TEE_PARAM_TYPE_NONE);
	if (param_types != exp_param_types)
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

	/*
	 * Cross-boundary workflow commands:
	 *   KEM_INIT     — TA generates keypair; sk stored in session (never
	 *                  leaves TEE); only pk returned to host.
	 *   KEM_DEC_HOST — host sends ct it encapsulated in normal world; TA
	 *                  decapsulates with session sk; returns ss to host
	 *                  for comparison.
	 */
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

		/* Generate keypair: pk goes to host, sk stays in session */
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
		if (params[0].memref.size < TEE_PQC_KEM_CIPHERTEXTBYTES ||
		    params[1].memref.size < TEE_PQC_KEM_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		/* Decapsulate using session-held sk; return ss to host */
		TEE_PQC_KEM_DECAPS(params[1].memref.buffer,
				   params[0].memref.buffer,
				   session->kem_sk);
		params[1].memref.size = TEE_PQC_KEM_BYTES;
		return TEE_SUCCESS;
	}

	/*
	 * Signature cross-boundary commands:
	 *   SIG_KEYGEN — TA generates signing keypair; sk stored in session
	 *                (never leaves TEE); only pk returned to host.
	 *   SIG_SIGN   — host sends message; TA signs with session sk;
	 *                returns signature to host for normal-world verify.
	 */
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

		/* Generate keypair: pk goes to host, sk stays in session */
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
		if (params[1].memref.size < TEE_PQC_SIG_BYTES)
			return TEE_ERROR_SHORT_BUFFER;

		/* Sign message with session-held sk; return sig to host */
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
