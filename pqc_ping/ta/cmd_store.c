// SPDX-License-Identifier: BSD-2-Clause
#include <tee_internal_api.h>
#include <pqc_ping_ta.h>
#include "ta_internal.h"

/* Persistent object IDs — sk and pk stored separately */
static const char KEM_SK_ID[] = "pqc_kem_sk";
static const char KEM_PK_ID[] = "pqc_kem_pk";
static const char SIG_SK_ID[] = "pqc_sig_sk";
static const char SIG_PK_ID[] = "pqc_sig_pk";
#define KEM_SK_ID_LEN (sizeof(KEM_SK_ID) - 1)
#define KEM_PK_ID_LEN (sizeof(KEM_PK_ID) - 1)
#define SIG_SK_ID_LEN (sizeof(SIG_SK_ID) - 1)
#define SIG_PK_ID_LEN (sizeof(SIG_PK_ID) - 1)

/* Write raw bytes to a persistent data object (overwrite if exists). */
static TEE_Result store_write(const char *id, uint32_t id_len,
			      const void *data, uint32_t data_len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	uint32_t flags = TEE_DATA_FLAG_ACCESS_READ        |
			 TEE_DATA_FLAG_ACCESS_WRITE       |
			 TEE_DATA_FLAG_ACCESS_WRITE_META  |
			 TEE_DATA_FLAG_OVERWRITE;
	TEE_Result res = TEE_CreatePersistentObject(TEE_STORAGE_PRIVATE,
						    id, id_len, flags,
						    TEE_HANDLE_NULL,
						    data, data_len, &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return res;
}

/* Read raw bytes from a persistent data object. */
static TEE_Result store_read(const char *id, uint32_t id_len,
			     void *buf, uint32_t buf_len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						  id, id_len,
						  TEE_DATA_FLAG_ACCESS_READ,
						  &obj);
	if (res != TEE_SUCCESS)
		return res;

	uint32_t n = 0;
	res = TEE_ReadObjectData(obj, buf, buf_len, &n);
	TEE_CloseObject(obj);
	if (res == TEE_SUCCESS && n != buf_len)
		return TEE_ERROR_CORRUPT_OBJECT;
	return res;
}

/* Return TEE_SUCCESS if object exists, TEE_ERROR_ITEM_NOT_FOUND otherwise. */
static TEE_Result store_exists(const char *id, uint32_t id_len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_OpenPersistentObject(TEE_STORAGE_PRIVATE,
						  id, id_len,
						  TEE_DATA_FLAG_ACCESS_READ,
						  &obj);
	if (res == TEE_SUCCESS)
		TEE_CloseObject(obj);
	return res;
}

/* Delete object; silent if not found. */
static void store_delete(const char *id, uint32_t id_len)
{
	TEE_ObjectHandle obj = TEE_HANDLE_NULL;
	TEE_Result res = TEE_OpenPersistentObject(
				TEE_STORAGE_PRIVATE, id, id_len,
				TEE_DATA_FLAG_ACCESS_READ |
				TEE_DATA_FLAG_ACCESS_WRITE_META,
				&obj);
	if (res == TEE_SUCCESS)
		TEE_CloseAndDeletePersistentObject1(obj);
}

TEE_Result ta_cmd_store(uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[4], struct pqc_session *session)
{
	switch (cmd_id) {

	/* ---- KEM lifecycle -------------------------------------------- */

	case TA_PQC_PING_CMD_KEM_KEYGEN_SAVE:
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

		/* Persist both sk and pk so pk can be recovered after restart */
		TEE_Result res = store_write(KEM_SK_ID, KEM_SK_ID_LEN,
					     session->kem_sk,
					     TEE_PQC_KEM_SECRETKEYBYTES);
		if (res != TEE_SUCCESS)
			return res;
		return store_write(KEM_PK_ID, KEM_PK_ID_LEN,
				   params[0].memref.buffer,
				   TEE_PQC_KEM_PUBLICKEYBYTES);
	}

	case TA_PQC_PING_CMD_KEM_LOAD:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_Result res = store_read(KEM_SK_ID, KEM_SK_ID_LEN,
					    session->kem_sk,
					    TEE_PQC_KEM_SECRETKEYBYTES);
		if (res == TEE_SUCCESS)
			session->kem_sk_valid = 1;
		return res;
	}

	case TA_PQC_PING_CMD_KEM_STATUS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		uint32_t s = PQC_KEY_ABSENT;
		if (session->kem_sk_valid)
			s |= PQC_KEY_IN_MEMORY;
		if (store_exists(KEM_SK_ID, KEM_SK_ID_LEN) == TEE_SUCCESS)
			s |= PQC_KEY_PERSISTED;
		params[0].value.a = s;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_DESTROY:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_MemFill(session->kem_sk, 0, TEE_PQC_KEM_SECRETKEYBYTES);
		session->kem_sk_valid = 0;
		store_delete(KEM_SK_ID, KEM_SK_ID_LEN);
		store_delete(KEM_PK_ID, KEM_PK_ID_LEN);
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_KEM_GET_PK:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_KEM_PUBLICKEYBYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_Result res = store_read(KEM_PK_ID, KEM_PK_ID_LEN,
					    params[0].memref.buffer,
					    TEE_PQC_KEM_PUBLICKEYBYTES);
		if (res == TEE_SUCCESS)
			params[0].memref.size = TEE_PQC_KEM_PUBLICKEYBYTES;
		return res;
	}

	/* ---- SIG lifecycle -------------------------------------------- */

	case TA_PQC_PING_CMD_SIG_KEYGEN_SAVE:
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

		TEE_Result res = store_write(SIG_SK_ID, SIG_SK_ID_LEN,
					     session->sig_sk,
					     TEE_PQC_SIG_SECRETKEYBYTES);
		if (res != TEE_SUCCESS)
			return res;
		return store_write(SIG_PK_ID, SIG_PK_ID_LEN,
				   params[0].memref.buffer,
				   TEE_PQC_SIG_PUBLICKEYBYTES);
	}

	case TA_PQC_PING_CMD_SIG_LOAD:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_Result res = store_read(SIG_SK_ID, SIG_SK_ID_LEN,
					    session->sig_sk,
					    TEE_PQC_SIG_SECRETKEYBYTES);
		if (res == TEE_SUCCESS)
			session->sig_sk_valid = 1;
		return res;
	}

	case TA_PQC_PING_CMD_SIG_STATUS:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_VALUE_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		uint32_t s = PQC_KEY_ABSENT;
		if (session->sig_sk_valid)
			s |= PQC_KEY_IN_MEMORY;
		if (store_exists(SIG_SK_ID, SIG_SK_ID_LEN) == TEE_SUCCESS)
			s |= PQC_KEY_PERSISTED;
		params[0].value.a = s;
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_SIG_DESTROY:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;

		TEE_MemFill(session->sig_sk, 0, TEE_PQC_SIG_SECRETKEYBYTES);
		session->sig_sk_valid = 0;
		store_delete(SIG_SK_ID, SIG_SK_ID_LEN);
		store_delete(SIG_PK_ID, SIG_PK_ID_LEN);
		return TEE_SUCCESS;
	}

	case TA_PQC_PING_CMD_SIG_GET_PK:
	{
		uint32_t exp = TEE_PARAM_TYPES(TEE_PARAM_TYPE_MEMREF_OUTPUT,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE,
					       TEE_PARAM_TYPE_NONE);
		if (param_types != exp)
			return TEE_ERROR_BAD_PARAMETERS;
		if (params[0].memref.size < TEE_PQC_SIG_PUBLICKEYBYTES)
			return TEE_ERROR_SHORT_BUFFER;

		TEE_Result res = store_read(SIG_PK_ID, SIG_PK_ID_LEN,
					    params[0].memref.buffer,
					    TEE_PQC_SIG_PUBLICKEYBYTES);
		if (res == TEE_SUCCESS)
			params[0].memref.size = TEE_PQC_SIG_PUBLICKEYBYTES;
		return res;
	}

	default:
		return TEE_ERROR_BAD_PARAMETERS;
	}
}
