/* SPDX-License-Identifier: BSD-2-Clause */
#ifndef TA_INTERNAL_H
#define TA_INTERNAL_H

#include <tee_internal_api.h>
#include <pqc_algo.h>

/* Per-session state: secret keys never leave the TA. */
struct pqc_session {
#ifdef PQC_ENABLE_KEM
	uint8_t  kem_sk[TEE_PQC_KEM_SECRETKEYBYTES];
	uint32_t kem_sk_valid;
#endif
#ifdef PQC_ENABLE_SIG
	uint8_t  sig_sk[TEE_PQC_SIG_SECRETKEYBYTES];
	uint32_t sig_sk_valid;
#endif
	uint32_t _dummy; /* ensure non-empty struct */
};

#ifdef PQC_ENABLE_KEM
TEE_Result ta_cmd_kem(uint32_t cmd_id, uint32_t param_types,
		      TEE_Param params[4], struct pqc_session *session);
#endif

#ifdef PQC_ENABLE_SIG
TEE_Result ta_cmd_sig(uint32_t cmd_id, uint32_t param_types,
		      TEE_Param params[4], struct pqc_session *session);
#endif

#if defined(PQC_ENABLE_KEM) || defined(PQC_ENABLE_SIG)
TEE_Result ta_cmd_store(uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[4], struct pqc_session *session);

TEE_Result ta_cmd_bench(uint32_t cmd_id, uint32_t param_types,
			TEE_Param params[4]);
#endif

#endif /* TA_INTERNAL_H */
