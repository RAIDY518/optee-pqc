/* SPDX-License-Identifier: BSD-2-Clause */
/*
 * Copyright (c) 2016-2017, Linaro Limited
 * All rights reserved.
 */
#ifndef TA_PQC_PING_H
#define TA_PQC_PING_H

/*
 * This UUID is generated with uuidgen
 * the ITU-T UUID generator at http://www.itu.int/ITU-T/asn1/uuid.html
 */
#define TA_PQC_PING_UUID \
	{ 0x49d90b2c, 0xdcb4, 0x4f62, \
		{ 0x8b, 0xdf, 0xce, 0x53, 0x8f, 0xc1, 0x4d, 0xca} }

/* The function IDs implemented in this TA */
#define TA_PQC_PING_CMD_EMPTY        0
#define TA_PQC_PING_CMD_PING         1
#define TA_PQC_PING_CMD_INFO         2
#define TA_PQC_PING_CMD_KEM_SELFTEST 3  /* keygen+encaps+decaps+cmp in one call: PASS/FAIL */
#define TA_PQC_PING_CMD_KEM_KEYGEN   4  /* generate keypair, return pk+sk */
#define TA_PQC_PING_CMD_KEM_ENCAPS   5  /* take pk, return ct+ss */
#define TA_PQC_PING_CMD_KEM_DECAPS   6  /* take sk+ct, return ss */

/* ML-KEM-512 compile-time sizes for host-side buffer allocation */
#define PQC_KEM_PUBLICKEYBYTES    800
#define PQC_KEM_SECRETKEYBYTES   1632
#define PQC_KEM_CIPHERTEXTBYTES   768
#define PQC_KEM_SHARED_BYTES       32

struct pqc_info_out {
    uint32_t kem_pk;
    uint32_t kem_sk;
    uint32_t kem_ct;
    uint32_t kem_ss;
    uint32_t sig_pk;
    uint32_t sig_sk;
    uint32_t sig_sig;
};

#endif /*TA_PQC_PING_H*/
