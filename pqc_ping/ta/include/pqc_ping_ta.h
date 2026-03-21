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
#define TA_PQC_PING_CMD_KEM_INIT     7  /* keygen; store sk in session, return only pk */
#define TA_PQC_PING_CMD_KEM_DEC_HOST 8  /* take ct from host, decaps with session sk, return ss */
#define TA_PQC_PING_CMD_SIG_KEYGEN   9  /* keygen; store sk in session, return only pk */
#define TA_PQC_PING_CMD_SIG_SIGN    10  /* sign msg with session sk, return sig */

/* Secure storage / key lifecycle commands */
#define TA_PQC_PING_CMD_KEM_KEYGEN_SAVE 11 /* keygen + persist sk; return pk */
#define TA_PQC_PING_CMD_KEM_LOAD        12 /* restore sk from secure storage */
#define TA_PQC_PING_CMD_KEM_STATUS      13 /* report key state (value out) */
#define TA_PQC_PING_CMD_KEM_DESTROY     14 /* wipe memory + delete storage */
#define TA_PQC_PING_CMD_SIG_KEYGEN_SAVE 15 /* keygen + persist sk; return pk */
#define TA_PQC_PING_CMD_SIG_LOAD        16 /* restore sk from secure storage */
#define TA_PQC_PING_CMD_SIG_STATUS      17 /* report key state (value out) */
#define TA_PQC_PING_CMD_SIG_DESTROY     18 /* wipe memory + delete storage */

/* Key status bits (returned by KEM_STATUS / SIG_STATUS) */
#define PQC_KEY_ABSENT    0  /* no key in memory, not persisted */
#define PQC_KEY_IN_MEMORY 1  /* key loaded in session */
#define PQC_KEY_PERSISTED 2  /* key exists in secure storage */
#define PQC_KEY_READY     3  /* in-memory AND persisted */

/* ML-KEM-512 compile-time sizes for host-side buffer allocation */
#define PQC_KEM_PUBLICKEYBYTES    800
#define PQC_KEM_SECRETKEYBYTES   1632
#define PQC_KEM_CIPHERTEXTBYTES   768
#define PQC_KEM_SHARED_BYTES       32

/* ML-DSA-44 compile-time sizes for host-side buffer allocation */
#define PQC_SIG_PUBLICKEYBYTES   1312
#define PQC_SIG_SECRETKEYBYTES   2560
#define PQC_SIG_BYTES            2420

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
