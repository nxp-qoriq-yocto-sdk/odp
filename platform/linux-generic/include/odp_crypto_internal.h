/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <openssl/des.h>

#define OP_RESULT_MAGIC 0x91919191

/** Forward declaration of session structure */
typedef struct odp_crypto_generic_session odp_crypto_generic_session_t;

/**
 * Algorithm handler function prototype
 */
typedef
enum crypto_alg_err (*crypto_func_t)(odp_crypto_op_params_t *params,
				     odp_crypto_generic_session_t *session);

/**
 * Function prototypes for ESP protocol computation.They are called in
 * "odp_crypto_operation" function when proto-esp option is active.
 */
typedef
void (*before_func)(odp_crypto_op_params_t *params,
		    odp_crypto_generic_session_t *session);
typedef
void (*after_func)(odp_crypto_op_params_t *params,
		   odp_crypto_generic_session_t *session);
/**
 * Per crypto session data structure
 */
struct odp_crypto_generic_session {
	struct odp_crypto_generic_session *next;
	enum odp_crypto_op op;
	odp_bool_t do_cipher_first;
	odp_queue_t compl_queue;
	odp_pool_t output_pool;
	odp_atomic_u64_t seq_no;
	odp_ipsec_params_t ipsec_params;
	enum odp_ipsec_mode ipsec_mode;
	enum odp_ipsec_proto ipsec_proto;
	struct {
		before_func before;
		after_func after;
	} in_crypto_func;
	struct {
		enum odp_cipher_alg   alg;
		struct {
			uint8_t *data;
			size_t   len;
		} iv;
		union {
			struct {
				DES_key_schedule ks1;
				DES_key_schedule ks2;
				DES_key_schedule ks3;
			} des;
		} data;
		crypto_func_t func;
	} cipher;
	struct {
		enum odp_auth_alg  alg;
		int icv_len;
		union {
			struct {
				uint8_t  key[16];
				uint32_t bytes;
			} md5;
		} data;
		crypto_func_t func;
	} auth;
};

/**
 * Per packet operation result
 */
typedef struct odp_crypto_generic_op_result {
	uint32_t magic;
	odp_crypto_op_result_t result;
} odp_crypto_generic_op_result_t;

/**
 * Per session creation operation result
 */
typedef struct odp_crypto_generic_session_result {
	enum odp_crypto_ses_create_err rc;
	odp_crypto_session_t           session;
} odp_crypto_generic_session_result_t;

#ifdef __cplusplus
}
#endif

#endif
