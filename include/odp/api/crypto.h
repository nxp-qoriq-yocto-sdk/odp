/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_API_CRYPTO_H_
#define ODP_API_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @defgroup odp_crypto ODP CRYPTO
 *  Macros, enums, types and operations to utilise crypto.
 *  @{
 */

/**
 * @def ODP_CRYPTO_SESSION_INVALID
 * Invalid session handle
 */

/**
 * @typedef odp_crypto_session_t
 * Crypto API opaque session handle
 */

/**
 * @typedef odp_crypto_compl_t
* Crypto API completion event (platform dependent).
*/

/**
 * @enum odp_crypto_op_mode
 * Crypto API operation mode
 *
 * @enum odp_crypto_op_mode:ODP_CRYPTO_SYNC
 * Synchronous, return results immediately
 *
 * @enum odp_crypto_op_mode:ODP_CRYPTO_ASYNC
 * Aynchronous, return results via posted event
 */

/**
 * @enum odp_crypto_op
 * Crypto API operation type
 *
 * @enum odp_crypto_op:ODP_CRYPTO_OP_ENCODE
 * Encrypt and/or compute authentication ICV
 *
 * @enum odp_crypto_op:ODP_CRYPTO_OP_DECODE
 * Decrypt and/or verify authentication ICV
 */

/**
 * @enum odp_cipher_alg
 * Crypto API cipher algorithm
 *
 * @enum odp_cipher_alg:ODP_CIPHER_ALG_NULL
 * No cipher algorithm specified
 *
 * @enum odp_cipher_alg:ODP_CIPHER_ALG_DES
 * DES
 *
 * @enum odp_cipher_alg:ODP_CIPHER_ALG_3DES_CBC
 * Triple DES with cipher block chaining
 */

/**
 * @enum odp_auth_alg
 * Crypto API authentication algorithm
 *
 * @enum odp_auth_alg:ODP_AUTH_ALG_NULL
 * No authentication algorithm specified
 *
 * @enum odp_auth_alg:ODP_AUTH_ALG_MD5_96
 * HMAC-MD5 with 96 bit key
 */

/**
 * Crypto API key structure
 */
typedef struct odp_crypto_key {
	uint8_t *data;       /**< Key data */
	uint32_t length;     /**< Key length in bytes */
} odp_crypto_key_t;

/**
 * Crypto API IV structure
 */
typedef struct odp_crypto_iv {
	uint8_t *data;      /**< IV data */
	uint32_t length;    /**< IV length in bytes */
} odp_crypto_iv_t;

/**
 * Crypto API data range specifier
 */
typedef struct odp_crypto_data_range {
	uint32_t offset;  /**< Offset from beginning of buffer (chain) */
	uint32_t length;  /**< Length of data to operate on */
} odp_crypto_data_range_t;

/**
 * Crypto API session creation parameters
 */
typedef struct odp_crypto_session_params {
	enum odp_crypto_op op;             /**< Encode versus decode */
	odp_bool_t auth_cipher_text;       /**< Authenticate/cipher ordering */
	enum odp_crypto_op_mode pref_mode; /**< Preferred sync vs async */
	enum odp_cipher_alg cipher_alg;    /**< Cipher algorithm */
	odp_crypto_key_t cipher_key;       /**< Cipher key */
	odp_crypto_iv_t  iv;               /**< Cipher Initialization Vector (IV) */
	enum odp_auth_alg auth_alg;        /**< Authentication algorithm */
	odp_crypto_key_t auth_key;         /**< Authentication key */
	odp_queue_t compl_queue;           /**< Async mode completion event queue */
	odp_pool_t output_pool;            /**< Output buffer pool */
} odp_crypto_session_params_t;

/**
 * @var odp_crypto_session_params_t::auth_cipher_text
 *
 *   Controls ordering of authentication and cipher operations,
 *   and is relative to the operation (encode vs decode).
 *   When encoding, @c TRUE indicates the authentication operation
 *   should be performed @b after the cipher operation else before.
 *   When decoding, @c TRUE indicates the reverse order of operation.
 *
 * @var odp_crypto_session_params_t::compl_queue
 *
 *   When the API operates asynchronously, the completion queue is
 *   used to return the completion status of the operation to the
 *   application.
 *
 * @var odp_crypto_session_params_t::output_pool
 *
 *   When the output packet is not specified during the call to
 *   odp_crypto_operation, the output packet buffer will be allocated
 *   from this pool.
 */

/**
 * Crypto API per packet operation parameters
 */
typedef struct odp_crypto_op_params {
	odp_crypto_session_t session;   /**< Session handle from creation */
	void *ctx;                      /**< User context */
	odp_packet_t pkt;               /**< Input packet buffer */
	odp_packet_t out_pkt;           /**< Output packet buffer */
	uint8_t *override_iv_ptr;       /**< Override session IV pointer */
	uint32_t hash_result_offset;    /**< Offset from start of packet buffer for hash result */
	odp_crypto_data_range_t cipher_range;   /**< Data range to apply cipher */
	odp_crypto_data_range_t auth_range;     /**< Data range to authenticate */
} odp_crypto_op_params_t;

/**
 * @var odp_crypto_op_params_t::pkt
 *   Specifies the input packet buffer for the crypto operation.  When the
 *   @c out_pkt variable is set to @c ODP_PACKET_INVALID (indicating a new
 *   buffer should be allocated for the resulting packet), the \#define TBD
 *   indicates whether the implementation will free the input packet buffer
 *   or if it becomes the responsibility of the caller.
 *
 * @var odp_crypto_op_params_t::out_pkt
 *
 *   The API supports both "in place" (the original packet "pkt" is
 *   modified) and "copy" (the packet is replicated to a new buffer
 *   which contains the modified data).
 *
 *   The "in place" mode of operation is indicated by setting @c out_pkt
 *   equal to @c pkt.  For the copy mode of operation, setting @c out_pkt
 *   to a valid packet buffer value indicates the caller wishes to specify
 *   the destination buffer.  Setting @c out_pkt to @c ODP_PACKET_INVALID
 *   indicates the caller wishes the destination packet buffer be allocated
 *   from the output pool specified during session creation.
 *
 *   @sa odp_crypto_session_params_t::output_pool.
 */

/**
 * @enum odp_crypto_ses_create_err
 * Crypto API session creation return code
 *
 * @enum odp_crypto_ses_create_err:ODP_CRYPTO_SES_CREATE_ERR_NONE
 * Session created
 *
 * @enum odp_crypto_ses_create_err:ODP_CRYPTO_SES_CREATE_ERR_ENOMEM
 * Creation failed, no resources
 *
 * @enum odp_crypto_ses_create_err:ODP_CRYPTO_SES_CREATE_ERR_INV_CIPHER
 * Creation failed, bad cipher params
 *
 * @enum odp_crypto_ses_create_err:ODP_CRYPTO_SES_CREATE_ERR_INV_AUTH
 * Creation failed, bad auth params
 */

/**
 * @enum crypto_alg_err
 * Crypto API algorithm return code
 *
 * @enum crypto_alg_err:ODP_CRYPTO_ALG_ERR_NONE
 * Algorithm successful
 *
 * @enum crypto_alg_err:ODP_CRYPTO_ALG_ERR_DATA_SIZE
 * Invalid data block size
 *
 * @enum crypto_alg_err:ODP_CRYPTO_ALG_ERR_KEY_SIZE
 * Key size invalid for algorithm
 *
 * @enum crypto_alg_err:ODP_CRYPTO_ALG_ERR_ICV_CHECK
 * Computed ICV value mismatch
 *
 * @enum crypto_alg_err:ODP_CRYPTO_ALG_ERR_IV_INVALID
 * IV value not specified
 */

/**
 * @enum crypto_hw_err
 * Crypto API hardware centric return code
 *
 * @enum crypto_hw_err:ODP_CRYPTO_HW_ERR_NONE
 * Operation completed successfully
 *
 * @enum crypto_hw_err:ODP_CRYPTO_HW_ERR_DMA
 * Error detected during DMA of data
 *
 * @enum crypto_hw_err:ODP_CRYPTO_HW_ERR_BP_DEPLETED
 * Operation failed due to buffer pool depletion
 */

/**
 * Cryto API per packet operation completion status
 */
typedef struct odp_crypto_compl_status {
	enum crypto_alg_err alg_err;  /**< Algorithm specific return code */
	enum crypto_hw_err  hw_err;   /**< Hardware specific return code */
} odp_crypto_compl_status_t;

/**
 * Crypto API operation result
 */
typedef struct odp_crypto_op_result {
	odp_bool_t  ok;                  /**< Request completed successfully */
	void *ctx;                       /**< User context from request */
	odp_packet_t pkt;                /**< Output packet */
	odp_crypto_compl_status_t cipher_status; /**< Cipher status */
	odp_crypto_compl_status_t auth_status;   /**< Authentication status */
	int proto_status;		/**< Protocol specific status
					 * Bit wise errors
					 * LSB-Bit 0 - if set indicates that
					 * HFN value matches or exceeds
					 * HFN threshold
					 * Others reserved */
} odp_crypto_op_result_t;

/**
 * Crypto session creation (synchronous)
 *
 * @param params            Session parameters
 * @param session           Created session else ODP_CRYPTO_SESSION_INVALID
 * @param status            Failure code if unsuccessful
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int
odp_crypto_session_create(odp_crypto_session_params_t *params,
			  odp_crypto_session_t *session,
			  enum odp_crypto_ses_create_err *status);

/**
 * Crypto session destroy
 *
 * Destroy an unused session. Result is undefined if session is being used
 * (i.e. asynchronous operation is in progress).
 *
 * @param session           Session handle
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int odp_crypto_session_destroy(odp_crypto_session_t session);

/**
 * Return crypto completion handle that is associated with event
 *
 * Note: any invalid parameters will cause undefined behavior and may cause
 * the application to abort or crash.
 *
 * @param ev An event of type ODP_EVENT_CRYPTO_COMPL
 *
 * @return crypto completion handle
 */
odp_crypto_compl_t odp_crypto_compl_from_event(odp_event_t ev);

/**
 * Convert crypto completion handle to event handle
 *
 * @param completion_event  Completion event to convert to generic event
 *
 * @return Event handle
 */
odp_event_t odp_crypto_compl_to_event(odp_crypto_compl_t completion_event);

/**
 * Release crypto completion event
 *
 * @param completion_event  Completion event we are done accessing
 */
void
odp_crypto_compl_free(odp_crypto_compl_t completion_event);

/**
 * Crypto per packet operation
 *
 * Performs the cryptographic operations specified during session creation
 * on the packet.  If the operation is performed synchronously, "posted"
 * will return FALSE and the result of the operation is immediately available.
 * If "posted" returns TRUE the result will be delivered via the completion
 * queue specified when the session was created.
 *
 * @param params            Operation parameters
 * @param posted            Pointer to return posted, TRUE for async operation
 * @param result            Results of operation (when posted returns FALSE)
 *
 * @retval 0 on success
 * @retval <0 on failure
 */
int
odp_crypto_operation(odp_crypto_op_params_t *params,
		     odp_bool_t *posted,
		     odp_crypto_op_result_t *result);

/**
 * Crypto per packet operation query result from completion event
 *
 * @param completion_event  Event containing operation results
 * @param result            Pointer to result structure
 */
void
odp_crypto_compl_result(odp_crypto_compl_t completion_event,
			odp_crypto_op_result_t *result);

/**
 * Get printable value for an odp_crypto_session_t
 *
 * @param hdl  odp_crypto_session_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_crypto_session_t handle.
 */
uint64_t odp_crypto_session_to_u64(odp_crypto_session_t hdl);

/**
 * Get printable value for an odp_crypto_compl_t
 *
 * @param hdl  odp_crypto_compl_t handle to be printed
 * @return     uint64_t value that can be used to print/display this
 *             handle
 *
 * @note This routine is intended to be used for diagnostic purposes
 * to enable applications to generate a printable value that represents
 * an odp_crypto_compl_t handle.
 */
uint64_t odp_crypto_compl_to_u64(odp_crypto_compl_t hdl);

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
