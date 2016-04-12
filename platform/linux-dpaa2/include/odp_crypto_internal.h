/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
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
#include <odp/crypto.h>
#include <odp/helper/ip.h>
#include <odp/helper/udp.h>
#include <nadk_sec_priv.h>

#define SES_STATUS_FREE     0
#define SES_STATUS_INUSE    1

/**
 * Maximum number of crypto sessions
 */
#define ODP_CONFIG_CRYPTO_SES   64

extern struct nadk_dev *sec_dev;

/*!
 * The type of operation supported by NADK SEC Library
 */
enum nadk_op_type {
	NADK_SEC_NONE,	/*!< No Cipher operations*/
	NADK_SEC_CIPHER,/*!< CIPHER operations */
	NADK_SEC_AUTH,	/*!< Authentication Operations */
	NADK_SEC_AEAD,	/*!< Authenticated Encryption with associated data */
	NADK_SEC_IPSEC,	/*!< IPSEC protocol operations*/
	NADK_SEC_PDCP,	/*!< PDCP protocol operations*/
	NADK_SEC_PKC,	/*!< Public Key Cryptographic Operations */
	NADK_SEC_MAX
};

/*!
 * Class 1 context to be supplied by application
 */
struct nadk_cipher_ctxt {
	odp_crypto_iv_t  iv;	/**< Cipher Initialization Vector (IV) */
	uint8_t *init_counter;	/*!< Set initial counter for CTR mode */
};

/*!
 *  Class 2 context to be supplied by application
 */
struct nadk_auth_ctxt {
	uint8_t trunc_len;              /*!< Length for output ICV, should
					  * be 0 if no truncation required */
};

/*!
 * AEAD Processing context for single pass non-protocol processing
 */
struct nadk_aead_ctxt {
	odp_bool_t auth_cipher_text;       /**< Authenticate/cipher ordering */
	odp_crypto_iv_t  iv;	/**< Cipher Initialization Vector (IV) */
	uint16_t auth_only_len; /*!< Length of data for Auth only */
	uint8_t trunc_len;              /*!< Length for output ICV, should
					  * be 0 if no truncation required */
};

/*!
 * nadk header for NAT-T support in IPSec ESP
 */
struct nadk_sec_natt_hdr {
	odph_ipv4hdr_t tunnel_header;	/*!< Outer IP Header for
			* tunnel mode*/
	odph_udphdr_t udp_header;	/*!< UDP Header for NAT Traversal
			* support. Valid for NAT-T tunnels*/
};

/*!
 * Additional IPSec header and options
 */
union header {
	struct nadk_sec_natt_hdr natt;	/*!< Outer NATT Header */
	odph_ipv4hdr_t ip4_hdr;	/*!< Outer IPv4 Header */
};

#define NADK_IPSEC_ESN 0x0001	/*!< Extended sequence number in IPSec */
#define NADK_IV_RANDOM 0x0002	/*!< Random IV for Class 1 Operation */
#define NADK_IPSEC_NATT 0x0004	/*!< NAT-Traversal required */
#define NADK_IPSEC_ANTIREPLAY_NONE 0x0008	/*!< No Antireplay Support*/
#define NADK_IPSEC_ANTIREPLAY_32 0x0010	/*!< Antireplay window of 32 bit */
#define NADK_IPSEC_ANTIREPLAY_64 0x0018	/*!< Antireplay window of 64 bit */
#define NADK_IPSEC_ANTIREPLAY_MASK 0x0018 /*!< Antireplay flag mask */
#define NADK_IPSEC_IP_CHECKSUM	0x0020	/*!<IP Header checksum update */
#define NADK_IPSEC_DTTL	0x0040	/*!<IP Header TTL Decrement */

/*!
 * The structure is to be filled by user as a part of
 * nadk_sec_proto_ctxt
 */
struct nadk_ipsec_ctxt {
	enum odp_ipsec_mode ipsec_mode; /*!< Operation Mode Tunnel/Transport*/
	uint16_t proto_flags;	/*!< Protocol specific bit-flags */
	odp_crypto_iv_t  iv;	/**< Cipher Initialization Vector (IV) */
	uint32_t salt_nounce;	/*!< Nounce for CTR mode algo's and salt
				 * for GCM mode*/
	uint32_t init_count;	/*!< Initial counter for counter mode algo's*/
	uint32_t spi;		/*!< SPI value */
	union header hdr;	/*!< Header options for IPSec Protocol */
};

/*!
 * The structure is to be filled by user as a part of
 * nadk_sec_proto_ctxt for PDCP Control Plane Protocol
 */
struct nadk_pdcp_ctxt {
	enum odp_pdcp_mode pdcp_mode;	/*!< Data/Control mode*/
	int8_t bearer;	/*!< PDCP bearer ID */
	int8_t pkt_dir;/*!< PDCP Frame Direction 0:UL 1:DL*/
	int8_t hfn_ovd;/*!< Overwrite HFN per packet*/
	uint32_t hfn;	/*!< Hyper Frame Number */
	uint32_t hfn_threshold;	/*!< HFN Threashold for key renegotiation */
	uint8_t sn_size;	/*!< Sequence number size, 7/12/15 */
	/*!< Type of the Class 2 algorithm. Supports SHA1 */

};

#define NULL_CRYPTO	1
#define NULL_IPSEC	2
struct nadk_null_sec_ctxt {
	enum odp_ipsec_mode ipsec_mode; /*!< Operation Mode Tunnel/Transport*/
	uint8_t null_ctxt_type; /*!< NULL CRYPTO or NULL IPSEC context */
	uint32_t spi;           /*!< SPI value */
	uint32_t seq_no;         /**< ESP TX sequence number */
	union header hdr;	/*!< Header options for IPSec Protocol */
};

typedef struct crypto_ses_entry_u {
	odp_queue_t compl_queue;
	void *ctxt;	/*!< Additional opaque context maintained for NADK
			 * Driver. The relevant information to be filled by
			 * NADK SEC driver are per flow FLC, associated SEC
			 * Object */
	uint8_t ctxt_type;
	enum odp_crypto_op dir;		/*!< Operation Direction */
	enum odp_cipher_alg cipher_alg;	/*!< Cipher Algorithm*/
	enum odp_auth_alg auth_alg;	/*!< Authentication Algorithm*/
	odp_crypto_key_t cipher_key;	/**< Cipher key */
	odp_crypto_key_t auth_key;	/**< Authentication key */
	uint8_t status;
	union {
		struct nadk_cipher_ctxt cipher_ctxt;
		struct nadk_auth_ctxt auth_ctxt;
		struct nadk_aead_ctxt aead_ctxt;
		struct nadk_ipsec_ctxt ipsec_ctxt;
		struct nadk_pdcp_ctxt pdcp_ctxt;
		struct nadk_null_sec_ctxt null_sec_ctxt;
	} ext_params;
} crypto_ses_entry_t;

typedef struct crypto_ses_table_t {
	crypto_ses_entry_t ses[ODP_CONFIG_CRYPTO_SES];
} crypto_ses_table_t;

typedef struct crypto_vq_t {
	void *rx_vq;
	uint8_t vq_id;
	int num_sessions;
} crypto_vq_t;

#ifdef __cplusplus
}
#endif

#endif
