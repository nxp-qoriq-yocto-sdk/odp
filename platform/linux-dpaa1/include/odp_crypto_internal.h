/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:	BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto - implementation internal
 */

#ifndef ODP_CRYPTO_INTERNAL_H_
#define ODP_CRYPTO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/pool.h>
#include <odp/buffer.h>
#include <odp/debug.h>
#include <odp/align.h>
#include <odp/crypto.h>
#include <odp/helper/ip.h>
#include <configs/odp_config_platform.h>

#include <odp_pool_internal.h>


#include <usdpaa/fsl_usd.h>
#include <usdpaa/fsl_qman.h>

#if defined LS1043
/* RTA defines cpu_to_be32 and cpu_to_le32 macros for its internal use,
 * only if both are not yet defined here, so they are un-defined here, in
 * order to RTA defines its own macros.
 * These defines must be removed after integration with RTA */
#if defined(cpu_to_be32)
	#undef cpu_to_be32
#endif
#endif	/* LS1043 */

#include <flib/desc/common.h>
#include <flib/rta.h>

/* RTA un-defines __BIG_ENDIAN on LE platforms or __LITTLE_ENDIAN on BE
 * platforms. Redefine the macros in order to ODP applications compile.
 * These defines must be removed after integration with RTA */
#ifndef __BIG_ENDIAN
	#define __BIG_ENDIAN	0x10e1
#endif
#ifndef __LITTLE_ENDIAN
	#define __LITTLE_ENDIAN	0xe110
#endif

/** apps/lib/crypto/sec.h */
#define MAX_DESCRIPTOR_SIZE	 64
#define SEC_PREHDR_SDLEN_MASK	 0x0000007F /**< Bit mask for PreHeader length
						 field */

/* Optimization -
   ignore override_iv_ptr crypto arg and read IV from packet */
#undef ODP_CRYPTO_IV_FROM_PACKET

/* Use ICV SW check until HW check is available
 */
#define ODP_CRYPTO_ICV_HW_CHECK

#ifdef ODP_CRYPTO_ICV_HW_CHECK
#define ICV_CHECK_SG_NUM	4
#else
#define ICV_CHECK_SG_NUM	3
#endif

/** rta/include/flib/desc/common.h */
/**
 * struct my_alginfo - Container for algorithm details
 * @algtype: algorithm selector; for valid values, see documentation of the
 *           functions where it is used.
 * @keylen: length of the provided algorithm key, in bytes
 * @key: address where algorithm key resides; virtual address if key_type is
 *       RTA_DATA_IMM, physical (bus) address if key_type is RTA_DATA_PTR or
 *       RTA_DATA_IMM_DMA.
 * @key_enc_flags: key encryption flags; see encrypt_flags parameter of KEY
 *                 command for valid values.
 * @key_type: enum rta_data_type
 * @algmode: algorithm mode selector; for valid values, see documentation of the
 *           functions where it is used.
 */
struct my_alginfo {
	uint32_t algtype;
	uint32_t keylen;
	uint64_t key;
	uint32_t key_enc_flags;
	enum rta_data_type key_type;
	uint16_t algmode;
};

/**
 * cnstr_shdsc_blkcipher - block cipher transformation
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: if true, perform descriptor byte swapping on a 4-byte boundary
 * @cipherdata: pointer to block cipher transform definitions
 * @iv: IV data; if NULL, "ivlen" bytes from the input frame will be read as IV
 * @ivlen: IV length
 * @dir: DIR_ENC/DIR_DEC
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int my_cnstr_shdsc_blkcipher(uint32_t *descbuf,
				bool ps, bool swap,
				struct my_alginfo *cipherdata,
				uint8_t *iv, uint32_t ivlen, uint8_t dir)
{
	struct program prg;
	struct program *p = &prg;
	const bool is_aes_dec = (dir == DIR_DEC) &&
				(cipherdata->algtype == OP_ALG_ALGSEL_AES);
	LABEL(keyjmp);
	LABEL(skipdk);
	REFERENCE(pkeyjmp);
	REFERENCE(pskipdk);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	SHR_HDR(p, SHR_SERIAL, 1, SC);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
		/* Insert Key */
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));

	if (is_aes_dec) {
		ALG_OPERATION(p, cipherdata->algtype, cipherdata->algmode,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);

		pskipdk = JUMP(p, skipdk, LOCAL_JUMP, ALL_TRUE, 0);
	}
	SET_LABEL(p, keyjmp);

	if (is_aes_dec) {
		ALG_OPERATION(p, OP_ALG_ALGSEL_AES, cipherdata->algmode |
			      OP_ALG_AAI_DK, OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE, dir);
		SET_LABEL(p, skipdk);
	} else {
		ALG_OPERATION(p, cipherdata->algtype, cipherdata->algmode,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	}

		if (iv)
			/* IV load, convert size */
		LOAD(p, (uintptr_t)iv, CONTEXT1, 0, ivlen, IMMED | COPY);
		else
			/* IV is present first before the actual message */
		SEQLOAD(p, CONTEXT1, 0, ivlen, 0);

	MATHB(p, SEQINSZ, SUB, MATH2, VSEQINSZ, 4, 0);
	MATHB(p, SEQINSZ, SUB, MATH2, VSEQOUTSZ, 4, 0);

		/* Insert sequence load/store with VLF */
	SEQFIFOLOAD(p, MSG1, 0, VLF | LAST1);
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	if (is_aes_dec)
		PATCH_JUMP(p, pskipdk, skipdk);

	return PROGRAM_FINALIZE(p);
}

#ifdef ODP_CRYPTO_ICV_HW_CHECK
/**
 * my_cnstr_shdsc_hmac - HMAC shared
 * @descbuf: pointer to descriptor-under-construction buffer
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: if true, perform descriptor byte swapping on a 4-byte boundary
 * @authdata: pointer to authentication transform definitions;
 *            message digest algorithm: OP_ALG_ALGSEL_MD5/ SHA1-512.
 * @do_icv: 0 if ICV checking is not desired, any other value if ICV checking
 *          is needed for all the packets processed by this shared descriptor
 * @trunc_len: Length of the truncated ICV to be written in the output buffer, 0
 *             if no truncation is needed
 *
 * Note: There's no support for keys longer than the corresponding digest size,
 * according to the selected algorithm.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int my_cnstr_shdsc_hmac(uint32_t *descbuf,
				odp_bool_t ps, odp_bool_t swap,
		      struct my_alginfo *authdata, uint8_t do_icv,
		      uint8_t trunc_len)
{
	struct program prg;
	struct program *p = &prg;
	uint8_t storelen, opicv, dir;
	LABEL(keyjmp);
	LABEL(jmpprecomp);
	REFERENCE(pkeyjmp);
	REFERENCE(pjmpprecomp);

	/* Compute fixed-size store based on alg selection */
	switch (authdata->algtype) {
	case OP_ALG_ALGSEL_MD5:
		storelen = 16;
		break;
	case OP_ALG_ALGSEL_SHA1:
		storelen = 20;
		break;
	case OP_ALG_ALGSEL_SHA224:
		storelen = 28;
		break;
	case OP_ALG_ALGSEL_SHA256:
		storelen = 32;
		break;
	case OP_ALG_ALGSEL_SHA384:
		storelen = 48;
		break;
	case OP_ALG_ALGSEL_SHA512:
		storelen = 64;
		break;
	default:
		return -EINVAL;
	}

	trunc_len = trunc_len && (trunc_len < storelen) ? trunc_len : storelen;

	opicv = do_icv ? ICV_CHECK_ENABLE : ICV_CHECK_DISABLE;
	dir = do_icv ? DIR_DEC : DIR_ENC;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	SHR_HDR(p, SHR_SERIAL, 1, SC);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);
	KEY(p, KEY2, authdata->key_enc_flags, authdata->key, storelen,
	    INLINE_KEY(authdata));

	/* Do operation */
	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC,
		      OP_ALG_AS_INITFINAL, opicv, dir);

	pjmpprecomp = JUMP(p, jmpprecomp, LOCAL_JUMP, ALL_TRUE, 0);
	SET_LABEL(p, keyjmp);

	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC_PRECOMP,
		      OP_ALG_AS_INITFINAL, opicv, dir);

	SET_LABEL(p, jmpprecomp);

	/* compute sequences */
	if (opicv == ICV_CHECK_ENABLE)
		MATHB(p, SEQINSZ, SUB, trunc_len, VSEQINSZ, 4, IMMED2);
	else
		MATHB(p, SEQINSZ, SUB, MATH2, VSEQINSZ, 4, 0);

	/* Do load (variable length) */
	SEQFIFOLOAD(p, MSG2, 0, VLF | LAST2);

	if (opicv == ICV_CHECK_ENABLE)
		SEQFIFOLOAD(p, ICV2, trunc_len, LAST2);
	else
		SEQSTORE(p, CONTEXT2, 0, trunc_len, 0);

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, pjmpprecomp, jmpprecomp);

	return PROGRAM_FINALIZE(p);
}

#else
#error "Must be updated to support the ps and swap parameters..."
/* It's really needed? Now it is not used. Remove it when RTA integration is
 * done. Remove also the ODP_CRYPTO_ICV_HW_CHECK definition.
 */
static inline void my_cnstr_shdsc_hmac(uint32_t *descbuf, unsigned *bufsize,
		      struct my_alginfo *authdata, uint8_t *icv, uint8_t trunclen)
{
	struct program prg;
	struct program *program = &prg;
	uint8_t storelen;
	uint8_t opicv;

	/* Compute fixed-size store based on alg selection */
	switch (authdata->algtype) {
	case OP_ALG_ALGSEL_MD5:
		storelen = 16;
		break;
	case OP_ALG_ALGSEL_SHA1:
		storelen = 20;
		break;
	case OP_ALG_ALGSEL_SHA224:
		storelen = 28;
		break;
	case OP_ALG_ALGSEL_SHA256:
		storelen = 32;
		break;
	case OP_ALG_ALGSEL_SHA384:
		storelen = 48;
		break;
	case OP_ALG_ALGSEL_SHA512:
		storelen = 64;
		break;
	default:
		return;
	}

	opicv = icv ? ICV_CHECK_ENABLE : ICV_CHECK_DISABLE;

	PROGRAM_CNTXT_INIT(program, descbuf, 0);
	SHR_HDR(program, SHR_ALWAYS, 1, SC);
	{
		KEY(program, KEY2, authdata->key_enc_flags, authdata->key,
		    storelen, IMMED | COPY);
		/* compute sequences */
		MATHB(program, SEQINSZ, SUB, MATH2, VSEQINSZ, 4, 0);
		MATHB(program, SEQINSZ, SUB, MATH2, VSEQOUTSZ, 4, 0);
		/* Do operation */
		ALG_OPERATION(program, authdata->algtype, OP_ALG_AAI_HMAC,
			      OP_ALG_AS_INITFINAL, opicv, DIR_ENC);
		/* Do load (variable length) */
		SEQFIFOLOAD(program, MSG2, 32, VLF | LAST1 | LAST2);
		SEQSTORE(program, CONTEXT2, 0, trunclen, 0);
	}
	*bufsize = PROGRAM_FINALIZE(program);
}
#endif

#ifdef CAAM_DESC_SHARE_SERIAL
/*
 * RTA_INTEGRATED
 *
 * When the integration with RTA will be done, the descriptors in this file
 * should be removed. Now the descriptors are pasted from RTA and the my_
 * prefix was added.
 *
 * my_cnstr_shdsc_combined should be replaced with my_cnstr_shdsc_authenc. Code
 * must be updated to use the RTA cnstr_shdsc_authenc descriptor (SG info).
 */

//#define RTA_INTEGRATED

#ifndef RTA_INTEGRATED
static inline int
my_cnstr_shdsc_combined(uint32_t *descbuf,
			odp_bool_t ps, odp_bool_t swap,
			struct my_alginfo *cipherdata,
			struct my_alginfo *authdata,
			uint32_t ivlen, uint32_t auth_only_len,
			uint8_t trunc_len, uint8_t dir) {
	struct program prg;
	struct program *p = &prg;
	const int is_aes_dec = (dir == DIR_DEC) &&
			   (cipherdata->algtype == OP_ALG_ALGSEL_AES);

	uint8_t storelen;
	LABEL(keyjmp);
	LABEL(skipkeys);
	REFERENCE(pkeyjmp);
	REFERENCE(pskipkeys);

	/* Compute fixed-size store based on alg selection */
	switch (authdata->algtype) {
	case OP_ALG_ALGSEL_MD5:
		storelen = 16;
		break;
	case OP_ALG_ALGSEL_SHA1:
		storelen = 20;
		break;
	case OP_ALG_ALGSEL_SHA224:
		storelen = 28;
		break;
	case OP_ALG_ALGSEL_SHA256:
		storelen = 32;
		break;
	case OP_ALG_ALGSEL_SHA384:
		storelen = 48;
		break;
	case OP_ALG_ALGSEL_SHA512:
		storelen = 64;
		break;
	default:
		return -EINVAL;
	}

	trunc_len = trunc_len && (trunc_len < storelen) ? trunc_len : storelen;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	SHR_HDR(p, SHR_SERIAL, 1, SC);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);

	KEY(p, KEY2, authdata->key_enc_flags, authdata->key, storelen,
			INLINE_KEY(authdata));

	/* Insert Key */
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));

	/* Do operation */
	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC,
		      OP_ALG_AS_INITFINAL,
		      dir == DIR_ENC ? ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      dir);

	if (is_aes_dec)
		ALG_OPERATION(p, cipherdata->algtype, OP_ALG_AAI_CBC,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	pskipkeys = JUMP(p, skipkeys, LOCAL_JUMP, ALL_TRUE, 0);

	SET_LABEL(p, keyjmp);

	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC_PRECOMP,
		      OP_ALG_AS_INITFINAL,
		      dir == DIR_ENC ? ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      dir);

	if (is_aes_dec) {
		ALG_OPERATION(p, OP_ALG_ALGSEL_AES, OP_ALG_AAI_CBC |
			      OP_ALG_AAI_DK, OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE, dir);
		SET_LABEL(p, skipkeys);
	} else {
		SET_LABEL(p, skipkeys);
		ALG_OPERATION(p, cipherdata->algtype, OP_ALG_AAI_CBC,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	}

	if (dir == DIR_ENC)
		MATHB(p, SEQINSZ, SUB, ivlen + auth_only_len, VSEQINSZ, 4, IMMED2);
	else
		MATHB(p, SEQINSZ, SUB, ivlen + auth_only_len + trunc_len,
		      VSEQINSZ, 4,  IMMED2);
	MATHB(p, VSEQINSZ, SUB, MATH0, VSEQOUTSZ, 4, 0);

	/* Prepare for writing the output frame */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	/* Read IV */
	SEQLOAD(p, CONTEXT1, 0, ivlen, 0);

	/* Read data needed only for authentication */
	SEQFIFOLOAD(p, MSG2, auth_only_len, 0);

	if (dir == DIR_ENC) {
		/* Read input plaintext, encrypt and authenticate & write to output */
		SEQFIFOLOAD(p, MSGOUTSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Finally, write the ICV */
		SEQSTORE(p, CONTEXT2, 0, trunc_len, 0);
	} else {
		/* Read input plaintext, encrypt and authenticate & write to output */
		SEQFIFOLOAD(p, MSGINSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Read the ICV to check */
		SEQFIFOLOAD(p, ICV2, trunc_len, LAST2);
	}

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, pskipkeys, skipkeys);

	return PROGRAM_FINALIZE(p);
}

#else
#error "Not tested. Use this descriptor for RTA integration."

/**
 * cnstr_shdsc_authenc - authenc-like descriptor
 * @descbuf: pointer to buffer used for descriptor construction
 * @swap: if true, perform descriptor byte swapping on a 4-byte boundary
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @cipherdata: ointer to block cipher transform definitions.
 *              Valid algorithm values one of OP_ALG_ALGSEL_* {DES, 3DES, AES}
 * @authdata: pointer to authentication transform definitions.
 *            Valid algorithm values - one of OP_ALG_ALGSEL_* {MD5, SHA1,
 *            SHA224, SHA256, SHA384, SHA512}
 * Note: The key for authentication is supposed to be given as plain text.
 * Note: There's no support for keys longer than the corresponding digest size,
 *       according to the selected algorithm.
 *
 * @ivlen: length of the IV to be read from the input frame, before any data
 *         to be processed
 * @auth_only_len: length of the data to be authenticated-only (commonly IP
 *                 header, IV, Sequence number and SPI)
 * Note: Extended Sequence Number processing is NOT supported
 *
 * @trunc_len: the length of the ICV to be written to the output frame. If 0,
 *             then the corresponding length of the digest, according to the
 *             selected algorithm shall be used.
 * @dir: Protocol direction, encapsulation or decapsulation (DIR_ENC/DIR_DEC)
 *
 * Note: Here's how the input frame needs to be formatted so that the processing
 *       will be done correctly:
 * For encapsulation:
 *     Input:
 * +----+----------------+---------------------------------------------+
 * | IV | Auth-only data | Padded data to be authenticated & Encrypted |
 * +----+----------------+---------------------------------------------+
 *     Output:
 * +--------------------------------------+
 * | Authenticated & Encrypted data | ICV |
 * +--------------------------------+-----+

 * For decapsulation:
 *     Input:
 * +----+----------------+--------------------------------+-----+
 * | IV | Auth-only data | Authenticated & Encrypted data | ICV |
 * +----+----------------+--------------------------------+-----+
 *     Output:
 * +----+--------------------------+
 * | Decrypted & authenticated data |
 * +----+--------------------------+
 *
 * Note: This descriptor can use per-packet commands, encoded as below in the
 *       DPOVRD register:
 * 32    24    16               0
 * +------+---------------------+
 * | 0x80 | 0x00| auth_only_len |
 * +------+---------------------+
 *
 * This mechanism is available only for SoCs having SEC ERA >= 3. In other
 * words, this will not work for P4080TO2
 *
 * Note: The descriptor does not add any kind of padding to the input data,
 *       so the upper layer needs to ensure that the data is padded properly,
 *       according to the selected cipher. Failure to do so will result in
 *       the descriptor failing with a data-size error.
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int my_cnstr_shdsc_authenc(uint32_t *descbuf, bool swap, bool ps,
				      struct my_alginfo *cipherdata,
				      struct my_alginfo *authdata,
				      uint16_t ivlen, uint16_t auth_only_len,
				      uint8_t trunc_len, uint8_t dir)
{
	struct program prg;
	struct program *p = &prg;
	const bool is_aes_dec = (dir == DIR_DEC) &&
				(cipherdata->algtype == OP_ALG_ALGSEL_AES);

	LABEL(skip_patch_len);
	LABEL(keyjmp);
	LABEL(skipkeys);
	LABEL(aonly_len_offset);
	LABEL(out_skip_offset);
	LABEL(patch_icv_off);
	LABEL(skip_patch_icv_off);
	REFERENCE(pskip_patch_len);
	REFERENCE(pkeyjmp);
	REFERENCE(pskipkeys);
	REFERENCE(read_len);
	REFERENCE(write_len);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);

	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	/*
	 * Since we currently assume that key length is equal to hash digest
	 * size, it's ok to truncate keylen value.
	 */
	trunc_len = trunc_len && (trunc_len < authdata->keylen) ?
			trunc_len : (uint8_t)authdata->keylen;

	SHR_HDR(p, SHR_SERIAL, 1, SC);

	/*
	 * M0 will contain the value provided by the user when creating
	 * the shared descriptor. If the user provided an override in
	 * DPOVRD, then M0 will contain that value
	 */
	MATHB(p, MATH0, ADD, auth_only_len, MATH0, 4, IMMED2);

	if (rta_sec_era >= RTA_SEC_ERA_3) {
		/*
		 * Check if the user wants to override the auth-only len
		 */
		MATHB(p, DPOVRD, ADD, 0x80000000, MATH2, 4, IMMED2);

		/*
		 * No need to patch the length of the auth-only data read if
		 * the user did not override it
		 */
		pskip_patch_len = JUMP(p, skip_patch_len, LOCAL_JUMP, ALL_TRUE,
				  MATH_N);

		/* Get auth-only len in M0 */
		MATHB(p, MATH2, AND, 0xFFFF, MATH0, 4, IMMED2);

		/*
		 * Since M0 is used in calculations, don't mangle it, copy
		 * its content to M1 and use this for patching.
		 */
		MATHB(p, MATH0, ADD, MATH1, MATH1, 4, 0);

		read_len = MOVE(p, DESCBUF, 0, MATH1, 0, 6, WAITCOMP | IMMED);
		write_len = MOVE(p, MATH1, 0, DESCBUF, 0, 8, WAITCOMP | IMMED);

		SET_LABEL(p, skip_patch_len);
	}
	/*
	 * MATH0 contains the value in DPOVRD w/o the MSB, or the initial
	 * value, as provided by the user at descriptor creation time
	 */
	if (dir == DIR_ENC)
		MATHB(p, MATH0, ADD, ivlen, MATH0, 4, IMMED2);
	else
		MATHB(p, MATH0, ADD, ivlen + trunc_len, MATH0, 4, IMMED2);

	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, SHRD);

	KEY(p, KEY2, authdata->key_enc_flags, authdata->key, authdata->keylen,
	    INLINE_KEY(authdata));

	/* Insert Key */
	KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, INLINE_KEY(cipherdata));

	/* Do operation */
	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC,
		      OP_ALG_AS_INITFINAL,
		      dir == DIR_ENC ? ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      dir);

	if (is_aes_dec)
		ALG_OPERATION(p, OP_ALG_ALGSEL_AES, cipherdata->algmode,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	pskipkeys = JUMP(p, skipkeys, LOCAL_JUMP, ALL_TRUE, 0);

	SET_LABEL(p, keyjmp);

	ALG_OPERATION(p, authdata->algtype, OP_ALG_AAI_HMAC_PRECOMP,
		      OP_ALG_AS_INITFINAL,
		      dir == DIR_ENC ? ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      dir);

	if (is_aes_dec) {
		ALG_OPERATION(p, OP_ALG_ALGSEL_AES, cipherdata->algmode |
			      OP_ALG_AAI_DK, OP_ALG_AS_INITFINAL,
			      ICV_CHECK_DISABLE, dir);
		SET_LABEL(p, skipkeys);
	} else {
		SET_LABEL(p, skipkeys);
		ALG_OPERATION(p, cipherdata->algtype, cipherdata->algmode,
			      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	}

	/*
	 * Prepare the length of the data to be both encrypted/decrypted
	 * and authenticated/checked
	 */
	MATHB(p, SEQINSZ, SUB, MATH0, VSEQINSZ, 4, 0);

	MATHB(p, VSEQINSZ, SUB, MATH3, VSEQOUTSZ, 4, 0);

	/* Prepare for writing the output frame */
	SEQFIFOSTORE(p, MSG, 0, 0, VLF);

	SET_LABEL(p, aonly_len_offset);

	/* Read IV */
	SEQLOAD(p, CONTEXT1, 0, ivlen, 0);

	/*
	 * Read data needed only for authentication. This is overwritten above
	 * if the user requested it.
	 */
	SEQFIFOLOAD(p, MSG2, auth_only_len, 0);

	if (dir == DIR_ENC) {
		/*
		 * Read input plaintext, encrypt and authenticate & write to
		 * output
		 */
		SEQFIFOLOAD(p, MSGOUTSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Finally, write the ICV */
		SEQSTORE(p, CONTEXT2, 0, trunc_len, 0);
	} else {
		/*
		 * Read input ciphertext, decrypt and authenticate & write to
		 * output
		 */
		SEQFIFOLOAD(p, MSGINSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Read the ICV to check */
		SEQFIFOLOAD(p, ICV2, trunc_len, LAST2);
	}

	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_JUMP(p, pskipkeys, skipkeys);
	PATCH_JUMP(p, pskipkeys, skipkeys);

	if (rta_sec_era >= RTA_SEC_ERA_3) {
		PATCH_JUMP(p, pskip_patch_len, skip_patch_len);
		PATCH_MOVE(p, read_len, aonly_len_offset);
		PATCH_MOVE(p, write_len, aonly_len_offset);
	}

	return PROGRAM_FINALIZE(p);
}

#endif	/* RTA_INTEGRATED */

#else
#error "Must be updated to support the ps and swap parameters..."
/* It's really needed? Now it is not used. Remove it when RTA integration is
 * done. Remove also the CAAM_DESC_SHARE_SERIAL definition from
 * odp_config_platform.h
 */
static inline void
my_cnstr_shdsc_combined(uint32_t *descbuf,
			unsigned *bufsize,
			struct my_alginfo *cipherdata,
			struct my_alginfo *authdata,
			uint32_t ivlen, uint32_t auth_only_len,
			uint8_t trunc_len, uint8_t dir) {
	struct program prg;
	struct program *program = &prg;
	const int is_aes_dec = (dir == DIR_DEC) && \
			   (cipherdata->algtype == OP_ALG_ALGSEL_AES);

	uint8_t storelen;
	LABEL(keyjmp);
	LABEL(skipkeys);
	REFERENCE(pkeyjmp);
	REFERENCE(pskipkeys);

	PROGRAM_CNTXT_INIT(program, descbuf, 0);

	/* Compute fixed-size store based on alg selection */
	switch (authdata->algtype) {
	case OP_ALG_ALGSEL_MD5:
		storelen = 16;
		break;
	case OP_ALG_ALGSEL_SHA1:
		storelen = 20;
		break;
	case OP_ALG_ALGSEL_SHA224:
		storelen = 28;
		break;
	case OP_ALG_ALGSEL_SHA256:
		storelen = 32;
		break;
	case OP_ALG_ALGSEL_SHA384:
		storelen = 48;
		break;
	case OP_ALG_ALGSEL_SHA512:
		storelen = 64;
		break;
	default:
		return;
	}

	trunc_len = trunc_len && (trunc_len < storelen) ? trunc_len : storelen;

	SHR_HDR(program, SHR_ALWAYS, 1, 0);

	KEY(program, KEY2, authdata->key_enc_flags, authdata->key, storelen,
	    IMMED | COPY);

	/* Insert Key */
	KEY(program, KEY1, cipherdata->key_enc_flags, cipherdata->key,
	    cipherdata->keylen, IMMED | COPY);

	/* Do operation */
	ALG_OPERATION(program, authdata->algtype, OP_ALG_AAI_HMAC,
		      OP_ALG_AS_INITFINAL,
		      dir == DIR_ENC ? ICV_CHECK_DISABLE : ICV_CHECK_ENABLE,
		      dir);

	ALG_OPERATION(program, cipherdata->algtype, OP_ALG_AAI_CBC,
		      OP_ALG_AS_INITFINAL, ICV_CHECK_DISABLE, dir);
	if (dir == DIR_ENC)
		MATHB(program, SEQINSZ, SUB, ivlen + auth_only_len, VSEQINSZ, 4, IMMED2);
	else
		MATHB(program, SEQINSZ, SUB, ivlen + auth_only_len + trunc_len,
		      VSEQINSZ, 4,  IMMED2);
	MATHB(program, VSEQINSZ, SUB, MATH0, VSEQOUTSZ, 4, 0);

	/* Prepare for writing the output frame */
	SEQFIFOSTORE(program, MSG, 0, 0, VLF);

	/* Read IV */
	SEQLOAD(program, CONTEXT1, 0, ivlen, 0);

	/* Read data needed only for authentication */
	SEQFIFOLOAD(program, MSG2, auth_only_len, 0);

	if (dir == DIR_ENC) {
		/* Read input plaintext, encrypt and authenticate & write to output */
		SEQFIFOLOAD(program, MSGOUTSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Finally, write the ICV */
		SEQSTORE(program, CONTEXT2, 0, trunc_len, 0);
	} else {
		/* Read input plaintext, encrypt and authenticate & write to output */
		SEQFIFOLOAD(program, MSGINSNOOP, 0, VLF | LAST1 | LAST2 | FLUSH1);

		/* Read the ICV to check */
		SEQFIFOLOAD(program, ICV2, trunc_len, LAST2);
	}

	PATCH_JUMP(program, pkeyjmp, keyjmp);
	PATCH_JUMP(program, pskipkeys, skipkeys);

	*bufsize = PROGRAM_FINALIZE(program);
}
#endif		/* CAAM_DESC_SHARE_SERIAL */

struct preheader_s {
	union {
		uint32_t word;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			uint16_t rsvd63_48;
			unsigned int rsvd47_39:9;
			unsigned int idlen:7;
#else
			unsigned int idlen:7;
			unsigned int rsvd47_39:9;
			uint16_t rsvd63_48;
#endif
		} field;
	} __packed hi;

	union {
		uint32_t word;
		struct {
#if ODP_BYTE_ORDER == ODP_BIG_ENDIAN
			unsigned int rsvd31_30:2;
			unsigned int fsgt:1;
			unsigned int lng:1;
			unsigned int offset:2;
			unsigned int abs:1;
			unsigned int add_buf:1;
			uint8_t pool_id;
			uint16_t pool_buffer_size;
#else
			uint16_t pool_buffer_size;
			uint8_t pool_id;
			unsigned int add_buf:1;
			unsigned int abs:1;
			unsigned int offset:2;
			unsigned int lng:1;
			unsigned int fsgt:1;
			unsigned int rsvd31_30:2;
#endif
		} field;
	} __packed lo;
} __packed;

struct sec_descriptor_t {
	struct preheader_s prehdr;
	uint32_t descbuf[MAX_DESCRIPTOR_SIZE];
};

/** apps/lib/crypto/sec.h end*/

#define SES_STATUS_FREE     0
#define SES_STATUS_INIT     1
#define SES_STATUS_READY    2

struct sg_priv;
typedef	void (*build_compound_fd_t)(struct odp_crypto_op_params *params,
							struct sg_priv *sgp);

struct crypto_ses_s {
	/* session params section */
	enum odp_crypto_op op;
	struct {
		enum odp_cipher_alg cipher_alg;
		odp_crypto_key_t key;
		uint8_t *iv;
		dma_addr_t iv_p;
		size_t iv_len;
	} cipher;

	struct {
		enum odp_auth_alg auth_alg;
		odp_crypto_key_t key;
	} auth;

	enum odp_crypto_op_mode op_mode;

	odp_pool_t output_pool;
	odp_buffer_t out_buf_size;
	odp_queue_t compl_queue;

	/* session internals */
	odp_spinlock_t		lock ODP_ALIGNED_CACHE;
	int			status;
	odp_crypto_session_t	handle;
	odp_queue_t		input_queue;
	struct qman_fq		input_fq;
	struct sec_descriptor_t *prehdr_desc;
	build_compound_fd_t	build_compound_fd;
	uint32_t		auth_only_len;
	/* IPSEC specific */
	/* Split key generation context */
	struct qman_fq		*to_sec_sk_fq;
	struct qman_fq		*from_sec_sk_fq;
	void			*sk_desc; /* Split key Job Queue Descriptor */
	void			*split_key;
	uint32_t		sk_algtype;
};

typedef union crypto_ses_entry_u {
	struct crypto_ses_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct crypto_ses_s))];
} crypto_ses_entry_t;

#define SESSION_FROM_FQ(fq)	 \
	((crypto_ses_entry_t *)container_of(fq, struct crypto_ses_s, input_fq))

/*
 * Operation completion event structure
 * */
struct ODP_PACKED op_compl_event {
	/* output packet */
	odp_packet_t out_pkt;
	/* output fd status*/
	uint32_t status;
	/* operation context */
	void *ctx;
};
#define MAX_ICV_LEN	32

/*
 * S/G entry for submitting CAAM jobs
 * */
struct ODP_PACKED sg_priv {
	struct op_compl_event __ev; /* used when completion event is the input buffer */
	struct qm_sg_entry sg[2]; /* input & output */
	crypto_ses_entry_t *ses;
	odp_buffer_t compl_ev;
	uint8_t icv[MAX_ICV_LEN]; /* computed ICV when checking */
	odp_packet_t in_pkt;
};

/* S/G entries and data for AH ICV check */
struct ODP_PACKED ah_icv_chk_in {
	struct qm_sg_entry sg[ICV_CHECK_SG_NUM]; /* ip_hdr, AH, zero_icv, IP payload, ICV to be checked */
};

struct ODP_PACKED cbc_cipher_in {
	struct qm_sg_entry sg[2]; /* IV + data block */
	uint8_t iv[IV_MAX_LEN];   /* IV */
};

struct ODP_PACKED authenc_encap_in {
	struct qm_sg_entry sg[5]; /* in :IV + auth_only + enc
				    out : enc + ICV */
};

struct ODP_PACKED authenc_decap_in {
	struct qm_sg_entry sg[6]; /* in : IV + ip_hdr|ah + zero ICV + ESP|ESP payload
				     out: decrypted payload + ICV to compare with */
};

/*
 * S/G entry is carried in fd annotation area
 * */
_ODP_STATIC_ASSERT(sizeof(struct sg_priv) <=
		   FD_DEFAULT_OFFSET, "ERR_CAAM_SG_SIZE");

_ODP_STATIC_ASSERT(sizeof(struct ah_icv_chk_in) <=
		   ODP_CONFIG_PACKET_TAILROOM, "ERR_CAAM_SG_SIZE");

_ODP_STATIC_ASSERT(sizeof(struct cbc_cipher_in) <=
		   ODP_CONFIG_PACKET_TAILROOM, "ERR_CAAM_SG_SIZE");

_ODP_STATIC_ASSERT(sizeof(struct authenc_encap_in) <=
		   ODP_CONFIG_PACKET_TAILROOM, "ERR_CAAM_SG_SIZE");

_ODP_STATIC_ASSERT(sizeof(struct authenc_decap_in) <=
		   ODP_CONFIG_PACKET_TAILROOM, "ERR_CAAM_SG_SIZE");

crypto_ses_entry_t *get_ses_entry(uint32_t ses_id);

uint32_t get_sesid(crypto_ses_entry_t *entry);

static inline uint32_t session_to_id(odp_crypto_session_t handle)
{
	return handle - 1;
}

static inline odp_crypto_session_t session_from_id(uint32_t ses_id)
{
	return ses_id + 1;
}

static inline crypto_ses_entry_t *session_to_entry(odp_crypto_session_t handle)
{
	uint32_t ses_id;

	ses_id = session_to_id(handle);
	return get_ses_entry(ses_id);
}

/******************************************************************************/
/**
 * DOC: IPsec Shared Descriptor Constructors
 *
 * Shared descriptors for IPsec protocol.
 */

/* General IPSec ESP encap / decap PDB options */

/**
 * PDBOPTS_ESP_ESN - Extended sequence included
 */
#define PDBOPTS_ESP_ESN		0x10

/**
 * PDBOPTS_ESP_IPVSN - Process IPv6 header
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_IPVSN	0x02

/**
 // * PDBOPTS_ESP_TUNNEL - Tunnel mode next-header byte
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_TUNNEL	0x01

/* IPSec ESP Encap PDB options */

/**
 * PDBOPTS_ESP_UPDATE_CSUM - Update ip header checksum
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_UPDATE_CSUM 0x80

/**
 * PDBOPTS_ESP_DIFFSERV - Copy TOS/TC from inner iphdr
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_DIFFSERV	0x40

/**
 * PDBOPTS_ESP_IVSRC - IV comes from internal random gen
 */
#define PDBOPTS_ESP_IVSRC	0x20

/**
 * PDBOPTS_ESP_IPHDRSRC - IP header comes from PDB
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_IPHDRSRC	0x08

/**
 * PDBOPTS_ESP_INCIPHDR - Prepend IP header to output frame
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_INCIPHDR	0x04

/**
 * PDBOPTS_ESP_OIHI_MASK - Mask for Outer IP Header Included
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_OIHI_MASK	0x0c

/**
 * PDBOPTS_ESP_OIHI_PDB_INL - Prepend IP header to output frame from PDB (where
 *                            it is inlined).
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_OIHI_PDB_INL 0x0c

/**
 * PDBOPTS_ESP_OIHI_PDB_REF - Prepend IP header to output frame from PDB
 *                            (referenced by pointer).
 *
 * Vlid only for IPsec new mode.
 */
#define PDBOPTS_ESP_OIHI_PDB_REF 0x08

/**
 * PDBOPTS_ESP_OIHI_IF - Prepend IP header to output frame from input frame
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_OIHI_IF	0x04

/**
 * PDBOPTS_ESP_NAT - Enable RFC 3948 UDP-encapsulated-ESP
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_NAT		0x02

/**
 * PDBOPTS_ESP_NUC - Enable NAT UDP Checksum
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_NUC		0x01

/* IPSec ESP Decap PDB options */

/**
 * PDBOPTS_ESP_ARS_MASK - antireplay window mask
 */
#define PDBOPTS_ESP_ARS_MASK	0xc0

/**
 * PDBOPTS_ESP_ARSNONE - No antireplay window
 */
#define PDBOPTS_ESP_ARSNONE	0x00

/**
 * PDBOPTS_ESP_ARS64 - 64-entry antireplay window
 */
#define PDBOPTS_ESP_ARS64	0xc0

/**
 * PDBOPTS_ESP_ARS128 - 128-entry antireplay window
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_ARS128	0x80

/**
 * PDBOPTS_ESP_ARS32 - 32-entry antireplay window
 */
#define PDBOPTS_ESP_ARS32	0x40

/**
 * PDBOPTS_ESP_VERIFY_CSUM - Validate ip header checksum
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_VERIFY_CSUM 0x20

/**
 * PDBOPTS_ESP_TECN - Implement RRFC6040 ECN tunneling from outer header to
 *                    inner header.
 *
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_TECN	0x20

/**
 * PDBOPTS_ESP_OUTFMT - Output only decapsulation
 *
 * Valid only for IPsec legacy mode.
 */
#define PDBOPTS_ESP_OUTFMT	0x08

/**
 * PDBOPTS_ESP_AOFL - Adjust out frame len
 *
 * Valid only for IPsec legacy mode and for SEC >= 5.3.
 */
#define PDBOPTS_ESP_AOFL	0x04

/**
 * PDBOPTS_ESP_ETU - EtherType Update
 *
 * Add corresponding ethertype (0x0800 for IPv4, 0x86dd for IPv6) in the output
 * frame.
 * Valid only for IPsec new mode.
 */
#define PDBOPTS_ESP_ETU		0x01

#define PDBHMO_ESP_DECAP_SHIFT		28
#define PDBHMO_ESP_ENCAP_SHIFT		28
#define PDBNH_ESP_ENCAP_SHIFT		16
#define PDBNH_ESP_ENCAP_MASK		(0xff << PDBNH_ESP_ENCAP_SHIFT)
#define PDBHDRLEN_ESP_DECAP_SHIFT	16
#define PDBHDRLEN_MASK			(0x0fff << PDBHDRLEN_ESP_DECAP_SHIFT)

/**
 * PDBHMO_ESP_DECAP_DTTL - IPsec ESP decrement TTL (IPv4) / Hop limit (IPv6)
 *                         HMO option.
 */
#define PDBHMO_ESP_DECAP_DTTL	(0x02 << PDBHMO_ESP_DECAP_SHIFT)

/**
 * PDBHMO_ESP_ENCAP_DTTL - IPsec ESP increment TTL (IPv4) / Hop limit (IPv6)
 *                         HMO option.
 */
#define PDBHMO_ESP_ENCAP_DTTL	(0x02 << PDBHMO_ESP_ENCAP_SHIFT)

/**
 * PDBHMO_ESP_DIFFSERV - (Decap) DiffServ Copy - Copy the IPv4 TOS or IPv6
 *                       Traffic Class byte from the outer IP header to the
 *                       inner IP header.
 */
#define PDBHMO_ESP_DIFFSERV	(0x01 << PDBHMO_ESP_DECAP_SHIFT)

/**
 * PDBHMO_ESP_SNR - (Encap) - Sequence Number Rollover control
 *
 * Configures behaviour in case of SN / ESN rollover:
 * error if SNR = 1, rollover allowed if SNR = 0.
 * Valid only for IPsec new mode.
 */
#define PDBHMO_ESP_SNR		(0x01 << PDBHMO_ESP_ENCAP_SHIFT)

/**
 * PDBHMO_ESP_DFBIT - (Encap) Copy DF bit - if an IPv4 tunnel mode outer IP
 *                    header is coming from the PDB, copy the DF bit from the
 *                    inner IP header to the outer IP header.
 */
#define PDBHMO_ESP_DFBIT	(0x04 << PDBHMO_ESP_ENCAP_SHIFT)

/**
 * PDBHMO_ESP_DFV - (Decap) - DF bit value
 *
 * If ODF = 1, DF bit in output frame is replaced by DFV.
 * Valid only from SEC Era 5 onwards.
 */
#define PDBHMO_ESP_DFV		(0x04 << PDBHMO_ESP_DECAP_SHIFT)

/**
 * PDBHMO_ESP_ODF - (Decap) Override DF bit in IPv4 header of decapsulated
 *                  output frame.
 *
 * If ODF = 1, DF is replaced with the value of DFV bit.
 * Valid only from SEC Era 5 onwards.
 */
#define PDBHMO_ESP_ODF		(0x08 << PDBHMO_ESP_DECAP_SHIFT)

/**
 * struct ipsec_encap_cbc - PDB part for IPsec CBC encapsulation
 * @iv: 16-byte array initialization vector
 */
struct ipsec_encap_cbc {
	uint8_t iv[16];
};


/**
 * struct ipsec_encap_ctr - PDB part for IPsec CTR encapsulation
 * @ctr_nonce: 4-byte array nonce
 * @ctr_initial: initial count constant
 * @iv: initialization vector
 */
struct ipsec_encap_ctr {
	uint8_t ctr_nonce[4];
	uint32_t ctr_initial;
	uint64_t iv;
};

/**
 * struct ipsec_encap_ccm - PDB part for IPsec CCM encapsulation
 * @salt: 3-byte array salt (lower 24 bits)
 * @ccm_opt: CCM algorithm options - MSB-LSB description:
 *  b0_flags (8b) - CCM B0; use 0x5B for 8-byte ICV, 0x6B for 12-byte ICV,
 *    0x7B for 16-byte ICV (cf. RFC4309, RFC3610)
 *  ctr_flags (8b) - counter flags; constant equal to 0x3
 *  ctr_initial (16b) - initial count constant
 * @iv: initialization vector
 */
struct ipsec_encap_ccm {
	uint8_t salt[4];
	uint32_t ccm_opt;
	uint64_t iv;
};

/**
 * struct ipsec_encap_gcm - PDB part for IPsec GCM encapsulation
 * @salt: 3-byte array salt (lower 24 bits)
 * @rsvd: reserved, do not use
 * @iv: initialization vector
 */
struct ipsec_encap_gcm {
	uint8_t salt[4];
	uint32_t rsvd;
	uint64_t iv;
};

/**
 * struct ipsec_encap_pdb - PDB for IPsec encapsulation
 * @options: MSB-LSB description (both for legacy and new modes)
 *  hmo (header manipulation options) - 4b
 *  reserved - 4b
 *  next header (legacy) / reserved (new) - 8b
 *  next header offset (legacy) / AOIPHO (actual outer IP header offset) - 8b
 *  option flags (depend on selected algorithm) - 8b
 * @seq_num_ext_hi: (optional) IPsec Extended Sequence Number (ESN)
 * @seq_num: IPsec sequence number
 * @spi: IPsec SPI (Security Parameters Index)
 * @ip_hdr_len: optional IP Header length (in bytes)
 *  reserved - 16b
 *  Opt. IP Hdr Len - 16b
 * @ip_hdr: optional IP Header content (only for IPsec legacy mode)
 */
struct ipsec_encap_pdb {
	uint32_t options;
	uint32_t seq_num_ext_hi;
	uint32_t seq_num;
	union {
		struct ipsec_encap_cbc cbc;
		struct ipsec_encap_ctr ctr;
		struct ipsec_encap_ccm ccm;
		struct ipsec_encap_gcm gcm;
	};
	uint32_t spi;
	uint32_t ip_hdr_len;
	uint8_t ip_hdr[0];
};

static inline unsigned __my_rta_copy_ipsec_encap_pdb(struct program *program,
						  struct ipsec_encap_pdb *pdb,
						  uint32_t algtype)
{
	unsigned start_pc = program->current_pc;

	__rta_out32(program, pdb->options);
	__rta_out32(program, pdb->seq_num_ext_hi);
	__rta_out32(program, pdb->seq_num);

	switch (algtype & OP_PCL_IPSEC_CIPHER_MASK) {
	case OP_PCL_IPSEC_DES_IV64:
	case OP_PCL_IPSEC_DES:
	case OP_PCL_IPSEC_3DES:
	case OP_PCL_IPSEC_AES_CBC:
	case OP_PCL_IPSEC_NULL:
		rta_copy_data(program, pdb->cbc.iv, sizeof(pdb->cbc.iv));
		break;

	case OP_PCL_IPSEC_AES_CTR:
		rta_copy_data(program, pdb->ctr.ctr_nonce,
			      sizeof(pdb->ctr.ctr_nonce));
		__rta_out32(program, pdb->ctr.ctr_initial);
		__rta_out64(program, true, pdb->ctr.iv);
		break;

	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
		rta_copy_data(program, pdb->ccm.salt, sizeof(pdb->ccm.salt));
		__rta_out32(program, pdb->ccm.ccm_opt);
		__rta_out64(program, true, pdb->ccm.iv);
		break;

	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
	case OP_PCL_IPSEC_AES_NULL_WITH_GMAC:
		rta_copy_data(program, pdb->gcm.salt, sizeof(pdb->gcm.salt));
		__rta_out32(program, pdb->gcm.rsvd);
		__rta_out64(program, true, pdb->gcm.iv);
		break;
	}

	__rta_out32(program, pdb->spi);
	__rta_out32(program, pdb->ip_hdr_len);

	return start_pc;
}

/**
 * struct ipsec_decap_cbc - PDB part for IPsec CBC decapsulation
 * @rsvd: reserved, do not use
 */
struct ipsec_decap_cbc {
	uint32_t rsvd[2];
};

/**
 * struct ipsec_decap_ctr - PDB part for IPsec CTR decapsulation
 * @ctr_nonce: 4-byte array nonce
 * @ctr_initial: initial count constant
 */
struct ipsec_decap_ctr {
	uint8_t ctr_nonce[4];
	uint32_t ctr_initial;
};

/**
 * struct ipsec_decap_ccm - PDB part for IPsec CCM decapsulation
 * @salt: 3-byte salt (lower 24 bits)
 * @ccm_opt: CCM algorithm options - MSB-LSB description:
 *  b0_flags (8b) - CCM B0; use 0x5B for 8-byte ICV, 0x6B for 12-byte ICV,
 *    0x7B for 16-byte ICV (cf. RFC4309, RFC3610)
 *  ctr_flags (8b) - counter flags; constant equal to 0x3
 *  ctr_initial (16b) - initial count constant
 */
struct ipsec_decap_ccm {
	uint8_t salt[4];
	uint32_t ccm_opt;
};

/**
 * struct ipsec_decap_gcm - PDB part for IPsec GCN decapsulation
 * @salt: 4-byte salt
 * @rsvd: reserved, do not use
 */
struct ipsec_decap_gcm {
	uint8_t salt[4];
	uint32_t rsvd;
};

/**
 * struct ipsec_decap_pdb - PDB for IPsec decapsulation
 * @options: MSB-LSB description (both for legacy and new modes)
 *  hmo (header manipulation options) - 4b
 *  IP header length - 12b
 *  next header offset (legacy) / AOIPHO (actual outer IP header offset) - 8b
 *  option flags (depend on selected algorithm) - 8b
 * @seq_num_ext_hi: (optional) IPsec Extended Sequence Number (ESN)
 * @seq_num: IPsec sequence number
 * @anti_replay: Anti-replay window; size depends on ARS (option flags);
 *  format must be Big Endian, irrespective of platform
 */
struct ipsec_decap_pdb {
	uint32_t options;
	union {
		struct ipsec_decap_cbc cbc;
		struct ipsec_decap_ctr ctr;
		struct ipsec_decap_ccm ccm;
		struct ipsec_decap_gcm gcm;
	};
	uint32_t seq_num_ext_hi;
	uint32_t seq_num;
	uint32_t anti_replay[4];
};

#if 1

/* On P4080 */

static inline void __my_rta_out_be32(struct program *program, uint32_t val)
{
	//program->buffer[program->current_pc] = cpu_to_be32(val);
	program->buffer[program->current_pc] = odp_cpu_to_be_32(val);

	program->current_pc++;
}

#endif

static inline unsigned __my_rta_copy_ipsec_decap_pdb(struct program *program,
						  struct ipsec_decap_pdb *pdb,
						  uint32_t algtype)
{
	unsigned start_pc = program->current_pc;
	unsigned i, ars;

	__rta_out32(program, pdb->options);

	switch (algtype & OP_PCL_IPSEC_CIPHER_MASK) {
	case OP_PCL_IPSEC_DES_IV64:
	case OP_PCL_IPSEC_DES:
	case OP_PCL_IPSEC_3DES:
	case OP_PCL_IPSEC_AES_CBC:
	case OP_PCL_IPSEC_NULL:
		__rta_out32(program, pdb->cbc.rsvd[0]);
		__rta_out32(program, pdb->cbc.rsvd[1]);
		break;

	case OP_PCL_IPSEC_AES_CTR:
		rta_copy_data(program, pdb->ctr.ctr_nonce,
			      sizeof(pdb->ctr.ctr_nonce));
		__rta_out32(program, pdb->ctr.ctr_initial);
		break;

	case OP_PCL_IPSEC_AES_CCM8:
	case OP_PCL_IPSEC_AES_CCM12:
	case OP_PCL_IPSEC_AES_CCM16:
		rta_copy_data(program, pdb->ccm.salt, sizeof(pdb->ccm.salt));
		__rta_out32(program, pdb->ccm.ccm_opt);
		break;

	case OP_PCL_IPSEC_AES_GCM8:
	case OP_PCL_IPSEC_AES_GCM12:
	case OP_PCL_IPSEC_AES_GCM16:
	case OP_PCL_IPSEC_AES_NULL_WITH_GMAC:
		rta_copy_data(program, pdb->gcm.salt, sizeof(pdb->gcm.salt));
		__rta_out32(program, pdb->gcm.rsvd);
		break;
	}

	__rta_out32(program, pdb->seq_num_ext_hi);
	__rta_out32(program, pdb->seq_num);

	switch (pdb->options & PDBOPTS_ESP_ARS_MASK) {
	case PDBOPTS_ESP_ARS128:
		ars = 4;
		break;
	case PDBOPTS_ESP_ARS64:
		ars = 2;
		break;
	case PDBOPTS_ESP_ARS32:
		ars = 1;
		break;
	case PDBOPTS_ESP_ARSNONE:
	default:
		ars = 0;
		break;
	}

	for (i = 0; i < ars; i++)
		__my_rta_out_be32(program, pdb->anti_replay[i]);

	return start_pc;
}

/* P4080/T1040/T4240 specific RTA duplication */

/* Operation type selectors - OP TYPE */
#define OP_TYPE_SHIFT		24
#define OP_TYPE_MASK		(0x07 << OP_TYPE_SHIFT)

#define OP_TYPE_UNI_PROTOCOL	(0x00 << OP_TYPE_SHIFT)
#define OP_TYPE_PK		(0x01 << OP_TYPE_SHIFT)
#define OP_TYPE_CLASS1_ALG	(0x02 << OP_TYPE_SHIFT)
#define OP_TYPE_CLASS2_ALG	(0x04 << OP_TYPE_SHIFT)
#define OP_TYPE_DECAP_PROTOCOL	(0x06 << OP_TYPE_SHIFT)
#define OP_TYPE_ENCAP_PROTOCOL	(0x07 << OP_TYPE_SHIFT)

/* Derived Key Protocol (DKP) Protinfo */
#define OP_PCL_DKP_SRC_SHIFT	14
#define OP_PCL_DKP_SRC_MASK	(3 << OP_PCL_DKP_SRC_SHIFT)
#define OP_PCL_DKP_SRC_IMM	(0 << OP_PCL_DKP_SRC_SHIFT)
#define OP_PCL_DKP_SRC_PTR	(2 << OP_PCL_DKP_SRC_SHIFT)
#define OP_PCL_DKP_SRC_SGF	(3 << OP_PCL_DKP_SRC_SHIFT)

#define OP_PCL_DKP_DST_SHIFT	12
#define OP_PCL_DKP_DST_MASK	(3 << OP_PCL_DKP_DST_SHIFT)
#define OP_PCL_DKP_DST_IMM	(0 << OP_PCL_DKP_DST_SHIFT)
#define OP_PCL_DKP_DST_PTR	(2 << OP_PCL_DKP_DST_SHIFT)
#define OP_PCL_DKP_DST_SGF	(3 << OP_PCL_DKP_DST_SHIFT)

#define OP_PCL_DKP_KEY_SHIFT	0
#define OP_PCL_DKP_KEY_MASK	(0xfff << OP_PCL_DKP_KEY_SHIFT)

#define OP_PCLID_SHIFT		16
#define OP_PCLID_DKP_MD5	(0x20 << OP_PCLID_SHIFT)
#define OP_PCLID_DKP_SHA1	(0x21 << OP_PCLID_SHIFT)
#define OP_PCLID_DKP_SHA224	(0x22 << OP_PCLID_SHIFT)
#define OP_PCLID_DKP_SHA256	(0x23 << OP_PCLID_SHIFT)
#define OP_PCLID_DKP_SHA384	(0x24 << OP_PCLID_SHIFT)
#define OP_PCLID_DKP_SHA512	(0x25 << OP_PCLID_SHIFT)

/*
 * DKP Protocol - Restrictions on key (SRC,DST) combinations
 * For e.g. my_key_in_out[0][0] = 1 means (SRC=IMM,DST=IMM) combination is allowed
 */
static const uint8_t my_key_in_out[4][4] = { {1, 0, 0, 0},
					  {1, 1, 1, 1},
					  {1, 0, 1, 0},
					  {1, 0, 0, 1} };

static inline int my__rta_dkp_proto(uint16_t protoinfo)
{
	int key_src = (protoinfo & OP_PCL_DKP_SRC_MASK) >> OP_PCL_DKP_SRC_SHIFT;
	int key_dst = (protoinfo & OP_PCL_DKP_DST_MASK) >> OP_PCL_DKP_DST_SHIFT;

	if (!my_key_in_out[key_src][key_dst]) {
		pr_err("PROTO_DESC: Invalid DKP key (SRC,DST)\n");
		return -EINVAL;
	}

	return 0;
}

static const struct proto_map my_proto_table[] = {
/*1*/	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_SSL30_PRF,	 __rta_ssl_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_TLS10_PRF,	 __rta_ssl_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_TLS11_PRF,	 __rta_ssl_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_TLS12_PRF,	 __rta_ssl_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DTLS10_PRF,	 __rta_ssl_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_IKEV1_PRF,	 __rta_ike_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_IKEV2_PRF,	 __rta_ike_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_PUBLICKEYPAIR, __rta_dlc_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DSASIGN,	 __rta_dlc_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DSAVERIFY,	 __rta_dlc_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_IPSEC,         __rta_ipsec_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_SRTP,	         __rta_srtp_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_SSL30,	 __rta_ssl_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_TLS10,	 __rta_ssl_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_TLS11,	 __rta_ssl_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_TLS12,	 __rta_ssl_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_DTLS10,	 __rta_ssl_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_MACSEC,        __rta_macsec_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_WIFI,          __rta_wifi_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_WIMAX,         __rta_wimax_proto},
/*21*/	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_BLOB,          __rta_blob_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DIFFIEHELLMAN, __rta_dlc_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_RSAENCRYPT,	 __rta_rsa_enc_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_RSADECRYPT,	 __rta_rsa_dec_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_3G_DCRC,       __rta_3g_dcrc_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_3G_RLC_PDU,    __rta_3g_rlc_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_3G_RLC_SDU,    __rta_3g_rlc_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_LTE_PDCP_USER, __rta_lte_pdcp_proto},
/*29*/	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_LTE_PDCP_CTRL, __rta_lte_pdcp_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_MD5,       my__rta_dkp_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_SHA1,      my__rta_dkp_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_SHA224,    my__rta_dkp_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_SHA256,    my__rta_dkp_proto},
	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_SHA384,    my__rta_dkp_proto},
/*35*/	{OP_TYPE_UNI_PROTOCOL,   OP_PCLID_DKP_SHA512,    my__rta_dkp_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_PUBLICKEYPAIR, __rta_dlc_proto},
/*37*/	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_DSASIGN,	 __rta_dlc_proto},
/*38*/	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_LTE_PDCP_CTRL_MIXED,
	 __rta_lte_pdcp_mixed_proto},
	{OP_TYPE_DECAP_PROTOCOL, OP_PCLID_IPSEC_NEW,     __rta_ipsec_proto},
};

/*
 * Allowed OPERATION protocols for each SEC Era.
 * Values represent the number of entries from proto_table[] that are supported.
 */
static const unsigned my_proto_table_sz[] = {21, 29, 29, 29, 29, 35, 37, 39};

static inline int my_rta_proto_operation(struct program *program, uint32_t optype,
				      uint32_t protid, uint16_t protoinfo)
{
	uint32_t opcode = CMD_OPERATION;
	unsigned i, found = 0;
	uint32_t optype_tmp = optype;
	unsigned start_pc = program->current_pc;
	int ret = -EINVAL;

	for (i = 0; i < my_proto_table_sz[rta_sec_era]; i++) {
		/* clear last bit in optype to match also decap proto */
		optype_tmp &= (uint32_t)~(1 << OP_TYPE_SHIFT);
		if (optype_tmp == my_proto_table[i].optype) {
			if (my_proto_table[i].protid == protid) {
				/* nothing else to verify */
				if (my_proto_table[i].protoinfo_func == NULL) {
					found = 1;
					break;
				}
				/* check protoinfo */
				ret = (*my_proto_table[i].protoinfo_func)
						(protoinfo);
				if (ret < 0) {
					pr_err("PROTO_DESC: Bad PROTO Type. SEC Program Line: %d\n",
					       program->current_pc);
					goto err;
				}
				found = 1;
				break;
			}
		}
	}
	if (!found) {
		pr_err("PROTO_DESC: Operation Type Mismatch. SEC Program Line: %d\n",
		       program->current_pc);
		goto err;
	}

	__rta_out32(program, opcode | optype | protid | protoinfo);
	program->current_instruction++;
	return (int)start_pc;

 err:
	program->first_error_pc = start_pc;
	program->current_instruction++;
	return ret;
}

static inline int my_rta_dkp_proto(struct program *program, uint32_t protid,
				uint16_t key_src, uint16_t key_dst,
				uint16_t keylen, uint64_t key,
				enum rta_data_type key_type)
{
	unsigned start_pc = program->current_pc;
	unsigned in_words = 0, out_words = 0;
	int ret;

	key_src &= OP_PCL_DKP_SRC_MASK;
	key_dst &= OP_PCL_DKP_DST_MASK;
	keylen &= OP_PCL_DKP_KEY_MASK;

	ret = my_rta_proto_operation(program, OP_TYPE_UNI_PROTOCOL, protid,
				  key_src | key_dst | keylen);
	if (ret < 0)
		return ret;

	if ((key_src == OP_PCL_DKP_SRC_PTR) ||
	    (key_src == OP_PCL_DKP_SRC_SGF)) {
		__rta_out64(program, program->ps, key);
		in_words = program->ps ? 2 : 1;
	} else if (key_src == OP_PCL_DKP_SRC_IMM) {
		__rta_inline_data(program, key, inline_flags(key_type), keylen);
		in_words = (unsigned)((keylen + 3) / 4);
	}

	if ((key_dst == OP_PCL_DKP_DST_PTR) ||
	    (key_dst == OP_PCL_DKP_DST_SGF)) {
		out_words = in_words;
	} else  if (key_dst == OP_PCL_DKP_DST_IMM) {
		out_words = split_key_len(protid) / 4;
	}

	if (out_words < in_words) {
		pr_err("PROTO_DESC: DKP doesn't currently support a smaller descriptor\n");
		program->first_error_pc = start_pc;
		return -EINVAL;
	}

	/* If needed, reserve space in resulting descriptor for derived key */
	program->current_pc += (out_words - in_words);

	return (int)start_pc;
}

#define MY_DKP_PROTOCOL(program, protid, key_src, key_dst, keylen,	\
							key, key_type)	\
	my_rta_dkp_proto(program, protid, key_src, key_dst, keylen, key, key_type)


/* END of P4080/T1040/T4240 specific RTA duplication */

static inline void __my_gen_auth_key(struct program *program,
				  struct my_alginfo *authdata)
{
	uint32_t dkp_protid;

	switch (authdata->algtype & OP_PCL_IPSEC_AUTH_MASK) {
	case OP_PCL_IPSEC_HMAC_MD5_96:
	case OP_PCL_IPSEC_HMAC_MD5_128:
		dkp_protid = OP_PCLID_DKP_MD5;
		break;
	case OP_PCL_IPSEC_HMAC_SHA1_96:
	case OP_PCL_IPSEC_HMAC_SHA1_160:
		dkp_protid = OP_PCLID_DKP_SHA1;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_256_128:
		dkp_protid = OP_PCLID_DKP_SHA256;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_384_192:
		dkp_protid = OP_PCLID_DKP_SHA384;
		break;
	case OP_PCL_IPSEC_HMAC_SHA2_512_256:
		dkp_protid = OP_PCLID_DKP_SHA512;
		break;
	default:
		KEY(program, KEY2, authdata->key_enc_flags, authdata->key,
		    authdata->keylen, INLINE_KEY(authdata));
		return;
	}

	if (authdata->key_type == RTA_DATA_PTR)
		MY_DKP_PROTOCOL(program, dkp_protid, OP_PCL_DKP_SRC_PTR,
			     OP_PCL_DKP_DST_PTR, (uint16_t)authdata->keylen,
			     authdata->key, authdata->key_type);
	else
		MY_DKP_PROTOCOL(program, dkp_protid, OP_PCL_DKP_SRC_IMM,
			     OP_PCL_DKP_DST_IMM, (uint16_t)authdata->keylen,
			     authdata->key, authdata->key_type);
}

/**
 * cnstr_shdsc_ipsec_encap - IPSec ESP encapsulation protocol-level shared
 *                           descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: if true, perform descriptor byte swapping on a 4-byte boundary
 * @pdb: pointer to the PDB to be used with this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the
 *       block guide for a details of the encapsulation PDB.
 * @cipherdata: pointer to block cipher transform definitions
 *              Valid algorithm values - one of OP_PCL_IPSEC_*
 * @authdata: pointer to authentication transform definitions
 *            If an authentication key is required by the protocol:
 *            -For SEC Eras 1-5, an MDHA split key must be provided;
 *            Note that the size of the split key itself must be specified.
 *            -For SEC Eras 6+, a "normal" key must be provided; DKP (Derived
 *            Key Protocol) will be used to compute MDHA on the fly in HW.
 *            Valid algorithm values - one of OP_PCL_IPSEC_*
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int my_cnstr_shdsc_ipsec_encap(uint32_t *descbuf,
						bool ps, bool swap,
						struct ipsec_encap_pdb *pdb,
						struct my_alginfo *cipherdata,
						struct my_alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;

	LABEL(keyjmp);
	REFERENCE(pkeyjmp);
	LABEL(hdr);
	REFERENCE(phdr);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	phdr = SHR_HDR(p, SHR_SERIAL, hdr, 0);
	__my_rta_copy_ipsec_encap_pdb(p, pdb, cipherdata->algtype);
	COPY_DATA(p, pdb->ip_hdr, pdb->ip_hdr_len);
	SET_LABEL(p, hdr);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH|SHRD);
	if (authdata->keylen) {
		if (rta_sec_era < RTA_SEC_ERA_6)
			KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags,
			    authdata->key, authdata->keylen,
			    INLINE_KEY(authdata));
		else
			__my_gen_auth_key(p, authdata);
	}
	if (cipherdata->keylen)
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, OP_TYPE_ENCAP_PROTOCOL,
		 OP_PCLID_IPSEC,
		 (uint16_t)(cipherdata->algtype | authdata->algtype));
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_HDR(p, phdr, hdr);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_shdsc_ipsec_decap - IPSec ESP decapsulation protocol-level shared
 *                           descriptor.
 * @descbuf: pointer to buffer used for descriptor construction
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: if true, perform descriptor byte swapping on a 4-byte boundary
 * @pdb: pointer to the PDB to be used with this descriptor
 *       This structure will be copied inline to the descriptor under
 *       construction. No error checking will be made. Refer to the
 *       block guide for details about the decapsulation PDB.
 * @cipherdata: pointer to block cipher transform definitions.
 *              Valid algorithm values - one of OP_PCL_IPSEC_*
 * @authdata: pointer to authentication transform definitions
 *            If an authentication key is required by the protocol:
 *            -For SEC Eras 1-5, an MDHA split key must be provided;
 *            Note that the size of the split key itself must be specified.
 *            -For SEC Eras 6+, a "normal" key must be provided; DKP (Derived
 *            Key Protocol) will be used to compute MDHA on the fly in HW.
 *            Valid algorithm values - one of OP_PCL_IPSEC_*
 *
 * Return: size of descriptor written in words or negative number on error
 */
static inline int my_cnstr_shdsc_ipsec_decap(uint32_t *descbuf,
						bool ps, bool swap,
						struct ipsec_decap_pdb *pdb,
						struct my_alginfo *cipherdata,
						struct my_alginfo *authdata)
{
	struct program prg;
	struct program *p = &prg;

	LABEL(keyjmp);
	REFERENCE(pkeyjmp);
	LABEL(hdr);
	REFERENCE(phdr);

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);
	phdr = SHR_HDR(p, SHR_SERIAL, hdr, 0);
	__my_rta_copy_ipsec_decap_pdb(p, pdb, cipherdata->algtype);
	SET_LABEL(p, hdr);
	pkeyjmp = JUMP(p, keyjmp, LOCAL_JUMP, ALL_TRUE, BOTH|SHRD);
	if (authdata->keylen) {
		if (rta_sec_era < RTA_SEC_ERA_6)
			KEY(p, MDHA_SPLIT_KEY, authdata->key_enc_flags,
			    authdata->key, authdata->keylen,
			    INLINE_KEY(authdata));
		else
			__my_gen_auth_key(p, authdata);
	}
	if (cipherdata->keylen)
		KEY(p, KEY1, cipherdata->key_enc_flags, cipherdata->key,
		    cipherdata->keylen, INLINE_KEY(cipherdata));
	SET_LABEL(p, keyjmp);
	PROTOCOL(p, OP_TYPE_DECAP_PROTOCOL,
		 OP_PCLID_IPSEC,
		 (uint16_t)(cipherdata->algtype | authdata->algtype));
	PATCH_JUMP(p, pkeyjmp, keyjmp);
	PATCH_HDR(p, phdr, hdr);
	return PROGRAM_FINALIZE(p);
}

/**
 * cnstr_jobdesc_mdsplitkey - Generate an MDHA split key
 * @descbuf: pointer to buffer to hold constructed descriptor
 * @ps: if 36/40bit addressing is desired, this parameter must be true
 * @swap: must be true when core endianness doesn't match SEC endianness
 * @alg_key: pointer to HMAC key to generate ipad/opad from
 * @keylen: HMAC key length
 * @cipher: HMAC algorithm selection, one of OP_ALG_ALGSEL_*
 *     The algorithm determines key size (bytes):
 *     -  OP_ALG_ALGSEL_MD5    - 16
 *     -  OP_ALG_ALGSEL_SHA1   - 20
 *     -  OP_ALG_ALGSEL_SHA224 - 28
 *     -  OP_ALG_ALGSEL_SHA256 - 32
 *     -  OP_ALG_ALGSEL_SHA384 - 48
 *     -  OP_ALG_ALGSEL_SHA512 - 64
 * @padbuf: pointer to buffer to store generated ipad/opad
 *
 * Split keys are IPAD/OPAD pairs. For details, refer to MDHA Split Keys chapter
 * in SEC Reference Manual.
 *
 * Return: size of descriptor written in words or negative number on error
 */

static inline int my_cnstr_jobdesc_mdsplitkey(uint32_t *descbuf,
					bool ps, bool swap,
					uint64_t alg_key, uint8_t keylen,
					uint32_t cipher,
					uint64_t padbuf)
{
	struct program prg;
	struct program *p = &prg;

	PROGRAM_CNTXT_INIT(p, descbuf, 0);
	if (swap)
		PROGRAM_SET_BSWAP(p);
	if (ps)
		PROGRAM_SET_36BIT_ADDR(p);

	JOB_HDR(p, SHR_NEVER, 1, 0, 0);
	KEY(p, KEY2, 0, alg_key, keylen, 0);
	ALG_OPERATION(p, cipher, OP_ALG_AAI_HMAC, OP_ALG_AS_INIT,
		      ICV_CHECK_DISABLE, DIR_DEC);
	FIFOLOAD(p, MSG2, 0, 0, LAST2 | IMMED | COPY);
	JUMP(p, 1, LOCAL_JUMP, ALL_TRUE, CLASS2);
	FIFOSTORE(p, MDHA_SPLIT_KEY, 0, padbuf, split_key_len(cipher), 0);
	return PROGRAM_FINALIZE(p);
}

#endif
