/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_mbuf_priv.h
 *
 * @brief		Buffer management library services for NADK based applications.
 */

#ifndef _NADK_MBUF_PRIV_H_
#define _NADK_MBUF_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/* NADK header files */
#include <nadk/common/nadk_cfg.h>
#include <nadk/rts/nadk_mbuf.h>
#include <nadk/rts/nadk_mbuf_priv_ldpaa.h>
#include <odp/config.h>

/* Maximum release/acquire from QBMAN */
#define NADK_MBUF_MAX_ACQ_REL	7

#define MAX_BPID 256

/*Macros to define operations on FD*/
#define NADK_SET_FD_ADDR(fd, addr) {				\
	fd->simple.addr_lo = lower_32_bits((uint64_t)addr);	\
	fd->simple.addr_hi = upper_32_bits((uint64_t)addr); }
#define NADK_SET_FD_LEN(fd, length)	fd->simple.len = length
#define NADK_SET_FD_BPID(fd, bpid)	fd->simple.bpid_offset |= bpid;
#define NADK_SET_FD_IVP(fd)   ((fd->simple.bpid_offset |= 0x00004000))
#define NADK_SET_FD_OFFSET(fd, offset)	fd->simple.bpid_offset |= (uint32_t)offset << 16;
#define NADK_SET_FD_INTERNAL_JD(fd, len) fd->simple.frc = (0x80000000 | (len));
#define NADK_SET_FD_FRC(fd, frc)	fd->simple.frc = frc;
#define NADK_RESET_FD_CTRL(fd)	fd->simple.ctrl = 0;

#define	NADK_SET_FD_ASAL(fd, asal)	(fd->simple.ctrl |= (asal << 16))
#define NADK_SET_FD_FLC(fd, addr)				\
	fd->simple.flc_lo = lower_32_bits((uint64_t)addr);	\
	fd->simple.flc_hi = upper_32_bits((uint64_t)addr);
#define NADK_SET_FLE_INTERNAL_JD(fle, len) fle->frc = (0x80000000 | (len));
#define NADK_GET_FLE_ADDR(fle)					\
	(uint64_t)((((uint64_t)(fle->addr_hi)) << 32) + fle->addr_lo)
#define NADK_SET_FLE_ADDR(fle, addr)	\
	fle->addr_lo = lower_32_bits((uint64_t)addr);     \
	fle->addr_hi = upper_32_bits((uint64_t)addr);
#define NADK_SET_FLE_BPID(fle, bpid)	fle->fin_bpid_offset |= (uint64_t)bpid;
#define NADK_GET_FLE_BPID(fle, bpid)	(fle->fin_bpid_offset & 0x000000ff)
#define NADK_SET_FLE_FIN(fle)	fle->fin_bpid_offset |= (uint64_t)1<<31;
#define NADK_SET_FLE_SG_EXT(fle)	fle->fin_bpid_offset |= (uint64_t)1<<29;
#define NADK_IS_SET_FLE_SG_EXT(fle)	\
	(fle->fin_bpid_offset & ((uint64_t)1<<29))? 1 : 0
#define NADK_SET_FLE_IVP(fle)   ((fle->fin_bpid_offset |= 0x00004000))
#define NADK_SET_FD_COMPOUND_FMT(fd)	\
	fd->simple.bpid_offset |= (uint32_t)1 << 28;
#define NADK_GET_FD_ADDR(fd)	\
	(uint64_t)((((uint64_t)(fd->simple.addr_hi)) << 32) + fd->simple.addr_lo)
#define NADK_GET_FD_LEN(fd)	(fd->simple.len)
#define NADK_GET_FD_BPID(fd)	((fd->simple.bpid_offset & 0x00003FFF))
#define NADK_GET_FD_IVP(fd)   ((fd->simple.bpid_offset & 0x00004000) >> 14)
#define NADK_GET_FD_OFFSET(fd)	((fd->simple.bpid_offset & 0x0FFF0000) >> 16)
#define NADK_GET_FD_FRC(fd)	(fd->simple.frc)
#define NADK_GET_FD_FLC(fd)	\
	(uint64_t)((((uint64_t)(fd->simple.flc_hi)) << 32) + fd->simple.flc_lo)
#define GET_VIRT_ADDR_FROM_ZONE(addr, bz) ((addr - bz->phys_addr) + nadk_memzone_virt(bz))
#define GET_PHY_ADDR_FROM_ZONE(addr, bz) (bz->phys_addr + ((uintptr_t)addr - nadk_memzone_virt(bz)))

#define NADK_INLINE_MBUF_FROM_BUF(buf, meta_data_size) \
	((struct nadk_mbuf *)((uint64_t)buf -  meta_data_size))
#define NADK_BUF_FROM_INLINE_MBUF(mbuf, meta_data_size) \
	((uint8_t *)((uint64_t)mbuf + meta_data_size))

/* Refer to Table 7-3 in SEC BG */
struct qbman_fle {
	uint32_t addr_lo;
	uint32_t addr_hi;
	uint32_t length;
	/* FMT must be 00, MSB is final bit  */
	uint32_t fin_bpid_offset;
	uint32_t frc;
	uint32_t reserved[3]; /* Not used currently */
};

/*!
 * Structure representing private buffer pool list. This buffer pool list may
 * have several buffer pools
 */
struct nadk_bp_list {
	struct nadk_bp_list *next;
	uint8_t num_buf_pools;
	struct buf_pool buf_pool[NADK_MAX_BUF_POOLS];
};

/*!
 * @details	Initializes the buffer pool list. Within this API
 *		memory required will be allocated, dpbp will get initialized,
 *		buffer pool list will be configured
 *
 * @param[in]	bp_list_cfg - buffer pool list configuration
 *
 * @returns	buffer pool list pointer in case of success; NULL otherwise
 *
 */
struct nadk_bp_list *nadk_mbuf_create_bp_list(
		struct nadk_bp_list_cfg *bp_list_cfg);


/*!
 * @details	Add the buffer pool list to the global list. Also the buffer
 *		pools in the list are stored in sorted order of size.
 *
 * @param[in]	bp_list - buffer pool list
 *
 * @returns	none
 *
 */
void nadk_add_bp_list(
		struct nadk_bp_list *bp_list);


/*!
 * @details	Allocate a SG NADK buffer of given size from given 'dev'.
 *
 * @param[in]	dev - NADK device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the NADK buffer size required.
 *
 * @returns	nadk buffer on success; NULL of failure .
 *
 */
nadk_mbuf_pt nadk_mbuf_alloc_sg(
		struct nadk_dev *dev,
		uint32_t size);


/*!
 * @details	Allocate SG NADK buffer from given buffer pool.
 *
 * @param[in]	bpid - buffer pool id (which was filled in by NADK at
 *		'nadk_mbuf_create_bp_list'
 *
 * @param[in]	length - if single buffer length is greater than the buffer size
 *		it may allocate SG list.
 *
 * @returns	nadk buffer on success; NULL on failure.
 *
 */
nadk_mbuf_pt nadk_mbuf_alloc_sg_from_bpid(
		uint16_t bpid,
		int length);


/*!
 * @details	Make a complete copy of given NADK buffer in case of SG
 *
 * @param[out]	to_buf - NADK buffer on which the 'from_buffer' is copied.
 *		'to_buf' should already have the buffer frames in it, and thus
 *		no new frame from any buffer pool will be allocated inside
 *		the function.
 *
 * @param[in]	from_buf - NADK buffer which needs to be copied.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_mbuf_sg_copy(
		nadk_mbuf_pt to_buf,
		nadk_mbuf_pt from_buf);

/* Extern declarations */
extern struct nadk_bp_list *g_bp_list;
extern bool_t sg_support;

#ifdef __cplusplus
}
#endif

#endif	/* _NADKBUF_PRIV_H_ */
