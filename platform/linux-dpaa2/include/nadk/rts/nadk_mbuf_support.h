/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_mbuf_support.h
 *
 * @brief		Extended Buffer management library services.
 */

#ifndef _NADK_MBUF_SUPPORT_H_
#define _NADK_MBUF_SUPPORT_H_

#ifdef __cplusplus
extern "C" {
#endif

/* NADK header files */
#include <nadk/common/nadk_cfg.h>
#include <nadk/rts/nadk_mbuf.h>

/* Invalid context pointer value */
#define INVALID_CNTXT_PTR	((void *)0xFFFFFFFF)

/* get the first pools bpid */
int nadk_mbuf_pool_get_bpid(void *bplist);

/*!
 * @details     Reset a INLINE NADK mbuf shell to default values
 *
 * @param[in]   mbuf - nadk buffer
 *
 * @returns     none
 *
 */
static inline void nadk_inline_mbuf_reset(
		nadk_mbuf_pt mbuf)
{
	mbuf->flags &= ~(NADKBUF_SEC_CNTX_VALID | NADKBUF_AIOP_CNTX_VALID);
	mbuf->eth_flags = 0;
	/* No Atomic context for allocated buffer */
	mbuf->atomic_cntxt = INVALID_CNTXT_PTR;

	mbuf->next_sg = 0;
	/*todo - need to reset hash_val, timestamp, destructor also,
	however they are not in use currently*/
}


#ifdef __cplusplus
}
#endif

#endif	/* _NADK_MBUF_SUPPORT_H_ */
