/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_hwq.h
 * @description	Function for NADK Software Frame Queue
 */

#ifndef _NADK_HWQ_H_
#define _NADK_HWQ_H_

#ifdef __cplusplus
extern "C" {
#endif

/* NADK include files */
#include <nadk/core/nadk_dev.h>

/*!
 * @details	Attach the Frame Queue to a concentrator
 *
 * @param[in]	h_nadk_hwq - Handle to NADK Frame Queue
 *
 * @param[in]	vq_param - NADK VQ param configuration
 *
 * @returns	NADK_SUCCESS on success, NADK_FAILURE otherwise
 *
 */
int nadk_attach_frameq_to_conc(
		void *h_nadk_hwq,
		struct nadk_vq_param *vq_param);

int nadk_detach_frameq_from_conc(void *h_nadk_hwq);

/*!
 * @details	Get a FREE NADK Frame Queue
 *
 * @returns	Handle to the ACQUIRED NADK Frame Queue, NULL incase there
 *		are no FREE Frame Queues
 *
 */
void *nadk_get_frameq(void);

/*!
 * @details	Put the Frame Queue back into the FREE list
 *
 * @param[in]	h_nadk_hwq - Handle to NADK Frame Queue
 *
 * @returns	none
 *
 */
void nadk_put_frameq(void *h_nadk_hwq);

/*!
 * @details	Receive a packet from a NADK Frame Queue
 *
 * @param[in]	h_nadk_hwq - Handle to NADK Frame Queue
 *
 * @param[in]	buf_list - List of pointers of nadk_mbuf's. Received buffers
 *		will be stored in this list.
 *
 * @param[in]	num - number of buffers to receive
 *
 * @returns	number of buffers received, NADK_FAILURE on failure
 *
 */
int nadk_hwq_recv(void *h_nadk_hwq,
		  struct nadk_mbuf *buf_list[],
		int num);

/*!
 * @details	Send a packet to a NADK Frame Queue
 *
 * @param[in]	h_nadk_hwq - Handle to NADK Frame Queue
 *
 * @param[in]	buf_list - List of pointers of nadk_mbuf's to transmit
 *
 * @param[in]	num - number of buffers to transmit
 *
 * @returns	number of buffers transmitted, NADK_FAILURE on failure
 *
 */
int nadk_hwq_xmit(void *h_nadk_hwq,
		  struct nadk_mbuf *buf_list[],
		int num);

#ifdef __cplusplus
}
#endif

#endif /* _NADK_HWQ_H_ */
