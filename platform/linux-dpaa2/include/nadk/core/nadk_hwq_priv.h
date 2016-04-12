/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_hwq_priv.h
 * @description	Private function & definitions for NADK Frame Queue
 */

#ifndef _NADK_HWQ_PRIV_H_
#define _NADK_HWQ_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/* NADK include files */
#include <nadk_lock.h>
#include <nadk_vq.h>

/* Maximum number of frame queues supported */
#define MAX_FRAMEQ 64

enum frameq_state_t {
	FRAMEQ_STATE_INVALID, /* Frame queue is invalid */
	FRAMEQ_STATE_FREE, /* Frame queue is free and can be
		* acquired by a user */
	FRAMEQ_STATE_ACQUIRED, /* Frame queue is in use */
	FRAMEQ_STATE_ATTACHED /* Frame queue is in use and attached to conc */
};

/* NADK Frame Queue structure */
struct nadk_hwq_t {
	struct nadk_vq dummy_vq; /* Dummy vq structure requied in case
		*  frame queue is attached to concentrator. Concentrator uses
		*  this to determine the callback function to FD
		*  to MBUF conversion */
	enum frameq_state_t state; /* State of the queue */
	uint32_t fqid; /* Frame Queue ID */
	struct fsl_mc_io *mc_io; /* MC IO required to communicate with MC */
	uint16_t token; /* MC token also required to communicate with MC */
};

/*!
 * @details	Probe and initialize a NADK Frame Queue.
 *
 * @param[in]	dev - NADK device. In this case it will be DPCI type of device
 *
 * @returns	NADK_DEVICE_CONSUMED on success, NADK_FAILURE otherwise
 *
 */
int nadk_hwq_probe(struct nadk_dev *dev,
		   const void *data);

/*!
 * @details	Cleaup all the NADK Frame Queue devices
 *
 * @returns	none
 *
 */
int nadk_hwq_close_all(void);

void *nadk_hwq_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);

#ifdef __cplusplus
}
#endif

#endif /* _NADK_HWQ_PRIV_H_ */
