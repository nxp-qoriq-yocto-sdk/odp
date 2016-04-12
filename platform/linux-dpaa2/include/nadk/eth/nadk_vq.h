/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_vq.h
 * @description	NADK VQ structure for internal usages.
 */

#ifndef _NADK_VQ_H_
#define _NADK_VQ_H_

/*Standard header files*/
#include <stddef.h>

/*Nadk header files*/
#include <nadk/core/nadk_dev.h>
#include <odp/hints.h>
#include <odp/std_types.h>

/*MC header files*/
#include <fsl_dpni.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif

typedef void *(nadk_vq_cb_dqrr_t)(
		struct qbman_swp *qm,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr);
struct nadk_qman_fq {
	nadk_vq_cb_dqrr_t *cb; /*! <Callback for handling the dqrr output*/
	int cgr_groupid;
};
/*!
 * The NADK Virtual Queue structure for ethernet driver.
 */
struct nadk_vq {
	struct nadk_qman_fq qmfq;
	struct nadk_dev *dev;	/*! <parent nadk device pointer - required for aggr*/
	enum nadk_fq_type fq_type;/*!< Type of this queue i.e. RX or TX
					or TX-conf/error */
	int32_t eventfd;	/*!< Event Fd of this queue */
	uint32_t fqid;		/*!< Unique ID of this queue */
	uint8_t tc_index;	/*!< traffic class identifier */
	uint16_t flow_id;	/*!< To be used by NADK frmework */
	uint64_t usr_ctxt;

	struct qbman_result *dq_storage[2]; /*!< Per VQ storage used in case
			* of NADK_PREFETCH_MODE*/
	int toggle; /*!< Toggle to handle the per VQ DQRR storage
			* required to be used */
	uint8_t dqrr_idx; /* The index of the per VQ DQRR storage enrty which
			* is being processed */
	uint8_t		sync;	/*!< Whether queue is atmoic or ordered */
};


#ifdef __cplusplus
}
#endif

#endif /* _NADK_VQ_H_ */
