/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_aiop_priv.h
 * @description	Private function & definitions for NADK AIOP type Device
 */

#ifndef _NADK_AIOP_PRIV_H_
#define _NADK_AIOP_PRIV_H_

#ifdef __cplusplus
extern "C" {
#endif

/*Nadk header files*/
#include <nadk_dev.h>
#include <nadk_dev_priv.h>

/* MC header files */
#include <fsl_dpci.h>

/* QBMAN header files */
#include <fsl_qbman_base.h>

#define AIOP_MAX_FQ_PAIRS DPCI_PRIO_NUM

/*AIOP specific macros to define operations on FD*/
#define NADK_AIOP_SET_FD_FRC(fd, aiop_cnxt)			\
	fd->simple.frc = aiop_cnxt->frc;
#define NADK_AIOP_SET_FD_FLC(fd, aiop_cnxt)			\
	fd->simple.flc_lo =					\
		lower_32_bits((uint64_t)(aiop_cnxt->flc));	\
	fd->simple.flc_hi =					\
		upper_32_bits((uint64_t)(aiop_cnxt->flc));
#define NADK_AIOP_SET_FD_ERR(fd, aiop_cnxt) fd->simple.ctrl |= aiop_cnxt->error;
#define NADK_AIOP_GET_FRC(fd)	(fd->simple.frc)
#define NADK_AIOP_GET_FLC(fd)	((uint64_t)(fd->simple.flc_hi) << 32) + fd->simple.flc_lo;
#define NADK_AIOP_GET_ERR(fd)	(uint8_t)(fd->simple.ctrl & 0x000000FF)

/*!
 * The NADK Virtual Queue structure for AIOP driver.
 */
struct aiop_vq {
	int32_t eventfd; /*!< Event Fd of this queue */
	uint16_t fqid;	/*!< Unique ID of this queue */
};

/*!
 * Information private to the AIOP device
 */
struct nadk_aiop_priv {
	int id; /*!< DPCI ID */
	uint8_t num_fq_pairs; /*!< Number of FQ pairs */
	struct rx_fq_config { /*!< Structure for RX FQ */
		bool_t use_dpio; /*!< DPIO is to be used for notifications
				      or not */
		bool_t use_dpcon; /*!< DPCON to be used as aggregation device
				       for this RX FQ or not */
		uint16_t dpio_id; /*!< DPIO's ID in case it is being used for
				       notification */
		uint16_t dpcon_id; /*!< DPCON's ID in case it the RX FQ is used
					in aggregation */
		uint8_t prio; /*!< Priority of the RX FQ */
		uint64_t rx_user_ctx; /*!< User specific Rx context */
	} rx_fq[AIOP_MAX_FQ_PAIRS];
};

/*!
 * @details	AIOP driver API to register to NADK framework. It will be
 *		called by NADK and will register its device driver to NADK.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_driver_init(void);

/*!
 * @details	AIOP driver API to unregister to NADK framework. It will be
 *		called by NADK and will unregister its device driver to NADK.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_driver_exit(void);

/*!
 * @details	AIOP driver default configuration API.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_defconfig(
		struct nadk_dev *dev);

/*!
 * @details	AIOP driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_probe(
		struct nadk_dev *dev, const void *data);

/*!
 * @details	AIOP driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_remove(
		struct nadk_dev *dev);

/*!
 * @details	Start a AIOP device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_start(
		struct nadk_dev *dev);

/*!
 * @details	Setup a RX virtual queues to a AIOP device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @param[in]	vq_cfg - Pointer to VQ configuration
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_setup_rx_vq(
		struct nadk_dev *dev,
		uint8_t vq_index,
		struct nadk_vq_param *vq_cfg);

/*!
 * @details	Setup a TX virtual queues to a AIOP device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @param[in]	num - Number of TX queues
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_setup_tx_vq(
		struct nadk_dev *dev,
		uint32_t num, uint32_t action);

/*!
 * @details	Disable a AIOP device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_stop(
		struct nadk_dev *dev);

/*!
 * @details	Receives frames from given NADK device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @param[in]	vq - Pointer to the virtual Queue of a device
 *
 * @param[in]	buf - Pointer to NADK buffer which will be passed to user
 *
 * @param[in]	num - Number of frames to be received
 *
 * @returns	Number of packets received if success; error code otherwise.
 *
 */
int32_t nadk_aiop_rcv(
		struct nadk_dev *dev,
		void *vq,
		uint32_t num,
		nadk_mbuf_pt buf[]);

/*!
 * @details	Transmits frames to given NADK device.
 *
 * @param[in]	dev - Pointer to NADK AIOP device
 *
 * @param[in]	vq - Pointer to the virtual Queue of a device
 *
 * @param[in]	buf - Pointer to NADK buffers which are to be transmited.
 *
 * @param[in]	num - Number of frames to be transmited
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_xmit(
		struct nadk_dev *dev,
		void *vq,
		uint32_t num,
		nadk_mbuf_pt buf[]);

nadk_mbuf_pt nadk_aiop_fd_to_mbuf(
		const struct qbman_fd *fd);

void nadk_aiop_mbuf_to_fd(
		nadk_mbuf_pt mbuf,
		struct qbman_fd *fd);

#ifdef __cplusplus
}
#endif

#endif /* _NADK_AIOP_PRIV_H_ */
