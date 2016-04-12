/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_aiop.c
 *
 * @brief	AIOP driver implementation. It contains initialization of
 *	AIOP interfaces for NADK device framework based application.
 *
 * @addtogroup	NADK_AIOP
 * @ingroup	NADK_DEV
 * @{
 */

/*NADK header files*/
#include <odp/std_types.h>
#include <nadk_common.h>
#include <nadk_dev.h>
#include <nadk_dev_priv.h>
#include <nadk_io_portal_priv.h>
#include <nadk_mbuf.h>
#include <nadk_mbuf_priv.h>
#include <nadk_malloc.h>
#include <nadk_aiop.h>
#include "nadk_aiop_priv.h"
#include <nadk_time.h>
#include <nadk_hwq_priv.h>

 /*MC header files*/
#include <fsl_dpci.h>
#include <fsl_dpci_cmd.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

/* Device properties */
#define LDPAA_AIOP_DEV_MAJ_NUM		DPCI_VER_MAJOR
#define LDPAA_AIOP_DEV_MIN_NUM		DPCI_VER_MINOR
#define LDPAA_AIOP_DEV_VENDOR_ID	6487
#define LDPAA_AIOP_DEV_NAME		"ldpaa-aiop"

/* The AIOP device driver structure */
struct nadk_driver aiop_driver = {
	.name			=	LDPAA_AIOP_DEV_NAME,
	.vendor_id		=	LDPAA_AIOP_DEV_VENDOR_ID,
	.major			=	LDPAA_AIOP_DEV_MAJ_NUM,
	.minor			=	LDPAA_AIOP_DEV_MIN_NUM,
	.dev_type		=	NADK_AIOP_CI,
	.dev_probe		=	nadk_aiop_probe,
	.dev_shutdown		=	nadk_aiop_remove
};

/*!
 * @details	Function to initialize the AIOP driver. This should be called
 *		by NADK framework when it comes up.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_driver_init(void)
{
	NADK_TRACE(CMD);

	/* Register AIOP driver to NADK */
	nadk_register_driver(&aiop_driver);
	return NADK_SUCCESS;
}

/*!
 * @details	Function to un-initialize the AIOP driver. This should be
 *		called by NADK framework when it exits.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_driver_exit(void)
{
	NADK_TRACE(CMD);

	/* De-register AIOP driver to NADK */
	nadk_unregister_driver(&aiop_driver);
	return NADK_SUCCESS;
}

/*!
 * @details	Initializes the AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @param[in]	data - data pointer.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_probe(
		struct nadk_dev *dev,
		const void *data ODP_UNUSED)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_aiop_priv *aiop_priv;
	struct fsl_mc_io *dpci;
	struct dpci_attr attr;
	int32_t ret, i;
	struct aiop_vq *vq_mem;

	NADK_TRACE(CMD);

	/* Open the nadk device via MC and save the handle for further use */
	dpci = (struct fsl_mc_io *)nadk_calloc(NULL, 1,
		sizeof(struct fsl_mc_io), 0);
	if (!dpci) {
		NADK_ERR(CMD, "Memory allocation failure");
		return NADK_FAILURE;
	}

	dpci->regs = dev_priv->mc_portal;
	ret = dpci_open(dpci, CMD_PRI_LOW, dev_priv->hw_id, &(dev_priv->token));
	if (ret != 0) {
		NADK_ERR(CMD, "Opening device failed with err code: %d", ret);
		goto err1;
	}

	/* Get the device attributes */
	ret = dpci_get_attributes(dpci, CMD_PRI_LOW, dev_priv->token, &attr);
	if (ret != 0) {
		NADK_ERR(CMD, "Reading device failed with err code: %d", ret);
		goto err2;
	}

	/* In case the number of priorities are 1, give it to NADK frame Queue
	 * module and close the dpci device */
	if (attr.num_of_priorities == 1) {
		/* Close the device. It will be handled by FrameQ module */
		ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
		if (ret != 0)
			NADK_ERR(CMD, "Closing the device failed with "
				"err code: %d", ret);
		nadk_free(dpci);

		/* Now call FrameQ probe */
		ret = nadk_hwq_probe(dev, data);
		if (ret != NADK_SUCCESS)
			return NADK_FAILURE;
		else
			return NADK_DEV_CONSUMED;
	}

	/*Allocate space for device specific data*/
	aiop_priv = (struct nadk_aiop_priv *)nadk_calloc(NULL, 1, sizeof(
			struct nadk_aiop_priv) + sizeof(struct aiop_vq) *
			(2 * attr.num_of_priorities), 0);
	if (!aiop_priv) {
		NADK_ERR(CMD, "Failure to allocate the memory"
			"for private data");
		goto err2;
	}

	/* Save the RX/TX flow information in nadk device */
	aiop_priv->id = attr.id;
	aiop_priv->num_fq_pairs = attr.num_of_priorities;
	vq_mem = (struct aiop_vq *)(aiop_priv + 1);
	for (i = 0; i < attr.num_of_priorities; i++) {
		dev->rx_vq[i] = vq_mem++;
		dev->tx_vq[i] = vq_mem++;
	}

	/* Configure device specific callbacks to the NADK */
	dev_priv->fn_dev_start = nadk_aiop_start;
	dev_priv->fn_dev_stop = nadk_aiop_stop;
	dev_priv->fn_dev_send = nadk_aiop_xmit;
	dev_priv->fn_dev_rcv = nadk_aiop_rcv;
	dev_priv->fn_setup_rx_vq = nadk_aiop_setup_rx_vq;
	dev_priv->fn_setup_tx_vq = nadk_aiop_setup_tx_vq;

	dev_priv->drv_priv = aiop_priv;
	dev_priv->hw = dpci;

	dev->num_rx_vqueues = aiop_priv->num_fq_pairs;
	dev->num_tx_vqueues = aiop_priv->num_fq_pairs;

	NADK_INFO(CMD, "Successfully initialized the AIOP device");

	return NADK_SUCCESS;

err2:
	/* Close the device in case of error */
	ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		NADK_ERR(CMD, "Closing the device failed with err code: %d",
			ret);
err1:
	nadk_free(dpci);

	return NADK_FAILURE;
}

/*!
 * @details	Un-initializes the AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_remove(
		struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_aiop_priv *aiop_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	int32_t ret;

	NADK_TRACE(CMD);

	/* First close the device at underlying layer */
	ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		NADK_ERR(CMD, "Closing the device failed with err code: %d",
			ret);

	/* Free the allocated memory for AIOP private data */
	nadk_free(aiop_priv);
	nadk_free(dpci);

	NADK_INFO(CMD, "Sucessfully closed the device");
	return NADK_SUCCESS;
}

/*!
 * @details	Activate/Start an already configured AIOP device.
 *
 * @param[in]	dev - Pointer to the AIOP device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_start(
		struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_aiop_priv *aiop_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	struct dpci_rx_queue_attr rx_attr;
	struct dpci_tx_queue_attr tx_attr;
	struct aiop_vq *rx_vq, *tx_vq;
	int ret, i;

	NADK_TRACE(CMD);

	/* After enabling a DPNI, Device will be ready for RX/TX. */
	ret = dpci_enable(dpci, CMD_PRI_LOW,  dev_priv->token);
	if (ret != 0) {
		NADK_ERR(CMD, "Enabling device failed with err code: %d",
			ret);
		return NADK_FAILURE;
	}


	for (i = 0; i < aiop_priv->num_fq_pairs; i++) {
		ret = dpci_get_rx_queue(dpci, CMD_PRI_LOW, dev_priv->token, i, &rx_attr);
		if (ret != 0) {
			NADK_ERR(CMD, "Reading device failed with"
				"err code: %d", ret);
			goto err;
		}
		rx_vq = (struct aiop_vq *)(dev->rx_vq[i]);
		rx_vq->fqid = rx_attr.fqid;
		NADK_INFO(CMD, "rx_vq->fqid: %x", rx_vq->fqid);
		ret = dpci_get_tx_queue(dpci, CMD_PRI_LOW, dev_priv->token, i, &tx_attr);
		if (ret != 0) {
			NADK_ERR(CMD, "Reading device failed with"
				"err code: %d", ret);
			goto err;
		}
		tx_vq = (struct aiop_vq *)(dev->tx_vq[i]);
		tx_vq->fqid = tx_attr.fqid;
		NADK_INFO(CMD, "tx_vq->fqid: %x", tx_vq->fqid);
	}

	dev->state = DEV_ACTIVE;

	NADK_INFO(CMD, "Device started successfully");
	return NADK_SUCCESS;
err:
	/* Disable the DPCI */
	ret = dpci_disable(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		NADK_ERR(CMD, "Disabling device failed with err code: %d",
			ret);

	return NADK_FAILURE;
}

/*!
 * @details	De-activate/Stop an active AIOP device. This function should be
 *		invoked only, if the deivce is in active state.
 *
 * @param[in]	dev - Pointer to AIOP device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_stop(
		struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	int32_t ret;

	NADK_TRACE(CMD);

	/* Disable the DPCI */
	ret = dpci_disable(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0) {
		NADK_ERR(CMD, "Disabling device failed with err code: %d",
			ret);
		return NADK_FAILURE;
	}
	dev->state = DEV_INACTIVE;

	NADK_INFO(CMD, "Device stopped successfully");
	return NADK_SUCCESS;
}

/*!
 * @details	Create the NADK buffer from the QBMAN FD.
 *
 * @param[in]	fd - FD using which the NADK buffer has to be created.
 *
 * @returns	pointer to the NADK buffer created.
 *
 */
nadk_mbuf_pt nadk_aiop_fd_to_mbuf(
		const struct qbman_fd *fd)
{
	nadk_mbuf_pt mbuf;
	struct aiop_buf_info *aiop_cnxt;

	NADK_TRACE(CMD);

	/* Allocate the NADK buffer shell */
	mbuf = nadk_mbuf_alloc_shell();
	if (!mbuf) {
		NADK_ERR(CMD, "Error in allocating NADK buffer shell");
		return NULL;
	}

	/* Allocate the aiop context memory */
	aiop_cnxt = nadk_aiop_cntx_alloc();
	if (!aiop_cnxt) {
		NADK_ERR(CMD, "Error in allocating AIOP context");
		nadk_mbuf_free_shell(mbuf);
		return NULL;
	}

	/* Set the NADK buffer parameters */
	mbuf->head = (uint8_t *)NADK_GET_FD_ADDR(fd);
	mbuf->data = mbuf->head + NADK_GET_FD_OFFSET(fd);
	mbuf->frame_len = NADK_GET_FD_LEN(fd);
	mbuf->tot_frame_len = mbuf->frame_len;
	mbuf->bpid = NADK_GET_FD_BPID(fd);
	mbuf->end_off = mbuf->frame_len;

	aiop_cnxt->frc = NADK_AIOP_GET_FRC(fd);
	aiop_cnxt->flc = NADK_AIOP_GET_FLC(fd);
	aiop_cnxt->error = NADK_AIOP_GET_ERR(fd);

	mbuf->drv_priv_cnxt = aiop_cnxt;
	mbuf->flags |= NADKBUF_AIOP_CNTX_VALID;

#ifdef NADK_DEBUG
	nadk_mbuf_dump_pkt(stdout, mbuf);
	nadk_hexdump(stdout, "AIOP Context", mbuf->drv_priv_cnxt,
		sizeof(struct aiop_buf_info));
#endif

	return mbuf;

}

/*!
 * @details	Create the QBMAN FD from the NADK buffer.
 *
 * @param[in]	mbuf - NADK buffer using which the FD has to be created.
 *
 * @param[out]	fd - pointer to the FD.
 *
 * @returns	none
 *
 */
void nadk_aiop_mbuf_to_fd(
		nadk_mbuf_pt mbuf,
		struct qbman_fd *fd)
{
	struct aiop_buf_info *aiop_cnxt = mbuf->drv_priv_cnxt;

	NADK_TRACE(CMD);

	/* Set some of the FD parameters to 0.
	 * For performance reasons do not memset */
	fd->simple.bpid_offset = 0;
	fd->simple.ctrl = 0;

	NADK_SET_FD_ADDR(fd, mbuf->head);
	NADK_SET_FD_LEN(fd, mbuf->frame_len);
	NADK_SET_FD_BPID(fd, mbuf->bpid);
	NADK_SET_FD_OFFSET(fd, (mbuf->data - mbuf->head));

	NADK_AIOP_SET_FD_FRC(fd, aiop_cnxt);
	NADK_AIOP_SET_FD_FLC(fd, aiop_cnxt);
	NADK_AIOP_SET_FD_ERR(fd, aiop_cnxt);

#ifdef NADK_DEBUG
	nadk_hexdump(stdout, "FD created", fd, sizeof(struct qbman_fd));
#endif
}

/*!
 * @details	Packet receive function for AIOP to recevie packet/s
 *		from a given device queue.
 *
 * @param[in]	dev - Pointer to AIOP device structure from which
 *		packets need to be received.
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[out]	buf_list - Pointer to list received buffers.
 *
 * @param[in]	num -  Maximum number of buffers to receive.
 *
 * @returns	Number of packets received if success; error code otherwise.
 *
 */
int32_t nadk_aiop_rcv(
		struct nadk_dev *dev ODP_UNUSED,
		void *vq,
		uint32_t num,
		nadk_mbuf_pt mbuf[])
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage = thread_io_info.dq_storage;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	struct aiop_vq *rx_vq = (struct aiop_vq *)vq;
	int ret, qbman_try_again = 0, rcvd_pkts = 0;
	uint8_t is_last = 0, status;

	NADK_TRACE(CMD);

	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_fq(&pulldesc, rx_vq->fqid);
	qbman_pull_desc_set_numframes(&pulldesc, num);
	qbman_pull_desc_set_storage(&pulldesc, dq_storage,
		(dma_addr_t)dq_storage, TRUE);

try_again:
	/*Issue a volatile dequeue command.*/
	ret = qbman_swp_pull(swp, &pulldesc);
	if (ret < 0) {
		if (ret == -EBUSY) {
			NADK_INFO(CMD,
				"VDQ command is not issued. QBMAN is busy\n");
			nadk_msleep(5);
			qbman_try_again++;
			if (qbman_try_again > 50)
				return NADK_FAILURE;
		} else {
			NADK_ERR(CMD,
				"VDQ command is not issued. Err Code = %0x\n",
				ret);
			return NADK_FAILURE;
		}
		goto try_again;
	}

	/* Recieve the packets till Last Dequeue entry is found with
	   respect to the above issues PULL command.
	 */
	while (!is_last) {
		/* Loop until the dq_storage is updated with
		 * new token by QBMAN */
		while (!qbman_result_has_new_result(swp, dq_storage))
			;

		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dq_storage)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dq_storage);
			if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				NADK_INFO(CMD, "No frame is delivered\n");
				continue;
			}
		}

		/* Can avoid "qbman_result_is_DQ" check as
		   we are not expecting Notification on this SW-Portal */

		fd = qbman_result_DQ_fd(dq_storage);
		mbuf[rcvd_pkts] = nadk_aiop_fd_to_mbuf(fd);
		rcvd_pkts++;
		dq_storage++;
	} /* End of Packet Rx loop */

	NADK_INFO(CMD, "%d packets received", rcvd_pkts);
	return rcvd_pkts;
}

/*!
 * @details	Packet transmit Function for AIOP. This function may be used to
 *		transmit multiple packets at a time.
 *
 * @param[in]	dev - Pointer to AIOP device structure through which
 *		packet/s need to be sent
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[in]	buf_list - Pointer to list of pointers to buffer which
 *		required to be sent.
 *
 * @param[in]	num - Number of valid buffers in the buffer list.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_xmit(
		struct nadk_dev *dev ODP_UNUSED,
		void *vq,
		uint32_t num,
		nadk_mbuf_pt mbuf[])
{
	struct qbman_fd fd;
	struct qbman_eq_desc eqdesc;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct aiop_vq *tx_vq = (struct aiop_vq *)vq;
	uint32_t loop;
	int ret;

	NADK_TRACE(CMD);

	/* Prepare enqueue descriptor */
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_fq(&eqdesc, tx_vq->fqid);
	qbman_eq_desc_set_no_orp(&eqdesc, 0);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);

	/* Prepare each packet which is to be send */
	for (loop = 0; loop < num; loop++) {

		/* Convert nadk buffer into frame descriptor */
		nadk_aiop_mbuf_to_fd(mbuf[loop], &fd);

		/* Enqueue a packet to the QBMAN */
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				NADK_DBG(CMD, "Transmit failure with err code: %d",
					ret);
			}
		} while (ret == -EBUSY);

		if (mbuf[loop]->flags & NADKBUF_ALLOCATED_SHELL)
			nadk_mbuf_free_shell(mbuf[loop]);
		NADK_INFO(CMD, "Successfully transmitted a packet");
	}
	return loop;

}

/*!
 * @details	Add a RX side virtual queue/s to the AIOP device.This function
 *		shall get called for each RX VQ for which a thread is suppose
 *		to process the packets. Optionally, A RX VQ may be attached to
 *		an preconfigured Aggregator device.
 *
 * @param[in]	dev - Pointer to AIOP device structure.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]	aggr_dev - Pointer aggregator device to which
 *		this VQ should be attached.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_aiop_setup_rx_vq(
		struct nadk_dev *dev,
		uint8_t vq_index,
		struct nadk_vq_param *vq_cfg ODP_UNUSED)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpci = dev_priv->hw;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	uint32_t max_vq_index;
	int ret;

	NADK_TRACE(CMD);

	max_vq_index = nadk_dev_get_max_rx_vq(dev);
	if (vq_index >= max_vq_index) {
		NADK_ERR(CMD, "Invalid VQ index: %d", vq_index);
		return NADK_FAILURE;
	}

	/* Set up the Rx Queue */
	memset(&rx_queue_cfg, 0, sizeof(struct dpci_dest_cfg));
	ret = dpci_set_rx_queue(dpci, CMD_PRI_LOW, dev_priv->token, vq_index, &rx_queue_cfg);
	if (ret) {
		NADK_ERR(CMD, "Setting the Rx queue failed with err code: %d",
			ret);
		return NADK_FAILURE;
	}

	NADK_INFO(CMD, "Sucessfully configured Rx queue");
	return NADK_SUCCESS;
}

/* This API is not required for AIOP, but is here in case user calls it */
int32_t nadk_aiop_setup_tx_vq(
		struct nadk_dev *dev ODP_UNUSED,
		uint32_t num ODP_UNUSED, uint32_t action  ODP_UNUSED)
{
	NADK_TRACE(CMD);

	NADK_NOTE(CMD, "Tx queues are by default configured for AIOP");
	return NADK_SUCCESS;
}

/*!
 * @details	Get the AIOP device ID. The device ID shall be passed by GPP
 *		to the AIOP using CMDIF commands.
 *
 * @param[in]	dev - nadk AIOP device
 *
 * @return	none
 *
 */
int get_aiop_dev_id(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_aiop_priv *aiop_priv = dev_priv->drv_priv;

	return aiop_priv->id;
}

/*! @} */
