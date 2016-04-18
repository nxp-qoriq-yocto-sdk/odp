/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_hwq.c
 *
 * @brief	Frame Queue support for the applications. These are
 *		non-interface related queues, i.e. they do not belong
 *		to Ethernet/SEC/AIOP devices.
 *
 */

/* NADK include files */
#include <nadk_dev.h>
#include <nadk_dev_priv.h>
#include <nadk_hwq_priv.h>
#include <nadk_hwq.h>
#include <nadk_io_portal_priv.h>
#include <nadk_conc_priv.h>
#include <nadk_mbuf_priv.h>

 /*MC header files*/
#include <fsl_dpci.h>
#include <fsl_dpci_cmd.h>

/*ODP header files*/
#include <odp/hints.h>

/* Array-list to maintain software queues */
struct nadk_hwq_t frameq[MAX_FRAMEQ];

/* Lock required to be taken while allocating or freeing the queue */
lock_t frameq_lock;

/* Conversion function for FD to MBUF. This is used as a callback
 * function when the packet is received by conc device */
void *nadk_hwq_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm ODP_UNUSED,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr)
{
	struct nadk_mbuf *mbuf;

	mbuf = (struct nadk_mbuf *)NADK_GET_FD_ADDR(fd);

	/* Fetch the User context to restore the VQ*/
	mbuf->vq = (void *)qbman_result_DQ_fqd_ctx(dqrr);
	return (void *)mbuf;
}

/* Get a free entry from the global list.
 * Also change the state from INVALID to FREE */
static inline struct nadk_hwq_t *nadk_create_frameq(void)
{
	int i;

	NADK_TRACE(FRAMEQ);

	for (i = 0; i < MAX_FRAMEQ; i++) {
		if (frameq[i].state == FRAMEQ_STATE_INVALID) {
			frameq[i].state = FRAMEQ_STATE_FREE;
			return &(frameq[i]);
		}
	}

	return NULL;
}

/* Mark the frame Queue as invalid */
static inline void nadk_destroy_frameq(
		struct nadk_hwq_t *frame_queue)
{
	NADK_TRACE(FRAMEQ);

	if (frame_queue->state == FRAMEQ_STATE_INVALID)
		NADK_ERR(FRAMEQ, "Destroying an invalid Frame Queue");

	frame_queue->state = FRAMEQ_STATE_INVALID;
}

int nadk_hwq_probe(struct nadk_dev *dev,
		ODP_UNUSED const void *data)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpci;
	struct dpci_attr attr;
	struct nadk_hwq_t *frame_queue;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	struct dpci_rx_queue_attr rx_attr;
	int32_t ret;
	static int frameq_lock_initialized = FALSE;

	NADK_TRACE(FRAMEQ);

	if (frameq_lock_initialized == FALSE) {
		LOCK_INIT(frameq_lock, 0);
		frameq_lock_initialized = true;
	}
	/* Open the nadk device via MC */
	dpci = (struct fsl_mc_io *)nadk_calloc(NULL, 1,
			sizeof(struct fsl_mc_io), 0);
	if (!dpci) {
		NADK_ERR(FRAMEQ, "Memory allocation failure");
		return NADK_FAILURE;
	}

	dpci->regs = dev_priv->mc_portal;
	ret = dpci_open(dpci, CMD_PRI_LOW, dev_priv->hw_id,
			&(dev_priv->token));
	if (ret != 0) {
		NADK_ERR(FRAMEQ, "Opening device failed with "
			"err code: %d", ret);
		goto err1;
	}

	/* Get the device attributes */
	ret = dpci_get_attributes(dpci, CMD_PRI_LOW, dev_priv->token, &attr);
	if (ret != 0) {
		NADK_ERR(FRAMEQ, "Reading device failed with "
			"err code: %d", ret);
		goto err2;
	}

	/* Return error in case number of priorities are not '1' */
	if (attr.num_of_priorities != 1) {
		NADK_ERR(FRAMEQ, "Invalid number of queues");
		goto err2;
	}

	/* Set up the Rx Queue */
	memset(&rx_queue_cfg, 0, sizeof(struct dpci_dest_cfg));
	ret = dpci_set_rx_queue(dpci, CMD_PRI_LOW,
				dev_priv->token, 0, &rx_queue_cfg);
	if (ret) {
		NADK_ERR(FRAMEQ, "Setting the Rx queue failed with "
			"err code: %d", ret);
		goto err2;
	}

	/* Enable the device */
	ret = dpci_enable(dpci, CMD_PRI_LOW,  dev_priv->token);
	if (ret != 0) {
		NADK_ERR(FRAMEQ, "Enabling device failed with "
			"err code: %d", ret);
		goto err2;
	}

	/* Get the Rx FQID */
	ret = dpci_get_rx_queue(dpci, CMD_PRI_LOW,
				dev_priv->token, 0, &rx_attr);
	if (ret != 0) {
		NADK_ERR(CMD, "Reading device failed with "
			"err code: %d", ret);
		goto err3;
	}

	/* Get a free NADK FRAMEQ and populate it */
	frame_queue = nadk_create_frameq();
	if (!frame_queue) {
		NADK_ERR(FRAMEQ, "nadk_alloc_frameq failed");
		goto err3;
	}
	frame_queue->mc_io = dpci;
	frame_queue->token = dev_priv->token;
	frame_queue->fqid = rx_attr.fqid;

	NADK_INFO(FRAMEQ, "Successfully initialized the Frame Queue");

	return NADK_SUCCESS;
err3:
	/* Disable the DPCI */
	ret = dpci_disable(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		NADK_ERR(FRAMEQ, "Disabling device failed with "
			"err code: %d", ret);

err2:
	/* Close the device in case of error */
	ret = dpci_close(dpci, CMD_PRI_LOW, dev_priv->token);
	if (ret != 0)
		NADK_ERR(FRAMEQ, "Closing the device failed with "
			"err code: %d", ret);
err1:
	/* Free the DPCI handle */
	nadk_free(dpci);

	return NADK_FAILURE;
}

/* Clean-up all the frame queues */
int nadk_hwq_close_all(void)
{
	int i, ret;

	NADK_TRACE(FRAMEQ);

	LOCK_DESTROY(frameq_lock);
	for (i = 0; i < MAX_FRAMEQ; i++) {
		if (frameq[i].state != FRAMEQ_STATE_INVALID) {
			if (frameq[i].state == FRAMEQ_STATE_ATTACHED) {
				ret = nadk_detach_frameq_from_conc(&frameq[i]);
				if (ret != NADK_SUCCESS)
					NADK_ERR(FRAMEQ, "Unable to detach from conc");
			}

			/* Close the device */
			ret = dpci_close(frameq[i].mc_io,
					 CMD_PRI_LOW, frameq[i].token);
			if (ret != 0)
				NADK_ERR(FRAMEQ, "Closing the device failed with "
					"err code: %d", ret);
			nadk_free(frameq[i].mc_io);
			nadk_destroy_frameq(&frameq[i]);
		}
	}

	NADK_INFO(CMD, "Successfully closed the device");
	return NADK_SUCCESS;
}

/* Attach a frame queue to a concentrator device */
int nadk_attach_frameq_to_conc(
		void *h_nadk_hwq,
		struct nadk_vq_param *vq_param)
{
	struct conc_attr attr;
	struct dpci_rx_queue_cfg rx_queue_cfg;
	struct nadk_hwq_t *nadk_hwq = h_nadk_hwq;
	int ret;

	NADK_TRACE(FRAMEQ);

	if (nadk_hwq->state != FRAMEQ_STATE_ACQUIRED) {
		NADK_ERR(FRAMEQ, "Frame queue not in ACQUIRED state");
		return NADK_FAILURE;
	}

	memset(&attr, 0, sizeof(struct conc_attr));
	/* Get DPCONC object attributes */
	nadk_conc_get_attributes(vq_param->conc_dev, &attr);

	/*Do settings to get the frame on a DPCON object*/
	rx_queue_cfg.options		= DPCI_QUEUE_OPT_DEST |
					  DPNI_QUEUE_OPT_USER_CTX;
	rx_queue_cfg.dest_cfg.dest_type	= DPCI_DEST_DPCON;
	rx_queue_cfg.dest_cfg.dest_id	= attr.obj_id;
	rx_queue_cfg.dest_cfg.priority	= vq_param->prio;

	/* Set the callback. This will be called when conc will
	 * dequeue the packet from this frame queue */
	nadk_hwq->dummy_vq.qmfq.cb	= nadk_hwq_cb_dqrr_fd_to_mbuf;
	rx_queue_cfg.user_ctx		= (uint64_t)(&nadk_hwq->dummy_vq);

	ret = dpci_set_rx_queue(nadk_hwq->mc_io, CMD_PRI_LOW,
				nadk_hwq->token, 0, &rx_queue_cfg);
	if (ret) {
		NADK_ERR(FRAMEQ, "Setting the Rx queue failed with "
			"err code: %d", ret);
		return NADK_FAILURE;
	}

	return NADK_SUCCESS;
}

/* Detach a frame queue from a concentrator device */
int nadk_detach_frameq_from_conc(void *h_nadk_hwq)
{
	struct dpci_rx_queue_cfg rx_queue_cfg;
	struct nadk_hwq_t *nadk_hwq = h_nadk_hwq;
	int ret;

	NADK_TRACE(FRAMEQ);

	if (nadk_hwq->state != FRAMEQ_STATE_ATTACHED) {
		NADK_ERR(FRAMEQ, "Frame Queue is not attached to CONC");
		return NADK_FAILURE;
	}

	/*Do settings to get the frame on a DPCON object*/
	rx_queue_cfg.options		= DPCI_QUEUE_OPT_DEST;
	rx_queue_cfg.dest_cfg.dest_type	= DPCI_DEST_NONE;

	ret = dpci_set_rx_queue(nadk_hwq->mc_io, CMD_PRI_LOW,
				nadk_hwq->token, 0, &rx_queue_cfg);
	if (ret) {
		NADK_ERR(FRAMEQ, "Setting the Rx queue failed with "
			"err code: %d", ret);
		return NADK_FAILURE;
	}

	return NADK_SUCCESS;
}

/* Get a FREE frame queue from the frame queue list */
void *nadk_get_frameq(void)
{
	int i;

	NADK_TRACE(FRAMEQ);

	LOCK(frameq_lock);
	for (i = 0; i < MAX_FRAMEQ; i++) {
		if (frameq[i].state == FRAMEQ_STATE_FREE) {
			frameq[i].state = FRAMEQ_STATE_ACQUIRED;
			UNLOCK(frameq_lock);
			return &(frameq[i]);
		}
	}

	UNLOCK(frameq_lock);
	return NULL;
}

/* Mark the frame queue as FREE, so that it can be taken by another user */
void nadk_put_frameq(void *h_nadk_hwq)
{
	struct nadk_hwq_t *nadk_hwq = h_nadk_hwq;
	int ret;

	NADK_TRACE(FRAMEQ);

	if (nadk_hwq->state == FRAMEQ_STATE_INVALID) {
		NADK_ERR(FRAMEQ, "Frame Queue is in INVALID state");
		return;
	}

	if (nadk_hwq->state == FRAMEQ_STATE_ATTACHED) {
		ret = nadk_detach_frameq_from_conc(h_nadk_hwq);
		if (ret != NADK_SUCCESS) {
			NADK_ERR(FRAMEQ, "Unable to detach from conc");
			return;
		}
	}

	nadk_hwq->state = FRAMEQ_STATE_FREE;
}

/* Receive buffers from the NADK Frame Queue */
int nadk_hwq_recv(void *h_nadk_hwq,
		  struct nadk_mbuf *buf_list[],
		int num)
{
	struct nadk_hwq_t *frameq = h_nadk_hwq;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	const struct qbman_result *dqrr_entry;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;
	uint8_t status, is_last = 0;
	int ret, rcvd_pkts = 0;

	/* Prepare the pull descriptor */
	qbman_pull_desc_clear(&pulldesc);
	qbman_pull_desc_set_fq(&pulldesc, frameq->fqid);
	qbman_pull_desc_set_numframes(&pulldesc, num);

	/* Issue a volatile dequeue command. */
	do {
		ret = qbman_swp_pull(swp, &pulldesc);
		if (ret != 0) {
			NADK_DBG(FRAMEQ, "VDQ command is not issued. QBMAN is busy\n");
		}
	} while (ret != 0);

	/* Receive the packets till Last Dequeue entry is found with
	 * respect to the above issues PULL command. */
	while (!is_last) {
		dqrr_entry = qbman_swp_dqrr_next(swp);
		if (odp_unlikely(NULL == dqrr_entry))
			continue;

		/* Check whether Last Pull command is Expired and
		setting Condition for Loop termination */
		if (qbman_result_DQ_is_pull_complete(dqrr_entry)) {
			is_last = 1;
			/* Check for valid frame. */
			status = (uint8_t)qbman_result_DQ_flags(dqrr_entry);
			if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
				NADK_INFO(CONC, "No frame is delivered\n");
				qbman_swp_dqrr_consume(swp, dqrr_entry);
				continue;
			}
		}

		/* Get the FD from the DQRR entry */
		fd = qbman_result_DQ_fd(dqrr_entry);
		buf_list[rcvd_pkts] = (struct nadk_mbuf *)NADK_GET_FD_ADDR(fd);
		qbman_swp_dqrr_consume(swp, dqrr_entry);
		rcvd_pkts++;
	}

	/* Return number of packets received */
	return rcvd_pkts;
}

/* Send buffers to the NADK Frame Queue */
int nadk_hwq_xmit(void *h_nadk_hwq,
		  struct nadk_mbuf *buf_list[],
		int num)
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct nadk_hwq_t *frameq = h_nadk_hwq;
	struct qbman_fd fd;
	struct qbman_eq_desc eqdesc;
	int loop, ret;

	/* Prepare enqueue descriptor */
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_fq(&eqdesc, frameq->fqid);
	qbman_eq_desc_set_no_orp(&eqdesc, 0);
	qbman_eq_desc_set_response(&eqdesc, 0, 0);

	/* Prepare each packet which is to be send */
	for (loop = 0; loop < num; loop++) {
		/* Convert nadk buffer into frame descriptor */
		NADK_SET_FD_ADDR((&fd), buf_list[loop]);
		NADK_SET_FD_LEN((&fd), sizeof(struct nadk_mbuf));
		/* Set DCA for freeing DQRR if required. We are saving
		   DQRR entry index in buffer when using DQRR mode.
		   The same need to be freed by H/W.
		*/
		if (ANY_ATOMIC_CNTXT_TO_FREE(buf_list[loop])) {
			qbman_eq_desc_set_dca(&eqdesc, 1, GET_HOLD_DQRR_IDX, 0);
			MARK_HOLD_DQRR_PTR_INVALID;
		}

		/* Enqueue a packet to the QBMAN */
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, &fd);
			if (ret != 0) {
				NADK_DBG(FRAMEQ, "Transmit failure. QBMAN is busy\n");
			}
		} while (ret != 0);
	}

	/* Return number of packets transmitted */
	return loop;
}
