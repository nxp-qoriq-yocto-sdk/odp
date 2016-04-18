/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*
 * file	nadk_sec.c
 *
 * brief	Sec driver implementation. It contains initialization of
 *		Security interface for NADK device framework based application
 *
 */
#include <odp.h>
#include <nadk_dev.h>
#include <nadk_common.h>
#include <nadk_mbuf.h>
#include <nadk_mbuf_priv.h>
#include <nadk_dev_priv.h>
#include <nadk_io_portal_priv.h>
#include "nadk_sec_priv.h"
#include <nadk_conc_priv.h>
#include <nadk_vq.h>
#include <nadk_eth_ldpaa_qbman.h>
#include <nadk_malloc.h>
#include <flib/rta.h>
#include <flib/desc.h>
#include <flib/desc/jobdesc.h>
#include <fsl_dpseci.h>
#include <fsl_dpseci_cmd.h>
#include <odp/byteorder.h>
#include <nadk_queue.h>
#include <nadk_time.h>
#include <odp/hints.h>
#include <odp/plat/event_types.h>
#include <odp_buffer_internal.h>

#define LDPAA_SEC_DEV_VENDER_ID		0x1957
#define LDPAA_SEC_DEV_NAME		"ldpaa-sec"
#define SEC_NOT_IMPLEMENTED	0

enum rta_sec_era rta_sec_era = RTA_SEC_ERA_8;

struct sec_dev_list {
	TAILQ_ENTRY(sec_dev_list) next;
	struct nadk_dev *dev;
	uint32_t index;
};

TAILQ_HEAD(sec_map_list, sec_dev_list);
struct sec_map_list dev_map_list;
struct sec_dev_list *sec_dev_map, *last_used_dev = NULL;

void *nadk_sec_cb_dqrr_fd_to_mbuf(
		struct qbman_swp *qm ODP_UNUSED,
		const struct qbman_fd *fd,
		const struct qbman_result *dqrr ODP_UNUSED)
{
	/* FIXME Check if you can pass the original XXX_req in original
	   buffer or FD? If so, retrieving it back will be efficient. */
	nadk_mbuf_pt mbuf;
	struct qbman_fle *fle, *fle1, *sge;

	fle = (struct qbman_fle *)NADK_GET_FD_ADDR(fd);
	if (odp_unlikely(NADK_GET_FD_IVP(fd))) {
		NADK_DBG(SEC, "ALLOC shell called");
		mbuf = nadk_mbuf_alloc_shell();
		if (!mbuf) {
			NADK_ERR(ETH, "Unable to allocate shell");
			return NULL;
		}
		mbuf->bpid = NADK_GET_FD_BPID(fd);
		mbuf->priv_meta_off = NADK_GET_FD_OFFSET(fd);
		mbuf->head = (uint8_t *)NADK_GET_FLE_ADDR(fle) + mbuf->priv_meta_off;
		mbuf->data = mbuf->head;
		mbuf->end_off = NADK_GET_FD_LEN(fd);

	} else {
		NADK_DBG(SEC, "INLINE SHELL Retrieved, meta_data_size: %x",
			 bpid_info[NADK_GET_FD_BPID(fd)].meta_data_size);
		mbuf = NADK_INLINE_MBUF_FROM_BUF(NADK_GET_FD_ADDR(fd),
			bpid_info[NADK_GET_FD_BPID(fd)].meta_data_size);
	}

	mbuf->frame_len   = fle->length;
	mbuf->tot_frame_len = mbuf->frame_len;
	mbuf->drv_priv_resv[1] = fd->simple.frc;
	NADK_DBG(SEC, "priv_meta_off: %x, data: %p, head: %p, end_off: %x, "
			"bpid: %x, len: %x, tot_len: %x\n", mbuf->priv_meta_off,
			mbuf->data, mbuf->head, mbuf->end_off, mbuf->bpid,
			mbuf->frame_len, mbuf->tot_frame_len);

	mbuf->flags |= NADKBUF_SEC_CNTX_VALID;
	fle1 = fle + 1;
	if (NADK_IS_SET_FLE_SG_EXT(fle)) {
		sge = (struct qbman_fle *)NADK_GET_FLE_ADDR(fle);
		nadk_data_free(sge);
	} else if (NADK_IS_SET_FLE_SG_EXT(fle1)) {
		sge = (struct qbman_fle *)NADK_GET_FLE_ADDR(fle1);
		nadk_data_free(sge);
	}

	if (mbuf->priv_meta_off < 2*sizeof(struct qbman_fle))
		nadk_data_free(fle);
	/*TODO Stash bits are not taken care currently*/
	mbuf->vq = (void *)NADK_GET_FD_FLC(fd);

	_odp_buffer_type_set(mbuf, ODP_EVENT_CRYPTO_COMPL);

	/*todo - based on vq type, store the DQRR in mbuf*/
	return mbuf;
}

int32_t nadk_sec_attach_bp_list(struct nadk_dev *dev,
		void *blist)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_bp_list *bp_list = (struct nadk_bp_list *)blist;

	dev_priv->bp_list = bp_list;

	return NADK_SUCCESS;
}

int32_t nadk_sec_dev_list_init(void)
{
	TAILQ_INIT(&dev_map_list);
	return NADK_SUCCESS;
}

int32_t nadk_sec_dev_list_add(struct nadk_dev *dev)
{
	sec_dev_map = nadk_malloc(NULL, sizeof(struct sec_dev_list));
	if (!sec_dev_map) {
		NADK_ERR(SEC, "nadk_malloc for sec_dev_map failed");
		return NADK_FAILURE;
	}
	sec_dev_map->dev = dev;
	TAILQ_INSERT_TAIL(&dev_map_list, sec_dev_map, next);
	return NADK_SUCCESS;
}

struct nadk_dev *nadk_sec_get_dev(void)
{
#ifndef SINGLE_DPSECI
	if (last_used_dev) {
		TAILQ_FOREACH(sec_dev_map, &dev_map_list, next) {
			if ((last_used_dev == TAILQ_PREV(sec_dev_map,
						sec_map_list, next))) {
				last_used_dev = sec_dev_map;
				return last_used_dev->dev;
			}
		}
	}
#endif
	last_used_dev = TAILQ_FIRST(&dev_map_list);
	return last_used_dev->dev;
}

int32_t nadk_sec_start(struct nadk_dev *dev)
{
	int32_t retcode, i;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpseci = dev_priv->hw;
	struct dpseci_attr attr;
	struct nadk_vq *vq;
	struct dpseci_rx_queue_attr rx_attr;
	struct dpseci_tx_queue_attr tx_attr;

	memset(&attr, 0, sizeof(struct dpseci_attr));

	retcode = dpseci_enable(dpseci, CMD_PRI_LOW, dev_priv->token);
	if (retcode) {
		NADK_ERR(SEC, "\tDPSECI with HW_ID = %d ENABLE FAILED",
				dev_priv->hw_id);
		return NADK_FAILURE;
	}
	retcode = dpseci_get_attributes(dpseci, CMD_PRI_LOW, dev_priv->token, &attr);
	if (retcode) {
		NADK_ERR(SEC, "\tDPSEC ATTRIBUTE READ FAILED, disabling DPSEC");
		goto get_attr_failure;
	}
	for (i = 0; i < attr.num_rx_queues; i++) {
		vq = dev->rx_vq[i];
		dpseci_get_rx_queue(dpseci, CMD_PRI_LOW, dev_priv->token, i, &rx_attr);
		vq->fqid = rx_attr.fqid;
		NADK_INFO(SEC, "\trx_fqid: %d", vq->fqid);
	}
	for (i = 0; i < attr.num_tx_queues; i++) {
		vq = dev->tx_vq[i];
		dpseci_get_tx_queue(dpseci, CMD_PRI_LOW, dev_priv->token, i, &tx_attr);
		vq->fqid = tx_attr.fqid;
		NADK_INFO(SEC, "\ttx_fqid: %d", vq->fqid);
	}
	return NADK_SUCCESS;

get_attr_failure:
	dpseci_disable(dpseci, CMD_PRI_LOW, dev_priv->token);
	return NADK_FAILURE;
}

int32_t nadk_sec_stop(struct nadk_dev *dev)
{
	int32_t retcode;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpseci = (struct fsl_mc_io *)dev_priv->hw;

	dev->state = DEV_INACTIVE;
	/* Disable the SEC interface and set nadk device as inactive*/
	retcode = dpseci_disable(dpseci, CMD_PRI_LOW, dev_priv->token);
	if (retcode != 0) {
		NADK_ERR(SEC, "Device cannot be disabled:Error Code = %0x\n",
				retcode);
		return NADK_FAILURE;
	}
	retcode = dpseci_reset(dpseci, CMD_PRI_LOW, dev_priv->token);
	if (retcode < 0) {
		NADK_ERR(SEC, "Device cannot be reset:Error Code = %0x\n",
				retcode);
		return NADK_FAILURE;
	}

	return NADK_SUCCESS;
}

int32_t nadk_sec_setup_rx_vq(struct nadk_dev *dev,
				uint8_t vq_id,
				struct nadk_vq_param *vq_cfg)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_vq *rx_vq;
	struct fsl_mc_io *dpseci = dev_priv->hw;
	struct dpseci_rx_queue_cfg cfg;
	int32_t	retcode;

	memset(&cfg, 0, sizeof(struct dpseci_rx_queue_cfg));
	rx_vq = (struct nadk_vq *)(dev->rx_vq[vq_id]);
	rx_vq->sync = ODP_SCHED_SYNC_NONE;

	if (vq_cfg) {
		if (vq_cfg->conc_dev) {
			struct conc_attr attr;
			memset(&attr, 0, sizeof(struct conc_attr));
			/*Get DPCONC object attributes*/
			nadk_conc_get_attributes(vq_cfg->conc_dev, &attr);

			/*Do settings to get the frame on a DPCON object*/
			cfg.options		= DPSECI_QUEUE_OPT_DEST;
			cfg.dest_cfg.dest_type	= DPSECI_DEST_DPCON;
			cfg.dest_cfg.dest_id	= attr.obj_id;
			cfg.dest_cfg.priority	= vq_cfg->prio;
			dev->conc_dev		= vq_cfg->conc_dev;
			NADK_INFO(SEC, "DPCON ID = %d\t Prio = %d\n",
					cfg.dest_cfg.dest_id,
					cfg.dest_cfg.priority);
			NADK_INFO(SEC, "Attaching SEC device %s"
				"with Channel %s\n",
				dev->dev_string, vq_cfg->conc_dev->dev_string);
		}
		if (vq_cfg->sync == ODP_SCHED_SYNC_ATOMIC) {
			cfg.options = cfg.options |
				DPNI_QUEUE_OPT_ORDER_PRESERVATION;
			cfg.order_preservation_en = TRUE;
			rx_vq->sync = vq_cfg->sync;
		}
	}

	cfg.options = cfg.options | DPSECI_QUEUE_OPT_USER_CTX;
	cfg.user_ctx = (uint64_t)(dev->rx_vq[vq_id]);
	rx_vq->qmfq.cb = nadk_sec_cb_dqrr_fd_to_mbuf;

	NADK_DBG(SEC, "\nSetting DPSEC to DPSEC_DEST_NONE,"
			" no notification will be sent");

	retcode = dpseci_set_rx_queue(dpseci, CMD_PRI_LOW, dev_priv->token,
				      vq_id, &cfg);
	return retcode;
}

int32_t nadk_sec_recv(void *vq,
		uint32_t num,
		nadk_mbuf_pt mbuf[])
{
	/* Function is responsible to receive frames for a given device and VQ*/
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	struct qbman_result *dq_storage = thread_io_info.dq_storage;
	struct nadk_vq *sec_vq = (struct nadk_vq *)vq;
	int32_t rcvd_pkts = 0;
	uint8_t status, is_last = 0;
	const struct qbman_fd *fd;
	struct qbman_pull_desc pulldesc;

	nadk_qbman_pull_desc_set(&pulldesc, num, sec_vq->fqid, dq_storage);

	while (1) {
		if (qbman_swp_pull(swp, &pulldesc)) {
			NADK_WARN(SEC, "VDQ command is not issued....QBMAN is busy\n");
			/* Portal was busy, try again */
			continue;
		}
		break;
	};

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
				NADK_INFO(SEC, "No frame is delivered\n");
				continue;
			}
		}

		/* Can avoid "qbman_result_is_DQ" check as
		   we are not expecting Notification on this SW-Portal */
		fd = qbman_result_DQ_fd(dq_storage);
		NADK_INFO(SEC, "Vq= %x", NADK_GET_FD_FLC(fd));
		mbuf[rcvd_pkts] = sec_vq->qmfq.cb(swp, fd, dq_storage);
		if (mbuf[rcvd_pkts])
			rcvd_pkts++;
		dq_storage++;
	} /* End of Packet Rx loop */

	NADK_INFO(SEC, "SEC Received %d Packets", ret);
	/*Return the total number of packets received to NADK app*/
	return rcvd_pkts;
}

int32_t nadk_sec_probe(struct nadk_dev *dev, ODP_UNUSED const void *cfg)
{
	struct nadk_sec_priv *sec_priv;
	struct fsl_mc_io *dpseci;
	int32_t retcode, i;
	uint16_t token;
	struct dpseci_attr attr;
	struct nadk_vq *vq_mem;
	struct nadk_dev_priv *dev_priv = dev->priv;

	/* Allocate the space for nadk sec private data */
	sec_priv = (struct nadk_sec_priv *)nadk_calloc(NULL, 1,
			sizeof(struct nadk_sec_priv), 0);

	if (sec_priv == NULL) {
		NADK_ERR(SEC, "Memory not allocated for NADK_SEC_PRIV");
		return NADK_FAILURE;
	}

	/* FIXME create a per device cache of buffers which may be required
	   for run-time processing of Jobs. Such cache helps in limiting
	   the Job's which the current thread can send.
	 */

	vq_mem = (struct nadk_vq *)(sec_priv);
	for (i = 0; i < MAX_RX_VQS; i++) {
		vq_mem->dev = dev;
		dev->rx_vq[i] = vq_mem++;
	}
	for (i = 0; i < MAX_TX_VQS; i++) {
		vq_mem->dev = dev;
		dev->tx_vq[i] = vq_mem++;
	};

	dev_priv->fn_dev_start   = nadk_sec_start;
	dev_priv->fn_setup_rx_vq = nadk_sec_setup_rx_vq;
	dev_priv->fn_dev_send    = NULL;
	dev_priv->fn_dev_rcv     = NULL;

	/*Open the nadk device via MC and save the handle for further use*/
	dpseci = (struct fsl_mc_io *)nadk_calloc(NULL, 1,
				sizeof(struct fsl_mc_io), 0);
	if (!dpseci) {
		NADK_ERR(SEC, "Error in allocating the memory for dpsec object\n");
		goto mem_alloc_failure;
	}
	dpseci->regs = dev_priv->mc_portal;

	retcode = dpseci_open(dpseci, CMD_PRI_LOW, dev_priv->hw_id, &token);
	if (retcode != 0) {
		NADK_ERR(SEC,
			"Cannot open the dpsec device: Error Code = %x\n",
			retcode);
		goto dev_open_failure;
	}
	retcode = dpseci_get_attributes(dpseci, CMD_PRI_LOW, token, &attr);
	if (retcode != 0) {
		NADK_ERR(SEC,
			"Cannot get dpsec device attributed: Error Code = %x\n",
			retcode);
		goto dev_open_failure;
	}
	dev->num_tx_vqueues = attr.num_tx_queues;
	dev->num_rx_vqueues = attr.num_rx_queues;

	NADK_NOTE(SEC, "DPSECI: number of tx vq = %d rx vq = %d",
			attr.num_tx_queues, attr.num_rx_queues);

	dev_priv->drv_priv = sec_priv;
	dev_priv->hw = dpseci;
	dev_priv->token = token;
	dev->state = DEV_ACTIVE;
	sprintf(dev->dev_string, "dpsec-%u", dev_priv->hw_id);
	return NADK_SUCCESS;

dev_open_failure:
		nadk_free(dpseci);
mem_alloc_failure:
		nadk_free(sec_priv);
		return NADK_FAILURE;
}

int32_t nadk_sec_remove(struct nadk_dev *dev)
{
	/* 1. Reverse function of probe.*/
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_sec_priv *sec_priv = dev_priv->drv_priv;
	struct fsl_mc_io *dpseci = dev_priv->hw;
	int32_t retcode;

	/*TODO add device busy attribute also.*/

	dev->state = DEV_INACTIVE;
	/*First close the device at underlying layer*/
	retcode = dpseci_close(dpseci, CMD_PRI_LOW, dev_priv->token);
	if (retcode < 0) {
		NADK_ERR(SEC,
			"Error in closing the device with errocode = %d\n",
			retcode);
		return NADK_FAILURE;
	}

	/*Free the allocated memory for SEC private data*/
	nadk_free(sec_priv);
	nadk_free(dpseci);

	return NADK_SUCCESS;
}

struct nadk_driver sec_driver = {
	.name			=	LDPAA_SEC_DEV_NAME,
	.vendor_id		=	LDPAA_SEC_DEV_VENDER_ID,
	.major			=	DPSECI_VER_MAJOR,
	.minor			=	DPSECI_VER_MINOR,
	.dev_type		=	NADK_SEC,
	.dev_probe		=	nadk_sec_probe,
	.dev_shutdown	=	nadk_sec_remove
};

int32_t nadk_sec_driver_init(void)
{
	/*Register SEC driver to NADK*/
	nadk_register_driver(&sec_driver);
	nadk_sec_dev_list_init();

	return NADK_SUCCESS;
}

int32_t nadk_sec_driver_exit(void)
{
	/*Register SEC driver to NADK*/
	nadk_unregister_driver(&sec_driver);

	return NADK_SUCCESS;
}
