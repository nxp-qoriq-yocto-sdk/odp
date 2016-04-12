/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		cmdif_client_gpp.c
 * @description	GPP to AIOP cmdif APIs
 */

#include <nadk_dev.h>
#include <odp/std_types.h>
#include <nadk_time.h>
#include <fsl_cmdif_client.h>
#include <fsl_cmdif_flib_c.h>
#include <nadk_aiop.h>
#include <nadk_mpool.h>

#define CMDIF_CLIENT_TIMEOUT		3000
#define CMDIF_CLIENT_SYNC_WAIT		100

int send_fd(struct cmdif_fd *cfd, int pr, void *nadk_dev)
{
	struct nadk_dev *aiop_dev = nadk_dev;
	struct nadk_mbuf mbuf, *send_mbuf = &mbuf;
	struct aiop_buf_info aiop_cnxt;
	int max_tx_vq = nadk_dev_get_max_tx_vq(aiop_dev);
	int ret;

	if (pr < 0 || pr >= max_tx_vq || !cfd || !nadk_dev) {
		NADK_ERR(CMD, "Invalid input");
		return -EINVAL;
	}

	memset(&mbuf, 0, sizeof(struct nadk_mbuf));
	/* Set the fields of the NADK buffer shell */
	send_mbuf->head = (uint8_t *)(cfd->u_addr.d_addr);
	send_mbuf->data = (uint8_t *)(cfd->u_addr.d_addr);
	send_mbuf->frame_len = cfd->d_size;
	send_mbuf->bpid = 0;

	aiop_cnxt.frc = cfd->u_frc.frc;
	aiop_cnxt.flc = cfd->u_flc.flc;
	aiop_cnxt.error = 0;
	send_mbuf->drv_priv_cnxt = &aiop_cnxt;

	/* Using the VQ on basis of priority */
	ret = nadk_send(aiop_dev, aiop_dev->tx_vq[pr], 1,
		&send_mbuf);
	if (ret != 1) {
		NADK_ERR(CMD, "Error in transmitting packet");
		return ret;
	}
	return NADK_SUCCESS;
}

int receive_fd(struct cmdif_fd *cfd, int pr, void *nadk_dev)
{
	struct nadk_dev *aiop_dev = nadk_dev;
	nadk_mbuf_pt recv_mbuf;
	struct aiop_buf_info *aiop_cnxt;
	int max_rx_vq = nadk_dev_get_max_rx_vq(aiop_dev);
	int32_t in_pkt;

	if (pr < 0 || pr > max_rx_vq || !cfd || !nadk_dev) {
		NADK_ERR(CMD, "Invalid input");
		return -EINVAL;
	}

	in_pkt = nadk_receive(aiop_dev, aiop_dev->rx_vq[pr],
		1, &recv_mbuf);
	if (in_pkt < 0) {
		NADK_ERR(CMD, "Error calling nadk_receive");
		return in_pkt;
	}

	if (in_pkt == 0) {
		NADK_DBG(CMD, "No packet received");
	} else {
		aiop_cnxt = recv_mbuf->drv_priv_cnxt;
		cfd->u_flc.flc = aiop_cnxt->flc;
		cfd->u_frc.frc = aiop_cnxt->frc;
		cfd->d_size = recv_mbuf->frame_len;
		cfd->u_addr.d_addr = (uint64_t)(recv_mbuf->head);
		nadk_mbuf_free_shell(recv_mbuf);
	}

	return in_pkt;
}

int cmdif_open(struct cmdif_desc *cidesc,
		const char *module_name,
		uint8_t instance_id,
		void *data,
		uint32_t size)
{
	struct cmdif_fd fd;
	int err = 0;
	int t = 0;
	int resp = 0;

	err = cmdif_open_cmd(cidesc, module_name, instance_id, data,
			(uint64_t)(data), size, &fd);
	if (err) {
		NADK_ERR(CMD, "cmdif_open_cmd failed with err code: %d",
			err);
		goto error;
	}

	err = send_fd(&fd, CMDIF_PRI_LOW, cidesc->regs);
	if (err) {
		NADK_ERR(CMD, "send_fd failed");
		goto error;
	}

	/* Wait for response from Server */
	do {
		resp = cmdif_sync_ready(cidesc);
		if (resp == 0)
			nadk_msleep(CMDIF_CLIENT_SYNC_WAIT);
		t++;
	} while ((resp == 0) && (t < CMDIF_CLIENT_TIMEOUT));
	if (t == CMDIF_CLIENT_TIMEOUT) {
		NADK_ERR(CMD, "cmdif_sync_ready reached timeout value");
		err = -ETIMEDOUT;
		goto error;
	}

	err = cmdif_open_done(cidesc);
	if (err) {
		NADK_ERR(CMD, "cmdif_open_done failed with err code: %d",
			err);
		goto error;
	}

	return NADK_SUCCESS;

error:
	return err;
}


int cmdif_close(struct cmdif_desc *cidesc)
{
	struct cmdif_fd fd;
	int err = 0;
	int t = 0;
	int resp = 0;

	err = cmdif_close_cmd(cidesc, &fd);
	if (err) {
		NADK_ERR(CMD, "cmdif_close_cmd failed with err code: %d",
			err);
		goto error;
	}

	err = send_fd(&fd, CMDIF_PRI_LOW, cidesc->regs);
	if (err) {
		NADK_ERR(CMD, "send_fd failed");
		goto error;
	}

	/* Wait for response from Server */
	do {
		resp = cmdif_sync_ready(cidesc);
		if (resp == 0)
			nadk_msleep(CMDIF_CLIENT_SYNC_WAIT);
		t++;
	} while ((resp == 0) && (t < CMDIF_CLIENT_TIMEOUT));
	if (t == CMDIF_CLIENT_TIMEOUT) {
		NADK_ERR(CMD, "cmdif_sync_ready reached timeout value");
		goto error;
	}

	err = cmdif_close_done(cidesc);
	if (err)
		NADK_ERR(CMD, "cmdif_close_done failed with err code: %d",
			err);

	return NADK_SUCCESS;

error:
	return err;
}

int cmdif_send(struct cmdif_desc *cidesc,
		uint16_t cmd_id,
		uint32_t size,
		int priority,
		uint64_t data,
		cmdif_cb_t *async_cb,
		void *async_ctx)
{
	struct cmdif_fd fd;
	int err = 0;
	int t = 0;
	int resp = 0;

	err = cmdif_cmd(cidesc, cmd_id, size, data, async_cb, async_ctx, &fd);
	if (err) {
		NADK_ERR(CMD, "cmdif_cmd failed with err code: %d", err);
		return err;
	}

	err = send_fd(&fd, priority, cidesc->regs);
	if (err) {
		NADK_ERR(CMD, "send_fd failed");
		return err;
	}

	if (cmdif_is_sync_cmd(cmd_id)) {
		/* Wait for response from Server */
		do {
			resp = cmdif_sync_ready(cidesc);
			if (resp == 0)
				nadk_msleep(CMDIF_CLIENT_SYNC_WAIT);
			t++;
		} while ((resp == 0) && (t < CMDIF_CLIENT_TIMEOUT));
		if (t == CMDIF_CLIENT_TIMEOUT) {
			NADK_ERR(CMD, "cmdif_sync_ready reached "
				"timeout value");
			return -ETIMEDOUT;
		}
		err = cmdif_sync_cmd_done(cidesc);
		if (err) {
			NADK_ERR(CMD, "cmdif_sync_cmd_done failed with "
				"err code: %d", err);
			return err;
		}

	}

	return NADK_SUCCESS;
}

int cmdif_resp_read(struct cmdif_desc *cidesc, int priority)
{
	struct   cmdif_fd fd;
	int      err = 0, num_pkts;

	if (cidesc == NULL)
		return -EINVAL;

	num_pkts = receive_fd(&fd, priority, cidesc->regs);
	if (num_pkts < 0) {
		NADK_ERR(CMD, "Error calling receive_fd");
		return num_pkts;
	}
	while (num_pkts > 0) {
		err = cmdif_async_cb(&fd);
		if (err) {
			NADK_ERR(CMD, "Error calling cmdif_async_cb");
			return err;
		}
		num_pkts = receive_fd(&fd, priority, cidesc->regs);
		if (num_pkts < 0) {
			NADK_ERR(CMD, "Error calling receive_fd");
			return num_pkts;
		}
	}
	return NADK_SUCCESS;
}
