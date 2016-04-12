/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdio.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <poll.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <stdlib.h>

#include <linux/ethtool.h>
#include <linux/sockios.h>

#include <odp/hints.h>
#include <odp/thread.h>
#include <odp_debug_internal.h>
#include <odp_packet_nadk.h>
#include <nadk.h>
#include <nadk_dev.h>
#include <nadk_dev_priv.h>
#include <nadk_ethdev.h>


int setup_pkt_nadk(pkt_nadk_t * const pkt_nadk ODP_UNUSED, void *dev,
							odp_pool_t pool)
{
	uint32_t max_rx_vq;
	int i, ret;
	struct nadk_dev *netdev = (struct nadk_dev *)dev;
	pool_entry_t *phandle = (pool_entry_t *)pool;
	struct nadk_dev_priv *dev_priv = netdev->priv;

	ODP_DBG("setup_pkt_nadk\n");

	if (dev_priv->bp_list) {
		ODP_ERR("Already setuped\n");
		return -1;
	}

	/* Get Max available RX & TX VQs for this device */
	NADK_NOTE(APP1, "port =>  %s being created",
		netdev->dev_string);

	/* Get Max available RX & TX VQs for this device */
	max_rx_vq = nadk_dev_get_max_rx_vq(netdev);
	if (max_rx_vq < 1) {
		ODP_ERR("Not enough Resource to run\n");
		goto fail_nadkstart;
	}
	/* Add RX Virtual queues to this device */
	i = 0;
	{
		NADK_NOTE(APP1, "setup FQ %d", i);
		ret = nadk_dev_setup_rx_vq(netdev, i, NULL);
		if (NADK_FAILURE == ret) {
			NADK_ERR(APP1,
				"Fail to configure RX VQs\n");
			goto fail_nadkstart;
		}
	}

	ret = nadk_eth_attach_bp_list(netdev, (void *)(phandle->s.int_hdl));
	if (NADK_FAILURE == ret) {
		ODP_ERR("Failure to attach buffers to the"
						"Ethernet device\n");
		goto fail_nadkstart;
	}

	return 0;

fail_nadkstart:
	return -1;
}

int32_t cleanup_pkt_nadk(pkt_nadk_t *const pkt_nadk)
{
	struct nadk_dev *net_dev;
	struct nadk_dev_priv *dev_priv;
	int ret;

	net_dev = pkt_nadk->dev;
	dev_priv = (struct nadk_dev_priv *)net_dev->priv;
	dev_priv->bp_list = NULL;
	ret = nadk_eth_reset(net_dev);
	if (ret)
		ODP_ERR("Failure to reset the device\n");

	return ret;
}

int start_pkt_nadk(pkt_nadk_t *const pkt_nadk)
{
	uint32_t max_tx_vq;
	int ret;
	struct nadk_dev *netdev = pkt_nadk->dev;
	max_tx_vq = nadk_dev_get_max_tx_vq(netdev);
	if (max_tx_vq < 1) {
		ODP_ERR("Not enough Resource to run\n");
		return -1;
	}
	ret = nadk_dev_start(netdev);
	if (NADK_FAILURE == ret) {
		ODP_ERR("Not enough Resource to run\n");
		return -1;
	}
	/*Error handling is not done as a workaround of failure of
	  below API after CTRL+C*/
	nadk_dev_setup_tx_vq(netdev, max_tx_vq, NADKBUF_TX_NO_ACTION);
	return 0;
}

int close_pkt_nadk(pkt_nadk_t *const pkt_nadk)
{
	struct nadk_dev *net_dev;
	int ret;

	net_dev = pkt_nadk->dev;
	ret = nadk_dev_stop(net_dev);
	if (NADK_FAILURE == ret) {
		ODP_ERR("Unable to stop device\n");
		return -1;
	}

	ODP_DBG("close pkt_nadk, %u\n", pkt_nadk->portid);

	return 0;
}
