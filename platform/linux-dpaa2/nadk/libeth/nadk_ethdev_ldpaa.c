/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	nadk_ethdev.c
 *
 * @brief	Ethernet Configuration APIs implementation. It contains API for
 *		runtime configuration for NADK Ethernet devices.
 *
 * @addtogroup	NADK_ETH
 * @ingroup	NADK_DEV
 * @{
 */

#include <nadk_dev.h>
#include <nadk_dev_priv.h>
#include <nadk_ethdev.h>
#include <nadk_eth_priv.h>
#include <nadk_io_portal_priv.h>
#include <nadk_ether.h>
#include <nadk_ethdev_priv_ldpaa.h>
#include <nadk_common.h>
#include <nadk_mpool.h>
#include <nadk_memzone.h>
#include <nadk_memconfig.h>
#include <odp/hints.h>

/*MC header files*/
#include <fsl_dpni.h>
#include <fsl_dpkg.h>

#define ENABLE 1
#define DISABLE 0


/* Size of the input SMMU mapped memory required by MC */
#define DIST_PARAM_IOVA_SIZE 256

struct queues_config *nadk_eth_get_queues_config(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_eth_priv *eth_priv = dev_priv->drv_priv;

	return &(eth_priv->q_config);
}

int nadk_eth_mtu_set(struct nadk_dev *dev,
			uint16_t mtu)
{
	int ret;
	struct dpni_attr attr;
	struct nadk_dev_priv *dev_priv;
	struct nadk_eth_priv *eth_priv;
	struct fsl_mc_io *dpni;
	struct dpni_extended_cfg *ext_cfg;

	if (dev == NULL)
		return NADK_FAILURE;
	dev_priv = dev->priv;
	if (dev_priv == NULL)
		return NADK_FAILURE;
	eth_priv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (eth_priv == NULL)
		return NADK_FAILURE;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return NADK_FAILURE;

	/* Following memory allocation is required to avoid SMMU fault */
	ext_cfg = nadk_data_malloc(NULL, 256, ODP_CACHE_LINE_SIZE);
	if (!ext_cfg) {
		NADK_ERR(ETH, "Memory allocation failed for ext_cfg\n");
		return NADK_FAILURE;
	}
	attr.ext_cfg_iova = (uint64_t)(NADK_VADDR_TO_IOVA(ext_cfg));

	ret = dpni_get_attributes(dpni, CMD_PRI_LOW, dev_priv->token, &attr);
	/* Free the unused memory first as return value
	   of above function may be ERROR */
	nadk_data_free(ext_cfg);
	if (ret) {
		NADK_ERR(ETH, "DPNI get attribute failed: Error Code = %0x\n",
								ret);
		return NADK_FAILURE;
	}
	/* Set the Max Rx frame length as 'mtu' +
	 * Maximum Ethernet header length */
	ret = dpni_set_max_frame_length(dpni, CMD_PRI_LOW, dev_priv->token,
			mtu + ETH_VLAN_HLEN);
	if (ret) {
		NADK_ERR(ETH, "setting the max frame length failed");
		return NADK_FAILURE;
	}
	if (attr.options & DPNI_OPT_IPF) {
		ret = dpni_set_mtu(dpni, CMD_PRI_LOW, dev_priv->token, mtu);
		if (ret) {
			NADK_ERR(ETH, "Setting the MTU failed");
			return NADK_FAILURE;
		}
	}
	eth_priv->cfg.mtu = mtu;
	NADK_NOTE(ETH, "MTU set as %d for the %s", mtu, dev->dev_string);
	return NADK_SUCCESS;
}

uint16_t nadk_eth_mtu_get(struct nadk_dev *dev)
{
	uint16_t mtu = 0;
	struct nadk_dev_priv *dev_priv;
	struct nadk_eth_priv *eth_priv;

	if (dev == NULL)
		return mtu;

	dev_priv = dev->priv;
	if (dev_priv == NULL)
		return mtu;
	eth_priv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (eth_priv == NULL)
		return mtu;

	return eth_priv->cfg.mtu;
}

void nadk_eth_set_buf_headroom(ODP_UNUSED struct nadk_dev *dev,
			       ODP_UNUSED uint32_t headroom)
{
	NADK_NOTE(ETH, "Headroom is configured %d for the device", headroom);
	NADK_NOTE(ETH, "Not Implemented");
	return;
}

void nadk_eth_promiscuous_enable(ODP_UNUSED struct nadk_dev *dev)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		NADK_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		NADK_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, ENABLE);
	if (ret < 0)
		NADK_ERR(ETH, "Unable to enable promiscuous mode");
	epriv->cfg.hw_features |= NADK_PROMISCUOUS_ENABLE;
	return;
}

void nadk_eth_promiscuous_disable(struct nadk_dev *dev)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		NADK_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		NADK_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_unicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, DISABLE);
	if (ret < 0)
		NADK_ERR(ETH, "Unable to disable promiscuous mode");

	epriv->cfg.hw_features &= ~NADK_PROMISCUOUS_ENABLE;
	return;
}

int nadk_eth_promiscuous_get(struct nadk_dev *dev)
{
	struct nadk_dev_priv *priv;
	struct nadk_eth_priv *epriv;
	priv = (struct nadk_dev_priv *)(dev->priv);
	epriv = (struct nadk_eth_priv *)(priv->drv_priv);

	return BIT_ISSET_AT_POS(epriv->cfg.hw_features, NADK_PROMISCUOUS_ENABLE);
}

void nadk_eth_multicast_enable(struct nadk_dev *dev)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		NADK_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		NADK_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, ENABLE);
	if (ret < 0)
		NADK_ERR(ETH, "Unable to enable multicast mode");
	epriv->cfg.hw_features |= NADK_MULTICAST_ENABLE;
	return;
}


void nadk_eth_multicast_disable(struct nadk_dev *dev)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	if (dev_priv == NULL) {
		NADK_ERR(ETH, "dev_priv is NULL");
		return;
	}

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL) {
		NADK_ERR(ETH, "dpni is NULL");
		return;
	}

	ret = dpni_set_multicast_promisc(dpni, CMD_PRI_LOW, dev_priv->token, DISABLE);
	if (ret < 0)
		NADK_ERR(ETH, "Unable to disable multicast mode");
	epriv->cfg.hw_features &= ~NADK_MULTICAST_ENABLE;
	return;
}



void nadk_eth_offload_cheksum(ODP_UNUSED struct nadk_dev *dev,
			      ODP_UNUSED uint8_t en_rx_checksum,
				ODP_UNUSED uint8_t en_tx_checksum)
{
	NADK_NOTE(ETH, "Not Implemented");
	return;
}

int32_t nadk_eth_set_mac_addr(struct nadk_dev *dev,
			uint8_t *addr)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	if (dev_priv == NULL)
		return NADK_FAILURE;

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return NADK_FAILURE;

	ret = dpni_set_primary_mac_addr(dpni, CMD_PRI_LOW, dev_priv->token, addr);

	if (ret == 0)
		return NADK_SUCCESS;
	else
		return NADK_FAILURE;
}

int32_t nadk_eth_get_mac_addr(struct nadk_dev *dev,
			uint8_t *addr)
{
	int ret;
	struct nadk_dev_priv *dev_priv = dev->priv;
	if (dev_priv == NULL)
		return NADK_FAILURE;

	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	if (dpni == NULL)
		return NADK_FAILURE;

	ret = dpni_get_primary_mac_addr(dpni, CMD_PRI_LOW, dev_priv->token, addr);

	if (ret == 0)
		return NADK_SUCCESS;
	else
		return NADK_FAILURE;
}

void nadk_eth_get_link_info(struct nadk_dev *dev ODP_UNUSED,
				int32_t wait_to_complete ODP_UNUSED,
				struct nadk_eth_link *link_info)
{

	link_info->link_speed = ETH_LINK_SPEED_AUTONEG;
	link_info->link_duplex = ETH_LINK_FULL_DUPLEX;
	link_info->link_status = 1;

	NADK_NOTE(ETH, "Not Implemented");
	return;
}

int32_t nadk_eth_setup_flow_distribution(struct nadk_dev *dev,
		uint32_t req_dist_set,
		uint8_t tc_index,
		uint16_t dist_size)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = dev_priv->hw;
	struct nadk_eth_priv *eth_priv = dev_priv->drv_priv;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	struct queues_config *q_config = &(eth_priv->q_config);
	void_t *p_params;
	int ret;

	if (dist_size > q_config->tc_config[tc_index].num_dist) {
		NADK_ERR(BUF, "Dist size greater than num_dist %d > %d",
			dist_size, q_config->tc_config[tc_index].num_dist);
		return -EINVAL;
	}
	p_params = nadk_data_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!p_params) {
		NADK_ERR(BUF, "Memory unavaialble");
		return -ENOMEM;
	}
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));

	nadk_distset_to_dpkg_profile_cfg(req_dist_set, &kg_cfg);
	tc_cfg.key_cfg_iova = (uint64_t)(NADK_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = dist_size;
	tc_cfg.dist_mode = DPNI_DIST_MODE_HASH;
	q_config->tc_config[tc_index].num_dist_used = dist_size;

	if (dpni_prepare_key_cfg(&kg_cfg, p_params))
		NADK_WARN(BUF, "Unable to prepare extract parameters");

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token, tc_index,
		&tc_cfg);
	nadk_data_free(p_params);
	if (ret) {
		NADK_ERR(ETH, "Setting distribution for Rx failed with"
			"err code: %d", ret);
		return ret;
	}

	q_config->tc_config[tc_index].dist_type = NADK_ETH_FLOW_DIST;

	return NADK_SUCCESS;
}

void nadk_eth_remove_flow_distribution(struct nadk_dev *dev,
		uint8_t tc_index)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct nadk_eth_priv *eth_priv = dev_priv->drv_priv;
	struct dpni_rx_tc_dist_cfg tc_cfg;
	struct dpkg_profile_cfg kg_cfg;
	struct queues_config *q_config;
	void_t *p_params;
	int ret;

	p_params = nadk_data_malloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!p_params) {
		NADK_ERR(BUF, "Memory unavaialble");
		return;
	}
	memset(&kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	memset(&tc_cfg, 0, sizeof(struct dpni_rx_tc_dist_cfg));
	memset(p_params, 0, DIST_PARAM_IOVA_SIZE);

	q_config = &(eth_priv->q_config);
	tc_cfg.key_cfg_iova = (uint64_t)(NADK_VADDR_TO_IOVA(p_params));
	tc_cfg.dist_size = 0;
	tc_cfg.dist_mode = DPNI_DIST_MODE_NONE;

	if (dpni_prepare_key_cfg(&kg_cfg, p_params))
		NADK_WARN(BUF, "Unable to prepare extract parameters");

	ret = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token, tc_index,
		&tc_cfg);
	nadk_data_free(p_params);
	if (ret)
		NADK_ERR(ETH, "Unsetting distribution for Rx failed with"
			"err code: %d", ret);
	else
		q_config->tc_config[tc_index].dist_type = NADK_ETH_NO_DIST;

}

int nadk_eth_timestamp_enable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = TRUE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Enabling timestamp for Rx failed with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Enabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Enabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return NADK_SUCCESS;
}

int nadk_eth_timestamp_disable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct dpni_buffer_layout layout;
	int ret;

	layout.options = DPNI_BUF_LAYOUT_OPT_TIMESTAMP;
	layout.pass_timestamp = FALSE;

	ret = dpni_set_rx_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Disabling timestamp failed for Rx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_tx_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Disabling timestamp failed for Tx with"
			"err code: %d", ret);
		return ret;
	}
	ret = dpni_set_tx_conf_buffer_layout(dpni, CMD_PRI_LOW, dev_priv->token, &layout);
	if (ret) {
		NADK_ERR(ETH, "Disabling timestamp failed for Tx-conf with"
			"err code: %d", ret);
		return ret;
	}

	return NADK_SUCCESS;
}

int nadk_eth_frag_enable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	int ret;

	ret = dpni_set_ipf(dpni, CMD_PRI_LOW, dev_priv->token, 1);
	if (ret != 0) {
		NADK_ERR(ETH, "Enabling Ethernet device fragmentation "
			"feature failed with retcode: %d", ret);
		return ret;
	}
	epriv->cfg.hw_features |= NADK_FRAG_ENABLE;

	return NADK_SUCCESS;
}

int nadk_eth_frag_disable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	int ret;

	ret = dpni_set_ipf(dpni, CMD_PRI_LOW, dev_priv->token, 0);
	if (ret != 0) {
		NADK_ERR(ETH, "Disabling Ethernet device fragmentation "
			"feature failed with retcode: %d", ret);
		return ret;
	}
	epriv->cfg.hw_features &= ~NADK_FRAG_ENABLE;

	return NADK_SUCCESS;
}

int nadk_eth_reassembly_enable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	int ret;

	ret = dpni_set_ipr(dpni, CMD_PRI_LOW, dev_priv->token, 1);
	if (ret != 0) {
		NADK_ERR(ETH, "Enabling Ethernet device reassembly "
			"feature failed with retcode: %d", ret);
		return ret;
	}
	epriv->cfg.hw_features |= NADK_REASSEMBLY_ENABLE;

	return NADK_SUCCESS;
}

int nadk_eth_reassembly_disable(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct fsl_mc_io *dpni = (struct fsl_mc_io *)(dev_priv->hw);
	struct nadk_eth_priv *epriv = (struct nadk_eth_priv *)(dev_priv->drv_priv);
	int ret;

	ret = dpni_set_ipr(dpni, CMD_PRI_LOW, dev_priv->token, 0);
	if (ret != 0) {
		NADK_ERR(ETH, "Disabling Ethernet device reassembly "
			"feature failed with retcode: %d", ret);
		return ret;
	}
	epriv->cfg.hw_features &= ~NADK_REASSEMBLY_ENABLE;

	return NADK_SUCCESS;
}

/*! @} */
