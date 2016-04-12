/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	nadk_ethdev_priv_ldpaa.c
 *
 * @brief	Private API's required by Ethernet Configuration APIs implementation.
 *
 * @addtogroup	NADK_ETH
 * @ingroup	NADK_DEV
 * @{
 */

#include <nadk_ethdev.h>
#include <nadk_ethdev_priv_ldpaa.h>

/*MC header files*/
#include <fsl_dpkg.h>

void nadk_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg)
{
	uint32_t loop = 0, i = 0, dist_field = 0;

	memset(kg_cfg, 0, sizeof(struct dpkg_profile_cfg));
	while (req_dist_set) {
		NADK_DBG(ETH, "req_dist_set: %x", req_dist_set);
		if (req_dist_set%2 != 0) {
			dist_field = 1U << loop;
			switch (dist_field) {
			case NADK_FDIST_L2_SA:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_ETH;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_ETH_SA;
				break;
			case NADK_FDIST_L2_DA:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_ETH;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_ETH_DA;
				break;
			case NADK_FDIST_L2_VID:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_VLAN;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_VLAN_VID;
				break;
			case NADK_FDIST_IP_SA:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_SRC;
				break;
			case NADK_FDIST_IP_DA:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_DST;
				break;
			case NADK_FDIST_IP_PROTO:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_IP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_IP_PROTO;
				break;
			case NADK_FDIST_TCP_SP:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_SRC;
				break;
			case NADK_FDIST_TCP_DP:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_TCP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_TCP_PORT_DST;
				break;
			case NADK_FDIST_UDP_SP:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_UDP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_UDP_PORT_SRC;
				break;
			case NADK_FDIST_UDP_DP:
				kg_cfg->extracts[i].extract.from_hdr.prot =
					NET_PROT_UDP;
				kg_cfg->extracts[i].extract.from_hdr.field =
					NH_FLD_UDP_PORT_DST;
				break;
			default:
				NADK_ERR(ETH, "Bad flow distribution option");
			}
			kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
			kg_cfg->extracts[i].extract.from_hdr.type =
				DPKG_FULL_FIELD;
			kg_cfg->num_extracts++;
			i++;
		}
		req_dist_set = req_dist_set>>1;
		loop++;
	}
}

/*! @} */
