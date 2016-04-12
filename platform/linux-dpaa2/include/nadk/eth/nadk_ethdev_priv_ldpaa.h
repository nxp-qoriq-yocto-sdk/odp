/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	nadk_ethdev_priv_ldpaa.h
 *
 * @brief	Private API's required by Ethernet Configuration APIs implementation.
 *
 * @addtogroup	NADK_ETH
 * @ingroup	NADK_DEV
 * @{
 */

#include <nadk_ethdev.h>

/*MC header files*/
#include <fsl_dpkg.h>

/*!
 * @details	This API converts the req_dist_set, which is set by the user
 *		of this API to the MC's understandable form (dpkg_profile_cfg).
 *
 * @param[in]	req_dist_set - The distribution set on which the hashi
 *		distibution is to be configured.
 *
 * @param[out]	kg_cfg - The dpkg_profile_cfg corresponding to req_dist_set
 *
 * @returns	none
 *
 */
void nadk_distset_to_dpkg_profile_cfg(
		uint32_t req_dist_set,
		struct dpkg_profile_cfg *kg_cfg);

/*! @} */
