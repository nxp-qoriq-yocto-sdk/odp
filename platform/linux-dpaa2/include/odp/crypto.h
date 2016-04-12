/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP crypto
 */

#ifndef ODP_PLAT_CRYPTO_H_
#define ODP_PLAT_CRYPTO_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/buffer.h>
#include <odp/pool.h>
#include <odp/queue.h>
#include <odp/packet.h>

#include <odp/plat/crypto_types.h>
#include <odp/plat/crypto_pdcp_types.h>
#include <odp/plat/crypto_ipsec_types.h>
/** @ingroup odp_crypto
 *  @{
 */

/**
 * @}
 */

#include <odp/api/crypto.h>
#include <odp/api/crypto_ipsec.h>
#include <odp/api/crypto_pdcp.h>

#ifdef __cplusplus
}
#endif

#endif
