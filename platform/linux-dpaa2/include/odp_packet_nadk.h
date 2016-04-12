/* Copyright (c) 2013, Linaro Limited
 * Copyright (c) 2015, Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#ifndef ODP_PACKET_NADK_H
#define ODP_PACKET_NADK_H

#include <stdint.h>
#include <net/if.h>

#include <odp/align.h>
#include <odp/debug.h>
#include <odp/packet.h>

#include <odp_packet_internal.h>
#include <odp/pool.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>

/*NADK header files */
#include <nadk/common/nadk_common.h>
#include <odp/hints.h>
#include <nadk/common/nadk_cfg.h>
#include <odp/std_types.h>
#include <nadk/rts/nadk_malloc.h>
#include <nadk/core/nadk_dev.h>


#define ODP_NADK_MODE_HW	0
#define ODP_NADK_MODE_SW	1

#define NADK_BLOCKING_IO

#define MAX_PKT_BURST 1

#define BURST_TX_DRAIN_US 100 /* TX drain every ~100us */

/** Packet socket using nadk mmaped rings for both Rx and Tx */
typedef struct {
	odp_pool_t pool;

	/********************************/
	char ifname[32];
	uint8_t portid;
	uint16_t queueid;
	struct nadk_dev *dev;
} pkt_nadk_t;

/**
  * externel API to transmit the packet on fqid
  * API added to test the ODP queue's test cases
  */
int32_t nadk_eth_xmit_fqid(void *vq, uint32_t num,
				nadk_mbuf_pt buf[]);

int32_t nadk_eth_xmit(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);

/**
 * Configure an interface to work in nadk mode
 */
int setup_pkt_nadk(pkt_nadk_t * const pkt_nadk, void *netdev,
					odp_pool_t pool);
/**
 * Switch interface from nadk mode to normal mode
 */
int32_t cleanup_pkt_nadk(pkt_nadk_t *const pkt_nadk);

int start_pkt_nadk(pkt_nadk_t * const pkt_nadk);

int close_pkt_nadk(pkt_nadk_t * const pkt_nadk);

#endif
