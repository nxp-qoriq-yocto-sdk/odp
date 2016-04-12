/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_eth_ldpaa_qbman.h
 * @description	Structure & MACRO definitions to support qbman procesing.
 */

#ifndef _NADK_ETH_LDPAA_QBMAN_H_
#define _NADK_ETH_LDPAA_QBMAN_H_

#include <nadk_memconfig.h>

static inline void nadk_qbman_pull_desc_channel_set(
		struct qbman_pull_desc *pulldesc,
		uint32_t num,
		uint16_t ch_id,
		struct qbman_result *dq_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_channel(pulldesc, ch_id,
		qbman_pull_type_active_noics);
	qbman_pull_desc_set_storage(pulldesc, dq_storage,
		(dma_addr_t)(NADK_VADDR_TO_IOVA(dq_storage)), TRUE);
}

static inline void nadk_qbman_pull_desc_set(
		struct qbman_pull_desc *pulldesc,
		uint32_t num,
		uint32_t fqid,
		struct qbman_result *dq_storage)
{
	qbman_pull_desc_clear(pulldesc);
	qbman_pull_desc_set_numframes(pulldesc, num);
	qbman_pull_desc_set_fq(pulldesc, fqid);
	qbman_pull_desc_set_storage(pulldesc, dq_storage,
		(dma_addr_t)(NADK_VADDR_TO_IOVA(dq_storage)), TRUE);
}

#endif /*_NADK_ETH_LDPAA_QBMAN_H_*/
