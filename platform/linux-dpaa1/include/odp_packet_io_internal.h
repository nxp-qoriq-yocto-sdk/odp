/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_INTERNAL_H_
#define ODP_PACKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/spinlock.h>
#include <odp/classification.h>
#include <odp_classification_internal.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/fman.h>
#include <usdpaa/usdpaa_netcfg.h>

#include "configs/odp_config_platform.h"

extern struct usdpaa_netcfg_info *netcfg;
extern void *pktio_entry_ptr[];

struct pktio_entry {
	odp_spinlock_t lock;		/**< entry spinlock */
	int taken;			/**< is entry taken(1) or free(0) */
	odp_queue_t inq_default;	/**< default input queue, if set */
	odp_queue_t outq_default;	/**< default out queue */
	struct fman_if *__if;		/**< FMAN interface backing this entry */
	int promisc;			/**< 1/0 - promisc enabled/dsiabled */
	struct fman_if_ic_params icp;	/**< FMAN interface IC params */
	uint32_t pcd_fqid;		/**< PCD fqid on which frames are received */
	struct qman_fq rx_fq;		/**< QMAN Rx frame queue */
	struct qman_fq tx_fq;
	odp_pktio_t id;			/**< Entry id */
	odp_pool_t pool;
	odp_packet_t *pkt_table;	/**< Packet table to receive in burst mode.
					     Passed by odp_pktio_recv */
	odp_cos_t default_cos;		/**<default class of service */
	odp_cos_t error_cos;		/**<error class of service */
	struct list_head def_cos_node; /**<pktio entry in default cos list */
	struct list_head err_cos_node; /**<pktio entry in error cos list */
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

/* per-port information associated with pktio devices */
typedef struct {
	/* buffer pools */
	struct fman_if_bpool bpool[MAX_PORT_BPOOLS];
	struct fm_eth_port_cfg *p_cfg;
	/* first fqid available for pktio */
	uint32_t last_fqid;
	/* current number of configured buffer pools */
	unsigned bp_num;
        uint8_t scheme_count;

        t_Handle fman_handle;
        t_Handle pcd_handle;
        t_Handle port_handle;
        t_Handle net_env_set;
        t_Handle tree_handle;
        t_FmPortPcdParams pcd_param;
        t_FmPortPcdPrsParams prs_param;
        t_FmPortPcdKgParams  kg_param;
        t_FmPcdNetEnvParams dist_units;
        struct scheme_info scheme[FMC_SCHEMES_NUM];
        int cc_root[CCTREE_MAX_GROUPS];
        odp_spinlock_t lock;
        struct list_head scheme_list, pmr_list, pmr_set_list;
        struct scheme_info *l2_vpri, *l3_dscp;
        bool l3_precedence;
        bool config_pcd; /**< mark if the pcd was configured for this port */

} netcfg_port_info;

#define PKTIO_ENTRY_FROM_FQ(fq)	\
	((struct pktio_entry *)container_of(fq, struct pktio_entry, rx_fq))


netcfg_port_info  *pktio_get_port_info(struct fman_if *__if);

enum qman_cb_dqrr_result dqrr_cb_qm(struct qman_portal *qm __always_unused,
				    struct qman_fq *fq,
				    const struct qm_dqrr_entry *dqrr);

static inline int pktio_to_id(odp_pktio_t pktio)
{
        return _odp_typeval(pktio) - 1;
}

static inline pktio_entry_t *get_pktio_entry(odp_pktio_t pktio)
{
        if (odp_unlikely(pktio == ODP_PKTIO_INVALID))
                return NULL;

        if (odp_unlikely(_odp_typeval(pktio) > ODP_CONFIG_PKTIO_ENTRIES)) {
                ODP_DBG("pktio limit %d/%d exceed\n",
                        _odp_typeval(pktio), ODP_CONFIG_PKTIO_ENTRIES);
                return NULL;
        }

        return pktio_entry_ptr[pktio_to_id(pktio)];
}

#ifdef __cplusplus
}
#endif

#endif
