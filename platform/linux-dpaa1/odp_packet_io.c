/* Copyright (c) 2014, Linaro Limited
 * Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/packet_io.h>
#include <odp/packet.h>
#include <odp_internal.h>
#include <odp/spinlock.h>
#include <odp/shared_memory.h>
#include <odp/hints.h>
#include <odp/config.h>
#include <odp/debug.h>
#include <odp/thread.h>
#include <odp/system_info.h>

#include <odp_queue_internal.h>
#include <odp_pool_internal.h>
#include <odp_schedule_internal.h>
#include <odp_packet_internal.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>

#include <configs/odp_config_platform.h>
#include <usdpaa/fsl_usd.h>
#include <usdpaa/of.h>
#include <usdpaa/fsl_qman.h>
#include <usdpaa/usdpaa_netcfg.h>

#include <string.h>
#include <assert.h>

/* Per-thread transmit frame queue */
static __thread struct qman_fq local_fq;

/* Direct receive pool channel */
static u32 sdqcr_vdq, pchannel_vdq;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

/* MTU to be reported for the "loop" interface */
#define PKTIO_LOOP_MTU 1500

/* MAC address for the "loop" interface */
static const char pktio_loop_mac[] = {0x02, 0xe9, 0x34, 0x80, 0x73, 0x01};

/* Get fman_if from shared mac interface name */
static inline struct fman_if
*get_fman_if_byshmac(const char *dev)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if->shared_mac_info.is_shared_mac &&
		    port_cfg->fman_if->shared_mac_info.shared_mac_name &&
		    !strcmp(port_cfg->fman_if->shared_mac_info.shared_mac_name,
			   dev))
			return port_cfg->fman_if;
	}
	return NULL;
}

/* Get fman_if from port name (fman index, port type/index */
static inline struct fman_if
*get_fman_if_byname(const char *dev)
{
	char *cp;
	const char delim[] = "-";
	char *fm, *port, *end;
	int fm_idx = -1, port_idx = -1;
	int i;
	enum fman_mac_type mac_type = fman_offline;
	struct fm_eth_port_cfg *port_cfg;
	struct fman_if_ic_params icp;

	if (strcmp(dev, "loop") == 0) {
		for (i = 0; i < netcfg->num_ethports; i++) {
			port_cfg = &netcfg->port_cfg[i];
			if (port_cfg->fman_if->mac_type == fman_offline) {
				memset(&icp, 0, sizeof(icp));
				/* set ICEOF for O/H port to the default value */
				icp.iceof = DEFAULT_ICEOF;
				fman_if_set_ic_params(port_cfg->fman_if, &icp);
				if (fman_ip_rev >= FMAN_V3)
					fman_if_set_dnia(port_cfg->fman_if,
							 OH_DEQ_NIA);
				return port_cfg->fman_if;
			}
		}

		return NULL;
	}

	cp = strdup(dev);
	if (!cp)
		return NULL;
	fm = strsep(&cp, delim);
	port = strsep(&cp, delim);
	end = strsep(&cp, delim);

	if (fm && port && !end) {
		if (!strncmp(fm, "fm", 2) && isdigit(fm[2]) &&
		    fm[3] == '\0')
			fm_idx = fm[2] - '0';
		if (!strncmp(port, "mac", 3) && isdigit(port[3]) &&
		    port[4] == '\0') {
			port_idx = port[3] - '0';
			if (port_idx >= 9) {
				mac_type = fman_mac_10g;
			} else {
				mac_type = fman_mac_1g;
			}
		}
		/* Support for fmx-mac10 interface */
		if (!strncmp(port, "mac", 3) && isdigit(port[4]) &&
		    port[5] == '\0') {
			port_idx = 10;
			mac_type = fman_mac_10g;
		}
		if (!strncmp(port, "oh", 2) && isdigit(port[2]) &&
		    port[3] == '\0') {
			port_idx = port[2] - '0';
			mac_type = fman_offline;
		}
	}
	if (fm_idx < 0 || port_idx < 0)
		return NULL;
	free(cp);
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if->fman_idx == fm_idx &&
		    port_cfg->fman_if->mac_idx == port_idx &&
		    port_cfg->fman_if->mac_type == mac_type)
			return port_cfg->fman_if;
	}

	return NULL;
}

/* Get port configuration from fman_if */
static inline struct fm_eth_port_cfg
*get_port_cfg_byif(struct fman_if *__if)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;
	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = &netcfg->port_cfg[i];
		if (port_cfg->fman_if == __if)
			return port_cfg;
	}
	return NULL;
}

/* Get first PCD range start fqid */
static inline uint32_t
get_pcd_start_fqid(struct fm_eth_port_cfg *p_cfg)
{
	struct fm_eth_port_fqrange *fqr;
	/* only first range */
	list_for_each_entry(fqr, p_cfg->list, list)
		return fqr->start;
	return 0;
}

/* Get fqids number of first PCD range*/
static inline uint32_t
get_pcd_count(struct fm_eth_port_cfg *p_cfg)
{
	struct fm_eth_port_fqrange *fqr;
	list_for_each_entry(fqr, p_cfg->list, list)
		return fqr->count;
	return 0;
}

/* Find buffer pool in the current configured port pool */
static inline bool
fman_if_find_bpid(struct fman_if *__if, uint32_t bpid)
{
	bool found = false;
	struct fman_if_bpool *bp;
	list_for_each_entry(bp, &__if->bpool_list, node) {
		if (bp->bpid == bpid) {
			found = true;
			break;
		}
	}
	return found;
}

typedef struct {
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
	netcfg_port_info port_info[];
} pktio_table_t;

static pktio_table_t *pktio_tbl;

netcfg_port_info  *pktio_get_port_info(struct fman_if *__if)
{
	int i;
	struct fm_eth_port_cfg *port_cfg;

	for (i = 0; i < netcfg->num_ethports; i++) {
		port_cfg = pktio_tbl->port_info[i].p_cfg;
		if (port_cfg->fman_if == __if)
			break;
	}

	return	&pktio_tbl->port_info[i];
}

static int is_free(pktio_entry_t *entry)
{
	return (entry->s.taken == 0);
}

static void set_free(pktio_entry_t *entry)
{
	entry->s.taken = 0;
}

static void set_taken(pktio_entry_t *entry)
{
	entry->s.taken = 1;
}
static void lock_entry(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
}

static void unlock_entry(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.lock);
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	entry->s.outq_default = ODP_QUEUE_INVALID;
	entry->s.default_cos = ODP_COS_INVALID;
	entry->s.error_cos = ODP_COS_INVALID;
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				entry->s.id = id;
				return id; /* return with entry locked! */
			}
			unlock_entry(entry);
		}
	}

	return ODP_PKTIO_INVALID;
}

static int free_pktio_entry(odp_pktio_t id)
{
	pktio_entry_t *entry = get_pktio_entry(id);

	if (entry == NULL)
		return -1;

	set_free(entry);

	return 0;
}

int odp_pktio_init_local(void)
{
	int ret;
	ret = qman_create_fq(1, QMAN_FQ_FLAG_NO_MODIFY, &local_fq);
	if (ret)
		ODP_ERR("odp_pktio_init_local failed (%d)\n", ret);
	local_fq.cb.ern = ern_cb;
	return ret;
}

void odp_pktio_term_local(void)
{
	qman_destroy_fq(&local_fq, 0);
}

int odp_pktio_init_global(void)
{
	pktio_entry_t *pktio_entry;
	int id, i, ret;
	struct fm_eth_port_cfg *p_cfg;
	odp_shm_t shm;
	shm = odp_shm_reserve("odp_pktio_entries",
			      sizeof(pktio_table_t) +
			      netcfg->num_ethports * sizeof(netcfg_port_info),
			      sizeof(pktio_entry_t), ODP_SHM_SW_ONLY);
	pktio_tbl = odp_shm_addr(shm);
	if (pktio_tbl == NULL)
		return -1;

	ret = qman_alloc_pool_range(&pchannel_vdq, 1, 1, 0);
	if (ret != 1)
		return -1;

	sdqcr_vdq = QM_SDQCR_CHANNELS_POOL_CONV(pchannel_vdq);



	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		pktio_entry_ptr[id - 1] = pktio_entry;
		odp_spinlock_init(&pktio_entry->s.lock);
	}

	/* copy ports configuration to pktio table */
	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];
		pktio_tbl->port_info[i].p_cfg = p_cfg;
		pktio_tbl->port_info[i].last_fqid = get_pcd_start_fqid(p_cfg);
	}

	/* reset bpool list for each port - we explicitly assign
	 buffer pools to ports when opening pktio devices  */
	struct fman_if_bpool *bp, *tmpbp;
	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];
		list_for_each_entry_safe(bp, tmpbp,
					 &p_cfg->fman_if->bpool_list, node){
			list_del(&bp->node);
			free(bp);
		}
	}

	return 0;
}

/* DQRR callback when pktio works in queue mode - static deq */
/* Handles PKTIN queues & PACKET buffer types */
enum qman_cb_dqrr_result dqrr_cb_qm(struct qman_portal *qm __always_unused,
					 struct qman_fq *fq,
					 const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	void *fd_addr;
	odp_buffer_hdr_t *buf_hdr;
	odp_buffer_t buf;
	odp_packet_hdr_t *pkthdr;
	odp_packet_t pkt;
	size_t off;

	fd = &dqrr->fd;
	pool  = get_pool_entry(fd->bpid);
	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);

	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);
	assert(!(dqrr->stat & QM_DQRR_STAT_UNSCHEDULED));
	assert(qentry->s.type == ODP_QUEUE_TYPE_PKTIN);
	assert(fd->offset == FD_DEFAULT_OFFSET);
	assert(pool->s.params.type == ODP_POOL_PACKET);

	/* get packet header from frame start address */
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
	off = fd->offset;
	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;

		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format as
		 * is provided by the HW to LE as expected by the LE CPUs,
		 * on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						       qm_sg_addr(&sgt[sgcnt]));
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		fd_addr = buf_hdr->addr[sgcnt];
	}


	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	buf = odp_hdr_to_buf(buf_hdr);

	assert(pkthdr->buf_hdr.addr[0] == ((void *)pkthdr + pool->s.buf_offset));

	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);

	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;

	odp_pktio_set_input(pkthdr, qentry->s.pktin);
	buf_set_input_queue(buf_hdr, queue_from_id(get_qid(qentry)));

	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);

	 return odp_sched_collect_pkt(pkthdr, pkt, dqrr, qentry);
}

static enum qman_cb_dqrr_result
dqrr_cb_poll_pktin(struct qman_portal *qm __always_unused,
		   struct qman_fq *fq,
		   const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	void *fd_addr;
	odp_buffer_t buf;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkthdr;
	odp_packet_t pkt;
	size_t off;

	fd = &dqrr->fd;
	pool = get_pool_entry(fd->bpid);

	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);
	assert(fd->offset == FD_DEFAULT_OFFSET);
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	off = fd->offset;
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);

	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;
#ifdef ODP_MULTI_POOL_SG_SUPPORT
		pool_entry_t	*pool_sg;
		odp_pool_t	pool_handle;
#endif
		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format
		 * as is provided by the HW to LE as expected by the
		 * LE CPUs, on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
#ifndef ODP_MULTI_POOL_SG_SUPPORT
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
#else
		pool_sg = get_pool_entry(sgt->bpid);
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool_sg);

		pool_handle = pool_index_to_handle(sgt->bpid);
		buf_hdr->sg_pool_hdl[0] = pool_handle;
#endif
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						       qm_sg_addr(&sgt[sgcnt]));
#ifdef ODP_MULTI_POOL_SG_SUPPORT
			pool_handle = pool_index_to_handle(sgt[sgcnt].bpid);
			buf_hdr->sg_pool_hdl[sgcnt] = pool_handle;
#endif
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		fd_addr = buf_hdr->addr[sgcnt];
	}
	buf = odp_hdr_to_buf(buf_hdr);

	queue_entry_t *qentry = QENTRY_FROM_FQ(fq);
	pktio_entry_t *pktio_entry = get_pktio_entry(qentry->s.pktin);
#ifndef ODP_MULTI_POOL_SG_SUPPORT
	assert((pool == odp_pool_to_entry(pktio_entry->s.pool) &&
		pktio_entry->s.__if->mac_type != fman_offline) ||
	       (pool != odp_pool_to_entry(pktio_entry->s.pool) &&
                 pktio_entry->s.__if->mac_type == fman_offline));
#endif
	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;
	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);
	odp_pktio_set_input(pkthdr, pktio_entry->s.id);
	odp_queue_set_input(_odp_packet_to_buffer(pkt), ODP_QUEUE_INVALID);
	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);

	if (pktio_entry->s.pkt_table) {
		assert(dqrr->stat & QM_DQRR_STAT_UNSCHEDULED);
		*(pktio_entry->s.pkt_table) = pkt;
		(pktio_entry->s.pkt_table)++;
	}
	return qman_cb_dqrr_consume;
}

/* DQRR callback when pktio works in direct receive mode - volatile deq */
static enum qman_cb_dqrr_result
dqrr_cb_im(struct qman_portal *qm __always_unused,
	   struct qman_fq *fq,
	   const struct qm_dqrr_entry *dqrr)
{
	const struct qm_fd *fd;
	struct qm_sg_entry *sgt;
	pool_entry_t *pool;
	odp_buffer_hdr_t *buf_hdr;
	odp_packet_hdr_t *pkthdr;
	odp_buffer_t buf;
	odp_packet_t pkt;
	void *fd_addr;
	size_t off;

	fd = &dqrr->fd;
	pool = get_pool_entry(fd->bpid);

	assert(dqrr->stat & QM_DQRR_STAT_FD_VALID);
	assert(fd->offset == FD_DEFAULT_OFFSET);

	/* get packet header from frame start address */
	fd_addr = __dma_mem_ptov(qm_fd_addr(fd));
	buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
	off = fd->offset;
	if (fd->format == qm_fd_sg) {
		unsigned	sgcnt;

		sgt = (struct qm_sg_entry *)(fd_addr + fd->offset);
		/* On LE CPUs, converts the SG entry from the BE format
		 * as is provided by the HW to LE as expected by the
		 * LE CPUs, on BE CPUs does nothing */
		hw_sg_to_cpu(&sgt[0]);

		fd_addr = __dma_mem_ptov(qm_sg_addr(sgt));/* first sg entry */
		buf_hdr = odp_buf_hdr_from_addr(fd_addr, pool);
		off = sgt->offset;
		sgcnt = 1;
		do {
			hw_sg_to_cpu(&sgt[sgcnt]);

			buf_hdr->addr[sgcnt] = __dma_mem_ptov(
						       qm_sg_addr(&sgt[sgcnt]));
			sgcnt++;
		} while (sgt[sgcnt - 1].final != 1);
		buf_hdr->addr[sgcnt] = __dma_mem_ptov(qm_fd_addr(fd));
		buf_hdr->segcount = sgcnt;
		fd_addr = buf_hdr->addr[sgcnt];
	}
	buf = odp_hdr_to_buf(buf_hdr);

	/* get input interface */
	struct pktio_entry *pktio_entry = PKTIO_ENTRY_FROM_FQ(fq);
	assert(pool == odp_pool_to_entry(pktio_entry->pool));

	pkthdr = (odp_packet_hdr_t *)buf_hdr;
	pkthdr->headroom = pool->s.headroom;
	pkthdr->tailroom = pool->s.tailroom;
	/* setup and receive ODP packet */
	pkt = _odp_packet_from_buffer(buf);
	odp_pktio_set_input(pkthdr, pktio_entry->id);
	buf_set_input_queue(buf_hdr, ODP_QUEUE_INVALID);
	_odp_packet_parse(pkthdr, fd->length20, off, fd_addr);

	if (pktio_entry->pkt_table) {
		assert(dqrr->stat & QM_DQRR_STAT_UNSCHEDULED);
		*(pktio_entry->pkt_table) = pkt;
		(pktio_entry->pkt_table)++;
	}

	return qman_cb_dqrr_consume;
}

/*
 * Create a Tx queue for interface
 * */
static int create_tx_fq(struct qman_fq *fq, struct fman_if *__if)
{
	int ret;
	struct qm_mcc_initfq opts;
	queue_entry_t *qentry;
	uint32_t flags = QMAN_FQ_FLAG_DYNAMIC_FQID |
			 QMAN_FQ_FLAG_TO_DCPORTAL;

	ret = qman_create_fq(0, flags, fq);
	if (ret)
		return ret;

	qentry = QENTRY_FROM_FQ(fq);
	memset(&opts, 0, sizeof(opts));
	opts.we_mask = QM_INITFQ_WE_DESTWQ | QM_INITFQ_WE_FQCTRL |
		       QM_INITFQ_WE_CONTEXTA | QM_INITFQ_WE_CONTEXTB;
	opts.fqd.dest.channel = __if->tx_channel_id;
	opts.fqd.dest.wq = qentry->s.param.sched.prio;
	opts.fqd.fq_ctrl = QM_FQCTRL_PREFERINCACHE;
	opts.fqd.context_b = 0;
	if (__if->mac_type == fman_offline && fman_ip_rev >= FMAN_V3) {
		opts.fqd.context_a.hi = 0;
		opts.fqd.context_a.lo = 0;
	} else {
		opts.fqd.context_a.hi = 0x80000000 | fman_dealloc_bufs_mask_hi;
		opts.fqd.context_a.lo = 0 | fman_dealloc_bufs_mask_lo;
	}

	ret = qman_init_fq(fq, QMAN_INITFQ_FLAG_SCHED, &opts);
	return ret;
}

/*
 * A pktio device is a Tx/Rx facility built on top of a pair of HW queues.
 * Rx queue is allocated from the PCD ranges allocated by USDPAA to port
 * corresponding to argument *dev.
 * It works in two modes - queue mode and interface mode. In queue mode,
 * the Rx queue is under QMAN scheduler control and application gets frames
 * from this queue (possibly) using ODP scheduling calls.
 * In interface mode, frames are dequeued explicitly using
 * volatile dequeue commands.
 * Pktio is created in interface mode. It is put in queue mode when an ODP
 * queue is set as the default input queue.
 * Supports multiple pktio on top of the same device.
 * */
odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool,
				const odp_pktio_param_t *param ODP_UNUSED)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	char name[ODP_QUEUE_NAME_LEN];
	queue_entry_t *queue_entry;
	odp_queue_t qid;
	struct fman_if *__if;
	pool_entry_t *pool_t;
	struct fman_if_bpool *bpool;
	struct fm_eth_port_cfg *p_cfg;
	uint32_t count, start;
	int ret, is_shared = 1;
	queue_entry_t *qentry;
	int i;

	id = odp_pktio_lookup(dev);
	if (id != ODP_PKTIO_INVALID) {
		/* interface is already open */
		__odp_errno = EEXIST;
		return ODP_PKTIO_INVALID;
	}

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}

	/* if successful, alloc_pktio_entry() returns with the entry locked */
	pktio_entry = get_pktio_entry(id);
	pktio_entry->s.id = id;

	/* get the fman interface for this device */
	__if = get_fman_if_byshmac(dev);
	if (!__if) {
		__if = get_fman_if_byname(dev);
		is_shared = 0;
	}
	if (!__if) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto out;
	}

	/* allocate an PCD fqid for this pktio rx */
	uint32_t pcd_fqid;
	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];
		if (p_cfg == pktio_tbl->port_info[i].p_cfg &&
		    p_cfg->fman_if == __if) {
			/* use rx_def for private interfaces */
			if (!is_shared) {
				pktio_entry->s.pcd_fqid = p_cfg->rx_def;
				break;
			}

			count = get_pcd_count(p_cfg);
			start = get_pcd_start_fqid(p_cfg);
			/* no fqid available in PCD range */
			if (pktio_tbl->port_info[i].last_fqid > start + count) {
				free_pktio_entry(id);
				id = ODP_PKTIO_INVALID;
				goto out;
			}
			pcd_fqid = pktio_tbl->port_info[i].last_fqid;
			pktio_entry->s.pcd_fqid = pcd_fqid;

			pktio_entry->s.rx_fq.fqid = 0;

			pktio_tbl->port_info[i].last_fqid++;
			break;
		}
	}

	/* reserve non-dynamic fqid */
	ret = qman_reserve_fqid(pktio_entry->s.pcd_fqid);
	if (ret) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto out;
	}

	/* create default output queue */
	snprintf(name, sizeof(name), "%" PRIu64 "-pktio_outq_default",
						odp_pktio_to_u64(id));
	name[ODP_QUEUE_NAME_LEN-1] = '\0';

	qid = odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL);
	if (qid == ODP_QUEUE_INVALID)
		goto out;
	pktio_entry->s.outq_default = qid;

	queue_entry = queue_to_qentry(qid);
	queue_entry->s.pktout = id;


	/* create HW Tx queue for output */
	odp_queue_t outq = pktio_entry->s.outq_default;
	qentry = queue_to_qentry(outq);
	ret = create_tx_fq(&pktio_entry->s.tx_fq, __if);
	if (ret) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto out;
	}
	qentry->s.fq = pktio_entry->s.tx_fq;

	/* set fman interface for pktio */
	if (!pktio_entry->s.__if)
		pktio_entry->s.__if = __if;

	/* get IC transfer params */
	ret = fman_if_get_ic_params(__if, &pktio_entry->s.icp);
	if (ret) {
		free_pktio_entry(id);
		id = ODP_PKTIO_INVALID;
		goto out;
	}
	assert(pktio_entry->s.icp.iceof == DEFAULT_ICEOF);
	assert(pktio_entry->s.icp.iciof == DEFAULT_ICIOF);
	assert(pktio_entry->s.icp.icsz == DEFAULT_ICSZ);

	/* set buffer pool into the port configuration	*/
	unsigned bpool_num;
	pool_t = get_pool_entry(pool_handle_to_index(pool));
	if (pktio_tbl->port_info[i].bp_num < MAX_PORT_BPOOLS &&
	    !fman_if_find_bpid(__if, pool_t->s.pool_id)) {
		bpool_num = pktio_tbl->port_info[i].bp_num;
		bpool = &pktio_tbl->port_info[i].bpool[bpool_num];
		bpool->bpid = pool_t->s.pool_id;

		bpool->count = pool_t->s.params.pkt.num;
		bpool->size = pool_t->s.params.pkt.len;
		list_add_tail(&bpool->node, &__if->bpool_list);

		fman_if_set_bp(__if, pktio_tbl->port_info[i].bp_num,
			       pool_t->s.pool_id, pool_t->s.params.pkt.len);
		pktio_tbl->port_info[i].bp_num++;
	}
	pktio_entry->s.pool = pool;

out:
	unlock_entry(pktio_entry);
	return id;
}

int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	if (addr_size < ETH_ALEN) {
		/* Output buffer too small */
		return -1;
	}

	if (pktio_entry->s.__if->mac_type == fman_offline)
		memcpy(mac_addr, pktio_loop_mac, addr_size);
	else
		memcpy(mac_addr, pktio_entry->s.__if->mac_addr.ether_addr_octet,
		       addr_size);

	return ETH_ALEN;
}

int odp_pktio_mtu(odp_pktio_t id ODP_UNUSED)
{
	return FM_MAX_FRM;
}


int odp_pktio_close(odp_pktio_t id)
{

	int i, ret = 0;
	struct fm_eth_port_cfg *p_cfg = NULL;
	pktio_entry_t *pktio_entry;

	ODP_DBG("odp_pktio_finish\n");

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry)
		return -1;

	for (i = 0; i < netcfg->num_ethports; i++) {
		p_cfg = &netcfg->port_cfg[i];
		if (pktio_entry->s.__if == p_cfg->fman_if &&
		    p_cfg->fman_if->shared_mac_info.is_shared_mac) {
			usdpaa_netcfg_enable_disable_shared_rx(p_cfg->fman_if,
							       false);
			pktio_tbl->port_info[i].last_fqid =
						      get_pcd_start_fqid(p_cfg);
		}
	}

	/* destroy rx and tx queues */
	if (pktio_entry->s.inq_default != ODP_QUEUE_INVALID) {
		ret = odp_queue_destroy(pktio_entry->s.inq_default);
		if (ret)
			return -1;

		pktio_entry->s.inq_default = ODP_QUEUE_INVALID;
	}

	if (pktio_entry->s.outq_default != ODP_QUEUE_INVALID){
		ret = odp_queue_destroy(pktio_entry->s.outq_default);
		if (ret)
			return -1;

		pktio_entry->s.outq_default = ODP_QUEUE_INVALID;
	}

	ret = free_pktio_entry(id);


	return ret;
}

int odp_pktio_start(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	fman_if_enable_rx(pktio_entry->s.__if);
	unlock_entry(pktio_entry);

	return 0;
}

int odp_pktio_stop(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	fman_if_disable_rx(pktio_entry->s.__if);
	unlock_entry(pktio_entry);

	return 0;
}


int  odp_pktio_term_global(void)
{

	ODP_DBG("odp_pktio_term_global\n");

	pktio_entry_t *pktio_entry;
	int id;

	qman_release_pool_range(pchannel_vdq, 1);
	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		if (pktio_entry)
			odp_pktio_close(pktio_entry->s.id);
	}
	return 0;
}

odp_pktio_t odp_pktio_lookup(const char *dev)
{
	struct fman_if *__if;
	int i;

	__if = get_fman_if_byshmac(dev);
	if (!__if)
		__if = get_fman_if_byname(dev);
	if (!__if)
		return ODP_PKTIO_INVALID;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; i++) {
		if (pktio_tbl->entries[i].s.taken == 0)
			continue;

		if (pktio_tbl->entries[i].s.__if == __if)
			return pktio_tbl->entries[i].s.id;
	}

	return ODP_PKTIO_INVALID;
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;

	lock_entry(pktio_entry);
	if (pktio_entry->s.__if->mac_type != fman_offline) {
		if (enable)
			fman_if_promiscuous_enable(pktio_entry->s.__if);
		else
			fman_if_promiscuous_disable(pktio_entry->s.__if);
	}
	pktio_entry->s.promisc = enable;
	unlock_entry(pktio_entry);

	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry;
	pktio_entry = get_pktio_entry(id);

	if (!pktio_entry)
		return -1;
	return pktio_entry->s.promisc;
}

/*
 * Receive a number of packets from a pktio device (interface mode).
 * Pktio Rx queue is initialized at first receive and volatile
 * dequeue command is executed to receive packets.
 * */
int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	unsigned pkts;
	int ret;

	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (unlikely(received_sigint)) {
		odp_term_local();
		pthread_exit(NULL);
	}
	if(unlikely(!pktio_entry->s.rx_fq.fqid)){
		/* create HW Rx queue */
		ret = qman_create_fq(pktio_entry->s.pcd_fqid,
				     QMAN_FQ_FLAG_NO_ENQUEUE,
				     &pktio_entry->s.rx_fq);
		ret = queue_init_rx_fq(&pktio_entry->s.rx_fq, pchannel_vdq);
		if (ret < 0)
			return ret;

		pktio_entry->s.rx_fq.cb.dqrr = dqrr_cb_im;
		pktio_entry->s.rx_fq.cb.ern = ern_cb;
	}

	lock_entry(pktio_entry);
	pktio_entry->s.pkt_table = pkt_table;
	qman_static_dequeue_add(sdqcr_vdq);
	pkts = do_volatile_deq(&pktio_entry->s.rx_fq, len, true);
	qman_static_dequeue_del(sdqcr_vdq);
	pktio_entry->s.pkt_table = NULL;
	unlock_entry(pktio_entry);

	return pkts;
}

/*
 * Transmit a number of packets from a pktio device.
 * */
int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	odp_queue_t outq = odp_pktio_outq_getdef(id);
	queue_entry_t *qentry = queue_to_qentry(outq);
	odp_packet_t pkt;

	int ret;
	int i = 0;
	while (i < len) {
		pkt = pkt_table[i];

		ret = pktout_enqueue(qentry,
				     (odp_buffer_hdr_t *)(odp_packet_hdr(pkt)));
		if (odp_unlikely(ret == -1)) {
			if (odp_likely(errno == EAGAIN))
				continue; /* resend buffer */
			else
				break;
		}
		i++;
	} /* end while */
	return i;
}

/*
 * Setup a default queue for a pktio device.
 * Pktio Rx queue is initialized in a pool channel and scheduled.
 * This places the pktio device in queue mode; direct receive
 * is not possible beyond this call. Application is expected
 * to obtain frames by calling the scheduler.
 * */
int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	uint16_t channel;
	int ret;
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	queue_entry_t *qentry = queue_to_qentry(queue);

	if (pktio_entry == NULL || qentry == NULL)
		return -1;

	if (qentry->s.type != ODP_QUEUE_TYPE_PKTIN)
		return -1;


	lock_entry(pktio_entry);
	pktio_entry->s.inq_default = queue;
	unlock_entry(pktio_entry);

	queue_lock(qentry);
	qentry->s.pktin = id;
	if (queue != ODP_QUEUE_INVALID) {
		if (!qentry->s.poll_pktin) {
			channel = get_next_rx_channel();
			qentry->s.fq.cb.dqrr = dqrr_cb_qm;
			qentry->s.fq.cb.ern = ern_cb;
		} else {
			channel = pchannel_vdq;
			qentry->s.fq.cb.dqrr = dqrr_cb_poll_pktin;
			qentry->s.fq.cb.ern = ern_cb;
		}
		/* create HW Rx queue */
		ret = qman_create_fq(pktio_entry->s.pcd_fqid,
				     QMAN_FQ_FLAG_NO_ENQUEUE,
				     &qentry->s.fq);
		ret = queue_init_rx_fq(&qentry->s.fq, channel);
		if (ret < 0)
			return ret;
	}
	if (!qentry->s.poll_pktin) {
		qman_schedule_fq(&qentry->s.fq);
		qentry->s.status = QUEUE_STATUS_SCHED;
	}
	queue_unlock(qentry);

	return 0;
}

int odp_pktio_inq_remdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	odp_queue_t queue;
	queue_entry_t *qentry;

	if (pktio_entry == NULL)
		return -1;

	lock_entry(pktio_entry);
	queue = pktio_entry->s.inq_default;
	qentry = queue_to_qentry(queue);

	queue_lock(qentry);
	if (qentry->s.status == QUEUE_STATUS_FREE) {
		queue_unlock(qentry);
		unlock_entry(pktio_entry);
		return -1;
	}

	qentry->s.pktin = ODP_PKTIO_INVALID;
	queue_unlock(qentry);

	pktio_entry->s.inq_default = ODP_QUEUE_INVALID;
	unlock_entry(pktio_entry);

	return 0;
}

odp_queue_t odp_pktio_inq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.inq_default;
}

odp_queue_t odp_pktio_outq_getdef(odp_pktio_t id)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	if (pktio_entry == NULL)
		return ODP_QUEUE_INVALID;

	return pktio_entry->s.outq_default;
}

static inline size_t odp_pkt_get_len(odp_buffer_hdr_t *buf_hdr)
{
	return ((odp_packet_hdr_t *)(buf_hdr))->frame_len;
}

static inline size_t odp_pkt_get_data_off(odp_buffer_hdr_t *buf_hdr)
{
	return ((odp_packet_hdr_t *)(buf_hdr))->l2_offset +
		((odp_packet_hdr_t *)(buf_hdr))->headroom;
}

static inline uint32_t odp_buf_get_bpid(odp_buffer_hdr_t *buf_hdr)
{
	return buf_hdr->handle.pool_id;
}

/* Enqueue a buffer for transmission */
int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	uint32_t pool_id;
	size_t len, off;
	struct qm_fd fd;
	odp_queue_t inq;
	queue_entry_t *in_qentry = NULL;
	int ret;

	pool_id = odp_buf_get_bpid(buf_hdr);
	len = odp_pkt_get_len(buf_hdr);
	off = odp_pkt_get_data_off(buf_hdr);
	inq = buf_hdr->inq;

	__config_fd(&fd, buf_hdr, off, len, pool_id, qentry);
	local_fq.fqid = qentry->s.fq.fqid;

	if (inq != ODP_QUEUE_INVALID) {
		in_qentry = queue_to_qentry(inq);
	} else {
		/* pktio burst mode */
		ret = qman_enqueue(&local_fq, &fd, 0);
		return ret;
	}

	return queue_enqueue_tx_fq(&local_fq, &fd, buf_hdr, in_qentry);
}

/* no dequeue from PKTOUT queues */
odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *qentry)
{
	(void)qentry;
	return NULL;
}

int pktout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer(buf_hdr[i]->handle.handle);

	nbr = odp_pktio_send(qentry->s.pktout, pkt_tbl, num);
	return nbr;
}

/* no dequeue from PKTOUT queues */
int pktout_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	(void)qentry;
	(void)buf_hdr;
	(void)num;
	return 0;
}

/* no direct enqueue to PKTIN queue*/
int pktin_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	(void)qentry, (void)buf_hdr;
	return -1;
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	/* no direct dequeue from HW sched PKTIN queue */
	if (!qentry->s.poll_pktin)
		return NULL;

	pktio_entry_t *pktio_entry = get_pktio_entry(qentry->s.pktin);
	assert(pktio_entry);
	odp_packet_t pkt = ODP_PACKET_INVALID;

	lock_entry(pktio_entry);
	pktio_entry->s.pkt_table = &pkt;
	qman_static_dequeue_add(sdqcr_vdq);
	assert(qentry->s.fq.cb.dqrr == dqrr_cb_poll_pktin);
	do_volatile_deq(&qentry->s.fq, 1, true);
	qman_static_dequeue_del(sdqcr_vdq);
	pktio_entry->s.pkt_table = NULL;
	unlock_entry(pktio_entry);

	if (pkt != ODP_PACKET_INVALID)
		return odp_buf_to_hdr(_odp_packet_to_buffer(pkt));

	return NULL;
}

/* no direct enqueue to PKTIN queue*/
int pktin_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	(void)qentry, (void)buf_hdr, (void)num;
	return -1;
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	/* no direct dequeue from HW sched PKTIN queue */
	(void)qentry, (void)buf_hdr, (void)num;
	return -1;
}
void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
}
