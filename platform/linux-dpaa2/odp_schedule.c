/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <string.h>
#include <pthread.h>

#include <odp/init.h>
#include <odp/schedule.h>
#include <odp_schedule_internal.h>
#include <odp/align.h>
#include <odp/queue.h>
#include <odp/shared_memory.h>
#include <odp/buffer.h>
#include <odp/pool.h>
#include <odp_internal.h>
#include <odp/config.h>
#include <odp_debug_internal.h>
#include <odp/thread.h>
#include <odp/time.h>
#include <odp/spinlock.h>
#include <odp/hints.h>
#include <odp/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp/init.h>
#include <odp_config_internal.h>

#include <odp_queue_internal.h>
#include <dpaa2_time.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_conc_priv.h>
#include <dpaa2_mbuf_priv.h>
#include <dpaa2_io_portal_priv.h>
#include <dpaa2_vq.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_memconfig.h>
#include <fsl_qbman_portal.h>
#include <fsl_dpcon.h>
#include <fsl_dpio.h>
#include <fsl_dpni.h>
#include <fsl_dpkg.h>
#include <fsl_mc_sys.h>


/* Limits to number of scheduled queues */
#define SCHED_POOL_SIZE (256*1024)

/* Scheduler sub queues */
#define QUEUES_PER_PRIO  4

/* TODO: random or queue based selection */
#define SEL_PRI_QUEUE(x) ((QUEUES_PER_PRIO-1) & (queue_to_id(x)))

/* Maximum number of dequeues */
#define MAX_DEQ 16

/* Starting handle of users scheduler groups */
#define _ODP_SCHED_GROUP_NAMED (ODP_SCHED_GROUP_CONTROL + 1)

/* Internal routine to get scheduler thread mask addrs */
odp_thrmask_t *thread_sched_grp_mask(int index);

/* Mask with all threads set */
odp_thrmask_t sched_mask_all;

/* Per thread list of groups*/
struct thread_groups {
	int count;      /**< groups count **/
	int grp_ptr;    /**< flag to avoid starvation **/
	void *dpio_dev; /**< portal **/
	odp_schedule_group_t groups[MAX_SCHED_GRPS];
};

struct thread_groups thr_grp[_ODP_INTERNAL_MAX_THREADS] = {{0} };

/* Hidden flag that will be used in test application to do bench mark */
#define ODP_BENCHMARK	BIT_POS(31)

#define SWAP_MAC_HDR(overlay)		{\
	register uint32_t a, b, c;\
	a = overlay[0];\
	b = overlay[1];\
	c = overlay[2];\
	overlay[0] = (b >> 16) | (c << 16);\
	overlay[1] = (c >> 16) | (a << 16);\
	overlay[2] = (a >> 16) | (b << 16);\
}

/* Enable this Flag to get debug prints in loopback functionoality */
#define	LOOPBACK_DEBUG	0

static inline int32_t odp_schedule_dummy(dpaa2_mbuf_pt mbuf[], int num);
/* Receive function to have PUSH/PULL at run time */
__thread odp_sch_recv_t fn_sch_recv_pkt = odp_schedule_dummy;

static inline int32_t odp_set_push_mode(odp_schedule_group_t group, struct dpaa2_dpio_dev *dpio);

static inline int32_t odp_unset_push_mode(odp_schedule_group_t group, struct dpaa2_dpio_dev *dpio);

/* Mask of queues per priority */
typedef uint8_t pri_mask_t;

_ODP_STATIC_ASSERT((8*sizeof(pri_mask_t)) >= QUEUES_PER_PRIO,
		   "pri_mask_t_is_too_small");


typedef struct {
	odp_queue_t    pri_queue[ODP_CONFIG_SCHED_PRIOS][QUEUES_PER_PRIO];
	pri_mask_t     pri_mask[ODP_CONFIG_SCHED_PRIOS];
	odp_spinlock_t mask_lock;
	odp_pool_t     pool;
	odp_spinlock_t grp_lock;
	struct {
		char		name[ODP_SCHED_GROUP_NAME_LEN]; /**< name of the group **/
		struct dpaa2_dev *conc_dev; /**< conc device for group **/
		int queues;	/**< queues count **/
		int ch_index;	/**< channel index for corresponding conc device **/
		odp_thrmask_t	*mask; /**< thread mask **/
	} sched_grp[MAX_SCHED_GRPS];
} sched_t;

typedef struct {
	odp_queue_t queue;

} queue_desc_t;

typedef struct {
	odp_queue_t pri_queue;
	odp_event_t desc_ev;

	odp_event_t ev[MAX_DEQ];
	int num;
	int index;
	odp_queue_t queue;
	int pause;

} sched_local_t;

/* Global scheduler context */
static sched_t *sched;

int scheduled_init = 0;

static inline odp_queue_t select_pri_queue(odp_queue_t queue, int prio)
{
	int id = SEL_PRI_QUEUE(queue);
	return sched->pri_queue[prio][id];
}


int odp_schedule_init_global(void)
{
	int32_t retcode, i = 0;
	odp_shm_t shm;
	struct dpaa2_dev *cdev;

	ODP_DBG("Schedule init ... ");

	shm = odp_shm_reserve("odp_scheduler",
				sizeof(sched_t),
				ODP_CACHE_LINE_SIZE, 0);

	sched = odp_shm_addr(shm);
	if (!sched) {
		ODP_ERR("Schedule init: Shm reserve failed.\n");
		return -1;
	}

	memset(sched, 0, sizeof(sched_t));
	/*Scan the device list for concentrator device*/
	retcode = odp_dpaa2_scan_device_list(DPAA2_CONC);
	if (!retcode) {
		ODP_ERR("Schedule init failed...\n");
		odp_shm_free(shm);
		return -1;
	}
	for (i = 0; i < _ODP_SCHED_GROUP_NAMED; i++) {
		cdev = odp_get_inactive_conc_dev();
		if (!cdev) {
			odp_shm_free(shm);
			ODP_ERR("Resources unavailable\n");
			return -1;
		}
		retcode = dpaa2_conc_start(cdev);
		if (DPAA2_FAILURE == retcode) {
			odp_shm_free(shm);
			ODP_ERR("Failed Conc - dpaa2_dev_start\n");
			return retcode;
		}
		sched->sched_grp[i].conc_dev = cdev;
		sched->sched_grp[i].ch_index = DPAA2_INVALID_CHANNEL_IDX;
		sched->sched_grp[i].queues = 0;
		sched->sched_grp[i].mask = thread_sched_grp_mask(i);
	}
	strcpy(sched->sched_grp[0].name, "ODP_SCHED_GROUP_ALL");
	strcpy(sched->sched_grp[1].name, "ODP_SCHED_GROUP_WORKER");
	strcpy(sched->sched_grp[2].name, "ODP_SCHED_GROUP_CONTROL");

	for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		sched->sched_grp[i].conc_dev = NULL;
		sched->sched_grp[i].ch_index = DPAA2_INVALID_CHANNEL_IDX;
		sched->sched_grp[i].queues = 0;
		sched->sched_grp[i].mask = thread_sched_grp_mask(i);
	}

	odp_thrmask_setall(&sched_mask_all);

	scheduled_init = 1;

	ODP_DBG("done\n");

	return 0;
}

int odp_schedule_term_global(void)
{
	int32_t retcode, i = 0;

	if (!scheduled_init)
		return 0;

	odp_thrmask_zero(&sched_mask_all);

	for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		sched->sched_grp[i].conc_dev = NULL;
		sched->sched_grp[i].queues = 0;
		sched->sched_grp[i].ch_index = DPAA2_INVALID_CHANNEL_IDX;
	}

	for (i = 0; i < _ODP_SCHED_GROUP_NAMED; i++) {
		retcode = dpaa2_conc_stop(sched->sched_grp[i].conc_dev);
		if (DPAA2_FAILURE == retcode) {
			ODP_ERR("Failed Conc - dpaa2_conc_stop\n");
			return retcode;
		}
		memset(sched->sched_grp[i].name, 0, ODP_SCHED_GROUP_NAME_LEN);
		sched->sched_grp[i].conc_dev = NULL;
		sched->sched_grp[i].ch_index = DPAA2_INVALID_CHANNEL_IDX;
		sched->sched_grp[i].queues = 0;
	}

	retcode = odp_shm_free(odp_shm_lookup("odp_scheduler"));
	if (retcode < 0) {
		ODP_ERR("shm free failed for shm_odp_pmr_tbl");
		return retcode;
	}

	scheduled_init = 0;
	return 0;
}
void odp_schedule_mask_set(odp_queue_t queue, int prio)
{
	int id = SEL_PRI_QUEUE(queue);

	odp_spinlock_lock(&sched->mask_lock);
	sched->pri_mask[prio] |= 1 << id;
	odp_spinlock_unlock(&sched->mask_lock);
}


odp_buffer_t odp_schedule_buffer_alloc(odp_queue_t queue)
{
	odp_buffer_t buf;

	buf = odp_buffer_alloc(sched->pool);

	if (buf != ODP_BUFFER_INVALID) {
		queue_desc_t *desc;
		desc        = odp_buffer_addr(buf);
		desc->queue = queue;
	}

	return buf;
}


void odp_schedule_queue(odp_queue_t queue, int prio)
{
	queue_entry_t *qentry;
	struct dpaa2_dev *ndev;
	struct dpaa2_vq_param vq_cfg;
	pktio_entry_t *pktio_entry;
	uint32_t i, max_rx_vq = 0;
	struct queues_config *q_config;
	int32_t ret;

	qentry = queue_to_qentry(queue);
	pktio_entry = get_pktio_entry(qentry->s.pktin);
	if (pktio_entry == NULL || queue == ODP_QUEUE_INVALID)
		return;

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	if (enable_hash) {
		/* Adding support for multiple VQs & Rx Side distribution.
		   Since, there is no ODP API available to enable Rx
		   distribution, we are enabling all available VQs for a
		   given User queue.
		*/
		max_rx_vq = dpaa2_dev_get_max_rx_vq(ndev);
		ODP_PRINT("%s: MAX RX VQs are %d  for %s (%s)\n", __func__,
			max_rx_vq, ndev->dev_string, pktio_entry->s.name);
		/* Enable distribution */
		q_config = dpaa2_eth_get_queues_config(ndev);
		for (i = 0; i < q_config->num_tcs; i++) {
			ret = dpaa2_eth_setup_flow_distribution(ndev,
					DPAA2_FDIST_IP_SA | DPAA2_FDIST_IP_DA,
					i,
					q_config->tc_config[i].num_dist);
			if (ret) {
				ODP_ERR("Fail to configure RX dist\n");
				return;
			}
		}
		ODP_PRINT("Configured RX dist! 0x%X\n", DPAA2_FDIST_IP_SA | DPAA2_FDIST_IP_DA);
	}

	/*Prepare VQ parameters for configuring */
	memset(&vq_cfg, 0, sizeof(struct dpaa2_vq_param));
	/*Get a conc device from the DPAA2 then map this queue to conc device*/
	vq_cfg.conc_dev = odp_get_conc_from_grp(qentry->s.param.sched.group);

	vq_cfg.prio = prio;
	vq_cfg.sync = qentry->s.param.sched.sync;
	if (enable_hash) {
		/*Configure DPAA2 for RX Queue*/
		for (i = 0; i < max_rx_vq; i++) {
			dpaa2_eth_setup_rx_vq(ndev, i, &vq_cfg);
			/* All Low level VQs must be mapped to single User
				Qeueue */
			dpaa2_dev_set_vq_handle(ndev->rx_vq[i],
					(uint64_t)qentry->s.handle);
			if (DPAA2_FAILURE == ret) {
				ODP_ERR("Fail to setup RX VQ with CONC\n");
				return;
			}
			ODP_DBG("setup VQ %d with handle 0x%X\n", i,
					qentry->s.handle);
		}
	} else {
		i = 0;
		dpaa2_eth_setup_rx_vq(ndev, i, &vq_cfg);
		/* All Low level VQs must be mapped to single User Qeueue */
		dpaa2_dev_set_vq_handle(ndev->rx_vq[i],
					(uint64_t)qentry->s.handle);
		ODP_DBG("setup VQ %d with handle 0x%X\n", i, qentry->s.handle);
	}
	ret = odp_add_queue_to_group(qentry->s.param.sched.group);
	if (ret == 1)
		odp_affine_group(qentry->s.param.sched.group, NULL);
}

int32_t odp_add_queue_to_group(odp_schedule_group_t grp)
{
	int count;

	odp_spinlock_lock(&sched->grp_lock);

	sched->sched_grp[grp].queues += 1;
	count = sched->sched_grp[grp].queues;
	odp_spinlock_unlock(&sched->grp_lock);
	return count;
}

int32_t odp_sub_queue_to_group(odp_schedule_group_t grp)
{
	int count;

	odp_spinlock_lock(&sched->grp_lock);

	if (!sched->sched_grp[grp].queues) {
		ODP_DBG("No queue is affined to group\n");
		return -1;
	}
	sched->sched_grp[grp].queues -= 1;
	count = sched->sched_grp[grp].queues;
	odp_spinlock_unlock(&sched->grp_lock);

	return count;
}

struct dpaa2_dev *odp_get_conc_from_grp(odp_schedule_group_t grp)
{
	return sched->sched_grp[grp].conc_dev;
}

void odp_schedule_release_atomic(void)
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;

	if (IS_HOLD_DQRR_VALID) {
		qbman_swp_dqrr_consume(swp, GET_HOLD_DQRR_PTR);
		MARK_HOLD_DQRR_PTR_INVALID;
		/* Since Last buffer is not freed yet,
		   its safe to access it */
		MARK_HOLD_BUF_CNTXT_INVALID;
	}
}



/*
 * Function to receive Scheduled packet from I/O Portal with PUSH Mode
 */
static inline int32_t odp_rcv_push_mode(dpaa2_mbuf_pt mbuf[], int num ODP_UNUSED)
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	const struct qbman_fd *fd;
	const struct qbman_result *dqrr_entry;
	struct dpaa2_vq *rvq;
	uint8_t status;

	/* Function is responsible to receive frame for a given
	   DPCON device and Channel ID.
	*/

	/* Free the last holded DQRR entry, if any.
	   Possible when packet is on hold or consumed
	   without free in termination cases
	 */
	if (IS_HOLD_DQRR_VALID) {
		qbman_swp_dqrr_consume(swp, GET_HOLD_DQRR_PTR);
		/* Since Last buffer is not freed yet,
		   its safe to access it */
		MARK_HOLD_BUF_CNTXT_INVALID;
		MARK_HOLD_DQRR_PTR_INVALID;
	}
	/*Receive the packets*/
	dqrr_entry = qbman_swp_dqrr_next(swp);
	if (NULL == dqrr_entry)
		return 0;

	/* Check for valid frame. If not sent a consume
	 * confirmation to QBMAN receive_sch_pktotherwise give it to DPAA2
	 * application and then send consume confirmation to
	 * QBMAN.
	 */
	status = (uint8_t)qbman_result_DQ_flags(dqrr_entry);
	if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
		ODP_DBG("No frame is delivered\n");
		qbman_swp_dqrr_consume(swp, dqrr_entry);
		return 0;
	}

	fd = qbman_result_DQ_fd(dqrr_entry);
	rvq = (struct dpaa2_vq *)qbman_result_DQ_fqd_ctx(dqrr_entry);
	if (rvq) {
		mbuf[0] = rvq->qmfq.cb(swp, fd, dqrr_entry);
		/* Set the current context in both threadinfo & buffer */
		SAVE_HOLD_DQRR_PTR(dqrr_entry);
		SAVE_HOLD_BUF_PTR(mbuf[0]);
		mbuf[0]->atomic_cntxt = (void *)dqrr_entry;
	} else {
		qbman_swp_dqrr_consume(swp, dqrr_entry);
		ODP_ERR("Null Return VQ received\n");
		return 0;
	}
	/*Check for the errors received*/
	/*Return the total number of packets received to DPAA2 app*/
	return 1;
}


/* Function to benchmark low level performance */
static inline int32_t odp_qbman_loopback(dpaa2_mbuf_pt mbuf[] ODP_UNUSED, int num ODP_UNUSED)
{
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	const struct qbman_fd *fd;
	const struct qbman_result *dqrr_entry;
	struct dpaa2_vq *rvq;
	uint8_t status;
	struct dpaa2_vq *eth_tx_vq = NULL;
	struct qbman_eq_desc eqdesc;
	struct dpaa2_dev_priv *dev_priv;
	uint32_t *overlay;
	int ret;

	/* Function is responsible to receive frame for a given
	   DPCON device and Channel ID.
	*/
	printf("%s: \n", __func__);
	qbman_eq_desc_clear(&eqdesc);
	qbman_eq_desc_set_no_orp(&eqdesc, DPAA2_EQ_RESP_ERR_FQ);

	/*Receive the packets*/
	while (1) {
		dqrr_entry = qbman_swp_dqrr_next(swp);
		if (odp_unlikely(NULL == dqrr_entry)) {
			if (odp_unlikely(received_sigint)) {
				if (odp_term_local())
					fprintf(stderr, "error: odp_term_local() failed.\n");
				pthread_exit(NULL);
			}
			continue;
		}
		status = (uint8_t)qbman_result_DQ_flags(dqrr_entry);
		if (odp_unlikely((status & QBMAN_DQ_STAT_VALIDFRAME) == 0)) {
			ODP_DBG("No frame is delivered\n");
			qbman_swp_dqrr_consume(swp, dqrr_entry);
			continue;
		}

		rvq = (struct dpaa2_vq *)qbman_result_DQ_fqd_ctx(dqrr_entry);
		eth_tx_vq = rvq->dev->tx_vq[0];
		dev_priv = (struct dpaa2_dev_priv *)rvq->dev->priv;

		qbman_eq_desc_set_qd(&eqdesc, dev_priv->qdid,
				eth_tx_vq->flow_id, eth_tx_vq->tc_index);
		/* SET DCA */
#define QBMAN_IDX_FROM_DQRR(p) (((unsigned long)p & 0x1ff) >> 6)
		qbman_eq_desc_set_dca(&eqdesc, 1,
				QBMAN_IDX_FROM_DQRR(dqrr_entry), 0);
		fd = qbman_result_DQ_fd(dqrr_entry);

		/* Swap Mac address */
		overlay = (uint32_t *)DPAA2_IOVA_TO_VADDR(
				(uint8_t *)DPAA2_GET_FD_ADDR(fd) +
					DPAA2_GET_FD_OFFSET(fd));
#if LOOPBACK_DEBUG
		printf("ETH:  0x%X%X%X\n", overlay[0], overlay[1], overlay[2]);
#endif
		/* Swap the SRC & DST Mac addresses */
		SWAP_MAC_HDR(overlay);

#if LOOPBACK_DEBUG
		{
			int i = 0;

			ODP_DBG("%s: FLC 0x%lu 0x%x\n", __func__,
				DPAA2_GET_FD_FLC(fd), fd->simple.ctrl);
			while (i < 8) {
				ODP_DBG(" %08X", fd->words[i]);
				i++;
			}
			ODP_DBG("\n");
		}
#endif
		do {
			ret = qbman_swp_enqueue(swp, &eqdesc, fd);
		} while (ret == -EBUSY);
		/*Check for the errors received*/
	} /* End of While() */
}

static inline int32_t odp_rcv_pull_mode(dpaa2_mbuf_pt mbuf[], int num)
{
	struct dpaa2_dev *ndev;
	int thr_id, count, ret = 0;
	int *i;

	thr_id = odp_thread_id();
	i = &thr_grp[thr_id].grp_ptr;
	count = thr_grp[thr_id].count;
	*i %= count;
	do {
		ndev = sched->sched_grp[thr_grp[thr_id].groups[*i]].conc_dev;
		ret = dpaa2_conc_recv(ndev, NULL, num, mbuf);
		if (ret > 0)
			return ret;
		*i += 1;
	} while (*i < count);
	return ret;
}

/* This dummy Receive function will first configure the Channel to DPIO
 * mapping for PUSH/PULL Mode & then reset the "fn_sch_recv_pkt" function
 * pointer to related Function
 */
static inline int32_t odp_schedule_dummy(dpaa2_mbuf_pt mbuf[], int num)
{
	int thr_id, ret, i;
	odp_thread_type_t type = odp_thread_type();

	thr_id = odp_thread_id();

	if (dq_schedule_mode & ODPFSL_PUSH) {
		/* For Group ALL */
		ret = odp_set_push_mode(ODP_SCHED_GROUP_ALL, NULL);
		if (ret)
			return -1;
		/* For Worker / Control Group */
		if (type == ODP_THREAD_WORKER) {
			ret = odp_set_push_mode(ODP_SCHED_GROUP_WORKER, NULL);
			if (ret)
				return -1;
		} else {
			ret = odp_set_push_mode(ODP_SCHED_GROUP_CONTROL, NULL);
			if (ret)
				return -1;
		}
		/* For User defined groups */
		for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
			if (sched->sched_grp[i].name[0] != 0 &&
				odp_thrmask_isset(sched->sched_grp[i].mask, thr_id)) {
				ret = odp_set_push_mode(i, NULL);
				if (ret)
					return -1;
			}
		}

		if (dq_schedule_mode & ODP_BENCHMARK)
			fn_sch_recv_pkt = odp_qbman_loopback;
		else
			fn_sch_recv_pkt = odp_rcv_push_mode;

		ODP_DBG("Setting ODP schedule PUSH pointer for thread %d\n", thr_id);
	} else {
		/* PULL Mode configuration */
		/* Set the RCV function pointer */
		fn_sch_recv_pkt = odp_rcv_pull_mode;
		ODP_DBG("Setting ODP schedule PULL pointer for thread %d\n", thr_id);
	}

	/* Now Receive packets from actual function */
	return fn_sch_recv_pkt(mbuf, num);
}

odp_event_t odp_schedule(odp_queue_t *out_queue, uint64_t wait)
{
	int32_t ret;
	odp_event_t ev = ODP_EVENT_INVALID;
	dpaa2_mbuf_pt pkt_buf[1];
	uint64_t wait_till;
	/* Timeout Handling*/
	if (wait)
		wait_till = dpaa2_time_get_cycles() + wait;

	do {
		ret = fn_sch_recv_pkt(pkt_buf, 1);
		if (ret > 0) {
			ev = (odp_event_t)pkt_buf[0];
			if (out_queue) {
				*out_queue =
					(odp_queue_t)dpaa2_dev_get_vq_handle(pkt_buf[0]->vq);
			}
			break;
		} else if (ret == 0) {
			if ((wait != ODP_SCHED_WAIT) && (wait_till <= dpaa2_time_get_cycles()))
				break;
		}

		if (odp_unlikely(received_sigint)) {
			if (odp_term_local())
				fprintf(stderr, "error: odp_term_local() failed.\n");
			pthread_exit(NULL);
		}

	} while (1);

	return ev;
#if 0
	if (start_cycle == 0) {
		start_cycle = odp_time_cycles();
		continue;
	}
	cycle = odp_time_cycles();
	diff = odp_time_diff_cycles(start_cycle, cycle);
	if (wait < diff)
		break;
	return ret;
#endif
}

int odp_schedule_multi(odp_queue_t *out_queue, uint64_t wait,
		       odp_event_t events[], int num)
{
	int32_t i, num_pkt = 0;
	dpaa2_mbuf_pt pkt_buf[MAX_DEQ];
	uint64_t wait_till;
	/* Timeout Handling*/
	if (wait)
		wait_till = dpaa2_time_get_cycles() + wait;

	while (1) {
		num_pkt = fn_sch_recv_pkt(pkt_buf, num);


		if (num_pkt > 0) {
			if (out_queue) {
				*out_queue = (odp_queue_t)
					dpaa2_dev_get_vq_handle(pkt_buf[0]->vq);
			}

			for (i = 0; i < num_pkt; i++)
				events[i] = (odp_event_t)pkt_buf[i];

			return num_pkt;

		} else if (num_pkt == 0) {
			if ((wait != ODP_SCHED_WAIT) && (wait_till <= dpaa2_time_get_cycles()))
				break;
		}

		if (odp_unlikely(received_sigint)) {
			if (odp_term_local())
				fprintf(stderr, "error: odp_term_local() failed.\n");
			pthread_exit(NULL);
		}

	}
	if (out_queue)
		*out_queue = ODP_QUEUE_INVALID;

	return -1;
}

int odp_schedule_init_local(void)
{
	int thr_id, i;
	odp_thread_type_t type = odp_thread_type();
	odp_thrmask_t *mask;

	thr_id = odp_thread_id();
	thr_grp[thr_id].dpio_dev = thread_io_info.dpio_dev;
	mask = sched->sched_grp[ODP_SCHED_GROUP_ALL].mask;
	odp_thrmask_set(mask, thr_id);
	if (sched->sched_grp[ODP_SCHED_GROUP_ALL].queues) {
		thr_grp[thr_id].groups[thr_grp[thr_id].count] = ODP_SCHED_GROUP_ALL;
		thr_grp[thr_id].count += 1;
	}
	if (type == ODP_THREAD_WORKER) {
		mask = sched->sched_grp[ODP_SCHED_GROUP_WORKER].mask;
		odp_thrmask_set(mask, thr_id);
		if (sched->sched_grp[ODP_SCHED_GROUP_WORKER].queues) {
			thr_grp[thr_id].groups[thr_grp[thr_id].count] = ODP_SCHED_GROUP_WORKER;
			thr_grp[thr_id].count += 1;
		}
	} else {
		mask = sched->sched_grp[ODP_SCHED_GROUP_CONTROL].mask;
		odp_thrmask_set(mask, thr_id);
		if (sched->sched_grp[ODP_SCHED_GROUP_CONTROL].queues) {
			thr_grp[thr_id].groups[thr_grp[thr_id].count] = ODP_SCHED_GROUP_CONTROL;
			thr_grp[thr_id].count += 1;
		}
		/* PULL Mode configuration */
		/* Set the RCV function pointer */
		fn_sch_recv_pkt = odp_rcv_pull_mode;
	}
	if (dq_schedule_mode & ODPFSL_PUSH) {
		for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
			if (sched->sched_grp[i].name[0] != 0 &&
				odp_thrmask_isset(sched->sched_grp[i].mask, thr_id) &&
				sched->sched_grp[i].queues) {
				odp_thrmask_t msk;

				odp_thrmask_zero(&msk);
				odp_thrmask_set(&msk, thr_id);
				odp_affine_group(i, &msk);
			}
		}

	}
	return 0;
}

int odp_schedule_term_local(void)
{
	uint32_t thr_id, i;
	odp_thread_type_t type;
	odp_thrmask_t clr_mask;

	type = odp_thread_type();
	thr_id = odp_thread_id();
	odp_thrmask_zero(&clr_mask);
	odp_thrmask_set(&clr_mask, thr_id);

	for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
		if (sched->sched_grp[i].name[0] != 0 &&
			odp_thrmask_isset(sched->sched_grp[i].mask, thr_id) &&
			sched->sched_grp[i].queues) {
			odp_thrmask_t msk;

			odp_thrmask_zero(&msk);
			odp_thrmask_set(&msk, thr_id);
			odp_deaffine_group(i, &msk);
		}
	}
	if (sched->sched_grp[ODP_SCHED_GROUP_ALL].queues)
		odp_deaffine_group(ODP_SCHED_GROUP_ALL, &clr_mask);

	if (type == ODP_THREAD_WORKER) {
		if (sched->sched_grp[ODP_SCHED_GROUP_WORKER].queues)
			odp_deaffine_group(ODP_SCHED_GROUP_WORKER, &clr_mask);

	} else {
		if (sched->sched_grp[ODP_SCHED_GROUP_CONTROL].queues)
			odp_deaffine_group(ODP_SCHED_GROUP_CONTROL, &clr_mask);
	}

	if (!(dq_schedule_mode & ODPFSL_PUSH)) {
		for (i = 0; i < dpaa2_res.res_cnt.conc_dev_cnt; i++)
			dpaa2_dev_deaffine_conc_list(dpaa2_res.conc_dev[i]);
	}
	thr_grp[thr_id].dpio_dev = NULL;

	return 0;
}

void odp_schedule_pause(void)
{
	uint32_t i;
	/*De-affine the concentrator for global scheduling of this thread*/
	for (i = 0; i < dpaa2_res.res_cnt.conc_dev_cnt; i++)
		dpaa2_dev_deaffine_conc_list(dpaa2_res.conc_dev[i]);
}


void odp_schedule_resume(void)
{
	uint32_t i;
	/*Affine the concentrator for global scheduling of this thread*/
	for (i = 0; i < dpaa2_res.res_cnt.conc_dev_cnt; i++)
		dpaa2_dev_affine_conc_list(dpaa2_res.conc_dev[i]);
}


uint64_t odp_schedule_wait_time(uint64_t ns)
{
	return ns;
}


int odp_schedule_num_prio(void)
{
	return ODP_CONFIG_SCHED_PRIOS;
}
void odp_schedule_release_ordered(void)
{
	ODP_UNIMPLEMENTED();
}
void odp_schedule_release_context(void)
{
	ODP_UNIMPLEMENTED();
}

int32_t odp_affine_group(odp_schedule_group_t group, const odp_thrmask_t *msk)
{
	int i, already_present = 0, thr;
	const odp_thrmask_t *mask;

	if (msk)
		mask = msk;
	else
		mask = sched->sched_grp[group].mask;

	thr = odp_thrmask_first(mask);
	while (0 <= thr) {
		for (i = 0; i < thr_grp[thr].count; i++) {
			if (thr_grp[thr].groups[i] == group) {
				already_present = 1;
				break;
			}
		}
		if (!already_present) {
			thr_grp[thr].groups[thr_grp[thr].count] = group;
			thr_grp[thr].count += 1;
		}
		already_present = 0;
		thr = odp_thrmask_next(mask, thr);
	}

	return 0;
}

int32_t odp_deaffine_group(odp_schedule_group_t group, const odp_thrmask_t *msk)
{
	int i, already_present = 0, thr, ret;
	struct dpaa2_dpio_dev *dpio_dev;
	const odp_thrmask_t *mask;

	if (msk)
		mask = msk;
	else
		mask = sched->sched_grp[group].mask;

	thr = odp_thrmask_first(mask);
	while (0 <= thr) {
		for (i = 0; i < thr_grp[thr].count; i++) {
			if (thr_grp[thr].groups[i] == group) {
				already_present = 1;
				break;
			}
		}
		if (already_present) {
			if (dq_schedule_mode & ODPFSL_PUSH) {
				dpio_dev = (struct dpaa2_dpio_dev *) thr_grp[thr].dpio_dev;
				if (dpio_dev) {
					ret = odp_unset_push_mode(group, dpio_dev);
					if (ret)
						return -1;
				}
			}
			if (i != (thr_grp[thr].count - 1))
				thr_grp[thr].groups[i] = thr_grp[thr].groups[thr_grp[thr].count-1];
			else
				thr_grp[thr].groups[i] = 0;
			thr_grp[thr].count -= 1;
		}
	already_present = 0;
	thr = odp_thrmask_next(mask, thr);
	}

	return 0;
}

static inline int32_t odp_set_push_mode(odp_schedule_group_t group, struct dpaa2_dpio_dev *dpio)
{
	struct dpaa2_dev *conc_dev = sched->sched_grp[group].conc_dev;

	if (dq_schedule_mode & ODPFSL_PUSH) {
		/* PUSH Mode configuration */
		int32_t retcode;
		uint8_t ch_index;
		struct conc_attr attr;
		struct dpaa2_dpio_dev *dpio_dev;
		struct qbman_swp *swp;

		if (dpio)
			dpio_dev = dpio;
		else
			dpio_dev = thread_io_info.dpio_dev;

		swp = dpio_dev->sw_portal;
		/*Get conc attributes so that channel ID can be mapped*/
		dpaa2_conc_get_attributes(conc_dev, &attr);
		/*Get mapping index corresponding to DPCON object*/
		retcode = dpio_add_static_dequeue_channel(dpio_dev->dpio,
				CMD_PRI_LOW, dpio_dev->token, attr.obj_id,
							&ch_index);
		if (retcode < 0) {
			ODP_ERR("Static dequeue cfg failed: Code = %d\n",
								retcode);
			return -1;
		}
		/*Configure QBMAN for addition of static dequeue command*/
		qbman_swp_push_set(swp, ch_index, true);
		/* Save mapping for future use */
		sched->sched_grp[group].ch_index = ch_index;
		dpio_dev->ch_idx[dpio_dev->ch_count++] = ch_index;
	} else {
		ODP_DBG("PUSH mode is not enabled\n");
		return -1;
	}
	return 0;
}

static inline int32_t odp_unset_push_mode(odp_schedule_group_t group, struct dpaa2_dpio_dev *dpio)
{
	struct dpaa2_dev *conc_dev = sched->sched_grp[group].conc_dev;

	if (dq_schedule_mode & ODPFSL_PUSH) {
		int32_t retcode, i = 0;
		struct conc_attr attr;
		struct dpaa2_dpio_dev *dpio_dev;
		struct qbman_swp *swp;

		if (dpio)
			dpio_dev = dpio;
		else
			dpio_dev = thread_io_info.dpio_dev;

		swp = dpio_dev->sw_portal;
		/*Check that device is not NULL*/

		/*Get conc attributes so that channel ID can be mapped*/
		dpaa2_conc_get_attributes(conc_dev, &attr);
		/*Configure QBMAN for removal of static dequeue command*/

		for (i = 0; i < dpio_dev->ch_count; i++) {
			if (dpio_dev->ch_idx[i] == sched->sched_grp[group].ch_index) {
				qbman_swp_push_set(swp, sched->sched_grp[group].ch_index, false);
				/*Remove mapping index corresponding to DPCON object*/
				retcode = dpio_remove_static_dequeue_channel(dpio_dev->dpio,
						CMD_PRI_LOW, dpio_dev->token, attr.obj_id);
				if (retcode < 0) {
					ODP_ERR("Error in removing mapping index: Code = %d\n",
										retcode);
					return -1;
				}

				sched->sched_grp[group].ch_index = DPAA2_INVALID_CHANNEL_IDX;
				if (i == dpio_dev->ch_count - 1)
					dpio_dev->ch_idx[i] = DPAA2_INVALID_CHANNEL_IDX;
				else
					dpio_dev->ch_idx[i] = dpio_dev->ch_idx[dpio_dev->ch_count];
				dpio_dev->ch_count--;
				break;
			}
		}
	} else {
		ODP_DBG("PUSH mode is not enabled\n");
		return -1;
	}
	return 0;
}

odp_schedule_group_t odp_schedule_group_create(const char *name,
					       const odp_thrmask_t *mask)
{
	int i, retcode;
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;

	odp_spinlock_lock(&sched->grp_lock);
	for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
		if (sched->sched_grp[i].name[0] == 0) {
			sched->sched_grp[i].conc_dev = odp_get_inactive_conc_dev();
			if (!sched->sched_grp[i].conc_dev) {
				ODP_ERR("ERR while creation of group\n");
				odp_spinlock_unlock(&sched->grp_lock);
				return group;
			}

			retcode = dpaa2_conc_start(sched->sched_grp[i].conc_dev);
			if (DPAA2_FAILURE == retcode) {
				ODP_ERR("Failed Conc - dpaa2_conc_start\n");
				odp_spinlock_unlock(&sched->grp_lock);
				return group;
			}
			strncpy(sched->sched_grp[i].name, name,
					ODP_SCHED_GROUP_NAME_LEN - 1);
			odp_thrmask_copy(sched->sched_grp[i].mask, mask);
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);

	return group;
}

int odp_schedule_group_destroy(odp_schedule_group_t group)
{
	int ret, retcode;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < MAX_SCHED_GRPS &&
		group >= _ODP_SCHED_GROUP_NAMED &&
		sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_zero(sched->sched_grp[group].mask);
		memset(sched->sched_grp[group].name, 0,
				ODP_SCHED_GROUP_NAME_LEN);
		if (sched->sched_grp[group].conc_dev) {
			retcode = dpaa2_conc_stop(sched->sched_grp[group].conc_dev);
			if (DPAA2_FAILURE == retcode) {
				odp_spinlock_unlock(&sched->grp_lock);
				ODP_ERR("Failed Conc - dpaa2_conc_stop\n");
				return -1;
			}
			sched->sched_grp[group].conc_dev = NULL;
		}
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

odp_schedule_group_t odp_schedule_group_lookup(const char *name)
{
	odp_schedule_group_t group = ODP_SCHED_GROUP_INVALID;
	int i;

	odp_spinlock_lock(&sched->grp_lock);

	for (i = _ODP_SCHED_GROUP_NAMED; i < MAX_SCHED_GRPS; i++) {
		if (strcmp(name, sched->sched_grp[i].name) == 0) {
			group = (odp_schedule_group_t)i;
			break;
		}
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return group;
}

int odp_schedule_group_join(odp_schedule_group_t group,
			    const odp_thrmask_t *mask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < MAX_SCHED_GRPS &&
			group >= _ODP_SCHED_GROUP_NAMED &&
			sched->sched_grp[group].name[0] != 0) {
		odp_thrmask_or(sched->sched_grp[group].mask,
			sched->sched_grp[group].mask,
			mask);
		if (sched->sched_grp[group].queues)
			odp_affine_group(group, mask);

		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);

	return ret;
}

int odp_schedule_group_leave(odp_schedule_group_t group,
			     const odp_thrmask_t *mask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < MAX_SCHED_GRPS &&
			group >= _ODP_SCHED_GROUP_NAMED &&
			sched->sched_grp[group].name[0] != 0) {
			odp_thrmask_t leavemask;

			odp_deaffine_group(group, mask);
			odp_thrmask_xor(&leavemask, mask, &sched_mask_all);
			odp_thrmask_and(sched->sched_grp[group].mask,
					sched->sched_grp[group].mask,
					&leavemask);
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);

	return ret;
}

int odp_schedule_group_thrmask(odp_schedule_group_t group,
			       odp_thrmask_t *thrmask)
{
	int ret;

	odp_spinlock_lock(&sched->grp_lock);

	if (group < MAX_SCHED_GRPS &&
		group >= _ODP_SCHED_GROUP_NAMED &&
		sched->sched_grp[group].name[0] != 0) {
		*thrmask = *sched->sched_grp[group].mask;
		ret = 0;
	} else {
		ret = -1;
	}

	odp_spinlock_unlock(&sched->grp_lock);
	return ret;
}

void odp_schedule_prefetch(int num ODP_UNUSED)
{
	return;
}
