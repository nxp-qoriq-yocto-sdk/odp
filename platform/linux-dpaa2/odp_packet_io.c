/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/packet_io.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp/packet.h>
#include <odp_packet_internal.h>
#include <odp_internal.h>
#include <odp/spinlock.h>
#include <odp/shared_memory.h>
#include <odp_packet_dpaa2.h>
#include <odp/config.h>
#include <odp_queue_internal.h>
#include <odp_schedule_internal.h>
#include <odp_crypto_internal.h>
#include <odp_classification_internal.h>
#include <odp_debug_internal.h>
#include <odp/init.h>

#include <string.h>
#include <sys/ioctl.h>
#include <ifaddrs.h>
#include <errno.h>
#include <dpaa2.h>
#include <dpaa2_dev.h>
#include <dpaa2_ethdev.h>
#include <dpaa2_sec_priv.h>
#include <dpaa2_ether.h>
#include <pthread.h>
#include <dpaa2_eth_priv.h>
#include <dpaa2_dev_priv.h>

#include <fsl_dpni.h>
#include <fsl_dpni_cmd.h>
#include <fsl_mc_sys.h>

/* Actual mapped loopback device */
char loop_device[10];

/* VFIO container */
char container[8];

static pktio_table_t *pktio_tbl;

/* pktio pointer entries ( for inlines) */
void *pktio_entry_ptr[ODP_CONFIG_PKTIO_ENTRIES];

int odp_pktio_init_global(void)
{
	char name[ODP_QUEUE_NAME_LEN];
	pktio_entry_t *pktio_entry;
	queue_entry_t *queue_entry;
	odp_queue_t qid;
	int64_t id, retcode;
	odp_shm_t shm;

	shm = odp_shm_reserve("odp_pktio_entries",
				    sizeof(pktio_table_t),
				    0, 0);

	pktio_tbl = odp_shm_addr(shm);
	if (pktio_tbl == NULL) {
		ODP_ERR("Error in allocating pktio table memory\n");
		return -1;
	}

	memset(pktio_tbl, 0, sizeof(pktio_table_t));

	odp_spinlock_init(&pktio_tbl->lock);

	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];

		odp_spinlock_init(&pktio_entry->s.lock);
		odp_spinlock_init(&pktio_entry->s.cls.lock);

		pktio_entry_ptr[id - 1] = pktio_entry;
		/* Create a default output queue for each pktio resource */
		snprintf(name, sizeof(name), "%i-pktio_outq_default", (int)id);
		name[ODP_QUEUE_NAME_LEN-1] = '\0';

		qid = odp_queue_create(name, ODP_QUEUE_TYPE_PKTOUT, NULL);
		if (qid == ODP_QUEUE_INVALID)
			return -1;
		pktio_entry->s.outq_default = qid;

		queue_entry = queue_to_qentry(qid);
		queue_entry->s.pktout = (odp_pktio_t)id;
	}

	/*Scan the device list for Ethernet devices*/
	retcode = odp_dpaa2_scan_device_list(DPAA2_NIC);
	if (!retcode) {
		ODP_ERR("Schedule init failed...\n");
		return -1;
	}
	return 0;
}
int odp_pktio_term_global(void)
{
	pktio_entry_t *pktio_entry;
	int ret;
	int id;

	if (!pktio_tbl)
		return 0;
	for (id = 1; id <= ODP_CONFIG_PKTIO_ENTRIES; ++id) {
		pktio_entry = &pktio_tbl->entries[id - 1];
		if (pktio_entry)
			odp_queue_destroy(pktio_entry->s.outq_default);
	}

	ret = odp_shm_free(odp_shm_lookup("odp_pktio_entries"));
	if (ret < 0)
		ODP_ERR("shm free failed for odp_pktio_entries");

	return ret;
}

int odp_pktio_init_local(void)
{
	return 0;
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

static void lock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_lock(&entry->s.lock);
	odp_spinlock_lock(&entry->s.cls.lock);
}

static void unlock_entry_classifier(pktio_entry_t *entry)
{
	odp_spinlock_unlock(&entry->s.cls.lock);
	odp_spinlock_unlock(&entry->s.lock);
}
void odp_pktio_param_init(odp_pktio_param_t *params)
{
	memset(params, 0, sizeof(odp_pktio_param_t));
}

static void init_pktio_entry(pktio_entry_t *entry)
{
	set_taken(entry);
	entry->s.inq_default = ODP_QUEUE_INVALID;
	memset(&entry->s.pkt_dpaa2, 0, sizeof(entry->s.pkt_dpaa2));
	/* Save pktio parameters, type is the most useful */
	//memcpy(&entry->s.params, params, sizeof(*params));
	pktio_classifier_init(entry);
}

static odp_pktio_t alloc_lock_pktio_entry(void)
{
	odp_pktio_t id;
	pktio_entry_t *entry;
	int i;

	for (i = 0; i < ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = &pktio_tbl->entries[i];
		if (is_free(entry)) {
			lock_entry_classifier(entry);
			if (is_free(entry)) {
				init_pktio_entry(entry);
				init_pktio_cls_rule_list(i);
				id = _odp_cast_scalar(odp_pktio_t, i + 1);
				return id; /* return with entry locked! */
			}
			unlock_entry_classifier(entry);
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

static int init_loop(pktio_entry_t *entry, odp_pktio_t id)
{
	char loopq_name[ODP_QUEUE_NAME_LEN];

	entry->s.type = ODP_PKTIO_TYPE_LOOPBACK;
	snprintf(loopq_name, sizeof(loopq_name), "%" PRIu64 "-pktio_loopq",
		 odp_pktio_to_u64(id));
	entry->s.loopq = odp_queue_create(loopq_name,
					  ODP_QUEUE_TYPE_POLL, NULL);

	if (entry->s.loopq == ODP_QUEUE_INVALID) {
		ODP_ERR("Unable to create queue for loop device\n");
		return -1;
	}

	return 0;
}

odp_pktio_t odp_pktio_open(const char *dev, odp_pool_t pool,
				const odp_pktio_param_t *param)
{
	odp_pktio_t id;
	pktio_entry_t *pktio_entry;
	queue_entry_t *queue_entry;
	struct dpaa2_dev *ndev;
	int ret, loop_dev = 0;
	uint8_t src_mac[ODPH_ETHADDR_LEN];

	ODP_DBG("Allocating dpaa2 pktio\n");

	if (strlen(dev) >= IFNAMSIZ) {
		/* ioctl names limitation */
		ODP_ERR("pktio name %s is too big, limit is %d bytes\n",
			dev, IFNAMSIZ);
		return ODP_PKTIO_INVALID;
	}

	if (!(strcmp(dev, "loop"))) {
		strcpy(container, vfio_container);
		strcpy(loop_device, "LOOP_IF_");
		strtok(container, ".");
		strcat(loop_device, strtok(NULL, "."));

		dev = getenv(loop_device);
		if (!dev) {
			ODP_ERR("Unable to find loop device");
			return ODP_PKTIO_INVALID;
		}
		loop_dev = 1;
		ODP_DBG("%s is mapped to loop device\n", dev);
	}

	ndev = odp_get_dpaa2_eth_dev(dev);
	if (!ndev) {
		ODP_ERR("unable to find dpaa2_dev %s", dev);
		return ODP_PKTIO_INVALID;
	}

	id = alloc_lock_pktio_entry();
	if (id == ODP_PKTIO_INVALID) {
		ODP_ERR("No resources available.\n");
		return ODP_PKTIO_INVALID;
	}
	/* if successful, alloc_pktio_entry() returns with the entry locked */

	pktio_entry = get_pktio_entry(id);
	if (!pktio_entry)
		return ODP_PKTIO_INVALID;

	if (loop_dev) {
		ret = init_loop(pktio_entry, id);
		if (ret)
			return ODP_PKTIO_INVALID;
	}

	pktio_entry->s.pkt_dpaa2.dev = ndev;
	ndev->pktio = (uint64_t)id;
	memcpy(&pktio_entry->s.param, param, sizeof(odp_pktio_param_t));
	ret = setup_pkt_dpaa2(&pktio_entry->s.pkt_dpaa2, (void *)ndev, pool);
	if (ret != 0) {
		unlock_entry_classifier(pktio_entry);
		cleanup_pkt_dpaa2(&pktio_entry->s.pkt_dpaa2);
		free_pktio_entry(id);
		__odp_errno = EEXIST;
		id = ODP_PKTIO_INVALID;
		ODP_ERR("Unable to init any I/O type.\n");
		return id;
	}

	snprintf(pktio_entry->s.name, IFNAMSIZ, "%s", dev);
	unlock_entry_classifier(pktio_entry);

	ret = odp_pktio_mac_addr(id, src_mac, sizeof(src_mac));
	if (ret < 0) {
		ODP_ERR("Error: failed during MAC address get for %s\n", dev);
	} else {
		printf("\nPort %s = Mac %02X.%02X.%02X.%02X.%02X.%02X\n", \
			dev, src_mac[0], src_mac[1], src_mac[2],
			src_mac[3], src_mac[4], src_mac[5]);
	}
	/*Configure tx queue at underlying hardware queues*/
	queue_entry = queue_to_qentry(pktio_entry->s.outq_default);
	queue_entry->s.priv = ndev->tx_vq[0];
	dpaa2_dev_set_vq_handle(ndev->tx_vq[0], (uint64_t)queue_entry->s.handle);

	return id;
}
int odp_pktio_start(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL)
		return -1;
	lock_entry(entry);
	if (entry) {
		ret = start_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (DPAA2_FAILURE == ret) {
			ODP_ERR("Unable to start pktio\n");
			unlock_entry(entry);
			return -1;
		}
	}
	unlock_entry(entry);
	return 0;
}

int odp_pktio_stop(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	int ret;

	entry = get_pktio_entry(pktio);
	if (entry == NULL)
		return -1;
	lock_entry(entry);
	if (entry) {
		ret = close_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (DPAA2_FAILURE == ret) {
			ODP_ERR("Unable to stop pktio\n");
			unlock_entry(entry);
			return -1;
		}
	}
	unlock_entry(entry);
	return 0;
}

int odp_pktio_close(odp_pktio_t id)
{
	pktio_entry_t *entry;
	int res = -1;

	entry = get_pktio_entry(id);
	if (entry == NULL)
		return -1;

	lock_entry(entry);
	if (!is_free(entry)) {
		res  = close_pkt_dpaa2(&entry->s.pkt_dpaa2);
		if (entry->s.type == ODP_PKTIO_TYPE_LOOPBACK)
			res |= odp_queue_destroy(entry->s.loopq);

		res |= free_pktio_entry(id);
	}

	res |= cleanup_pkt_dpaa2(&entry->s.pkt_dpaa2);
	if (res)
		ODP_ERR("pktio cleanup failed\n");

	/*Free allocated memories*/
	dpaa2_data_free((void *)(entry->s.priv));
	dpaa2_data_free((void *)(entry->s.cls.tc_cfg.key_cfg_iova));
	unlock_entry(entry);

	if (res != 0)
		return -1;

	return 0;
}
odp_pktio_t odp_pktio_lookup(const char *dev)
{
	odp_pktio_t id = ODP_PKTIO_INVALID;
	pktio_entry_t *entry;
	int i;

	if (!(strcmp(dev, "loop"))) {
		dev = getenv(loop_device);
		if (!dev) {
			ODP_ERR("Unable to find loop device");
			return ODP_PKTIO_INVALID;
		}
		ODP_DBG("%s is mapped to loop device\n", dev);
	}

	odp_spinlock_lock(&pktio_tbl->lock);

	for (i = 1; i <= ODP_CONFIG_PKTIO_ENTRIES; ++i) {
		entry = get_pktio_entry(_odp_cast_scalar(odp_pktio_t, i));
		if (is_free(entry))
			continue;

		lock_entry(entry);

		if (!is_free(entry) &&
		    strncmp(entry->s.name, dev, IFNAMSIZ) == 0)
			id = _odp_cast_scalar(odp_pktio_t, i);

		unlock_entry(entry);

		if (id != ODP_PKTIO_INVALID)
			break;
	}

	odp_spinlock_unlock(&pktio_tbl->lock);

	return id;
}

extern int32_t dpaa2_eth_recv(struct dpaa2_dev *dev,
			void *vq,
			uint32_t num,
			dpaa2_mbuf_pt mbuf[]);

/**
 * Receive packets using dpaa2
 */
static inline int recv_pkt_dpaa2(pkt_dpaa2_t * const pkt_dpaa2, odp_packet_t pkt_table[],
		unsigned len)
{
	struct dpaa2_dev *dev = pkt_dpaa2->dev;
	static int vq = 0;
	return dpaa2_eth_recv(dev, dev->rx_vq[vq], len, pkt_table);
}

int odp_pktio_recv(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local())
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}

	if (pktio_entry == NULL)
		return -1;

	return recv_pkt_dpaa2(&pktio_entry->s.pkt_dpaa2, pkt_table, len);

}

int odp_pktio_send(odp_pktio_t id, odp_packet_t pkt_table[], int len)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	struct dpaa2_dev *ndev;
	int pkts;

	if (pktio_entry == NULL)
		return -1;

	ndev = pktio_entry->s.pkt_dpaa2.dev;
	pkts = dpaa2_eth_xmit(ndev, ndev->tx_vq[0], len, pkt_table);

	return pkts;
}

int odp_pktio_inq_setdef(odp_pktio_t id, odp_queue_t queue)
{
	pktio_entry_t *pktio_entry = get_pktio_entry(id);
	queue_entry_t *qentry;
	struct dpaa2_dev *ndev;

	if (pktio_entry == NULL || queue == ODP_QUEUE_INVALID)
		return -1;

	qentry = queue_to_qentry(queue);

	queue_lock(qentry);
	lock_entry(pktio_entry);
	if (pktio_entry->s.param.in_mode == ODP_PKTIN_MODE_RECV ||
		(qentry->s.queue_param_set == true &&
		 pktio_entry->s.param.in_mode != ODP_PKTIN_MODE_SCHED) ||
		(qentry->s.queue_param_set == false &&
		pktio_entry->s.param.in_mode != ODP_PKTIN_MODE_POLL)) {
		unlock_entry(pktio_entry);
		queue_unlock(qentry);
		return -1;
	}
	ndev = pktio_entry->s.pkt_dpaa2.dev;
	pktio_entry->s.inq_default = queue;
	qentry->s.pktin = id;
	qentry->s.pktout = id;
	qentry->s.status = QUEUE_STATUS_READY;
	qentry->s.priv = ndev->rx_vq[0];
	dpaa2_dev_set_vq_handle(ndev->rx_vq[0], (uint64_t)qentry->s.handle);
	unlock_entry(pktio_entry);

	if (qentry->s.queue_param_set) {
		odp_schedule_queue(queue, qentry->s.param.sched.prio);
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

	if (qentry->s.queue_param_set && enable_hash) {
		struct dpaa2_dev *ndev;

		ndev = pktio_entry->s.pkt_dpaa2.dev;
		dpaa2_eth_remove_flow_distribution(ndev, 0);
	}

	if (qentry->s.status == QUEUE_STATUS_FREE) {
		queue_unlock(qentry);
		unlock_entry(pktio_entry);
		return -1;
	}

	qentry->s.enqueue = queue_enq_dummy;
	qentry->s.enqueue_multi = queue_enq_multi_dummy;
	qentry->s.status = QUEUE_STATUS_NOTSCHED;
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

int pktout_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer((odp_buffer_t) buf_hdr);
	int len = 1;
	int nbr;
	pktio_entry_t *pktio_entry;
	struct dpaa2_dev *ndev;

	pktio_entry = get_pktio_entry(qentry->s.pktout);
	if (pktio_entry == NULL)
		return -1;
	ndev = pktio_entry->s.pkt_dpaa2.dev;
	nbr = dpaa2_eth_xmit(ndev, qentry->s.priv, len, &pkt);

	return (nbr == len ? 0 : -1);
}

odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *qentry ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return NULL;
}

int pktout_enq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[],
		     int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer((odp_buffer_t) buf_hdr[i]);

	nbr = odp_pktio_send(qentry->s.pktout, pkt_tbl, num);
	return nbr;
}

int pktout_deq_multi(queue_entry_t *qentry ODP_UNUSED,
		     odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
		     int num ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int pktin_enqueue(queue_entry_t *qentry,
		  odp_buffer_hdr_t *buf_hdr)
{
	odp_packet_t pkt = _odp_packet_from_buffer((odp_buffer_t)buf_hdr);
	int len = 1;
	int nbr;

	nbr = dpaa2_eth_xmit_fqid(qentry->s.priv, len, &pkt);

	return (nbr == len ? 0 : -1);
}

odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *qentry)
{
	dpaa2_mbuf_pt pkt_buf[1];
	int pkts;

	pkts = odp_pktio_recv(qentry->s.pktin, pkt_buf, 1);
	if (pkts <= 0)
		return NULL;

	return pkt_buf[0];
}

odp_buffer_hdr_t *sec_dequeue(queue_entry_t *qentry)
{
	dpaa2_mbuf_pt pkt_buf[1];
	int pkts;
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local())
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}
	pkts = dpaa2_sec_recv(crypto_vq->rx_vq, 1, pkt_buf);
	if (pkts <= 0)
		return NULL;

	return pkt_buf[0];
}

int sec_dequeue_multi(queue_entry_t *qentry, odp_buffer_hdr_t *pkt_buf[], int num)
{
	int pkts;
	crypto_vq_t *crypto_vq = qentry->s.priv;

	/* If ctrl+C signal is received, just exit the thread */
	if (odp_unlikely(received_sigint)) {
		if (odp_term_local())
			fprintf(stderr, "error: odp_term_local() failed.\n");
		pthread_exit(NULL);
	}
	pkts = dpaa2_sec_recv(crypto_vq->rx_vq, num, pkt_buf);

	return pkts;
}

int pktin_enq_multi(queue_entry_t *qentry,
		    odp_buffer_hdr_t *buf_hdr[],
		    int num)
{
	odp_packet_t pkt_tbl[QUEUE_MULTI_MAX];
	int nbr;
	int i;

	for (i = 0; i < num; ++i)
		pkt_tbl[i] = _odp_packet_from_buffer((odp_buffer_t)buf_hdr[i]);

	nbr = dpaa2_eth_xmit_fqid(qentry->s.priv,
				num, pkt_tbl);
	return nbr;
}

int pktin_deq_multi(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr[], int num)
{
	int32_t pkts;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	pkts = odp_pktio_recv(qentry->s.pktin, buf_hdr, num);
	if (pkts <= 0)
		goto done;
done:
	return pkts;
}

int odpfsl_pktio_mtu_set(odp_pktio_t id, unsigned mtu)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	unlock_entry(entry);
	return dpaa2_eth_mtu_set(entry->s.pkt_dpaa2.dev, mtu);
}

int odp_pktio_mtu(odp_pktio_t id)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	unlock_entry(entry);
	return dpaa2_eth_mtu_get(entry->s.pkt_dpaa2.dev);
}

int odp_pktio_promisc_mode_set(odp_pktio_t id, odp_bool_t enable)
{
	pktio_entry_t *entry;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}
	if (enable)
		dpaa2_eth_promiscuous_enable(entry->s.pkt_dpaa2.dev);
	else
		dpaa2_eth_promiscuous_disable(entry->s.pkt_dpaa2.dev);
	unlock_entry(entry);
	return 0;
}

int odp_pktio_promisc_mode(odp_pktio_t id)
{
	pktio_entry_t *entry;
	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	unlock_entry(entry);
	return dpaa2_eth_promiscuous_get(entry->s.pkt_dpaa2.dev);
}

int odpfsl_pktio_mac_addr_set(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;

	if (addr_size < ETH_ADDR_LEN)
		return 0;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return 0;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	if (dpaa2_eth_set_mac_addr(ndev, (uint8_t *)mac_addr)
		== DPAA2_SUCCESS)
		return ETH_ADDR_LEN;
	return 0;
}


int odp_pktio_mac_addr(odp_pktio_t id, void *mac_addr, int addr_size)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	if (addr_size < ETH_ADDR_LEN)
		return -1;

	entry = get_pktio_entry(id);
	if (entry == NULL) {
		ODP_DBG("pktio entry %d does not exist\n", id);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_DBG("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	if (dpaa2_eth_get_mac_addr(ndev, (uint8_t *)mac_addr)
		== DPAA2_SUCCESS)
		return ETH_ADDR_LEN;
	return -1;
}

int odp_pktio_stats(odp_pktio_t pktio,
		    odp_pktio_stats_t *stats)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	struct fsl_mc_io *dpni;
	struct dpaa2_dev_priv *dev_priv;
	int32_t  retcode = -1;
	uint64_t value;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		printf("pktio entry %p does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_ERR("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	/*First check for the invalid parameters passed*/
	if (!ndev || (!ndev->priv)) {
		ODP_ERR("Device is NULL");
		return -1;
	}

	dev_priv = ndev->priv;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);

	if (stats) {
		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					    DPNI_CNT_ING_BYTE, &value);
		if (retcode)
			goto error;
		stats->in_octets = value;
		/*total pkt received */
		retcode = dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					   DPNI_CNT_ING_FRAME, &value);
		if (retcode)
			goto error;
		stats->in_ucast_pkts = value;
		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					DPNI_CNT_ING_MCAST_FRAME, &value);
		if (retcode)
			goto error;
		/* less the multicast pkts*/
		stats->in_ucast_pkts -= value;
		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					DPNI_CNT_ING_BCAST_FRAME, &value);
		if (retcode)
			goto error;
		/* less the broadcast pkts*/
		stats->in_ucast_pkts -= value;

		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					DPNI_CNT_ING_FRAME_DROP, &value);
		if (retcode)
			goto error;
		stats->in_discards = value;
		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					    DPNI_CNT_ING_FRAME_DISCARD, &value);
		if (retcode)
			goto error;
		stats->in_errors = value;
		/*retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					    DPNI_CNT_EGR_FRAME, &value);
		if (retcode)
			goto error;
		*/
		retcode = dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				 DPNI_CNT_EGR_BYTE, &value);
		if (retcode)
			goto error;
		stats->out_octets = value;
		retcode =  dpni_get_counter(dpni, CMD_PRI_LOW, dev_priv->token,
					    DPNI_CNT_EGR_FRAME_DISCARD, &value);
		if (retcode)
			goto error;
		stats->out_errors = value;
		stats->out_discards = 0;
		stats->out_ucast_pkts = 0;
	}
	return retcode;
error:
	ODP_ERR("Operation not completed:Error Code = %d\n", retcode);
	return retcode;
}

int odp_pktio_stats_reset(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	struct dpaa2_dev *ndev;
	struct fsl_mc_io *dpni;
	struct dpaa2_dev_priv *dev_priv;
	int32_t  retcode;

	entry = get_pktio_entry(pktio);
	if (entry == NULL) {
		printf("pktio entry %p does not exist\n", pktio);
		return -1;
	}

	lock_entry(entry);

	if (odp_unlikely(is_free(entry))) {
		unlock_entry(entry);
		ODP_ERR("already freed pktio\n");
		return -1;
	}

	ndev = entry->s.pkt_dpaa2.dev;
	unlock_entry(entry);

	/*First check for the invalid parameters passed*/
	if (!ndev || (!ndev->priv)) {
		ODP_ERR("Device is NULL");
		return -1;
	}

	dev_priv = ndev->priv;
	dpni = (struct fsl_mc_io *)(dev_priv->hw);

	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_BCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_BCAST_BYTES, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_MCAST_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_MCAST_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_FRAME_DROP, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_ING_FRAME_DISCARD, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_EGR_FRAME, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_EGR_BYTE, 0);
	if (retcode)
		goto error;
	retcode =  dpni_set_counter(dpni, CMD_PRI_LOW, dev_priv->token,
				    DPNI_CNT_EGR_FRAME_DISCARD, 0);
	if (retcode)
		goto error;
	return retcode;
error:
	ODP_ERR("Operation not completed:Error Code = %d\n", retcode);
	return retcode;
}
