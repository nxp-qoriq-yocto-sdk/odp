/*
 *  Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */
/*   Derived from DPDK's rte_kni.c
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2013 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdarg.h>
#include <errno.h>

#include <odp/std_types.h>
#include <odp/hints.h>
#include <nadk_ether.h>
#include <nadk_common.h>
#include <nadk_mpool.h>
#include <nadk_memzone.h>
#include "nadk_kni_common.h"
#include <nadk_kni.h>

#include "nadk_kni_fifo.h"

#define MAX_MBUF_BURST_NUM		8

#define KNI_REQUEST_MBUF_NUM_MAX      32

#define POOL_BUF_LEN 2048

#define KNI_MZ_CHECK(mz) do { if (mz) { NADK_WARN(KNI, "mz"); goto fail; } } while (0)

/**
 * KNI context
 */
struct nadk_kni {
	char name[NADK_KNI_NAMESIZE];        /**< KNI interface name */
	uint16_t group_id;                  /**< Group ID of KNI devices */
	handle_t pktmbuf_pool;   /**< pkt kbuf mempool */
	unsigned kbuf_size;                 /**< kbuf size */

	struct nadk_kni_fifo *tx_q;          /**< TX queue */
	struct nadk_kni_fifo *rx_q;          /**< RX queue */
	struct nadk_kni_fifo *alloc_q;       /**< Allocated kbufs queue */
	struct nadk_kni_fifo *free_q;        /**< To be freed kbufs queue */

	/* For request & response */
	struct nadk_kni_fifo *req_q;         /**< Request queue */
	struct nadk_kni_fifo *resp_q;        /**< Response queue */
	void *sync_addr;                   /**< Req/Resp Mem address */

	odpfsl_knidev_ops_t ops;             /**< operations for request */
	uint8_t in_use:1;                 /**< kni in use */
};

enum kni_ops_status {
	KNI_REQ_NO_REGISTER = 0,
	KNI_REQ_REGISTERED,
};

static void kni_free_mbufs(struct nadk_kni *kni);
static void kni_allocate_mbufs(struct nadk_kni *kni, int num);

static volatile int kni_fd = -1;

static handle_t kni_memzone_reserve(const char *name,
				    size_t len, unsigned flags)
{
	return nadk_memzone_reserve(name, len, flags, 0);
}

/*
 * pktmbuf constructor, given as a callback function to
 * nadk_mempool_create().
 * Set the fields of a packet kbuf to their default values.
 */
void
nadk_pktmbuf_init(void *mp, void *_m)
{
	struct kni_mbuf *m = _m;
	uint32_t buf_len = POOL_BUF_LEN  - sizeof(struct kni_mbuf);

	memset(m, 0, POOL_BUF_LEN);

	/* start of buffer is just after kbuf structure */
	m->buf_addr = (char *)m + sizeof(struct kni_mbuf);
	m->buf_physaddr = nadk_mem_virt2phy(m) +
			sizeof(struct kni_mbuf);
	m->buf_len = (uint16_t)buf_len;

	/* keep some headroom between start of buffer and data */
	m->pkt.data = (char *)m->buf_addr + NADK_PKTMBUF_HEADROOM;

	/* init some constant fields */
	m->type = KNI_MBUF_PKT;
	m->pool = mp;
	m->pkt.nb_segs = 1;
	m->pkt.in_port = 0xff;
}

/**
 * Reset the fields of a packet kbuf to their default values.
 *
 * The given kbuf must have only one segment.
 *
 * @param m
 *   The packet kbuf to be resetted.
 */
static inline void nadk_pktmbuf_reset(struct kni_mbuf *m)
{
	uint32_t buf_ofs;

	m->pkt.next = NULL;
	m->pkt.pkt_len = 0;
	m->pkt.nb_segs = 1;
	m->pkt.in_port = 0xff;

	m->ol_flags = 0;
	buf_ofs = (NADK_PKTMBUF_HEADROOM <= m->buf_len) ?
			NADK_PKTMBUF_HEADROOM : m->buf_len;
	m->pkt.data = (char *)m->buf_addr + buf_ofs;

	m->pkt.data_len = 0;
}

/**
 * Allocate a new kbuf (type is pkt) from a mempool.
 *
 * This new kbuf contains one segment, which has a length of 0. The pointer
 * to data is initialized to have some bytes of headroom in the buffer
 * (if buffer size allows).
 *
 * @param mp
 *   The mempool from which the kbuf is allocated.
 * @return
 *   - The pointer to the new kbuf on success.
 *   - NULL if allocation failed.
 */
struct kni_mbuf *nadk_pktmbuf_alloc(void *mp)
{
	struct kni_mbuf *m = nadk_mpool_getblock(mp, NULL);

	if (!m) {
		NADK_WARN(KNI, "Unable to get buf");
		return NULL;
	}
	nadk_pktmbuf_init(mp, m);
	nadk_pktmbuf_reset(m);
	return m;
}

/**
 * Free a packet kbuf back into its original mempool.
 *
 * Free an kbuf, and all its segments in case of chained buffers. Each
 * segment is added back into its original mempool.
 *
 * @param m
 *   The packet kbuf to be freed.
 */
void nadk_pktmbuf_free(void *_m)
{
	struct kni_mbuf *m = (struct kni_mbuf *)_m;
	struct kni_mbuf *m_next;

	while (m != NULL) {
		m_next = m->pkt.next;
		nadk_mpool_relblock(m->pool, (uint8_t *)m);
		m = m_next;
	}
}

struct nadk_kni *nadk_kni_alloc(void *pktmbuf_pool,
				const struct nadk_kni_conf *conf,
		odpfsl_knidev_ops_t *ops)
{
	int ret;
	struct nadk_kni_device_info dev_info;
	struct nadk_kni *ctx;
	char intf_name[NADK_KNI_NAMESIZE];
#define OBJNAMSIZ 32
	char obj_name[OBJNAMSIZ];
	char mz_name[NADK_MZ_NAMESIZE];
	struct nadk_memzone *mz;

	if (!pktmbuf_pool || !conf || !conf->name[0])
		return NULL;

	NADK_TRACE(KNI);

	/* Check FD and open once */
	if (kni_fd < 0) {
		kni_fd = open("/dev/" KNI_DEVICE, O_RDWR);
		if (kni_fd < 0) {
			NADK_ERR(KNI, "Can not open /dev/%s\n",
				 KNI_DEVICE);
			return NULL;
		}
	}

	snprintf(intf_name, NADK_KNI_NAMESIZE, "%s", conf->name);
	snprintf(mz_name, NADK_MZ_NAMESIZE, "kni_%s", intf_name);
	mz = kni_memzone_reserve(mz_name, sizeof(struct nadk_kni), 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx = (struct nadk_kni *)nadk_memzone_virt(mz);

	if (ctx->in_use) {
		NADK_DBG(KNI, "KNI %s is in use\n", ctx->name);
		goto fail;
	}
	memset(ctx, 0, sizeof(struct nadk_kni));
	if (ops)
		memcpy(&ctx->ops, ops, sizeof(odpfsl_knidev_ops_t));

	NADK_TRACE(KNI);

	memset(&dev_info, 0, sizeof(dev_info));
	dev_info.bus = conf->addr.bus;
	dev_info.devid = conf->addr.devid;
	dev_info.function = conf->addr.function;
	dev_info.vendor_id = conf->id.vendor_id;
	dev_info.device_id = conf->id.device_id;
	dev_info.core_id = conf->core_id;
	dev_info.force_bind = conf->force_bind;
	dev_info.group_id = conf->group_id;
	dev_info.kbuf_size = conf->kbuf_size;

	memcpy(dev_info.macaddr, conf->macaddr, ETH_ADDR_LEN);
	dev_info.mtu = conf->mtu;

	snprintf(ctx->name, NADK_KNI_NAMESIZE, "%s", intf_name);
	snprintf(dev_info.name, NADK_KNI_NAMESIZE, "%s", intf_name);

	/* TX RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_tx_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->tx_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->tx_q, KNI_FIFO_COUNT_MAX);
	dev_info.tx_phys = mz->phys_addr;
	NADK_DBG(KNI, "tx_phys:      0x%016llx, tx_q addr:      0x%p\n",
		 mz->phys_addr, ctx->tx_q);

	/* RX RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_rx_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->rx_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->rx_q, KNI_FIFO_COUNT_MAX);
	dev_info.rx_phys = mz->phys_addr;

	/* ALLOC RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_alloc_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->alloc_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->alloc_q, KNI_FIFO_COUNT_MAX);
	dev_info.alloc_phys = mz->phys_addr;

	/* FREE RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_free_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->free_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->free_q, KNI_FIFO_COUNT_MAX);
	dev_info.free_phys = mz->phys_addr;

	/* Request RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_req_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->req_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->req_q, KNI_FIFO_COUNT_MAX);
	dev_info.req_phys = mz->phys_addr;

	/* Response RING */
	snprintf(obj_name, OBJNAMSIZ, "kni_resp_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->resp_q = (struct nadk_kni_fifo *)nadk_memzone_virt(mz);
	kni_fifo_init(ctx->resp_q, KNI_FIFO_COUNT_MAX);
	dev_info.resp_phys = mz->phys_addr;

	/* Req/Resp sync mem area */
	snprintf(obj_name, OBJNAMSIZ, "kni_sync_%s", intf_name);
	mz = kni_memzone_reserve(obj_name, KNI_FIFO_SIZE, 0);
	KNI_MZ_CHECK(mz == NULL);
	ctx->sync_addr = (void *)nadk_memzone_virt(mz);
	dev_info.sync_va = ctx->sync_addr;
	dev_info.sync_phys = mz->phys_addr;

	/* MBUF mempool */
	dev_info.kbuf_va = (void *)nadk_get_mpool_virtaddr(pktmbuf_pool);
	dev_info.kbuf_phys = nadk_get_mpool_phyaddr(pktmbuf_pool);
	dev_info.kbuf_mem_size = nadk_mpool_size(pktmbuf_pool);
	NADK_WARN(KNI, "memsize = 0x%lu, vaddr =0x%lu, phy = 0x%lu",
		  dev_info.kbuf_mem_size, (uint64_t)dev_info.kbuf_va,
		dev_info.kbuf_phys);
	ctx->pktmbuf_pool = pktmbuf_pool;
	ctx->group_id = conf->group_id;
	ctx->kbuf_size = conf->kbuf_size;

	ret = ioctl(kni_fd, NADK_KNI_IOCTL_CREATE, &dev_info);
	KNI_MZ_CHECK(ret < 0);

	ctx->in_use = 1;
	kni_allocate_mbufs(ctx, KNI_REQUEST_MBUF_NUM_MAX);
	return ctx;

fail:
	perror("nadk_kni_alloc");
	return NULL;
}

static void
kni_free_fifo(struct nadk_kni_fifo *fifo)
{
	int ret;
	struct kni_mbuf *pkt;

	do {
		ret = kni_fifo_get(fifo, (void **)&pkt, 1);
		if (ret)
			nadk_pktmbuf_free(pkt);
	} while (ret);
}

int
nadk_kni_release(struct nadk_kni *kni)
{
	struct nadk_kni_device_info dev_info;

	if (!kni || !kni->in_use)
		return -1;

	snprintf(dev_info.name, sizeof(dev_info.name), "%s", kni->name);
	if (ioctl(kni_fd, NADK_KNI_IOCTL_RELEASE, &dev_info) < 0) {
		NADK_DBG(KNI, "Fail to release kni device\n");
		return -1;
	}

	/* kbufs in all fifo should be released, except request/response */
	kni_free_fifo(kni->tx_q);
	kni_free_fifo(kni->rx_q);
	kni_free_fifo(kni->alloc_q);
	kni_free_fifo(kni->free_q);
	memset(kni, 0, sizeof(struct nadk_kni));

	return 0;
}

int
nadk_kni_handle_request(struct nadk_kni *kni)
{
	unsigned ret;
	struct nadk_kni_request *req;

	if (kni == NULL)
		return -1;

	/* Get request kbuf */
	ret = kni_fifo_get(kni->req_q, (void **)&req, 1);
	if (ret != 1)
		return 0; /* It is OK of can not getting the request kbuf */

	if (req != kni->sync_addr)
		NADK_ERR(KNI, "Wrong req pointer %p\n", req);

	/* Analyze the request and call the relevant actions for it */
	switch (req->req_id) {
	case NADK_KNI_REQ_CHANGE_MTU: /* Change MTU */
		if (kni->ops.change_mtu)
			req->result = kni->ops.change_mtu(kni->ops.port_id,
							req->new_mtu);
		break;
	case NADK_KNI_REQ_CFG_NETWORK_IF: /* Set network interface up/down */
		if (kni->ops.config_network_if)
			req->result = kni->ops.config_network_if(\
					kni->ops.port_id, req->if_up);
		break;
	case NADK_KNI_REQ_CHANGE_MAC_ADDR: /* Change MAC Address */
		if (kni->ops.config_mac_address)
			req->result = kni->ops.config_mac_address(kni->ops.port_id,
							req->mac_addr);
		break;
	case NADK_KNI_REQ_CHANGE_PROMISC: /* Change PROMISCUOUS MODE */
		if (kni->ops.config_promiscusity)
			req->result = kni->ops.config_promiscusity(kni->ops.port_id,
							req->promiscusity);
		break;
	default:
		NADK_WARN(KNI, "Unknown request id %u\n", req->req_id);
		req->result = -1;
		break;
	}

	/* Construct response kbuf and put it back to resp_q */
	ret = kni_fifo_put(kni->resp_q, (void **)&req, 1);
	if (ret != 1) {
		NADK_WARN(KNI, "Fail to put the muf back to resp_q\n");
		return -1; /* It is an error of can't putting the kbuf back */
	}

	return 0;
}

unsigned
nadk_kni_tx_burst(struct nadk_kni *kni, struct kni_mbuf **kbufs, unsigned num)
{
	unsigned ret = kni_fifo_put(kni->rx_q, (void **)kbufs, num);

	/* Get kbufs from free_q and then free them */
	kni_free_mbufs(kni);

	return ret;
}

unsigned
nadk_kni_rx_burst(struct nadk_kni *kni, struct kni_mbuf **kbufs, unsigned num)
{
	unsigned ret = kni_fifo_get(kni->tx_q, (void **)kbufs, num);

	if (odp_likely(ret))
		kni_allocate_mbufs(kni, ret);
	return ret;
}

static void
kni_free_mbufs(struct nadk_kni *kni)
{
	int i, ret;
	struct kni_mbuf *pkts[MAX_MBUF_BURST_NUM];

	ret = kni_fifo_get(kni->free_q, (void **)pkts, MAX_MBUF_BURST_NUM);
	if (odp_likely(ret)) {
		for (i = 0; i < ret; i++)
			nadk_pktmbuf_free(pkts[i]);
	}
}

static void
kni_allocate_mbufs(struct nadk_kni *kni, int num)
{
	int i, ret;
	struct kni_mbuf *pkts[KNI_FIFO_SIZE];

	NADK_TRACE(KNI);

	/* Check if pktmbuf pool has been configured */
	if (kni->pktmbuf_pool == NULL) {
		NADK_WARN(KNI, "No valid mempool for allocating kbufs\n");
		return;
	}

	for (i = 0; i < num; i++) {
		pkts[i] = nadk_pktmbuf_alloc(kni->pktmbuf_pool);
		if (odp_unlikely(pkts[i] == NULL)) {
			/* Out of memory */
			NADK_WARN(KNI, "Out of memory\n");
			break;
		}
	}

	/* No pkt kbuf alocated */
	if (i == 0)
		return;

	ret = kni_fifo_put(kni->alloc_q, (void **)pkts, i);

	/* Check if any kbufs not put into alloc_q, and then free them */
	if (ret && ret < i) {
		int j;

		for (j = ret; j < i; j++)
			nadk_pktmbuf_free(pkts[j]);
	}
}

/* It is deprecated and just for backward compatibility */
uint8_t
nadk_kni_get_port_id(struct nadk_kni *kni)
{
	if (!kni)
		return ~0x0;

	return kni->ops.port_id;
}

struct nadk_kni *
nadk_kni_get(const char *name)
{
	struct nadk_kni *kni;
	void_t *mz;
	char mz_name[NADK_MZ_NAMESIZE];

	if (!name || !name[0])
		return NULL;

	snprintf(mz_name, NADK_MZ_NAMESIZE, "kni_%s", name);
	mz = (void *)nadk_memzone_lookup(mz_name);
	if (!mz)
		return NULL;

	kni = (struct nadk_kni *)nadk_memzone_virt(mz);
	if (!kni->in_use)
		return NULL;

	return kni;
}

/*
 * It is deprecated and just for backward compatibility.
 */
struct nadk_kni *
nadk_kni_info_get(uint8_t port_id)
{
	char name[NADK_MZ_NAMESIZE];

	if (port_id >= ODPFSL_MAX_ETHPORTS)
		return NULL;

	snprintf(name, NADK_MZ_NAMESIZE, "vEth%u", port_id);

	return nadk_kni_get(name);
}

static enum kni_ops_status
kni_check_request_register(odpfsl_knidev_ops_t *ops)
{
	/* check if KNI request ops has been registered*/
	if (NULL == ops)
		return KNI_REQ_NO_REGISTER;

	if ((NULL == ops->change_mtu) && (NULL == ops->config_network_if))
		return KNI_REQ_NO_REGISTER;

	return KNI_REQ_REGISTERED;
}

int
nadk_kni_register_handlers(struct nadk_kni *kni, odpfsl_knidev_ops_t *ops)
{
	enum kni_ops_status req_status;

	if (NULL == ops) {
		NADK_ERR(KNI, "Invalid KNI request operation.\n");
		return -1;
	}

	if (NULL == kni) {
		NADK_ERR(KNI, "Invalid kni info.\n");
		return -1;
	}

	req_status = kni_check_request_register(&kni->ops);
	if (KNI_REQ_REGISTERED == req_status) {
		NADK_ERR(KNI, "The KNI request operation"
					"has already registered.\n");
		return -1;
	}

	memcpy(&kni->ops, ops, sizeof(odpfsl_knidev_ops_t));
	return 0;
}

int
nadk_kni_unregister_handlers(struct nadk_kni *kni)
{
	if (NULL == kni) {
		NADK_ERR(KNI, "Invalid kni info.\n");
		return -1;
	}

	kni->ops.change_mtu = NULL;
	kni->ops.config_network_if = NULL;
	kni->ops.config_mac_address = NULL;
	kni->ops.config_promiscusity = NULL;
	return 0;
}

void
nadk_kni_close(void)
{
	if (kni_fd < 0)
		return;

	close(kni_fd);
	kni_fd = -1;
}
