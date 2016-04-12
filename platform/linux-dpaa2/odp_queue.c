/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/queue.h>
#include <odp_queue_internal.h>
#include <odp/std_types.h>
#include <odp/align.h>
#include <odp/buffer.h>
#include <odp_buffer_internal.h>
#include <odp_pool_internal.h>
#include <odp_internal.h>
#include <odp/shared_memory.h>
#include <odp/schedule.h>
#include <odp_schedule_internal.h>
#include <odp/config.h>
#include <odp_packet_io_internal.h>
#include <odp_packet_io_queue.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>
#include <odp/sync.h>

#include <nadk_hwq.h>

#ifdef USE_TICKETLOCK
#include <odp/ticketlock.h>
#define LOCK(a)      odp_ticketlock_lock(a)
#define UNLOCK(a)    odp_ticketlock_unlock(a)
#define LOCK_INIT(a) odp_ticketlock_init(a)
#else
#include <odp/spinlock.h>
#define LOCK(a)      odp_spinlock_lock(a)
#define UNLOCK(a)    odp_spinlock_unlock(a)
#define LOCK_INIT(a) odp_spinlock_init(a)
#endif

#include <string.h>


typedef struct queue_table_t {
	queue_entry_t  queue[ODP_CONFIG_QUEUES];
} queue_table_t;

static queue_table_t *queue_tbl;


queue_entry_t *get_qentry(uint32_t queue_id)
{
	return &queue_tbl->queue[queue_id];
}

static void queue_init(queue_entry_t *queue, const char *name,
		       odp_queue_type_t type, odp_queue_param_t *param)
{
	if ((!queue) || (!name)) {
		ODP_ERR("Either queue or name is NULL");
		return;
	}

	strncpy(queue->s.name, name, ODP_QUEUE_NAME_LEN - 1);
	queue->s.type = type;

	switch (type) {
	case ODP_QUEUE_TYPE_POLL:
		queue->s.enqueue = queue_enq;
		queue->s.dequeue = queue_deq;
		queue->s.enqueue_multi = queue_enq_multi;
		queue->s.dequeue_multi = queue_deq_multi;
		break;
	case ODP_QUEUE_TYPE_PKTIN:
		queue->s.enqueue = pktin_enqueue;
		queue->s.dequeue = pktin_dequeue;
		queue->s.enqueue_multi = pktin_enq_multi;
		queue->s.dequeue_multi = pktin_deq_multi;
		if (param) {
			queue->s.queue_param_set = true;
		}
		break;
	case ODP_QUEUE_TYPE_PKTOUT:
		queue->s.enqueue = pktout_enqueue;
		queue->s.dequeue = pktout_dequeue;
		queue->s.enqueue_multi = pktout_enq_multi;
		queue->s.dequeue_multi = pktout_deq_multi;
		break;
	case ODP_QUEUE_TYPE_SCHED:
		queue->s.enqueue = queue_enq;
		queue->s.dequeue = queue_deq;
		queue->s.enqueue_multi = queue_enq_multi;
		queue->s.dequeue_multi = queue_deq_multi;
		queue->s.queue_param_set = true;
		break;
	default:
		ODP_ERR("Invalid type of queue\n");
		return;
	}

	if (param) {
		memcpy(&queue->s.param, param, sizeof(odp_queue_param_t));
	} else {
		if (type == ODP_QUEUE_TYPE_SCHED)
			queue->s.param.sched.group = ODP_SCHED_GROUP_ALL;
		else
			queue->s.param.sched.group = ODP_SCHED_GROUP_INVALID;
		queue->s.param.sched.prio = ODP_SCHED_PRIO_DEFAULT;
		queue->s.param.sched.sync = ODP_SCHED_SYNC_NONE;
		queue->s.param.sched.lock_count = 0;
		queue->s.param.context = NULL;
	}

	queue->s.head = NULL;
	queue->s.tail = NULL;
	queue->s.sched_buf = ODP_BUFFER_INVALID;
}


int odp_queue_init_global(void)
{
	uint32_t i;
	odp_shm_t shm;

	ODP_DBG("Queue init ... ");

	shm = odp_shm_reserve("odp_queues",
			      sizeof(queue_table_t),
			      0/*sizeof(queue_entry_t)*/, 0);

	queue_tbl = odp_shm_addr(shm);

	if (queue_tbl == NULL)
		return -1;

	memset(queue_tbl, 0, sizeof(queue_table_t));

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		/* init locks */
		queue_entry_t *queue = get_qentry(i);
		LOCK_INIT(&queue->s.lock);
		queue->s.handle = queue_from_id(i);
	}

	ODP_DBG("done\n");
	ODP_DBG("Queue init global\n");
	ODP_DBG("  struct queue_entry_s size %zu\n",
		sizeof(struct queue_entry_s));
	ODP_DBG("  queue_entry_t size        %zu\n",
		sizeof(queue_entry_t));
	ODP_DBG("\n");

	return 0;
}

int odp_queue_term_global(void)
{
	int ret = 0;
	int rc = 0;
	queue_entry_t *queue;
	int i;

	if (!queue_tbl)
		return 0;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];
		if (queue) {
			LOCK(&queue->s.lock);
			if (queue->s.status != QUEUE_STATUS_FREE) {
				ODP_ERR("Not destroyed queue: %s\n", queue->s.name);
				rc = -1;
			}
			UNLOCK(&queue->s.lock);
		}
	}

	ret = odp_shm_free(odp_shm_lookup("odp_queues"));
	if (ret < 0) {
		ODP_ERR("shm free failed for odp_queues");
		rc = -1;
	}

	return rc;
}

odp_queue_type_t odp_queue_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.type;
}

odp_schedule_sync_t odp_queue_sched_type(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync;
}

odp_schedule_prio_t odp_queue_sched_prio(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.prio;
}

odp_schedule_group_t odp_queue_sched_group(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.param.sched.group;
}

odp_queue_t odp_queue_create(const char *name, odp_queue_type_t type,
			     odp_queue_param_t *param)
{
	uint32_t i;
	queue_entry_t *queue;
	odp_queue_t handle = ODP_QUEUE_INVALID;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue = &queue_tbl->queue[i];

		if (queue->s.status != QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);
		if (queue->s.status == QUEUE_STATUS_FREE) {
			queue_init(queue, name, type, param);

			if (type == ODP_QUEUE_TYPE_SCHED ||
			    type == ODP_QUEUE_TYPE_PKTIN)
				queue->s.status = QUEUE_STATUS_NOTSCHED;
			else
				queue->s.status = QUEUE_STATUS_READY;

			handle = queue->s.handle;
			UNLOCK(&queue->s.lock);
			break;
		}
		UNLOCK(&queue->s.lock);
	}

	/* create a SW queue for SCHED/POLL queues */
	if ((type == ODP_QUEUE_TYPE_SCHED) || (type == ODP_QUEUE_TYPE_POLL)) {
		/* Get a NADK Frame Queue */
		void *sw_queue = nadk_get_frameq();

		if (!sw_queue) {
			ODP_ERR("Unable to allocate NADK queue\n");
			queue->s.status = QUEUE_STATUS_FREE;
			return ODP_QUEUE_INVALID;
		}

		if (type == ODP_QUEUE_TYPE_SCHED) {
			struct nadk_vq_param vq_param;
			int ret;

			/* Attach the queue to CONC */
			memset(&vq_param, 0, sizeof(struct nadk_vq_param));
			vq_param.conc_dev = odp_get_conc_from_grp(param->sched.group);
			vq_param.prio = ODP_SCHED_PRIO_DEFAULT;
			ret = nadk_attach_frameq_to_conc(sw_queue, &vq_param);
			if (NADK_FAILURE == ret) {
				ODP_ERR("Fail to setup RX VQ with CONC\n");
				queue->s.status = QUEUE_STATUS_FREE;
				nadk_put_frameq(sw_queue);
				return ODP_QUEUE_INVALID;
			}
			ret = odp_add_queue_to_group(param->sched.group);
			if (ret == 1)
				odp_affine_group(param->sched.group, NULL);
		}
		/* Store the handle for future reference */
		nadk_dev_set_vq_handle(sw_queue, (uint64_t)handle);

		/*Store the sw_queue in queue_entry priv*/
		queue->s.priv = sw_queue;
	}
	return handle;
}

int odp_queue_destroy(odp_queue_t handle)
{
	int ret;
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	LOCK(&queue->s.lock);
	if (queue->s.status == QUEUE_STATUS_FREE) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue_destroy: queue \"%s\" already free\n",
			queue->s.name);
		return -1;
	}
	if (queue->s.head != NULL) {
		UNLOCK(&queue->s.lock);
		ODP_ERR("queue_destroy: queue \"%s\" not empty\n",
			queue->s.name);
		return -1;
	}

	if (queue->s.queue_param_set) {
		ret = odp_sub_queue_to_group(queue->s.param.sched.group);
		if (!ret)
			odp_deaffine_group(queue->s.param.sched.group, NULL);
		queue->s.queue_param_set = false;
	}

	queue->s.enqueue = queue_enq_dummy;
	queue->s.enqueue_multi = queue_enq_multi_dummy;

	switch (queue->s.status) {
	case QUEUE_STATUS_READY:
		queue->s.status = QUEUE_STATUS_FREE;
		queue->s.head = NULL;
		queue->s.tail = NULL;
		break;
	case QUEUE_STATUS_SCHED:
		/*
		 * Override dequeue_multi to destroy queue when it will
		 * be scheduled next time.
		 */
		queue->s.status = QUEUE_STATUS_DESTROYED;
		queue->s.dequeue_multi = queue_deq_multi_destroy;
		break;
	case QUEUE_STATUS_NOTSCHED:
		/* Queue won't be scheduled anymore */
		if (queue->s.sched_buf != ODP_BUFFER_INVALID)
			odp_buffer_free(queue->s.sched_buf);
		queue->s.sched_buf = ODP_BUFFER_INVALID;
		queue->s.status = QUEUE_STATUS_FREE;
		queue->s.head = NULL;
		queue->s.tail = NULL;
		break;
	default:
		ODP_ABORT("Unexpected queue status\n");
	}

	UNLOCK(&queue->s.lock);

	return 0;
}

odp_buffer_t queue_sched_buf(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	return queue->s.sched_buf;
}


int queue_sched_atomic(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);

	return queue->s.param.sched.sync == ODP_SCHED_SYNC_ATOMIC;
}

int odp_queue_context_set(odp_queue_t handle, void *context)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	odp_sync_stores();
	queue->s.param.context = context;
	odp_sync_stores();
	return 0;
}

void *odp_queue_context(odp_queue_t handle)
{
	queue_entry_t *queue;
	queue = queue_to_qentry(handle);
	return queue->s.param.context;
}

odp_queue_t odp_queue_lookup(const char *name)
{
	uint32_t i;

	for (i = 0; i < ODP_CONFIG_QUEUES; i++) {
		queue_entry_t *queue = &queue_tbl->queue[i];

		if (queue->s.status == QUEUE_STATUS_FREE)
			continue;

		LOCK(&queue->s.lock);
		if (strcmp(name, queue->s.name) == 0) {
			/* found it */
			UNLOCK(&queue->s.lock);
			return queue->s.handle;
		}
		UNLOCK(&queue->s.lock);
	}

	return ODP_QUEUE_INVALID;
}


int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr)
{
	int num_xmit;

	num_xmit = nadk_hwq_xmit(queue->s.priv, &buf_hdr, 1);
	return (num_xmit == 1 ? 0 : -1);
}

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	return nadk_hwq_xmit(queue->s.priv, buf_hdr, num);
}

int queue_enq_dummy(queue_entry_t *queue ODP_UNUSED,
		    odp_buffer_hdr_t *buf_hdr ODP_UNUSED)
{
	return -1;
}

int queue_enq_multi_dummy(queue_entry_t *queue ODP_UNUSED,
			  odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
			  int num ODP_UNUSED)
{
	return -1;
}

int odp_queue_enq_multi(odp_queue_t handle, const odp_event_t ev[], int num)
{
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	queue_entry_t *queue;
	int i;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	for (i = 0; i < num; i++)
		buf_hdr[i] = odp_buf_to_hdr(odp_buffer_from_event(ev[i]));

	return queue->s.enqueue_multi(queue, buf_hdr, num);
}


int odp_queue_enq(odp_queue_t handle, odp_event_t ev)
{
	odp_buffer_hdr_t *buf_hdr;
	queue_entry_t *queue;

	queue   = queue_to_qentry(handle);
	buf_hdr = odp_buf_to_hdr(odp_buffer_from_event(ev));

	return queue->s.enqueue(queue, buf_hdr);
}


odp_buffer_hdr_t *queue_deq(queue_entry_t *queue)
{
	odp_buffer_hdr_t *buf_hdr[1] = {NULL};

	nadk_hwq_recv(queue->s.priv, buf_hdr, 1);
	return buf_hdr[0];
}

int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num)
{
	return nadk_hwq_recv(queue->s.priv, buf_hdr, num);
}

int queue_deq_multi_destroy(queue_entry_t *queue,
			    odp_buffer_hdr_t *buf_hdr[] ODP_UNUSED,
			    int num ODP_UNUSED)
{
	LOCK(&queue->s.lock);

	if (queue->s.sched_buf != ODP_BUFFER_INVALID)
		odp_buffer_free(queue->s.sched_buf);
	queue->s.sched_buf = ODP_BUFFER_INVALID;
	queue->s.status = QUEUE_STATUS_FREE;
	queue->s.head = NULL;
	queue->s.tail = NULL;

	UNLOCK(&queue->s.lock);

	return 0;
}

int odp_queue_deq_multi(odp_queue_t handle, odp_event_t events[], int num)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr[QUEUE_MULTI_MAX];
	int i, ret;

	if (num > QUEUE_MULTI_MAX)
		num = QUEUE_MULTI_MAX;

	queue = queue_to_qentry(handle);

	ret = queue->s.dequeue_multi(queue, buf_hdr, num);

	for (i = 0; i < ret; i++)
		events[i] = odp_buffer_to_event(buf_hdr[i]);

	return ret;
}


odp_event_t odp_queue_deq(odp_queue_t handle)
{
	queue_entry_t *queue;
	odp_buffer_hdr_t *buf_hdr;

	queue   = queue_to_qentry(handle);
	buf_hdr = queue->s.dequeue(queue);

	if (buf_hdr)
		return odp_buffer_to_event(buf_hdr);

	return ODP_EVENT_INVALID;
}


void queue_lock(queue_entry_t *queue)
{
	LOCK(&queue->s.lock);
}


void queue_unlock(queue_entry_t *queue)
{
	UNLOCK(&queue->s.lock);
}

int32_t fill_queue_configuration(queue_entry_t *queue,
					struct nadk_vq_param *cfg)
{
	memset(cfg, 0, sizeof(struct nadk_vq_param));

	switch (queue->s.type) {
	case ODP_QUEUE_TYPE_SCHED:
	case ODP_QUEUE_TYPE_POLL:
	case ODP_QUEUE_TYPE_PKTIN:
		if (queue->s.queue_param_set) {
			cfg->prio        = queue->s.param.sched.prio;
			cfg->sync        = queue->s.param.sched.sync;
			cfg->conc_dev    = odp_get_conc_from_grp(queue->s.param.sched.group);
		}
		break;
	default:
		ODP_ERR("Invalid type of error");
		return -1;
	}
	return 0;
}
void odp_queue_param_init(odp_queue_param_t *params)
{
	memset(params, 0, sizeof(odp_queue_param_t));
}
void odp_schedule_order_lock(unsigned lock_index ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}
void odp_schedule_order_unlock(unsigned lock_index ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
}
int odp_queue_lock_count(odp_queue_t handle ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}
