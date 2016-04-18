/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP queue - implementation internal
 */

#ifndef ODP_QUEUE_INTERNAL_H_
#define ODP_QUEUE_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/queue.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/packet_io.h>
#include <odp/align.h>


#define USE_TICKETLOCK

#ifdef USE_TICKETLOCK
#include <odp/ticketlock.h>
#else
#include <odp/spinlock.h>
#endif

#define QUEUE_MULTI_MAX 16

#define QUEUE_STATUS_FREE         0
#define QUEUE_STATUS_READY        1
#define QUEUE_STATUS_NOTSCHED     2
#define QUEUE_STATUS_SCHED        3
#define QUEUE_STATUS_DESTROYED    4

typedef int odp_dev_type_t;
#define ODP_DEV_ANY            0
#define ODP_DEV_NIC            1
#define ODP_DEV_SEC            2

/* forward declaration */
union queue_entry_u;

typedef int (*enq_func_t)(union queue_entry_u *, odp_buffer_hdr_t *);
typedef	odp_buffer_hdr_t *(*deq_func_t)(union queue_entry_u *);

typedef int (*enq_multi_func_t)(union queue_entry_u *,
				odp_buffer_hdr_t **, int);
typedef	int (*deq_multi_func_t)(union queue_entry_u *,
				odp_buffer_hdr_t **, int);

struct queue_entry_s {
#ifdef USE_TICKETLOCK
	odp_ticketlock_t  lock ODP_ALIGNED_CACHE;
#else
	odp_spinlock_t    lock ODP_ALIGNED_CACHE;
#endif

	odp_buffer_hdr_t *head;
	odp_buffer_hdr_t *tail;
	int               status;

	enq_func_t       enqueue ODP_ALIGNED_CACHE;
	deq_func_t       dequeue;
	enq_multi_func_t enqueue_multi;
	deq_multi_func_t dequeue_multi;

	odp_queue_t       handle;
	odp_buffer_t      sched_buf;
	odp_queue_type_t  type;
	odp_queue_param_t param;
	bool		  queue_param_set;
	odp_pktio_t       pktin;
	odp_pktio_t       pktout;
	odp_dev_type_t    dev_type;
	char              name[ODP_QUEUE_NAME_LEN];
	void		*priv;
};

typedef union queue_entry_u {
	struct queue_entry_s s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct queue_entry_s))];
} queue_entry_t;


queue_entry_t *get_qentry(uint32_t queue_id);

int queue_enq(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *queue_deq(queue_entry_t *queue);

int queue_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);
int queue_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);

int queue_enq_dummy(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
int queue_enq_multi_dummy(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			  int num);
int queue_deq_multi_destroy(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
			    int num);

void queue_lock(queue_entry_t *queue);
void queue_unlock(queue_entry_t *queue);

odp_buffer_t queue_sched_buf(odp_queue_t queue);
int queue_sched_atomic(odp_queue_t handle);

static inline uint32_t queue_to_id(odp_queue_t handle)
{
	return _odp_typeval(handle) - 1;
}

static inline odp_queue_t queue_from_id(uint32_t queue_id)
{
	return _odp_cast_scalar(odp_queue_t, queue_id + 1);
}

static inline queue_entry_t *queue_to_qentry(odp_queue_t handle)
{
	uint32_t queue_id;

	queue_id = queue_to_id(handle);
	return get_qentry(queue_id);
}

static inline int queue_is_free(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return queue->s.status == QUEUE_STATUS_FREE;
}

static inline int queue_is_sched(odp_queue_t handle)
{
	queue_entry_t *queue;

	queue = queue_to_qentry(handle);

	return ((queue->s.status == QUEUE_STATUS_SCHED) &&
		(queue->s.pktin != ODP_PKTIO_INVALID));
}

/**
 * Details: It will updated Queue cfg parameter for given queue.
 * Param queue: Input queue whose configuration is to be updated.
 * Param cfg: Pointer to queue configuration which will be updated.
 *
 * Return: Failure(< 0) or Success(0).
*/
int32_t fill_queue_configuration(queue_entry_t *queue,
				struct nadk_vq_param *cfg);
#ifdef __cplusplus
}
#endif

#endif
