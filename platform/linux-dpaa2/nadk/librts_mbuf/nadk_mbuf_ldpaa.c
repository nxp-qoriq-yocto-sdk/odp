/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_mbuf_ldpaa.c
 * @brief		Buffer management library services for NADK based for LS
 */

/* Standard header files */
#include <errno.h>
#include <pthread.h>

/* NADK header files */
#include <nadk_common.h>
#include <nadk_mbuf_priv.h>
#include <nadk_dev_priv.h>
#include <nadk_io_portal_priv.h>
#ifdef NADK_AIOP_CI_DEVICE
#include <nadk_aiop.h>
#endif
#include <nadk_vq.h>
#include <nadk_memconfig.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

#include <odp/plat/event_types.h>
#include <odp/plat/packet_annot.h>
#include <odp_buffer_internal.h>
#include <odp_align_internal.h>
#include <odp/config.h>
#include <odp_packet_internal.h>

uint32_t nadk_mbuf_head_room;

/*!
 * @details	Initialize a buffer pool list. This API should be called
 *		when IO context is affined to the thread.
 * @param[in,out]	bp_list_cfg -  Buffer pool list configuration.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
void *nadk_mbuf_pool_list_init(
		struct nadk_bp_list_cfg *bp_list_cfg)
{
	struct qbman_release_desc releasedesc;
	struct nadk_bp_list *bp_list;
	struct qbman_swp *swp;
	int pool_index;
	uint64_t bufs[NADK_MBUF_MAX_ACQ_REL];
	int num_pools;

	NADK_TRACE(BUF);

	if (!thread_io_info.dpio_dev) {
		NADK_ERR(BUF, "No IO context available");
		return NULL;
	}

	/* Check if number of pools are more than the maximum supported */
	num_pools = bp_list_cfg->num_buf_pools;
	if (num_pools > NADK_MAX_BUF_POOLS) {
		NADK_ERR(BUF, "Invalid number of pools");
		return NULL;
	}

	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		if (bp_list_cfg->buf_pool[pool_index].size <
			NADK_MBUF_MIN_SIZE) {
			NADK_ERR(BUF, "Invalid size of a pool");
			return NULL;
		}
	}

	/* Create the buffer pool list, initializing dpbp, bufmem etc */
	bp_list = nadk_mbuf_create_bp_list(bp_list_cfg);
	if (!bp_list) {
		NADK_ERR(BUF, "Unable to create the bp list");
		return NULL;
	}

	swp = thread_io_info.dpio_dev->sw_portal;

	/* Fill the pool, release the buffers to BMAN */
	for (pool_index = 0; pool_index < num_pools; pool_index++) {
		uint32_t num_bufs, buf_size, count;
		uint8_t *h_bpool_mem;
		nadk_mbuf_pt	mbuf;
		uint16_t bpid;
		int ret;

		num_bufs = bp_list->buf_pool[pool_index].num_bufs;
		buf_size = bp_list->buf_pool[pool_index].meta_data_size +
				nadk_mbuf_sw_annotation +
				NADK_MBUF_HW_ANNOTATION +
				nadk_mbuf_head_room +
				bp_list->buf_pool[pool_index].size;

		bpid = bp_list->buf_pool[pool_index].bpid;
		h_bpool_mem = bp_list->buf_pool[pool_index].h_bpool_mem;

		/* Create a release descriptor required for releasing
		 * buffers into BMAN */
		qbman_release_desc_clear(&releasedesc);
		qbman_release_desc_set_bpid(&releasedesc, bpid);

		for (count = 0; count < num_bufs; ) {
			uint8_t i, rel;
			/* In BMAN we can release buffers maximum 7 at a time.
			 * This takes care of it. (hardware stockpile)*/
			rel = (num_bufs - count) > NADK_MBUF_MAX_ACQ_REL ?
				NADK_MBUF_MAX_ACQ_REL : (num_bufs - count);
			for (i = 0; i < rel; i++) {
				/* Carve out buffers from complete memory
				 * chunk allocated from mempool */
				/* TODO Check of dma memory alignment
				 * (for performance) */
				mbuf = (nadk_mbuf_pt)h_bpool_mem;
				bufs[i] = (uint64_t)(h_bpool_mem) +
					bp_list->buf_pool[pool_index].meta_data_size;

				memset(mbuf, 0, sizeof(odp_packet_hdr_t));
				mbuf->priv_meta_off = NADK_MBUF_HW_ANNOTATION +
							NADK_MBUF_SW_ANNOTATION;
				mbuf->head	= (uint8_t *)bufs[i] + mbuf->priv_meta_off;
				mbuf->data	= mbuf->head + nadk_mbuf_head_room;
				mbuf->bpid	= bpid;
				mbuf->end_off	= bpid_info[mbuf->bpid].size;
				mbuf->frame_len  = mbuf->end_off - nadk_mbuf_head_room;
				mbuf->tot_frame_len = mbuf->frame_len;
				_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);
				if (bpid_info[bpid].odp_user_area)
					mbuf->user_priv_area = h_bpool_mem + sizeof(odp_packet_hdr_t);

				mbuf->atomic_cntxt = INVALID_CNTXT_PTR;
				NADK_DBG2(BUF, "Releasing memory: %llx",
					bufs[i]);
				h_bpool_mem += buf_size;
				NADK_MODIFY_VADDR_TO_IOVA(bufs[i], uint64_t);

			}
			NADK_INFO(BUF, "QBMan SW Portal 0x%p\n", swp);
			do {
				/* Release buffer/s into the BMAN */
				ret = qbman_swp_release(swp, &releasedesc,
						bufs, rel);
			} while (ret == -EBUSY);
			count += rel;
			NADK_DBG(BUF, "Released %d buffers\n", count);
		}

		NADK_INFO(BUF, "Created %u bufs with bpid: %d",
			num_bufs, bpid);
	}

	/* Add into the global buffer pool list. We will keep all the
	 * buffer pool id's, sizes and the memory taken from the memory pool
	 * in this global bp list. */
	nadk_add_bp_list(bp_list);

	return (void *)bp_list;
}


/*!
 * @details	Allocate NADK buffer from given buffer pool.
 *
 * @param[in]	bpid - buffer pool id (which was filled in by NADK at
 *		'nadk_create_buf_pool_list'
 *
 * @param[in]	length - if single buffer length is greater than the buffer size
 *		it may allocate SG list.
 *
 * @returns	nadk buffer on success; NULL on failure.
 *
 */
nadk_mbuf_pt nadk_mbuf_alloc_from_bpid(
		uint16_t bpid,
		int length)
{
	nadk_mbuf_pt mbuf = NULL;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	int ret = 0;
	uint64_t buf;
	struct bpsp *pool = th_bpsp_info[bpid];

	NADK_TRACE(BUF);

	/* Check for valid bpid. If size is 0 at the input bpid,
	 * impiles it is invalid */
	if (!bpid_info[bpid].size) {
		NADK_ERR(BUF, "Please provide a valid bpid");
		return NULL;
	}

	/* Allocate SG NADK buffer if sg support is enabled and length
	than the buffer size */
	if ((unsigned)length > bpid_info[bpid].size) {
			if (sg_support)
				return nadk_mbuf_alloc_sg_from_bpid(bpid, length);
			else
				return NULL;
	}
	if (bpid_info[bpid].stockpile) {
		/*if the stockpile for this bpid for this thread is not available,
		it will allocate the stockpile for this thread */
		if (odp_unlikely(!pool)) {
			th_bpsp_info[bpid] = nadk_calloc(NULL, 1,
						sizeof(struct bpsp), 0);
			if (!th_bpsp_info[bpid]) {
				NADK_ERR(BUF, "Fail to create stockpile pool memory");
				return NULL;
			}
			pool = th_bpsp_info[bpid];

			pool->size = bpid_info[bpid].size;
			pool->sp = nadk_calloc(NULL, BMAN_STOCKPILE_SZ, 8, 0);
			if (!pool->sp) {
				NADK_ERR(BUF, "Fail to allocate stockpile memory");
				nadk_free(pool);
				th_bpsp_info[bpid] = NULL;
				return NULL;
			}
			pool->sp_fill = 0;
		}

		/* Only need a h/w op if we'll hit the low-water thresh */
		if (pool->sp_fill < BMAN_STOCKPILE_LOW) {
			/* refill stockpile with max amount, but if max amount
			 * isn't available, try amount the user wants */
			/* Acquire the buffer from BMAN */
			do {
				ret = qbman_swp_acquire(swp, bpid,
						pool->sp + pool->sp_fill, BMAN_STOCKPILE_SIZE);
			} while (ret == -EBUSY);
			if (ret <= 0) {
				/* Maybe buffer pool has less than 7 buffers */
				do {
					ret = qbman_swp_acquire(swp, bpid,
							pool->sp + pool->sp_fill, 1);
				} while (ret == -EBUSY);
				/* If still No buffer, retuen NULL if we
				   don't have any in stockpile */
				if (ret <= 0) {
					if (pool->sp_fill == 0) {
						NADK_WARN(BUF, "Buffer alloc(bpid %d)fail: err: %x",
										bpid, ret);
						return NULL;
					}
					goto provide_rem_buf;
				}
			}
#ifdef NADK_MBUF_DEBUG
			else {
				unsigned int i;

				for (i = 0; i < BMAN_STOCKPILE_SZ; i++)
					printf("\n BUF %d - %lx", i, *(pool->sp + i));
			}
#endif
			pool->sp_fill += ret;
		}
provide_rem_buf:
		pool->sp_fill--;

		buf = *((uint64_t *)pool->sp + pool->sp_fill);
		if (buf == 0) {
			NADK_ERR(BUF, "Buf alloc(bpid %d)fail: qbman ret: %x ",
				  bpid, ret);
			return NULL;
		}
	} else {
		/* non stockpile use case */
		do {
			/* Acquire the buffer from BMAN */
			ret = qbman_swp_acquire(swp, bpid, &buf, 1);
		} while (ret == -EBUSY);
		if (ret <= 0) {
			NADK_WARN(BUF, "Buffer alloc(bpid %d)fail: err: %x",
				bpid, ret);
			return NULL;
		}
	}
	NADK_MODIFY_IOVA_TO_VADDR(buf, uint64_t);

	NADK_INFO(BUF, "Buffer acquired: %lx", buf);

	mbuf = NADK_INLINE_MBUF_FROM_BUF(buf, bpid_info[bpid].meta_data_size);

	nadk_inline_mbuf_reset(mbuf);
	_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);

	mbuf->data = mbuf->head + nadk_mbuf_head_room;
	mbuf->frame_len = mbuf->end_off - (mbuf->head - mbuf->data);
	mbuf->tot_frame_len += mbuf->frame_len;

	return mbuf;
}

/*!
 * @details	Free a given NADK buffer
 *
 * @param[in]	mbuf - nadk buffer to be freed
 *
 * @returns	none
 *
 */
void nadk_mbuf_free(nadk_mbuf_pt mbuf)
{
	struct qbman_release_desc releasedesc;
	nadk_mbuf_pt tmp = mbuf;
	struct qbman_swp *swp = thread_io_info.dpio_dev->sw_portal;
	uint64_t buf;
	int ret = 0;
	struct bpsp *pool;

	NADK_TRACE(BUF);

	IF_LOG_LEVEL(NADK_LOG_INFO) {
		nadk_mbuf_dump_pkt(stdout, mbuf);
		printf("\n");
	}
	/* Note: Resetting of Buffer context is not required as
	   it will be done at next odp_schedule / odp_packet_alloc call
	 */
	if (ANY_ATOMIC_CNTXT_TO_FREE(mbuf)) {
		qbman_swp_dqrr_consume(swp, GET_HOLD_DQRR_PTR);
		MARK_HOLD_DQRR_PTR_INVALID;
	}

	while (tmp != NULL) {
		tmp = tmp->next_sg;
		/* Destructor set means the buffer frame is user defined and
		 * will be freed by calling the destructor registered by
		 * the user */
		if (mbuf->destructor) {
			NADK_INFO(BUF, "Calling user specified destructor");
			mbuf->destructor(mbuf);
		} else if (mbuf->bpid != INVALID_BPID) {
			pool = th_bpsp_info[mbuf->bpid];
			/*if stockpile is not available for this thread, directly release the
			buffers to qbman*/
			if (pool == NULL) {
				/* Create a release descriptor required for releasing
				 * buffers into BMAN */
				qbman_release_desc_clear(&releasedesc);
				qbman_release_desc_set_bpid(&releasedesc,
							    mbuf->bpid);
				buf = (uint64_t)nadk_mbuf_frame_addr(mbuf);
				NADK_INFO(BUF, "Releasing buffer: %llx", buf);
				NADK_INFO(BUF, "QBMan SW Portal 0x%p\n", swp);
				do {
					/* Release buffer into the BMAN */
					ret = qbman_swp_release(swp,
								&releasedesc, &buf, 1);
				} while (ret == -EBUSY);
				if (ret) {
					NADK_ERR(BUF, "Unable to free data memory "
						"of buffer\n");
					goto release_done;
				}
			} else {
			/* This needs some explanation. Adding the given buffers may take the
			 * stockpile over the threshold, but in fact the stockpile may already
			 * *be* over the threshold if a previous release-to-hw attempt had
			 * failed. So we have 3 cases to cover;
			 *   1. we add to the stockpile and don't hit the threshold,
			 *   2. we add to the stockpile, hit the threshold and release-to-hw,
			 *   3. we have to release-to-hw before adding to the stockpile
			 *	(not enough room in the stockpile for case 2).
			 * Our constraints on thresholds guarantee that in case 3, there must be
			 * at least 8 bufs already in the stockpile, so all release-to-hw ops
			 * are for 8 bufs. Despite all this, the API must indicate whether the
			 * given buffers were taken off the caller's hands, irrespective of
			 * whether a release-to-hw was attempted. */
			/* Add buffers to stockpile if they fit */
			if ((uint32_t)pool->sp_fill < BMAN_STOCKPILE_SZ) {
				pool->sp[pool->sp_fill] = (uint64_t)nadk_mbuf_frame_addr(mbuf);
				NADK_INFO(BUF, "Buffer released: %lx", *buf);
				pool->sp_fill++;
			}
			/* Do hw op if hitting the high-water threshold */
			if ((uint32_t)pool->sp_fill >= BMAN_STOCKPILE_HIGH) {
				/* Create a release descriptor required for releasing
				 * buffers into BMAN */
				qbman_release_desc_clear(&releasedesc);
				qbman_release_desc_set_bpid(&releasedesc, mbuf->bpid);
				NADK_INFO(BUF, "QBMan SW Portal 0x%p\n", swp);
				do {
					/* Release buffer into the BMAN */
					ret = qbman_swp_release(swp,
								&releasedesc,
								pool->sp + (pool->sp_fill - BMAN_STOCKPILE_SIZE),
								BMAN_STOCKPILE_SIZE);
				} while (ret == -EBUSY);
				if (ret) {
					NADK_ERR(BUF, "Unable to free data memory "
						"of buffer\n");
					goto release_done;
				}
				pool->sp_fill -= BMAN_STOCKPILE_SIZE;
			}
			}
		}
release_done:
		if (mbuf->flags & NADKBUF_ALLOCATED_SHELL)
			nadk_mbuf_free_shell(mbuf);
		mbuf = tmp;
	}
}


/*!
 * @details	Free a NADK buffer shell without the data frame. It will also
 *		free the aiop_cntx if the NADKBUF_AIOP_CNTX_VALID is set.
 *
 * param[in]	nadk buffer shell pointer to be freed.
 *
 * @returns	none
 *
 */
void nadk_mbuf_free_shell(
		nadk_mbuf_pt mbuf)
{
	NADK_TRACE(BUF);

	if (mbuf) {
#ifdef NADK_AIOP_CI_DEVICE
		if (mbuf->flags & NADKBUF_AIOP_CNTX_VALID)
			nadk_aiop_cntx_free(mbuf->drv_priv_cnxt);
#endif
		if (odp_unlikely(!(mbuf->flags & NADKBUF_ALLOCATED_SHELL))) {
			NADK_INFO(BUF, "May be an inline buffer");
			return;
		}
#ifdef NADK_MBUF_MALLOC
		nadk_free(mbuf);
#else
		nadk_mpool_relblock(nadk_mbuf_shell_mpool, mbuf);
#endif
	}
}


/*!
 * @details	Get the maximum number of buffer pools
 *
 * @returns	Maximum number of buffer pools available to the user
 *
 */
uint32_t nadk_mbuf_get_max_pools(void)
{
	struct dpbp_node *dpbp_node;
	int num;

	NADK_TRACE(BUF);

	dpbp_node = g_dpbp_list;
	num = 0;

	while (dpbp_node) {
		dpbp_node = dpbp_node->next;
		num++;
	}

	NADK_INFO(BUF, "Maximum number of pools: %d", num);
	return num;
}


/*!
 * @details	Clean-up routine for NADK buffer library. This API should be
 *		called when IO context is affined to the thread.
 *
 * @returns	none
 *
 */
void nadk_mbuf_finish(void)
{
	struct nadk_bp_list *bp_list, *temp;

	NADK_TRACE(BUF);

	bp_list = g_bp_list;

	/* De-initialize all the buffer pool lists */
	while (bp_list) {
		nadk_mbuf_pool_list_deinit(bp_list);

		temp = bp_list->next;
		nadk_free(bp_list);
		bp_list = temp;
	}

	/* De-initialize the dpbp's */
	nadk_mbuf_dpbp_disable_all();

	NADK_DBG(BUF, "Disabled buffer resources");

}
