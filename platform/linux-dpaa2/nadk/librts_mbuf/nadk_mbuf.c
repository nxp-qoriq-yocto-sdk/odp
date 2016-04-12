/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_mbuf.c
 * @brief		Buffer management library services for NADK based
 *		applications.
 *			- Library to alloc/free/manipulate/ to nadk buffers.
 */

/* NADK header files */
#include <odp/std_types.h>
#include <nadk_common.h>
#include <nadk_mbuf.h>
#include <nadk_mbuf_priv.h>
#include <nadk_dev_priv.h>
#include <nadk_eth_priv.h>
#include <nadk_internal.h>
#include <odp/hints.h>
#include <odp/plat/packet_annot.h>

#ifndef NADK_MBUF_MALLOC
/* @internal NADK Shell mpool name */
char nadk_mbuf_shell_mpool_name[] = "NADK_SHELL_MPOOL";

/* @internal NADK Shell mpool handle */
void *nadk_mbuf_shell_mpool;
#endif

bool_t sg_support;

/*!
 * @details	Configures the NADK buffer library e.g. for SG allocation,
 *		inline nadk buffer allocation etc. This API should be called
 *		once during initialization
 *
 * @param[in]	cfg_flags - Flags for NADK buffer library configuration.
 *		User shall use 'NADK_CFG_SG_SUPPORT' for cfg_flags
 *
 * @returns	none
 *
 */
void nadk_mbuf_lib_config(
		uint32_t cfg_flags)
{
	NADK_TRACE(BUF);

	if (cfg_flags & NADK_CFG_SG_SUPPORT)
		sg_support = TRUE;
}


/*!
 * @details	Allocate a NADK buffer of given size from given 'dev'.
 *		If the size is larger than the single available buffer,
 *		Scatter Gather frame will be allocated
 *		(provided support is enabled at 'nadk_mbuf_lib_config')
 *
 * @param[in]	dev - NADK device. Buffer will be allcoated from the pool
 *		affined to this 'dev'
 *
 * @param[in]	size - the NADK buffer size required.
 *
 * @returns	nadk buffer on success; NULL on failure .
 *
 */
nadk_mbuf_pt nadk_mbuf_alloc(
		struct nadk_dev *dev,
		uint32_t size)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	struct nadk_bp_list *bp_list = dev_priv->bp_list;
	nadk_mbuf_pt mbuf;
	int8_t pool_index, num_buf_pools;
	uint16_t bpid = INVALID_BPID;

	NADK_TRACE(BUF);

	num_buf_pools = bp_list->num_buf_pools;
	pool_index = 0;

loop:
	/* Get the best fit bpid as per size */
	while (pool_index < num_buf_pools) {
		NADK_DBG(BUF, "pool_index :%d,, size = %d", pool_index,
			bp_list->buf_pool[pool_index].size);
		if (size <= bp_list->buf_pool[pool_index].size) {
			bpid = bp_list->buf_pool[pool_index].bpid;
			NADK_DBG(BUF, "Best fit bpid found :%d", bpid);
			break;
		}
		pool_index++;
	}

	/* Allocate SG NADK buffer if support is enabled */
	if (pool_index == num_buf_pools) {
		if (sg_support) {
			return nadk_mbuf_alloc_sg(dev, size);
		} else {
			NADK_INFO(BUF, "No more buffers available");
			return NULL;
		}
	}

	/* Allocate buffer from the bpid */
	mbuf = nadk_mbuf_alloc_from_bpid(bpid, 0);
	/* In case no buffer is available re-scan the pending list */
	if (!mbuf) {
		pool_index++;
		NADK_DBG(BUF, "Retrying from next bpid");
		goto loop;
	}

	/* reset the the annotation data */
	if (mbuf->priv_meta_off)
		memset(mbuf->head - mbuf->priv_meta_off, 0, mbuf->priv_meta_off);

	NADK_DBG(BUF, "Buffer allocated");
	return mbuf;
}

/**
 * mbuf offset pointer
 *
 * Returns pointer to data in the packet offset. Optionally outputs
 * handle to the segment and number of data bytes in the segment following the
 * pointer.
 *
 * @param      mbuf     Mbuf handle
 * @param      offset   Byte offset into the packet data pointer
 * @param[out] len      Number of data bytes remaining in the segment (output).
 *                      Ignored when NULL.
 * @param[out] seg      Handle to the segment containing the address (output).
 *                      Ignored when NULL.
 *
 * @return data Pointer to the offset
 * @retval NULL  Requested offset exceeds packet length
 */
uint8_t *nadk_mbuf_offset(nadk_mbuf_pt mbuf, uint32_t offset, uint32_t *len,
			nadk_mbuf_pt *seg)
{
	nadk_mbuf_pt tmp = mbuf;
	uint16_t accum_len = 0;

	NADK_TRACE(BUF);

	/* offset is more than the total frame length */
	if (mbuf->tot_frame_len <= offset)
			return NULL;

	/* Check if first segment suffice */
	if (mbuf->frame_len  >= offset)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > offset)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		NADK_ERR(BUF, "Buffer shorter than requested offset");
		return NULL;
	}

cur_mbuf:

	if (seg)
		*seg = tmp;

	if (len)
		*len = tmp->frame_len - offset;
	return tmp->data + offset - accum_len;
}
/*!
 * @details	Pull the NADK buffer in tail by given size.
 *
 * @param[in]	mbuf - nadk buffer
 *
 * @param[in]	length - length by which the buffer is to be trimmed
 *
 * @param[in]	free_extra - free the remaining segments if any
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_mbuf_pull_tail(
		nadk_mbuf_pt mbuf,
		uint32_t length,
		uint8_t free_extra)
{
	nadk_mbuf_pt tmp = mbuf;
	uint16_t accum_len = 0;
	uint16_t final_len = mbuf->tot_frame_len - length;

	NADK_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto free_mbufs;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * after trimming */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		NADK_ERR(BUF, "Buffer shorter than requested trimming length");
		return NADK_FAILURE;
	}

free_mbufs:
	/* adjust the lengths */
	tmp->frame_len = final_len - accum_len;

	mbuf->tot_frame_len = final_len;

	NADK_DBG(BUF, "Final total length: %d", mbuf->tot_frame_len);
	NADK_DBG(BUF, "Last segment length: %d", tmp->frame_len);

	/* free remaining segments */
	if (free_extra && tmp->next_sg)
		nadk_mbuf_free(tmp->next_sg);

	return NADK_SUCCESS;
}


/*!
 * @details	Make a complete copy of given NADK buffer
 *
 * @param[out]	to_buf - NADK buffer on which the 'from_buffer' is copied.
 *		'to_buf' should already have the buffer frames in it, and thus
 *		no new frame from any buffer pool will be allocated inside
 *		the function.
 *
 * @param[in]	from_buf - NADK buffer which needs to be copied.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_mbuf_copy(
		nadk_mbuf_pt to_buf,
		nadk_mbuf_pt from_buf)
{
	uint32_t avail_len;
	const size_t start_offset = ODP_OFFSETOF(struct nadk_mbuf, flags);
	const size_t len = sizeof(struct nadk_mbuf);
	uint8_t *src, *dst;

	NADK_TRACE(BUF);

	/* If any parameter is SG packet call sg copy */
	if (to_buf->next_sg || from_buf->next_sg)
		return nadk_mbuf_sg_copy(to_buf, from_buf);

	to_buf->tot_frame_len = from_buf->tot_frame_len;

	/* Check if required length is available in the to_buf */
	avail_len = nadk_mbuf_avail_len(to_buf);
	if (from_buf->frame_len > avail_len) {
		NADK_WARN(BUF, "Not enough length in the to_buf");
		return NADK_FAILURE;
	}

	dst = (uint8_t *)to_buf + start_offset;
	src = (uint8_t *)from_buf + start_offset;
	memcpy(dst, src, len - start_offset);

	/* copy the data and other parameters */
	if (from_buf->frame_len)
			memcpy(to_buf->data, from_buf->data, from_buf->frame_len);

	/* copy the annotation data */
	if (from_buf->priv_meta_off >= NADK_MBUF_HW_ANNOTATION &&
		to_buf->priv_meta_off >= NADK_MBUF_HW_ANNOTATION)
		memcpy(to_buf->head - NADK_MBUF_HW_ANNOTATION,
				from_buf->head - NADK_MBUF_HW_ANNOTATION,
				NADK_MBUF_HW_ANNOTATION)
	NADK_DBG(BUF, "Non SG buffer copied successfully");
	return NADK_SUCCESS;
}

/*!
 * @details	Fill in the NADK buffer with the data provided.
 *		This will also handle SG (in case SG is enabled).
 *		This API will overwrite any old data and will start
 *		writing from the data pointer
 *
 * @param[in]	mbuf - nadk buffer on which the data is to be copied.
 *		This can also be a SG buffer
 *
 * @param[in]	data - data pointer from where copy has to be made
 *
 * @param[in]	offset - the offset at which data to be copied
 *
 * @param[in]	length - the length of data to be copied
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_mbuf_data_copy_in(
		nadk_mbuf_pt mbuf,
		const uint8_t *data,
		uint32_t offset,
		uint32_t length)
{
	nadk_mbuf_pt tmp = mbuf;
	void *bdata;
	const void *in_data;
	uint16_t accum_len = 0, avail_len;
	uint16_t final_len = mbuf->tot_frame_len - offset;

	NADK_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		NADK_ERR(BUF, "Buffer shorter than requested offset");
		return NADK_FAILURE;
	}

cur_mbuf:
	bdata = tmp->data + offset - accum_len;
	avail_len = tmp->end_off - nadk_mbuf_headroom(tmp);
	in_data = data;
	while (tmp) {
		avail_len = tmp->end_off - nadk_mbuf_headroom(tmp);
		if (length <= avail_len)  {
			memcpy(bdata, in_data, length);
			NADK_DBG(BUF, "Copied %d bytes in a segment",
				length);
			return NADK_SUCCESS;
		} else {
			memcpy(bdata, in_data, avail_len);
			tmp = tmp->next_sg;
			if (tmp)
				bdata = tmp->data;
			length -= avail_len;
			in_data += avail_len;
			NADK_DBG(BUF, "Copied %d bytes in a segment",
				avail_len);
		}
	}
	return NADK_FAILURE;
}

int nadk_mbuf_data_copy_out(
		nadk_mbuf_pt mbuf,
		uint8_t *data,
		uint32_t offset,
		uint32_t length)
{
	nadk_mbuf_pt tmp = mbuf;
	void *bdata;
	void *out_data;
	uint16_t accum_len = 0, avail_len;
	uint16_t final_len = mbuf->tot_frame_len - offset;

	NADK_TRACE(BUF);

	/* Check if first segment suffice */
	if (mbuf->frame_len >= final_len)
		goto cur_mbuf;

	tmp = tmp->next_sg;
	/* Break at the segment which is to be the last segment
	 * for offset */
	while (tmp != NULL) {
		if (accum_len + tmp->frame_len > final_len)
			break;

		accum_len += tmp->frame_len;
		tmp = tmp->next_sg;
	}

	if (!tmp) {
		NADK_ERR(BUF, "Buffer shorter than requested offset");
		return NADK_FAILURE;
	}

cur_mbuf:
	bdata = tmp->data + offset - accum_len;
	avail_len = tmp->end_off - nadk_mbuf_headroom(tmp);
	out_data = data;
	while (tmp) {
		avail_len = tmp->end_off - nadk_mbuf_headroom(tmp);
		if (length <= avail_len)  {
			memcpy(out_data, bdata, length);
			NADK_DBG(BUF, "Copied %d bytes from a segment",
				length);
			return NADK_SUCCESS;
		} else {
			memcpy(out_data, bdata, avail_len);
			tmp = tmp->next_sg;
			if (tmp)
				bdata = tmp->data;
			length -= avail_len;
			out_data += avail_len;
			NADK_DBG(BUF, "Copied %d bytes from a segment",
				avail_len);
		}
	}
	return NADK_FAILURE;
}


/*!
 * @details	Dump NADK buffer and its data
 *
 * @param[in]	stream - out device (file or stderr, stdout etc).
 *
 * @param[in]	mbuf - nadk buffer
 *
 * @returns	none
 *
 */
void nadk_mbuf_dump_pkt(
		void *stream,
		nadk_mbuf_pt mbuf)
{
	nadk_mbuf_pt tmp = mbuf;
	int i = 0;

	NADK_TRACE(BUF);

	/* TODO use stream */
	while (tmp != NULL) {
		NADK_NOTE(BUF, "segment %d:", i++);
		NADK_NOTE(BUF, "NADK BUFFER SHELL:");
		nadk_memdump(stream, "BufShell", tmp, sizeof(struct nadk_mbuf));

		NADK_NOTE(BUF, "next_sg: %p", tmp->next_sg);
		NADK_NOTE(BUF, "head: %p", tmp->head);
		NADK_NOTE(BUF, "data: %p", tmp->data);
		NADK_NOTE(BUF, "priv_meta_off: %u", tmp->priv_meta_off);
		NADK_NOTE(BUF, "phy_addr: 0x%lx", tmp->phyaddr);
		NADK_NOTE(BUF, "end_off: %u", tmp->end_off);
		NADK_NOTE(BUF, "frame length: %u", tmp->frame_len);
		NADK_NOTE(BUF, "total frame length: %u", tmp->tot_frame_len);
		NADK_NOTE(BUF, "bpid: %u", tmp->bpid);
		NADK_NOTE(BUF, "flags: %x", tmp->flags);
		NADK_NOTE(BUF, "vq: %p", tmp->vq);
		NADK_NOTE(BUF, "user_priv_area: %p", tmp->user_priv_area);
		NADK_NOTE(BUF, "user_cnxt_ptr: 0x%lx", tmp->user_cnxt_ptr);

		NADK_NOTE(BUF, "timestamp: %lu", tmp->timestamp);
		NADK_NOTE(BUF, "hash_val: %d", tmp->hash_val);
		NADK_NOTE(BUF, "eth_flags: %x", tmp->eth_flags);
		NADK_NOTE(BUF, "usr_flags: %x", tmp->usr_flags);

		nadk_hexdump(stream, "BufData", tmp->data, tmp->frame_len);
		tmp = tmp->next_sg;
	}
}

#ifndef NADK_MBUF_MALLOC
/** @internal API */
int32_t nadk_mbuf_shell_mpool_init(uint32_t num_global_blocks)
{
	struct nadk_mpool_cfg mpcfg;

	memset(&mpcfg, 0, sizeof(struct nadk_mpool_cfg));
	mpcfg.name = nadk_mbuf_shell_mpool_name;
	mpcfg.block_size = sizeof(struct nadk_mbuf);
	mpcfg.num_global_blocks = num_global_blocks;
	mpcfg.flags = 0;
	mpcfg.num_threads = 0;
	mpcfg.num_per_thread_blocks = 0;

	nadk_mbuf_shell_mpool = nadk_mpool_create(&mpcfg, NULL, NULL);
	if (nadk_mbuf_shell_mpool == NULL)
		return NADK_FAILURE;

	return NADK_SUCCESS;
}

/** @internal API */
int32_t nadk_mbuf_shell_mpool_exit(void)
{
	return nadk_mpool_delete(nadk_mbuf_shell_mpool);
}
/* get the first pools bpid */
int nadk_mbuf_pool_get_bpid(void *bplist)
{
	struct nadk_bp_list *bp_list = (struct nadk_bp_list *)bplist;

	return bp_list->buf_pool[0].bpid;
}

#endif
