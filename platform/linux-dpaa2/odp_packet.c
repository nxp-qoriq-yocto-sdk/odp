/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/packet.h>
#include <odp_packet_internal.h>
#include <odp_debug_internal.h>
#include <odp/hints.h>
#include <odp/byteorder.h>

#include <odp_queue_internal.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>
#include <odp/helper/tcp.h>
#include <odp/helper/udp.h>

#include <string.h>
#include <stdio.h>
#include <nadk_mbuf_priv_ldpaa.h>
/*
 *
 * Alloc and free
 * ********************************************************
 *
 */

odp_packet_t odp_packet_alloc(odp_pool_t pool_hdl, uint32_t len)
{
	pool_entry_t *pool = odp_pool_to_entry(pool_hdl);
	struct nadk_mbuf *mbuf;

	odp_packet_t pkt;

	if (pool->s.params.type != ODP_POOL_PACKET)
		return ODP_PACKET_INVALID;


	pkt = (odp_packet_t)nadk_mbuf_alloc_from_bpid(
				pool->s.bpid, len);
	if (!pkt) {
		ODP_ERR("Error in mbuf alloc for len =%d\n", len);
		return ODP_PACKET_INVALID;
	}
	mbuf = (struct nadk_mbuf *)pkt;
	mbuf->frame_len = len;
	mbuf->tot_frame_len = mbuf->frame_len;

	return pkt;
}

void odp_packet_free(odp_packet_t pkt)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);

	nadk_mbuf_free((nadk_mbuf_pt)pkt_hdr);
}

int odp_packet_reset(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *const pkt_hdr = odp_packet_hdr(pkt);
	struct nadk_mbuf *mbuf = (nadk_mbuf_pt)pkt_hdr;

	nadk_mbuf_reset(mbuf);
	mbuf->tot_frame_len = len;
	if (!mbuf->next_sg)
		mbuf->frame_len = mbuf->tot_frame_len;
	_odp_buffer_type_set(mbuf, ODP_EVENT_PACKET);
	return 0;
}

odp_packet_t _odp_packet_from_buffer(odp_buffer_t buf)
{
	return (odp_packet_t)buf;
}

odp_buffer_t _odp_packet_to_buffer(odp_packet_t pkt)
{
	return (odp_buffer_t)pkt;
}

odp_packet_t odp_packet_from_event(odp_event_t ev)
{
	return (odp_packet_t)ev;
}

odp_event_t odp_packet_to_event(odp_packet_t pkt)
{
	return (odp_event_t)pkt;
}

/*
 *
 * Pointers and lengths
 * ********************************************************
 *
 */

void *odp_packet_head(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	return pkt_hdr->head;
}

uint32_t odp_packet_buf_len(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	/*todo  take care of seg case */
	return pkt_hdr->end_off;
}

uint32_t odp_packet_seg_len(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	/*TODO - need to implement for multi-seg case - the data pointer may be in 2nd segment*/
	return pkt_hdr->frame_len;
}

uint32_t odp_packet_headroom(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_headroom((nadk_mbuf_pt)pkt_hdr);
}

uint32_t odp_packet_tailroom(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_tailroom((struct nadk_mbuf *)pkt_hdr);
}

void *odp_packet_tail(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_tail((struct nadk_mbuf *)pkt_hdr);
}

void *odp_packet_push_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_push((struct nadk_mbuf *)pkt_hdr, len);
}

void *odp_packet_pull_head(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_pull((struct nadk_mbuf *)pkt_hdr, len);
}

void *odp_packet_push_tail(odp_packet_t pkt, uint32_t len)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	return nadk_mbuf_push_tail((struct nadk_mbuf *)pkt_hdr, len, FALSE);
}

void *odp_packet_pull_tail(odp_packet_t pkt, uint32_t len)
{
	int32_t ret;

	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	ret = nadk_mbuf_pull_tail((struct nadk_mbuf *)pkt_hdr, len, FALSE);

	if (!ret)
		return pkt->data + pkt->frame_len;

	return NULL;
}

void *odp_packet_offset(odp_packet_t pkt, uint32_t offset, uint32_t *len,
			odp_packet_seg_t *seg)
{
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);

	void *buf = nadk_mbuf_offset(
		(struct nadk_mbuf *)pkt_hdr, offset, len, seg);

	if (seg && *seg == NULL)
		*seg = ODP_PACKET_SEG_INVALID;

	return buf;
}

/*
 *
 * Meta-data
 * ********************************************************
 *
 */

odp_pool_t odp_packet_pool(odp_packet_t pkt)
{
	odp_buffer_t buf = _odp_packet_to_buffer(pkt);

	return (odp_pool_t)odp_buf_to_pool(buf);
}

odp_pktio_t odp_packet_input(odp_packet_t pkt)
{
	struct nadk_mbuf *mbuf = (struct nadk_mbuf *)pkt;
	struct nadk_dev *dev;

	dev = nadk_dev_from_vq(mbuf->vq);
	if (!dev) {
		ODP_ERR("Device pointer is NULL\n");
		return ODP_PKTIO_INVALID;
	}
	return (odp_pktio_t)dev->pktio;
}

void *odp_packet_user_ptr(odp_packet_t pkt)
{
	struct nadk_mbuf *mbuf;

	mbuf = odp_nadk_mbuf_hdr(pkt);
	return (void *)mbuf->user_cnxt_ptr;
}

void odp_packet_user_ptr_set(odp_packet_t pkt, const void *ctx)
{
	odp_nadk_mbuf_hdr(pkt)->user_cnxt_ptr = (uint64_t)ctx;
}

void *odp_packet_user_area(odp_packet_t pkt)
{
	return (void *)odp_nadk_mbuf_hdr(pkt) + sizeof(odp_packet_hdr_t);
}

uint32_t odp_packet_user_area_size(odp_packet_t pkt)
{
	return bpid_info[odp_nadk_mbuf_hdr(pkt)->bpid].odp_user_area;
}

void odp_packet_user_u64_set(odp_packet_t pkt, uint64_t ctx)
{
	odp_nadk_mbuf_hdr(pkt)->user_cnxt_ptr = ctx;
}


int odp_packet_is_segmented(odp_packet_t pkt)
{
	return !(nadk_mbuf_is_contiguous(pkt));
}

int odp_packet_num_segs(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	int i = 1;
	while(pkt_hdr->next_sg) {
		i++;
		pkt_hdr = pkt_hdr->next_sg;
	}
	return i;
}

odp_packet_seg_t odp_packet_first_seg(odp_packet_t pkt)
{
	return (odp_packet_seg_t)pkt;
}

odp_packet_seg_t odp_packet_last_seg(odp_packet_t pkt)
{
	return nadk_mbuf_lastseg(pkt);
}

odp_packet_seg_t odp_packet_next_seg(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	if ((seg == ODP_SEGMENT_INVALID)  || (seg->next_sg == ODP_SEGMENT_INVALID))
		return ODP_SEGMENT_INVALID;
	return seg->next_sg ? (odp_packet_seg_t)seg->next_sg : ODP_PACKET_SEG_INVALID;
}

/*
 *
 * Segment level
 * ********************************************************
 *
 */

void *odp_packet_seg_buf_addr(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	return seg->head;
}

uint32_t odp_packet_seg_buf_len(odp_packet_t pkt ODP_UNUSED,
				odp_packet_seg_t seg)
{
	return seg->end_off;
}

void *odp_packet_seg_data(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	return seg->data;
}

uint32_t odp_packet_seg_data_len(odp_packet_t pkt ODP_UNUSED, odp_packet_seg_t seg)
{
	return seg->frame_len;
}

/*
 *
 * Manipulation
 * ********************************************************
 *
 */

odp_packet_t odp_packet_add_data(odp_packet_t pkt ODP_UNUSED, uint32_t offset ODP_UNUSED,
				 uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_PACKET_INVALID;
#if 0
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen + len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset, newpkt,
					       offset + len,
					       pktlen - offset) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			odp_packet_hdr_t *new_hdr = odp_packet_hdr(newpkt);
			new_hdr->input = pkt_hdr->input;
			new_hdr->buf_hdr.buf_u64 = pkt_hdr->buf_hdr.buf_u64;
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
		}
	}
	return newpkt;
#endif
}

odp_packet_t odp_packet_rem_data(odp_packet_t pkt ODP_UNUSED, uint32_t offset ODP_UNUSED,
				 uint32_t len ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return ODP_PACKET_INVALID;
#if 0
	odp_packet_hdr_t *pkt_hdr = odp_packet_hdr(pkt);
	uint32_t pktlen = pkt_hdr->frame_len;
	odp_packet_t newpkt;

	if (offset > pktlen || offset + len > pktlen)
		return ODP_PACKET_INVALID;

	newpkt = odp_packet_alloc(pkt_hdr->buf_hdr.pool_hdl, pktlen - len);

	if (newpkt != ODP_PACKET_INVALID) {
		if (_odp_packet_copy_to_packet(pkt, 0,
					       newpkt, 0, offset) != 0 ||
		    _odp_packet_copy_to_packet(pkt, offset + len,
					       newpkt, offset,
					       pktlen - offset - len) != 0) {
			odp_packet_free(newpkt);
			newpkt = ODP_PACKET_INVALID;
		} else {
			odp_packet_hdr_t *new_hdr = odp_packet_hdr(newpkt);
			new_hdr->input = pkt_hdr->input;
			new_hdr->buf_hdr.buf_u64 = pkt_hdr->buf_hdr.buf_u64;
			odp_atomic_store_u32(
				&new_hdr->buf_hdr.ref_count,
				odp_atomic_load_u32(
					&pkt_hdr->buf_hdr.ref_count));
			copy_packet_parser_metadata(pkt_hdr, new_hdr);
			odp_packet_free(pkt);
		}
	}

	return newpkt;
#endif
}

/*
 *
 * Copy
 * ********************************************************
 *
 */

odp_packet_t odp_packet_copy(odp_packet_t pkt, odp_pool_t pool)
{
	struct nadk_mbuf *srchdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	uint32_t pktlen = srchdr->tot_frame_len;
	odp_packet_t newpkt = odp_packet_alloc(pool, pktlen);
	struct nadk_mbuf *dsthdr = (struct nadk_mbuf *)odp_packet_hdr(newpkt);

	if (nadk_mbuf_copy(dsthdr, srchdr))
		return ODP_PACKET_INVALID;
	return newpkt;
}

int odp_packet_copydata_out(odp_packet_t pkt, uint32_t offset,
			    uint32_t len, void *dst)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);

	if (offset + len > pkt_hdr->tot_frame_len)
		return -1;

	if (nadk_mbuf_data_copy_out(pkt_hdr, dst, offset, len))
		return -1;
	return 0;
}

int odp_packet_copydata_in(odp_packet_t pkt, uint32_t offset,
			   uint32_t len, const void *src)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)odp_packet_hdr(pkt);
	if (offset + len > pkt_hdr->tot_frame_len)
		return -1;

	if (nadk_mbuf_data_copy_in(pkt_hdr, src, offset, len))
		return -1;
	return 0;
}

/*
 *
 * Debugging
 * ********************************************************
 *
 */

void odp_packet_print(odp_packet_t pkt)
{
	odp_packet_hdr_t *hdr = odp_packet_hdr(pkt);
	nadk_mbuf_dump_pkt(stdout, (struct nadk_mbuf *)hdr);
	//todo print rest of packet headers
}

int odp_packet_is_valid(odp_packet_t pkt)
{
	odp_packet_hdr_t *pkt_hdr;
	if (pkt == ODP_PACKET_INVALID)
		return 0;
	pkt_hdr = odp_packet_hdr(pkt);
	return ((pkt_hdr) && nadk_mbuf_is_valid((struct nadk_mbuf *)pkt_hdr));
}

/*
 *
 * ODP Extensions
 * ********************************************************
 *
 */

uint16_t odpfsl_packet_pool_internal_id(odp_pool_t pkt_pool)
{
	pool_entry_t *pool = (pool_entry_t *)pkt_pool;

	return pool->s.bpid;
}

odp_packet_t odpfsl_packet_from_addr(void *addr)
{
	odp_packet_t pkt;
	void *pkt_addr;

	pkt = (odp_packet_t)(addr - (NADK_MBUF_HW_ANNOTATION +
		NADK_MBUF_SW_ANNOTATION + sizeof(odp_packet_hdr_t)));
	pkt_addr = odp_packet_data(pkt);

	if (pkt_addr != addr)
		return NULL;

	return pkt;
}
