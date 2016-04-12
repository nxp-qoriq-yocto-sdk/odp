/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/buffer.h>
#include <odp_pool_internal.h>
#include <odp_buffer_internal.h>
#include <odp_debug_internal.h>
#include <nadk_mpool_priv.h>

#include <string.h>
#include <stdio.h>


odp_buffer_t odp_buffer_from_event(odp_event_t ev)
{
	return (odp_buffer_t)ev;
}

odp_event_t odp_buffer_to_event(odp_buffer_t buf)
{
	return (odp_event_t)buf;
}

void *odp_buffer_addr(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return hdr->data;
}

uint32_t odp_buffer_size(odp_buffer_t buf)
{
	odp_buffer_hdr_t	*buf_hdr = odp_buf_to_hdr(buf);
	pool_entry_t		*pool = odp_buf_to_pool(buf_hdr);
	struct nadk_pool	*mpool;

	mpool = (struct nadk_pool *)pool->s.int_hdl;
	if (!mpool)
		return 0;

	return mpool->data_size - mpool->priv_data_size;
}


int _odp_buffer_type(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);

	return (hdr->usr_flags & ODP_EVENT_TYPES);
}

int odp_buffer_is_valid(odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr = odp_buf_to_hdr(buf);
	int32_t type;

	if (buf == ODP_BUFFER_INVALID)
		return false;

	if (!(hdr->data))
		return false;

	type = _odp_buffer_type(buf);
	if (!(type & ODP_EVENT_BUFFER))
		return false;

	return true;
}


int odp_buffer_snprint(char *str, uint32_t n, odp_buffer_t buf)
{
	odp_buffer_hdr_t *hdr;
	int len = 0;

	if (!odp_buffer_is_valid(buf)) {
		ODP_PRINT("Buffer is not valid.\n");
		return len;
	}

	hdr = odp_buf_to_hdr(buf);

	len += snprintf(&str[len], n-len,
			"Buffer\n");
	len += snprintf(&str[len], n-len,
			"  pool         %"PRIu64"\n", (int64_t) hdr->bpid);
#if 0
	len += snprintf(&str[len], n-len,
			"  phy_addr     %"PRIu64"\n", hdr->phyaddr);
#endif
	len += snprintf(&str[len], n-len,
			"  addr         %p\n",        hdr->data);
	len += snprintf(&str[len], n-len,
			"  size         %u\n",        hdr->tot_frame_len);

	return len;
}


void odp_buffer_print(odp_buffer_t buf)
{
	if (_odp_buffer_type(buf) == ODP_EVENT_PACKET)
		nadk_mbuf_dump_pkt(stdout, buf);
	//todo - add for non packets
}
