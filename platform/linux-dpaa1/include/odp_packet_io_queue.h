/* Copyright (c) 2014, Freescale Semiconductor Inc.
 * Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
/* Copyright (c) 2015 Freescale Semiconductor, Inc.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in the
 *       documentation and/or other materials provided with the distribution.
 *     * Neither the name of Freescale Semiconductor nor the
 *       names of its contributors may be used to endorse or promote products
 *       derived from this software without specific prior written permission.
 *
 *
 * ALTERNATIVELY, this software may be distributed under the terms of the
 * GNU General Public License ("GPL") as published by the Free Software
 * Foundation, either version 2 of that License or (at your option) any
 * later version.
 *
 * THIS SOFTWARE IS PROVIDED BY Freescale Semiconductor ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL Freescale Semiconductor BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */
/**
 * @file
 *
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_QUEUE_H_
#define ODP_PACKET_IO_QUEUE_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp_queue_internal.h>
#include <odp_buffer_internal.h>

/** Max nbr of pkts to receive in one burst (keep same as QUEUE_MULTI_MAX) */
#define ODP_PKTIN_QUEUE_MAX_BURST 16
/* pktin_deq_multi() depends on the condition: */
_ODP_STATIC_ASSERT(ODP_PKTIN_QUEUE_MAX_BURST >= QUEUE_MULTI_MAX,
		   "ODP_PKTIN_DEQ_MULTI_MAX_ERROR");

int pktin_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *pktin_dequeue(queue_entry_t *queue);

int pktin_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);
int pktin_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[], int num);


int pktout_enqueue(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr);
odp_buffer_hdr_t *pktout_dequeue(queue_entry_t *queue);

int buffer_enqueue(queue_entry_t *qentry, odp_buffer_hdr_t *buf_hdr);

int pktout_enq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		     int num);
int pktout_deq_multi(queue_entry_t *queue, odp_buffer_hdr_t *buf_hdr[],
		     int num);
#ifdef __cplusplus
}
#endif

#endif
