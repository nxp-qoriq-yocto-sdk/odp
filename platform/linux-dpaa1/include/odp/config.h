/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP configuration
 */

#ifndef ODP_PLAT_CONFIG_H_
#define ODP_PLAT_CONFIG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_compiler_optim
 *  @{
 */

/**
 * Maximum number of threads
 */
#define ODP_CONFIG_MAX_THREADS  128

/**
 * Maximum number of buffer pools
 */
#define ODP_CONFIG_POOLS 16

/**
 * Maximum number of queues
 */
#define ODP_CONFIG_QUEUES       1024

/**
 * Number of scheduling priorities
 */
#define ODP_CONFIG_SCHED_PRIOS  8

/**
 *  * Number of scheduling groups
 *   */
#define ODP_CONFIG_SCHED_GRPS 5
/* NUM_POOL_CHANNELS_GROUP + 3(i.e. _ALL/_WORKER/_CONTROL */

/**
 * Maximum number of packet IO resources
 */
#define ODP_CONFIG_PKTIO_ENTRIES 64

/**
 * Minimum buffer alignment
 *
 * This defines the minimum supported buffer alignment. Requests for values
 * below this will be rounded up to this value.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MIN 8

/**
 * Maximum buffer alignment
 *
 * This defines the maximum supported buffer alignment. Requests for values
 * above this will fail.
 */
#define ODP_CONFIG_BUFFER_ALIGN_MAX (4*1024)

/**
 * Default packet headroom
 *
 * This defines the minimum number of headroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations may reserve a larger than minimum headroom
 * size e.g. due to HW or a protocol specific alignment requirement.
 *
 * @internal In linux-generic implementation:
 * The default value (66) allows a 1500-byte packet to be received into a single
 * segment with Ethernet offset alignment and room for some header expansion.
 */
#define ODP_CONFIG_PACKET_HEADROOM 128

/**
 * Default packet tailroom
 *
 * This defines the minimum number of tailroom bytes that newly created packets
 * have by default. The default apply to both ODP packet input and user
 * allocated packets. Implementations are free to add to this as desired
 * without restriction. Note that most implementations will automatically
 * consider any unused portion of the last segment of a packet as tailroom
 */
#define ODP_CONFIG_PACKET_TAILROOM 256

/**
 * Maximum packet segment length
 *
 * This defines the maximum packet segment buffer length in bytes. The user
 * defined segment length (seg_len in odp_pool_param_t) must not be larger than
 * this.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MAX (64*1024)

/**
 * Minimum packet segment length
 *
 * This defines the minimum packet segment length in bytes. The user defined
 * buffer size (in odp_buffer_pool_param_t) in buffer pool creation will be
 * rounded up into this value.
 *
 * @internal In linux-generic implementation:
 * - The value MUST be a multiple of 8.
 * - The value MUST be a multiple of ODP_CACHE_LINE_SIZE
 * - The default value (1664) is large enough to support 1536-byte packets
 *   with the default headroom shown above and is a multiple of both 64 and 128,
 *   which are the most common cache line sizes.
 */
#define ODP_CONFIG_PACKET_SEG_LEN_MIN (1664)

/**
 * Maximum packet buffer length
 *
 * This defines the maximum number of bytes that can be stored into a packet
 * (maximum return value of odp_packet_buf_len()). Attempts to allocate
 * (including default head- and tailrooms) or extend packets to sizes larger
 * than this limit will fail.
 *
 * @internal In linux-generic implementation:
 * - The value MUST be an integral number of segments
 * - The value SHOULD be large enough to accommodate jumbo packets (9K)
 */
#define ODP_CONFIG_PACKET_BUF_LEN_MAX (ODP_CONFIG_PACKET_SEG_LEN_MIN*6)

/**
 *  Maximum number of classes of services
 */
#define ODP_COS_MAX_ENTRY 64

/**
 * Maximum number of pattern matching rules
 */
#define ODP_PMR_MAX_ENTRY 64

/**
 * Maximum number of pattern matching rules
 */
#define ODP_PMRSET_MAX_ENTRY 512

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
