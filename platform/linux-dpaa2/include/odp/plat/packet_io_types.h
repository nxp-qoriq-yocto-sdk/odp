/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP Packet IO
 */

#ifndef ODP_PACKET_IO_TYPES_H_
#define ODP_PACKET_IO_TYPES_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/plat/strong_types.h>

/** @addtogroup odp_packet_io ODP PACKET IO
 *  Operations on a packet.
 *  @{
 */

typedef ODP_HANDLE_T(odp_pktio_t);

#define ODP_PKTIO_INVALID _odp_cast_scalar(odp_pktio_t, 0)

#define ODP_PKTIO_ANY _odp_cast_scalar(odp_pktio_t, ~0)

#define ODP_PKTIO_MACADDR_MAXSIZE 16

/** Get printable format of odp_pktio_t */
static inline uint64_t odp_pktio_to_u64(odp_pktio_t hdl)
{
	return _odp_pri(hdl);
}

/**
 * @}
 */

#ifdef __cplusplus
}
#endif

#endif
