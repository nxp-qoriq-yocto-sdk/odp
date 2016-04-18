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
 * ODP packet IO - implementation internal
 */

#ifndef ODP_PACKET_IO_INTERNAL_H_
#define ODP_PACKET_IO_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/spinlock.h>
#include <odp_packet_nadk.h>
#include <odp_classification_datamodel.h>
#include <odp_align_internal.h>

#include <odp/config.h>
#include <odp/hints.h>

/**
 * Packet IO types
 */
typedef enum {
	ODP_PKTIO_TYPE_SOCKET_BASIC = 0x1,
	ODP_PKTIO_TYPE_SOCKET_MMSG,
	ODP_PKTIO_TYPE_SOCKET_MMAP,
	ODP_PKTIO_TYPE_LOOPBACK,
} odp_pktio_type_t;

struct pktio_entry {
	odp_spinlock_t lock;		/**< entry spinlock */
	int taken;			/**< is entry taken(1) or free(0) */
	odp_queue_t inq_default;	/**< default input queue, if set */
	odp_queue_t outq_default;	/**< default out queue */
	odp_queue_t loopq;		/**< loopback queue for "loop" device */
	odp_pktio_type_t type;		/**< pktio type */
	pkt_nadk_t pkt_nadk;		/**< using NADK API for IO */
	odp_bool_t cls_init_done;	/**< Classifier is initialized or not ?*/
	classifier_t cls;		/**< classifier linked with this pktio*/
	char name[IFNAMSIZ];		/**< name of pktio provided to
					   pktio_open() */
	odp_pktio_param_t param; /*PKTIO params*/
	odp_bool_t promisc;		/**< promiscuous mode state */
	void	*priv;
};

typedef union {
	struct pktio_entry s;
	uint8_t pad[ODP_CACHE_LINE_SIZE_ROUNDUP(sizeof(struct pktio_entry))];
} pktio_entry_t;

typedef struct {
	odp_spinlock_t lock;
	pktio_entry_t entries[ODP_CONFIG_PKTIO_ENTRIES];
} pktio_table_t;

extern void *pktio_entry_ptr[];


static inline pktio_entry_t *get_pktio_entry(odp_pktio_t id)
{
	if (odp_unlikely(id == ODP_PKTIO_INVALID ||
			 _odp_typeval(id) > ODP_CONFIG_PKTIO_ENTRIES))
		return NULL;

	return pktio_entry_ptr[_odp_typeval(id) - 1];
}
#ifdef __cplusplus
}
#endif

#endif
