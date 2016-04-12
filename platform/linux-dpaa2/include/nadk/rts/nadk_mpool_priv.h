/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

#ifndef NADK_MPOOL_INTERNAL_H
#define NADK_MPOOL_INTERNAL_H
#ifdef __cplusplus
extern "C" {
#endif

#include <nadk_mpool.h>
#include <odp/atomic.h>
#include <nadk_lock.h>

struct nadk_pool_link_node {
	char heap;
	struct nadk_pool_link_node *pNext;
};

struct nadk_pool {
	char name[NADK_MAX_POOL_NAME_LEN];
	char in_use;
	lock_t pool_mutex;
	void *p_memory;
	struct nadk_pool_link_node *head;
	struct nadk_pool_link_node *tail;
	unsigned int align_size;
	unsigned int data_size;
	unsigned int data_elem_size;
	unsigned int priv_data_size;/* Size of private data */
	uint64_t zone_size;
	uintptr_t phys_addr;
	uintptr_t virt_addr;
	unsigned int num_allocs;
	unsigned int num_heap_allocs;
	unsigned int num_frees;
	unsigned int num_per_core_static_entries;
	unsigned int num_per_core_max_entries;
	unsigned int num_entries;
	unsigned int num_max_entries;
};

struct nadk_shm_meta {
	int offset;
};

int nadk_mpool_init(void);
void nadk_mpool_exit(void);

struct nadk_pool *nadk_getfree_pool(void);

#ifdef __cplusplus
}
#endif

#endif /* NADK_MPOOL_INTERNAL_H */
