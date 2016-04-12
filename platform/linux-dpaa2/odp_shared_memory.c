/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/shared_memory.h>
#include <odp/debug.h>
#include <odp_debug_internal.h>


int odp_shm_term_global(void)
{
	return 0;
}

int odp_shm_init_local(void)
{
	return 0;
}
odp_shm_t odp_shm_reserve(const char *name, uint64_t size, uint64_t align,
			  uint32_t flags)
{
	if (flags & ODP_SHM_PROC) {
		/*TODO - support share memory between processes*/
		ODP_ERR("Process Shared memory currently not supported");
		return ODP_SHM_NULL;
	}
	return (odp_shm_t)nadk_memzone_reserve_aligned(name, size,
						SOCKET_ID_ANY, 0, align);
}

int odp_shm_info(odp_shm_t shm, odp_shm_info_t *info)
{
	struct nadk_memzone *mz = (struct nadk_memzone *)shm;
	info->name      = mz->name;
	info->addr      = (void *)nadk_memzone_virt(mz);
	info->size      = mz->len;
	info->page_size = mz->hugepage_sz;
	info->flags     = 0;
	return 0;
}

void odp_shm_print_all(void)
{
	nadk_memzone_dump(stdout);
}
