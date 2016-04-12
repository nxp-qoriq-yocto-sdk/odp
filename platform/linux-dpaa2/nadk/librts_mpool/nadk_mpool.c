/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

#include <stdio.h>
#include <string.h>
#include <pthread.h>
#include <signal.h>
#include <limits.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <sys/syscall.h>
#include <fcntl.h>
#include <unistd.h>

#include <nadk.h>
#include <nadk_common.h>
#include <nadk_memzone.h>
#include <nadk_mpool.h>
#include "nadk_mpool_priv.h"
#include <odp/hints.h>

static struct nadk_pool global_pools[NADK_MAX_MEM_POOLS];


struct nadk_pool *nadk_getfree_pool(void)
{
	int i;
	for (i = 0; i < NADK_MAX_MEM_POOLS; i++) {
		if (!global_pools[i].in_use)
			return &global_pools[i];
	}
	return NULL;
}

/*!
 * @details	Lookup a given mpool
 *
 * @param[in]	name - name of the mpool
 *
 * @returns	If mpool is found, returns the mpool. Else return NULL.
 *
 */
void_t *nadk_mpool_lookup(const char *name)
{
	int i;
	for (i = 0; i < NADK_MAX_MEM_POOLS; i++) {
		if (strcmp(global_pools[i].name, name) == 0)
			return &global_pools[i];
	}
	return NULL;
}

/*!
 * @details	Create the memory pool with the params given
 *
 * @param[in]	cfg - pointer to struct nadk_mpool_cfg
 *
 * @param[in]	elem_init - A function pointer that is called for each object at
 *   initialization of the pool. The user can set some meta data in
 *   objects if needed. This parameter can be NULL if not needed.
 *   The obj_init() function takes the mpool pointer, the init_arg,
 *   the object pointer and the object number as parameters.
 *
 * @param[in]	elem_init_arg - An opaque pointer to data that can be used as an argument for
 *   each call to the object constructor function.
 *
 * @param[out]	pointer to handle of the pool created
 *
 * @returns	SUCCESS/FAILURE
 *
 */
void_t *nadk_mpool_create(struct nadk_mpool_cfg *cfg,
	__attribute__((unused)) nadk_mpool_obj_ctor_t *elem_init,
	__attribute__((unused)) void *elem_init_arg)
{
	struct nadk_pool *ptr;
	struct nadk_pool_link_node *p_link_node;
	unsigned int jj;
	unsigned char *cptr;
	struct nadk_memzone *mzone;
	void *elem;

	ptr = nadk_mpool_lookup(cfg->name);
	if (ptr) {
		NADK_ERR(MEMPOOL, "%s - mpool already created",  cfg->name);
		return NULL;
	}

	ptr = nadk_getfree_pool();
	if (!ptr) {
		NADK_NOTE(MEMPOOL, "Pool not available");
		goto err;
	}

	NADK_TRACE(MEMPOOL);

	LOCK_INIT(ptr->pool_mutex, NULL);
	ptr->in_use = 1;
	strncpy(ptr->name, cfg->name, NADK_MAX_POOL_NAME_LEN);
	ptr->priv_data_size = cfg->priv_data_size;
	ptr->align_size = cfg->alignment;
	ptr->data_size = cfg->block_size;
	ptr->data_elem_size = cfg->block_size;
	ptr->num_entries = cfg->num_global_blocks;

	/* Adding the aligning requirements */
	/*This is including the node size also, - as that will be the part of complete data block*/
	if (ptr->align_size)
		ptr->data_elem_size += (ptr->align_size -
		((ptr->data_elem_size + sizeof(struct nadk_pool_link_node)) % ptr->align_size));


	ptr->zone_size = ((ptr->data_elem_size + sizeof(struct nadk_pool_link_node))
			* cfg->num_global_blocks) + ptr->align_size;

	NADK_DBG(MEMPOOL, "data = %u, blocks =%d, zone size =%llu",
		ptr->data_elem_size, ptr->num_entries, ptr->zone_size);



	mzone = nadk_memzone_reserve(ptr->name, ptr->zone_size, 0, 0);
	if (mzone == NULL) {
		NADK_ERR(MEMPOOL, "nadk_memzone_reserve: allocation failed"
			"for pool-%s \r\n", ptr->name);
		goto err1;
	}

	/* Store the virt address also for the mpool */
#ifdef	CONFIG_64BIT
	ptr->virt_addr = (uintptr_t)mzone->addr_64;
#else
	ptr->virt_addr = (uintptr_t)mzone->addr;
#endif

	ptr->phys_addr = (uintptr_t)mzone->phys_addr;

	NADK_DBG2(MEMPOOL, "shm_ptr = %lu, phy = %lu",
		ptr->virt_addr, ptr->phys_addr);


	/* Lock initilization is pending */
	ptr->p_memory = (void *)ptr->virt_addr;
	if (ptr->align_size)
		ptr->virt_addr = NADK_ALIGN_ROUNDUP(ptr->virt_addr,
		ptr->align_size);
	NADK_DBG2(MEMPOOL, "new mem = %lu", ptr->virt_addr);
	ptr->head = (struct nadk_pool_link_node *)(ptr->data_elem_size + ptr->virt_addr);
	ptr->num_frees = ptr->num_entries;


	/* call the initializer  for the first node*/
	if (elem_init) {
		elem = (void *)(ptr->head) - ptr->data_elem_size;
		elem_init(ptr, elem_init_arg, elem, 0);
	}

	/* If the number of nodes i.e num_global_blocks = 1, then a single
	 * block will be created */
	for (jj = 1, p_link_node = ptr->head;
		jj < cfg->num_global_blocks; jj++) {

		cptr = ptr->data_elem_size + (unsigned char *) (p_link_node + 1);
		NADK_DBG2(MEMPOOL, "create %dth node node = %lu\n", jj, cptr);

		/* call the initializer */
		if (elem_init) {
			elem = cptr - ptr->data_elem_size;
			elem_init(ptr, elem_init_arg, elem, jj);
		}

		p_link_node->pNext = (struct nadk_pool_link_node *) cptr;
		p_link_node = p_link_node->pNext;
	}

	p_link_node->pNext = NULL;
	ptr->tail = p_link_node;


	NADK_DBG(MEMPOOL, "Allocated pool name %s", cfg->name);

	return ptr;

err1:
	ptr->in_use = 0;
err:
	NADK_ERR(MEMPOOL, "Not Created %s", cfg->name);
	/*TBD the framework for returning error is to be fixed*/
	return NULL;
}


int32_t nadk_mpool_delete(void_t *mpool)
{
	struct nadk_pool *ptr = (struct nadk_pool *)mpool;
	struct nadk_pool *ptr_to_be_deleted;
	struct nadk_memzone *mzone;
	if (!ptr)
		return NADK_FAILURE;
	mzone = (struct nadk_memzone *)nadk_memzone_lookup(ptr->name);
	if (!mzone)
		return NADK_FAILURE;
	ptr_to_be_deleted = nadk_mpool_lookup(ptr->name);
	memset(ptr_to_be_deleted, 0, sizeof(struct nadk_pool));
	return nadk_memzone_free(mzone);
}
/*!
 * @details This API is used to get a memory block from a memory pool. Applications
 *   should not call this API once the mpool is set for delete.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in,out]	heap - flag that indicates whether allocation from heap
 *                 is wanted or not (true - wanted, false - unwanted) once
 *                 mem pool is exhausted (in direction)
 *                 flag that indicates whether allocation was done from heap as
 *                 the mem pool is exhausted (out direction)
 *
 * @returns	p_block or NULL- address of the allocated mem block
 *
 */
void_t *nadk_mpool_getblock(
	void_t *mpool,
	__attribute__((unused)) uint8_t *heap)
{
	struct nadk_pool *gl_pool;
	struct nadk_pool_link_node *p_temp_block = NULL;
	uint8_t *data;

	if (!mpool) {
		NADK_WARN(MEMPOOL, "mpool is NULL");
		return NULL;
	}

	gl_pool = (struct nadk_pool *)mpool;

	LOCK(gl_pool->pool_mutex);

	p_temp_block = gl_pool->head;
	if (p_temp_block) {
		gl_pool->head = p_temp_block->pNext;
		if (!(gl_pool->head))
			gl_pool->tail = NULL;
		gl_pool->num_allocs++;
		gl_pool->num_frees--;
		/*Data is before the the pNode -it is so - to be properly aligned*/
		data = (uint8_t *)p_temp_block - gl_pool->data_elem_size;

		/*private data should  not be memset, as it has been initialized by the
		obj_init function provided by the allocator*/
		memset(data + gl_pool->priv_data_size, 0,
			gl_pool->data_elem_size - gl_pool->priv_data_size);

		p_temp_block->pNext = NULL;
		p_temp_block->heap = 0;
		UNLOCK(gl_pool->pool_mutex);
		NADK_DBG2(MEMPOOL, "block allocated %s", gl_pool->name);
		return data;
	} else {
		NADK_NOTE(MEMPOOL, "No more node is available for pool %s \r\n",
			gl_pool->name);
		UNLOCK(gl_pool->pool_mutex);
		return NULL;
	}
}

/*!
 * @details This API is used to release a memory block to a memory pool.
 *
 * @param[in]	mpool - pointer to memory pool
 *
 * @param[in]	p_block - address of the mem block to be released
 *
 * @param[out]	none
 *
 * @returns	NADK_SUCCESS on SUCCESS; NADK_FAILURE on FAILURE.
 *
 */
int32_t nadk_mpool_relblock(
	void_t *mpool,
	void_t *p_block)
{
	struct nadk_pool *gl_pool = (struct nadk_pool *)mpool;
	struct nadk_pool_link_node *pNode;

	if (!mpool || !(p_block)) {
		NADK_WARN(MEMPOOL, "mpool or p_block is NULL");
		return -1;
	}
	/* pNode is at the end of data element*/
	pNode = (struct nadk_pool_link_node *)(p_block + gl_pool->data_elem_size);
	if (!(pNode)) {
		NADK_WARN(MEMPOOL, "pNode is NULL\n");
		return -1;
	}
	LOCK(gl_pool->pool_mutex);
	if (pNode->heap == 0) {
		pNode->pNext = gl_pool->head;
		gl_pool->head = pNode;
		gl_pool->num_allocs--;
		gl_pool->num_frees++;
	} else {
		NADK_NOTE(MEMPOOL, "Release failed for node \r\n");
	}
	UNLOCK(gl_pool->pool_mutex);

	return 0;
}

phys_addr_t
nadk_mem_virt2phy(const void *p_virt)
{
	int fd;
	uint64_t page, physaddr;
	uint64_t virt_pfn;
	int page_size;
	char str[64];

	sprintf(str, "/proc/%d/pagemap", getpid());

	/* standard page size */
	page_size = sysconf(_SC_PAGESIZE);
	NADK_DBG2(MEMPOOL, "file name is %s  %x", str, page_size);

	fd = open(str, O_RDONLY);
	if (fd < 0) {
		NADK_ERR(MEMPOOL, "cannot open %s: %s\n", str, strerror(errno));
		return NADK_BAD_PHYS_ADDR;
	}

	off_t offset;
	virt_pfn = ((uint64_t)p_virt) / page_size;
	offset = sizeof(uint64_t) * virt_pfn;

	NADK_DBG2(MEMPOOL, "ptr = %lu, %lu, offset =%lu - %x", p_virt, virt_pfn,
		offset, offset);

	NADK_DBG2(MEMPOOL, "pagesize = 0x%x, virt = %x - %x",
		page_size, p_virt, virt_pfn);

	if (lseek(fd, offset, SEEK_SET) == (off_t) -1) {
		NADK_ERR(MEMPOOL, "seek error in %s:offset=%lu, err=%s\n",
				str, offset, strerror(errno));
		close(fd);
		return NADK_BAD_PHYS_ADDR;
	}
	if (read(fd, &page, sizeof(uint64_t)) < 0) {
		NADK_ERR(MEMPOOL, "cannot read %s: %s\n",
				str, strerror(errno));
		close(fd);
		return NADK_BAD_PHYS_ADDR;
	}

	/*
	 * the pfn (page frame number) are bits 0-54 (see
	 * pagemap.txt in linux Documentation)
	 */
	physaddr = ((page & 0x7fffffffffffffULL) * page_size)
		+ ((unsigned long)p_virt % page_size);
	close(fd);
	return physaddr;
}

/*!
 * @details	Find physical address of the pool start block
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	physical address of pool start block
 *
 */
phys_addr_t nadk_get_mpool_phyaddr(const void_t *mpool)
{
	const struct nadk_pool *pool = (const struct nadk_pool *)mpool;

	return pool->phys_addr;
}

/*!
 * @details	Get virtual address of the pool start block
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	virtual address of pool start block
 *
 */
void *nadk_get_mpool_virtaddr(const void_t *mpool)
{
	const struct nadk_pool *pool = (const struct nadk_pool *)mpool;

	return (void *)(pool->virt_addr);
}


/*!
 * @details	Find physical address of a particular block in the pool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @param[in]	blk - ptr to the block in the mpool
 *
 * @returns	Physical address of a particular block in the pool
 *
 */
phys_addr_t nadk_get_mpool_blk_phyaddr(const void_t *mpool, const void *blk)
{
	phys_addr_t pool_phys_addr, offs = 0;

	const struct nadk_pool *pool = (const struct nadk_pool *)mpool;

	pool_phys_addr = nadk_get_mpool_phyaddr(mpool);
	offs = (phys_addr_t)blk - pool->virt_addr;

	return pool_phys_addr + offs;
}


/*!
 * @details	Find virtual address of a particular block in the pool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @param[in]	blk - ptr to the block in the mpool
 *
 * @returns	Virtual address of a particular block in the pool
 *
 */
void *nadk_get_mpool_blk_virtaddr(const void_t *mpool, const phys_addr_t blk)
{
	void *pool_virt_addr;
	int offs = 0;

	const struct nadk_pool *pool = (const struct nadk_pool *)mpool;

	pool_virt_addr = nadk_get_mpool_virtaddr(mpool);
	offs = blk - pool->phys_addr;

	return pool_virt_addr + offs;
}

/*!
 * @details	Find the count of the blocks in the mpool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	count of the blocks in the mpool
 *
 */
int nadk_mpool_count(const void_t *mpool)
{
	return (mpool ? ((const struct nadk_pool *)mpool)->num_entries : 0);
}

/*!
 * @details	Find the count of the free blocks in the mpool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	count of the blocks in the mpool
 *
 */
int nadk_mpool_free_count(const void_t *mpool)
{
	return (mpool ? ((const struct nadk_pool *)mpool)->num_frees : 0);
}

/*!
 * @details	Find the size of the given mpool
 *
 * @param[in]	mpool - ptr to the mpool structure
 *
 * @returns	Size of the mpool
 *
 */
uint64_t nadk_mpool_size(void_t *mpool)
{
	struct nadk_pool *gpool = (struct nadk_pool *)mpool;
	if (!mpool)
		return 0;
	return gpool->zone_size;
}

void nadk_mpool_dump(const void_t *mpool ODP_UNUSED)
{
}

/*!
 * @details Dump the status of all mpools to the file or console.
 *		If the user passes file handle then list is printed
 *		in the specified file else it is printed on stdout.
 *
 * @param[in]	stream - stream can be file pointer, stderr or stdout device.
 *
 * @returns	none
 *
 */
void nadk_mpool_list_dump(void *stream ODP_UNUSED)
{
}
