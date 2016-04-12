/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 *
 */

/*!
 * @file	nadk_io_portal_ldpaa.c
 *
 * @brief	Data Path I/O portal driver implementation. It contains initialization of
 *		Input/Output context required for NADK device framework based application.
 *
 */

/* System Header Files */
#include <sys/epoll.h>

/*NADK header files*/
#include "nadk_io_portal_priv.h"
#include <nadk_internal.h>
#include <nadk_vfio.h>

#ifdef ODP_ON_VM
#include <odp/api/cpu.h>

#define NUM_HOST_CPUS 8
#endif

#define NUM_DPIO_REGIONS	2
/* DPIO devices list */
struct nadk_dpio_device_list *dpio_dev_list; /*!< DPIO device list */
uint32_t io_space_count;

/* The DPIO reserved for notifier */
struct nadk_dpio_dev *notif_dpio;
/* The epoll fd to be used for epolling on the notifier DPIO */
int notif_dpio_epollfd;

/*!< I/O handle for this thread, for the use of NADK framework.
 * This is duplicated as will be used frequently
 */
__thread struct thread_io_info_t thread_io_info;
static int32_t nadk_configure_stashing(void);

struct nadk_driver io_p_driver = {
	.name			=	LDPAA_IO_P_NAME,
	.vendor_id		=	LDPAA_IO_P_VENDOR_ID,
	.major			=	LDPAA_IO_P_MAJ_NUM,
	.minor			=	LDPAA_IO_P_MIN_NUM,
	.dev_type		=	NADK_IO_CNTXT,
	.dev_probe		=	nadk_io_portal_probe,
	.dev_shutdown		=	nadk_io_portal_close
};

int32_t nadk_io_portal_init(void)
{
	/*Register Ethernet driver to NADK device framework*/
	nadk_register_driver(&io_p_driver);
	return NADK_SUCCESS;
}

int32_t nadk_io_portal_exit(void)
{
	/*Unregister Ethernet driver to NADK device framework*/
	nadk_unregister_driver(&io_p_driver);
	return NADK_SUCCESS;
}

static int nadk_notif_dpio_init(void)
{
	static struct epoll_event epoll_ev;
	int eventfd;
	int ret;

	notif_dpio_epollfd = epoll_create(1);
	ret = nadk_register_dpio_interrupt(notif_dpio,
		VFIO_DPIO_DATA_IRQ_INDEX);
	if (ret != NADK_SUCCESS) {
		NADK_ERR(FW, "Interrupt registeration failed");
		return NADK_FAILURE;
	}

	qbman_swp_interrupt_set_trigger(notif_dpio->sw_portal,
		QBMAN_SWP_INTERRUPT_DQRI);
	qbman_swp_interrupt_clear_status(notif_dpio->sw_portal,
		0xffffffff);
	/* This API is currently required to be called with channel index 0,
	so that notifications are pushed from the channel to the Notifier DPIO.
	Fix should be there in the QBMAN or MC should provide the channel index
	in attributes */
	qbman_swp_push_set(notif_dpio->sw_portal, 0, 1);

	eventfd = notif_dpio->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].fd;
	epoll_ev.events = EPOLLIN | EPOLLPRI;
	epoll_ev.data.fd = eventfd;

	ret = epoll_ctl(notif_dpio_epollfd, EPOLL_CTL_ADD, eventfd, &epoll_ev);
	if (ret < 0) {
		NADK_ERR(FW, "epoll_ctl failed");
		return NADK_FAILURE;
	}

	return NADK_SUCCESS;
}

/* Initializer funciton for DPIO device */
int32_t nadk_io_portal_probe(ODP_UNUSED struct nadk_dev *dev,
			const void *data)
{
	/* Probe function is responsible to initialize the DPIO devices.
	 * It does followings
	 * 1. Open & Enable the DPIO device
	 * 2. Allocated required resources.
	 */
	struct vfio_region_info reg_info = {
					.argsz = sizeof(reg_info) };
	struct nadk_dpio_dev *dpio_dev;
	const struct nadk_dev_priv *dev_priv = (const struct nadk_dev_priv *) data;
	struct vfio_device_info *obj_info =
		(struct vfio_device_info *)dev_priv->drv_priv;
	struct qbman_swp_desc p_des;
	struct dpio_attr attr;

	if (obj_info->num_regions < NUM_DPIO_REGIONS) {
		NADK_ERR(FW, "ERROR, Not sufficient number "
					"of DPIO regions.\n");
		return NADK_FAILURE;
	}

	NADK_INFO(FW, "Initializing DPIO DEVICE.\n");
	/* Allocate Device List first, If not already done */
	if (!dpio_dev_list) {
		dpio_dev_list = nadk_malloc(NULL,
				sizeof(struct nadk_dpio_device_list));
		if (NULL == dpio_dev_list) {
			NADK_ERR(FW, "ERROR, No Memory for DPIO list\n");
			return NADK_FAILURE;
		}
		/* Initialize the DPIO List */
		TAILQ_INIT(dpio_dev_list);
	}
	/* Allocate DPIO device object */
	dpio_dev = nadk_calloc(NULL, 1, sizeof(struct nadk_dpio_dev), 0);
	if (!dpio_dev) {
		NADK_ERR(FW, "ERROR, No Memory for DPIO Device\n");
		return NADK_FAILURE;
	}
	NADK_INFO(FW, "\t Allocated DPIO [%p]\n", dpio_dev);
	dpio_dev->dpio = NULL;
	dpio_dev->vfio_fd = dev_priv->vfio_fd;
	dpio_dev->hw_id = dev_priv->hw_id;
	memset(&dpio_dev->ch_idx, NADK_INVALID_CHANNEL_IDX, sizeof(uint8_t) * MAX_SCHED_GRPS);
	odp_atomic_init_u16(&dpio_dev->ref_count);
	/* Using single portal  for all devices */
	dpio_dev->mc_portal = dev_priv->mc_portal;

	NADK_INFO(FW, "\t MC_portal [%p]\n", dpio_dev->mc_portal);
	LOCK_INIT(dpio_dev->lock, NULL);
	/* Get SW portals regions */
	reg_info.index = 0;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO,
							&reg_info)) {
		NADK_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_REGION_INFO failed\n");
		goto free_dpio;
	}
	NADK_INFO(FW, "\t CE Region Offset = %llx\n", reg_info.offset);
	NADK_INFO(FW, "\t CE Region Size = %llx\n", reg_info.size);
	dpio_dev->ce_size = reg_info.size;
	dpio_dev->qbman_portal_ce_paddr = (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);
	/* Create Mapping for QBMan Cache Enabled area. This is a fix for
	   SMMU fault for DQRR statshing transaction. */
	if (vfio_dmamap_mem_region(dpio_dev->qbman_portal_ce_paddr,
				reg_info.offset,
				reg_info.size)) {
		NADK_ERR(FW, "DMAMAP for Portal CE area failed.\n");
		goto free_dpio;
	}

	reg_info.index = 1;
	if (ioctl(dpio_dev->vfio_fd, VFIO_DEVICE_GET_REGION_INFO,
					&reg_info)) {
		NADK_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_REGION_INFO failed\n");
		goto free_dpio;
	}
	NADK_INFO(FW, "\t CI Region Offset = %llx\n", reg_info.offset);
	NADK_INFO(FW, "\t CI Region Size = %llx\n", reg_info.size);
	dpio_dev->ci_size = reg_info.size;
	dpio_dev->qbman_portal_ci_paddr =  (uint64_t)mmap(NULL, reg_info.size,
				PROT_WRITE | PROT_READ, MAP_SHARED,
				dpio_dev->vfio_fd, reg_info.offset);

	/* Get the interrupts for DPIO device */
	if (nadk_get_interrupt_info(dpio_dev->vfio_fd, obj_info,
		&(dpio_dev->intr_handle)) != NADK_SUCCESS) {
		NADK_ERR(FW, "Unable to get interrupt information\n");
		goto free_dpio;
	};

	/* Initialize the IO space sw portal */
	dpio_dev->dpio = nadk_malloc(NULL, sizeof(struct fsl_mc_io));
	if (!dpio_dev->dpio) {
		NADK_ERR(FW, "Memory allocation failure\n");
		goto free_dpio;
	}
	NADK_INFO(FW, "\t Allocated  DPIO[%p]\n", dpio_dev->dpio);
	dpio_dev->dpio->regs = dpio_dev->mc_portal;
	if (dpio_open(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->hw_id,
			&(dpio_dev->token))) {
		NADK_ERR(FW, "Failed to allocate IO space\n");
		goto free_res;
	}
	if (dpio_enable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token)) {
		NADK_ERR(FW, "DPIO failed to Enable\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		goto free_res;
	}
	if (dpio_get_attributes(dpio_dev->dpio, CMD_PRI_LOW,
			dpio_dev->token, &attr)) {
		NADK_ERR(FW, "DPIO Get attribute failed\n");
		dpio_disable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW,  dpio_dev->token);
		goto free_res;
	}
	/* The following condition must not be TRUE */
	if (dpio_dev->hw_id != attr.id)
		NADK_WARN(FW, "DPIO IDs are different. VFIO vs MC API\n");

	NADK_INFO(FW, "DPIO ID %d\n", attr.id);
	NADK_INFO(FW, "Qbman Portal ID %d\n", attr.qbman_portal_id);
	NADK_INFO(FW, "Portal CE addr 0x%llX\n", attr.qbman_portal_ce_offset);
	NADK_INFO(FW, "Portal CI addr 0x%llX\n", attr.qbman_portal_ci_offset);
	/* Configure & setup SW portal */
	p_des.block = NULL;
	p_des.idx = attr.qbman_portal_id;
	p_des.cena_bar = (void *)(dpio_dev->qbman_portal_ce_paddr);
	p_des.cinh_bar = (void *)(dpio_dev->qbman_portal_ci_paddr);
	p_des.irq = -1;
	NADK_INFO(FW, "Portal CE addr 0x%p\n", p_des.cena_bar);
	NADK_INFO(FW, "Portal CI addr 0x%p\n", p_des.cinh_bar);
	p_des.qman_version = attr.qbman_version;
	dpio_dev->sw_portal = qbman_swp_init(&p_des);
	if (dpio_dev->sw_portal == NULL) {
		NADK_ERR(FW, "QBMan SW Portal Init failed\n");
		dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		goto free_res;
	}
	NADK_INFO(FW, "\t DPIO[%d]  ", dpio_dev->hw_id);
	NADK_INFO(FW, "QBMan SW Portal 0x%p\n", dpio_dev->sw_portal);

	/* Add device to NADK DPIO device List */
	if ((dev_priv->flags & NADK_EVENT_NOTIFIER) &&
			(NULL == notif_dpio) &&
			(attr.channel_mode == DPIO_LOCAL_CHANNEL)) {
		notif_dpio = dpio_dev;
		if (nadk_notif_dpio_init() != NADK_SUCCESS) {
			NADK_ERR(FW, "Unable to intialize the "
				"notification DPIO");
			notif_dpio = NULL;
			goto free_res;
		}
		NADK_INFO(FW, "NOTIFIER DPIO allocated\n");
		return NADK_SUCCESS;
	}

	io_space_count++;
	dpio_dev->index = io_space_count;
	TAILQ_INSERT_HEAD(dpio_dev_list, dpio_dev, next);

	NADK_INFO(FW, "\t Allocated DPIO Device %d\n", io_space_count);
	return NADK_SUCCESS;
free_res:
	nadk_free(dpio_dev->dpio);
free_dpio:
	LOCK_DESTROY(dpio_dev->lock);
	nadk_free(dpio_dev);
	return NADK_FAILURE;
}


void release_dpio(struct nadk_dpio_dev *dpio_dev)
{
	int ret;

	SWP_LOCK(dpio_dev);
	if (dpio_dev->dpio) {
		NADK_INFO(FW, "Closing DPIO object %p\n", dpio_dev->dpio);
		qbman_swp_finish(dpio_dev->sw_portal);

		ret = dpio_disable(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			NADK_ERR(FW, "Error in Disabling DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		ret = dpio_reset(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			NADK_ERR(FW, "Error in Resetting DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		ret = dpio_close(dpio_dev->dpio, CMD_PRI_LOW, dpio_dev->token);
		if (ret)
			NADK_ERR(FW, "Error in Closing DPIO "
				"device %p  Error %d\n", dpio_dev, ret);
		nadk_free(dpio_dev->dpio);
	}
	SWP_UNLOCK(dpio_dev);
	nadk_free(dpio_dev);

}

/* DPIO device cleanup fucntion */
int32_t nadk_io_portal_close(ODP_UNUSED struct nadk_dev *dev)
{
	/*Function is reverse of nadk_io_portal_probe.
	 * 1. RESET & Close the DPIO device
	 * 2. Free the allocated resources.
	 */
	if (dpio_dev_list) {
		struct nadk_dpio_dev *dpio_dev = NULL, *tmp;

		dpio_dev = TAILQ_FIRST(dpio_dev_list);
		while (dpio_dev) {
			NADK_INFO(FW, "RELEASING DPIO device %p\n", dpio_dev);
			tmp = TAILQ_NEXT(dpio_dev, next);
			release_dpio(dpio_dev);
			dpio_dev = tmp;
		}
		nadk_free(dpio_dev_list);
		dpio_dev_list = NULL;
	}
	/* Handle cleanup for notifier specific DPIO */
	if (notif_dpio) {
		release_dpio(notif_dpio);
		notif_dpio = NULL;
	}

	return NADK_SUCCESS;
}

/*!
 * @details	This function must be invoked by each IO thread of application
 *		once.  This function will affine a thread to a given IO context.
 *		If an application wish to share a IO context between multiple
 *		threads, same IO context shall be passed for all required
 *		threads.
 *
 * @param[in]	io_index - An index value of IO context. Range is 1 to
 *		total IO context count. or NADK_IO_PORTAL_ANY_FREE to be
 *		choosed by the underlying API.
 *
 * @returns     NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_thread_affine_io_context(uint32_t io_index)
{

	struct nadk_dpio_dev *dpio_dev = NULL;
	uint32_t ret;

	if (thread_io_info.dpio_dev) {
		NADK_NOTE(FW, "io_index %d  thread alread affined to =%d",
				io_index, thread_io_info.dpio_dev->index);
		return NADK_SUCCESS;
	}

	if (io_index == NADK_IO_PORTAL_ANY_FREE) {
		/* Get any unused DPIO dev handle from list */
		TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
		NADK_DBG(FW, "cpu %d io_index %d dpio index %d - dpio =%x/%d",
				odp_cpu_id(), io_index, dpio_dev ? dpio_dev->index : 0xff,
				thread_io_info.dpio_dev,
				odp_atomic_read_u16(&dpio_dev->ref_count));
		if (dpio_dev && (odp_atomic_read_u16(&dpio_dev->ref_count) == 0))
			break;
		}
	} else {
		/* Index value must lie in range (1 - io_space_count.resource_count) */
		if ((io_index <= 0) || (io_index > io_space_count)) {
			NADK_ERR(FW, "\tInvalid IO index- %d (ip_space_count = %d)\n",
						io_index, io_space_count);
			return NADK_FAILURE;
		}
		/* Get DPIO dev handle from list using index */
		TAILQ_FOREACH(dpio_dev, dpio_dev_list, next) {
			if (dpio_dev && (dpio_dev->index == io_index))
				break;
		}
	}
	if (!dpio_dev) {
		NADK_ERR(FW, "\tdpio_dev not found or not available\n");
		return NADK_FAILURE;
	}

	/* Increment reference count */
	odp_atomic_inc_u16(&dpio_dev->ref_count);

	/* Populate the thread_io_info structure */
	thread_io_info.dpio_dev = dpio_dev;
	thread_io_info.dq_storage = nadk_data_malloc(NULL,
		NUM_MAX_RECV_FRAMES * sizeof(struct qbman_result),
		ODP_CACHE_LINE_SIZE);
	if (!thread_io_info.dq_storage) {
		NADK_ERR(FW, "Memory allocation failure");
		return NADK_FAILURE;
	}
	ret = nadk_configure_stashing();
	if (ret) {
		NADK_ERR(FW, "nadk_configure_stashing failed");
		return NADK_FAILURE;
	}
	NADK_DBG(FW, "io_index %d affined with dpio index %d - dpio =%p",
			io_index, dpio_dev->index, thread_io_info.dpio_dev);

	return NADK_SUCCESS;
}

static int32_t nadk_configure_stashing(void)
{
	int8_t sdest;
	int32_t cpu_id, ret;
	struct nadk_dpio_dev *dpio_dev = NULL;

	dpio_dev = thread_io_info.dpio_dev;
	if (!dpio_dev) {
		NADK_ERR(FW, "\tdpio_dev not found. Stashing cannot be set\n");
		return NADK_FAILURE;
	}

	/* Set the Stashing Destination */
	cpu_id = sched_getcpu();/* change it to odp_cpu_id(), when nadk is deprecreted*/;
	if (cpu_id < 0) {
		NADK_ERR(FW, "\tGetting CPU Index failed\n");
		return NADK_FAILURE;
	}

#ifdef ODP_ON_VM
/*
 * In case of running ODP on the Virtual Machine the Stashing Destination gets
 * set in the H/W w.r.t. the Virtual CPU ID's. As a W.A. environment variable
 * HOST_START_CPU tells which the offset of the host start core of the
 * Virtual Machine threads.
 */
	if (getenv("HOST_START_CPU")) {
		cpu_id += atoi(getenv("HOST_START_CPU"));
		cpu_id = cpu_id % NUM_HOST_CPUS;
	}
#endif

	/* Set the STASH Destination depending on Current CPU ID.
	   Valid values of SDEST are 4,5,6,7. Where,
	   CPU 0-1 will have SDEST 4
	   CPU 2-3 will have SDEST 5.....and so on.
	*/
	NADK_CORE_CLUSTER_GET(sdest, cpu_id);
	NADK_INFO(FW, "%s: Portal= %d  CPU= %u SDEST= %d\n",
			__func__, dpio_dev->index, cpu_id, sdest);

	ret = dpio_set_stashing_destination(dpio_dev->dpio, CMD_PRI_LOW,
						dpio_dev->token, sdest);
	if (ret) {
		NADK_ERR(FW, "%s: %d ERROR in Setting SDEST\n", __func__, ret);
		return NADK_FAILURE;
	}
	return NADK_SUCCESS;
}

/*!
 * @details	Stop the already active IO thread & de-affine IO context from
 *		current thread. This function must be invoked before exiting
 *		from thread if, it has initially called
 *		nadk_thread_affine_io_context().
 *
 * @returns     Not applicable.
 *
 */
void nadk_thread_deaffine_io_context(void)
{
	struct nadk_dpio_dev *dpio_dev;

	/* Get DPIO portal for this thread context */
	dpio_dev = thread_io_info.dpio_dev;
	if ((dpio_dev == NULL) ||
			(odp_atomic_read_u16(&dpio_dev->ref_count) == 0))
		return;
	/* Decrement reference count */
	odp_atomic_dec_u16(&dpio_dev->ref_count);
	/* Unset the thread_io_info structure */
	nadk_data_free(thread_io_info.dq_storage);
	thread_io_info.dq_storage = NULL;
	thread_io_info.dpio_dev = NULL;
}

uint32_t nadk_get_io_context_count(void)
{
	return io_space_count;
}


int nadk_register_dpio_interrupt(struct nadk_dpio_dev *dpio_dev,
		uint32_t index)
{
	return nadk_register_interrupt(dpio_dev->vfio_fd,
		&(dpio_dev->intr_handle[index]), index);
}
