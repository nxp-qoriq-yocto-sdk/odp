/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_ldpaa.c
 *
 * @brief	Layerscape DPAA specific NADK framework functionalities.
 *
 */
#include <odp/std_types.h>
#include <fsl_dprc.h>
#include <fsl_dpio.h>
#include <fsl_dpmcp.h>

#include <pthread.h>
#include <fsl_qbman_portal.h>
#include <nadk.h>
#include <nadk_vfio.h>
#include <nadk_internal.h>
#include <nadk_dev_priv.h>
#include <nadk_malloc.h>
#include <nadk_mbuf_priv_ldpaa.h>
#include <nadk_io_portal_priv.h>
#include <nadk_dev_notif_priv.h>
#include <nadk_hwq_priv.h>

#include "eal_hugepages.h"
#include <nadk_memory.h>
#include <nadk_memconfig.h>
#include <dirent.h>
#include <string.h>
#include <odp/hints.h>

/***** Macros ********/

/***** Global Variables ********/
extern struct vfio_group vfio_groups[VFIO_MAX_GRP];
extern int container_device_fd;

/*!
 * A variable to store thread specific configuration / Settings.
 * This shall be defined per thread.
*/

/* MC Portals */
uint32_t mcp_id;
void *(*mcp_ptr_list);

#define MC_PORTALS_BASE_PADDR   ((phys_addr_t)0x00080C000000ULL)
#define MC_PORTAL_STRIDE        0x10000
#define MC_PORTAL_SIZE	64
#define MC_PORTAL_ID_TO_PADDR(portal_id) \
	(MC_PORTALS_BASE_PADDR + (portal_id) * MC_PORTAL_STRIDE)
/* Common MC Portal */
#define MC_PORTAL_INDEX		0

void *get_mc_portal(uint32_t idx)
{
	uint64_t mc_portal_paddr;
	int64_t v_addr;

	mc_portal_paddr = MC_PORTAL_ID_TO_PADDR(idx);
	NADK_INFO(FW, "MC [%d] has PHY_ADD = 0x%llX\n", idx, mc_portal_paddr);
	v_addr = (uint64_t)mmap(NULL, MC_PORTAL_SIZE,
		PROT_WRITE | PROT_READ, MAP_SHARED,
		container_device_fd, mc_portal_paddr);
	if (v_addr == -1)
		return NULL;

	NADK_INFO(FW, "MC [%d] has VIR_ADD = 0x%llX\n", idx, v_addr);
	return (void *)v_addr;
}

enum nadk_dev_type mc_to_nadk_dev_type(const char *dev_name)
{
	if (!strcmp(dev_name, "dpni"))
		return NADK_NIC;
	if (!strcmp(dev_name, "dpsw"))
		return NADK_SW;
	if (!strcmp(dev_name, "dpcon"))
		return NADK_CONC;
	if (!strcmp(dev_name, "dpci"))
		return NADK_AIOP_CI;
	if (!strcmp(dev_name, "dpseci"))
		return NADK_SEC;
	if (!strcmp(dev_name, "dpio"))
		return NADK_IO_CNTXT;

	/* Will add More cases */
	return NADK_MAX_DEV;
}


static struct nadk_driver *get_device_driver(const char *dev_name)
{

	enum nadk_dev_type dev_type =
		mc_to_nadk_dev_type(dev_name);

	if (dev_type == NADK_MAX_DEV)
		return NULL;

	return nadk_driver_list[dev_type];

}

/* Following function shall fetch total available list of MC devices
 * from VFIO container & populate private list of devices and other
 * data structures
 */
static int32_t nadk_dev_init_all(struct nadk_init_cfg *cfg)
{

	struct vfio_device *vdev;
	struct vfio_device_info device_info = { .argsz = sizeof(device_info) };
	struct vfio_group *group = &vfio_groups[0];
	char *temp_obj, *mcp_obj, *dev_name;
	const char *object_type;
	int32_t ret, object_id, i, dev_fd;
	DIR *d;
	struct dirent *dir;
	char path[VFIO_PATH_MAX];
	int64_t v_addr;

	sprintf(path, "/sys/kernel/iommu_groups/%d/devices", group->groupid);

	NADK_INFO(FW, "\t Devices path = %s\n", path);

	d = opendir(path);
	if (!d) {
		NADK_ERR(FW, "\t Unable to open directory %s\n", path);
		return NADK_FAILURE;
	}

	/*Counting the number of devices in a group and getting the mcp ID*/
	ndev_count = 0;
	mcp_obj = NULL;
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type == DT_LNK) {
			ndev_count++;
			if (!strncmp("dpmcp", dir->d_name, 5)) {
				if (mcp_obj)
					nadk_free(mcp_obj);
				mcp_obj = nadk_malloc(NULL, sizeof(dir->d_name));
				if (!mcp_obj) {
					NADK_ERR(FW, "\t Unable to allocate memory\n");
					return NADK_FAILURE;
				}
				strcpy(mcp_obj, dir->d_name);
				temp_obj = strtok(dir->d_name, ".");
				temp_obj = strtok(NULL, ".");
				sscanf(temp_obj, "%d", &mcp_id);
			}
		}
	}
	closedir(d);

	if (!mcp_obj) {
		NADK_ERR(FW, "\t MCP Object not Found\n");
		return NADK_FAILURE;
	}
	NADK_INFO(FW, "\t Total devices in conatiner = %d, MCP ID = %d\n",
			ndev_count, mcp_id);
	/* Allocate the memory depends upon number of objects in a group*/
	group->vfio_device = (struct vfio_device *) nadk_malloc(NULL,
				ndev_count * sizeof(struct vfio_device));

	if (!(group->vfio_device)) {
		NADK_ERR(FW, "\t Unable to allocate memory\n");
		nadk_free(mcp_obj);
		return NADK_FAILURE;
	}

	/* Initialize the Device List */
	TAILQ_INIT(&device_list);

	/* Allocate memory for MC Portal list */
	mcp_ptr_list = nadk_malloc(NULL, sizeof(void *) * 1);
	if (!mcp_ptr_list) {
		NADK_ERR(FW, "NO Memory!\n");
		nadk_free(mcp_obj);
		goto FAILURE;
	}

	v_addr = vfio_map_mcp_obj(group, mcp_obj);
	nadk_free(mcp_obj);
	if (v_addr == (int64_t) MAP_FAILED) {
		NADK_ERR(FW, "Error mapping region (errno = %d)\n", errno);
		goto FAILURE;
	}

	NADK_INFO(FW, "MC  has VIR_ADD = 0x%llX\n", v_addr);

	mcp_ptr_list[0] = (void *)v_addr;


	d = opendir(path);
	if (!d) {
		NADK_ERR(FW, "\t Directory %s not able to open\n", path);
		goto FAILURE;
	}

	i = 0;
	/* Parsing each object and initiating them*/
	while ((dir = readdir(d)) != NULL) {
		if (dir->d_type != DT_LNK)
			continue;
		if (!strncmp("dprc", dir->d_name, 4) || !strncmp("dpmcp", dir->d_name, 5))
			continue;
		dev_name = nadk_malloc(NULL, sizeof(dir->d_name));
		if (!dev_name) {
			NADK_ERR(FW, "\t Unable to allocate memory\n");
			goto FAILURE;
		}
		strcpy(dev_name, dir->d_name);
		object_type = strtok(dir->d_name, ".");
		temp_obj = strtok(NULL, ".");
		sscanf(temp_obj, "%d", &object_id);
		NADK_INFO(FW, "Parsing Device = %s\n", dev_name);

		/* getting the device fd*/
		dev_fd = ioctl(group->fd, VFIO_GROUP_GET_DEVICE_FD, dev_name);
		if (dev_fd < 0) {
			NADK_ERR(FW, "\tvfio: error getting device %s fd from group %d\n",
				dev_name, group->fd);
			nadk_free(dev_name);
			goto FAILURE;
		}
		nadk_free(dev_name);
		NADK_INFO(FW, "\tAdding device at index %d", group->object_index);
		vdev = &group->vfio_device[group->object_index++];
		vdev->fd = dev_fd;
		vdev->index = i;
		i++;
		/* Get Device inofrmation */
		if (ioctl(vdev->fd, VFIO_DEVICE_GET_INFO, &device_info)) {
			NADK_ERR(FW, "VFIO_DEVICE_FSL_MC_GET_INFO failed");
			goto FAILURE;
		}
		NADK_INFO(FW, "\tDevice Type %s, ID %d",
				object_type, object_id);
		NADK_INFO(FW, "\tnum_regions %d num_irqs %d",
				device_info.num_regions, device_info.num_irqs);


		/* Alloc a nadk_dev struct and add to device table */
		if (!strcmp(object_type, "dpbp")) {
			/* Call Buffer pool APIs to intialize pools */
			NADK_INFO(FW, "Initializing DPBP DEVICE.\n");
			if (nadk_mbuf_dpbp_init((uint64_t)mcp_ptr_list[MC_PORTAL_INDEX],
				object_id)) {
				NADK_ERR(FW, "DPBP Initialization Failed\n");
				goto FAILURE;
			}

		} else if (!strcmp(object_type, "dpio")) {

			struct nadk_driver *drv;
			struct nadk_dev_priv dev_priv;

			/* Get the Matching driver for this device */
			NADK_INFO(FW, "Initializing DEVICE[%s].\n", object_type);
			drv = get_device_driver(object_type);
			if (NULL == drv) {
				NADK_WARN(FW, "No Device driver for [%s]\n",
							object_type);
				continue;
			}

			dev_priv.vfio_fd = vdev->fd;
			dev_priv.hw_id = object_id;
			/* Using single portal  for all devices */
			dev_priv.mc_portal = mcp_ptr_list[MC_PORTAL_INDEX];
			dev_priv.flags = cfg->flags;
			/* Pass VFIO object attributes that may be used by DPIO driver.
			   The driver will overrite private data pointer to its own
			   data structure pointer, if required.
			 */
			dev_priv.drv_priv = (void *)&device_info;
			/* Now prob the DPIO device. DPIO portal driver will alocate its own
			   device strcuture & maintain same in seperate DPIO device list */
			NADK_INFO(FW, "Probing DPIO device.\n");
			if (drv->dev_probe(NULL, (void *)&dev_priv)) {
				NADK_WARN(FW, "Device [%s] Probe Failed.\n", object_type);
				continue;
			}

		} else if (!strcmp(object_type, "dpni") ||
				!strcmp(object_type, "dpci") ||
				!strcmp(object_type, "dpseci") ||
				!strcmp(object_type, "dpcon")) {

			struct nadk_driver *drv;
			struct nadk_dev *dev;
			struct nadk_dev_priv *dev_priv;

			/* Get the Matching driver for this device */
			NADK_INFO(FW, "Initializing DEVICE[%s].\n", object_type);
			drv = get_device_driver(object_type);
			if (NULL == drv) {
				NADK_WARN(FW, "No Device driver for [%s]\n",
							object_type);
				continue;
			}

			/* Allocate NADK device object */
			dev = nadk_malloc(NULL, sizeof(struct nadk_dev));
			if (!dev) {
				NADK_ERR(FW, " NO memory for DEVICE.\n");
				goto FAILURE;
			}
			dev_priv = nadk_malloc(NULL, sizeof(struct nadk_dev_priv));
			if (!dev_priv) {
				nadk_free(dev);
				NADK_ERR(FW, "No memory for device priv.\n");
				goto FAILURE;
			}
			dev->state = DEV_INACTIVE;
			dev->dev_type =
				mc_to_nadk_dev_type(object_type);

			/* Fill VFIO data. This shall be required in
			   device driver probe function for xxx_open API.
			*/
			dev_priv->vfio_fd = vdev->fd;
			dev_priv->hw_id = object_id;
			dev_priv->bp_list = NULL;
			/* Using single portal  for all devices */
			dev_priv->mc_portal = mcp_ptr_list[MC_PORTAL_INDEX];
			/* Pass VFIO object attributes that may be used by device driver.
			   The driver will overrite private data pointer to its own
			   data structure pointer, if required.
			 */
			dev_priv->drv_priv = (void *)&device_info;
			dev->priv = (void *)dev_priv;
			dev_priv->flags = cfg->flags;

			/* Initialize function pointers to dummy ones.
			 The device driver shall overwrite them with
			 required one */
			dev_priv->fn_dev_cfg = nadk_dummy_dev_fn;
			dev_priv->fn_dev_start = nadk_dummy_dev_fn;
			dev_priv->fn_dev_stop = nadk_dummy_dev_fn;
			dev_priv->fn_dev_send = nadk_dummy_send_fn;
			dev_priv->fn_dev_rcv = nadk_dummy_rcv_fn;
			dev_priv->fn_get_eventfd_from_vq = nadk_dummy_vq_fn;
			dev_priv->fn_get_vqid = nadk_dummy_vq_fn;
			dev_priv->fn_set_rx_vq_notif = nadk_dummy_notif_fn;
			/* Now prob the device */
			NADK_INFO(FW, "Probing device.\n");
			ret = drv->dev_probe(dev, cfg);
			if (ret != NADK_SUCCESS) {
				nadk_free(dev_priv);
				nadk_free(dev);
				if (ret == NADK_DEV_CONSUMED)
					/* In case device is condumed, don't ERR */
					NADK_INFO(FQ, "Device consumed");
				else
					NADK_WARN(FW, "Device Probe Failed.\n");
				continue;
			}
			/* Add device to NADK device List */
			TAILQ_INSERT_HEAD(&device_list, dev, next);
		} else {
			/* Handle all other devices */
			NADK_INFO(FW, "Unsupported Device Type '%s'\n",
					object_type);
			group->object_index--;
			i--;
			close(dev_fd);
		}
		/* End IF */
	}
	closedir(d);
	return NADK_SUCCESS;

FAILURE:
	nadk_free(group->vfio_device);
	group->vfio_device = NULL;
	return NADK_FAILURE;
}

int32_t nadk_dev_shutdown(ODP_UNUSED struct nadk_dev *dev)
{
	NADK_INFO(FW, "Device is closed successfully\n");
	return NADK_SUCCESS;
}

/*!
 * @details	Initialize the Network Application Development Kit Layer (NADK).
 *		This function must be the first function invoked by an
 *		application and is to be executed once.
 *
 * @param[in]	arg - A pointer to nadk_init_cfg structure.
 *
 * @returns     NADK_SUCCESS in case of successfull intialization of
 *		NADK Layer; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_platform_init(struct nadk_init_cfg *cfg)
{
	/* Do when we have valid VFIO container */
	if (cfg->vfio_container) {
		/* Find and Configure VFIO container / groups for this applicaton context */
		if (setup_vfio_grp(cfg->vfio_container))
			return NADK_FAILURE;

		/* Now scan & populate List of devices assigned to our container */
		if (nadk_dev_init_all(cfg))
			return NADK_FAILURE;
	}
	return NADK_SUCCESS;
}


/*!
 * @details	Do Clean up and exit for in context of a given application. This
 *		function must be invoked by an application before exiting.
 *
 * @returns     Not applicable.
 *
 */
void nadk_platform_exit(void)
{
	struct nadk_dev *dev;
	struct nadk_driver *drv;
	uint16_t mc_token, retcode;
	struct nadk_dev_priv *priv;
	struct fsl_mc_io mc_handle;

	/* Doing gracefull shutdown of all devices & release all resources */
	/* Need to handle cleanup for DPIO devices.
	   Get the Matching driver for this device */
	drv = get_device_driver("dpio");
	if (NULL != drv)
		drv->dev_shutdown(NULL);

	/* Handle cleanup of all other devices */
	dev = TAILQ_FIRST(&device_list);
	while (dev) {
		struct nadk_dev *dev_tmp;
		/* shutdown the device */
		NADK_INFO(FW, "RELEASING NIC %p\n", dev);
		drv = nadk_driver_list[dev->dev_type];
		drv->dev_shutdown(dev);
		/* Free unused memory */
		priv = (struct nadk_dev_priv *) dev->priv;
		close(priv->vfio_fd);
		nadk_free(dev->priv);
		dev_tmp = TAILQ_NEXT(dev, next);
		nadk_free(dev);
		dev = dev_tmp;
	}
	/* Close all the dpbp objects */
	nadk_mbuf_dpbp_close_all();
	/* Close all the frame queue objects */
	nadk_hwq_close_all();

	if (mcp_ptr_list) {
		mc_handle.regs = (void *) mcp_ptr_list[MC_PORTAL_INDEX];
		retcode = dpmcp_open(&mc_handle, CMD_PRI_LOW, mcp_id, &mc_token);
		if (retcode != 0)
			NADK_ERR(ETH, "Error in open MCP"
					" device: ErrorCode = %d\n", retcode);
		/* Resetting the device*/
		retcode = dpmcp_reset(&mc_handle, CMD_PRI_LOW, mc_token);
		if (retcode != 0)
			NADK_ERR(ETH, "Error in Resetting the MCP"
					" device: ErrorCode = %d\n", retcode);
		/*Close the device at underlying layer*/
		retcode = dpmcp_close(&mc_handle, CMD_PRI_LOW, mc_token);
		if (retcode != 0)
			NADK_ERR(ETH, "Error in closing the MCP"
					" device: ErrorCode = %d\n", retcode);

		nadk_free(mcp_ptr_list);
	}

	/* UNSET the container & Close Opened File descriptors */
	destroy_vfio_group(&vfio_groups[0]);
}

void nadk_dump_platform_device(void *device)
{
	/* Not Used for now*/
	device = device;

}

int32_t nadk_dev_affine_conc_list(struct nadk_dev *conc_dev ODP_UNUSED)
{
	NADK_INFO(EAL, "NOT supported for LDPAA\n");
	return NADK_SUCCESS;
}

int32_t nadk_dev_deaffine_conc_list(struct nadk_dev *conc_dev ODP_UNUSED)
{
	NADK_INFO(EAL, "NOT supported for LDPAA\n");
	return NADK_SUCCESS;
}
