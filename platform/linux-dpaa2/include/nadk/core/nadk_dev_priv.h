/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */


/**
 * @file		nadk_dev_priv.h
 * @description		Private function & definitions for NADK Device framework
 */

#ifndef _NADK_DEV_PRIV_H_
#define _NADK_DEV_PRIV_H_

#include <pthread.h>

#include <nadk.h>
#include <nadk_dev.h>
#include "nadk_vfio.h"
#include <fsl_mc_sys.h>

/*Macros to define QBMAN enqueue options */
/* Only Enqueue Error responses will be
 * pushed on FQID_ERR of Enqueue FQ */
#define NADK_EQ_RESP_ERR_FQ		0
/* All Enqueue responses will be pushed on address
 * set with qbman_eq_desc_set_response */
#define NADK_EQ_RESP_ALWAYS		1
/* Device is consumed at time of probing and does not needs
 * to be added into nadk_dev list */
#define NADK_DEV_CONSUMED		2

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *nadk_dev_fops*
 */
typedef int32_t (*nadk_dev_probe_t)(struct nadk_dev *dev, const void *cfg);
	 /**< Driver Function pointer to initialize a device instance. */
typedef int32_t (*nadk_dev_shutdown_t)(struct nadk_dev *dev); /**< Driver
				Function pointer to close a device. */
typedef int32_t (*nadk_dev_start_t)(struct nadk_dev *dev); /**< Driver
			Function pointer to start a device. */
typedef int32_t (*nadk_dev_cfg_t)(struct nadk_dev *dev); /**< Driver Function
			pointer for device default configuration. */
typedef int32_t (*nadk_dev_stop_t)(struct nadk_dev *dev); /**< Driver
			Function pointer to stop a device. */
typedef int32_t (*nadk_dev_send_t)(struct nadk_dev *dev,
			 void *vq,
			 uint32_t num,
			 nadk_mbuf_pt buf[]); /**< Driver Function pointer
					  to packet transmit Function */
typedef int32_t (*nadk_dev_setup_rx_vq_t) (struct nadk_dev *dev,
				uint8_t vq_index,
				struct nadk_vq_param *vq_cfg);
typedef int32_t (*nadk_dev_setup_tx_vq_t) (struct nadk_dev *dev,
				uint32_t num, uint32_t action);
typedef int (*nadk_dev_set_rx_vq_notif_t) (struct nadk_dev *dev,
				uint8_t vq_index,
				uint64_t user_context,
				nadk_notification_callback_t cb);

typedef int32_t (*nadk_dev_receive_t)(struct nadk_dev *dev,
			    void *vq,
			    uint32_t budget,
			    nadk_mbuf_pt buf[]); /**< Driver Function
					pointer to packet receive function */
typedef int32_t (*nadk_dev_get_eventfd_t)(void *vq); /**< Driver
				function pointer to get eventfd from VQ */
typedef int32_t (*nadk_dev_get_vqid_t)(void *vq); /**< Driver Function
					pointer to get the FQID/CHID */

/*
 * A structure that stores Common File operation & data for all drivers.
 */
struct nadk_driver {
	/**< Driver name. */
	const char	*name;
	uint32_t	vendor_id;
	uint32_t	major;
	uint32_t	minor;
	enum nadk_dev_type dev_type;
	/**< Device type of this Driver */
	nadk_dev_probe_t dev_probe;
	/**< Function pointer to probe a device. */
	nadk_dev_shutdown_t dev_shutdown;
	/**< Function pointer to close a device. */
};

/*
 * The NADK device structure private data.
 */
struct nadk_dev_priv {
	void *mc_portal; /**< MC Portal for configuring this device */
	void *hw; /**< Hardware handle for this device.Used by NADK framework */
	int32_t hw_id; /**< An unique ID of this device instance */
	int32_t qdid; /**< QDID for this device instance */
	int32_t	vfio_fd; /**< File descriptor received via VFIO */
	uint16_t token; /**< Token required by DPxxx objects */
	struct nadk_intr_handle *intr_handle;
	struct nadk_bp_list *bp_list; /**<Attached buffer pool list */

	/* Device operation function pointers */
	nadk_dev_cfg_t	fn_dev_cfg; /**< Driver Function pointer for device
				      default configuration. */
	nadk_dev_start_t fn_dev_start; /**< Driver Function pointer to start
					 a device. */
	nadk_dev_stop_t	fn_dev_stop; /**< Driver Function pointer to stop a
					device. */
	nadk_dev_send_t	fn_dev_send; /**< Driver Function pointer to packet
				       transmit Function */
	nadk_dev_receive_t fn_dev_rcv; /**< Driver Function pointer for
					 receiving packets */
	nadk_dev_setup_rx_vq_t fn_setup_rx_vq; /**< Driver Function pointer to
					 configure RX VQ */
	nadk_dev_setup_tx_vq_t fn_setup_tx_vq; /**< Driver Function pointer to
					 configure TX VQ */
	nadk_dev_set_rx_vq_notif_t fn_set_rx_vq_notif; /**< Driver Function
					pointer to configure RX VQ
					notification */
	nadk_dev_get_eventfd_t fn_get_eventfd_from_vq; /**< Driver Function
					pointer to get the eventfd from a VQ */
	nadk_dev_get_vqid_t fn_get_vqid; /**< Driver Function pointer to
					get the FQID/CHID */
	void	*drv_priv; /**< Private data of this device that is required
		by device driver. This shall contain device-specific Operations
		& Configuration parameters. */
	uint32_t flags;	/**< Flags passed by user to Enable features
			  like Shared Memory usage, notifier. */

};


struct nadk_dma_mem {
	unsigned long *ptr;
	uint64_t phys_addr;
};

extern void nadk_register_driver(struct nadk_driver *drv);
extern void nadk_unregister_driver(struct nadk_driver *drv);

static inline int32_t  nadk_dummy_dev_fn(ODP_UNUSED struct nadk_dev *dev)
{
	/* DO nothing */
	NADK_INFO(FW, "Dummy function");
	return NADK_SUCCESS;
}

static inline int32_t  nadk_dummy_vq_fn(ODP_UNUSED void *vq)
{
	/* DO nothing */
	NADK_INFO(FW, "Dummy function");
	return NADK_SUCCESS;
}

static inline int32_t nadk_dummy_send_fn(ODP_UNUSED struct nadk_dev *dev,
					 ODP_UNUSED void *vq,
				ODP_UNUSED uint32_t num,
				ODP_UNUSED nadk_mbuf_pt buf[])
{
	/* Raise indication that function not supported on this device */
	printf("Send function not supported for this device.\n");
	return NADK_SUCCESS;
}

static inline int32_t nadk_dummy_rcv_fn(ODP_UNUSED struct nadk_dev *dev,
					ODP_UNUSED void *vq,
				ODP_UNUSED uint32_t budget,
				ODP_UNUSED nadk_mbuf_pt buf[])
{
	/* Raise indication that function not supported on this device */
	printf("Receive function not supported for this device.\n");
	return NADK_SUCCESS;
}

static inline int32_t nadk_dummy_notif_fn(ODP_UNUSED struct nadk_dev *dev,
					  ODP_UNUSED uint8_t vq_index,
				ODP_UNUSED uint64_t user_context,
				ODP_UNUSED nadk_notification_callback_t cb)
{
	/* Raise indication that function not supported on this device */
	printf("Notification function not supported for this device.\n");
	return NADK_SUCCESS;
}

extern int ndev_count;

/* The NADK drivers list of registered drivers */
/* Drivers required for NIC, SEC, PME, DCE, AIOP_CI etc */
extern struct nadk_driver *nadk_driver_list[NADK_MAX_DEV];

void nadk_device_dump(void *stream);

#ifdef __cplusplus
}
#endif

#endif /* _NADK_DEV_PRIV_H_ */
