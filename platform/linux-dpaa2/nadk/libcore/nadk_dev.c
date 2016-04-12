/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_dev.c
 * @description	Generic Device framework functions
 */
#include <odp/std_types.h>
#include <nadk_common.h>
#include <nadk_dev_priv.h>
#include <nadk_internal.h>
#include <nadk_vq.h>

/************   GLobal parameters ****************/

/* The NADK drivers– list of registered drivers */
/* Drivers required for NIC, SEC, AIOP_CI, PME, DCE */
struct nadk_driver *nadk_driver_list[NADK_MAX_DEV];

/**
 * The NADK device table.
 * It has all devices except for DPIO devices
 */
struct nadk_device_list device_list;
int ndev_count;

void nadk_register_driver(struct nadk_driver *drv)
{

	/* Check that driver data is filled properly */
	if (drv->dev_probe == NULL || drv->dev_shutdown == NULL) {
		NADK_ERR(FW, "Driver Probe or Shutdown function not exist\n");
		return;
	}

	/*  check for name as well. this shall be used
	    to match against the vfio device name. */
	if (drv->name == NULL) {
		NADK_ERR(FW, "Driver Name is missing\n");
		return;
	}
	/* Store the driver pointer */
	if (drv->dev_type > NADK_MAX_DEV) {
		NADK_ERR(FW, "Device not supported.\n");
		return;
	}

	if (nadk_driver_list[drv->dev_type]) {
		NADK_ERR(FW, "Driver already registered.\n");
		return;
	} else
		nadk_driver_list[drv->dev_type] = drv;

	NADK_INFO(FW, "Driver [%p] registed for DEV %d.\n",
					drv, drv->dev_type);
}

void nadk_unregister_driver(struct nadk_driver *drv)
{
	if (drv->dev_type > NADK_MAX_DEV) {
		NADK_ERR(FW, "Device not supported.\n");
		return;
	}

	if (nadk_driver_list[drv->dev_type])
		nadk_driver_list[drv->dev_type] = NULL;
}


int32_t nadk_dev_init(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;

	return dev_priv->fn_dev_cfg(dev);
}


int32_t nadk_dev_start(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;

	return dev_priv->fn_dev_start(dev);
}

int32_t nadk_dev_stop(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;

	return dev_priv->fn_dev_stop(dev);
}

int32_t nadk_send(struct nadk_dev *dev,
			 void *vq,
			 uint32_t num,
			 nadk_mbuf_pt buf[])
{
	struct nadk_dev_priv *dev_priv = dev->priv;

	return dev_priv->fn_dev_send(dev, vq, num, buf);
}

int32_t nadk_receive(struct nadk_dev *dev,
			void *vq,
			uint32_t budget,
			nadk_mbuf_pt buf[])
{
	if (odp_likely(((size_t)dev))) {
		struct nadk_dev_priv *dev_priv = dev->priv;
		return dev_priv->fn_dev_rcv(dev, vq, budget, buf);
	} else
		return 0;
}

int32_t nadk_dev_get_max_rx_vq(struct nadk_dev *dev)
{
	return dev->num_rx_vqueues;
}

int32_t nadk_dev_get_max_tx_vq(struct nadk_dev *dev)
{
	return dev->num_tx_vqueues;
}

int32_t nadk_dev_setup_rx_vq(struct nadk_dev *dev,
				uint32_t vq_index,
				struct nadk_vq_param *vq_cfg)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	return dev_priv->fn_setup_rx_vq(dev, vq_index, vq_cfg);
}


int32_t nadk_dev_setup_tx_vq(struct nadk_dev *dev, uint32_t num,
					uint32_t action)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	return dev_priv->fn_setup_tx_vq(dev, num, action);
}

int nadk_dev_set_rx_vq_notification(
		struct nadk_dev *dev,
		uint32_t vq_index,
		uint64_t user_context,
		nadk_notification_callback_t cb)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	return dev_priv->fn_set_rx_vq_notif(dev, vq_index, user_context, cb);
}

int32_t nadk_dev_hwid(struct nadk_dev *dev)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	return dev_priv->hw_id;
}

/* dump device */
static void
nadk_dump_one_device(void *stream, struct nadk_dev *dev)
{
	fprintf(stream, " - device:%s. type =%d\n",
		dev->dev_string, dev->dev_type);

	nadk_dump_platform_device(dev);
}

/* dump all the devices on the bus */
void
nadk_device_dump(void *stream)
{
	struct nadk_dev *dev = NULL;

	TAILQ_FOREACH(dev, &device_list, next) {
		nadk_dump_one_device(stream, dev);
	}
}

struct nadk_dev *nadk_dev_from_vq(void *vq)
{
	return (vq ? ((struct nadk_vq *)vq)->dev : NULL);
}

/*!
 * @details     Set given user context handle to VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @param[in]   uhandle - user context value which needs to be set.
 *
 *
 * @returns     NADK_SUCCESS on success, NADK_FAILURE otherwise.
 *
 */
int nadk_dev_set_vq_handle(void *vq, uint64_t uhandle)
{
	struct nadk_vq *mvq = (struct nadk_vq *)vq;
	if (mvq) {
		mvq->usr_ctxt = uhandle;
		return NADK_SUCCESS;
	}
	return NADK_FAILURE;
}

/*!
 * @details     Return user context handle associated to given VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @returns     Handle of specified VQ on success, 0 otherwise.
 *
 */
uint64_t nadk_dev_get_vq_handle(void *vq)
{
	return (vq ? ((struct nadk_vq *)vq)->usr_ctxt : 0);
}
