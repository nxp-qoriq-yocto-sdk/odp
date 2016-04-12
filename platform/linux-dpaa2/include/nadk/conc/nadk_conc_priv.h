/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_conc_priv.h
 * @description		Private functions & MACRO definitions for concentrator
			Type Device
 */

#ifndef _NADK_CONC_PRIV_H_
#define _NADK_CONC_PRIV_H_

/*Standard header files*/
#include <stddef.h>

/*Nadk header files*/
#include <nadk_dev.h>
#include <odp/hints.h>
#include <nadk_mpool.h>
#include <odp/std_types.h>
#include <odp/spinlock.h>


#ifdef __cplusplus
extern "C" {
#endif

#define MAX_DEV_NAME_LENGTH		32

#define NADK_MAX_DEVICES_PER_CONC	16

#define NADK_INVALID_CHANNEL_ID		((uint32_t)(-1))

/*!
 * Structure to contain private information for DPCON devices.
 */
struct nadk_conc_priv {
	char name[MAX_DEV_NAME_LENGTH];
};

/*!
 * Structure to attributes for DPCON devices.
 */
struct conc_attr {
	int32_t obj_id;	/*!< DPCONC object ID */
	uint16_t ch_id;	/*!< Channel ID to be used for dequeue operation */
	uint8_t num_prio;/*!< Number of prioties within the Channel */
};

/*!
 * @details	Concentrator API to register to NADK framework. It will be called
 *		by NADK core framework and corresponding device driver will be
 *		added to NADK's driver list.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_driver_init(void);

/*!
 * @details	Concentrator API to unregister to NADK framework. It will be called
 *		by NADK core framework and corresponding device driver will be
 *		removed	from NADK's driver list.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_driver_exit(void);

/*!
 * @details	Concentrator driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to NADK concentrator device
 *
 * @param[in]	data - Pointer to device specific configuration. NULL otherwise.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_probe(struct nadk_dev *dev, const void *data);

/*!
 * @details	Concentrator driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to NADK Concentrator device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_remove(struct nadk_dev *dev);

/*!
 * @details	Enable a Concentrator device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to NADK Concentrator device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_start(struct nadk_dev *dev);

/*!
 * @details	Disable a  Concentrator device for use of RX/TX.
 *		After disabling no data can be Received or transmitted
 *
 * @param[in]	dev - Pointer to NADK Concentrator device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_stop(struct nadk_dev *dev);

/*!
 * @details	Receives frames from given NADK device and VQ.
 *
 * @param[in]	dev - Pointer to NADK Concentrator device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to NADK buffer which will be passed to user
 *
 * @param[in]	num - Number of frames to be received
 *
 * @returns	Actual total number of frames received on success.
 *		NADK_FAILURE otherwise.
 *
 */
int32_t nadk_conc_recv(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);


/*!
 * @details	Returns attributes for concentrator device.
 *
 * @param[in]	dev - Pointer to NADK concentrator  device.
 *
 * @param[in,out] attr - Pointer to attributs structure.
 *
 */
void nadk_conc_get_attributes(struct nadk_dev *dev, struct conc_attr *attr);


int32_t nadk_attach_device_to_conc(struct nadk_dev *dev, uint8_t vq_id,
					struct nadk_dev *conc);


#ifdef __cplusplus
}
#endif

#endif /* _NADK_CONC_PRIV_H_ */
