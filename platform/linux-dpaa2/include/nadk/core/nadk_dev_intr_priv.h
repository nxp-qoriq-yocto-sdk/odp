/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */


/**
 * @file	nadk_dev_intr_priv.h
 *
 * @brief	Private header file for NADK interrupt event module
 */

#ifndef _NADK_DEV_INTR_PRIV_H_
#define _NADK_DEV_INTR_PRIV_H_

/* NADK header files */
#include <odp/std_types.h>
#include <nadk_common.h>
#include <nadk.h>
#include <nadk_vfio.h>
#include <nadk_malloc.h>

#define NADK_INTR_REGISTERED BIT_POS(31)
#define NADK_INTR_ENABLED BIT_POS(30)

/*!
 * NADK interrupt stucture. This is kept by each device to store the FD and
 * flags corresponding to an interrupt.
 */
struct nadk_intr_handle {
	int fd; /*!< eventfd corresponding to the device */
	uint32_t flags; /*!< flags including maskable/
		* automasked/is_enabled information */
};

/*!
 * @details	Get the interrupt information of a particular device from VFIO.
 *		This API will also populate the same in the NADK database.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	device_info - Device info corresponding to the device FD
 *		(also the one provided by VFIO)
 *
 * @param[in, out]	intr_handle - Pointer to NADK interrupt structure for
 *		the device. This will get allocated within this API based
 *		on the number of interrupts and will also get populated
 *		by the information received from VFIO. Default value of
 *		FD will be populated to '0'.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int nadk_get_interrupt_info(int dev_vfio_fd,
		struct vfio_device_info *device_info,
		struct nadk_intr_handle **intr_handle);


/*!
 * @details	Register the interrupt with VFIO. This API will create an
 *		eventfd corresponding to the interrupt and register it with
 *		the VFIO
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to NADK interrupt structure at a
 *		particular 'index' for the device.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int nadk_register_interrupt(int dev_vfio_fd,
		struct nadk_intr_handle *intr_handle,
		uint32_t index);


/*!
 * @details	Enable the interrupt in VFIO.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to NADK interrupt structure at a
 *		particular 'index' for the device which needs to be enabled.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int nadk_enable_interrupt(int dev_vfio_fd,
		struct nadk_intr_handle *intr_handle,
		uint32_t index);


/*!
 * @details	Disable the interrupt in VFIO.
 *
 * @param[in]	dev_vfio_fd - Device FD (the one which is provided by VFIO)
 *
 * @param[in]	intr_handle - Pointer to NADK interrupt structure at a
 *		particular 'index' for the device which needs to be disabled.
 *
 * @param[in]	index - Index of the 'intr_handle'. This also index represents
 *		the index provided to VFIO.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int nadk_disable_interrupt(int dev_vfio_fd,
		struct nadk_intr_handle *intr_handle,
		uint32_t index);

#endif	/* _NADK_DEV_INTR_PRIV_H_ */
