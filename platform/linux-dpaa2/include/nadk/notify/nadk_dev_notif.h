/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file nadk_dev_notif.h
 *
 * @brief	NADK notifier module header file. Using this module user can
 *	receive notifications to know that a packet is received on a particular
 *	queue of a device
 *
 * @addtogroup NADK_NOTIFIER
 * @ingroup NADK
 * @{
 */

#ifndef _NADK_DEV_NOTIF_H_
#define _NADK_DEV_NOTIF_H_

/* NADK header files */
#include <odp/std_types.h>

/*! Default user context. This is used in case 'user_context' is not
 * provided by the user in 'nadk_set_rx_vq_notification' API
 */
#define DEFAULT_USER_CONTEXT	1

/*!
 * @details	Process all the notifications. This API wakes up all the threads
 *		which have packets and are sleeping on the eventfd of the VQ's.
 *		The user will sleep inside the threads using a select call on
 *		eventfd of the VQ.
 *
 *		In case callback is registered by the user while configuring
 *		the notifications, then instead of waking up the threads, the
 *		registered callback will be called.
 *
* @param[in]	timeout - Timeout in milliseconds. This API will block till the
 *		timeout occurs in case no notification is there to process.
 *		Specifying timeout as -1 will block indefinately till any
 *		notification is there to process.
 *
 * @returns	none
 *
 */
int nadk_dev_process_notifications(int timeout);

/*!
 * @details	Each VQ will have it's own TX notification eventfd on
 *		which user can select and wait for the event i.e. a packet
 *		on that particular VQ. This API should be called only
 *		after the VQ is configured for the notification.
 *
 * @param[in]	dev - NADK device
 *
 * @param[in]	vq - Queue of the device
 *
 * @returns	eventfd value for a particular VQ
 *
 */
int nadk_dev_get_eventfd(
		struct nadk_dev *dev,
		void *vq);

/*!
 * @details	In NADK, everytime a select call is successful, events are
 *		disabled by default. So user needs to enable the notifications
 *		explicitly by calling this API before going for a select.
 *
 * @param[in]	dev - NADK device
 *
 * @param[in]	vq - Queue of the device
 *
 * @returns	NADK_SUCCESS on succees, EBUSY on busy, error code otherwise
 *
 */
int nadk_dev_vq_enable_notifications(
		struct nadk_dev *dev,
		void *vq);


#endif /* _NADK_DEV_NOTIF_H_ */
