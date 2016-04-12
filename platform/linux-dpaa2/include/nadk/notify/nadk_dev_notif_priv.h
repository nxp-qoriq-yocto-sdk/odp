/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */


/**
 * @file	nadk_dev_notif_priv.h
 *
 * @brief	Private header file for NADK event notifier module
 */

#ifndef _NADK_DEV_NOTIF_PRIV_H_
#define _NADK_DEV_NOTIF_PRIV_H_

/* NADK Header files */
#include <nadk_dev.h>
#include <odp/std_types.h>
#include <nadk_queue.h>

/*! Default priority on basis of which FQDAN will be received */
#define NADK_NOTIF_DEF_PRIO	0

/*!
 * Notifier context structure which is created for every VQ which is
 * registered to the notifier so that when FQDAN/CDAN is received eventfd,
 * dev and vq can be determined
 */
struct notif_cnxt {
	TAILQ_ENTRY(notif_cnxt) next; /*!< Next in list. */
	int eventfd; /*!< Corresponding Eventfd */
	uint64_t user_cnxt; /*!< User Context provided by the user while
			     * configuring the notification */
	nadk_notification_callback_t cb; /*!< User registered
					  * callback function */
};
TAILQ_HEAD(notif_cnxt_list, notif_cnxt); /*!< Notifier context in D-linked Q */

/*!
 * @details	Initialize the notifier
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_notif_init(void);


/*!
 * @details	Register a VQ with the notifier. This will create an eventfd
 *		which is returned to the calling function and will also return
 *		the user_context which will be required by the device driver to
 *		configure the FQDAN/CDAN.
 *
 * @param[in]	user_context - User_context to be stored and given with
 *		event notification or callback
 *
 * @param[in]	cb - Callback provided by the user. In case callback is
 *		non-null, this will be called when notification is received
 *
 * @param[out]	efd - eventfd corresponding to the VQ
 *
 * @param[out]	notifier_context - Notifier Context which is required by
 *		calling function to configure the FQDAN/CDAN.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise
 *
 */
int nadk_reg_with_notifier(
		uint64_t user_context,
		nadk_notification_callback_t cb,
		int *efd,
		uint64_t *notifier_context);


/*!
 * @details	De-init the notifier
 *
 * @returns	none
 *
 */
void nadk_notif_close(void);


#endif	/* _NADK_DEV_NOTIF_PRIV_H_ */
