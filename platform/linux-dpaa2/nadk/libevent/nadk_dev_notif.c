/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file nadk_dev_notif.c
 *
 * @brief	NADK notifier module. Using this module user can receive
 *	notifications to know that a packet is received on a particular
 *	queue of a device
 *
 */

/* System Header Files */
#include <sys/epoll.h>

/* NADK header files */
#include <nadk_dev_priv.h>
#include <nadk_mbuf_priv.h>
#include <nadk_io_portal_priv.h>
#include <nadk_dev_notif_priv.h>
#include <nadk_dev_notif.h>

/* QBMAN header files */
#include <fsl_qbman_portal.h>

int nadk_dev_process_notifications(int timeout)
{
	struct qbman_swp *swp = notif_dpio->sw_portal;
	const struct qbman_result *dqrr_entry;
	struct notif_cnxt *notifier_context;
	uint64_t user_context;
	struct epoll_event events[1];
	int nfds = 0;
	uint32_t status;

	NADK_TRACE(NOTIFIER);

	nfds = epoll_wait(notif_dpio_epollfd, events, 1, timeout);
	/* epoll returned error */
	if (nfds < 0) {
		NADK_ERR(NOTIFIER, "epoll_wait returns with fail");
		return NADK_FAILURE;
	} else if (nfds == 0) {
		/* epoll_wait timeout */
		return NADK_SUCCESS;
	}

	status = qbman_swp_interrupt_read_status(swp);
	if (!status)
		return NADK_FAILURE;

	/* Overloading user_context to read dummy value */
	read(notif_dpio->intr_handle[VFIO_DPIO_DATA_IRQ_INDEX].fd,
		&user_context, sizeof(uint64_t));

	/* Recieve the Notifications */
	while (TRUE) {
		dqrr_entry = qbman_swp_dqrr_next(swp);
		if (!dqrr_entry) {
			NADK_INFO(NOTIFIER, "No FQDAN/CDAN delivered");
			break;
		}
		/* Check if FQDAN/CDAN is received */
		if (!qbman_result_is_FQDAN(dqrr_entry) &&
			!qbman_result_is_CDAN(dqrr_entry)) {
			qbman_swp_dqrr_consume(swp, dqrr_entry);
			NADK_INFO(NOTIFIER, "No FQDAN/CDAN delivered");
			break;
		}
		/* Get the CNTX from the FQDAN/CDAN */
		notifier_context = (struct notif_cnxt *)
				qbman_result_SCN_ctx(dqrr_entry);
		user_context = notifier_context->user_cnxt;
		if (notifier_context->cb)
			notifier_context->cb(user_context);
		else
			write(notifier_context->eventfd,
				&user_context, sizeof(uint64_t));

		/* Consume the entry. */
		qbman_swp_dqrr_consume(swp, dqrr_entry);
		NADK_INFO(NOTIFIER, "Notification received");
	}

	/* Clear the status and mark it as non-inhibitted to
	 * re-enable the interrupt on the portal */
	qbman_swp_interrupt_clear_status(swp, status);
	qbman_swp_interrupt_set_inhibit(swp, 0);
	return NADK_SUCCESS;
}

int nadk_dev_get_eventfd(
		struct nadk_dev *dev,
		void *vq)
{
	struct nadk_dev_priv *dev_priv = dev->priv;

	NADK_TRACE(NOTIFIER);

	return dev_priv->fn_get_eventfd_from_vq(vq);
}


int nadk_dev_vq_enable_notifications(
		struct nadk_dev *dev,
		void *vq)
{
	struct nadk_dev_priv *dev_priv = dev->priv;
	int id = dev_priv->fn_get_vqid(vq);

	NADK_TRACE(NOTIFIER);

	if (dev->dev_type != NADK_CONC)
		return qbman_swp_fq_schedule(
			thread_io_info.dpio_dev->sw_portal, id);
	else
		return qbman_swp_CDAN_enable(
			thread_io_info.dpio_dev->sw_portal, id);

	return NADK_SUCCESS;
}
