/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_dev_notif_priv.c
 *
 * @brief	Nadk event notifier module private API's
 *
 */

/* NADK Header files */
#include <sys/eventfd.h>
#include <nadk_queue.h>
#include <nadk_dev.h>
#include <nadk_dev_notif.h>
#include <nadk_dev_notif_priv.h>

struct notif_cnxt_list g_notif_cnxt_list;

int nadk_notif_init(void)
{
	NADK_TRACE(NOTIFIER);

	/* Initialize the Notifier context List */
	TAILQ_INIT(&g_notif_cnxt_list);

	return NADK_SUCCESS;
}


int nadk_reg_with_notifier(
		uint64_t user_context,
		nadk_notification_callback_t cb,
		int *efd,
		uint64_t *notifier_context)
{
	struct notif_cnxt *new_notif_cnxt = malloc(sizeof(struct notif_cnxt));

	NADK_TRACE(NOTIFIER);

	if (!new_notif_cnxt) {
		NADK_ERR(NOTIFIER, "Memory unavailable");
		return -ENOMEM;
	}

	new_notif_cnxt->user_cnxt = user_context;
	if (cb) {
		new_notif_cnxt->cb = cb;
	} else {
		/* Add a new link to the g_dev_vq */
		new_notif_cnxt->eventfd = eventfd(0, 0);
		if (new_notif_cnxt->eventfd == -1) {
			NADK_ERR(NOTIFIER, "Unable to create eventfd");
			free(new_notif_cnxt);
			return NADK_FAILURE;
		}
		if (!new_notif_cnxt->user_cnxt)
			new_notif_cnxt->user_cnxt = DEFAULT_USER_CONTEXT;
	}

	/* Add to the dev-vq List */
	TAILQ_INSERT_HEAD(&g_notif_cnxt_list, new_notif_cnxt, next);

	*efd = new_notif_cnxt->eventfd;
	*notifier_context = (uint64_t)(new_notif_cnxt);
	return NADK_SUCCESS;
}


void nadk_notif_close(void)
{
	struct notif_cnxt *p_notif_cnxt, *p_temp_notif_cnxt;

	NADK_TRACE(NOTIFIER);

	p_notif_cnxt = TAILQ_FIRST(&g_notif_cnxt_list);
	while (p_notif_cnxt) {
		p_temp_notif_cnxt = TAILQ_NEXT(p_notif_cnxt, next);
		nadk_free(p_notif_cnxt);
		p_notif_cnxt = p_temp_notif_cnxt;
	}

}
