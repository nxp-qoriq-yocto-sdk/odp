/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_dev.h
 *
 * @brief	Device framework for NADK based applications.
 *		- Centralized driver model.
 *		- Library to initialize, start, stop &
 *		  configure a device.
 *
 * @addtogroup	NADK_CORE
 * @ingroup	NADK_DEV
 * @{
 */

#ifndef _NADK_DEV_H_
#define _NADK_DEV_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <nadk/rts/nadk_mbuf.h>
#include <nadk/common/nadk_queue.h>

/*! Default maximum size used in NADK to store name of a NADK DEVICE */
#define DEF_NAME_SZ	24
/* forward declaration of nadk_mbuf to avoid cyclic dependency.*/
struct nadk_mbuf;
/*!
 *  A set of values to identify Device Type.
 */

enum nadk_dev_type {
	NADK_NIC,	/*!< Network Interface */
	NADK_SEC,	/*!< SEC Accelerator Interface */
	NADK_PME,	/*!< PME Accelerator Interface */
	NADK_DCE,	/*!< DCE Accelerator Interface */
	NADK_AIOP_CI,	/*!< Advance IO Accelerator Command Interface */
	NADK_CONC,	/*!< Concentrator Device to group multiple VQ  */
	NADK_SW,	/*!< Switch Device */
	NADK_IO_CNTXT,	/*!< Input Outut context device object */
	NADK_MAX_DEV	/*!< Maximum Device types count */
};

/*! Maximum number of RX VQ's */
#define MAX_RX_VQS	64
/*! Maximum number of TX VQ's */
#define MAX_TX_VQS	64

/*! Maximum number of Error VQ's corresponding to each Tx */
#define MAX_ERR_VQS	 MAX_TX_VQS
/*! Maximum default number of Error VQ's corresponding to a device */
#define MAX_DEF_ERR_VQS        1

/*!
 *  Set of vq index used to receive tx-conf and errors.
 */
#define ERR_VQ_BASE    0
/*! Index of the default Error VQ of the device */
#define DEF_ERR_VQ_INDEX (ERR_VQ_BASE + MAX_ERR_VQS)

/*!
 *  A set of values to identify State of a Device.
 */
enum dev_state {
	DEV_INACTIVE = 0, /*!< Network Interface is not operational */
	DEV_ACTIVE	/*!< Network Interface ia Operational */
};

/*!
 *  A set of values to identify type of frame queue.
 */
enum nadk_fq_type {
	NADK_FQ_TYPE_RX = 0,		/*!< RX frame queue */
	NADK_FQ_TYPE_RX_ERR,		/*!< RX error frame queue */
	NADK_FQ_TYPE_TX,		/*!< TX frame queue */
	NADK_FQ_TYPE_TX_CONF_ERR	/*!< TX Conf/Error frame queue */
};

/*! No VQ scheduling */
#define ODP_SCHED_SYNC_NONE     0
/*! VQ shall be configured as atomic - order shall be preserved*/
#define ODP_SCHED_SYNC_ATOMIC   1
/*! VQ shall be configured in order restoration mode  */
#define ODP_SCHED_SYNC_ORDERED  2

/*!
 * NADK VQ attrubutes
 */
struct nadk_vq_param {
	struct nadk_dev *conc_dev;	/*!< Concentrator device if vq needs to
						be attached */
	uint8_t		sync;		/*!< Whether needs to be created atmoic
						or ordered */
	uint8_t		prio;		/*!< Priority associated with the vq */
};

/*!
 * NADK device structure.
 */
struct nadk_dev {
	TAILQ_ENTRY(nadk_dev) next; /*!< Next in list. */

	uint16_t state; /**< device is ACTIVE or Not */
	enum nadk_dev_type dev_type; /*!< Ethernet NIC, Accelerators
				     * like SEC, PME, DCE, AIOP */
	char dev_string[DEF_NAME_SZ]; /*!< To identify the device during bus scan */

	void *priv; /*!< Private Data for this device */
	uint16_t num_rx_vqueues; /*!< Number of Rx queues in use. For NADK_CONC
				  * device, it shall awlays be 1 */
	uint16_t num_tx_vqueues; /*!< Number of Tx queues in use.
				  * 0 for Concentrator Device */
	struct nadk_dev *conc_dev; /*!< If any, Concentrator Device(AVQ)
				    * linked to this device */
	void *rx_vq[MAX_RX_VQS]; /*!< Set of RX virtual Queues
					  * for this device */
	void *tx_vq[MAX_TX_VQS]; /*!< Set of TX virtual Queues
				  * for this device */
	void *err_vq[MAX_ERR_VQS + MAX_DEF_ERR_VQS]; /*!< Set of Err virtual
						Queues for this device */
	uint64_t	pktio;
};

/*!
 * Typedef for the callback registered by the user. When this callback is
 * registered, on receive of any notification on the VQ this callback will
 * be called by the dispatcher. This will only provide the notifications
 * and will override the default evenfd based notification mechanism of NADK.
 */
typedef void (*nadk_notification_callback_t) (uint64_t user_cnxt);

/*!
 * NADK device list structure
 */
TAILQ_HEAD(nadk_device_list, nadk_dev); /*!< NADK devices in D-linked Q. */
extern struct nadk_device_list device_list; /*!< Global list of NADK devices. */

/*!
 * @details	Initialize & configure a device with default settings.
 *		This function must be invoked first before any other function
 *		in the device specific API. This function can also be re-invoked
 *		when a device is in the stopped state.
 *
 * @param[in]   dev - Pointer to NADK device structure
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_init(struct nadk_dev *dev);

/*!
 * @details	Shutdown a given configured NADK device.
 *
 * @param[in]	dev -  Pointer to NADK device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_shutdown(struct nadk_dev *dev);

/*!
 * @details	Activate/Start an already configured NADK device. This function
 *		must be invoked after NADK device initialization.
 *
 * @param[in]   dev - Pointer to NADK device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_start(struct nadk_dev *dev);


/*!
 * @details	De-activate/Stop an active NADK device. This function should be
 *		invoked only, if the deivce is in active state.
 *
 * @param[in]   dev - Pointer to NADK device structure.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_stop(struct nadk_dev *dev);


/*!
 * @details	Packet transmit Function. This function may be used to
 *		transmit multiple packets at a time.
 *		This API must be called after an IO context is already
 *		affined to the thread via API nadk_thread_affine_io_context().
 *
 * @param[in]	dev - Pointer to NADK device structure through which
 *			packet/s need to be sent
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[in]   num - Number of valid buffers in the buffer list.
 *
 * @param[in]   buf_list - Pointer to list of pointers to buffer which
 *			required to be sent.
 *
 * @returns	Number of successfully sent packets.
 */
extern int32_t nadk_send(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			struct nadk_mbuf *buf_list[]);

/*!
 * @details	Packet receive function to recevie packet/s
 *		from a given device queue.
 *		This API must be called after an IO context is already
 *		affined to the thread via API nadk_thread_affine_io_context().
 *
 * @param[in]	dev - Pointer to NADK device structure from which
 *			packets need to be received.
 *
 * @param[in]	vq -  Pointer to virtual queue.
 *
 * @param[in]	budget -  Maximum number of buffers to receive.
 *
 * @param[out]   buf_list - Pointer to list received buffers.
 *
 * @returns   Number of actually received packets on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_receive(struct nadk_dev *dev,
			void *vq,
			uint32_t budget,
			struct nadk_mbuf *buf_list[]);

/*!
 * @details	Provide maximum number of receive (RX) virtual
 *		queues (VQ) supported for the given device.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @returns	Number of RX VQ supported for the given device.
 *
 */
extern int32_t nadk_dev_get_max_rx_vq(struct nadk_dev *dev);

/*!
 * @details	Provide maximum number of transmit (TX) virtual
 *		queues (VQ) supported for the given device.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @returns	Number of TX VQ supported for the given device.
 *
 */
extern int32_t nadk_dev_get_max_tx_vq(struct nadk_dev *dev);


/*!
 * @details	Add a RX side virtual queue/s to the given device.This function
 *		shall get called for each RX VQ for which a thread is suppose
 *		to process the packets. Optinally, A RX VQ may be attached to
 *		an preconfigured Concentrator device.
 *		Note: While using ethernet driver if there are multiple
 *		VQ's per traffic class and they are required to be used,
 *		user needs to use API's nadk_eth_get_queues_config &
 *		nadk_eth_setup_flow_distribution before calling this API.
 *		If only one VQ is required to be used then only first VQ
 *		should be configured and used.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]   vq_cfg - Pointer vq configuration structure
 *
 *
 * @returns   NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_setup_rx_vq(struct nadk_dev *dev,
				uint32_t vq_index,
				struct nadk_vq_param *vq_cfg);

/*!
 * @details	Add the TX virtual queue/s for the given device. This function
 *		shall get called for a set of TX queues for which the thread is
 *		suppose to transmit the packets.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @param[in]   num - How many queues are required.
 *
 * @param[in]   action - bit mask flag to define action on TX.
 *		It will be set as <NADKBUF_TX_XXX>
 * @returns   NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_dev_setup_tx_vq(struct nadk_dev *dev,
				uint32_t num, uint32_t action);


/*!
 * @details	Set the notification on the particular device.
 *
 *		If a callback is not registered then the API
 *		nadk_disp_process_notifications will wakeup the eventfd
 *		corresponding to the VQ, providing the 'user_context' at the
 *		'read' call on that eventfd.
 *
 *		In case callback is registered, nadk_disp_process_notifications
 *		API will call this the cb function providing the 'user_context'.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]	user_context - User context to be returned to the user. In case
 *		'user_context' is provided as '0', 'DEFAULT_USER_CONTEXT'
 *		will be used.
 *
 * @param[in]	cb - Callback function provided by the user.
 *
 * @returns   NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int nadk_dev_set_rx_vq_notification(
		struct nadk_dev *dev,
		uint32_t vq_index,
		uint64_t user_context,
		nadk_notification_callback_t cb);


/*!
 * @details	This function shall be used for dumping the device list
 *		information for debug purpose only.
 *
 * @param[out]	stream - pointer to stream.
 *
 * @returns   Nothing.
 *
 */
void nadk_device_list_dump(void *stream);

/*!
 * @details	Provide the hwid  for the given device.
 *
 * @param[in]	dev - Pointer to NADK device structure.
 *
 * @returns	HW ID for the given device.
 *
 */
int32_t nadk_dev_hwid(struct nadk_dev *dev);

/*!
 * @details	Affine the concentator device list to thread
 *		specific IO conext.
 *
 * @param[in]	conc_dev - Concentrator device which is to be affined
 *
 * @returns	NADK_SUCCESS on success, Negative otherwise.
 *
 */
int32_t nadk_dev_affine_conc_list(struct nadk_dev *conc_dev);

/*!
 * @details	De-affine the concentator device list to thread
 *		specific IO conext.
 *
 * @param[in]	conc_dev - Concentrator device which is to be deaffined
 *
 * @returns	NADK_SUCCESS on success, Negative otherwise.
 *
 */
int32_t nadk_dev_deaffine_conc_list(struct nadk_dev *conc_dev);


/*!
 * @details	Return device pointer associated to given VQ.
 *
 * @param[in]	vq - Pointer to VQ
 *
 * @returns	nadk_dev pointer on success, NULL otherwise.
 *
 */
struct nadk_dev *nadk_dev_from_vq(void *vq);

/*!
 * @details     Set given uhandle to VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @param[in]   uhandle - Handle value which needs to be set.
 *
 *
 * @returns     NADK_SUCCESS on success, NADK_FAILURE otherwise.
 *
 */
int nadk_dev_set_vq_handle(void *vq, uint64_t uhandle);

/*!
 * @details     Return handle associated to given VQ.
 *
 * @param[in]   vq - Pointer to VQ
 *
 * @returns     Handle of specified queue on success, NADK_FAILURE otherwise.
 *
 */
uint64_t nadk_dev_get_vq_handle(void *vq);

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _NADK_DEV_H_ */
