/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_eth_priv.h
 * @description		Private functions & MACRO definitions for NADK Ethernet
			Type Device
 */

#ifndef _NADK_ETH_PRIV_H_
#define _NADK_ETH_PRIV_H_

/*Standard header files*/
#include <stddef.h>

/*Nadk header files*/
#include <nadk_ethdev.h>
#include <nadk_ether.h>
#include <nadk_dev.h>
#include <odp/hints.h>
#include <nadk_mpool.h>
#include <odp/std_types.h>

/*MC header files*/
#include <fsl_dpni.h>
/*QBMAN header files*/
#include <fsl_qbman_portal.h>

#ifdef __cplusplus
extern "C" {
#endif
/* Macros to define feature enable/disable options */
#define ETHDRV_DEVNAME 24
#define NADK_PROMISCIOUS_MODE_ENABLE	BIT_POS(0) /*!< Enable promiscious mode*/
#define NADK_CHECKSUM_ENABLE		BIT_POS(1) /*!< Enable csum validation
							mode*/
#define NADK_GRO_ENABLE			BIT_POS(2) /*!< Enable GRO*/
#define NADK_GSO_ENABLE			BIT_POS(3) /*!< Enable GSO*/
#define NADK_SG_ENABLE			BIT_POS(4) /*!< Enable SG support*/
#define NADK_FRAG_ENABLE		BIT_POS(5) /*!< Enable fragmentation
							support*/
#define NADK_REASSEMBLY_ENABLE		BIT_POS(6) /*!< Reassembly
							support enabled */
#define NADK_PAUSE_CNTRL_ENABLE		BIT_POS(7) /*!< Enable Pause control
							support*/
#define NADK_LOOPBACK_ENABLE		BIT_POS(8) /*!< Enable Loopback mode*/
#define NADK_TIMESTAMP_ENABLE		BIT_POS(9) /*!< Enable 1588 Timestamp*/

#define NADK_PROMISCUOUS_ENABLE		BIT_POS(10) /*!< Enable Promiscuous mode*/
#define NADK_MULTICAST_ENABLE		BIT_POS(11) /*!< Enable Multicast mode*/

/*Macros to define QBMAN enqueue options */
#define NADK_ETH_EQ_DISABLE		0	/*!< Dont Enqueue the Frame */
#define NADK_ETH_EQ_RESP_ON_SUCC	1	/*!< Enqueue the Frame with
							response after success*/
#define NADK_ETH_EQ_RESP_ON_FAIL	2	/*!< Enqueue the Frame with
							response after failure*/
#define NADK_ETH_EQ_NO_RESP		3	/*!< Enqueue the Frame without
							response*/
/*
  * Macros specific to Ethernet
  */
#define NADK_ETH_PRIV_DATA_SIZE	64	/*!< Ethernet Private data size*/

#define NADK_ETH_DEF_PRIO	0	/*!< Default Prioroty used for DPCON*/
/*
 * Definitions of all functions exported by an Ethernet driver through the
 * the generic structure of type *eth_config_fops*
 */


#define NET_IF_ADMIN_PRIORITY 4
#define NET_IF_RX_PRIORITY 4

/**
 * @internal Structure containing configuration
 *		parameters for an Ethernet driver.
 */
struct nadk_eth_config {
	uint32_t		hw_features;
	struct nadk_eth_link	link_info;
	uint16_t		headroom;
	/**< headroom required in device buffers */
	uint16_t		mtu;
	/**< MTU for this device */
	uint8_t name[ETHDRV_DEVNAME];
	/*TODO Think on this structure fields*/
	uint8_t			max_tcs;
	uint8_t			max_dist_per_tc[DPNI_MAX_TC];
	uint8_t			mac_addr[ETH_ADDR_LEN];
	/**< Ethernet MAC address */
};

/**
 * @internal A structure containing Operations & Configuration
 * parameters for an Ethernet driver.
 */
struct nadk_eth_priv {
	struct nadk_eth_config		cfg;
	struct dpni_cfg			default_param;
	struct queues_config		q_config;
};

/*!
 * @details	Ethernet API to register to NADK framework. It will be called
 *		by NADK core framework and it will register its device driver
 *		to NADK.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_driver_init(void);

/*!
 * @details	Ethernet API to unregister to NADK framework. It will be called
 *		by NADK core framework and it will unregister its device driver
 *		to NADK.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_driver_exit(void);

/*!
 * @details	Ethernet driver default configuration API. It reset the DPNI
 *		to its default state.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_defconfig(struct nadk_dev *dev);

/*!
 * @details	Ethernet driver probe function to initialize the device.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_probe(struct nadk_dev *dev, const void *data);

/*!
 * @details	Ethernet driver remove function to remove the device.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_remove(struct nadk_dev *dev);

/*!
 * @details	Enable a ethernet device for use of RX/TX.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_start(struct nadk_dev *dev);

/*!
 * @details	Setup a RX virtual queues to a Ethernet device.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @param[in]	vq_index - Pointer to NADK Ethernet device
 *
 * @param[in]   vq_cfg - Pointer vq configuration structure
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_setup_rx_vq(struct nadk_dev *dev,
				uint8_t vq_id,
				struct nadk_vq_param *vq_cfg);

/*!
 * @details	Setup a TX virtual queues to a Ethernet device.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @param[in]	num - Number of TX queues
 *
 * @param[in]  action - To define action on TX for confirmation/error
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_setup_tx_vq(struct nadk_dev *dev, uint32_t num,
					uint32_t action);

/*!
 * @details	Set the notification on the Ethernet device.
 *
 * @param[in]	dev - Pointer to Ethernet device.
 *
 * @param[in]	vq_index - Index of virtual queue out of total available RX VQs.
 *
 * @param[in]	user_context - User context provided by the user.
 *
 * @param[in]	cb - Callback function provided by the user.
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int nadk_eth_set_rx_vq_notification(
		struct nadk_dev *dev,
		uint8_t vq_id,
		uint64_t user_context,
		nadk_notification_callback_t cb);

/*!
 * @details	Disable a ethernet device for use of RX/TX.
 *		After disabling no data can be Received or transmitted
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_stop(struct nadk_dev *dev);

/*!
 * @details	Receives frames from given NADK device
 *		and VQ in optimal mode.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
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
int32_t nadk_eth_prefetch_recv(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);


/*!
 * @details	Receives frames from given NADK device and VQ.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
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
int32_t nadk_eth_recv(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);

/*!
 * @details	Transmits frames to given NADK device.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to NADK buffers which are to be transmited.
 *
 * @param[in]	num - Number of frames to be transmited
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_xmit(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);

/*!
 * @details	Transmits frames to given fqid. API added
 *		to test the ODP queue's test
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - Pointer to NADK buffers which are to be transmited.
 *
 * @param[in]	num - Number of frames to be transmited
 *
 * @returns	NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_xmit_fqid(void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);

/*!
 * @details	Internally loopback the frames from given
 *		Ethernet device and VQ.
 *
 * @param[in]	dev - Pointer to NADK Ethernet device
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @param[in]	buf - This is unused internally and is present here to
 *		maintain compatibility with the nadk_eth_recv
 *
 * @param[in]	num - This is unused internally and is present here to
 *		maintain compatibility with the nadk_eth_recv
 *
 * @returns	Actual total number of frames received on success.
 *		NADK_FAILURE otherwise.
 *
 */
int32_t nadk_eth_loopback(struct nadk_dev *dev,
			void *vq,
			uint32_t num,
			nadk_mbuf_pt buf[]);


/*!
 * @details	Get the eventfd corresponding to a VQ
 *
 * @param[in]	vq - Pointer to Virtual Queue
 *
 * @returns	Corresponding eventfd
 *
 */
int nadk_eth_get_eventfd_from_vq(void *vq);


/*!
 * @details	Get the FQID corresponding to a Rx VQ
 *
 * @param[in]	vq - Pointer to Rx Virtual Queue
 *
 * @returns	Corresponding FQID
 *
 */
int nadk_eth_get_fqid(void *vq);


#ifdef __cplusplus
}
#endif

#endif /* _NADK_ETH_PRIV_H_ */
