/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/*!
 * @file	nadk.h
 *
 * @brief	Common definitions and functions for NADK API framework.
 *
 * @addtogroup	NADK_COMMON
 * @ingroup	NADK
 * @{
 */

#ifndef _NADK_H_
#define _NADK_H_

#ifdef __cplusplus
extern "C" {
#endif
#include <stdbool.h>
#include <odp/hints.h>
#include <odp/std_types.h>
#include <nadk/common/nadk_common.h>


/*! NADK flags related to initialization */
enum {
	NADK_SHARED_MEM = BIT_POS(0), /*!< Shared memory usage is required */
	NADK_EVENT_NOTIFIER = BIT_POS(1), /*!< Application will use
					* its own event notifier */
	NADK_LOG_DISABLE = BIT_POS(2), /*!< Nadk logging to be disabled */
	NADK_LOG_FILE = BIT_POS(3), /*!< Option to send logs to file */
	NADK_SYSTEM_INFO = BIT_POS(4), /*!< Platform System Information*/
	NADK_PREFETCH_MODE = BIT_POS(5), /* Run NADK in prefetch mode.
		* In prefetch mode the Ethernet driver will prefetch the data
		* from the Hardware queue and store them in the software */
	NADK_SOFTQ_SUPPORT = BIT_POS(6) /*!< Use software queues with NADK.
		* This is for ODP software queue support. Using this an
		* additional software portal is reserved for software
		* queue support. */
};

/*!
 * A structure to store initialization configuration parameters,
 * which will be filled by User Application.
 */
struct nadk_init_cfg {
	uint64_t data_mem_size; /*!< Application total memory requirements for
				 * buffer pools, mem pools, memzone,
				 * nadk_data_malloc & NADK library
				 * internal usage */
	uint64_t buf_mem_size;  /*!< Not used currently */
	uint32_t flags;		/*!< To Enable features like Shared Memory
				 * usage, User space dispatcher */
	char *vfio_container;	/*!< VFIO container string */
	char *log_file_dir; /*! < Log file location if not syslog */
	uint32_t log_files; /*! <Total number for files to be created for logging.*/
	uint16_t log_file_size; /*!< Max Size of each log file */
	uint8_t log_level; /*!< Default log level is NADK_LOG_NOTICE */
	uint8_t log_facility; /*!< log facility type, USER, SYSLOG, CRON etc */

};

/*! NADK IO PORTAL - use any free portal when affining the thread */
#define NADK_IO_PORTAL_ANY_FREE 0xffff

/*!
 * @details	Initialize the Network Application Development Kit Layer (NADK).
 *		This function must be the first function invoked by an
 *		application and is to be executed once.
 *
 * @param[in]	arg - A pointer to nadk_init_cfg structure.
 *
 * @returns     NADK_SUCCESS in case of successfull intialization of
 *		NADK Layer; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_init(struct nadk_init_cfg *arg);


/*!
 * @details	Do Clean up and exit for in context of a given application. This
 *		function must be invoked by an application before exiting.
 *
 * @returns     Not applicable.
 *
 */
extern void nadk_cleanup(void);


/*!
 * @details	To get total number of available I/O contexts available for use.
 *
 * @returns     Number of IO context objects available for
 *		current application context
 *
 */
extern uint32_t nadk_get_io_context_count(void);


/*!
 * @details	This function must be invoked by each IO thread of application
 *		once.  This function will affine a thread to a given IO context.
 *		If an application wish to share a IO context between multiple
 *		threads, same IO context shall be passed for all required
 *		threads.
 *
 * @param[in]	index - An index value of IO context. Range is 1 to
 *		total IO context count. or NADK_IO_PORTAL_ANY_FREE to be
*		choosed by the underlying API.
 *
 * @returns     NADK_SUCCESS on success; NADK_FAILURE otherwise.
 *
 */
extern int32_t nadk_thread_affine_io_context(uint32_t index);


/*!
 * @details	Stop the already active IO thread & de-affine IO context from
 *		current thread. This function must be invoked before exiting
 *		from thread if, it has initially called
 *		nadk_thread_affine_io_context().
 *
 * @returns     Not applicable.
 *
 */
extern void nadk_thread_deaffine_io_context(void);


/*!
 * @details	Returns the CPU Core ID currently in use.
 *
 * @returns     Core ID
 *
 */
static inline int nadk_core_id(void)
{
	return 0;
}

/*!
* @details	Returns the eventfd for the calling thread's affined "io_context"
*
* @returns	Portal FD
*
*/

extern uint32_t nadk_get_io_context_eventid(void);
#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _NADK_H_ */
