/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/*!
 * @file		nadk_cfg.h
 *
 * @brief		Common definitions and functions for NADK framework.
 *
 * @addtogroup	NADK_CFG
 * @ingroup	NADK_COMMON
 * @{
 */

#ifndef _NADK_CFG_H_
#define _NADK_CFG_H_

#ifdef __cplusplus
extern "C" {
#endif


/*! Default namespace ID */
#define NADK_APP_DEF_NSID	0

/*!Maximum number of threads */
#define NADK_CONFIG_MAX_THREADS  128

/*!Maximum number of cores */
#define NADK_MAX_LCORE		8

/*!Maximum number of buffer pools */
#define NADK_MAX_BUF_POOLS	8

/*! Maximum number of memory pools allowed */
#define NADK_MAX_MEM_POOLS 128

/*! Maximum size of a log file */
#define NADK_MAX_LOG_FILES_SIZE 4000
/*! Default number of log files which will be created */
#define NADK_DEF_LOG_FILES 2
/*! Maximum number of log files which can be created */
#define NADK_MAX_LOG_FILES 8
/*! Default log file size */
#define NADK_DEF_LOG_FILE_SIZE 1000

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _NADK_CFG_H_ */
