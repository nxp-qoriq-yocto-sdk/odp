/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/*
 *   Derived from DPDK's rte_log.h
 *   BSD LICENSE
 *
 *   Copyright(c) 2010-2014 Intel Corporation. All rights reserved.
 *   All rights reserved.
 *
 *   Redistribution and use in source and binary forms, with or without
 *   modification, are permitted provided that the following conditions
 *   are met:
 *
 *     * Redistributions of source code must retain the above copyright
 *       notice, this list of conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright
 *       notice, this list of conditions and the following disclaimer in
 *       the documentation and/or other materials provided with the
 *       distribution.
 *     * Neither the name of Intel Corporation nor the names of its
 *       contributors may be used to endorse or promote products derived
 *       from this software without specific prior written permission.
 *
 *   THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 *   "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 *   LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 *   A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 *   OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 *   SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 *   LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 *   DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 *   THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 *   (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 *   OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 *
 */

#ifndef _NADK_LOG_H_
#define _NADK_LOG_H_

/*!
 * @file nadk_log.h
 *
 * @brief RTE Logs API
 * This file provides a log API to RTE applications.
 * @addtogroup NADK_LOG
 * @ingroup NADK_RTS
 * @{
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <stdbool.h>

/*! The nadk_log structure. */
struct nadk_logs {
	uint32_t type;  /*!< Bitfield with enabled logs. */
	uint32_t level; /*!< Log level. */
	uint32_t number_of_files;  /*!< number of log files. */
	uint16_t file_size;  /*!< log file size . */
	uint8_t file_logging;  /*!< file enabled logs. */
};

/*! Global log informations */
extern struct nadk_logs nadk_logs;

/*! SDK log type */
#define NADK_LOGTYPE_EAL     0x00000001 /*!< Log related to eal. */
#define NADK_LOGTYPE_MALLOC  0x00000002 /*!< Log related to malloc. */
#define NADK_LOGTYPE_RING    0x00000004 /*!< Log related to ring. */
#define NADK_LOGTYPE_MEMPOOL 0x00000008 /*!< Log related to mempool. */
#define NADK_LOGTYPE_TIMER   0x00000010 /*!< Log related to timers. */
#define NADK_LOGTYPE_PMD     0x00000020 /*!< Log related to poll mode driver. */
#define NADK_LOGTYPE_HASH    0x00000040 /*!< Log related to hash table. */
#define NADK_LOGTYPE_LPM     0x00000080 /*!< Log related to LPM. */
#define NADK_LOGTYPE_KNI     0x00000100 /*!< Log related to KNI. */
#define NADK_LOGTYPE_ACL     0x00000200 /*!< Log related to ACL. */
#define NADK_LOGTYPE_POWER   0x00000400 /*!< Log related to power. */
#define NADK_LOGTYPE_METER   0x00000800 /*!< Log related to QoS meter. */
#define NADK_LOGTYPE_SCHED   0x00001000 /*!< Log related to QoS port scheduler*/

#define NADK_LOGTYPE_FW	   NADK_LOGTYPE_EAL /*!< Log related to nadk framework*/
#define NADK_LOGTYPE_FRAMEQ	0x0000002 /**< Log related to S/W frame Queue */
#define NADK_LOGTYPE_ETH   NADK_LOGTYPE_PMD /*!< Log related to ethernet */
#define NADK_LOGTYPE_BUF   0x0002000	/*!< Log related to Buffer */
#define NADK_LOGTYPE_SEC   0x0004000	/*!< Log related to Sec driver */
#define NADK_LOGTYPE_CMD   0x0008000	/*!< Log related to AIOP driver */
#define NADK_LOGTYPE_MEMZONE 0x0010000	/*!< Log related to memzone */
#define NADK_LOGTYPE_CONC	0x0020000	/*!< Log related to concentrator */
#define NADK_LOGTYPE_NOTIFIER	0x0040000 /**< Log related to notifier */

#define NADK_LOGTYPE_ALL  0x000fffff	/*!< Logs related to all type */

/*! these log types can be used in an application */
#define NADK_LOGTYPE_USER1   0x01000000 /*!< User-defined log type 1. */
#define NADK_LOGTYPE_USER2   0x02000000 /*!< User-defined log type 2. */
#define NADK_LOGTYPE_USER3   0x04000000 /*!< User-defined log type 3. */
#define NADK_LOGTYPE_USER4   0x08000000 /*!< User-defined log type 4. */
#define NADK_LOGTYPE_USER5   0x10000000 /*!< User-defined log type 5. */
#define NADK_LOGTYPE_USER6   0x20000000 /*!< User-defined log type 6. */
#define NADK_LOGTYPE_USER7   0x40000000 /*!< User-defined log type 7. */
#define NADK_LOGTYPE_USER8   0x80000000 /*!< User-defined log type 8. */

#define NADK_LOGTYPE_APP1 NADK_LOGTYPE_USER1
#define NADK_LOGTYPE_APP2 NADK_LOGTYPE_USER2

/*! Can't use 0, as it gives compiler warnings */
#define NADK_LOG_EMERG    1U  /*!< System is unusable.               */
#define NADK_LOG_ALERT    2U  /*!< Action must be taken immediately. */
#define NADK_LOG_CRIT     3U  /*!< Critical conditions.              */
#define NADK_LOG_ERR      4U  /*!< Error conditions.                 */
#define NADK_LOG_WARNING  5U  /*!< Warning conditions.               */
#define NADK_LOG_NOTICE   6U  /*!< Normal but significant condition. */
#define NADK_LOG_INFO     7U  /*!< Informational.                    */
#define NADK_LOG_DEBUG    8U  /*!< Debug-level messages.             */
#define NADK_LOG_LEVEL    9U  /*!< Maximum log level.		     */

/*!
 * Check if log level set in NADK is greater than
 * or equal to the specified 'lvl'
 */
#define IF_LOG_LEVEL(lvl)  if (nadk_logs.level >= lvl)

/*!
 * Set the global log level.
 *
 * After this call, all logs that are lower or equal than level and
 * lower or equal than the NADK_LOG_LEVEL configuration option will be
 * displayed.
 *
 * @param level
 *   Log level. A value between NADK_LOG_EMERG (1) and NADK_LOG_DEBUG (8).
 */
void nadk_set_log_level(uint32_t level);

/*!
 * Get the global log level.
 */
uint32_t nadk_get_log_level(void);

/*!
 * Enable or disable the log type.
 *
 * @param type
 *   Log type, for example, NADK_LOGTYPE_EAL.
 * @param enable
 *   True for enable; false for disable.
 */
void nadk_set_log_type(uint32_t type, int enable);
/*!
 * Get the current loglevel for the message being processed.
 *
 * Before calling the user-defined stream for logging, the log
 * subsystem sets a per-lcore variable containing the loglevel and the
 * logtype of the message being processed. This information can be
 * accessed by the user-defined log output function through this
 * function.
 *
 * @return
 *   The loglevel of the message being processed.
 */
int nadk_log_cur_msg_loglevel(void);

/*!
 * Get the current logtype for the message being processed.
 *
 * Before calling the user-defined stream for logging, the log
 * subsystem sets a per-lcore variable containing the loglevel and the
 * logtype of the message being processed. This information can be
 * accessed by the user-defined log output function through this
 * function.
 *
 * @return
 *   The logtype of the message being processed.
 */
int nadk_log_cur_msg_logtype(void);

/*!
 * Enable or disable the history (enabled by default)
 *
 * @param enable
 *   true to enable, or 0 to disable history.
 */
void nadk_log_set_history(int enable);

/*!
 * Dump the log history to a file
 *
 * @param f
 *   A pointer to a file for output
 */
void nadk_log_dump_history(FILE *f);

/*!
 * Generates a log message.
 *
 * The message will be sent in the stream
 *
 * The level argument determines if the log should be displayed or
 * not, depending on the global nadk_logs variable.
 *
 * The preferred alternative is the NADK_LOG() function because debug logs may
 * be removed at compilation time if optimization is enabled. Moreover,
 * logs are automatically prefixed by type when using the macro.
 *
 * @param level
 *   Log level. A value between NADK_LOG_EMERG (1) and NADK_LOG_DEBUG (8).
 * @param logtype
 *   The log type, for example, NADK_LOGTYPE_EAL.
 * @param format
 *   The format string, as in printf(3), followed by the variable arguments
 *   required by the format.
 * @return
 *   - 0: Success.
 *   - Negative on error.
 */
int nadk_log(uint32_t level, uint32_t logtype, const char *format, ...)
#ifdef __GNUC__
#if (__GNUC__ > 4 || (__GNUC__ == 4 && __GNUC_MINOR__ > 2))
	__attribute__((cold))
#endif
#endif
	__attribute__((format(printf, 3, 4)));

/*!
 * Generates a log message.
 *
 * The NADK_LOG() is equivalent to nadk_log() with two differences:

 * - NADK_LOG() can be used to remove debug logs at compilation time,
 *   depending on NADK_LOG_LEVEL configuration option, and compilation
 *   optimization level. If optimization is enabled, the tests
 *   involving constants only are pre-computed. If compilation is done
 *   with -O0, these tests will be done at run time.
 * - The log level and log type names are smaller, for example:
 *   NADK_LOG(INFO, EAL, "this is a %s", "log");
 *
 * @param l
 *   Log level. A value between EMERG (1) and DEBUG (8). The short name is
 *   expanded by the macro, so it cannot be an integer value.
 * @param t
 *   The log type, for example, EAL. The short name is expanded by the
 *   macro, so it cannot be an integer value.
 * @param fmt
 *   The fmt string, as in printf(3), followed by the variable arguments
 *   required by the format.
 * @param args
 *   The variable list of arguments according to the format string.
 * @return
 *   - 0: Success.
 *   - Negative on error.
 */

#ifdef NADK_LOGLIB_DISABLE
#define NADK_LOG(l, t, fmt, arg...) \
	fprintf(stderr, "\n%s %d-%s-" fmt, __func__, __LINE__, #l, ##arg)
#else
#define NADK_LOG(l, t, f, ...) \
	(void)(((NADK_LOG_ ## l <= NADK_LOG_LEVEL) &&		\
	(NADK_LOG_ ## l <= nadk_logs.level) &&			\
	(NADK_LOGTYPE_ ## t & nadk_logs.type)) ?		\
nadk_log(NADK_LOG_ ## l, NADK_LOGTYPE_ ## t, "\n%s %d-" # t "-" # l ":" f, \
	__func__, __LINE__, ##__VA_ARGS__) : 0)
#endif

/*! System is unusable. */
#define NADK_EMREG(app, fmt, ...) NADK_LOG(EMERG, app, fmt, ##__VA_ARGS__)

/*! Action must be taken immediately. */
#define NADK_ALERT(app, fmt, ...) NADK_LOG(ALERT, app,  fmt, ##__VA_ARGS__)

/*! Critical conditions. */
#define NADK_CRIT(app, fmt, ...) NADK_LOG(CRIT, app,  fmt, ##__VA_ARGS__)
/*! Functional Errors. */
#define NADK_ERR(app, fmt, ...)  NADK_LOG(ERR, app, fmt, ##__VA_ARGS__)
/*! Warning Conditions. */
#define NADK_WARN(app, fmt, ...) NADK_LOG(WARNING, app, fmt, ##__VA_ARGS__)
/*! Normal but significant conditions. */
#define NADK_NOTE(app, fmt, ...) NADK_LOG(NOTICE, app, fmt, ##__VA_ARGS__)

#ifdef NADK_DEBUG
/*! Functional Trace. */
#define NADK_TRACE(app) NADK_LOG(DEBUG, app, "trace")
/*! Informational. */
#define NADK_INFO(app, fmt, ...) NADK_LOG(INFO, app, fmt, ##__VA_ARGS__)
/*! Low Level Debug. */
#define NADK_DBG(app, fmt, ...) NADK_LOG(DEBUG, app, fmt, ##__VA_ARGS__)
#define NADK_DBG2(...)
#else
#define NADK_TRACE(...)
#define NADK_INFO(...)
#define NADK_DBG(...)
#define NADK_DBG2(...)
#endif

#ifdef __cplusplus
}
#endif

/*! @} */
#endif /* _NADK_LOG_H_ */
