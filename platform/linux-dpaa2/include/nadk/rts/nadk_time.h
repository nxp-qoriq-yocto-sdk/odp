/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */


/*!
 * @file nadk_time.h
 *
 * @brief Time related functions
 *
 * @addtogroup NADK_TIMER
 * @ingroup NADK_RTS
 * @{
 */

#ifndef _NADK_TIME_H_
#define _NADK_TIME_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>

#define MS_PER_S 1000ULL /*!< Seconds in a Millisecond */
#define US_PER_S 1000000ULL /*!< Seconds in a Microsecond */
#define NS_PER_S 1000000000ULL /*!< Seconds in a Nanosecond */

/*!
 * @details	get the system ticks. (equivalent to jiffies)
 *
 * @param[out]	 number of ticks since the start of the system
 *
 */
uint64_t nadk_time_get_cycles(void);


/*!
 * @details	Time difference
 *
 * @param[in]	t1    First time stamp
 * @param[in]	t2    Second time stamp
 *
 * @param[out]	Difference of time stamps
 */
uint64_t nadk_time_diff_cycles(uint64_t t1, uint64_t t2);


/*!
 * @details	Convert CPU cycles to nanoseconds
 *
 * @param[in]	cycles  Time in CPU cycles
 *
 * @param[out]	Time in nanoseconds
 */
uint64_t nadk_time_cycles_to_ns(uint64_t cycles);

/*!
 * @details	Sleep for millisecond
 *
 * @param[in]	mst  Time in miliseconds
 *
 *
 */
void nadk_msleep(uint32_t mst);

/*!
 * @details	Sleep for microsecond
 *
 * @param[in]	ust  Time in microseconds
 *
 *
 */
void nadk_usleep(uint32_t ust);

#ifdef __cplusplus
}
#endif

/*! @} */

#endif /* _NADK_TIME_H_ */
