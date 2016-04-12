/* Copyright (c) 2015, Linaro Limited
 *  * All rights reserved.
 *   *
 *    * SPDX-License-Identifier:     BSD-3-Clause
 *     */
#define _POSIX_C_SOURCE 200809L

#include <odp/time.h>
#include <odp/hints.h>
#include <odp/system_info.h>
#include <usdpaa/fsl_usd.h>

inline uint64_t odp_time_cycles(void)
{
        return mfatb();
}
