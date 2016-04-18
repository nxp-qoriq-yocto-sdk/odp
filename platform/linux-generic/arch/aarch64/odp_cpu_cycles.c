/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#define _POSIX_C_SOURCE 199309L

#include <stdlib.h>
#include <time.h>

#include <odp/cpu.h>
#include <odp/hints.h>
#include <odp/system_info.h>
#include <odp_debug_internal.h>

#define GIGA 1000000000

uint64_t odp_cpu_cycles(void)
{
	struct timespec time;
	uint64_t sec, ns, hz, cycles;
	int ret;

	ret = clock_gettime(CLOCK_MONOTONIC_RAW, &time);

	if (ret != 0)
		ODP_ABORT("clock_gettime failed\n");

	hz  = odp_sys_cpu_hz();
	sec = (uint64_t)time.tv_sec;
	ns  = (uint64_t)time.tv_nsec;

	cycles  = sec * hz;
	cycles += (ns * hz) / GIGA;

	return cycles;
}

uint64_t odp_cpu_cycles_max(void)
{
	return UINT64_MAX;
}

uint64_t odp_cpu_cycles_resolution(void)
{
	return 1;
}
