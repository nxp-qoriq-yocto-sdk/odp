/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */
#define _POSIX_C_SOURCE 200809L

#include <odp/time.h>
#include <odp/hints.h>
#include <odp/system_info.h>
#include <usdpaa/fsl_usd.h>

#define GIGA 1000000000

uint64_t odp_time_diff_cycles(uint64_t t1, uint64_t t2)
{
	if (odp_likely(t2 > t1))
		return t2 - t1;

	return t2 + (UINT64_MAX - t1);
}

uint64_t odp_time_cycles_to_ns(uint64_t cycles)
{
	uint64_t hz = odp_sys_cpu_hz();

	if (cycles > (UINT64_MAX / GIGA))
		return (cycles/hz)*GIGA;

	return (cycles*GIGA)/hz;
}

uint64_t odp_time_ns_to_cycles(uint64_t ns)
{
	uint64_t hz = odp_sys_cpu_hz();

	if (ns > (UINT64_MAX / hz))
		return (ns/GIGA)*hz;

	return (ns*hz)/GIGA;
}
