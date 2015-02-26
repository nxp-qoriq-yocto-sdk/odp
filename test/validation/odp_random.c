/* Copyright (c) 2015, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp.h>
#include <odp_cunit_common.h>

/* Helper macro for CU_TestInfo initialization */
#define _CU_TEST_INFO(test_func) {#test_func, test_func}

static void random_get_size(void)
{
	int32_t ret;
	uint8_t buf[32];

	ret = odp_random_data(buf, sizeof(buf), false);
	CU_ASSERT(ret == sizeof(buf));
}

CU_TestInfo test_odp_random[] = {
	_CU_TEST_INFO(random_get_size),
	CU_TEST_INFO_NULL,
};

CU_SuiteInfo odp_testsuites[] = {
	{"Random", NULL, NULL, NULL, NULL, test_odp_random},
	CU_SUITE_INFO_NULL,
};
