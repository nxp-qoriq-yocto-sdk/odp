/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP debug
 */

#ifndef ODP_PLAT_DEBUG_H_
#define ODP_PLAT_DEBUG_H_

#ifdef __cplusplus
extern "C" {
#endif

/** @ingroup odp_ver_abt_log_dbg
 *  @{
 */

#ifndef ODP_UNIMPLEMENTED
/**
 * This macro is used to indicate when a given function is not implemented
 */
#define ODP_UNIMPLEMENTED() \
		printf("%s:%d:The function %s() is not implemented\n", \
			__FILE__, __LINE__, __func__)

#endif
/**
 * @}
 */

#include <odp/api/debug.h>

#ifdef __cplusplus
}
#endif

#endif
