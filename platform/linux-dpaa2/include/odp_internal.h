/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2013, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */


/**
 * @file
 *
 * ODP HW system information
 */

#ifndef ODP_INTERNAL_H_
#define ODP_INTERNAL_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/init.h>
#include <odp/thread.h>
#include <odp/spinlock.h>

extern __thread int __odp_errno;

typedef struct {
	uint64_t cpu_hz;
	uint64_t huge_page_size;
	uint64_t page_size;
	int      cache_line_size;
	int      cpu_count;
	char     model_str[128];
} odp_system_info_t;

struct odp_global_data_s {
	odp_log_func_t log_fn;
	odp_abort_func_t abort_fn;
	odp_system_info_t system_info;
};

extern struct odp_global_data_s odp_global_data;
extern uint32_t enable_hash;

int odp_system_info_init(void);

int odp_thread_init_global(void);
int odp_thread_init_local(odp_thread_type_t type);
int odp_thread_term_local(void);
int odp_thread_term_global(void);

int odp_shm_init_global(void);
int odp_shm_term_global(void);
int odp_shm_init_local(void);

int odp_pool_init_global(void);
int odp_pool_term_global(void);
int odp_pool_term_local(void);

int odp_pktio_init_global(void);
int odp_pktio_term_global(void);
int odp_pktio_init_local(void);

int odp_classification_init_global(void);
int odp_classification_term_global(void);

int odp_queue_init_global(void);
int odp_queue_term_global(void);

int odp_crypto_init_global(void);
int odp_crypto_term_global(void);

int odp_schedule_init_global(void);
int odp_schedule_term_global(void);
int odp_schedule_init_local(void);
int odp_schedule_term_local(void);

int odp_timer_init_global(void);
int odp_timer_disarm_all(void);

int odpfsl_ci_init_global(void);
int odpfsl_ci_term_global(void);

void _odp_flush_caches(void);

/*NADK specific Definitions*/

/*******************MACRO*******************/
#define NADK_MAX_ETH_DEV        16
#define NADK_MAX_CONC_DEV        8
#define NADK_MAX_CI_DEV		128

/* Enable QBMan Short Circuit Mode with ISOL CPU for benchmarking purpose */
#define  ODPFSL_DRIVER_LB		0
#define  ODPFSL_MAX_PLATFORM_CORE	8

/************DATA STRUCTURE*******************/
/*
 * Structure to contains available resource count at underlying layers.
 */
struct nadk_resource_cnt {
	uint32_t eth_dev_cnt;
	uint32_t conc_dev_cnt;
	uint32_t ci_dev_cnt;
	uint32_t io_context_cnt;
	uint32_t cpu_cnt;
};

/*
 * Structure to contains available resources.
 */
struct nadk_resources {
	struct nadk_resource_cnt res_cnt;
	struct nadk_dev *net_dev[NADK_MAX_ETH_DEV];
	struct nadk_dev *conc_dev[NADK_MAX_CONC_DEV];
	struct nadk_dev *ci_dev[NADK_MAX_CI_DEV];
};

/************EXTERN DEFINITION*******************/
extern struct nadk_resources nadk_res;

struct nadk_dev *odp_get_inactive_conc_dev(void);

struct nadk_dev *odp_get_nadk_eth_dev(const char *dev_name);

int32_t odp_nadk_scan_device_list(uint32_t dev_type);

#ifdef __cplusplus
}
#endif

#endif
