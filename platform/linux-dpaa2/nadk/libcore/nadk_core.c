/*
 * Copyright (c) 2014-2015 Freescale Semiconductor, Inc. All rights reserved.
 */

/*!
 * @file	nadk_core.c
 *
 * @brief	NADK framework Common functionalities.
 *
 */

#include <syslog.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include <nadk.h>
#include <odp.h>
#include "nadk_internal.h"
#include <nadk_eth_priv.h>
#include <nadk_conc_priv.h>
#include <nadk_common.h>
#include <odp/atomic.h>
#include <nadk_timer.h>

#include <sys/file.h>
#include "eal_internal_cfg.h"
#include "eal_hugepages.h"

#ifdef NADK_AIOP_CI_DEVICE
#include <nadk_aiop_priv.h>
#endif

#include <nadk_sec_priv.h>
#include <nadk_memconfig.h>

#ifndef NADK_MBUF_MALLOC
/* @internal Number of buffer to be reserved for NADK Shell mpool */
#define NADK_MBUF_SHELL_NUM 1024
#endif

/* internal configuration */
struct internal_config internal_config;

/* early configuration structure, when memory config is not mmapped */
static struct nadk_mem_config early_mem_config;

/* Address of global and public configuration */
static struct nadk_config sys_config = {
		.mem_config = &early_mem_config,
};

/* Return a pointer to the configuration structure */
struct nadk_config *
nadk_eal_get_configuration(void)
{
	return &sys_config;
}

/* Return a pointer to the configuration structure */
struct nadk_mem_config *nadk_get_mem_config(void)
{
	return nadk_eal_get_configuration()->mem_config;
}

/* parse a sysfs (or other) file containing one integer value */
int
eal_parse_sysfs_value(const char *filename, unsigned long *val)
{
	FILE *f;
	char buf[BUFSIZ];
	char *end = NULL;

	if ((f = fopen(filename, "r")) == NULL) {
		NADK_LOG(ERR, FW, "%s(): cannot open sysfs value %s\n",
			__func__, filename);
		return -1;
	}

	if (fgets(buf, sizeof(buf), f) == NULL) {
		NADK_LOG(ERR, FW, "%s(): cannot read sysfs value %s\n",
			__func__, filename);
		fclose(f);
		return -1;
	}
	*val = strtoul(buf, &end, 0);
	if ((buf[0] == '\0') || (end == NULL) || (*end != '\n')) {
		NADK_LOG(ERR, FW, "%s(): cannot parse sysfs value %s\n",
				__func__, filename);
		fclose(f);
		return -1;
	}
	fclose(f);
	return 0;
}

/* Unlocks hugepage directories that were locked by eal_hugepage_info_init */
static void
eal_hugedirs_unlock(void)
{
	int i;

	for (i = 0; i < MAX_HUGEPAGE_SIZES; i++) {
		/* skip uninitialized */
		if (internal_config.hugepage_info[i].lock_descriptor <= 0)
			continue;
		/* unlock hugepage file */
		flock(internal_config.hugepage_info[i].lock_descriptor, LOCK_UN);
		close(internal_config.hugepage_info[i].lock_descriptor);
		/* reset the field */
		internal_config.hugepage_info[i].lock_descriptor = -1;
	}
}

int nadk_eal_has_hugepages(void)
{
	return !internal_config.no_hugetlbfs;
}

/**
 * Print system information
 */
void nadk_print_system_info(void)
{
	printf("\nNADK system info");
	printf("\n----------------------------------------------");
	printf("\nCPU model:       %s", odp_sys_cpu_model_str());
	printf("\nCPU freq (hz):   %"PRIu64"", odp_sys_cpu_hz());
	printf("\nCache line size: %i", odp_sys_cache_line_size());
	printf("\nCore count:      %i\n", odp_cpu_count());
}

static int32_t nadk_rts_init(struct nadk_init_cfg *cfg)
{
	if (internal_config.no_hugetlbfs == 0 &&
			eal_hugepage_info_init() < 0) {
		NADK_ERR(FW, "Cannot get hugepage information\n");
		return NADK_FAILURE;
	}

	if (internal_config.memory == 0) {
		internal_config.memory = cfg->data_mem_size;
	}

	if (cfg->data_mem_size == 0) {
		NADK_ERR(FW, "Data memory not specified\n");
		return NADK_FAILURE;
	}

	if (nadk_eal_memory_init(cfg) < 0) {
		NADK_ERR(FW, "FAIL - nadk_eal_memory_init\n");
		return NADK_FAILURE;
	}

	/* the directories are locked during eal_hugepage_info_init */
	eal_hugedirs_unlock();

	if (nadk_eal_memzone_init() < 0) {
		NADK_ERR(FW, "FAIL - nadk_eal_memzone_init\n");
		return NADK_FAILURE;
	}

#ifndef NADK_LOGLIB_DISABLE
	if (!(cfg->flags & NADK_LOG_DISABLE)) {
		const char *logid = "nadk";
		if (nadk_eal_log_init(cfg, logid, LOG_USER))
			return NADK_FAILURE;
		nadk_set_log_type(NADK_LOGTYPE_APP1 | NADK_LOGTYPE_ALL, 1);
#ifdef NADK_DEBUG
		nadk_set_log_level(NADK_LOG_DEBUG);
#else
		nadk_set_log_level(cfg->log_level ?
			cfg->log_level : NADK_LOG_NOTICE);
#endif
	}
#endif

	nadk_timer_subsystem_init();
#ifndef NADK_MBUF_MALLOC
	if (nadk_mbuf_shell_mpool_init(NADK_MBUF_SHELL_NUM))
		nadk_panic("Cannot init NADK mbuf shell mpool\n");
#endif
	return NADK_SUCCESS;
}

static int32_t nadk_rts_exit(void)
{
#ifndef NADK_MBUF_MALLOC
	nadk_mbuf_shell_mpool_exit();
#endif
	nadk_eal_log_exit();

	nadk_memzone_exit();

	nadk_eal_hugepage_exit();

	nadk_eal_memory_exit();

	memset(&internal_config, 0, sizeof(struct internal_config));

	return NADK_SUCCESS;
}

/*!
 * @details	Initialize the Network Application Development Kit Layer (NADK).
 *		This function must be the first function invoked by an
 *		application and is to be executed once.
 *
 * @param[in]	cfg - A pointer to nadk_init_cfg structure.
 *
 * @returns     NADK_SUCCESS in case of successfull intialization of
 *		NADK Layer; NADK_FAILURE otherwise.
 *
 */
int32_t nadk_init(struct nadk_init_cfg *cfg)
{

#ifndef NADK_LOGLIB_DISABLE
	if (!(cfg->flags & NADK_LOG_DISABLE)) {
		if (nadk_eal_log_early_init() < 0)
			nadk_panic("Cannot init early logs\n");
		nadk_set_log_level(NADK_LOG_DEBUG);
	}
#endif

	/* Init the run-time services memory, Buffers, Locks .. etc
	 * On the basis of input parameters cfg.data_mem_size & cfg.buf_mem_size
	*/
	if (nadk_rts_init(cfg))
		goto failure;

	if (cfg->flags & NADK_SYSTEM_INFO)
		nadk_print_system_info();

	/* Call init for each driver
	* Each driver calls nadk_register_driver with its dev_type and file_ops
	*/
	if (nadk_io_portal_init())
		goto failure;

	if (nadk_eth_driver_init())
		goto failure;
	if (nadk_sec_driver_init())
		goto failure;
#ifdef NADK_AIOP_CI_DEVICE
	if (nadk_aiop_driver_init())
		goto failure;
#endif
	if (nadk_conc_driver_init())
		goto failure;
	/* Other drivers to be added */
	if (nadk_platform_init(cfg))
		goto failure;

	nadk_notif_init();

	return NADK_SUCCESS;

failure:
	nadk_cleanup();
	return NADK_FAILURE;
}

/*!
 * @details	Do Clean up and exit for in context of a given application. This
 *		function must be invoked by an application before exiting.
 *
 * @returns     Not applicable.
 *
 */
void nadk_cleanup(void)
{
	nadk_notif_close();

	nadk_platform_exit();

	nadk_eth_driver_exit();
	nadk_sec_driver_exit();
#ifdef NADK_AIOP_CI_DEVICE
	nadk_aiop_driver_exit();
#endif
	nadk_conc_driver_exit();
	nadk_rts_exit();
}
