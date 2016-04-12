/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/*   Derived from DPDK's eal_common_log.h
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
 */

#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>

#include <nadk.h>
#include <nadk_common.h>
#include <nadk_queue.h>
#include <odp/spinlock.h>
#include <odp/hints.h>
#include <nadk_mpool.h>
#include <nadk_internal.h>

#define LOG_ELT_SIZE	512
#define NADK_LOG_HISTORY	256
#define LOG_HISTORY_MP_NAME "log_history"

static const char nadk_def_log_dir[] = "/var/log";

STAILQ_HEAD(log_history_list, log_history);

#ifdef LOG_MEMPOOL_SUPPORT
#define log_mempool_get nadk_mpool_getblock
#define log_mempool_free nadk_mpool_relblock
#else
#define log_mempool_get		malloc(NADK_LOG_HISTORY*2)
#define log_mempool_free(pool, obj)		free(obj)
#endif
/**
 * The structure of a message log in the log history.
 */
struct log_history {
	STAILQ_ENTRY(log_history) next;
	unsigned size;
	char buf[0];
};

/*static struct nadk_mpool *log_history_mp = NULL;*/
void *log_history_mp;

/* global log structure */
struct nadk_logs nadk_logs = {
	.type = ~0,
	.level = 0,
	.number_of_files = 0,
	.file_logging = 0,
};

FILE *earlylog_file;
FILE *log_file;
char filename[8][32];


static unsigned log_history_size;
static unsigned cur_id = 1;

static struct log_history_list log_history;

static odp_spinlock_t log_dump_lock = {0};
static odp_spinlock_t log_list_lock = {0};
static int history_enabled;

/**
 * This global structure stores some informations about the message
 * that is currently beeing processed by one lcore
 */
struct log_cur_msg {
	uint32_t loglevel; /**< log level - see nadk_log.h */
	uint32_t logtype;  /**< log type  - see nadk_log.h */
} ODP_ALIGNED_CACHE;
static struct log_cur_msg log_cur_msg[NADK_MAX_LCORE]; /**< per core log */

off_t fsize(FILE *f);

/* default logs */

int
nadk_log_add_in_history(const char *buf, size_t size)
{
	struct log_history *hist_buf = NULL;
	static const unsigned hist_buf_size = LOG_ELT_SIZE - sizeof(struct log_history);

	if (history_enabled == 0)
		return 0;

	odp_spinlock_lock(&log_list_lock);

	/* get a buffer for adding in history */
	if (log_history_size > NADK_LOG_HISTORY) {
		hist_buf = STAILQ_FIRST(&log_history);
		STAILQ_REMOVE_HEAD(&log_history, next);
	} else {
		hist_buf = nadk_mpool_getblock(log_history_mp, NULL);
	}

	/* no buffer */
	if (hist_buf == NULL) {
		odp_spinlock_unlock(&log_list_lock);
		return -ENOBUFS;
	}

	/* not enough room for msg, buffer go back in mempool */
	if (size >= hist_buf_size) {
		nadk_mpool_relblock(log_history_mp, hist_buf);
		odp_spinlock_unlock(&log_list_lock);
		return -ENOBUFS;
	}

	/* add in history */
	memcpy(hist_buf->buf, buf, size);
	hist_buf->buf[size] = hist_buf->buf[hist_buf_size-1] = '\0';
	hist_buf->size = size;
	STAILQ_INSERT_TAIL(&log_history, hist_buf, next);
	log_history_size++;
	odp_spinlock_unlock(&log_list_lock);

	return 0;
}

void
nadk_log_set_history(int enable)
{
	history_enabled = enable;
}

/* Change the stream that will be used by logging system */
int
nadk_openearlylog_stream(FILE *f)
{
	if (f == NULL)
		return -1;
	else
		earlylog_file = f;
	return 0;
}

/* Set global log level */
void
nadk_set_log_level(uint32_t level)
{
	nadk_logs.level = (uint32_t)level;
}

/* Get global log level */
uint32_t
nadk_get_log_level(void)
{
	return nadk_logs.level;
}

/* Set global log type */
void
nadk_set_log_type(uint32_t type, int enable)
{
	if (enable)
		nadk_logs.type |= type;
	else
		nadk_logs.type &= (~type);
}

/* get the current loglevel for the message beeing processed */
int nadk_log_cur_msg_loglevel(void)
{
	unsigned lcore_id;
	lcore_id = nadk_core_id();
	return log_cur_msg[lcore_id].loglevel;
}

/* get the current logtype for the message beeing processed */
int nadk_log_cur_msg_logtype(void)
{
	unsigned lcore_id;
	lcore_id = nadk_core_id();
	return log_cur_msg[lcore_id].logtype;
}

/* Dump log history to file */
void
nadk_log_dump_history(FILE *out)
{
	struct log_history_list tmp_log_history;
	struct log_history *hist_buf;
	unsigned i;

	/* only one dump at a time */
	odp_spinlock_lock(&log_dump_lock);

	/* save list, and re-init to allow logging during dump */
	odp_spinlock_lock(&log_list_lock);
	tmp_log_history = log_history;
	STAILQ_INIT(&log_history);
	odp_spinlock_unlock(&log_list_lock);

	for (i = 0; i < NADK_LOG_HISTORY; i++) {
		/* remove one message from history list */
		hist_buf = STAILQ_FIRST(&tmp_log_history);

		if (hist_buf == NULL)
			break;

		STAILQ_REMOVE_HEAD(&tmp_log_history, next);

		/* write on stdout */
		if (fwrite(hist_buf->buf, hist_buf->size, 1, out) == 0) {
			nadk_mpool_relblock(log_history_mp, hist_buf);
			break;
		}

		/* put back message structure in pool */
		nadk_mpool_relblock(log_history_mp, hist_buf);
	}
	fflush(out);

	odp_spinlock_unlock(&log_dump_lock);
}

off_t fsize(FILE *f)
{	off_t pos;
	off_t end;
	pos = ftell(f);
	fseek (f, 0, SEEK_END);
	end = ftell(f);
	fseek (f, pos, SEEK_SET);
	return end;
}

/*
 * Generates a log message The message will be sent in the stream.
 */
int
nadk_vlog(__attribute__((unused)) uint32_t level,
	__attribute__((unused)) uint32_t logtype,
	const char *format, va_list ap)
{
	int ret;
	FILE *f = earlylog_file;
	unsigned lcore_id;
	uint64_t file_size = nadk_logs.file_size * 1000;
	static uint64_t cur_len;
	/*converted file size from KBytes to bytes */

	/* save loglevel and logtype in a global per-lcore variable */
	lcore_id = nadk_core_id();
	log_cur_msg[lcore_id].loglevel = level;
	log_cur_msg[lcore_id].logtype = logtype;

	if (!nadk_logs.file_logging) {
		ret = vfprintf(f, format, ap);
		fflush(f);
	} else if (log_file) {
		f = log_file;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-nonliteral"
		ret = fprintf(f, format, ap);
#pragma GCC diagnostic pop
		fflush(f);
		if (ret <= 0) {
			printf("\n %s -err =%d", __FUNCTION__, ret);
			return ret;
		}
		cur_len += ret;
		/*printf("\n file size is %ld, %ld, %ld\n",
			fsize(files[1]),cur_len, file_size);*/
		if (cur_len >= file_size) {
			cur_id++;
			if (cur_id > nadk_logs.number_of_files) {
				cur_id = 1;
			}
			log_file = fopen(filename[cur_id - 1], "w");
			fclose(f);
		}
	}
	return 0;
}


/*
 * Generates a log message The message will be sent in the stream.
 */
int
nadk_log(uint32_t level, uint32_t logtype, const char *format, ...)
{
	va_list ap;
	int ret;

	va_start(ap, format);
	ret = nadk_vlog(level, logtype, format, ap);
	va_end(ap);
	return ret;
}

/*
 * called by environment-specific log init function to initialize log
 * history
 */
int
nadk_eal_common_log_init(struct nadk_init_cfg *cfg)
{
	char file_dir[24] = "\0";
	unsigned int i;

#ifdef LOG_MEMPOOL_SUPPORT
	struct nadk_mpool_cfg mpcfg = {0};

	/* reserve NADK_LOG_HISTORY*2 elements, so we can dump and
	* keep logging during this time */
	mpcfg.name = LOG_HISTORY_MP_NAME;
	mpcfg.block_size = NADK_LOG_HISTORY*2;
	mpcfg.num_global_blocks = LOG_ELT_SIZE;
	mpcfg.flags = 0; /* currently not using flags */
	mpcfg.num_threads = 0; /* currently not using threads */
	mpcfg.num_per_thread_blocks = 0; /* currently thread support is off */

	log_history_mp = nadk_mpool_create(&mpcfg, NULL, NULL);

	if (log_history_mp == NULL) {
		NADK_ERR(EAL, "cannot create log_history mempool\n");
		return NADK_FAILURE;
	}
#endif
	STAILQ_INIT(&log_history);

	nadk_logs.level = cfg->log_level;

	if (!nadk_logs.file_logging)
		return 0;

	nadk_logs.file_size = cfg->log_file_size;
	nadk_logs.number_of_files = cfg->log_files;

/*	TBD - the undefined log_file_dir is coming as junk.
	if (cfg->log_file_dir) {
		strcpy(file_dir, cfg->log_file_dir);
	} else
*/		strcpy(file_dir, nadk_def_log_dir);

	printf("\nTotal [%d] Log files each of size %d KB will be created\n",
				cfg->log_files, cfg->log_file_size);
	/*TBD - log_file directory is not being used at present*/
	printf("Following Log files are created:\n");
	for (i = 1; i <= cfg->log_files; i++) {
		sprintf(filename[i-1], "%s/nadk-%08d-%d.log",
			file_dir, getpid(), i);
		printf(" %s\n", filename[i-1]);
	}

	log_file = fopen(filename[0], "w");
	if (log_file == NULL)
		return -1;

	return 0;
}
int nadk_eal_common_log_exit(void)
{
	if (log_file) {
		fclose(log_file);
		log_file = NULL;
	}

	if (earlylog_file) {
		fclose(earlylog_file);
		earlylog_file = NULL;
	}

	if (log_history_mp)
		nadk_mpool_delete(log_history_mp);

	return 0;
}
