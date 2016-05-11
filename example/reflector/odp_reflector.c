/* Copyright (C) 2015 Freescale Semiconductor,Inc
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <stdlib.h>
#include <string.h>
#include <getopt.h>
#include <unistd.h>

#include <example_debug.h>

#include <odp.h>
#include <odp/helper/linux.h>
#include <odp/helper/eth.h>
#include <odp/helper/ip.h>

/*#define PERF_MONITOR	1*/
#ifdef	PERF_MONITOR
#include "../perfcounter/counters.h"
#endif
/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            8

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE	2048

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (2048 * SHM_PKT_POOL_BUF_SIZE)

/* ODP application data memory size include packet buffers */
#define ODPAPP_DATA_MEM_SIZE  ((uint64_t)256 * 1024 * 1024) /*256 MB*/

/** @def APPL_MODE_PKT_SCHED_PULL
 * @brief The application will handle packets with sheduler in Normal/PULL Mode
 */
#define APPL_MODE_PKT_SCHED_PULL	0

/** @def APPL_MODE_PKT_SCHED_PUSH
 * @brief The application will handle packets with sheduler in PUSH Mode
 */
#define APPL_MODE_PKT_SCHED_PUSH	1

/* Push mode with packet allocation and free */
#define APPL_MODE_PKT_ALLOC_SCH_PUSH	 2

/* Shuould not be used by User */
#define APPL_MODE_BENCHMARK		3


/** @def PRINT_APPL_MODE(x)
 * @brief Macro to print the current status of how the application handles
 * packets.
 */
#define PRINT_APPL_MODE(x) printf("%s(%i)\n", #x, (x))

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
			    strrchr((file_name), '/') + 1 : (file_name))
#define ODP_APP_DEBUG 0
/**
 * Parsed command line application arguments
 */
typedef struct {
	int cpu_count;		/**< system CPU count */
	const char *mask;	/**< CPU mask */
	int if_count;		/**< Number of interfaces to be used */
	char **if_names;	/**< Array of pointers to interface names */
	int mode;		/**< Packet IO mode */
	char *if_str;		/**< Storage for interface names */
} appl_args_t;

/**
 * Thread specific arguments
 */
typedef struct {
	char *pktio_dev;	/**< Interface name to use */
	int mode;		/**< Thread mode */
} thread_args_t;

/**
 * Grouping of both parsed CL args and thread specific args - alloc together
 */
typedef struct {
	/** Application (parsed) arguments */
	appl_args_t appl;
	/** Thread specific arguments */
	thread_args_t thread[MAX_WORKERS];
} args_t;

/** Global pointer to args */
static args_t *args;

/** Global buffer pool */
static odp_pool_t pool;

/* helper funcs */
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static odp_packet_t copy_pkt_addrs(odp_packet_t spkt);

static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Name of device to open
 * @param pool Pool to associate with device for packet RX/TX
 * @param mode Packet processing mode for this device (BURST or QUEUE)
 *
 * @return The handle of the created pktio object.
 * @retval ODP_PKTIO_INVALID if the create fails.
 */
static odp_pktio_t create_pktio(const char *dev, odp_pool_t pool)
{
	odp_pktio_t pktio;
	odp_queue_t inq_def;
	odp_queue_param_t qparam;
	char inq_name[ODP_QUEUE_NAME_LEN];
	int ret;
	odp_pktio_param_t pktio_param;

	odp_pktio_param_init(&pktio_param);

	pktio_param.in_mode = ODP_PKTIN_MODE_SCHED;
	/* Open a packet IO instance */
	pktio = odp_pktio_open(dev, pool, &pktio_param);
	if (pktio == ODP_PKTIO_INVALID)
		EXAMPLE_ABORT("Error: pktio create failed for %s\n", dev);

	snprintf(inq_name, sizeof(inq_name), "%" PRIu64 "-pktio_inq_def",
		 odp_pktio_to_u64(pktio));
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	inq_def = odp_queue_create(inq_name,
			   ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID)
		EXAMPLE_ABORT("Error: pktio inq create failed for %s\n", dev);

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0)
		EXAMPLE_ABORT("Error: default input-Q setup for %s\n", dev);

	ret = odp_pktio_start(pktio);
	if (ret != 0)
		EXAMPLE_ABORT("Error: unable to start %s\n", dev);

	printf("  created pktio:%02" PRIu64
	       ", dev:%s\n"
	       "  \tdefault pktio%02" PRIu64 "-INPUT queue:%" PRIu64 "\n",
	       odp_pktio_to_u64(pktio), dev,
	       odp_pktio_to_u64(pktio), odp_queue_to_u64(inq_def));

	return pktio;
}

/**
 * Loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_alloc_thread(void *arg)
{
	int thr;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_packet_t pkt, pkt2;
	odp_event_t ev;
#ifdef PERF_MONITOR
	uint64_t pkt_cnt = 0;
	uint64_t read1 = 0, read2 = 0, diff = 0;

	arm_enable_cycle_counter();
#endif
	thr = odp_thread_id();
	thr_args = arg;

	pktio = odp_pktio_lookup(thr_args->pktio_dev);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: lookup of pktio %s failed\n",
			    thr, thr_args->pktio_dev);
		return NULL;
	}

	printf("  [%02i] looked up pktio:%02" PRIu64
	       ", queue mode (ATOMIC queues)\n"
	       "         default pktio%02" PRIu64 "-INPUT queue:%" PRIu64 "\n",
	       thr, odp_pktio_to_u64(pktio), odp_pktio_to_u64(pktio),
	       odp_queue_to_u64(odp_pktio_inq_getdef(pktio)));

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;
#ifdef PERF_MONITOR
		read1 = arm_read_counter(PM_COUNTER_1);
#endif
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);
		pkt = odp_packet_from_event(ev);

		pkt2 = copy_pkt_addrs(pkt);
		if (pkt2 == ODP_PACKET_INVALID) {
			EXAMPLE_ERR("  [%i] copy packet failed.\n", thr);
			odp_packet_free(pkt);
			continue;
		}
		/* Enqueue the packet for output */
		pktio_tmp = odp_packet_input(pkt);
		if (0 == odp_pktio_send(pktio_tmp, &pkt2, 1)) {
			EXAMPLE_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_packet_free(pkt);
			odp_packet_free(pkt2);
			continue;
		}
		odp_packet_free(pkt);

#ifdef PERF_MONITOR
		read2 = arm_read_counter(PM_COUNTER_1);
		diff += (read2 - read1);
		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 1000000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu  -- cycles diff: %lu\n", thr, pkt_cnt, diff / 1000000);
			diff = 0;
			fflush(NULL);
		}
#endif
	}

#ifdef PERF_MONITOR
	arm_disable_cycle_counter();
#endif
/* unreachable */
	return NULL;
}
/**
 * Loopback worker thread using ODP queues
 *
 * @param arg  thread arguments of type 'thread_args_t *'
 */
static void *pktio_thread(void *arg)
{
	int thr;
	odp_pktio_t pktio;
	thread_args_t *thr_args;
	odp_packet_t pkt;
	odp_event_t ev;
#ifdef PERF_MONITOR
	uint64_t pkt_cnt = 0, read1 = 0, read2 = 0, diff = 0;

	arm_enable_cycle_counter();
#endif

	thr = odp_thread_id();
	thr_args = arg;

	pktio = odp_pktio_lookup(thr_args->pktio_dev);
	if (pktio == ODP_PKTIO_INVALID) {
		EXAMPLE_ERR("  [%02i] Error: lookup of pktio %s failed\n",
			    thr, thr_args->pktio_dev);
		return NULL;
	}

	printf("  [%02i] looked up pktio:%02" PRIu64
	       ", queue mode (ATOMIC queues)\n"
	       "         default pktio%02" PRIu64 "-INPUT queue:%" PRIu64 "\n",
	       thr, odp_pktio_to_u64(pktio), odp_pktio_to_u64(pktio),
	       odp_queue_to_u64(odp_pktio_inq_getdef(pktio)));

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;
#ifdef PERF_MONITOR
		read1 = arm_read_cycle_counter();
#endif
		ev = odp_schedule(NULL, ODP_SCHED_WAIT);
		pkt = odp_packet_from_event(ev);

		/* Swap Eth MACs and possibly IP-addrs before sending back */
		swap_pkt_addrs(&pkt, 1);

		/* Enqueue the packet for output */
		pktio_tmp = odp_packet_input(pkt);
		if (0 == odp_pktio_send(pktio_tmp, &pkt, 1)) {
			EXAMPLE_ERR("  [%i] Queue enqueue failed.\n", thr);
			odp_packet_free(pkt);
			continue;
		}
#ifdef PERF_MONITOR
		read2 = arm_read_cycle_counter();
		diff += (read2 - read1);
		/* Print packet counts every once in a while */
		if (odp_unlikely(pkt_cnt++ % 1000000 == 0)) {
			printf("  [%02i] pkt_cnt:%lu  -- cycles diff: %lu\n", thr, pkt_cnt, diff / 1000000);
			diff = 0;
			fflush(NULL);
		}
#endif
	}
#ifdef PERF_MONITOR
	arm_disable_cycle_counter();
#endif

/* unreachable */
	return NULL;
}

static void stats_prints(odp_pktio_t pktio, odp_pktio_stats_t *stats)
{
	printf(" [%lu]stats are:", odp_pktio_to_u64(pktio));
	printf("\n   in_octets  = %lu ", stats->in_octets);
	printf("in_ucast_pkts = %lu ", stats->in_ucast_pkts);
	printf("in_discards = %lu ", stats->in_discards);
	printf("in_errors = %lu ", stats->in_errors);
	printf("in_unknown_protos = %lu ", stats->in_unknown_protos);
	printf("\n   out_octets = %lu ", stats->out_octets);
	printf("out_ucast_pkts = %lu ", stats->out_ucast_pkts);
	printf("out_discards = %lu ", stats->out_discards);
	printf("out_errors = %lu\n ", stats->out_errors);
}

/**
 * ODP packet example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	int num_workers;
	int i;
	int cpu;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_platform_init_t plat_init;
	odp_pktio_stats_t stats;
	odp_pktio_t pktio;

	args = calloc(1, sizeof(args_t));
	if (args == NULL) {
		EXAMPLE_ERR("Error: args mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	memset(args, 0, sizeof(*args));
	/* Parse and store the application arguments */
	parse_args(argc, argv, &args->appl);

	/* Init ODP before calling anything else */

	switch (args->appl.mode) {
	case  APPL_MODE_PKT_SCHED_PULL:
		plat_init.dq_schedule_mode = ODPFSL_PULL;
		break;
	case APPL_MODE_PKT_SCHED_PUSH:
	case APPL_MODE_PKT_ALLOC_SCH_PUSH:
		plat_init.dq_schedule_mode = ODPFSL_PUSH;
		break;
	case APPL_MODE_BENCHMARK:
		plat_init.dq_schedule_mode = ODPFSL_PUSH;
		/* Following BIT is for internal use only
		   and not meant for User application */
		plat_init.dq_schedule_mode |= (1 << 31) ;
		break;
	}
	plat_init.data_mem_size = ODPAPP_DATA_MEM_SIZE;
	if (odp_init_global(NULL, &plat_init)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), &args->appl);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args->appl.cpu_count)
		num_workers = args->appl.cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
	if (args->appl.mask) {
		odp_cpumask_from_str(&cpumask, args->appl.mask);
		num_workers = odp_cpumask_count(&cpumask);
	}

	(void)odp_cpumask_to_str(&cpumask, cpumaskstr, sizeof(cpumaskstr));

	printf("num worker threads: %i\n", num_workers);
	printf("first CPU:          %i\n", odp_cpumask_first(&cpumask));
	printf("cpu mask:           %s\n", cpumaskstr);

	/* Create packet pool */
	odp_pool_param_init(&params);
	params.pkt.seg_len = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.len     = SHM_PKT_POOL_BUF_SIZE;
	params.pkt.num     = SHM_PKT_POOL_SIZE/SHM_PKT_POOL_BUF_SIZE;
	params.type        = ODP_POOL_PACKET;

	pool = odp_pool_create("packet_pool", &params);

	if (pool == ODP_POOL_INVALID) {
		EXAMPLE_ERR("Error: packet pool create failed.\n");
		exit(EXIT_FAILURE);
	}
	odp_pool_print(pool);

	/* Create a pktio instance for each interface */
	for (i = 0; i < args->appl.if_count; ++i)
		create_pktio(args->appl.if_names[i], pool);

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		int if_idx;

		if_idx = i % args->appl.if_count;

		args->thread[i].pktio_dev = args->appl.if_names[if_idx];
		args->thread[i].mode = args->appl.mode;

		/*
		 * Create threads one-by-one instead of all-at-once,
		 * because each thread might get different arguments.
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
			  (args->appl.mode == APPL_MODE_PKT_ALLOC_SCH_PUSH) ?
					  pktio_alloc_thread : pktio_thread,
					  &args->thread[i]);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	/* Master thread waits for other threads to exit */
	odph_linux_pthread_join(thread_tbl, num_workers);

	for (i = 0; i < args->appl.if_count; ++i) {
		memset(&stats, 0, sizeof(stats));
		printf("\nPacket stats I/F - %s", args->appl.if_names[i]);
		pktio = odp_pktio_lookup(args->appl.if_names[i]);
		if (pktio == ODP_PKTIO_INVALID)
			continue;
		odp_pktio_stats(pktio, &stats);
		stats_prints(pktio, &stats);
	}
	free(args->appl.if_names);
	free(args->appl.if_str);
	free(args);
	printf("Exit\n\n");

	return 0;
}


/**
 * Swap eth src<->dst and IP src<->dst addresses
 *
 * @param pkt_tbl  Array of packets
 * @param len      Length of pkt_tbl[]
 */

static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	odph_ethhdr_t *eth;
	odph_ethaddr_t tmp_addr;
	odph_ipv4hdr_t *ip;
	uint32be_t ip_tmp_addr; /* tmp ip addr */
	unsigned i;

	for (i = 0; i < len; ++i) {
		pkt = pkt_tbl[i];
		if (odp_packet_has_eth(pkt)) {
			eth = (odph_ethhdr_t *)odp_packet_l2_ptr(pkt, NULL);

			tmp_addr = eth->dst;
			eth->dst = eth->src;
			eth->src = tmp_addr;

			if (odp_packet_has_ipv4(pkt)) {
				/* IPv4 */
				ip = (odph_ipv4hdr_t *)
					odp_packet_l3_ptr(pkt, NULL);

				ip_tmp_addr  = ip->src_addr;
				ip->src_addr = ip->dst_addr;
				ip->dst_addr = ip_tmp_addr;
			}
		}
	}
}

static odp_packet_t copy_pkt_addrs(odp_packet_t spkt)
{
	odp_packet_t pkt2;
	odph_ethhdr_t *eth, *srceth;
	odph_ipv4hdr_t *ip, *sip;

	pkt2 = odp_packet_alloc(pool, odp_packet_len(spkt));
	if (pkt2 == ODP_PACKET_INVALID)
		return pkt2;

	srceth = (odph_ethhdr_t *)odp_packet_l2_ptr(spkt, NULL);
	sip = (odph_ipv4hdr_t *)((char *)srceth + ODPH_ETHHDR_LEN);
	/* ether */
	eth = (odph_ethhdr_t *)odp_packet_data(pkt2);
	memcpy((char *)eth->src.addr, srceth->dst.addr, ODPH_ETHADDR_LEN);
	memcpy((char *)eth->dst.addr, srceth->src.addr, ODPH_ETHADDR_LEN);
	eth->type = odp_cpu_to_be_16(ODPH_ETHTYPE_IPV4);

	/* ip */
	ip = (odph_ipv4hdr_t *)((char *)eth + ODPH_ETHHDR_LEN);
	ip->dst_addr = sip->src_addr;
	ip->src_addr = sip->dst_addr;
	ip->ver_ihl = sip->ver_ihl;
	ip->tot_len = sip->tot_len;
	ip->proto = ODPH_IPPROTO_UDP;
	ip->chksum = 0;
	return pkt2;
}


/**
 * Parse and store the command line arguments
 *
 * @param argc       argument count
 * @param argv[]     argument vector
 * @param appl_args  Store application arguments here
 */
static void parse_args(int argc, char *argv[], appl_args_t *appl_args)
{
	int opt;
	int long_index;
	char *token;
	size_t len;
	odp_cpumask_t cpumask, cpumask_args, cpumask_and;
	int i, num_workers;
	static struct option longopts[] = {
		{"workers", required_argument, NULL, 'w'},
		{"cpumask", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};

	appl_args->mode = APPL_MODE_PKT_SCHED_PUSH;

	while (1) {
		opt = getopt_long(argc, argv, "+c:+w:i:+m:h",
				  longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'w':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'c':
			appl_args->mask = optarg;
			odp_cpumask_from_str(&cpumask_args, args->appl.mask);
			num_workers = odp_cpumask_default_worker(&cpumask, 0);
			odp_cpumask_and(&cpumask_and, &cpumask_args, &cpumask);
			if (odp_cpumask_count(&cpumask_and) <
			    odp_cpumask_count(&cpumask_args)) {
				EXAMPLE_ERR("Wrong cpu mask, max cpu's:%d\n",
					    num_workers);
				exit(EXIT_FAILURE);
			}
			break;
			/* parse packet-io interface names */
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_str = malloc(len);
			if (appl_args->if_str == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* count the number of tokens separated by ',' */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL;
			     token = strtok(NULL, ","), i++)
				;

			appl_args->if_count = i;

			if (appl_args->if_count == 0) {
				free((void *)appl_args->if_str);
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			/* allocate storage for the if names */
			appl_args->if_names =
			    calloc(appl_args->if_count, sizeof(char *));

			/* store the if names (reset names string) */
			strcpy(appl_args->if_str, optarg);
			for (token = strtok(appl_args->if_str, ","), i = 0;
			     token != NULL; token = strtok(NULL, ","), i++) {
				appl_args->if_names[i] = token;
			}
			break;

		case 'm':
			i = atoi(optarg);
			switch (i) {
			case 0:
				appl_args->mode = APPL_MODE_PKT_SCHED_PULL;
				break;
			case 1:
				appl_args->mode = APPL_MODE_PKT_SCHED_PUSH;
				break;
			case 2:
				appl_args->mode = APPL_MODE_PKT_ALLOC_SCH_PUSH;
				break;
			case 3:
				appl_args->mode = APPL_MODE_BENCHMARK;
				break;
			default:
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			break;
		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);

		default:
			break;
		}
	}

	if (appl_args->if_count == 0 || appl_args->mode == -1) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	optind = 1;		/* reset 'extern optind' from the getopt lib */
}

/**
 * Print system and application info
 */
static void print_info(char *progname, appl_args_t *appl_args)
{
	int i;

	printf("\n"
	       "ODP system info\n"
	       "---------------\n"
	       "ODP API version: %s\n"
	       "CPU model:       %s\n"
	       "CPU freq (hz):   %"PRIu64"\n"
	       "Cache line size: %i\n"
	       "CPU count:       %i\n"
	       "\n",
	       odp_version_api_str(), odp_sys_cpu_model_str(), odp_sys_cpu_hz(),
	       odp_sys_cache_line_size(), odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
	       "-----------------\n"
	       "IF-count:        %i\n"
	       "Using IFs:      ",
	       progname, appl_args->if_count);
	for (i = 0; i < appl_args->if_count; ++i)
		printf(" %s", appl_args->if_names[i]);
	printf("\n"
	       "Mode:            ");
	switch (appl_args->mode) {
	case APPL_MODE_PKT_SCHED_PULL:
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED_PULL);
		break;
	case APPL_MODE_PKT_SCHED_PUSH:
		PRINT_APPL_MODE(APPL_MODE_PKT_SCHED_PUSH);
		break;
	case APPL_MODE_PKT_ALLOC_SCH_PUSH:
		PRINT_APPL_MODE(APPL_MODE_PKT_ALLOC_SCH_PUSH);
		break;
	case APPL_MODE_BENCHMARK:
		PRINT_APPL_MODE(APPL_MODE_BENCHMARK);
		break;
	}
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
	       "Usage: %s OPTIONS\n"
	       "  E.g. %s -i dpni.1,dpni.2 -m 1 --cpumask 0x2\n"
	       "\n"
	       "FSL OpenDataPlane reflector application.\n"
	       "\n"
	       "Mandatory OPTIONS:\n"
	       "  -i, --interface pktio interfaces (comma-separated, no spaces)\n"
	       "\n"
	       "Optional OPTIONS\n"
	       "  -w, --workers specify number of workers need to be assigned to application\n"
	       "	         default is to assign all\n"
	       "  -c, --cpumask to set on cores\n"
	       "  -m, --mode      0:	Receive Packets in Schedule PULL Mode.\n"
	       "                  1:	Receive Packets in Schedule PUSH Mode.\n"
		   "                  2:	Receive Packets in Schedule PUSH Mode - with alloc and free\n"
	       "  -h, --help		Display help and exit.\n"
	       "\n", NO_PATH(progname), NO_PATH(progname)
	    );
}
