/* Copyright (c) 2015, Linaro Limited
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
#include <strings.h>
#include <errno.h>
#include <stdio.h>

/** @def MAX_WORKERS
 * @brief Maximum number of worker threads
 */
#define MAX_WORKERS            32

/** @def SHM_PKT_POOL_SIZE
 * @brief Size of the shared memory block
 */
#define SHM_PKT_POOL_SIZE      (512*2048)

/** @def SHM_PKT_POOL_BUF_SIZE
 * @brief Buffer size of the packet pool buffer
 */
#define SHM_PKT_POOL_BUF_SIZE  1856

/** @def MAX_PMR_COUNT
 * @brief Maximum number of Classification Policy for Exact Matching
 */
#define MAX_PMR_COUNT	8

/** @def PMR_RULE_BASE_INDEX
 * @brief Starting Index to store PMR in "stats"
 */
#define PMR_RULE_BASE_INDEX	0

/** @def MAX_L2_RULE_COUNT
 * @brief Maximum number of Classification Policy for L2 Prio
 */
#define MAX_L2_RULE_COUNT	8

/** @def L2_RULE_BASE_INDEX
 * @brief Starting Index to store L2 rule in "stats"
 */
#define L2_RULE_BASE_INDEX	(PMR_RULE_BASE_INDEX + MAX_PMR_COUNT)

/** @def MAX_L3_RULE_COUNT
 * @brief Maximum number of Classification Policy for L3 QoS
 */
#define MAX_L3_RULE_COUNT	8

/** @def L3_RULE_BASE_INDEX
 * @brief Starting Index to store L3 rule in "stats"
 */
#define L3_RULE_BASE_INDEX	(L2_RULE_BASE_INDEX + MAX_L2_RULE_COUNT)

/** @def MAX_RULE_COUNT
 * @brief Maximum number of Classification Rules
 */
#define MAX_RULE_COUNT	(MAX_PMR_COUNT + MAX_L2_RULE_COUNT + \
			MAX_L3_RULE_COUNT + 1)

/** @def DEFAULT_RULE_BASE_INDEX
 * @brief Starting Index to store Default rule in "stats"
 */
#define DEFAULT_RULE_BASE_INDEX (MAX_RULE_COUNT - 1)

/** @def DISPLAY_STRING_LEN
 * @brief Length of string used to display term value
 */
#define DISPLAY_STRING_LEN	32

/** Get rid of path in filename - only for unix-type paths using '/' */
#define NO_PATH(file_name) (strrchr((file_name), '/') ? \
		strrchr((file_name), '/') + 1 : (file_name))

typedef struct {
	odp_queue_t queue;	/**< Associated queue handle */
	odp_cos_t cos;		/**< Associated cos handle */
	odp_pmr_t pmr;		/**< Associated pmr handle */
	odp_atomic_u64_t packet_count;	/**< count of received packets */
	char queue_name[ODP_QUEUE_NAME_LEN];	/**< queue name */
	union {
		struct {
			odp_pmr_term_e term;	/**< odp pmr term value */
			uint64_t val;		/**< pmr term value */
			uint64_t mask;		/**< pmr term mask */
			uint32_t val_sz;	/**< size of the pmr term */
			uint32_t offset;	/**< pmr term offset */
		} rule;
		struct {
			uint8_t val;		/**<  L2 Priority Value*/
		} l2_rule;
		struct {
			uint8_t val;		/**< L3 QoS Value */
		} l3_rule;
	};
	char value[DISPLAY_STRING_LEN];	/**< Display string for value */
	char mask[DISPLAY_STRING_LEN];	/**< Display string for mask */
} global_statistics;

typedef struct {
	global_statistics stats[MAX_RULE_COUNT];
	int policy_count;	/**< global policy count for PMR*/
	int l2_rule_count;	/**< global policy count for L2 Prio Rules*/
	int l3_rule_count;	/**< global policy count for L3 Prio Rules*/
	int appl_mode;		/**< application mode */
	odp_atomic_u64_t total_packets;	/**< total received packets */
	int cpu_count;		/**< Number of CPUs to use */
	uint32_t time;		/**< Number of seconds to run */
	char *if_name;		/**< pointer to interface names */
	odp_bool_t l3_precedence;/**< Precedence Flag Over L2
						Prio Rule*/
} appl_args_t;

enum packet_mode {
	APPL_MODE_DROP,		/**< Packet is dropped */
	APPL_MODE_REPLY		/**< Packet is sent back */
};

/* helper funcs */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len);
static void swap_pkt_addrs(odp_packet_t pkt_tbl[], unsigned len);
static void parse_args(int argc, char *argv[], appl_args_t *appl_args);
static void print_info(char *progname, appl_args_t *appl_args);
static void usage(char *progname);
static void configure_cos_queue(odp_pktio_t pktio, appl_args_t *args);
static void configure_default_queue(odp_pktio_t pktio, appl_args_t *args);
static int convert_str_to_pmr_enum(char *token, odp_pmr_term_e *term,
				   uint32_t *offset);
static int parse_pmr_policy(appl_args_t *appl_args, char *argv[], char *optarg);

static inline
void print_cls_statistics(appl_args_t *args)
{
	int i;
	uint32_t timeout;
	int infinite = 0;

	printf("\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	/* print statistics */
	printf("CLASSIFIER EXAMPLE STATISTICS\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	printf("CONFIGURATION\n");
	printf("\n");
	printf("QUEUE\tVALUE\t\tMASK\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	for (i = 0; i < args->policy_count - 1; i++) {
		printf("%s\t", args->stats[i].queue_name);
		printf("%s\t", args->stats[i].value);
		printf("%s\n", args->stats[i].mask);
	}
	for (i = 0; i < args->l2_rule_count; i++) {
		printf("%s\t", args->stats[L2_RULE_BASE_INDEX + i].queue_name);
		printf("VLAN Prio:%s\n",
		       args->stats[L2_RULE_BASE_INDEX + i].value);
	}
	for (i = 0; i < args->l3_rule_count; i++) {
		printf("%s\t", args->stats[L3_RULE_BASE_INDEX + i].queue_name);
		printf("IP QoS:%s\n",
		       args->stats[L3_RULE_BASE_INDEX + i].value);
	}
	printf("\n");
	printf("RECEIVED PACKETS\n");
	for (i = 0; i < 40; i++)
		printf("-");
	printf("\n");
	for (i = 0; i < args->policy_count - 1; i++)
		printf("%-12s ", args->stats[i].queue_name);
	for (i = 0; i < args->l2_rule_count; i++) {
		printf("%-12s ",
		       args->stats[L2_RULE_BASE_INDEX + i].queue_name);
	}
	for (i = 0; i < args->l3_rule_count; i++) {
		printf("%-12s ",
		       args->stats[L3_RULE_BASE_INDEX + i].queue_name);
	}

	printf("%-12s ", args->stats[DEFAULT_RULE_BASE_INDEX].queue_name);
	printf("Total Packets");
	printf("\n");

	timeout = args->time;

	/* Incase if default value is given for timeout
	run the loop infinitely */
	if (timeout == 0)
		infinite = 1;

	for (; timeout > 0 || infinite; timeout--) {
		for (i = 0; i < args->policy_count - 1; i++)
			printf("%-12" PRIu64 " ",
			       odp_atomic_load_u64(&args->stats[i]
						   .packet_count));

		for (i = 0; i < args->l2_rule_count; i++)
			printf("%-12" PRIu64 " ",
			       odp_atomic_load_u64(&args->stats[L2_RULE_BASE_INDEX + i]
						   .packet_count));

		for (i = 0; i < args->l3_rule_count; i++)
			printf("%-12" PRIu64 " ",
			       odp_atomic_load_u64(&args->stats[L3_RULE_BASE_INDEX + i]
						   .packet_count));

		printf("%-12" PRIu64 " ",
		       odp_atomic_load_u64(&args->stats[DEFAULT_RULE_BASE_INDEX]
						   .packet_count));

		printf("%-" PRIu64, odp_atomic_load_u64(&args->
							total_packets));

		sleep(1);
		printf("\r");
		fflush(stdout);
	}

	printf("\n");
}

static inline
int parse_ipv4_addr(const char *ipaddress, uint64_t *addr)
{
	uint32_t b[4];
	int converted;

	converted = sscanf(ipaddress, "%d.%d.%d.%d",
			&b[3], &b[2], &b[1], &b[0]);
	if (4 != converted)
		return -1;

	if ((b[0] > 255) || (b[1] > 255) || (b[2] > 255) || (b[3] > 255))
		return -1;

	*addr = b[0] | b[1] << 8 | b[2] << 16 | b[3] << 24;

	return 0;
}

static inline
int parse_mask(const char *str, uint64_t *mask)
{
	uint64_t b;
	int ret;

	ret = sscanf(str, "%" SCNx64, &b);
	*mask = b;
	return ret != 1;
}

static
int parse_value(const char *str, uint64_t *val, uint32_t *val_sz)
{
	size_t len;
	size_t i;
	int converted;
	union {
		uint64_t u64;
		uint8_t u8[8];
	} buf = {.u64 = 0};

	len = strlen(str);
	if (len > 2 * sizeof(buf))
		return -1;

	for (i = 0; i < len; i += 2) {
		converted = sscanf(&str[i], "%2" SCNx8, &buf.u8[i / 2]);
		if (1 != converted)
			return -1;
	}

	*val = buf.u64;
	*val_sz = len / 2;
	return 0;
}

/**
 * Create a pktio handle, optionally associating a default input queue.
 *
 * @param dev Device name
 * @param pool Associated Packet Pool
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
	if (pktio == ODP_PKTIO_INVALID) {
		if (odp_errno() == EPERM)
			EXAMPLE_ERR("Root level permission required\n");

		EXAMPLE_ERR("pktio create failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	odp_queue_param_init(&qparam);
	qparam.sched.prio  = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync  = ODP_SCHED_SYNC_ATOMIC;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	snprintf(inq_name, sizeof(inq_name), "%" PRIu64 "-pktio_inq_def",
		 odp_pktio_to_u64(pktio));
	inq_name[ODP_QUEUE_NAME_LEN - 1] = '\0';

	inq_def = odp_queue_create(inq_name, ODP_QUEUE_TYPE_PKTIN, &qparam);
	if (inq_def == ODP_QUEUE_INVALID) {
		EXAMPLE_ERR("pktio inq create failed for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	ret = odp_pktio_inq_setdef(pktio, inq_def);
	if (ret != 0) {
		EXAMPLE_ERR("default input-Q setup for %s\n", dev);
		exit(EXIT_FAILURE);
	}

	printf("  created pktio:%02" PRIu64
			", dev:%s, queue mode (ATOMIC queues)\n"
			"  \tdefault pktio%02" PRIu64
			"-INPUT queue:%" PRIu64 "\n",
			odp_pktio_to_u64(pktio), dev,
			odp_pktio_to_u64(pktio), odp_queue_to_u64(inq_def));

	return pktio;
}

/**
 * Worker threads to receive the packet
 *
 */
static void *pktio_receive_thread(void *arg)
{
	int thr;
	odp_queue_t outq_def;
	odp_packet_t pkt;
	odp_event_t ev;
	unsigned long err_cnt = 0;
	odp_queue_t queue;
	int i;
	thr = odp_thread_id();
	appl_args_t *appl = (appl_args_t *)arg;
	global_statistics *stats;

	/* Loop packets */
	for (;;) {
		odp_pktio_t pktio_tmp;

		/* Use schedule to get buf from any input queue */
		ev = odp_schedule(&queue, ODP_SCHED_WAIT);

		/* Loop back to receive packets incase of invalid event */
		if (odp_unlikely(ev == ODP_EVENT_INVALID))
			continue;

		pkt = odp_packet_from_event(ev);

		/* Total packets received */
		odp_atomic_inc_u64(&appl->total_packets);

		/* Drop packets with errors */
		if (odp_unlikely(drop_err_pkts(&pkt, 1) == 0)) {
			EXAMPLE_ERR("Drop frame - err_cnt:%lu\n", ++err_cnt);
			continue;
		}

		pktio_tmp = odp_packet_input(pkt);
		outq_def = odp_pktio_outq_getdef(pktio_tmp);

		if (outq_def == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("  [%02i] Error: def output-Q query\n",
				    thr);
			return NULL;
		}

		/* Swap Eth MACs and possibly IP-addrs before sending back */
		swap_pkt_addrs(&pkt, 1);

		for (i = 0; i <  MAX_RULE_COUNT; i++) {
			stats = &appl->stats[i];
			if (queue == stats->queue)
				odp_atomic_inc_u64(&stats->packet_count);
		}

		if (appl->appl_mode == APPL_MODE_DROP)
			odp_packet_free(pkt);
		else
			if (odp_queue_enq(outq_def, ev)) {
				EXAMPLE_ERR("  [%i] Queue enqueue failed.\n",
					    thr);
				odp_packet_free(pkt);
				continue;
			}
	}

	return NULL;
}

static void configure_default_queue(odp_pktio_t pktio, appl_args_t *args)
{
	odp_queue_param_t qparam;
	odp_cos_t cos_default;
	char cos_name[ODP_COS_NAME_LEN];
	const char *queue_name = "DefaultQueue";
	odp_queue_t queue_default;
	global_statistics *stats = args->stats;

	snprintf(cos_name, sizeof(cos_name), "Default%s", args->if_name);
	cos_default = odp_cos_create(cos_name);

	odp_queue_param_init(&qparam);
	qparam.sched.prio = ODP_SCHED_PRIO_DEFAULT;
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;
	queue_default = odp_queue_create(queue_name,
					 ODP_QUEUE_TYPE_SCHED, &qparam);

	if (0 > odp_cos_queue_set(cos_default, queue_default)) {
		EXAMPLE_ERR("odp_cos_queue_set failed");
		exit(EXIT_FAILURE);
	}

	if (0 > odp_pktio_default_cos_set(pktio, cos_default)) {
		EXAMPLE_ERR("odp_pktio_default_cos_set failed");
		exit(EXIT_FAILURE);
	}
	stats[DEFAULT_RULE_BASE_INDEX].cos = cos_default;
	/* add default queue to global stats */
	stats[DEFAULT_RULE_BASE_INDEX].queue = queue_default;
	snprintf(stats[DEFAULT_RULE_BASE_INDEX].queue_name,
		 sizeof(stats[DEFAULT_RULE_BASE_INDEX].queue_name),
		 "%s", queue_name);
	odp_atomic_init_u64(&stats[DEFAULT_RULE_BASE_INDEX].packet_count, 0);
	args->policy_count++;
}

static void configure_cos_queue(odp_pktio_t pktio, appl_args_t *args)
{
	char cos_name[ODP_COS_NAME_LEN];
	char queue_name[ODP_QUEUE_NAME_LEN];
	int i;
	global_statistics *stats;
	odp_queue_param_t qparam;

	for (i = 0; i < args->policy_count; i++) {
		stats = &args->stats[i];
		snprintf(cos_name, sizeof(cos_name), "CoS%s",
			 stats->queue_name);
		stats->cos = odp_cos_create(cos_name);

		const odp_pmr_match_t match = {
			.term = stats->rule.term,
			.val = &stats->rule.val,
			.mask = &stats->rule.mask,
			.val_sz = stats->rule.val_sz,
			.offset = stats->rule.offset
		};

		stats->pmr = odp_pmr_create(&match);
		qparam.sched.prio = i % odp_schedule_num_prio();
		qparam.sched.sync = ODP_SCHED_SYNC_NONE;
		qparam.sched.group = ODP_SCHED_GROUP_ALL;

		snprintf(queue_name, sizeof(queue_name), "%s%d",
			 args->stats[i].queue_name, i);
		stats->queue = odp_queue_create(queue_name,
						 ODP_QUEUE_TYPE_SCHED,
						 &qparam);
		if (0 > odp_cos_queue_set(stats->cos, stats->queue)) {
			EXAMPLE_ERR("odp_cos_queue_set failed");
			exit(EXIT_FAILURE);
		}

		if (0 > odp_pktio_pmr_cos(stats->pmr, pktio, stats->cos)) {
			EXAMPLE_ERR("odp_pktio_pmr_cos failed");
			exit(EXIT_FAILURE);
		}

		odp_atomic_init_u64(&stats->packet_count, 0);
	}
}

static void configure_l3_qos_cos_queue(odp_pktio_t pktio, appl_args_t *args)
{
	int i = 0, retval;
	odp_cos_t cos_tbl[MAX_L3_RULE_COUNT];
	odp_queue_t queue_tbl[MAX_L3_RULE_COUNT];
	uint8_t qos_tbl[MAX_L3_RULE_COUNT];
	char cosname[ODP_COS_NAME_LEN];
	char queuename[ODP_QUEUE_NAME_LEN];
	odp_queue_param_t qparam;
	global_statistics *stats;

	/** Initialize scalar variable qos_tbl **/
	for (i = 0; i < MAX_L3_RULE_COUNT; i++)
		qos_tbl[i] = 0;

	/*Configure Scheduler parameters*/
	memset(&qparam, 0, sizeof(odp_queue_param_t));
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < args->l3_rule_count; i++) {
		stats = &args->stats[L3_RULE_BASE_INDEX + i];
		sprintf(cosname, "%s_%d", "L3_Cos", i);
		cos_tbl[i] = odp_cos_create(cosname);
		if (cos_tbl[i] == ODP_COS_INVALID) {
			EXAMPLE_ERR("odp_cos_create failed");
			break;
		}
		stats->cos = cos_tbl[i];

		qparam.sched.prio = i % odp_schedule_num_prio();
		sprintf(queuename, "%s_%d", stats->queue_name, i);
		queue_tbl[i] = odp_queue_create(queuename, ODP_QUEUE_TYPE_SCHED,
					      &qparam);
		if (queue_tbl[i] == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("odp_queue_create failed");
			break;
		}

		stats->queue = queue_tbl[i];

		retval = odp_cos_queue_set(cos_tbl[i], queue_tbl[i]);
		if (retval < 0) {
			EXAMPLE_ERR("odp_cos_queue_set failed");
			exit(EXIT_FAILURE);
		}
		qos_tbl[i] = (int8_t)stats->l3_rule.val;
		odp_atomic_init_u64(&stats->packet_count, 0);
	}
	/* count 'i' is passed instead of num_qos to handle the rare scenario
	if the odp_cos_create() failed in the middle*/
	if (i != 0) {
		retval = odp_cos_with_l3_qos(pktio, i, qos_tbl, cos_tbl,
					     args->l3_precedence);
		if (retval < 0) {
			EXAMPLE_ERR("Error in configuring l3 QoS rules\n");
			exit(EXIT_FAILURE);
		}
	}
}

static void configure_l2_prio_cos_queue(odp_pktio_t pktio, appl_args_t *args)
{
	int i = 0, retval;
	odp_cos_t cos_tbl[MAX_L2_RULE_COUNT] = {0};
	odp_queue_t queue_tbl[MAX_L2_RULE_COUNT] = {0};
	uint8_t l2_tbl[MAX_L2_RULE_COUNT] = {0};
	char cosname[ODP_COS_NAME_LEN] = {'0'};
	char queuename[ODP_QUEUE_NAME_LEN] = {'0'};
	odp_queue_param_t qparam;
	global_statistics *stats;

	/*Configure Scheduler parameters*/
	memset(&qparam, 0, sizeof(odp_queue_param_t));
	qparam.sched.sync = ODP_SCHED_SYNC_NONE;
	qparam.sched.group = ODP_SCHED_GROUP_ALL;

	for (i = 0; i < args->l2_rule_count; i++) {
		stats = &args->stats[L2_RULE_BASE_INDEX + i];
		sprintf(cosname, "%s_%d", "L2_Cos", i);
		cos_tbl[i] = odp_cos_create(cosname);
		if (cos_tbl[i] == ODP_COS_INVALID) {
			EXAMPLE_ERR("odp_cos_create failed");
			break;
		}
		stats->cos = cos_tbl[i];

		qparam.sched.prio = i % odp_schedule_num_prio();
		sprintf(queuename, "%s_%d", stats->queue_name, i);
		queue_tbl[i] = odp_queue_create(queuename, ODP_QUEUE_TYPE_SCHED,
					      &qparam);
		if (queue_tbl[i] == ODP_QUEUE_INVALID) {
			EXAMPLE_ERR("odp_queue_create failed");
			break;
		}
		stats->queue = queue_tbl[i];

		retval = odp_cos_queue_set(cos_tbl[i], queue_tbl[i]);
		if (retval < 0) {
			EXAMPLE_ERR("odp_cos_queue_set failed");
			exit(EXIT_FAILURE);
		}
		l2_tbl[i] = (uint8_t)stats->l2_rule.val;
		odp_atomic_init_u64(&stats->packet_count, 0);
	}
	/* count 'i' is passed instead of num_qos to handle the rare scenario
	if the odp_cos_create() failed in the middle*/
	if (i != 0) {
		retval = odp_cos_with_l2_priority(pktio, args->l2_rule_count,
						  l2_tbl, cos_tbl);
		if (retval < 0) {
			EXAMPLE_ERR("Error in configuring l2 priority rules\n");
			exit(EXIT_FAILURE);
		}
	}
}

/**
 * ODP Classifier example main function
 */
int main(int argc, char *argv[])
{
	odph_linux_pthread_t thread_tbl[MAX_WORKERS];
	odp_pool_t pool;
	int num_workers;
	int i;
	int cpu;
	odp_cpumask_t cpumask;
	char cpumaskstr[ODP_CPUMASK_STR_SIZE];
	odp_pool_param_t params;
	odp_pktio_t pktio;
	appl_args_t *args;

	args = calloc(1, sizeof(appl_args_t));
	if (args == NULL) {
		EXAMPLE_ERR("Error: args mem alloc failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Parse and store the application arguments */
	parse_args(argc, argv, args);

	/* Init ODP before calling anything else */
	if (odp_init_global(NULL, NULL)) {
		EXAMPLE_ERR("Error: ODP global init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Init this thread */
	if (odp_init_local(ODP_THREAD_CONTROL)) {
		EXAMPLE_ERR("Error: ODP local init failed.\n");
		exit(EXIT_FAILURE);
	}

	/* Print both system and application information */
	print_info(NO_PATH(argv[0]), args);

	/* Default to system CPU count unless user specified */
	num_workers = MAX_WORKERS;
	if (args->cpu_count)
		num_workers = args->cpu_count;

	/* Get default worker cpumask */
	num_workers = odp_cpumask_default_worker(&cpumask, num_workers);
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

	/* odp_pool_print(pool); */
	odp_atomic_init_u64(&args->total_packets, 0);

	/* create pktio per interface */
	pktio = create_pktio(args->if_name, pool);

	configure_cos_queue(pktio, args);

	configure_l2_prio_cos_queue(pktio, args);

	configure_l3_qos_cos_queue(pktio, args);

	/* configure default Cos and default queue */
	configure_default_queue(pktio, args);

	if (odp_pktio_start(pktio)) {
		EXAMPLE_ERR("Error: unable to start pktio.\n");
		exit(EXIT_FAILURE);
	}

	/* Create and init worker threads */
	memset(thread_tbl, 0, sizeof(thread_tbl));

	cpu = odp_cpumask_first(&cpumask);
	for (i = 0; i < num_workers; ++i) {
		odp_cpumask_t thd_mask;
		/*
		 * Calls odp_thread_create(cpu) for each thread
		 */
		odp_cpumask_zero(&thd_mask);
		odp_cpumask_set(&thd_mask, cpu);
		odph_linux_pthread_create(&thread_tbl[i], &thd_mask,
					  pktio_receive_thread,
					  args);
		cpu = odp_cpumask_next(&cpumask, cpu);
	}

	print_cls_statistics(args);

	for (i = 0; i < args->policy_count; i++) {
		odp_cos_destroy(args->stats[i].cos);
		odp_queue_destroy(args->stats[i].queue);
	}

	free(args->if_name);
	free(args);
	printf("Exit\n\n");

	return 0;
}

/**
 * Drop packets which input parsing marked as containing errors.
 *
 * Frees packets with error and modifies pkt_tbl[] to only contain packets with
 * no detected errors.
 *
 * @param pkt_tbl  Array of packet
 * @param len      Length of pkt_tbl[]
 *
 * @return Number of packets with no detected error
 */
static int drop_err_pkts(odp_packet_t pkt_tbl[], unsigned len)
{
	odp_packet_t pkt;
	unsigned pkt_cnt = len;
	unsigned i, j;

	for (i = 0, j = 0; i < len; ++i) {
		pkt = pkt_tbl[i];

		if (odp_unlikely(odp_packet_has_error(pkt))) {
			odp_packet_free(pkt); /* Drop */
			pkt_cnt--;
		} else if (odp_unlikely(i != j++)) {
			pkt_tbl[j-1] = pkt;
		}
	}

	return pkt_cnt;
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

static int convert_str_to_pmr_enum(char *token, odp_pmr_term_e *term,
				   uint32_t *offset)
{
	if (NULL == token)
		return -1;

	if (0 == strcasecmp(token, "ODP_PMR_SIP_ADDR")) {
		*term = ODP_PMR_SIP_ADDR;
		return 0;
	} else {
		errno = 0;
		*offset = strtoul(token, NULL, 0);
		if (errno)
			return -1;
		*term = ODP_PMR_CUSTOM_FRAME;
		return 0;
	}
	return -1;
}

static int parse_l3_rule_policy(appl_args_t *appl_args, char *argv[] ODP_UNUSED,
				char *optarg)
{
	int policy_count;
	char *token;
	uint8_t	l3_prio;
	size_t len;
	global_statistics *stats;
	char *l3_rule_str;

	policy_count = appl_args->l3_rule_count;
	stats = appl_args->stats;

	/* last array index is needed for default queue */
	if (policy_count >= MAX_L3_RULE_COUNT - 1) {
		EXAMPLE_ERR("Maximum allowed PMR reached\n");
		return -1;
	}

	len = strlen(optarg);
	len++;
	l3_rule_str = malloc(len);
	if (!l3_rule_str)
		return -1;
	strcpy(l3_rule_str, optarg);

	/* L2 Priority Value */
	token = strtok(l3_rule_str, ":");
	strncpy(stats[L3_RULE_BASE_INDEX + policy_count].value, token,
		DISPLAY_STRING_LEN - 1);
	l3_prio = atoi(token);
	stats[L3_RULE_BASE_INDEX + policy_count].l3_rule.val = l3_prio;

	/* Queue Name */
	token = strtok(NULL, ":");

	strncpy(stats[L3_RULE_BASE_INDEX + policy_count].queue_name, token,
		ODP_QUEUE_NAME_LEN - 1);
	appl_args->l3_rule_count++;
	free(l3_rule_str);
	return 0;
}

static int parse_l2_rule_policy(appl_args_t *appl_args, char *argv[],
				char *optarg)
{
	int policy_count;
	char *token;
	uint8_t	l2_prio;
	size_t len;
	global_statistics *stats;
	char *l2_rule_str;

	policy_count = appl_args->l2_rule_count;
	stats = appl_args->stats;

	/* last array index is needed for default queue */
	if (policy_count >= MAX_L2_RULE_COUNT - 1) {
		EXAMPLE_ERR("Maximum allowed PMR reached\n");
		return -1;
	}

	len = strlen(optarg);
	len++;
	l2_rule_str = malloc(len);
	strcpy(l2_rule_str, optarg);

	/* L2 Priority Value */
	token = strtok(l2_rule_str, ":");
	strncpy(stats[L2_RULE_BASE_INDEX + policy_count].value, token,
		DISPLAY_STRING_LEN - 1);
	l2_prio = atoi(token);
	if (l2_prio > 7) {
		EXAMPLE_ERR("L2 Prio is out of range: Must be between 0-7\n");
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	stats[L2_RULE_BASE_INDEX + policy_count].l2_rule.val = l2_prio;

	/* Queue Name */
	token = strtok(NULL, ":");

	strncpy(stats[L2_RULE_BASE_INDEX + policy_count].queue_name, token,
		ODP_QUEUE_NAME_LEN - 1);
	appl_args->l2_rule_count++;
	free(l2_rule_str);
	return 0;
}

static int parse_pmr_policy(appl_args_t *appl_args, char *argv[], char *optarg)
{
	int policy_count;
	char *token;
	size_t len;
	odp_pmr_term_e term;
	global_statistics *stats;
	char *pmr_str;
	uint32_t offset;

	policy_count = appl_args->policy_count;
	stats = appl_args->stats;

	/* last array index is needed for default queue */
	if (policy_count >= MAX_PMR_COUNT - 1) {
		EXAMPLE_ERR("Maximum allowed PMR reached\n");
		return -1;
	}

	len = strlen(optarg);
	len++;
	pmr_str = malloc(len);
	strcpy(pmr_str, optarg);

	/* PMR TERM */
	token = strtok(pmr_str, ":");
	if (convert_str_to_pmr_enum(token, &term, &offset)) {
		EXAMPLE_ERR("Invalid ODP_PMR_TERM string\n");
		exit(EXIT_FAILURE);
	}
	stats[policy_count].rule.term = term;

	/* PMR value */
	switch (term)	{
	case ODP_PMR_SIP_ADDR:
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].value, token,
			DISPLAY_STRING_LEN - 1);
		parse_ipv4_addr(token, &stats[policy_count].rule.val);
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].mask, token,
			DISPLAY_STRING_LEN - 1);
		parse_mask(token, &stats[policy_count].rule.mask);
		stats[policy_count].rule.val_sz = 4;
		stats[policy_count].rule.offset = 0;
	break;
	case ODP_PMR_CUSTOM_FRAME:
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].value, token,
			DISPLAY_STRING_LEN - 1);
		parse_value(token, &stats[policy_count].rule.val,
			    &stats[policy_count].rule.val_sz);
		token = strtok(NULL, ":");
		strncpy(stats[policy_count].mask, token,
			DISPLAY_STRING_LEN - 1);
		parse_mask(token, &stats[policy_count].rule.mask);
		stats[policy_count].rule.offset = offset;
	break;
	default:
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}

	/* Queue Name */
	token = strtok(NULL, ":");

	strncpy(stats[policy_count].queue_name, token, ODP_QUEUE_NAME_LEN - 1);
	appl_args->policy_count++;
	free(pmr_str);
	return 0;
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
	size_t len;
	int i;
	int interface = 0;
	int pmr_policy = 0, l2_rules = 0, l3_rules = 0;

	static struct option longopts[] = {
		{"count", required_argument, NULL, 'c'},
		{"interface", required_argument, NULL, 'i'},	/* return 'i' */
		{"policy", required_argument, NULL, 'p'},	/* return 'p' */
		{"l2_policy", required_argument, NULL, 'l'},	/* return 'l' */
		{"l3_policy", required_argument, NULL, 'q'},	/* return 'q' */
		{"l3_policy_precedence", required_argument, NULL, 'a'},
								/* return 'a' */
		{"mode", required_argument, NULL, 'm'},		/* return 'm' */
		{"time", required_argument, NULL, 't'},		/* return 't' */
		{"help", no_argument, NULL, 'h'},		/* return 'h' */
		{NULL, 0, NULL, 0}
	};


	while (1) {
		opt = getopt_long(argc, argv, "+c:t:i:p:m:t:l:q:a:h",
				longopts, &long_index);

		if (opt == -1)
			break;	/* No more options */

		switch (opt) {
		case 'c':
			appl_args->cpu_count = atoi(optarg);
			break;
		case 'p':
			if (0 > parse_pmr_policy(appl_args, argv, optarg))
				continue;
			pmr_policy = 1;
			break;
		case 'l':
			if (0 > parse_l2_rule_policy(appl_args, argv, optarg))
				continue;
			l2_rules = 1;
			break;
		case 'q':
			if (0 > parse_l3_rule_policy(appl_args, argv, optarg))
				continue;
			l3_rules = 1;
			break;
		case 't':
			appl_args->time = atoi(optarg);
			break;
		case 'a':
			appl_args->l3_precedence = atoi(optarg);
			break;
		case 'i':
			len = strlen(optarg);
			if (len == 0) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}
			len += 1;	/* add room for '\0' */

			appl_args->if_name = malloc(len);
			if (appl_args->if_name == NULL) {
				usage(argv[0]);
				exit(EXIT_FAILURE);
			}

			strcpy(appl_args->if_name, optarg);
			interface = 1;
			break;

		case 'h':
			usage(argv[0]);
			exit(EXIT_SUCCESS);
			break;
		case 'm':
			i = atoi(optarg);
			if (i == 0)
				appl_args->appl_mode = APPL_MODE_DROP;
			else
				appl_args->appl_mode = APPL_MODE_REPLY;
			break;

		default:
			break;
		}
	}

	if (!interface || (!pmr_policy && !l2_rules && !l3_rules)) {
		usage(argv[0]);
		exit(EXIT_FAILURE);
	}
	if (appl_args->if_name == NULL) {
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
	printf("\n"
			"ODP system info\n"
			"---------------\n"
			"ODP API version: %s\n"
			"CPU model:       %s\n"
			"CPU freq (hz):   %"PRIu64"\n"
			"Cache line size: %i\n"
			"CPU count:       %i\n"
			"\n",
			odp_version_api_str(), odp_sys_cpu_model_str(),
			odp_sys_cpu_hz(), odp_sys_cache_line_size(),
			odp_cpu_count());

	printf("Running ODP appl: \"%s\"\n"
			"-----------------\n"
			"Using IF:%s      ",
			progname, appl_args->if_name);
	printf("\n\n");
	fflush(NULL);
}

/**
 * Prinf usage information
 */
static void usage(char *progname)
{
	printf("\n"
			"OpenDataPlane Classifier example.\n"
			"Usage: %s OPTIONS\n"
			"  E.g. %s -i eth1 -m 0 -p \"ODP_PMR_SIP_ADDR:10.10.10.5:FFFFFFFF:queue1\" \\\n"
			"\t\t\t-p \"ODP_PMR_SIP_ADDR:10.10.10.7:000000FF:queue2\" \\\n"
			"\t\t\t-p \"ODP_PMR_SIP_ADDR:10.5.5.10:FFFFFF00:queue3\"\n"
			"\t\t\t-l \"4:queue4\"\n"
			"\t\t\t-q \"40:queue5\"\n"
			"\t\t\t-a \"1/0\"\n"
			"\n"
			"For the above example configuration the following will be the packet distribution\n"
			"queue1\t\tPackets with source ip address 10.10.10.5\n"
			"queue2\t\tPackets with source ip address whose last 8 bits match 7\n"
			"queue3\t\tPackets with source ip address in the subnet 10.5.5.0\n"
			"queue4\t\tPackets with VLAN Priority\n"
			"queue5\t\tPackets with QoS value 40\n"
			"\n"
			"Mandatory OPTIONS:\n"
			"  -i, --interface Eth interface\n"
			"  -p, --policy [<odp_pmr_term_e>|<offset>]:<value>:<mask bits>:<queue name>\n"
			"\n"
			"<odp_pmr_term_e>	Packet Matching Rule defined with odp_pmr_term_e "
			"for the policy\n"
			"<offset>		Absolute offset in bytes from frame start to define a "
			"ODP_PMR_CUSTOM_FRAME Packet Matching Rule for the policy\n"
			"\n"
			"<value>		PMR value to be matched.\n"
			"\n"
			"<mask  bits>		PMR mask bits to be applied on the PMR term value\n"
			"<Queue Name>		Name of target queue\n"
			"\n"
			"  -l, --l2_policy <VLAN Priority Value>:<queue name>\n"
			"\n"
			"<VLAN Priority Value>	L2 VLAN priority value\n"
			"<Queue Name>		Name of target queue\n"
			"\n"
			"  -q, --l3_policy <L3 QoS Value>:<queue name>\n"
			"\n"
			"<L3 QoS Value>		L3 QoS value\n"
			"<Queue Name>		Name of target queue\n"
			"\n"
			"Optional OPTIONS\n"
			"  -c, --count <number> CPU count.\n"
			"                       default: CPU core count.\n"
			"\n"
			"  -m, --mode		0: Packet Drop mode. Received packets will be dropped\n"
			"			!0: Packet ICMP mode. Received packets will be sent back\n"
			"                       default: Packet Drop mode\n"
			"\n"
			" -t, --timeout		!0: Time for which the classifier will be run in seconds\n"
			"			0: Runs in infinite loop\n"
			"			default: Runs in infinite loop\n"
			"\n"
			" -a, --l3_policy_precedence	!0: L3 policy rule will take precedence over\n"
			"				L2 Policy rules else L2 policy take precendece\n"
			"			default: 0\n"
			"\n"
			"  -h, --help		Display help and exit.\n"
			"\n", NO_PATH(progname), NO_PATH(progname)
	      );
}
