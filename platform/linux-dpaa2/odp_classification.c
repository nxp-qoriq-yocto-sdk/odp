/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

#include <odp/classification.h>
#include <odp/align.h>
#include <odp/queue.h>
#include <odp/debug.h>
#include <odp_internal.h>
#include <odp_debug_internal.h>
#include <odp_packet_internal.h>
#include <odp/packet_io.h>
#include <odp/byteorder.h>
#include <odp_packet_io_internal.h>
#include <odp_classification_datamodel.h>
#include <odp_classification_internal.h>
#include <odp_pool_internal.h>
#include <nadk_dev_priv.h>
#include <nadk_eth_priv.h>
#include <nadk_conc_priv.h>
#include <nadk_io_portal_priv.h>
#include <nadk_queue.h>
#include <odp/shared_memory.h>
#include <odp/helper/eth.h>
#include <string.h>
#include <odp/spinlock.h>
#include <odp/hints.h>
#include <fsl_dpcon.h>
#include <fsl_dpni.h>
#include <fsl_dpkg.h>
#include <fsl_mc_sys.h>

#define CLS_LOCK(a)      odp_spinlock_lock(a)
#define CLS_UNLOCK(a)    odp_spinlock_unlock(a)
#define CLS_LOCK_INIT(a)	odp_spinlock_init(a)

static cos_tbl_t	*cos_tbl;
static pmr_tbl_t	*pmr_tbl;
static pmr_set_tbl_t	*pmr_set_tbl;

/*
 * Global index to define the next free location in pmr_info where extract type
 * value cab be added.
 */
uint32_t pmr_index;
/*
 * Global index to define maximum length of key extracted by the underlying
 * layer. It will be addeed with the length to the pmr type i.e. if pmr type
 * is ODP_PMR_UDP_DPORT then this will added with 2 bytes(size of UDP
 * destination port).
 *
 */
#define ODP_L2_PRIO_KEY_LEN	2
#define ODP_L3_DSCP_KEY_LEN	1
static uint32_t key_cfg_len = ODP_L2_PRIO_KEY_LEN + ODP_L3_DSCP_KEY_LEN;
/*
 * Global debug flag to enable/disable printing of rules
 */
static uint32_t print_rules;
/*
 * It is a local database which is used to configure key extract paramters
 * at underlying layer. Maximum 8 paramter can be updated.
 */
pmr_info_t pmr_info[DPKG_MAX_NUM_OF_EXTRACTS] = {
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF},
						{0, 0, 0xFFFF}, {0, 0, 0xFFFF}
						};

/*Global list of rules configured at hardware*/
static struct rule pmr_rule_list[ODP_CONFIG_PKTIO_ENTRIES];
static struct rule l2_rule_list[ODP_CONFIG_PKTIO_ENTRIES];
static struct rule l3_rule_list[ODP_CONFIG_PKTIO_ENTRIES];

cos_t *get_cos_entry_internal(odp_cos_t cos_id)
{
	return &(cos_tbl->cos_entry[_odp_typeval(cos_id)]);
}

pmr_set_t *get_pmr_set_entry_internal(odp_pmr_set_t pmr_set_id)
{
	return &(pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)]);
}

pmr_t *get_pmr_entry_internal(odp_pmr_t pmr_id)
{
	return &(pmr_tbl->pmr[_odp_typeval(pmr_id)]);
}

static void odp_configure_l2_prio_rule(pktio_entry_t *pktio ODP_UNUSED,
				       pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;
	uint8_t	size = 2;

	for (i = 0; pmr_info[i].is_valid; i++)
		offset = offset + pmr_info[i].size;

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy((void *)stream, (void *)(pmr->s.term_value[0].val), size);
	memcpy((void *)mask, (void *)(pmr->s.term_value[0].mask), size);
	pmr->s.rule.key_size = key_cfg_len;
}

static void odp_configure_l3_prio_rule(pktio_entry_t *pktio ODP_UNUSED,
				       pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;
	uint8_t	size = 1;

	for (i = 0; pmr_info[i].is_valid; i++)
		offset = offset + pmr_info[i].size;
	offset = offset + 2;

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy(stream, (void *)(pmr->s.term_value[0].val), size);
	memcpy(mask, (void *)(pmr->s.term_value[0].mask), size);
	pmr->s.rule.key_size = key_cfg_len;
}

static void odp_insert_exact_match_rule(odp_pktio_t pktio,
					struct exact_match_rule *fs_rule)
{
	pktio_entry_t *pktio_entry;
	uint64_t idx = ((uint64_t)pktio - 1);

	pktio_entry = get_pktio_entry(pktio);
	if (!pktio_entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return;
	}

	switch (fs_rule->type) {
	case EXACT_MATCH_RULE_PMR:
		/*Insert at last into rule_list1*/
		TAILQ_INSERT_TAIL(&pmr_rule_list[idx], fs_rule, next);
		break;
	case EXACT_MATCH_RULE_L2:
		/*Insert at last into rule_list2*/
		TAILQ_INSERT_TAIL(&l2_rule_list[idx], fs_rule, next);
		break;
	case EXACT_MATCH_RULE_L3:
		/*Insert at last into rule_list3*/
		TAILQ_INSERT_TAIL(&l3_rule_list[idx], fs_rule, next);
		break;
	default:
		ODP_ERR("Invalid exact rule type = %d\n", fs_rule->type);
		break;
	}
}

static void print_all_rule_list(uint64_t pktio_idx)
{
	uint8_t *temp;
	struct exact_match_rule *temp_rule;
	uint32_t i = 0;

	/*Add all the Classification rules at underlying platform*/
	printf("Packet Matching rules information:\n");
	printf("======================Start PMR======================\n");
	TAILQ_FOREACH(temp_rule, &pmr_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End PMR======================\n");
	i = 0;
	printf("L2 Matching rules information:\n");
	printf("======================Start L2======================\n");
	TAILQ_FOREACH(temp_rule, &l2_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End L2======================\n");
	i = 0;
	printf("L3 Matching rules information:\n");
	printf("======================Start L3======================\n");
	TAILQ_FOREACH(temp_rule, &l3_rule_list[pktio_idx], next) {
		temp_rule->rule->key_size = key_cfg_len;
		temp = (uint8_t *)temp_rule->rule->key_iova;
		printf("key Size = %d\n", temp_rule->rule->key_size);
		printf("Traffic Class ID = %d\n", temp_rule->tc_id);
		printf("Flow ID = %d\n", temp_rule->flow_id);
		printf("PMR:\n");
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\nMask:\n");
		i = 0;
		temp = (uint8_t *)temp_rule->rule->mask_iova;
		while (i < key_cfg_len) {
			printf("%0x\t", *temp);
			temp++;
			i++;
		}
		printf("\n");
	}
	printf("======================End L3======================\n");
}

/* Initialize different tables used for classification i.e. PMR table,
 * PMR set table, CoS table etc
 */
int odp_classification_init_global(void)
{
	odp_shm_t cos_shm;
	odp_shm_t pmr_shm;
	odp_shm_t pmr_set_shm;
	int i;

	/*Allocating CoS table*/
	cos_shm = odp_shm_reserve("shm_odp_cos_tbl",
			sizeof(cos_tbl_t),
			sizeof(cos_t), 0);

	if (cos_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_cos_tbl");
		goto error;
	}

	cos_tbl = odp_shm_addr(cos_shm);
	if (cos_tbl == NULL)
		goto error_cos;

	memset(cos_tbl, 0, sizeof(cos_tbl_t));
	for (i = 0; i < ODP_COS_MAX_ENTRY; i++) {
		/* init locks */
		cos_t *cos =
			get_cos_entry_internal(_odp_cast_scalar(odp_cos_t, i));
		CLS_LOCK_INIT(&cos->s.lock);
	}

	/*Allocating PMR table*/
	pmr_shm = odp_shm_reserve("shm_odp_pmr_tbl",
			sizeof(pmr_tbl_t),
			sizeof(pmr_t), 0);

	if (pmr_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_pmr_tbl");
		goto error_cos;
	}

	pmr_tbl = odp_shm_addr(pmr_shm);
	if (pmr_tbl == NULL)
		goto error_pmr;

	memset(pmr_tbl, 0, sizeof(pmr_tbl_t));
	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		/* init locks */
		pmr_t *pmr =
			get_pmr_entry_internal(_odp_cast_scalar(odp_pmr_t, i));
		CLS_LOCK_INIT(&pmr->s.lock);
	}

	/*Allocating PMR Set table*/
	pmr_set_shm = odp_shm_reserve("shm_odp_pmr_set_tbl",
			sizeof(pmr_set_tbl_t), 0, 0);

	if (pmr_set_shm == ODP_SHM_INVALID) {
		ODP_ERR("shm allocation failed for shm_odp_pmr_set_tbl");
		goto error_pmr;
	}

	pmr_set_tbl = odp_shm_addr(pmr_set_shm);
	if (pmr_set_tbl == NULL)
		goto error_pmrset;

	memset(pmr_set_tbl, 0, sizeof(pmr_set_tbl_t));
	for (i = 0; i < ODP_PMRSET_MAX_ENTRY; i++) {
		/* init locks */
		pmr_set_t *pmr =
			get_pmr_set_entry_internal
			(_odp_cast_scalar(odp_pmr_set_t, i));
		CLS_LOCK_INIT(&pmr->s.lock);
	}

	return 0;

error_pmrset:
	odp_shm_free(pmr_set_shm);
error_pmr:
	odp_shm_free(pmr_shm);
error_cos:
	odp_shm_free(cos_shm);
error:
	return -1;
}

int odp_classification_term_global(void)
{
	int ret = 0;
	int rc = 0;

	ret = odp_shm_free(odp_shm_lookup("shm_odp_cos_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_cos_tbl");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup("shm_odp_pmr_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_pmr_tbl");
		rc = -1;
	}

	ret = odp_shm_free(odp_shm_lookup("shm_odp_pmr_set_tbl"));
	if (ret < 0) {
		ODP_ERR("shm free failed for shm_odp_pmr_tbl");
		rc = -1;
	}

	return rc;
}

odp_cos_t odp_cos_create(const char *name)
{
	int i;

	for (i = 0; i < ODP_COS_MAX_ENTRY; i++) {
		CLS_LOCK(&cos_tbl->cos_entry[i].s.lock);
		if (0 == cos_tbl->cos_entry[i].s.used) {
			memset(&(cos_tbl->cos_entry[i].s), 0,
						sizeof(struct cos_s));
			strncpy(cos_tbl->cos_entry[i].s.name, name,
				ODP_COS_NAME_LEN - 1);
			cos_tbl->cos_entry[i].s.name[ODP_COS_NAME_LEN - 1] = 0;
			cos_tbl->cos_entry[i].s.next_pmr = NULL;
			cos_tbl->cos_entry[i].s.next_cos = NULL;
			cos_tbl->cos_entry[i].s.queue = NULL;
			cos_tbl->cos_entry[i].s.used = 1;
			CLS_UNLOCK(&cos_tbl->cos_entry[i].s.lock);
			return _odp_cast_scalar(odp_cos_t, i);
		}
		CLS_UNLOCK(&cos_tbl->cos_entry[i].s.lock);
	}
	ODP_ERR("ODP_COS_MAX_ENTRY reached");
	return ODP_COS_INVALID;
}

/*
 * It Allocates a block from pre-allocated PMR set table.
 */
odp_pmr_set_t alloc_pmr_set(pmr_t **pmr)
{
	int i;

	for (i = 0; i < ODP_PMRSET_MAX_ENTRY; i++) {
		CLS_LOCK(&pmr_set_tbl->pmr_set[i].s.lock);
		if (0 == pmr_set_tbl->pmr_set[i].s.valid) {
			pmr_set_tbl->pmr_set[i].s.valid = 1;
			pmr_set_tbl->pmr_set[i].s.num_pmr = 0;
			*pmr = (pmr_t *)&pmr_set_tbl->pmr_set[i];
			/* return as locked */
			return _odp_cast_scalar(odp_pmr_set_t, i);
		}
		CLS_UNLOCK(&pmr_set_tbl->pmr_set[i].s.lock);
	}
	ODP_ERR("ODP_PMRSET_MAX_ENTRY reached");
	return ODP_PMR_SET_INVAL;
}

/*
 * It Allocates a block from pre-allocated PMR table.
 */
odp_pmr_t alloc_pmr(pmr_t **pmr)
{
	int i;

	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++) {
		CLS_LOCK(&pmr_tbl->pmr[i].s.lock);
		if (0 == pmr_tbl->pmr[i].s.valid) {
			pmr_tbl->pmr[i].s.valid = 1;
			*pmr = &pmr_tbl->pmr[i];
			/* return as locked */
			return _odp_cast_scalar(odp_pmr_t, i);
		}
		CLS_UNLOCK(&pmr_tbl->pmr[i].s.lock);
	}
	ODP_ERR("ODP_PMR_MAX_ENTRY reached");
	return ODP_PMR_INVAL;
}

cos_t *get_cos_entry(odp_cos_t cos_id)
{
	if (_odp_typeval(cos_id) >= ODP_COS_MAX_ENTRY ||
	    cos_id == ODP_COS_INVALID)
		return NULL;
	if (cos_tbl->cos_entry[_odp_typeval(cos_id)].s.used == 0)
		return NULL;
	return &(cos_tbl->cos_entry[_odp_typeval(cos_id)]);
}


pmr_set_t *get_pmr_set_entry(odp_pmr_set_t pmr_set_id)
{
	if (_odp_typeval(pmr_set_id) >= ODP_PMRSET_MAX_ENTRY ||
	    pmr_set_id == ODP_PMR_SET_INVAL)
		return NULL;
	if (pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)].s.valid == 0)
		return NULL;
	return &(pmr_set_tbl->pmr_set[_odp_typeval(pmr_set_id)]);
}

pmr_t *get_pmr_entry(odp_pmr_t pmr_id)
{
	if (_odp_typeval(pmr_id) >= ODP_PMR_MAX_ENTRY ||
	    pmr_id == ODP_PMR_INVAL)
		return NULL;
	if (pmr_tbl->pmr[_odp_typeval(pmr_id)].s.valid == 0)
		return NULL;
	return &(pmr_tbl->pmr[_odp_typeval(pmr_id)]);
}

int odp_cos_destroy(odp_cos_t cos_id)
{
	cos_t *cos = get_cos_entry(cos_id);
	if (NULL == cos) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	cos->s.used = 0;
	return 0;
}

int odp_cos_queue_set(odp_cos_t cos_id, odp_queue_t queue_id)
{
	cos_t *cos = get_cos_entry(cos_id);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}
	/* Locking is not required as intermittent stale
	data during CoS modification is acceptable*/
	cos->s.queue = queue_to_qentry(queue_id);
	return 0;
}

int odp_cos_drop_set(odp_cos_t cos_id ODP_UNUSED, odp_drop_e drop_policy ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static int32_t odp_offload_rules(odp_pktio_t pktio)
{
	pktio_entry_t *entry;
	struct exact_match_rule	*fs_rule;
	int32_t	retcode;
	uint32_t index = (uint64_t)pktio - 1;
	struct nadk_dev		*dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio);
	dev = entry->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;

	/*Add all the Classification rules at underlying platform*/
	TAILQ_FOREACH(fs_rule, &pmr_rule_list[index], next) {
		fs_rule->rule->key_size = key_cfg_len;
		retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW, dev_priv->token,
					    fs_rule->tc_id, fs_rule->rule,
						fs_rule->flow_id);
		if (retcode < 0)
			goto pmr_add_failure;
	}
	if (entry->s.cls.l3_precedence) {
		TAILQ_FOREACH(fs_rule, &l3_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id,
					fs_rule->rule, fs_rule->flow_id);
			if (retcode < 0)
				goto l3_rule_add_failure;
		}
		TAILQ_FOREACH(fs_rule, &l2_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id,
					fs_rule->rule, fs_rule->flow_id);
			if (retcode < 0)
				goto l2_rule_add_failure;
		}
	} else {
		TAILQ_FOREACH(fs_rule, &l2_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id,
					fs_rule->rule, fs_rule->flow_id);
			if (retcode < 0)
				goto l2_rule_add_failure;
		}
		TAILQ_FOREACH(fs_rule, &l3_rule_list[index], next) {
			fs_rule->rule->key_size = key_cfg_len;
			retcode = dpni_add_fs_entry(dpni, CMD_PRI_LOW,
						    dev_priv->token,
							fs_rule->tc_id,
					fs_rule->rule, fs_rule->flow_id);
			if (retcode < 0)
				goto l3_rule_add_failure;
		}
	}
	return 0;

pmr_add_failure:
		ODP_DBG("Error in adding PMR to underlying hardware\n");
		return retcode;
l2_rule_add_failure:
		ODP_DBG("Error in adding l2 rule to underlying hardware\n");
		return retcode;
l3_rule_add_failure:
		ODP_DBG("Error in adding l3 rule to underlying hardware\n");
		return retcode;
}

int odp_pktio_default_cos_set(odp_pktio_t pktio_in, odp_cos_t default_cos)
{
	int32_t retcode;
	pktio_entry_t *entry;
	queue_entry_t *queue;
	cos_t *cos;
	struct nadk_vq_param cfg;
	struct nadk_dev *dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	cos = get_cos_entry(default_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	/*Connect a default H/W FQ of given pktio*/
	dev = entry->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*Packet will be forwarded to default flow ID 0.*/
	tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
	tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type first and fill its required configuration*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/* Configure queue handle into nadk device vq so that ODP can retrieve
	 * queue handle from the nadk device VQ.
	 */
	nadk_dev_set_vq_handle(dev->rx_vq[ODP_CLS_DEFAULT_FLOW],
						(uint64_t)queue->s.handle);

	/*Update input and output device in ODP queue structure*/
	queue->s.pktin = pktio_in;
	queue->s.pktout = pktio_in;

	/*Configure the queue propeties at H/W with configuration updated above*/
	retcode = nadk_eth_setup_rx_vq(dev, ODP_CLS_DEFAULT_FLOW, &cfg);
	if (retcode < 0) {
		ODP_ERR("Error in setup Rx flow");
		return -1;
	}
	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[ODP_CLS_DEFAULT_FLOW];

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	/*Add all the Classification rules at underlying platform*/
	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		return -1;
	}

	cos->s.tc_id = ODP_CLS_DEFAULT_TC; /*TODO Need to update with variable value*/
	entry->s.cls.default_cos = cos;
	return 0;
}

int odp_pktio_error_cos_set(odp_pktio_t pktio_in, odp_cos_t error_cos)
{
	pktio_entry_t *entry;
	cos_t *cos;

	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	cos = get_cos_entry(error_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}
	/*TODO: Currently This API is not supported. Placing below code as a
		placeholder
	*/
#if 0
	int dpni_set_rx_err_queue(struct fsl_mc_io	*mc_io,
			  uint16_t			token,
			  const struct dpni_queue_cfg	*cfg);

	int dpni_get_rx_err_queue(struct fsl_mc_io	*mc_io,
			  uint16_t			token,
			  struct dpni_queue_attr	*attr);
#endif
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_skip_set(odp_pktio_t pktio_in ODP_UNUSED, uint32_t offset ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

int odp_pktio_headroom_set(odp_pktio_t pktio_in ODP_UNUSED, uint32_t headroom ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

static void odp_delete_l2_rule_list(odp_pktio_t pktio)
{
	struct exact_match_rule *temp_rule;
	uint32_t index = (uint64_t)pktio - 1;

	TAILQ_FOREACH(temp_rule, &l2_rule_list[index], next) {
		nadk_data_free((void *)temp_rule->rule->key_iova);
		nadk_data_free((void *)temp_rule->rule->mask_iova);
	}
}

static void odp_delete_l3_rule_list(odp_pktio_t pktio)
{
	struct exact_match_rule *temp_rule;
	uint32_t index = (uint64_t)pktio - 1;

	TAILQ_FOREACH(temp_rule, &l3_rule_list[index], next) {
		nadk_data_free((void *)temp_rule->rule->key_iova);
		nadk_data_free((void *)temp_rule->rule->mask_iova);
	}
}

int odp_cos_with_l2_priority(odp_pktio_t pktio_in, uint8_t num_qos,
			     uint8_t qos_table[], odp_cos_t cos_table[])
{
	uint16_t qos_mask = odp_cpu_to_be_16(0xE000);
	uint8_t *qos_value;
	uint32_t i, j;
	cos_t *cos;
	pmr_t *pmr[8];
	odp_pmr_t pmr_id[8];
	pktio_entry_t *entry;
	queue_entry_t *queue[8];
	void *params[2];
	int32_t retcode;
	struct nadk_vq_param	cfg[8];
	struct nadk_dev		*dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio_in);
	if (!entry) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	dev = entry->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = entry->s.cls.flow_id;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*if default CoS is created then:
		packet will be forwarded to default flow ID 0.
	Else packet will be dropped as a default action
	*/
	if (entry->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	}

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      ODP_CLS_DEFAULT_TC, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					ODP_CLS_DEFAULT_TC);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Now we are done with device information. Lets get some reuqired number
	of PMRs to store the rules*/
	for (i = 0; i < num_qos; i++) {
		pmr_id[i] = alloc_pmr(&pmr[i]);
		/*if alloc_pmr() is successful it returns with lock acquired*/
		if (pmr_id[i] == ODP_PMR_INVAL)
			return -1;

		qos_value = (uint8_t *)nadk_calloc(NULL, 1,
						sizeof(uint16_t), 0);
		if (!qos_value)
			goto unlock_pmr_and_clean;

		qos_value[0] = (qos_table[i] << 5);
		pmr[i]->s.num_pmr = 1;
		pmr[i]->s.term_value[0].val = (uint64_t)qos_value;
		pmr[i]->s.term_value[0].mask = (uint64_t)&qos_mask;

		/*Allocate memory for matching rule configuration at H/W.*/
		params[0] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[0]) {
			ODP_ERR("Memory unavaialble");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		/*Allocate memory for mask rule configuration at H/W.*/
		params[1] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[1]) {
			ODP_ERR("Memory unavaialble");
			nadk_free(qos_value);
			nadk_data_free((void *)params[0]);
			goto unlock_pmr_and_clean;
		}
		/*Updating ODP database for PMR*/
		pmr[i]->s.rule.key_iova = (uint64_t)params[0];
		pmr[i]->s.rule.mask_iova = (uint64_t)params[1];
		pmr[i]->s.rule.key_size = 0;

		/*Collect CoS and associated queue configuration associated
		with pktio*/
		cos = get_cos_entry(cos_table[i]);
		if (cos) {
			/*Check for the Queue Type*/
			queue[i] = cos->s.queue;
			retcode = fill_queue_configuration(queue[i], &cfg[i]);
			if (retcode < 0) {
				nadk_free(qos_value);
				goto unlock_pmr_and_clean;
			}

			/*Update ODP database according to the H/W resource
			values*/
			queue[i]->s.priv = dev->rx_vq[++flow_id];
			/*TODO Need to update with variable value*/
			cos->s.tc_id = ODP_CLS_DEFAULT_TC;
			nadk_dev_set_vq_handle(dev->rx_vq[flow_id],
					       (uint64_t)queue[i]->s.handle);
			/*Update input and output nadk device in ODP queue*/
			queue[i]->s.pktin = pktio_in;
			queue[i]->s.pktout = pktio_in;

			if (flow_id < dev->num_rx_vqueues) {
				retcode = nadk_eth_setup_rx_vq(dev, flow_id,
							       &cfg[i]);
				if (retcode < 0) {
					ODP_ERR("Error in setup Rx flow\n");
					nadk_free(qos_value);
					goto unlock_pmr_and_clean;
				}
			} else {
				ODP_ERR("flow_id out of range\n");
				nadk_free(qos_value);
				goto unlock_pmr_and_clean;
			}
		} else {
			ODP_ERR("NULL CoS entry found\n");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		odp_configure_l2_prio_rule(entry, pmr[i]);
		/*Update rule list*/
		fs_rule = nadk_calloc(NULL, 1, sizeof(struct exact_match_rule),
				      0);
		if (!fs_rule) {
			ODP_ERR(" NO memory for DEVICE.\n");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		fs_rule->tc_id = ODP_CLS_DEFAULT_TC;
		fs_rule->flow_id = flow_id;
		fs_rule->type = EXACT_MATCH_RULE_L2;
		fs_rule->rule = &pmr[i]->s.rule;

		/*First validate the correct order of rule in rule list and then
		insert the rule in list.*/
		odp_insert_exact_match_rule(pktio_in, fs_rule);

		/*Free allocated memory*/
		nadk_free(qos_value);

		/*Unlock PMR entry*/
		CLS_UNLOCK(&pmr[i]->s.lock);
	}

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry: Error Code = %d\n", retcode);
		goto clean_allocated_resources;
	}
	entry->s.cls.flow_id = flow_id;
	return 0;

unlock_pmr_and_clean:
	/*Unlock PMR entry*/
	CLS_UNLOCK(&pmr[i]->s.lock);

clean_allocated_resources:
	for (j = 0; j < i; j++) {
		nadk_data_free((void *)pmr[i]->s.rule.key_iova);
		nadk_data_free((void *)pmr[i]->s.rule.mask_iova);
	}

	/*Free allocated memory for L2 Shadow database*/
	odp_delete_l2_rule_list(pktio_in);
	return -1;
}

int odp_cos_with_l3_qos(odp_pktio_t pktio_in,
			uint32_t num_qos,
			uint8_t qos_table[],
			odp_cos_t cos_table[],
			odp_bool_t l3_preference)
{
	uint8_t qos_mask = 0xFC;
	uint8_t *qos_value;
	uint32_t i, j;
	cos_t *cos;
	pmr_t *pmr[8];
	odp_pmr_t pmr_id[8];
	pktio_entry_t *entry;
	queue_entry_t *queue[8];
	void *params[2];
	int32_t retcode;
	struct nadk_vq_param	cfg[8];
	struct nadk_dev		*dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	/*Get pktio entry where rules are to be applied*/
	entry = get_pktio_entry(pktio_in);
	if (entry == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}
	entry->s.cls.l3_precedence = l3_preference;
	dev = entry->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = entry->s.cls.flow_id;
	tc_cfg = &entry->s.cls.tc_cfg;

	/*Configure distribution parameters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*if default CoS is created then:
		packet will be forwarded to default flow ID 0.
	Else packet will be dropped as a default action
	*/
	if (entry->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	}

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(entry);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
				      ODP_CLS_DEFAULT_TC, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					ODP_CLS_DEFAULT_TC);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Now we are done with device information. Lets get some reuqired number
	of PMRs to store the rules*/
	for (i = 0; i < num_qos; i++) {
		pmr_id[i] = alloc_pmr(&pmr[i]);
		/*if alloc_pmr() is successful it returns with lock acquired*/
		if (pmr_id[i] == ODP_PMR_INVAL)
			return -1;

		qos_value = (uint8_t *)nadk_calloc(NULL, 1, sizeof(uint8_t), 0);
		if (!qos_value) {
			ODP_ERR("Memory unavaialble");
			goto unlock_pmr_and_clean;
		}
		*qos_value = qos_table[i];
		pmr[i]->s.num_pmr = 1;
		pmr[i]->s.term_value[0].val = (uint64_t)qos_value;
		pmr[i]->s.term_value[0].mask = (uint64_t)&qos_mask;

		/*Allocate memory for matching rule configuration at H/W.*/
		params[0] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[0]) {
			ODP_ERR("Memory unavaialble");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}
		/*Allocate memory for mask rule configuration at H/W.*/
		params[1] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
		if (!params[1]) {
			ODP_ERR("Memory unavaialble");
			nadk_free(qos_value);
			nadk_data_free((void *)params[0]);
			goto unlock_pmr_and_clean;
		}
		/*Updating ODP database for PMR*/
		pmr[i]->s.rule.key_iova = (uint64_t)params[0];
		pmr[i]->s.rule.mask_iova = (uint64_t)params[1];
		pmr[i]->s.rule.key_size = 0;

		/*Collect CoS and associated queue configuration associated
		with pktio*/
		cos = get_cos_entry(cos_table[i]);
		if (cos) {
			/*Check for the Queue Type*/
			queue[i] = cos->s.queue;
			retcode = fill_queue_configuration(queue[i], &cfg[i]);
			if (retcode < 0) {
				nadk_free(qos_value);
				goto unlock_pmr_and_clean;
			}

			/*Update ODP database according to the H/W resource
			values*/
			queue[i]->s.priv = dev->rx_vq[++flow_id];
			/*TODO Need to update with variable value*/
			cos->s.tc_id = ODP_CLS_DEFAULT_TC;
			nadk_dev_set_vq_handle(dev->rx_vq[flow_id],
					       (uint64_t)queue[i]->s.handle);
			/*Update input and output nadk device in ODP queue*/
			queue[i]->s.pktin = pktio_in;
			queue[i]->s.pktout = pktio_in;

			if (flow_id < dev->num_rx_vqueues) {
				retcode = nadk_eth_setup_rx_vq(dev, flow_id,
							       &cfg[i]);
				if (retcode < 0) {
					nadk_free(qos_value);
					ODP_ERR("Error in setup Rx flow");
					goto unlock_pmr_and_clean;
				}
			} else {
				ODP_ERR("Number of flows reached at maximum limit\n");
				nadk_free(qos_value);
				goto unlock_pmr_and_clean;
			}
		} else {
			ODP_ERR("NULL CoS entry found\n");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		odp_configure_l3_prio_rule(entry, pmr[i]);
		/*Update rule list*/
		fs_rule = nadk_calloc(NULL, 1, sizeof(struct exact_match_rule),
				      0);
		if (!fs_rule) {
			ODP_ERR(" NO memory for DEVICE.\n");
			nadk_free(qos_value);
			goto unlock_pmr_and_clean;
		}

		fs_rule->tc_id = ODP_CLS_DEFAULT_TC;
		fs_rule->flow_id = flow_id;
		fs_rule->type = EXACT_MATCH_RULE_L3;
		fs_rule->rule = &pmr[i]->s.rule;

		/*Unlock PMR entry*/
		CLS_UNLOCK(&pmr[i]->s.lock);
		/*First validate the correct order of rule in rule list and then
		insert the rule in list.*/
		odp_insert_exact_match_rule(pktio_in, fs_rule);
	}

	if (print_rules)
		print_all_rule_list((uint64_t)pktio_in - 1);

	retcode = odp_offload_rules(pktio_in);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		goto clean_allocated_resources;
	}
	entry->s.cls.flow_id = flow_id;
	return 0;

unlock_pmr_and_clean:
	/*Unlock PMR entry*/
	CLS_UNLOCK(&pmr[i]->s.lock);

clean_allocated_resources:
	for (j = 0; j < i; j++) {
		nadk_data_free((void *)pmr[i]->s.rule.key_iova);
		nadk_data_free((void *)pmr[i]->s.rule.mask_iova);
	}
	/*Free allocated memory for L2 Shadow database*/
	odp_delete_l3_rule_list(pktio_in);
	return -1;
}

/*
 * This API is used to create a key generation sceme from pre-updated data
 * pmr_info. This profile key will be provided to underlying layer(MC)
 * so that a packet can be extracted and built a matching key for these
 * paramters only.
 */
void odp_setup_extract_key(struct dpkg_profile_cfg *kg_cfg)
{
	uint64_t i = 0;

	while (pmr_info[i].is_valid) {
		switch (pmr_info[i].type) {
		case ODP_PMR_LEN:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IPV4;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_IPV4_TOTAL_LEN;
			break;
		case ODP_PMR_ETHTYPE_0:
		case ODP_PMR_ETHTYPE_X:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_ETH;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_ETH_TYPE;
			break;
		case ODP_PMR_VLAN_ID_0:
		case ODP_PMR_VLAN_ID_X:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_VLAN;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_VLAN_VID;
			break;
		case ODP_PMR_DMAC:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_ETH;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_ETH_DA;
			break;
		case ODP_PMR_IPPROTO:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_PROTO;
			break;
		case ODP_PMR_UDP_DPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_UDP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_UDP_PORT_DST;
			break;
		case ODP_PMR_TCP_DPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_TCP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_TCP_PORT_DST;
			break;
		case ODP_PMR_UDP_SPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_UDP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_UDP_PORT_SRC;
			break;
		case ODP_PMR_TCP_SPORT:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_TCP;
			kg_cfg->extracts[i].extract.from_hdr.field =
							NH_FLD_TCP_PORT_SRC;
			break;
		case ODP_PMR_SIP_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_SRC;
			break;
		case ODP_PMR_DIP_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_DST;
			break;
		case ODP_PMR_SIP6_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_SRC;
			break;
		case ODP_PMR_DIP6_ADDR:
			kg_cfg->extracts[i].extract.from_hdr.prot =
								NET_PROT_IP;
			kg_cfg->extracts[i].extract.from_hdr.field =
								NH_FLD_IP_DST;
			break;
		default:
			ODP_ERR("Bad flow distribution option");
		}
		kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
		kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
		kg_cfg->num_extracts++;
		i++;
	}
	/*Configure for L2 priorioty*/
	kg_cfg->extracts[i].extract.from_hdr.prot = NET_PROT_VLAN;
	kg_cfg->extracts[i].extract.from_hdr.field = NH_FLD_VLAN_TCI;
	kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
	kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
	kg_cfg->num_extracts++;

	/*Configure for L3 priorioty*/
	i++;
	kg_cfg->extracts[i].extract.from_hdr.prot = NET_PROT_IP;
	kg_cfg->extracts[i].extract.from_hdr.field = NH_FLD_IP_TOS_TC;
	kg_cfg->extracts[i].type = DPKG_EXTRACT_FROM_HDR;
	kg_cfg->extracts[i].extract.from_hdr.type = DPKG_FULL_FIELD;
	kg_cfg->num_extracts++;
}

/*
 *  It will create an extract parmeter key.
 */
int odp_setup_dist(pktio_entry_t *pktio_entry)
{
	struct dpkg_profile_cfg	*key_cfg;
	uint8_t			*param;

	key_cfg = pktio_entry->s.priv;
	param = (uint8_t *)pktio_entry->s.cls.tc_cfg.key_cfg_iova;
	memset(param, 0, DIST_PARAM_IOVA_SIZE);
	memset(key_cfg, 0, DIST_PARAM_IOVA_SIZE);

	odp_setup_extract_key(key_cfg);
	/* no need for mc portal lock*/
	if (dpni_prepare_key_cfg(key_cfg, param) < 0) {
		ODP_ERR("Unable to prepare extract parameters");
		return -1;
	}
	return 0;
}

/*
 * It is a local function to convert from host order to network order
 */
void convert_param_to_network_order(void *val, void *mask, uint32_t val_sz)
{
	switch (val_sz) {
	case 2:
		*(uint16_t *)val = odp_cpu_to_be_16(*(uint16_t *)val);
		*(uint16_t *)mask = odp_cpu_to_be_16(*(uint16_t *)mask);
		break;
	case 4:
		*(uint32_t *)val = odp_cpu_to_be_32(*(uint32_t *)val);
		*(uint32_t *)mask = odp_cpu_to_be_32(*(uint32_t *)mask);
		break;
	case 8:
		*(uint64_t *)val = odp_cpu_to_be_64(*(uint64_t *)val);
		*(uint64_t *)mask = odp_cpu_to_be_64(*(uint64_t *)mask);
		break;
	case 1:
		break;
	default:
		ODP_ERR("Unsupported val_size");
		break;
	}
}

odp_pmr_t odp_pmr_create(const odp_pmr_match_t *match)
{
	uint8_t *params[2];
	uint8_t *uargs[2];
	pmr_t *pmr;
	odp_pmr_t id;

	if (match->val_sz > ODP_PMR_TERM_BYTES_MAX) {
		ODP_ERR("val_sz greater than max supported limit");
		return ODP_PMR_INVAL;
	}

	id = alloc_pmr(&pmr);
	/*if alloc_pmr() is successful it returns with lock acquired*/
	if (id == ODP_PMR_INVAL)
		return ODP_PMR_INVAL;

	pmr->s.num_pmr = 1;
	/*Allocate memory for matching rule configuration at H/W.*/
	params[0] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[0]) {
		ODP_ERR("Memory unavaialble");
		return ODP_PMR_INVAL;
	}
	/*Allocate memory for mask rule at H/W.*/
	params[1] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[1]) {
		ODP_ERR("Memory unavaialble");
		nadk_data_free((void *)params[0]);
		return ODP_PMR_INVAL;
	}
	/* Allocate memory for mathcing rule provided by user. This memory will
	   be freed once matching rule is configured at H/W.
	*/
	uargs[0] = nadk_calloc(NULL, 1, match->val_sz, ODP_CACHE_LINE_SIZE);
	if (!uargs[0]) {
		nadk_data_free((void *)params[0]);
		nadk_data_free((void *)params[1]);
		ODP_ERR("Memory unavaialble");
		return ODP_PMR_INVAL;
	}
	/* Allocate memory for masking rule provided by user. This memory will
	   be freed once matching rule is configured at H/W.
	*/
	uargs[1] = nadk_calloc(NULL, 1, match->val_sz, ODP_CACHE_LINE_SIZE);
	if (!uargs[1]) {
		ODP_ERR("Memory unavaialble");
		nadk_data_free((void *)params[0]);
		nadk_data_free((void *)params[1]);
		nadk_free((void *)uargs[0]);
		return ODP_PMR_INVAL;
	}

	/*Updating ODP database for PMR*/
	pmr->s.term_value[0].term = match->term;
	memcpy(uargs[0], match->val, match->val_sz);
	memcpy(uargs[1], match->mask, match->val_sz);
	convert_param_to_network_order(uargs[0], uargs[1], match->val_sz);
	pmr->s.term_value[0].val = (uint64_t)uargs[0];
	pmr->s.term_value[0].mask = (uint64_t)uargs[1];
	pmr->s.rule.key_iova = (uint64_t)params[0];
	pmr->s.rule.mask_iova = (uint64_t)params[1];
	pmr->s.rule.key_size = 0;
	set_pmr_info((void *)pmr);
	CLS_UNLOCK(&pmr->s.lock);
	return id;
}

int odp_pmr_destroy(odp_pmr_t pmr_id)
{
	pmr_t *pmr = get_pmr_entry(pmr_id);
	uint32_t loop, pos;

	if (pmr == NULL)
		return -1;

	pos = pmr->s.pos[0];
	loop = pos + 1;
	key_cfg_len -= pmr_info[pos].size;

	/* Update local pmr_info array for deleted PMR entry. Below loop shifts
	   all the pmr_info entry at left so that all free entries are at right.
	*/
	while (pmr_info[loop].is_valid == 1) {
		pmr_info[loop - 1].type = pmr_info[loop].type;
		pmr_info[loop - 1].size = pmr_info[loop].size;
		pmr_info[loop - 1].is_valid = pmr_info[loop].is_valid;
		loop++;
	}
	/*Invalidated all the fields for particular pmr_info entry*/
	pmr_info[loop - 1].type = 0xFFFF;
	pmr_info[loop - 1].size = 0;
	pmr_info[loop - 1].is_valid = 0;
	pmr_index = loop - 1;

	/*Free pre-allocated memory for PMR rule and mask*/
	nadk_data_free((void *)(pmr->s.rule.key_iova));
	nadk_data_free((void *)(pmr->s.rule.mask_iova));
	if (pmr->s.term_value[0].val)
		nadk_free((void *)(pmr->s.term_value[0].val));
	if (pmr->s.term_value[0].mask)
		nadk_free((void *)(pmr->s.term_value[0].mask));
	pmr->s.rule.key_size = 0;
	pmr->s.valid = 0;
	pmr->s.num_pmr = 0;
	return 0;
}

/*Update pmr_info array for created PMR and PMR set.*/
void set_pmr_info(void *rule)
{
	odp_pmr_term_e  term;		/* PMR Term */
	int32_t loop = 0;
	uint32_t i = 0;
	pmr_set_t *pmr = (pmr_set_t *)rule;

	/*Check for valid PMR*/
	if (!pmr) {
		ODP_ERR("No PMR rule found");
		return;
	}

check_next:
	for (; i < pmr->s.num_pmr; i++) {
		term	= pmr->s.term_value[i].term;
		/* Scan list of pmr_info for any exiting PMR type.
		   If PMR type is not present then updated it with new one.
		*/
		for (loop = 0; loop < DPKG_MAX_NUM_OF_EXTRACTS; loop++) {
			if (pmr_info[loop].type == term) {
				++i;
				goto check_next;
			}
		}

		/*If pmr_info is full, No New pmr type can be added*/
		if (pmr_index >= DPKG_MAX_NUM_OF_EXTRACTS) {
			ODP_ERR("Maximum PMR limit reached\n");
			return;
		}

		/*No existing entry found. pmr_info updation starts from here*/
		switch (term) {
		case ODP_PMR_LEN:
			pmr_info[pmr_index].type = ODP_PMR_LEN;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_ETHTYPE_0:
			pmr_info[pmr_index].type = ODP_PMR_ETHTYPE_0;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_ETHTYPE_X:
			pmr_info[pmr_index].type = ODP_PMR_ETHTYPE_X;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_VLAN_ID_0:
			pmr_info[pmr_index].type = ODP_PMR_VLAN_ID_0;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_VLAN_ID_X:
			pmr_info[pmr_index].type = ODP_PMR_VLAN_ID_X;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_DMAC:
			pmr_info[pmr_index].type = ODP_PMR_DMAC;
			pmr_info[pmr_index].size = sizeof(uint64_t);
			break;
		case ODP_PMR_IPPROTO:
			pmr_info[pmr_index].type = ODP_PMR_IPPROTO;
			pmr_info[pmr_index].size = sizeof(uint8_t);
			break;
		case ODP_PMR_UDP_DPORT:
			pmr_info[pmr_index].type = ODP_PMR_UDP_DPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_TCP_DPORT:
			pmr_info[pmr_index].type = ODP_PMR_TCP_DPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
		break;
		case ODP_PMR_UDP_SPORT:
			pmr_info[pmr_index].type = ODP_PMR_UDP_SPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_TCP_SPORT:
			pmr_info[pmr_index].type = ODP_PMR_TCP_SPORT;
			pmr_info[pmr_index].size = sizeof(uint16_t);
			break;
		case ODP_PMR_SIP_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_SIP_ADDR;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_DIP_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_DIP_ADDR;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_SIP6_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_SIP6_ADDR;
			pmr_info[pmr_index].size = 16;
			break;
		case ODP_PMR_DIP6_ADDR:
			pmr_info[pmr_index].type = ODP_PMR_DIP6_ADDR;
			pmr_info[pmr_index].size = 16;
			break;
		case ODP_PMR_IPSEC_SPI:
			pmr_info[pmr_index].type = ODP_PMR_IPSEC_SPI;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		case ODP_PMR_LD_VNI:
			pmr_info[pmr_index].type = ODP_PMR_LD_VNI;
			pmr_info[pmr_index].size = sizeof(uint32_t);
			break;
		default:
			ODP_PRINT("Term type does not supported");
			return;
		}
		if (pmr_info[pmr_index].is_valid == 0) {
			/*Save the position. It will be used while destroying
			  PMR*/
			pmr->s.pos[i] = pmr_index;
			key_cfg_len += pmr_info[pmr_index].size;
			pmr_info[pmr_index++].is_valid = 1;
		}
	}
}

/*
 * A packet matching rule is required to be written in the same order as key
 * extract paramaters are configured. This function updates the offset value
 * in PMR according to PMR type. Updated offset will be used to get correct
 * location in rule memory where data is to be written.
 */
void odp_update_pmr_set_offset(pktio_entry_t *pktio ODP_UNUSED,
			       pmr_set_t *pmr_set)
{
	uint8_t i, j, offset;
	uint8_t *stream, *mask;

	for (j = 0; j < pmr_set->s.num_pmr; j++) {
		offset = 0;
		for (i = 0; pmr_info[i].is_valid; i++) {
			if (pmr_info[i].type == (pmr_set->s.term_value[j].term))
				break;
			offset = offset + pmr_info[i].size;
		}

		/*Write rules on iova memory to be configured*/
		stream = (uint8_t *)(pmr_set->s.rule.key_iova + offset);
		mask = (uint8_t *)(pmr_set->s.rule.mask_iova + offset);
		memcpy(stream, (void *)(pmr_set->s.term_value[j].val), pmr_info[i].size);
		memcpy(mask, (void *)(pmr_set->s.term_value[j].mask), pmr_info[i].size);
		nadk_free((void *)(pmr_set->s.term_value[j].val));
		nadk_free((void *)(pmr_set->s.term_value[j].mask));
		pmr_set->s.term_value[j].val = (uint64_t)NULL;
		pmr_set->s.term_value[j].mask = (uint64_t)NULL;
	}
	pmr_set->s.rule.key_size = key_cfg_len;

}

/*
 * Similar function as above but works for single PMR only
 */
void odp_update_pmr_offset(pktio_entry_t *pktio ODP_UNUSED, pmr_t *pmr)
{
	uint8_t i, offset = 0;
	uint8_t *stream, *mask;

	for (i = 0; pmr_info[i].is_valid; i++) {
		if (pmr_info[i].type == (pmr->s.term_value[0].term))
			break;
		offset = offset + pmr_info[i].size;
	}

	/*Write rules on iova memory to be configured*/
	stream = (uint8_t *)(pmr->s.rule.key_iova + offset);
	mask = (uint8_t *)(pmr->s.rule.mask_iova + offset);

	memcpy(stream, (void *)(pmr->s.term_value[0].val), pmr_info[i].size);
	memcpy(mask, (void *)(pmr->s.term_value[0].mask), pmr_info[i].size);
	pmr->s.rule.key_size = key_cfg_len;
}

int odp_pktio_pmr_cos(odp_pmr_t pmr_id,
		      odp_pktio_t src_pktio,
		      odp_cos_t dst_cos)
{
	int32_t			retcode;
	pktio_entry_t		*pktio;
	queue_entry_t		*queue;
	pmr_t			*pmr;
	cos_t			*cos;
	/*Platform specific objects and variables*/
	struct nadk_vq_param	cfg;
	struct nadk_dev		*dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	pktio = get_pktio_entry(src_pktio);
	if (pktio == NULL) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	pmr = get_pmr_entry(pmr_id);
	if (pmr == NULL) {
		ODP_ERR("Invalid odp_pmr_t handle");
		return -1;
	}

	cos = get_cos_entry(dst_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	dev = pktio->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = pktio->s.cls.flow_id;
	tc_cfg = &pktio->s.cls.tc_cfg;

	/*Configure distribution paramters*/
	tc_cfg->dist_size = dev->num_rx_vqueues;
	/*	if default CoS is created then:
			packet will be forwarded to default flow ID 0.
		Else packet will be dropped as a default action
	*/
	if (pktio->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;

	/*Setup H/W for distribution configuration*/
	odp_setup_dist(pktio);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[++flow_id];
	/*TODO Need to update with variable value*/
	cos->s.tc_id = ODP_CLS_DEFAULT_TC;

	odp_update_pmr_offset(pktio, pmr);

	nadk_dev_set_vq_handle(dev->rx_vq[flow_id], (uint64_t)queue->s.handle);

	/*Update input and output nadk device in ODP queue*/
	queue->s.pktin = src_pktio;
	queue->s.pktout = src_pktio;

	if (flow_id < dev->num_rx_vqueues) {
		retcode = nadk_eth_setup_rx_vq(dev, flow_id, &cfg);
		if (retcode < 0) {
			ODP_ERR("Error in setup Rx flow");
			return -1;
		}
	} else {
		ODP_ERR("Number of flows reached at maximum limit\n");
		return -1;
	}

	/*Update rule list*/
	fs_rule = nadk_malloc(NULL, sizeof(struct exact_match_rule));
	if (!fs_rule) {
		ODP_ERR(" NO memory for DEVICE.\n");
		return -1;
	}

	fs_rule->tc_id = cos->s.tc_id;
	fs_rule->flow_id = flow_id;
	fs_rule->type = EXACT_MATCH_RULE_PMR;
	fs_rule->rule = &(pmr->s.rule);

	/*First validate the correct order of rule in rule list and then
	insert the rule in list.*/
	odp_insert_exact_match_rule(src_pktio, fs_rule);

	/*Add all the Classification rules at underlying platform*/
	if (print_rules)
		print_all_rule_list((uint64_t)src_pktio - 1);

	retcode = odp_offload_rules(src_pktio);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		nadk_free((void *)fs_rule);
		return -1;
	}
	nadk_free((void *)(pmr->s.term_value[0].val));
	nadk_free((void *)(pmr->s.term_value[0].mask));
	pmr->s.term_value[0].val = (uint64_t)NULL;
	pmr->s.term_value[0].mask = (uint64_t)NULL;
	pktio->s.cls.flow_id = flow_id;
	return 0;
}

int odp_cos_pmr_cos(odp_pmr_t pmr_id ODP_UNUSED, odp_cos_t src_cos ODP_UNUSED, odp_cos_t dst_cos ODP_UNUSED)
{
	ODP_UNIMPLEMENTED();
	return 0;
}

unsigned long long odp_pmr_terms_cap(void)
{
	uint64_t term_cap = 0;

	term_cap |= (1 << ODP_PMR_ETHTYPE_0);
	term_cap |= (1 << ODP_PMR_IPPROTO);
	term_cap |= (1 << ODP_PMR_SIP_ADDR);
	term_cap |= (1 << ODP_PMR_DIP_ADDR);
	term_cap |= (1 << ODP_PMR_UDP_SPORT);
	term_cap |= (1 << ODP_PMR_TCP_SPORT);
	return term_cap;
}

unsigned odp_pmr_terms_avail(void)
{
	unsigned count = 0;
	int i;

	for (i = 0; i < ODP_PMR_MAX_ENTRY; i++)
		if (!pmr_tbl->pmr[i].s.valid)
			count++;
	return count;
}

int odp_pmr_match_set_create(int num_terms, const odp_pmr_match_t *terms,
			     odp_pmr_set_t *pmr_set_id)
{
	pmr_set_t *pmr;
	int i, count = 0, val_sz;
	odp_pmr_set_t id;
	uint8_t *params[2];
	uint8_t *args[2];

	if (num_terms > ODP_PMRTERM_MAX) {
		ODP_ERR("no of terms greater than supported ODP_PMRTERM_MAX");
		return -1;
	}

	id = alloc_pmr_set((pmr_t **)&pmr);
	/*if alloc_pmr_set is successful it returns with the acquired lock*/
	if (id == ODP_PMR_SET_INVAL) {
		*pmr_set_id = id;
		return -1;
	}
	/*Allocate memory for matching rule configuration at H/W */
	params[0] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[0]) {
		ODP_ERR("Memory unavaialble");
		return -1;
	}
	params[1] = nadk_data_zmalloc(
		NULL, DIST_PARAM_IOVA_SIZE, ODP_CACHE_LINE_SIZE);
	if (!params[1]) {
		ODP_ERR("Memory unavaialble");
		nadk_data_free((void *)params[0]);
		return -1;
	}

	/*Updating ODP database for PMR SET*/
	pmr->s.num_pmr = num_terms;
	for (i = 0; i < num_terms; i++) {
		val_sz = terms[i].val_sz;
		if (val_sz > ODP_PMR_TERM_BYTES_MAX)
			continue;
		args[0] = nadk_calloc(NULL, 1, val_sz, ODP_CACHE_LINE_SIZE);
		if (!args[0]) {
			ODP_ERR("Memory unavaialble");
			nadk_data_free((void *)params[0]);
			nadk_data_free((void *)params[1]);
			return -1;
		}
		args[1] = nadk_calloc(NULL, 1, val_sz, ODP_CACHE_LINE_SIZE);
		if (!args[1]) {
			ODP_ERR("Memory unavaialble");
			nadk_data_free((void *)params[0]);
			nadk_data_free((void *)params[1]);
			nadk_free((void *)(args[0]));
			return -1;
		}
		pmr->s.term_value[i].term = terms[i].term;
		memcpy(args[0], terms[i].val, val_sz);
		memcpy(args[1], terms[i].mask, val_sz);
		convert_param_to_network_order(args[0], args[1], val_sz);
		pmr->s.term_value[i].val = (uint64_t)args[0];
		pmr->s.term_value[i].mask = (uint64_t)args[1];
		count++;
	}
	set_pmr_info((void *)pmr);
	pmr->s.rule.key_iova = (uint64_t)params[0];
	pmr->s.rule.mask_iova = (uint64_t)params[1];
	pmr->s.rule.key_size = 0;

	*pmr_set_id = id;
	CLS_UNLOCK(&pmr->s.lock);
	return count;
}

int odp_pmr_match_set_destroy(odp_pmr_set_t pmr_set_id)
{
	int32_t pos, loop;
	uint32_t i;
	pmr_set_t *pmr;

	pmr = get_pmr_set_entry(pmr_set_id);
	if (pmr == NULL)
		return -1;

	for (i = 0; i < pmr->s.num_pmr; i++) {
		pos = pmr->s.pos[i];
		loop = pos + 1;
		key_cfg_len -= pmr_info[pos].size;
		while (pmr_info[loop].is_valid == 1) {
			pmr_info[loop - 1].type = pmr_info[loop].type;
			pmr_info[loop - 1].size = pmr_info[loop].size;
			pmr_info[loop - 1].is_valid = pmr_info[loop].is_valid;
			loop++;
		}
		pmr_info[loop - 1].type = 0xFFFF;
		pmr_info[loop - 1].size = 0;
		pmr_info[loop - 1].is_valid = 0;
		pmr_index = loop - 1;
	}
	for (i = 0; i < pmr->s.num_pmr; i++) {
		if (pmr->s.term_value[i].val)
			nadk_free((void *)(pmr->s.term_value[i].val));
		if (pmr->s.term_value[i].mask)
			nadk_free((void *)(pmr->s.term_value[i].mask));
	}
	nadk_data_free((void *)(pmr->s.rule.key_iova));
	nadk_data_free((void *)(pmr->s.rule.mask_iova));
	pmr->s.rule.key_size = 0;
	pmr->s.valid = 0;
	pmr->s.num_pmr = 0;
	return 0;
}

int odp_pktio_pmr_match_set_cos(odp_pmr_set_t pmr_set_id, odp_pktio_t src_pktio,
		odp_cos_t dst_cos)
{
	int32_t			retcode;
	uint32_t i;
	pktio_entry_t		*pktio;
	queue_entry_t		*queue;
	pmr_set_t		*pmr;
	cos_t			*cos;
	/*Platform specific objects and variables*/
	struct nadk_vq_param	cfg;
	struct nadk_dev		*dev;
	struct nadk_dev_priv	*dev_priv;
	struct fsl_mc_io	*dpni;
	uint16_t		flow_id;
	struct dpni_rx_tc_dist_cfg	*tc_cfg;
	struct exact_match_rule		*fs_rule;

	pktio = get_pktio_entry(src_pktio);
	if (!pktio) {
		ODP_ERR("Invalid odp_pktio_t handle");
		return -1;
	}

	pmr = (pmr_set_t *)get_pmr_set_entry(pmr_set_id);
	if (pmr == NULL) {
		ODP_ERR("Invalid odp_pmr_set_t handle");
		return -1;
	}

	cos = get_cos_entry(dst_cos);
	if (cos == NULL) {
		ODP_ERR("Invalid odp_cos_t handle");
		return -1;
	}

	/*Get H/W device information first*/
	dev = pktio->s.pkt_nadk.dev;
	dev_priv = dev->priv;
	dpni = dev_priv->hw;
	flow_id = pktio->s.cls.flow_id;
	tc_cfg = &pktio->s.cls.tc_cfg;

	tc_cfg->dist_size = dev->num_rx_vqueues;
	if (pktio->s.cls.default_cos) {
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_EXPLICIT_FLOWID;
		tc_cfg->fs_cfg.default_flow_id = ODP_CLS_DEFAULT_FLOW;
	} else
		tc_cfg->fs_cfg.miss_action = DPNI_FS_MISS_DROP;

	odp_setup_dist(pktio);
	retcode = dpni_set_rx_tc_dist(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id, tc_cfg);
	if (retcode < 0) {
		ODP_ERR("Distribution can not be configured: %d\n", retcode);
		return -1;
	}
	retcode = dpni_clear_fs_entries(dpni, CMD_PRI_LOW, dev_priv->token,
					cos->s.tc_id);
	if (retcode < 0) {
		ODP_ERR("Error(%d) in clearing FS table\n", retcode);
		return -1;
	}

	/*Check for the Queue Type*/
	queue = cos->s.queue;
	retcode = fill_queue_configuration(queue, &cfg);
	if (retcode < 0)
		return -1;

	/*Update ODP database according to the H/W resource values*/
	cos->s.queue->s.priv = dev->rx_vq[++flow_id];
	/*TODO Need to update with variable value*/
	cos->s.tc_id = ODP_CLS_DEFAULT_TC;
	odp_update_pmr_set_offset(pktio, pmr);
	nadk_dev_set_vq_handle(dev->rx_vq[flow_id], (uint64_t)queue->s.handle);
	queue->s.pktin = src_pktio;
	queue->s.pktout = src_pktio;

	if (flow_id < dev->num_rx_vqueues) {
		retcode = nadk_eth_setup_rx_vq(dev, flow_id, &cfg);
		if (retcode < 0) {
			ODP_ERR("Error in setup Rx flow");
			return -1;
		}
	} else {
		ODP_ERR("Number of flows reached at maximum limit\n");
		return -1;
	}

	/*Update rule list*/
	fs_rule = nadk_malloc(NULL, sizeof(struct exact_match_rule));
	if (!fs_rule) {
		ODP_ERR("NO memory for DEVICE.\n");
		return -1;
	}

	fs_rule->tc_id = cos->s.tc_id;
	fs_rule->flow_id = flow_id;
	fs_rule->type = EXACT_MATCH_RULE_PMR;
	fs_rule->rule = &(pmr->s.rule);

	/*First validate the correct order of rule in rule list and then
	insert the rule in list.*/
	odp_insert_exact_match_rule(src_pktio, fs_rule);

	if (print_rules)
		print_all_rule_list((uint64_t)src_pktio - 1);

	retcode = odp_offload_rules(src_pktio);
	if (retcode < 0) {
		ODP_ERR("Error in adding FS entry:Error Code = %d\n", retcode);
		nadk_free((void *)fs_rule);
		return -1;
	}

	/*Free user allocated pmr set memory*/
	for (i = 0; i < pmr->s.num_pmr; i++) {
		nadk_free((void *)(pmr->s.term_value[i].val));
		nadk_free((void *)(pmr->s.term_value[i].mask));
		pmr->s.term_value[i].val = (uint64_t)NULL;
		pmr->s.term_value[i].mask = (uint64_t)NULL;
	}
	pktio->s.cls.flow_id = flow_id;
	return 0;
}

/*
 *Internal function init shadow database of classfication rules lists
 */
void init_pktio_cls_rule_list(uint32_t index)
{
	/*Initialize locally maintained shadow database*/
	TAILQ_INIT(&pmr_rule_list[index]);
	TAILQ_INIT(&l2_rule_list[index]);
	TAILQ_INIT(&l3_rule_list[index]);
}

/*
 *Internal function init classifier module with its default configuration
 */
int pktio_classifier_init(pktio_entry_t *entry)
{
	classifier_t *cls;
	int i;
	uint8_t *param;
	struct dpkg_profile_cfg *key_cfg;

	/* classifier lock should be acquired by the calling function */
	if (entry == NULL)
		return -1;
	cls = &entry->s.cls;
	cls->num_pmr = 0;
	cls->flow_set = 0;
	cls->error_cos = NULL;
	cls->default_cos = NULL;
	cls->headroom = 0;
	cls->skip = 0;

	param = nadk_data_zmalloc(NULL, DIST_PARAM_IOVA_SIZE,
						ODP_CACHE_LINE_SIZE);
	if (!param) {
		ODP_ERR("Memory unavaialble");
		return -ENOMEM;
	}
	key_cfg = nadk_data_zmalloc(NULL, sizeof(struct dpkg_profile_cfg),
						ODP_CACHE_LINE_SIZE);
	if (!key_cfg) {
		ODP_ERR("Memory unavaialble");
		nadk_data_free((void *)param);
		return -ENOMEM;
	}
	cls->l3_precedence = 0;
	cls->flow_id = ODP_CLS_DEFAULT_FLOW;
	cls->tc_cfg.key_cfg_iova = (uint64_t)param;
	cls->tc_cfg.dist_mode = DPNI_DIST_MODE_FS;
	cls->tc_cfg.fs_cfg.miss_action = DPNI_FS_MISS_DROP;
	entry->s.priv = key_cfg;

	for (i = 0; i < ODP_PKTIO_MAX_PMR; i++) {
		cls->pmr[i] = NULL;
		cls->cos[i] = NULL;
	}
	return 0;
}
