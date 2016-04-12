/*
 * Copyright (c) 2015 Freescale Semiconductor, Inc. All rights reserved.
 */
/* Copyright (c) 2014, Linaro Limited
 * All rights reserved.
 *
 * SPDX-License-Identifier:     BSD-3-Clause
 */

/**
 * @file
 *
 * ODP packet flags
 */

#ifndef ODP_PLAT_PACKET_FLAGS_H_
#define ODP_PLAT_PACKET_FLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <odp/std_types.h>
#include <odp/plat/event_types.h>
#include <odp/plat/packet_io_types.h>
#include <odp/plat/packet_types.h>
#include <odp/plat/buffer_types.h>
#include <odp/plat/pool_types.h>
#include <nadk/eth/nadk_ether.h>
#include <odp/byteorder.h>
#include <odp/plat/packet_annot.h>
#include <odp/hints.h>
#include <odp/debug.h>

/** @ingroup odp_packet
 *  @{
 */
static inline int odp_packet_has_error(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word3, PARSING_ERROR);
}

static inline int odp_packet_has_eth(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT);
}

static inline int odp_packet_has_vlan(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT);
}

static inline int odp_packet_has_ipv4(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT);
}

static inline int odp_packet_has_ipv6(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT);
}

static inline int odp_packet_has_jumbo(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;

	return BIT_ISSET_AT_POS(pkt_hdr->eth_flags, NADKBUF_IS_JUMBO);
}

static inline int odp_packet_has_vlan_qinq(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT);
}

static inline int odp_packet_has_arp(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word3, L2_ARP_PRESENT);
}

static inline int odp_packet_has_ipfrag(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_MORE_FRAGMENT);
}

static inline int odp_packet_has_ipopt(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT);
}

static inline int odp_packet_has_ipsec(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_IPSEC_PRESENT);
}

static inline int odp_packet_has_udp(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT);
}

static inline int odp_packet_has_tcp(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT);
}

static inline int odp_packet_has_sctp(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT);
}

static inline int odp_packet_has_icmp(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT) ||
		BIT_ISSET_AT_POS(annotation->word4, L3_PROTO_ICMPV6_PRESENT);
}

static inline int odp_packet_has_flow_hash(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	return BIT_ISSET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_HASHVAL);
}

static inline int odp_packet_has_l2(odp_packet_t pkt)
{
	/*Underlying Hardware is designed to support only Ethernet Frame*/
	return odp_packet_has_eth(pkt);
}

static inline int odp_packet_has_l3(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	return BIT_ISSET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT) ||
			BIT_ISSET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT);
}

static inline int odp_packet_has_l4(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	/* if the l4 in the flags is already set */
	if (BIT_ISSET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_L4))
			return 1;

	/*let's recheck if the annotation is having the l4 related information*/
	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
	/*if the annotation area the offset is non-zero*/
	if (L4_OFFSET(annotation->word6) >> 8) {
		/* it is not an unknown L3 IP protocol*/
		/*todo - find a better way to implement it*/
		if (!(BIT_ISSET_AT_POS(annotation->word4, L3_IP_1_UNKNOWN_PROTOCOL)))
			BIT_SET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_L4);
	}
	return BIT_ISSET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_L4);
}

/* Set Input Flags */
static inline void odp_packet_has_eth_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word3, L2_ETH_MAC_PRESENT);
}

static inline void odp_packet_has_l2_set(odp_packet_t pkt, int val)
{
	odp_packet_has_eth_set(pkt, val);
}

static inline void odp_packet_has_ipv4_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_IPV4_1_PRESENT);
}

static inline void odp_packet_has_l3_set(odp_packet_t pkt, int val)
{
	/*TODO: Supported for IPv4 Packets only*/
	odp_packet_has_ipv4_set(pkt, val);
}

static inline void odp_packet_has_l4_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	if (val) {
		BIT_SET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_L4);
	} else {
		odp_packet_metadata_t *annotation;

		annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);
		annotation->word6 &= (~0x000000000000FF00);
		BIT_RESET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_L4);
	}
}

static inline void odp_packet_has_jumbo_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	if (val)
		BIT_SET_AT_POS(pkt_hdr->eth_flags, NADKBUF_IS_JUMBO);
	else
		BIT_RESET_AT_POS(pkt_hdr->eth_flags, NADKBUF_IS_JUMBO);
}

static inline void odp_packet_has_vlan_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word3, L2_VLAN_1_PRESENT);
}

static inline void odp_packet_has_vlan_qinq_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word3, L2_VLAN_N_PRESENT);
}

static inline void odp_packet_has_arp_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word3, L2_ARP_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word3, L2_ARP_PRESENT);
}

static inline void odp_packet_has_ipv6_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_IPV6_1_PRESENT);
}

static inline void odp_packet_has_ipfrag_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_IP_1_MORE_FRAGMENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_IP_1_MORE_FRAGMENT);
}

static inline void odp_packet_has_ipopt_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_IP_1_OPT_PRESENT);
}

static inline void odp_packet_has_ipsec_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_PROTO_IPSEC_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_PROTO_IPSEC_PRESENT);
}

static inline void odp_packet_has_udp_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_PROTO_UDP_PRESENT);
}

static inline void odp_packet_has_tcp_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_PROTO_TCP_PRESENT);
}

static inline void odp_packet_has_sctp_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val)
		BIT_SET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT);
	else
		BIT_RESET_AT_POS(annotation->word4, L3_PROTO_SCTP_PRESENT);
}

static inline void odp_packet_has_icmp_set(odp_packet_t pkt, int val)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;
	odp_packet_metadata_t *annotation;

	annotation = (odp_packet_metadata_t *)(pkt_hdr->head -
			NADK_MBUF_HW_ANNOTATION);

	if (val) {
		if (odp_packet_has_ipv4(pkt))
			BIT_SET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT);
		else
			BIT_SET_AT_POS(annotation->word4, L3_PROTO_ICMPV6_PRESENT);
	} else {
		if (odp_packet_has_ipv4(pkt))
			BIT_RESET_AT_POS(annotation->word4, L3_PROTO_ICMP_PRESENT);
		else
			BIT_RESET_AT_POS(annotation->word4, L3_PROTO_ICMPV6_PRESENT);
	}
}

static inline void odp_packet_has_flow_hash_clr(odp_packet_t pkt)
{
	struct nadk_mbuf *pkt_hdr = (struct nadk_mbuf *)pkt;

	BIT_RESET_AT_POS(pkt_hdr->eth_flags, NADKBUF_HAS_HASHVAL);
}

/**
 * @}
 */

#include <odp/api/packet_flags.h>

#ifdef __cplusplus
}
#endif

#endif
