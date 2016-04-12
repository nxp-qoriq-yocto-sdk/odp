/*
 * Copyright (c) 2014 Freescale Semiconductor, Inc. All rights reserved.
 */

/**
 * @file		nadk_eth_ldpaa_annotation.h
 * @description	Structure & MACRO definitions to support annotation
 *		area in FD.
 */

#ifndef _NADK_ETH_LDPAA_ANNOT_H_
#define _NADK_ETH_LDPAA_ANNOT_H_

/* TODO Once there will be common framework (for NADK/Linux) to read
 * and manipulate annotations, this file will be removed/modified
 */

/* Annotation valid bits in FD FRC */
#define NADK_FD_FRC_FASV		0x00008000
#define NADK_FD_FRC_FAEADV		0x00004000
#define NADK_FD_FRC_FAPRV		0x00002000
#define NADK_FD_FRC_FAIADV		0x00001000
#define NADK_FD_FRC_FASWOV		0x00000800
#define NADK_FD_FRC_FAICFDV		0x00000400

/* Annotation bits in FD CTRL */
#define NADK_FD_CTRL_ASAL		0x00020000	/* ASAL = 128 */
#define NADK_FD_CTRL_PTA		0x00800000
#define NADK_FD_CTRL_PTV1		0x00400000
#define NADK_FD_CTRL_PTV2		0x00200000
#define NADK_FD_CTRL_FAERR		0x00000040
#define NADK_FD_CTRL_FSE		0x00000020
#define NADK_FD_CTRL_SBE		0x00000008
#define NADK_FD_CTRL_UFD		0x00000004

#define NADK_FD_PTA_SIZE		64

/* TODO: we may want to move this and other WRIOP related defines
 * to a separate header
 */
/* Frame annotation status */
struct nadk_fas {
	uint32_t status;
	uint16_t ifpid;
	uint16_t ppid;
};

/* Debug frame, otherwise supposed to be discarded */
#define NADK_ETH_FAS_DISC		0x80000000
/* IP-reassembled frame */
#define NADK_ETH_FAS_IPR		0x20000000
/* Ethernet multicast frame */
#define NADK_ETH_FAS_MC			0x04000000
/* Ethernet broadcast frame */
#define NADK_ETH_FAS_BC			0x02000000
#define NADK_ETH_FAS_KSE		0x00040000
#define NADK_ETH_FAS_EOFH		0x00020000
#define NADK_ETH_FAS_MNLE		0x00010000
#define NADK_ETH_FAS_TIDE		0x00008000
#define NADK_ETH_FAS_PIEE		0x00004000
/* Frame length error */
#define NADK_ETH_FAS_FLE		0x00002000
/* Frame physical error; our favourite pastime */
#define NADK_ETH_FAS_FPE		0x00001000
#define NADK_ETH_FAS_PTE		0x00000080
#define NADK_ETH_FAS_ISP		0x00000040
#define NADK_ETH_FAS_PHE		0x00000020
#define NADK_ETH_FAS_BLE		0x00000010
/* L3 csum validation performed */
#define NADK_ETH_FAS_L3CV		0x00000008
/* L3 csum error */
#define NADK_ETH_FAS_L3CE		0x00000004
/* L4 csum validation performed */
#define NADK_ETH_FAS_L4CV		0x00000002
/* L4 csum error */
#define NADK_ETH_FAS_L4CE		0x00000001
/* These bits always signal errors */
#define NADK_ETH_RX_ERR_MASK		(NADK_ETH_FAS_DISC	| \
					 NADK_ETH_FAS_KSE	| \
					 NADK_ETH_FAS_EOFH	| \
					 NADK_ETH_FAS_MNLE	| \
					 NADK_ETH_FAS_TIDE	| \
					 NADK_ETH_FAS_PIEE	| \
					 NADK_ETH_FAS_FLE	| \
					 NADK_ETH_FAS_FPE	| \
					 NADK_ETH_FAS_PTE	| \
					 NADK_ETH_FAS_ISP	| \
					 NADK_ETH_FAS_PHE	| \
					 NADK_ETH_FAS_BLE	| \
					 NADK_ETH_FAS_L3CE	| \
					 NADK_ETH_FAS_L4CE)
/* Unsupported features in the ingress */
#define NADK_ETH_RX_UNSUPP_MASK	(NADK_ETH_FAS_IPR	| \
					 NADK_ETH_FAS_L3CV	| \
					 NADK_ETH_FAS_L4CV)
/* TODO trim down the bitmask; not all of them apply to Tx-confirm */
#define NADK_ETH_TXCONF_ERR_MASK	(NADK_ETH_FAS_KSE	| \
					 NADK_ETH_FAS_EOFH	| \
					 NADK_ETH_FAS_MNLE	| \
					 NADK_ETH_FAS_TIDE)

/* Timestamp offset in the annotations */
#define NADK_ETH_TIMESTAMP_OFFSET	8

#endif /*_NADK_ETH_LDPAA_ANNOT_H_*/
