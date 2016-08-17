/*
 * Argus Software Common include files -  output structures
 * Copyright (c) 2000-2015 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2, or (at your option)
 * any later version.

 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.

 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 */

/*
 * $Id: //depot/argus/argus/include/argus_isis.h#8 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifndef ArgusIsis_h
#define ArgusIsis_h

#include <sys/time.h>
#if defined(HAVE_SOLARIS) || defined(CYGWIN)
#include <net/etherdefs.h>
#endif
#include <argus_ethertype.h>



/*
 * Copyright (c) 1992, 1993, 1994, 1995, 1996
 *	The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 *
 * Original code by Matt Thomas, Digital Equipment Corporation
 *
 * Extensively modified by Hannes Gredler (hannes@juniper.net) for more
 * complete IS-IS support.
 */


#define NLPID_CLNS	129	/* 0x81 */
#define NLPID_ISIS	131	/* 0x83 */
#define NLPID_IP6       0x8e
#define NLPID_IP        0xcc
#define NLPID_NULLNS	0

#define ISIS_IPV4       1       /* AFI value */
#define ISIS_IPV6       2       /* AFI value */

/*
 * IS-IS is defined in ISO 10589.  Look there for protocol definitions.
 */

#define SYSTEM_ID_LEN	ETHER_ADDR_LEN
#define NODE_ID_LEN     SYSTEM_ID_LEN+1
#define LSP_ID_LEN      SYSTEM_ID_LEN+2

#define ISIS_VERSION	1
#define PDU_TYPE_MASK	0x1F
#define PRIORITY_MASK	0x7F

#define L1_LAN_IIH	15
#define L2_LAN_IIH	16
#define PTP_IIH		17
#define L1_LSP          18
#define L2_LSP          20
#define L1_CSNP  	24
#define L2_CSNP  	25
#define L1_PSNP		26
#define L2_PSNP		27

struct tok {
   int v;                  /* value */
   const char *s;          /* string */
};


#include <argus_gmpls.h>

/*
 * A TLV is a tuple of a type, length and a value and is normally used for
 * encoding information in all sorts of places.  This is an enumeration of
 * the well known types.
 *
 * list taken from rfc3359 plus some memory from veterans ;-)
 */

#define TLV_AREA_ADDR           1   /* iso10589 */
#define TLV_IS_REACH            2   /* iso10589 */
#define TLV_ESNEIGH             3   /* iso10589 */
#define TLV_PART_DIS            4   /* iso10589 */
#define TLV_PREFIX_NEIGH        5   /* iso10589 */
#define TLV_ISNEIGH             6   /* iso10589 */
#define TLV_ISNEIGH_VARLEN      7   /* iso10589 */
#define TLV_PADDING             8   /* iso10589 */
#define TLV_LSP                 9   /* iso10589 */
#define TLV_AUTH                10  /* iso10589, rfc3567 */
#define TLV_CHECKSUM            12  /* rfc3358 */
#define TLV_LSP_BUFFERSIZE      14  /* iso10589 rev2 */
#define TLV_EXT_IS_REACH        22  /* draft-ietf-isis-traffic-05 */
#define TLV_IS_ALIAS_ID         24  /* draft-ietf-isis-ext-lsp-frags-02 */
#define TLV_DECNET_PHASE4       42
#define TLV_LUCENT_PRIVATE      66
#define TLV_INT_IP_REACH        128 /* rfc1195, rfc2966 */
#define TLV_PROTOCOLS           129 /* rfc1195 */
#define TLV_EXT_IP_REACH        130 /* rfc1195, rfc2966 */
#define TLV_IDRP_INFO           131 /* rfc1195 */
#define TLV_IPADDR              132 /* rfc1195 */
#define TLV_IPAUTH              133 /* rfc1195 */
#define TLV_TE_ROUTER_ID        134 /* draft-ietf-isis-traffic-05 */
#define TLV_EXTD_IP_REACH       135 /* draft-ietf-isis-traffic-05 */
#define TLV_HOSTNAME            137 /* rfc2763 */
#define TLV_SHARED_RISK_GROUP   138 /* draft-ietf-isis-gmpls-extensions */
#define TLV_NORTEL_PRIVATE1     176
#define TLV_NORTEL_PRIVATE2     177
#define TLV_HOLDTIME            198 /* ES-IS */
#define TLV_RESTART_SIGNALING   211 /* draft-ietf-isis-restart-01 */
#define TLV_MT_IS_REACH         222 /* draft-ietf-isis-wg-multi-topology-05 */
#define TLV_MT_SUPPORTED        229 /* draft-ietf-isis-wg-multi-topology-05 */
#define TLV_IP6ADDR             232 /* draft-ietf-isis-ipv6-02 */
#define TLV_MT_IP_REACH         235 /* draft-ietf-isis-wg-multi-topology-05 */
#define TLV_IP6_REACH           236 /* draft-ietf-isis-ipv6-02 */
#define TLV_MT_IP6_REACH        237 /* draft-ietf-isis-wg-multi-topology-05 */
#define TLV_PTP_ADJ             240 /* rfc3373 */
#define TLV_IIH_SEQNR           241 /* draft-shen-isis-iih-sequence-00 */
#define TLV_VENDOR_PRIVATE      250 /* draft-ietf-isis-proprietary-tlv-00 */

/*
static struct tok isis_tlv_values[] = {
    { TLV_AREA_ADDR,	     "Area address(es)"},
    { TLV_IS_REACH,          "IS Reachability"},
    { TLV_ESNEIGH,           "ES Neighbor(s)"},
    { TLV_PART_DIS,          "Partition DIS"},
    { TLV_PREFIX_NEIGH,      "Prefix Neighbors"},
    { TLV_ISNEIGH,           "IS Neighbor(s)"},
    { TLV_ISNEIGH_VARLEN,    "IS Neighbor(s) (variable length)"},
    { TLV_PADDING,           "Padding"},
    { TLV_LSP,               "LSP entries"},
    { TLV_AUTH,              "Authentication"},
    { TLV_CHECKSUM,          "Checksum"},
    { TLV_LSP_BUFFERSIZE,    "LSP Buffersize"},
    { TLV_EXT_IS_REACH,      "Extended IS Reachability"},
    { TLV_IS_ALIAS_ID,       "IS Alias ID"},
    { TLV_DECNET_PHASE4,     "DECnet Phase IV"},
    { TLV_LUCENT_PRIVATE,    "Lucent Proprietary"},
    { TLV_INT_IP_REACH,      "IPv4 Internal Reachability"},
    { TLV_PROTOCOLS,         "Protocols supported"},
    { TLV_EXT_IP_REACH,      "IPv4 External Reachability"},
    { TLV_IDRP_INFO,         "Inter-Domain Information Type"},
    { TLV_IPADDR,            "IPv4 Interface address(es)"},
    { TLV_IPAUTH,            "IPv4 authentication (deprecated)"},
    { TLV_TE_ROUTER_ID,      "Traffic Engineering Router ID"},
    { TLV_EXTD_IP_REACH,      "Extended IPv4 Reachability"},
    { TLV_HOSTNAME,          "Hostname"},
    { TLV_SHARED_RISK_GROUP, "Shared Risk Link Group"},
    { TLV_NORTEL_PRIVATE1,   "Nortel Proprietary"},
    { TLV_NORTEL_PRIVATE2,   "Nortel Proprietary"},
    { TLV_HOLDTIME,          "Holdtime"},
    { TLV_RESTART_SIGNALING, "Restart Signaling"},
    { TLV_MT_IS_REACH,       "Multi Topology IS Reachability"},
    { TLV_MT_SUPPORTED,      "Multi Topology"},
    { TLV_IP6ADDR,           "IPv6 Interface address(es)"},
    { TLV_MT_IP_REACH,       "Multi-Topology IPv4 Reachability"},
    { TLV_IP6_REACH,         "IPv6 reachability"},
    { TLV_MT_IP6_REACH,      "Multi-Topology IP6 Reachability"},
    { TLV_PTP_ADJ,           "Point-to-point Adjacency State"},
    { TLV_IIH_SEQNR,         "Hello PDU Sequence Number"},
    { TLV_VENDOR_PRIVATE,    "Vendor Private"},
    { 0, NULL }
};
*/

#define SUBTLV_EXT_IS_REACH_ADMIN_GROUP           3 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_LINK_LOCAL_REMOTE_ID  4 /* draft-ietf-isis-gmpls-extensions */
#define SUBTLV_EXT_IS_REACH_LINK_REMOTE_ID        5 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_IPV4_INTF_ADDR        6 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_IPV4_NEIGHBOR_ADDR    8 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_MAX_LINK_BW           9 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_RESERVABLE_BW        10 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_UNRESERVED_BW        11 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_TE_METRIC            18 /* draft-ietf-isis-traffic-05 */
#define SUBTLV_EXT_IS_REACH_LINK_PROTECTION_TYPE 20 /* draft-ietf-isis-gmpls-extensions */
#define SUBTLV_EXT_IS_REACH_INTF_SW_CAP_DESCR    21 /* draft-ietf-isis-gmpls-extensions */

/*
static struct tok isis_ext_is_reach_subtlv_values[] = {
    { SUBTLV_EXT_IS_REACH_ADMIN_GROUP,            "Administrative groups" },
    { SUBTLV_EXT_IS_REACH_LINK_LOCAL_REMOTE_ID,   "Link Local/Remote Identifier" },
    { SUBTLV_EXT_IS_REACH_LINK_REMOTE_ID,         "Link Remote Identifier" },
    { SUBTLV_EXT_IS_REACH_IPV4_INTF_ADDR,         "IPv4 interface address" },
    { SUBTLV_EXT_IS_REACH_IPV4_NEIGHBOR_ADDR,     "IPv4 neighbor address" },
    { SUBTLV_EXT_IS_REACH_MAX_LINK_BW,            "Maximum link bandwidth" },
    { SUBTLV_EXT_IS_REACH_RESERVABLE_BW,          "Reservable link bandwidth" },
    { SUBTLV_EXT_IS_REACH_UNRESERVED_BW,          "Unreserved bandwidth" },
    { SUBTLV_EXT_IS_REACH_TE_METRIC,              "Traffic Engineering Metric" },
    { SUBTLV_EXT_IS_REACH_LINK_PROTECTION_TYPE,   "Link Protection Type" },
    { SUBTLV_EXT_IS_REACH_INTF_SW_CAP_DESCR,      "Interface Switching Capability" },
    { 250,                                        "Reserved for cisco specific extensions" },
    { 251,                                        "Reserved for cisco specific extensions" },
    { 252,                                        "Reserved for cisco specific extensions" },
    { 253,                                        "Reserved for cisco specific extensions" },
    { 254,                                        "Reserved for cisco specific extensions" },
    { 255,                                        "Reserved for future expansion" },
    { 0, NULL }
};
*/

#define SUBTLV_EXTD_IP_REACH_ADMIN_TAG32          1
#define SUBTLV_EXTD_IP_REACH_ADMIN_TAG64          2

/*
static struct tok isis_ext_ip_reach_subtlv_values[] = {
    { SUBTLV_EXTD_IP_REACH_ADMIN_TAG32,           "32-Bit Administrative tag" },
    { SUBTLV_EXTD_IP_REACH_ADMIN_TAG64,           "64-Bit Administrative tag" },
    { 0, NULL }
};
*/

#define SUBTLV_AUTH_SIMPLE        1
#define SUBTLV_AUTH_MD5          54
#define SUBTLV_AUTH_MD5_LEN      16
#define SUBTLV_AUTH_PRIVATE     255

/*
static struct tok isis_subtlv_auth_values[] = {
    { SUBTLV_AUTH_SIMPLE,	"simple text password"},
    { SUBTLV_AUTH_MD5,	        "HMAC-MD5 password"},
    { SUBTLV_AUTH_PRIVATE,	"Routing Domain private password"},
    { 0, NULL }
};
*/

#define SUBTLV_IDRP_RES           0
#define SUBTLV_IDRP_LOCAL         1
#define SUBTLV_IDRP_ASN           2

/*
static struct tok isis_subtlv_idrp_values[] = {
    { SUBTLV_IDRP_RES,         "Reserved"},
    { SUBTLV_IDRP_LOCAL,       "Routing-Domain Specific"},
    { SUBTLV_IDRP_ASN,         "AS Number Tag"},
    { 0, NULL}
};
*/

#define ISIS_8BIT_MASK(x)                  ((x)&0xff)

#define ISIS_MASK_LSP_OL_BIT(x)            ((x)&0x4)
#define ISIS_MASK_LSP_ISTYPE_BITS(x)       ((x)&0x3)
#define ISIS_MASK_LSP_PARTITION_BIT(x)     ((x)&0x80)
#define ISIS_MASK_LSP_ATT_BITS(x)          ((x)&0x78)
#define ISIS_MASK_LSP_ATT_ERROR_BIT(x)     ((x)&0x40)
#define ISIS_MASK_LSP_ATT_EXPENSE_BIT(x)   ((x)&0x20)
#define ISIS_MASK_LSP_ATT_DELAY_BIT(x)     ((x)&0x10)
#define ISIS_MASK_LSP_ATT_DEFAULT_BIT(x)   ((x)&0x8)

#define ISIS_MASK_MTID(x)                  ((x)&0x0fff)
#define ISIS_MASK_MTFLAGS(x)               ((x)&0xf000)

/*
static struct tok isis_mt_flag_values[] = {
    { 0x4000,                  "sub-TLVs present"},
    { 0x8000,                  "ATT bit set"},
    { 0, NULL}
};
*/

#define ISIS_MASK_TLV_EXTD_IP_UPDOWN(x)     ((x)&0x80)
#define ISIS_MASK_TLV_EXTD_IP_SUBTLV(x)     ((x)&0x40)

#define ISIS_MASK_TLV_EXTD_IP6_IE(x)        ((x)&0x40)
#define ISIS_MASK_TLV_EXTD_IP6_SUBTLV(x)    ((x)&0x20)

#define ISIS_LSP_TLV_METRIC_SUPPORTED(x)   ((x)&0x80)
#define ISIS_LSP_TLV_METRIC_IE(x)          ((x)&0x40)
#define ISIS_LSP_TLV_METRIC_UPDOWN(x)      ((x)&0x80)
#define ISIS_LSP_TLV_METRIC_VALUE(x)	   ((x)&0x3f)

#define ISIS_MASK_TLV_SHARED_RISK_GROUP(x) ((x)&0x1)

/*
static struct tok isis_mt_values[] = {
    { 0,    "IPv4 unicast"},
    { 1,    "In-Band Management"},
    { 2,    "IPv6 unicast"},
    { 3,    "Multicast"},
    { 4095, "Development, Experimental or Proprietary"},
    { 0, NULL }
};
*/

/*
static struct tok isis_iih_circuit_type_values[] = {
    { 1,    "Level 1 only"},
    { 2,    "Level 2 only"},
    { 3,    "Level 1, Level 2"},
    { 0, NULL}
};
*/

#define ISIS_LSP_TYPE_UNUSED0   0
#define ISIS_LSP_TYPE_LEVEL_1   1
#define ISIS_LSP_TYPE_UNUSED2   2
#define ISIS_LSP_TYPE_LEVEL_2   3

/*
static struct tok isis_lsp_istype_values[] = {
    { ISIS_LSP_TYPE_UNUSED0,	"Unused 0x0 (invalid)"},
    { ISIS_LSP_TYPE_LEVEL_1,	"L1 IS"},
    { ISIS_LSP_TYPE_UNUSED2,	"Unused 0x2 (invalid)"},
    { ISIS_LSP_TYPE_LEVEL_2,	"L1L2 IS"},
    { 0, NULL }
};

static struct tok osi_nlpid_values[] = {
    { NLPID_CLNS,   "CLNS"},
    { NLPID_IP,     "IPv4"},
    { NLPID_IP6,    "IPv6"},
    { 0, NULL }
};
*/

/*
 * Katz's point to point adjacency TLV uses codes to tell us the state of
 * the remote adjacency.  Enumerate them.
 */

#define ISIS_PTP_ADJ_UP   0
#define ISIS_PTP_ADJ_INIT 1
#define ISIS_PTP_ADJ_DOWN 2

/*
static struct tok isis_ptp_adjancey_values[] = {
    { ISIS_PTP_ADJ_UP,    "Up" },
    { ISIS_PTP_ADJ_INIT,  "Initializing" },
    { ISIS_PTP_ADJ_DOWN,  "Down" },
    { 0, NULL}
};
*/

struct isis_tlv_ptp_adj {
    u_int8_t adjacency_state;
    u_int8_t extd_local_circuit_id[4];
    u_int8_t neighbor_sysid[SYSTEM_ID_LEN];
    u_int8_t neighbor_extd_local_circuit_id[4];
};

/*
static int osi_cksum(const u_int8_t *, u_int);
static int isis_print(const u_int8_t *, u_int);
*/

struct isis_metric_block {
    u_int8_t metric_default;
    u_int8_t metric_delay;
    u_int8_t metric_expense;
    u_int8_t metric_error;
};

struct isis_tlv_is_reach {
    struct isis_metric_block isis_metric_block;
    u_int8_t neighbor_nodeid[NODE_ID_LEN];
};

struct isis_tlv_is_extd_reach {
  u_int8_t neighbor_nodeid[NODE_ID_LEN];
  u_int8_t metric_default[3]; 
  u_int8_t subtlv_len; 
#if defined(__GNUC__)
  u_int8_t subtlv[0];
#else
  u_int8_t subtlv[1];
#endif
}; 

struct isis_tlv_extd_ip_reach {
  u_int32_t metric_default;
  u_int8_t  up_down_bit : 1;
  u_int8_t  subtlvs_present : 1;
  u_int8_t  prefix_len : 6;
#if defined(__GNUC__)
  u_int8_t  prefix[0];
#else
  u_int8_t  prefix[1];
#endif
};

struct isis_tlv_es_reach {
    struct isis_metric_block isis_metric_block;
    u_int8_t neighbor_sysid[SYSTEM_ID_LEN];
};

struct isis_tlv_ip_reach {
    struct isis_metric_block isis_metric_block;
    u_int8_t prefix[4];
    u_int8_t mask[4];
};

struct isis_tlv_name { 
#if defined(__GNUC__)
  char name[0];
#else
  char name[4];
#endif
}; 

struct isis_tlv_csum { 
  u_int16_t csum;
};

/*
static struct tok isis_is_reach_virtual_values[] = {
    { 0,    "IsNotVirtual"},
    { 1,    "IsVirtual"},
    { 0, NULL }
};

static struct tok isis_restart_flag_values[] = {
    { 0x1,  "Restart Request"},
    { 0x2,  "Restart Acknowledgement"},
    { 0, NULL }
};
*/

struct isis_common_header {
    u_int8_t nlpid;
    u_int8_t fixed_len;
    u_int8_t version;			/* Protocol version */
    u_int8_t id_length;
    u_int8_t pdu_type;		        /* 3 MSbits are reserved */
    u_int8_t pdu_version;		/* Packet format version */
    u_int8_t reserved;
    u_int8_t max_area;
};

struct isis_iih_lan_header {
    u_int8_t circuit_type;
    u_int8_t source_id[SYSTEM_ID_LEN];
    u_int8_t holding_time[2];
    u_int8_t pdu_len[2];
    u_int8_t priority;
    u_int8_t lan_id[NODE_ID_LEN];
};

struct isis_iih_ptp_header {
    u_int8_t circuit_type;
    u_int8_t source_id[SYSTEM_ID_LEN];
    u_int8_t holding_time[2];
    u_int8_t pdu_len[2];
    u_int8_t circuit_id;
};

struct isis_lsp_header {
    u_int8_t pdu_len[2];
    u_int8_t remaining_lifetime[2];
    u_int8_t lsp_id[LSP_ID_LEN];
    u_int8_t sequence_number[4];
    u_int8_t checksum[2];
    u_int8_t typeblock;
};

struct isis_csnp_header {
    u_int8_t pdu_len[2];
    u_int8_t source_id[NODE_ID_LEN];
    u_int8_t start_lsp_id[LSP_ID_LEN];
    u_int8_t end_lsp_id[LSP_ID_LEN];
};

struct isis_psnp_header {
   u_int8_t pdu_len[2];
   u_int8_t source_id[NODE_ID_LEN];
};

struct isis_tlv_lsp {
   u_int8_t remaining_lifetime[2];
   u_int8_t lsp_id[LSP_ID_LEN];
   u_int8_t sequence_number[4];
   u_int8_t checksum[2];
};


#if defined(ArgusIsis)

/*
static struct tok isis_pdu_values[] = {
    { L1_LAN_IIH,       "L1 Lan IIH"},
    { L2_LAN_IIH,       "L2 Lan IIH"},
    { PTP_IIH,          "p2p IIH"},
    { L1_LSP,           "L1 LSP"},
    { L2_LSP,           "L2 LSP"},
    { L1_CSNP,          "L1 CSNP"},
    { L2_CSNP,          "L2 CSNP"},
    { L1_PSNP,          "L1 PSNP"},
    { L2_PSNP,          "L2 PSNP"},
    { 0, NULL}
};
*/

/* rfc3471 */
struct tok gmpls_link_prot_values[] = {
    { 0x01, "Extra Traffic"},
    { 0x02, "Unprotected"},
    { 0x04, "Shared"},
    { 0x08, "Dedicated 1:1"},
    { 0x10, "Dedicated 1+1"},
    { 0x20, "Enhanced"},
    { 0x40, "Reserved"},
    { 0x80, "Reserved"},
    { 0, NULL }
};

/* rfc3471 */
struct tok gmpls_switch_cap_values[] = {
    { 1,	"Packet-Switch Capable-1"},
    { 2,	"Packet-Switch Capable-2"},
    { 3,	"Packet-Switch Capable-3"},
    { 4,	"Packet-Switch Capable-4"},
    { 51,	"Layer-2 Switch Capable"},
    { 100,	"Time-Division-Multiplex"},
    { 150,	"Lambda-Switch Capable"},
    { 200,	"Fiber-Switch Capable"},
    { 0, NULL }
};

/* rfc3471 */
struct tok gmpls_encoding_values[] = {
    { 1,    "Packet"},
    { 2,    "Ethernet V2/DIX"},
    { 3,    "ANSI/ETSI PDH"},
    { 4,    "Reserved"},
    { 5,    "SDH ITU-T G.707/SONET ANSI T1.105"},
    { 6,    "Reserved"},
    { 7,    "Digital Wrapper"},
    { 8,    "Lambda (photonic)"},
    { 9,    "Fiber"},
    { 10,   "Reserved"},
    { 11,   "FiberChannel"},
    { 0, NULL }
};
#endif /* ArgusIsis */

#endif /* ArgusIsis_h */

