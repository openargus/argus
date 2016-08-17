/*
 * Argus Software.  Argus files - Input includes
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
 * $Id: //depot/argus/argus/argus/ArgusSource.h#47 $
 * $DateTime: 2015/04/13 00:43:29 $
 * $Change: 2982 $
 */

/*  ArgusSource.h */

#ifndef ArgusSource_h
#define ArgusSource_h

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>

#include <string.h>
#include <strings.h>

#if defined(ARGUS_TILERA)
#include <argus_tilera.h>

#include <sys/archlib.h>
#include <pass.h>
#include <sys/tile_io.h>
#include <sys/netio.h>
#include <sys/event.h>
#include <ilib.h>
#include <stdio.h>
#include <sys/simulator.h>
#include <sys/profiler.h>

#else
#include <pcap.h>
#endif

/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#ifndef _CPACK_H
#define _CPACK_H

struct cpack_state {
	u_int8_t					*c_buf;
	u_int8_t					*c_next;
	size_t						 c_len;
};

int cpack_init(struct cpack_state *, u_int8_t *, size_t);

int cpack_uint8(struct cpack_state *, u_int8_t *);
int cpack_uint16(struct cpack_state *, u_int16_t *);
int cpack_uint32(struct cpack_state *, u_int32_t *);
int cpack_uint64(struct cpack_state *, u_int64_t *);

#define cpack_int8(__s, __p)	cpack_uint8((__s),  (u_int8_t*)(__p))
#define cpack_int16(__s, __p)	cpack_uint16((__s), (u_int16_t*)(__p))
#define cpack_int32(__s, __p)	cpack_uint32((__s), (u_int32_t*)(__p))
#define cpack_int64(__s, __p)	cpack_uint64((__s), (u_int64_t*)(__p))

#endif /* _CPACK_H */
 
int pcap_read(pcap_t *, int cnt, pcap_handler, u_char *);
int pcap_offline_read(pcap_t *, int, pcap_handler, u_char *);

#include <signal.h>
#include <errno.h>

#include <argus/extract.h>
#include <argus/fddi.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>

#if defined(__NetBSD__)
#include <netinet/in.h>
#endif

#if !defined(__OpenBSD__)
#include <netinet/if_ether.h>
#endif

#include <netinet/in.h>

#if !defined(__OpenBSD__) || (defined(__OpenBSD__) && !defined(_NETINET_IF_SYSTEM_H_))
#define _NETINET_IF_SYSTEM_H_
#include <netinet/in_systm.h>
#endif

#ifndef _NETINET_IP_H_
#include <netinet/ip.h>
#define _NETINET_IP_H_
#endif

#ifndef _NETINET_UDP_H_
#include <netinet/udp.h>
#define _NETINET_UDP_H_
#endif

#include <netinet/tcp.h>

 
#define ARGUSLIBPPKTFILE	1
#define ARGUSSNOOPKTFILE	2
#define ARGUSMOATTSHPKTFILE	3
#define ARGUSDAGLINK            4
#define ARGUSERFPKTFILE		5

#define ARGUS_FILE_DEVICE	1
#define ARGUS_LIVE_DEVICE	2


#define ARGUS_MAXINTERFACE	64

#define ARGUS_TYPE_IND		0x01
#define ARGUS_TYPE_BOND		0x02
#define ARGUS_TYPE_DUPLEX	0x04

struct ArgusDeviceStruct {
   struct ArgusListObjectStruct *nxt;
   int status, type, mode, link, idtype, dlt;
   struct ArgusAddrStruct ArgusID;
   char *name, *dltname;
   struct ArgusListStruct *list;
#if defined(ARGUS_TILERA)
   netio_input_config_t config;
#endif
};

struct ArgusRfileStruct {
   struct ArgusListObjectStruct *nxt;
   int mode;
   char *name;
};

struct arguspcap_sf {
   FILE *rfile;
   int swapped;
   int hdrsize;
   int version_major;
   int version_minor;
   u_char *base;
};
  
struct arguspcap_md {
   struct pcap_stat stat;
   /*XXX*/
   int use_bpf;		/* using kernel filter */
   u_long	TotPkts;	/* can't oflow for 79 hrs on ether */
   u_long	TotAccepted;	/* count accepted by filter */
   u_long	TotDrops;	/* count of dropped packets */
   long	TotMissed;	/* missed by i/f during this run */
   long	OrigMissed;	/* missed by i/f before this run */
#ifdef linux
   int	sock_packet;	/* using Linux 2.0 compatible interface */
   int	timeout;	/* timeout specified to pcap_open_live */
   int	clear_promisc;	/* must clear promiscuous mode when we close */
   int	cooked;		/* using SOCK_DGRAM rather than SOCK_RAW */
   int	lo_ifindex;	/* interface index of the loopback device */
   char 	*device;	/* device name */
   struct pcap *next;	/* list of open promiscuous sock_packet pcaps */
#endif
};
  
struct arguspcap {
   int fd;
   int snapshot;
   int linktype;
   int tzoff;		/* timezone offset */
   int offset;		/* offset for proper alignment */
 
   struct arguspcap_sf sf;
   struct arguspcap_md md;
  
   /*
    * Read buffer.
    */
   int bufsize;
   u_char *buffer;
   u_char *bp;
   int cc;
  
   /*
    * Place holder for pcap_next().
    */
   u_char *pkt;
 
   /*
    * Placeholder for filter code if bpf not in kernel.
    */
   struct bpf_program fcode;
  
   char errbuf[PCAP_ERRBUF_SIZE];
};

#define MAXSTRSIZE 1024
#define ARGUS_MAXSNAPLEN 65535
 
struct ArgusInterfaceStruct {
   struct ArgusDeviceStruct *ArgusDevice;
   struct ifreq ifr;
   pcap_t *ArgusPd;
   struct bpf_program ArgusFilter;
   int state, index, ArgusInterfaceType;
   pcap_handler ArgusCallBack;

   struct arguspcap ArgusPcap;

   unsigned int ArgusLocalNet, ArgusNetMask;
   struct pcap_stat ArgusStat;

   long ArgusPacketOffset;
   long long ArgusTotalPkts;
   long long ArgusTotalIPPkts;
   long long ArgusTotalNonIPPkts;
   long long ArgusLastPkts;
   long long ArgusTotalDrop;
   long long ArgusLastDrop;
   long long ArgusTotalBytes;
   long long ArgusLastBytes;

   u_char *ArgusPacketBuffer;
   u_char ArgusPacketBufferBuffer[ARGUS_MAXSNAPLEN];
};


struct ArgusMoatTshPktHdr {
   unsigned int sec;
   char interface;
   char usec[3];
   struct ip ip;
   struct tcphdr tcp;
};

#define SNOOP_FILE_OFFSET 16

struct ArgusSnoopPktHdr {
    unsigned int len;
    unsigned int tlen;
    unsigned int pad[2];
    struct timeval argtvp;
};

#if defined(ArgusSource)

#define JUNIPER_BPF_OUT           0       /* Outgoing packet */
#define JUNIPER_BPF_IN            1       /* Incoming packet */
#define JUNIPER_BPF_PKT_IN        0x1     /* Incoming packet */
#define JUNIPER_BPF_NO_L2         0x2     /* L2 header stripped */
#define JUNIPER_BPF_IIF           0x4     /* IIF is valid */
#define JUNIPER_BPF_FILTER        0x40    /* BPF filtering is supported */
#define JUNIPER_BPF_EXT           0x80    /* extensions present */
#define JUNIPER_MGC_NUMBER        0x4d4743 /* = "MGC" */

#define JUNIPER_LSQ_COOKIE_RE         (1 << 3)
#define JUNIPER_LSQ_COOKIE_DIR        (1 << 2)
#define JUNIPER_LSQ_L3_PROTO_SHIFT     4
#define JUNIPER_LSQ_L3_PROTO_MASK     (0x17 << JUNIPER_LSQ_L3_PROTO_SHIFT)
#define JUNIPER_LSQ_L3_PROTO_IPV4     (0 << JUNIPER_LSQ_L3_PROTO_SHIFT)
#define JUNIPER_LSQ_L3_PROTO_IPV6     (1 << JUNIPER_LSQ_L3_PROTO_SHIFT)
#define JUNIPER_LSQ_L3_PROTO_MPLS     (2 << JUNIPER_LSQ_L3_PROTO_SHIFT)
#define JUNIPER_LSQ_L3_PROTO_ISO      (3 << JUNIPER_LSQ_L3_PROTO_SHIFT)
#define AS_PIC_COOKIE_LEN 8

#define JUNIPER_IPSEC_O_ESP_ENCRYPT_ESP_AUTHEN_TYPE 1
#define JUNIPER_IPSEC_O_ESP_ENCRYPT_AH_AUTHEN_TYPE 2
#define JUNIPER_IPSEC_O_ESP_AUTHENTICATION_TYPE 3
#define JUNIPER_IPSEC_O_AH_AUTHENTICATION_TYPE 4
#define JUNIPER_IPSEC_O_ESP_ENCRYPTION_TYPE 5


/* codepoints for encoding extensions to a .pcap file */
enum {
    JUNIPER_EXT_TLV_IFD_IDX = 1,
    JUNIPER_EXT_TLV_IFD_NAME = 2,
    JUNIPER_EXT_TLV_IFD_MEDIATYPE = 3,
    JUNIPER_EXT_TLV_IFL_IDX = 4,
    JUNIPER_EXT_TLV_IFL_UNIT = 5,
    JUNIPER_EXT_TLV_IFL_ENCAPS = 6, 
    JUNIPER_EXT_TLV_TTP_IFD_MEDIATYPE = 7,  
    JUNIPER_EXT_TLV_TTP_IFL_ENCAPS = 8
};

/* 1 byte type and 1-byte length */
#define JUNIPER_EXT_TLV_OVERHEAD 2

struct tok jnx_ext_tlv_values[] = {
    { JUNIPER_EXT_TLV_IFD_IDX, "Device Interface Index" },
    { JUNIPER_EXT_TLV_IFD_NAME,"Device Interface Name" },
    { JUNIPER_EXT_TLV_IFD_MEDIATYPE, "Device Media Type" },
    { JUNIPER_EXT_TLV_IFL_IDX, "Logical Interface Index" },
    { JUNIPER_EXT_TLV_IFL_UNIT,"Logical Unit Number" },
    { JUNIPER_EXT_TLV_IFL_ENCAPS, "Logical Interface Encapsulation" },
    { JUNIPER_EXT_TLV_TTP_IFD_MEDIATYPE, "TTP derived Device Media Type" },
    { JUNIPER_EXT_TLV_TTP_IFL_ENCAPS, "TTP derived Logical Interface Encapsulation" },
    { 0, NULL }
};

struct tok jnx_flag_values[] = {
    { JUNIPER_BPF_EXT, "Ext" },
    { JUNIPER_BPF_FILTER, "Filter" },
    { JUNIPER_BPF_IIF, "IIF" },
    { JUNIPER_BPF_NO_L2, "no-L2" },
    { JUNIPER_BPF_PKT_IN, "In" },
    { 0, NULL }
};

#define JUNIPER_IFML_ETHER              1
#define JUNIPER_IFML_FDDI               2
#define JUNIPER_IFML_TOKENRING          3
#define JUNIPER_IFML_PPP                4
#define JUNIPER_IFML_FRAMERELAY         5
#define JUNIPER_IFML_CISCOHDLC          6
#define JUNIPER_IFML_SMDSDXI            7
#define JUNIPER_IFML_ATMPVC             8
#define JUNIPER_IFML_PPP_CCC            9
#define JUNIPER_IFML_FRAMERELAY_CCC     10
#define JUNIPER_IFML_IPIP               11
#define JUNIPER_IFML_GRE                12
#define JUNIPER_IFML_PIM                13
#define JUNIPER_IFML_PIMD               14
#define JUNIPER_IFML_CISCOHDLC_CCC      15
#define JUNIPER_IFML_VLAN_CCC           16
#define JUNIPER_IFML_MLPPP              17
#define JUNIPER_IFML_MLFR               18
#define JUNIPER_IFML_ML                 19
#define JUNIPER_IFML_LSI                20
#define JUNIPER_IFML_DFE                21
#define JUNIPER_IFML_ATM_CELLRELAY_CCC  22
#define JUNIPER_IFML_CRYPTO             23
#define JUNIPER_IFML_GGSN               24
#define JUNIPER_IFML_LSI_PPP            25
#define JUNIPER_IFML_LSI_CISCOHDLC      26
#define JUNIPER_IFML_PPP_TCC            27
#define JUNIPER_IFML_FRAMERELAY_TCC     28
#define JUNIPER_IFML_CISCOHDLC_TCC      29
#define JUNIPER_IFML_ETHERNET_CCC       30
#define JUNIPER_IFML_VT                 31
#define JUNIPER_IFML_EXTENDED_VLAN_CCC  32
#define JUNIPER_IFML_ETHER_OVER_ATM     33
#define JUNIPER_IFML_MONITOR            34
#define JUNIPER_IFML_ETHERNET_TCC       35
#define JUNIPER_IFML_VLAN_TCC           36
#define JUNIPER_IFML_EXTENDED_VLAN_TCC  37
#define JUNIPER_IFML_CONTROLLER         38
#define JUNIPER_IFML_MFR                39
#define JUNIPER_IFML_LS                 40
#define JUNIPER_IFML_ETHERNET_VPLS      41
#define JUNIPER_IFML_ETHERNET_VLAN_VPLS 42
#define JUNIPER_IFML_ETHERNET_EXTENDED_VLAN_VPLS 43
#define JUNIPER_IFML_LT                 44
#define JUNIPER_IFML_SERVICES           45
#define JUNIPER_IFML_ETHER_VPLS_OVER_ATM 46
#define JUNIPER_IFML_FR_PORT_CCC        47
#define JUNIPER_IFML_FRAMERELAY_EXT_CCC 48
#define JUNIPER_IFML_FRAMERELAY_EXT_TCC 49
#define JUNIPER_IFML_FRAMERELAY_FLEX    50
#define JUNIPER_IFML_GGSNI              51
#define JUNIPER_IFML_ETHERNET_FLEX      52
#define JUNIPER_IFML_COLLECTOR          53
#define JUNIPER_IFML_AGGREGATOR         54
#define JUNIPER_IFML_LAPD               55
#define JUNIPER_IFML_PPPOE              56
#define JUNIPER_IFML_PPP_SUBORDINATE    57
#define JUNIPER_IFML_CISCOHDLC_SUBORDINATE  58
#define JUNIPER_IFML_DFC                59
#define JUNIPER_IFML_PICPEER            60

struct tok juniper_ifmt_values[] = {
    { JUNIPER_IFML_ETHER, "Ethernet" },
    { JUNIPER_IFML_FDDI, "FDDI" },
    { JUNIPER_IFML_TOKENRING, "Token-Ring" },
    { JUNIPER_IFML_PPP, "PPP" },
    { JUNIPER_IFML_PPP_SUBORDINATE, "PPP-Subordinate" },
    { JUNIPER_IFML_FRAMERELAY, "Frame-Relay" },
    { JUNIPER_IFML_CISCOHDLC, "Cisco-HDLC" },
    { JUNIPER_IFML_SMDSDXI, "SMDS-DXI" },
    { JUNIPER_IFML_ATMPVC, "ATM-PVC" },
    { JUNIPER_IFML_PPP_CCC, "PPP-CCC" },
    { JUNIPER_IFML_FRAMERELAY_CCC, "Frame-Relay-CCC" },
    { JUNIPER_IFML_FRAMERELAY_EXT_CCC, "Extended FR-CCC" },
    { JUNIPER_IFML_IPIP, "IP-over-IP" },
    { JUNIPER_IFML_GRE, "GRE" },
    { JUNIPER_IFML_PIM, "PIM-Encapsulator" },
    { JUNIPER_IFML_PIMD, "PIM-Decapsulator" },
    { JUNIPER_IFML_CISCOHDLC_CCC, "Cisco-HDLC-CCC" },
    { JUNIPER_IFML_VLAN_CCC, "VLAN-CCC" },
    { JUNIPER_IFML_EXTENDED_VLAN_CCC, "Extended-VLAN-CCC" },
    { JUNIPER_IFML_MLPPP, "Multilink-PPP" },
    { JUNIPER_IFML_MLFR, "Multilink-FR" },
    { JUNIPER_IFML_MFR, "Multilink-FR-UNI-NNI" },
    { JUNIPER_IFML_ML, "Multilink" },
    { JUNIPER_IFML_LS, "LinkService" },
    { JUNIPER_IFML_LSI, "LSI" },
    { JUNIPER_IFML_ATM_CELLRELAY_CCC, "ATM-CCC-Cell-Relay" },
    { JUNIPER_IFML_CRYPTO, "IPSEC-over-IP" },
    { JUNIPER_IFML_GGSN, "GGSN" },
    { JUNIPER_IFML_PPP_TCC, "PPP-TCC" },
    { JUNIPER_IFML_FRAMERELAY_TCC, "Frame-Relay-TCC" },
    { JUNIPER_IFML_FRAMERELAY_EXT_TCC, "Extended FR-TCC" },
    { JUNIPER_IFML_CISCOHDLC_TCC, "Cisco-HDLC-TCC" },
    { JUNIPER_IFML_ETHERNET_CCC, "Ethernet-CCC" },
    { JUNIPER_IFML_VT, "VPN-Loopback-tunnel" },
    { JUNIPER_IFML_ETHER_OVER_ATM, "Ethernet-over-ATM" },
    { JUNIPER_IFML_ETHER_VPLS_OVER_ATM, "Ethernet-VPLS-over-ATM" },
    { JUNIPER_IFML_MONITOR, "Monitor" },
    { JUNIPER_IFML_ETHERNET_TCC, "Ethernet-TCC" },
    { JUNIPER_IFML_VLAN_TCC, "VLAN-TCC" },
    { JUNIPER_IFML_EXTENDED_VLAN_TCC, "Extended-VLAN-TCC" },
    { JUNIPER_IFML_CONTROLLER, "Controller" },
    { JUNIPER_IFML_ETHERNET_VPLS, "VPLS" },
    { JUNIPER_IFML_ETHERNET_VLAN_VPLS, "VLAN-VPLS" },
    { JUNIPER_IFML_ETHERNET_EXTENDED_VLAN_VPLS, "Extended-VLAN-VPLS" },
    { JUNIPER_IFML_LT, "Logical-tunnel" },
    { JUNIPER_IFML_SERVICES, "General-Services" },
    { JUNIPER_IFML_PPPOE, "PPPoE" },
    { JUNIPER_IFML_ETHERNET_FLEX, "Flexible-Ethernet-Services" },
    { JUNIPER_IFML_FRAMERELAY_FLEX, "Flexible-FrameRelay" },
    { JUNIPER_IFML_COLLECTOR, "Flow-collection" },
    { JUNIPER_IFML_PICPEER, "PIC Peer" },
    { JUNIPER_IFML_DFC, "Dynamic-Flow-Capture" },
    {0,                    NULL}
};

#define JUNIPER_IFLE_ATM_SNAP           2
#define JUNIPER_IFLE_ATM_NLPID          3
#define JUNIPER_IFLE_ATM_VCMUX          4
#define JUNIPER_IFLE_ATM_LLC            5
#define JUNIPER_IFLE_ATM_PPP_VCMUX      6
#define JUNIPER_IFLE_ATM_PPP_LLC        7
#define JUNIPER_IFLE_ATM_PPP_FUNI       8
#define JUNIPER_IFLE_ATM_CCC            9
#define JUNIPER_IFLE_FR_NLPID           10
#define JUNIPER_IFLE_FR_SNAP            11
#define JUNIPER_IFLE_FR_PPP             12
#define JUNIPER_IFLE_FR_CCC             13
#define JUNIPER_IFLE_ENET2              14
#define JUNIPER_IFLE_IEEE8023_SNAP      15
#define JUNIPER_IFLE_IEEE8023_LLC       16
#define JUNIPER_IFLE_PPP                17
#define JUNIPER_IFLE_CISCOHDLC          18
#define JUNIPER_IFLE_PPP_CCC            19
#define JUNIPER_IFLE_IPIP_NULL          20
#define JUNIPER_IFLE_PIM_NULL           21
#define JUNIPER_IFLE_GRE_NULL           22
#define JUNIPER_IFLE_GRE_PPP            23
#define JUNIPER_IFLE_PIMD_DECAPS        24
#define JUNIPER_IFLE_CISCOHDLC_CCC      25
#define JUNIPER_IFLE_ATM_CISCO_NLPID    26
#define JUNIPER_IFLE_VLAN_CCC           27
#define JUNIPER_IFLE_MLPPP              28
#define JUNIPER_IFLE_MLFR               29
#define JUNIPER_IFLE_LSI_NULL           30
#define JUNIPER_IFLE_AGGREGATE_UNUSED   31
#define JUNIPER_IFLE_ATM_CELLRELAY_CCC  32
#define JUNIPER_IFLE_CRYPTO             33
#define JUNIPER_IFLE_GGSN               34
#define JUNIPER_IFLE_ATM_TCC            35
#define JUNIPER_IFLE_FR_TCC             36
#define JUNIPER_IFLE_PPP_TCC            37
#define JUNIPER_IFLE_CISCOHDLC_TCC      38
#define JUNIPER_IFLE_ETHERNET_CCC       39
#define JUNIPER_IFLE_VT                 40
#define JUNIPER_IFLE_ATM_EOA_LLC        41
#define JUNIPER_IFLE_EXTENDED_VLAN_CCC          42
#define JUNIPER_IFLE_ATM_SNAP_TCC       43
#define JUNIPER_IFLE_MONITOR            44
#define JUNIPER_IFLE_ETHERNET_TCC       45
#define JUNIPER_IFLE_VLAN_TCC           46
#define JUNIPER_IFLE_EXTENDED_VLAN_TCC  47
#define JUNIPER_IFLE_MFR                48
#define JUNIPER_IFLE_ETHERNET_VPLS      49
#define JUNIPER_IFLE_ETHERNET_VLAN_VPLS 50
#define JUNIPER_IFLE_ETHERNET_EXTENDED_VLAN_VPLS 51
#define JUNIPER_IFLE_SERVICES           52
#define JUNIPER_IFLE_ATM_ETHER_VPLS_ATM_LLC                53
#define JUNIPER_IFLE_FR_PORT_CCC        54
#define JUNIPER_IFLE_ATM_MLPPP_LLC      55
#define JUNIPER_IFLE_ATM_EOA_CCC        56
#define JUNIPER_IFLE_LT_VLAN            57
#define JUNIPER_IFLE_COLLECTOR          58
#define JUNIPER_IFLE_AGGREGATOR         59
#define JUNIPER_IFLE_LAPD               60
#define JUNIPER_IFLE_ATM_PPPOE_LLC          61
#define JUNIPER_IFLE_ETHERNET_PPPOE         62
#define JUNIPER_IFLE_PPPOE                  63
#define JUNIPER_IFLE_PPP_SUBORDINATE        64
#define JUNIPER_IFLE_CISCOHDLC_SUBORDINATE  65
#define JUNIPER_IFLE_DFC                    66
#define JUNIPER_IFLE_PICPEER                67

struct tok juniper_ifle_values[] = {
    { JUNIPER_IFLE_AGGREGATOR, "Aggregator" },
    { JUNIPER_IFLE_ATM_CCC, "CCC over ATM" },
    { JUNIPER_IFLE_ATM_CELLRELAY_CCC, "ATM CCC Cell Relay" },
    { JUNIPER_IFLE_ATM_CISCO_NLPID, "CISCO compatible NLPID" },
    { JUNIPER_IFLE_ATM_EOA_CCC, "Ethernet over ATM CCC" },
    { JUNIPER_IFLE_ATM_EOA_LLC, "Ethernet over ATM LLC" },
    { JUNIPER_IFLE_ATM_ETHER_VPLS_ATM_LLC, "Ethernet VPLS over ATM LLC" },
    { JUNIPER_IFLE_ATM_LLC, "ATM LLC" },
    { JUNIPER_IFLE_ATM_MLPPP_LLC, "MLPPP over ATM LLC" },
    { JUNIPER_IFLE_ATM_NLPID, "ATM NLPID" },
    { JUNIPER_IFLE_ATM_PPPOE_LLC, "PPPoE over ATM LLC" },
    { JUNIPER_IFLE_ATM_PPP_FUNI, "PPP over FUNI" },
    { JUNIPER_IFLE_ATM_PPP_LLC, "PPP over ATM LLC" },
    { JUNIPER_IFLE_ATM_PPP_VCMUX, "PPP over ATM VCMUX" },
    { JUNIPER_IFLE_ATM_SNAP, "ATM SNAP" },
    { JUNIPER_IFLE_ATM_SNAP_TCC, "ATM SNAP TCC" },
    { JUNIPER_IFLE_ATM_TCC, "ATM VCMUX TCC" },
    { JUNIPER_IFLE_ATM_VCMUX, "ATM VCMUX" },
    { JUNIPER_IFLE_CISCOHDLC, "C-HDLC" },
    { JUNIPER_IFLE_CISCOHDLC_CCC, "C-HDLC CCC" },
    { JUNIPER_IFLE_CISCOHDLC_SUBORDINATE, "C-HDLC via dialer" },
    { JUNIPER_IFLE_CISCOHDLC_TCC, "C-HDLC TCC" },
    { JUNIPER_IFLE_COLLECTOR, "Collector" },
    { JUNIPER_IFLE_CRYPTO, "Crypto" },
    { JUNIPER_IFLE_ENET2, "Ethernet" },
    { JUNIPER_IFLE_ETHERNET_CCC, "Ethernet CCC" },
    { JUNIPER_IFLE_ETHERNET_EXTENDED_VLAN_VPLS, "Extended VLAN VPLS" },
    { JUNIPER_IFLE_ETHERNET_PPPOE, "PPPoE over Ethernet" },
    { JUNIPER_IFLE_ETHERNET_TCC, "Ethernet TCC" },
    { JUNIPER_IFLE_ETHERNET_VLAN_VPLS, "VLAN VPLS" },
    { JUNIPER_IFLE_ETHERNET_VPLS, "VPLS" },
    { JUNIPER_IFLE_EXTENDED_VLAN_CCC, "Extended VLAN CCC" },
    { JUNIPER_IFLE_EXTENDED_VLAN_TCC, "Extended VLAN TCC" },
    { JUNIPER_IFLE_FR_CCC, "FR CCC" },
    { JUNIPER_IFLE_FR_NLPID, "FR NLPID" },
    { JUNIPER_IFLE_FR_PORT_CCC, "FR CCC" },
    { JUNIPER_IFLE_FR_PPP, "FR PPP" },
    { JUNIPER_IFLE_FR_SNAP, "FR SNAP" },
    { JUNIPER_IFLE_FR_TCC, "FR TCC" },
    { JUNIPER_IFLE_GGSN, "GGSN" },
    { JUNIPER_IFLE_GRE_NULL, "GRE NULL" },
    { JUNIPER_IFLE_GRE_PPP, "PPP over GRE" },
    { JUNIPER_IFLE_IPIP_NULL, "IPIP" },
    { JUNIPER_IFLE_LAPD, "LAPD" },
    { JUNIPER_IFLE_LSI_NULL, "LSI Null" },
    { JUNIPER_IFLE_LT_VLAN, "LT VLAN" },
    { JUNIPER_IFLE_MFR, "MFR" },
    { JUNIPER_IFLE_MLFR, "MLFR" },
    { JUNIPER_IFLE_MLPPP, "MLPPP" },
    { JUNIPER_IFLE_MONITOR, "Monitor" },
    { JUNIPER_IFLE_PIMD_DECAPS, "PIMd" },
    { JUNIPER_IFLE_PIM_NULL, "PIM Null" },
    { JUNIPER_IFLE_PPP, "PPP" },
    { JUNIPER_IFLE_PPPOE, "PPPoE" },
    { JUNIPER_IFLE_PPP_CCC, "PPP CCC" },
    { JUNIPER_IFLE_PPP_SUBORDINATE, "" },
    { JUNIPER_IFLE_PPP_TCC, "PPP TCC" },
    { JUNIPER_IFLE_SERVICES, "General Services" },
    { JUNIPER_IFLE_VLAN_CCC, "VLAN CCC" },
    { JUNIPER_IFLE_VLAN_TCC, "VLAN TCC" },
    { JUNIPER_IFLE_VT, "VT" },
    {0,                    NULL}
};

struct juniper_cookie_table_t {
    u_int32_t pictype;		/* pic type */
    u_int8_t  cookie_len;       /* cookie len */
    const char *s;		/* pic name */
};

static struct juniper_cookie_table_t juniper_cookie_table[] = {
#ifdef DLT_JUNIPER_ATM1
    { DLT_JUNIPER_ATM1,  4, "ATM1"},
#endif
#ifdef DLT_JUNIPER_ATM2
    { DLT_JUNIPER_ATM2,  8, "ATM2"},
#endif
#ifdef DLT_JUNIPER_MLPPP
    { DLT_JUNIPER_MLPPP, 2, "MLPPP"},
#endif
#ifdef DLT_JUNIPER_MLFR
    { DLT_JUNIPER_MLFR,  2, "MLFR"},
#endif
#ifdef DLT_JUNIPER_MFR
    { DLT_JUNIPER_MFR,   4, "MFR"},
#endif
#ifdef DLT_JUNIPER_PPPOE
    { DLT_JUNIPER_PPPOE, 0, "PPPoE"},
#endif
#ifdef DLT_JUNIPER_PPPOE_ATM
    { DLT_JUNIPER_PPPOE_ATM, 0, "PPPoE ATM"},
#endif
#ifdef DLT_JUNIPER_GGSN
    { DLT_JUNIPER_GGSN, 8, "GGSN"},
#endif
#ifdef DLT_JUNIPER_MONITOR
    { DLT_JUNIPER_MONITOR, 8, "MONITOR"},
#endif
#ifdef DLT_JUNIPER_SERVICES
    { DLT_JUNIPER_SERVICES, 8, "AS"},
#endif
#ifdef DLT_JUNIPER_ES
    { DLT_JUNIPER_ES, 0, "ES"},
#endif
    { 0, 0, NULL }
};

struct juniper_l2info_t {
    u_int32_t length;
    u_int32_t caplen;
    u_int32_t pictype;
    u_int8_t direction;
    u_int8_t header_len;
    u_int8_t cookie_len;
    u_int8_t cookie_type;
    u_int8_t cookie[8];
    u_int8_t bundle;
    u_int16_t proto;
    u_int8_t flags;
};

#define LS_COOKIE_ID            0x54
#define AS_COOKIE_ID            0x47
#define LS_MLFR_COOKIE_LEN	4
#define ML_MLFR_COOKIE_LEN	2
#define LS_MFR_COOKIE_LEN	6
#define ATM1_COOKIE_LEN         4
#define ATM2_COOKIE_LEN         8

#define ATM2_PKT_TYPE_MASK  0x70
#define ATM2_GAP_COUNT_MASK 0x3F

#define JUNIPER_PROTO_NULL          1
#define JUNIPER_PROTO_IPV4          2
#define JUNIPER_PROTO_IPV6          6

#define MFR_BE_MASK 0xc0
/*
static struct tok juniper_protocol_values[] = {
    { JUNIPER_PROTO_NULL, "Null" },
    { JUNIPER_PROTO_IPV4, "IPv4" },
    { JUNIPER_PROTO_IPV6, "IPv6" },
    { 0, NULL}
};
*/

int ip_heuristic_guess(register const u_char *, u_int);
int juniper_ppp_heuristic_guess(register const u_char *, u_int);
int juniper_read_tlv_value(const u_char *, u_int, u_int);
static int juniper_parse_header (const u_char *, const struct pcap_pkthdr *, struct juniper_l2info_t *);

#endif


#define ARGUS_HOLDING	1

struct ArgusSourceStruct {
   int state, status, proc;
 
   struct ArgusListStruct *ArgusDeviceList;
   struct ArgusListStruct *ArgusRfileList;
   struct ArgusModelerStruct *ArgusModel;
 
   char *ArgusInputFilter;

   struct ArgusAddrStruct ArgusID;
   int ArgusPcapBufSize, type, mode;

   struct timeval ArgusStartTime, ArgusEndTime, marktime, lasttime;

   int ArgusSnapLength, ArgusThisLength;
   unsigned char *ArgusThisSnapEnd;

   struct ieee80211_radiotap ArgusThisRadioTap;

   unsigned char ArgusInterfaceType;
   unsigned char ArgusInterfaceStatus;
  
   int Argustflag, sNflag, eNflag, kflag, pflag, uflag, tflag;
   float Tflag;

   pcap_if_t *ArgusPacketDevices;
   pcap_if_t *ArgusDevice;

   int ArgusInterfaceIndex, ArgusThisIndex, ArgusInterfaces;
   struct ArgusInterfaceStruct ArgusInterface[ARGUS_MAXINTERFACE];
   struct ArgusSourceStruct *srcs[ARGUS_MAXINTERFACE];

#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
   pthread_cond_t cond;
#endif

#if defined(ARGUS_TILERA)
  netio_queue_t queue;
#endif

   int ArgusInputPacketFileType;
   int ArgusReadingOffLine;
   int Argusbpflag, ArgusCaptureFlag;
   int Argusfflag, ArgusDumpPacket;
   int ArgusDumpPacketOnError;
   unsigned long ArgusPacketOffset;
  
   FILE *ArgusPacketInput;
   long ArgusInputOffset;
 
   int ArgusSnapLen, ArgusOflag, Arguspflag;
   char **ArgusArgv;
   int ArgusOptind;
   char *ArgusCmdBuf;

   char *ArgusWriteOutPacketFile;
   pcap_dumper_t *ArgusPcapOutFile;
};


void ArgusParseSourceID (struct ArgusSourceStruct *, char *);

int ArgusSnoopRead (struct ArgusSourceStruct *);

void ArgusIpPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusArcnetPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusEtherPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusTokenPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusAtmClipPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusLoopPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusHdlcPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusSlipPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusPppPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusPppBsdosPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusFddiPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusATMPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusSllPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusPppHdlcPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusPppEtherPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void Argus802_11Packet (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusLtalkPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusPrismPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void Argus802_11RadioPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void Argus802_11RadioAvsPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusEncPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusDagPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusJuniperPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusIpNetPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);
void ArgusNullPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p);


struct callback {
   pcap_handler function;
   int type;
   char *fname;
};

void ArgusSourceProcess (struct ArgusSourceStruct *);
void *ArgusGetPackets (void *);
struct ArgusDeviceStruct *ArgusCloneDevice(struct ArgusDeviceStruct *);


int ArgusOpenInputPacketFile(struct ArgusSourceStruct *, struct ArgusDeviceStruct *, struct ArgusInterfaceStruct *);

pcap_handler Arguslookup_pcap_callback (int);
pcap_handler Arguslookup_dag_callback (int);
void Argusbpf_dump(struct bpf_program *, int);

void setArgusRealTime (struct ArgusSourceStruct *, float value);
float getArgusRealTime (struct ArgusSourceStruct *);

unsigned int getArgusID(struct ArgusSourceStruct *);
unsigned int getArgusIDType(struct ArgusSourceStruct *);

void setArgusID(struct ArgusSourceStruct *src, void *ptr, unsigned int type);

void setArgusMoatTshFile (struct ArgusSourceStruct *, int value);
int getArgusMoatTshFile (struct ArgusSourceStruct *);

void setArgusWriteOutPacketFile (struct ArgusSourceStruct *, char *);



unsigned char getArgusInterfaceType(struct ArgusSourceStruct *);
void setArgusInterfaceType(struct ArgusSourceStruct *, unsigned char);
 
unsigned char getArgusInterfaceStatus(struct ArgusSourceStruct *);
void setArgusInterfaceStatus(struct ArgusSourceStruct *, unsigned char);


#if defined(ArgusSource)

static struct callback ArgusSourceCallbacks[] = {
#if defined(ARGUS_TILERA)
#else
   { ArgusArcnetPacket,    DLT_ARCNET,      "ArgusArcnetPacket()" },
   { ArgusEtherPacket,     DLT_EN10MB,      "ArgusEtherPacket()" },
   { ArgusTokenPacket,     DLT_IEEE802,     "ArgusTokenPacket()" },
   { ArgusSlipPacket,      DLT_SLIP,        "ArgusSlipPacket()" },
   { ArgusSlipPacket,      DLT_SLIP_BSDOS,  "ArgusSlipPacket()" },
   { ArgusPppPacket,       DLT_PPP,         "ArgusPppPacket()" },
   { ArgusPppBsdosPacket,  DLT_PPP_BSDOS,   "ArgusPppBsdosPacket()" },
   { ArgusFddiPacket,      DLT_FDDI,        "ArgusFddiPacket()" },
   { ArgusATMPacket,       DLT_ATM_RFC1483, "ArgusATMPacket()" },
   { ArgusIpPacket,        DLT_RAW,         "ArgusIpPacket()" },
   { ArgusNullPacket,      DLT_NULL,        "ArgusNullPacket()" },
#ifdef DLT_ENC
   { ArgusEncPacket,       DLT_ENC,         "ArgusEncPacket()" },
#endif
#ifdef DLT_LANE8023
   { ArgusLanePacket,      DLT_LANE8023,    "ArgusLanePacket()" },
#endif
#ifdef DLT_CIP
   { ArgusCipPacket,       DLT_CIP,         "ArgusCipPacket()" },
#endif
#ifdef DLT_ATM_CLIP
   { ArgusAtmClipPacket,   DLT_ATM_CLIP,    "ArgusAtmClipPacket()" },
#endif
#ifdef DLT_LINUX_SLL
   { ArgusSllPacket,       DLT_LINUX_SLL,   "ArgusSllPacket()" },
#endif
#ifdef DLT_LOOP
   { ArgusLoopPacket,      DLT_LOOP,        "ArgusLoopPacket()" },
#endif
#ifdef DLT_C_HDLC
   { ArgusHdlcPacket,      DLT_C_HDLC,      "ArgusHdlcPacket()" },
#endif
#ifdef DLT_HDLC
   { ArgusHdlcPacket,      DLT_HDLC,        "ArgusHdlcPacket()" },
#endif
#ifdef DLT_PPP_SERIAL
   { ArgusPppHdlcPacket,   DLT_PPP_SERIAL,  "ArgusPppHdlcPacket()" },
#endif
#ifdef DLT_PPP_ETHER
   { ArgusPppEtherPacket,  DLT_PPP_ETHER,   "ArgusPppEtherPacket()" },
#endif
#ifdef DLT_LINUX_SLL
   { ArgusSllPacket,       DLT_LINUX_SLL,   "ArgusSllPacket()" },
#endif
#ifdef DLT_IEEE802_11
   { Argus802_11Packet,    DLT_IEEE802_11,  "Argus802_11Packet()"},
#endif
#ifdef DLT_PRISM_HEADER
   { ArgusPrismPacket,     DLT_PRISM_HEADER, "ArgusPrismPacket()" },
#endif
#ifdef DLT_IEEE802_11_RADIO
   { Argus802_11RadioPacket, DLT_IEEE802_11_RADIO, "Argus802_11RadioPacket()" },
#endif
#ifdef DLT_IEEE802_11_RADIO_AVS
   { Argus802_11RadioAvsPacket, DLT_IEEE802_11_RADIO_AVS, "Argus802_11RadioAvsPacket()" },
#endif
#ifdef DLT_LTALK
   { ArgusLtalkPacket,     DLT_LTALK,       "ArgusLtalkPacket()" },
#endif
#ifdef DLT_JUNIPER_ETHER
   { ArgusJuniperPacket,   DLT_JUNIPER_ETHER,  "ArgusJuniperPacket()" },
#endif
#ifdef DLT_IPNET
   { ArgusIpNetPacket,   DLT_IPNET,  "ArgusIpNetPacket()" },
#endif
   { NULL, DLT_NULL, "" },
#endif
   { NULL, 0, NULL},
};

extern int Argustflag;

struct ArgusSourceStruct *ArgusSourceTask = NULL;

struct ArgusSourceStruct *ArgusNewSource(struct ArgusModelerStruct *);
struct ArgusSourceStruct *ArgusCloneSource(struct ArgusSourceStruct *);
int ArgusInitSource(struct ArgusSourceStruct *);
int ArgusCloseSource(struct ArgusSourceStruct *);
void ArgusDeleteSource(struct ArgusSourceStruct *);

extern char *ArgusCopyArgv (char **argv);

void setArgusOutputTask(void);
void setArgusModeler(struct ArgusSourceStruct *);

 
struct ArgusOutputStruct *getArgusOutputTask(void);
struct ArgusModelerStruct *getArgusModeler(struct ArgusSourceStruct *);

int getArgusSnapLen(struct ArgusSourceStruct *);
void setArgusSnapLen(struct ArgusSourceStruct *, int);

int getArgusbpflag(struct ArgusSourceStruct *);
int getArgusfflag(struct ArgusSourceStruct *);
int getArguspflag(struct ArgusSourceStruct *);
int getArgusOflag(struct ArgusSourceStruct *);

void setArgusbpflag(struct ArgusSourceStruct *, int);
void setArgusfflag(struct ArgusSourceStruct *, int);
void setArguspflag(struct ArgusSourceStruct *, int);
void setArgusOflag(struct ArgusSourceStruct *, int);
void setArgusCaptureFlag(struct ArgusSourceStruct *, int);

void setArgusDevice(struct ArgusSourceStruct *, char *, int, int);
void setArgusInfile(struct ArgusSourceStruct *, char *);
void setArgusrfile(struct ArgusSourceStruct *, char *);
void setArgusrFile(struct ArgusSourceStruct *, char *);

char *getArgusDevice(struct ArgusSourceStruct *);
char *getArgusInfile(struct ArgusSourceStruct *);
char *getArgusrfile(struct ArgusSourceStruct *);

void clearArgusDevice(struct ArgusSourceStruct *);

int ArgusCreatePktFromFddi(const struct fddi_header *, struct ether_header *, int);


#else /* defined(ArgusSource) */

extern struct ArgusSourceStruct *ArgusSourceTask;

extern long long ArgusTotalPkts;
extern long long ArgusLastPkts;
extern long long ArgusTotalDrop;
extern long long ArgusLastDrop;
extern long long ArgusTotalBytes;
extern long long ArgusLastBytes;

extern struct ArgusSourceStruct *ArgusSourceTask;

extern struct ArgusSourceStruct *ArgusNewSource(struct ArgusModelerStruct *);
extern struct ArgusSourceStruct *ArgusCloneSource(struct ArgusSourceStruct *);
extern int ArgusInitSource(struct ArgusSourceStruct *);
extern int ArgusCloseSource(struct ArgusSourceStruct *);
extern void ArgusDeleteSource(struct ArgusSourceStruct *);

extern struct ArgusOutputStruct *getArgusOutputTask(struct ArgusSourceStruct *);
extern void setArgusOutputTask(struct ArgusSourceStruct *);

extern struct ArgusModelerStruct *getArgusModeler(struct ArgusSourceStruct *);
extern void setArgusModeler(struct ArgusSourceStruct *);

extern int getArgusSnapLen(struct ArgusSourceStruct *);
extern void setArgusSnapLen(struct ArgusSourceStruct *, int);

extern int getArgusbpflag(struct ArgusSourceStruct *);
extern int getArgusfflag(struct ArgusSourceStruct *);
extern int getArguspflag(struct ArgusSourceStruct *);
extern int getArgusOflag(struct ArgusSourceStruct *);
extern int getArgusMoatTshFile (struct ArgusSourceStruct *);

extern void setArgusbpflag(struct ArgusSourceStruct *, int);
extern void setArgusfflag(struct ArgusSourceStruct *, int);
extern void setArguspflag(struct ArgusSourceStruct *, int);
extern void setArgusOflag(struct ArgusSourceStruct *, int);
extern void setArgusCaptureFlag(struct ArgusSourceStruct *, int);
extern void setArgusMoatTshFile (struct ArgusSourceStruct *, int value);

extern void setArgusWriteOutPacketFile (struct ArgusSourceStruct *, char *);

extern void setArgusDevice(struct ArgusSourceStruct *, char *, int, int);
extern void setArgusInfile(struct ArgusSourceStruct *, char *);
extern void setArgusrfile(struct ArgusSourceStruct *, char *);

extern char *getArgusDevice(struct ArgusSourceStruct *);
extern char *getArgusInfile(struct ArgusSourceStruct *);
extern char *getArgusrfile(struct ArgusSourceStruct *);

extern void clearArgusDevice(struct ArgusSourceStruct *);

#endif
#endif /* #ifndef ArgusSource_h */
