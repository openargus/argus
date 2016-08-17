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
 * $Id: //depot/argus/argus/include/argus_out.h#53 $
 * $DateTime: 2015/08/05 22:33:18 $
 * $Change: 3042 $
 */


#if !defined(Argus_out_h)
#define Argus_out_h

#include <argus_compat.h>

#if defined(HAVE_SOLARIS) || defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#endif

#include <argus_util.h>

#if defined(__OpenBSD__)
#include <netinet/in.h>
#endif

#include <netinet/if_ether.h>
#include <netinet/rtp.h>

#include <argus_llc.h>
#include <argus_isis.h>
#include <argus_udt.h>

#include <sys/time.h>
#pragma pack(2)

struct ArgusDSRfixLen {
   unsigned short data;
};

struct ArgusDSRvar8bitLen {
   unsigned char qual;
   unsigned char len;
};

struct ArgusDSRvar16bitLen {
   unsigned short len;
};

struct ArgusDSRHeader {
   unsigned char type;
   unsigned char subtype;
   union {
      struct ArgusDSRfixLen fl;
      struct ArgusDSRvar8bitLen  vl8;
      struct ArgusDSRvar16bitLen vl16;
   } dsr_un;
};

struct ArgusSystemDSRHeader {
   unsigned char type;
   unsigned char subtype;
   union {
      struct ArgusDSRfixLen      fl;
      struct ArgusDSRvar8bitLen  vl8;
      struct ArgusDSRvar16bitLen vl16;
   } dsr_un;
#if defined(ALIGN_64BIT)
   int pad[3];
#endif
};

struct ArgusTime {
   unsigned int tv_sec, tv_usec;
};

#define argus_dsrfl	dsr_un.fl
#define argus_dsrvl8	dsr_un.vl8
#define argus_dsrvl16	dsr_un.vl16

struct ArgusICMPObject {
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusICMPv6Object {
   unsigned char icmp_type, icmp_code;
   unsigned short cksum;
};

struct ArgusTCPInitStatus {
   unsigned int status, seqbase;
   unsigned int options;
   unsigned short win; 
   unsigned char flags, winshift;
};

struct ArgusTCPStatus {
   unsigned int status;
   unsigned char src, dst, pad[2];
};

struct ArgusTCPObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int status, seqbase, seq, ack, winnum;
   unsigned int bytes, retrans, ackbytes, winbytes;
   unsigned short win;
   unsigned char flags, winshift;
};
 
struct ArgusTCPObject {
   unsigned int status;
   unsigned int state, options;
   unsigned int synAckuSecs, ackDatauSecs;
   struct ArgusTCPObjectMetrics src, dst;
};

struct ArgusUDTObjectMetrics {
   struct ArgusTime lasttime;
   unsigned int seq, tstamp, ack, rtt, var, bsize, rate, lcap;
   int solo, first, middle, last, drops, retrans, nacked;
};

struct ArgusUDTObject {
   unsigned int state, status;
   struct udt_control_handshake hshake;
   struct ArgusUDTObjectMetrics src, dst;
};


struct ArgusRTPObject {
   unsigned int state;
   struct rtphdr  src, dst;
   unsigned short sdrop, ddrop;
   unsigned short ssdev, dsdev;
};
 
struct ArgusRTCPObject {
   struct rtcphdr src, dst;
   unsigned short sdrop, ddrop;
};

struct ArgusIGMPObjectV1 {
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
};

struct ArgusIGMPObject {
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
   struct ArgusTime jdelay;
   struct ArgusTime ldelay;
};

struct ArgusFragOffsetStruct {
   struct ArgusFragOffsetStruct *nxt;
   int start, end;
};

struct ArgusFragObject {
   unsigned int fragnum, frag_id;
   unsigned int startbytes, bytes, totbytes;
   unsigned short totlen, currlen, maxfraglen, pad;

   struct ArgusFlowStruct *parent;
   struct ArgusFragOffsetStruct offsets;
};

struct ArgusIsisLspFlow {
   unsigned char  lspid[LSP_ID_LEN];
   unsigned int   seqnum;
};

struct ArgusIsisHelloFlow {
  unsigned char srcid[SYSTEM_ID_LEN];
  unsigned char lanid[NODE_ID_LEN];
  u_int8_t circuit_id; /* for point-to-point */
};

struct ArgusIsisCsnpFlow {
   unsigned char srcid[NODE_ID_LEN];
};

struct ArgusIsisPsnpFlow {
   unsigned char srcid[NODE_ID_LEN];
};

struct ArgusIsisFlow {
   int pdu_type;
   char esrc[ETHER_ADDR_LEN], edst[ETHER_ADDR_LEN];
   char proto_version, pad[3];
   union {
      struct ArgusIsisHelloFlow hello;
      struct ArgusIsisLspFlow   lsp;
      struct ArgusIsisCsnpFlow  csnp;
      struct ArgusIsisPsnpFlow  psnp;
   } isis_un;
   int chksum;
};

struct ArgusESPObject {
   unsigned int status, spi, lastseq, lostseq;
};

struct ArgusARPObject { 
   unsigned char respaddr[6];    
   unsigned short pad; 
};  
 
struct ArgusDHCPObject {     
   unsigned int respaddr;   
};  

struct ArgusAHObject {
   unsigned int src_spi, dst_spi;
   unsigned int src_replay, dst_replay;
};

struct ArgusLcpFlow {
   struct ether_header ehdr;
   unsigned char code, id;
};

struct ArgusEtherMacFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct Argus80211MacFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct ArgusMacFlow {
   union {
      struct ArgusEtherMacFlow ether;
      struct Argus80211MacFlow wlan;
   } mac_union;
};

struct ArgusWlanFlow {
   unsigned char dhost[ETHER_ADDR_LEN];
   unsigned char shost[ETHER_ADDR_LEN];
   unsigned char bssid[ETHER_ADDR_LEN];
   unsigned char ssid[32];
};

struct ArgusIPAttrObject {
   unsigned char ttl, tos;
   unsigned short ip_id;
   unsigned short status;
   unsigned short options;
};


struct ArgusIsisObject {
   struct isis_common_header common;
   union {
      struct isis_iih_lan_header iih_lan;
      struct isis_iih_ptp_header iih_ptp;
      struct isis_lsp_header lsp;
      struct isis_csnp_header csnp;
      struct isis_psnp_header psnp;
   } isis_un;
};

struct ArgusLCPObject {
   unsigned int status;
   unsigned int state, options;
};

#include <argus/ieee802_11.h>

struct Argus80211Beacon {
   u_int8_t        timestamp[IEEE802_11_TSTAMP_LEN];
   u_char          ap[IEEE802_11_AP_LEN];

   u_int16_t       beacon_interval, listen_interval;
   u_int16_t       status_code, aid, reason_code;
   u_int16_t       auth_alg, auth_trans_seq_num;
   u_int16_t       capability_info;
   elem_status_t   challenge_status;
   struct challenge_t  challenge;
   elem_status_t   ssid_status;
   struct ssid_t   ssid;
   elem_status_t   rates_status;
   struct rates_t  rates;
   elem_status_t   ds_status;
   struct ds_t     ds;
   elem_status_t   cf_status;
   struct cf_t     cf;
   elem_status_t   fh_status;
   struct fh_t     fh;
   elem_status_t   tim_status;
   struct tim_t    tim;
};

struct Argus80211Probe {
};

struct Argus80211Object {
   union {
      struct Argus80211Beacon beacon;
      struct Argus80211Probe  probe;
   } o_un;
};

struct ArgusESPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad;
   unsigned int spi;
};

struct ArgusESPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned int spi;
};

struct ArgusHAddr {
   union {
      unsigned char ethernet[6];
      unsigned char ib[32];
      unsigned char ieee1394[16];
      unsigned char framerelay[4];
      unsigned char tokenring[6];
      unsigned char arcnet[1];
      unsigned char fiberchannel[12];
      unsigned char atm[20];
   } h_un;
};
 
struct ArgusArpFlow {
   unsigned short    hrd;
   unsigned short    pro;
   unsigned char     hln;
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_spa;
   unsigned int      arp_tpa;
   struct ArgusHAddr haddr;
};
 
struct ArgusRarpFlow {
   unsigned short    hrd;
   unsigned short    pro;
   unsigned char     hln;
   unsigned char     pln;
   unsigned short    op;
   unsigned int      arp_tpa;
   struct ArgusHAddr shaddr;
   struct ArgusHAddr dhaddr;
};

struct ArgusICMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short id, ip_id;
};

struct ArgusICMPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned char type, code;
   unsigned short id;
};


struct ArgusIPFragFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad[2];
   unsigned short ip_id;
};

struct ArgusIPv6FragFlow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned int ip_id;
};

struct ArgusIGMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short pad, ip_id;
};

struct ArgusIGMPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned char type, code;
   unsigned short pad;
};
 
struct ArgusIPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short sport, dport;
   unsigned char smask, dmask;
};

struct ArgusIPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif
   unsigned short sport, dport;
};

struct ArgusUdtFlow {
   struct ArgusMacFlow mac;
   unsigned int sockid;
};


struct ArgusFlow {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusIPv6Flow       ipv6;
      struct ArgusIPFlow           ip;
      struct ArgusEtherMacFlow    mac;
      struct ArgusICMPv6Flow   icmpv6;
      struct ArgusICMPFlow       icmp;
      struct ArgusIGMPv6Flow   igmpv6;
      struct ArgusIGMPFlow       igmp;
      struct ArgusESPv6Flow     espv6;
      struct ArgusESPFlow         esp;
      struct ArgusArpFlow         arp;
      struct ArgusRarpFlow       rarp;
      struct ArgusIPv6FragFlow fragv6;
      struct ArgusIPFragFlow     frag;
      struct ArgusLcpFlow         lcp;
      struct ArgusIsisFlow       isis;
      struct ArgusWlanFlow       wlan;
      struct ArgusUdtFlow         udt;
  } flow_un;
};

struct ArgusSystemFlow {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusIPv6Flow       ipv6;
      struct ArgusIPFlow           ip;
      struct ArgusEtherMacFlow    mac;
      struct ArgusICMPv6Flow   icmpv6;
      struct ArgusICMPFlow       icmp;
      struct ArgusIGMPv6Flow   igmpv6;
      struct ArgusIGMPFlow       igmp;
      struct ArgusESPv6Flow     espv6;
      struct ArgusESPFlow         esp;
      struct ArgusArpFlow         arp;
      struct ArgusRarpFlow       rarp;
      struct ArgusIPv6FragFlow fragv6;
      struct ArgusIPFragFlow     frag;
      struct ArgusLcpFlow         lcp;
      struct ArgusIsisFlow       isis;
      struct ArgusWlanFlow       wlan;
      struct ArgusUdtFlow         udt;
  } flow_un;
#if defined(ALIGN_64BIT)
   int tail[1]; 
#endif
};

#define    ipv6_flow flow_un.ipv6
#define      ip_flow flow_un.ip
#define  icmpv6_flow flow_un.icmpv6
#define    icmp_flow flow_un.icmp
#define    igmp_flow flow_un.igmp
#define   igmp6_flow flow_un.igmpv6
#define     mac_flow flow_un.mac
#define     arp_flow flow_un.arp
#define    rarp_flow flow_un.rarp
#define    esp6_flow flow_un.espv6
#define     esp_flow flow_un.esp
#define  fragv6_flow flow_un.fragv6
#define    frag_flow flow_un.frag
#define     lcp_flow flow_un.lcp
#define    isis_flow flow_un.isis
#define    wlan_flow flow_un.wlan
#define     udt_flow flow_un.udt


struct ArgusAddrStruct {
   union {
      unsigned int value;
      unsigned int ipv4;
      char str[4];
/*
      unsigned int ipv6[4];
      unsigned char ethersrc[6];
*/
   } a_un;
};

struct ArgusTransportStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusAddrStruct srcid;
   unsigned int seqnum;
};

struct ArgusTimeStruct {
   struct ArgusTime start, end;
};

struct ArgusEncapsStruct {
   struct ArgusDSRHeader hdr;
   unsigned int src, dst;
};

struct ArgusTimeObject {
   struct ArgusDSRHeader hdr;
   struct ArgusTimeStruct src, dst;
};

struct ArgusEventObject {
   struct ArgusDSRHeader hdr;

};

struct ArgusEventTimeStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusTime start;
   unsigned int duration;
};


struct ArgusUniStats {
   long long pkts, bytes, appbytes;
};

struct ArgusStatObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
   unsigned char fdist[8];
};

struct ArgusStatsObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
};

struct ArgusAgrStruct {
   struct ArgusDSRHeader hdr;
   unsigned int count;
   struct ArgusTime laststartime, lasttime;
   struct ArgusStatObject act, idle;
};


struct ArgusPacketSizeObject {
   unsigned short psizemin, psizemax;
};

struct ArgusPacketSizeStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusPacketSizeObject src, dst;
};

struct ArgusJitterObject {
   struct ArgusStatsObject src, dst;
};

struct ArgusJitterStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusJitterObject act, idle;
};

struct ArgusMacStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusMacFlow mac;
};
   
struct ArgusVlanStruct {
   struct ArgusDSRHeader hdr;
   unsigned short sid, did;
};
   
struct ArgusMplsStruct {
   struct ArgusDSRHeader hdr;
   unsigned int slabel;
   unsigned int dlabel;
}; 

struct ArgusIPAttrStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusIPAttrObject src, dst;
};

struct ArgusMetricStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusUniStats src, dst;
};
   
struct ArgusServiceStruct {
   struct ArgusDSRHeader hdr;
   char name[16];
};

struct ArgusDataStruct {
   struct ArgusDSRHeader hdr;
   unsigned short size, count;
   char array[8];
};

struct ArgusIcmpv6Struct {
   struct ArgusDSRHeader hdr;
   unsigned char icmp_type, icmp_code;
   unsigned short cksum;
};

struct ArgusIcmpStruct {
   struct ArgusDSRHeader hdr;
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusKeyStrokeMetrics {
   int n_strokes;
};

struct ArgusKeyStrokeStruct {
   struct ArgusKeyStrokeMetrics src, dst;
};

struct ArgusBehaviorStruct {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusKeyStrokeStruct keyStroke;
   } behavior_union;
};

#define     keyStroke behavior_union.keyStroke

struct ArgusCorMetrics {
   struct ArgusAddrStruct srcid;
   int deltaDur, deltaStart, deltaLast;
   int deltaSrcPkts, deltaDstPkts;
};

struct ArgusCorrelateStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusCorMetrics metrics;
};

struct ArgusCountryCodeStruct {
   struct ArgusDSRHeader hdr;
   char src[2], dst[2];
};

struct ArgusCoordinates {
   float lat, lon;
};

struct ArgusCoordinateRange {
   struct ArgusCoordinates max, min;
};

struct ArgusSiteLocation {
   unsigned int status;
   union {
      struct ArgusCoordinates cor;
      struct ArgusCoordinateRange range;
   } dist_union;
};

struct ArgusGeoLocationStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusSiteLocation src, dst;
};

struct ArgusLabelStruct {
   struct ArgusDSRHeader hdr;
   union {
      char *svc;
      char *label;
   }l_un;
};

struct ArgusIdStruct {
   int status;
   char name[64];
};

struct ArgusInputStruct {
   struct ArgusDSRHeader hdr;
   struct ArgusIdStruct id;
};


struct ArgusEventStruct {
   struct ArgusDSRHeader       event;   /* immediate data */
   struct ArgusTransportStruct trans;
   struct ArgusTimeObject       time;
   struct ArgusDataStruct       data;
};


struct ArgusMarStruct {
   unsigned int status, argusid;
   unsigned int localnet, netmask, nextMrSequenceNum;
   struct ArgusTime startime, now;
   unsigned char  major_version, minor_version;
   unsigned char interfaceType, interfaceStatus;
   unsigned short reportInterval, argusMrInterval;
   unsigned long long pktsRcvd, bytesRcvd;
   long long drift;

   unsigned int records, flows, dropped;
   unsigned int queue, output, clients;
   unsigned int bufs, bytes;
   unsigned short suserlen, duserlen;
   unsigned int pad[3];
   unsigned int thisid, record_len;
};

struct ArgusMarSupStruct {
   unsigned int status, argusid;
   struct ArgusTime startime, now;
   struct ArgusInputStruct input;
};

struct ArgusFarStruct {
   struct ArgusFlow flow;
};

/*
   The ArgusRecordHeader is composed of 4 4-bit fields, the
   type, version, cause and options fields.  For the purpose
   of portability, we define them as two char values, so that
   little endian machines don't mess up the order, and
   to avoid compiler problems with using bit fields.

   unsigned char type:4;
   unsigned char vers:4;
   unsigned char cause:4;
   unsigned char opt:4;
*/

struct ArgusRecordHeader {
   unsigned char type;
   unsigned char cause;
   u_int16_t len;
};

struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct    mar;
      struct ArgusMarSupStruct sup;
      struct ArgusFarStruct    far;
      struct ArgusEventStruct  event;
   } ar_un;
};

#define argus_mar       ar_un.mar
#define argus_sup       ar_un.sup
#define argus_far       ar_un.far
#define argus_event     ar_un.event

struct ArgusAsnStruct {
   struct ArgusDSRHeader hdr;
   uint32_t src_as;        /* originating AS of source address */
   uint32_t dst_as;        /* originating AS of destination address */
   uint32_t inode_as;      /* originating AS of intermediate node address, if present */
};


struct ArgusNetworkStruct {
   struct ArgusDSRHeader hdr;
   union {
      struct ArgusTCPInitStatus tcpinit;
      struct ArgusTCPStatus    tcpstatus;
      struct ArgusTCPObject    tcp;
      struct ArgusICMPObject   icmp;
      struct ArgusICMPv6Object icmpv6;
      struct ArgusUDTObject    udt;
      struct ArgusRTPObject    rtp;
      struct ArgusRTCPObject   rtcp;
      struct ArgusIGMPObject   igmp;
      struct ArgusDHCPObject   dhcp;
      struct ArgusESPObject    esp;
      struct ArgusARPObject    arp;
      struct ArgusAHObject     ah;
      struct ArgusFragObject   frag;
      struct ArgusLCPObject    lcp;
      struct ArgusIsisObject   isis;
   } net_union;
};


struct ArgusCanonRecord {
   struct ArgusRecordHeader      hdr;
   struct ArgusFlow              flow;
   struct ArgusTransportStruct   trans;
   struct ArgusTimeObject        time;
   struct ArgusEncapsStruct      encaps;
   struct ArgusAsnStruct         asn;
   struct ArgusIPAttrStruct      attr;
   struct ArgusMetricStruct      metric;
   struct ArgusNetworkStruct     net;
   struct ArgusMacStruct         mac;
   struct ArgusVlanStruct        vlan;
   struct ArgusMplsStruct        mpls;
   struct ArgusIcmpStruct        icmp;
   struct ArgusAgrStruct         agr;
   struct ArgusCorrelateStruct   cor;
   struct ArgusJitterStruct      jitter;
   struct ArgusPacketSizeStruct  psize;
   struct ArgusBehaviorStruct    actor;
   struct ArgusCountryCodeStruct cocode;
   struct ArgusLabelStruct       label;
   struct ArgusDataStruct        data;
};


#define ARGUS_NSR_STICKY                0x00100000
#define ARGUS_RECORD_MODIFIED           0x0100

struct ArgusRecordStruct {
   struct ArgusQueueHeader qhdr;
   unsigned int status, dsrindex, trans, autoid;
   unsigned short timeout, idle;
   struct RaBinProcessStruct *bins;
   struct ArgusInput *input;
   struct ArgusDSRHeader *dsrs[ARGUSMAXDSRTYPE];

   struct ArgusHashTableHdr *htblhdr;
   struct ArgusHashTableHdr *hinthdr;
   struct ArgusQueueStruct *nsq;
   struct ArgusRecordHeader hdr;
   struct ArgusCanonRecord canon;

   struct ArgusCorStruct *correlates;
   float srate, drate, sload, dload, dur, mean;
   float pcr, sploss, dploss;
   long long offset;
};


struct ArgusV2ETHERObject {
   unsigned char ethersrc[6];
   unsigned char etherdst[6];
};

struct ArgusV2MACFlow {
   struct ether_header ehdr;
   unsigned char dsap, ssap;
};

struct ArgusV2ESPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short pad;
   unsigned int spi;
};

struct ArgusV2ArpFlow {
   unsigned int arp_spa;
   unsigned int arp_tpa;
   unsigned char etheraddr[6];
   unsigned short pad;
};

struct ArgusV2RarpFlow {
   unsigned int arp_tpa;
   unsigned char srceaddr[6];
   unsigned char tareaddr[6];
};

struct ArgusV2ICMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short id, ip_id;
};

struct ArgusV2IGMPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned char type, code;
   unsigned short pad, ip_id;
};

struct ArgusV2IPFlow {
   unsigned int ip_src, ip_dst;
   unsigned char ip_p, tp_p;
   unsigned short sport, dport;
   unsigned short ip_id;
};

struct ArgusV2LoadObject {
   int n;
   float minval;
   float meanval;
   float stdev;
   float maxval;
};

struct ArgusV2LoadStruct {
   struct ArgusV2LoadObject pktsPerSec, bytesPerSec;
};

struct ArgusV2TimeObject {
   int n;
   unsigned int minval;
   unsigned int meanval;
   unsigned int stdev;
   unsigned int maxval;
};

struct ArgusV2TimeEntity {
   struct ArgusV2TimeObject act, idle;
};

struct ArgusV2AHObject {
   unsigned int src_spi, dst_spi;
   unsigned int src_replay, dst_replay;
};


struct ArgusV2ARPObject {
   unsigned char respaddr[6];
   unsigned short pad;
};

struct ArgusV2DHCPObject {
   unsigned int respaddr;
};

struct ArgusV2FragObject {
   unsigned char type, length;
   unsigned short status;
   int fragnum, frag_id;
   unsigned short ip_id, totlen, currlen, maxfraglen;
};

struct ArgusV2ICMPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned char icmp_type, icmp_code;
   unsigned short iseq;
   unsigned int osrcaddr, odstaddr;
   unsigned int isrcaddr, idstaddr;
   unsigned int igwaddr;
};

struct ArgusV2TCPObjectMetrics {
   unsigned int seqbase, ackbytes;
   unsigned int bytes, rpkts;
   unsigned short win;
   unsigned char flags, pad;
};

struct ArgusV2TCPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned int state;
   unsigned int options;
   unsigned int synAckuSecs, ackDatauSecs;
   struct ArgusV2TCPObjectMetrics src, dst;
};

struct ArgusV2RTPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned int state;
   struct rtphdr  src, dst;
   unsigned short sdrop, ddrop;
   unsigned short ssdev, dsdev;
};
 
struct ArgusV2RTCPObject {
   unsigned char type, length;
   unsigned short status;
   struct rtcphdr src, dst;
   unsigned short src_pkt_drop, dst_pkt_drop;
};

struct ArgusV2IGMPObjectV1 {
   unsigned char type, length;
   unsigned short status;
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
};

struct ArgusV2IGMPObject {
   unsigned char type, length;
   unsigned short status;
   unsigned char igmp_type, igmp_code;
   unsigned int igmp_group;
   struct ArgusTime jdelay;
   struct ArgusTime ldelay;
};

struct ArgusV2FRAGObject {
   unsigned char type, length;
   unsigned short status;
   int fragnum, frag_id;
   unsigned short totlen, currlen, maxfraglen;
};

struct ArgusV2ESPObject {
   unsigned int spi, lastseq, lostseq;
};

struct ArgusV2ESPStruct {
   unsigned char type, length;
   u_short status;
   struct ArgusV2ESPObject src, dst;
};

struct ArgusV2AGRStruct {
   unsigned char type, length;
   u_short status;
   unsigned int count;
   struct ArgusTime laststartime, lasttime;
   struct ArgusV2TimeObject act, idle;
   unsigned int startrange, endrange;
};

struct ArgusV2PerfStruct {
   unsigned char type, length;
   u_short status;

   int count;
   struct ArgusV2LoadStruct src, dst;
};

struct ArgusV2TimeStruct {
   unsigned char type, length;
   u_short status;
   struct ArgusV2TimeEntity src, dst;
};

struct ArgusV2MacStruct {
   unsigned char type, length;
   unsigned short status;
   union {
      struct ArgusV2ETHERObject ether;
   } phys_union;
};

#define ether_mac	phys_union.ether

struct ArgusV2VlanStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned short sid, did;
};

struct ArgusV2MplsStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned int slabel;
   unsigned int dlabel;
};



struct ArgusV2MarStruct {
   struct ArgusTime startime, now;
   unsigned char  major_version, minor_version; 
   unsigned char interfaceType, interfaceStatus;
   unsigned short reportInterval, argusMrInterval;
   unsigned int argusid, localnet, netmask, nextMrSequenceNum; 
   unsigned long long pktsRcvd, bytesRcvd;
   unsigned int  pktsDrop, flows, flowsClosed;
   unsigned int actIPcons,  cloIPcons;
   unsigned int actICMPcons,  cloICMPcons;
   unsigned int actIGMPcons,  cloIGMPcons;
   unsigned int inputs, outputs;
   unsigned int qcount,  qtime;
   int record_len;
};


struct ArgusV2TimeDesc {
   struct ArgusTime start;
   struct ArgusTime last;
};

struct ArgusV2Flow {
   union {
      struct ArgusV2IPFlow     ip;
      struct ArgusV2ICMPFlow icmp;
      struct ArgusV2IGMPFlow igmp;
      struct ArgusV2MACFlow   mac;
      struct ArgusV2ArpFlow   arp;
      struct ArgusV2RarpFlow rarp;
      struct ArgusV2ESPFlow   esp;
  } flow_union;
};

struct ArgusV2UniAttributes {
   unsigned short options;
   unsigned char ttl, tos;
};

struct ArgusV2IPAttributes {
   unsigned short soptions, doptions;
   unsigned char sttl, dttl;
   unsigned char stos, dtos;
};

struct ArgusV2ARPAttributes {
   unsigned char response[8]; 
};

struct ArgusV2Attributes {
   union {
      struct ArgusV2IPAttributes   ip;
      struct ArgusV2ARPAttributes arp;
   } attr_union;
};

#define attr_ip   attr.attr_union.ip
#define attr_arp  attr.attr_union.arp

struct ArgusV2ArchiveMeter {
   unsigned int count, bytes;
};

struct ArgusV2Meter {
   unsigned int count, bytes, appbytes;
};

struct ArgusV2FarHeaderStruct {
   unsigned char type, length;
   unsigned short status;
};

struct ArgusV2FarStruct {
   unsigned char type, length;
   unsigned short status;

   unsigned int ArgusV2TransRefNum;
   struct ArgusV2TimeDesc time;
   struct ArgusV2Flow flow;
   struct ArgusV2Attributes attr;
   struct ArgusV2Meter src, dst;
};

struct ArgusV2CorrelateStruct {
   unsigned char type, length;
   unsigned short status;
   unsigned int argusid;
   int deltaDur, deltaStart, deltaLast;
   char deltaSrcToS, deltaSrcTTL;
   char deltaDstToS, deltaDstTTL;
   unsigned short deltaSrcIpId, deltaDstIpId;
   struct ArgusV2Meter deltaSrc, deltaDst;
};

struct ArgusV2ServiceStruct {
   unsigned char type, length;
   u_short status;
   char name[16];
};


struct ArgusV2RecordArchiveHeader {
   unsigned char type, cause;
   unsigned short length;
   unsigned int status;
};

struct ArgusV2RecordHeader {
   unsigned char type, cause;
   unsigned short length;
   unsigned int status;
   unsigned int argusid;
   unsigned int seqNumber;
};

struct ArgusV2Record {
   struct ArgusV2RecordHeader ahdr;
   union {
      struct ArgusV2MarStruct  mar;
      struct ArgusV2FarStruct  far;
   } ar_un;
};

struct ArgusV2CanonicalRecord {
   struct ArgusV2RecordHeader ahdr;
   struct ArgusV2FarStruct    far;
   struct ArgusV2MacStruct    mac;
   union {
      struct ArgusV2TCPObject     tcp;
      struct ArgusV2ESPStruct     esp;
      struct ArgusV2IGMPObject   igmp;
      struct ArgusV2DHCPObject   dhcp;
      struct ArgusV2RTPObject     rtp;
      struct ArgusV2RTCPObject   rtcp;
      struct ArgusV2ARPObject     arp;
      struct ArgusV2AHObject       ah;
      struct ArgusV2FRAGObject   frag;
   } acr_union;
 
   struct ArgusV2AGRStruct        agr;
   struct ArgusV2TimeStruct      time;
   struct ArgusV2VlanStruct      vlan;
   struct ArgusV2MplsStruct      mpls;
   struct ArgusV2CorrelateStruct  cor;
   struct ArgusV2ICMPObject      icmp;
   struct ArgusV2ServiceStruct    svc;
};


struct ArgusV2ArchiveUniRecord {
   struct ArgusV2RecordArchiveHeader ahdr;
   unsigned int status;
   struct ArgusTime startime;
   unsigned int duration;
   struct ArgusV2Flow flow;
   struct ArgusV2UniAttributes attr;
   struct ArgusV2ArchiveMeter src;
};

struct ArgusV2ArchiveRecord {
   struct ArgusV2RecordArchiveHeader ahdr;
   unsigned int status;
   struct ArgusTime startime;
   unsigned int duration;
   struct ArgusV2Flow flow;
   struct ArgusV2Attributes attr;
   struct ArgusV2ArchiveMeter src, dst;
};


struct ArgusV2UserStruct {
   unsigned char type, length;
   u_short status;
   char data;
};

#if PRAGMA_STRUCT_ALIGN //{
#pragma options align=reset //}
#elif PRAGMA_STRUCT_PACKPUSH //}{
#pragma pack(pop)
#elif PRAGMA_STRUCT_PACK //}{
#pragma pack()
#endif //}

#pragma pack()

#endif /*  Argus_out_h  */
