/*
 * Argus Software.  Common include files. cons_out.h
 * Copyright (c) 2000-2020 QoSient, LLC
 * All rights reserved.
 *
 * THE ACCOMPANYING PROGRAM IS PROPRIETARY SOFTWARE OF QoSIENT, LLC,
 * AND CANNOT BE USED, DISTRIBUTED, COPIED OR MODIFIED WITHOUT
 * EXPRESS PERMISSION OF QoSIENT, LLC.
 *
 * QOSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QOSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */


#if !defined(cons_out_h)
#define cons_out_h

#if !defined(__OpenBSD__) || !defined(_NET_IF_H_)
#define _NET_IF_H_
#include <net/if.h>
#endif

#include <netinet/in.h>

#if !defined(__OpenBSD__) || !defined(_NETINET_IF_ETHER_H_)
#define _NETINET_IP_ETHER_H_
#include <netinet/if_ether.h>
#endif

struct THA_OBJECT {
   arg_int32 size;
   unsigned char *buffer;
};

struct tha {
   struct in_addr src;
   struct in_addr dst;
   arg_uint16 sport;
   arg_uint16 dport;
};

struct icmptha {
   struct in_addr src;
   struct in_addr dst;
   arg_uint32 port;
   arg_uint32 addr;
};


struct writeStruct {
   arg_uint32 status;
   struct argtimeval startime, lasttime;
   struct ether_addr ethersrc;
   struct ether_addr etherdst;
   struct tha addr;
   arg_int32 src_count, dst_count;
   arg_int32 src_bytes, dst_bytes;
};


struct inittcpWriteStruct {
   arg_int32 src_count, dst_count;
   arg_uint32 addr, seq;
};

struct tcpWriteStruct {
   arg_int32 src_count, dst_count;
   arg_int32 src_bytes, dst_bytes;
};

struct udpWriteStruct {
   arg_int32 src_count, dst_count;
   arg_int32 src_bytes, dst_bytes;
};

struct icmpWriteStruct {
   arg_uint8 type, code;
   arg_uint16 data;
   struct in_addr srcaddr, dstaddr, gwaddr;
};

struct fragWriteStruct {
   int fragnum, frag_id;
   unsigned short status, totlen, currlen, maxfraglen;
};

struct physWriteStruct {
   struct ether_addr ethersrc;
   struct ether_addr etherdst;
};

struct arpWriteStruct {
   struct argtimeval time;
   struct physWriteStruct phys;
   struct ether_arp arp;
};

struct  ipWriteStruct {
   struct argtimeval startime, lasttime;
   struct physWriteStruct ws_phys;
   struct in_addr src;
   struct in_addr dst;
   arg_uint16 sport;
   arg_uint16 dport;
   union {
      struct inittcpWriteStruct inittcp;
      struct  tcpWriteStruct  tcp;
      struct  udpWriteStruct  udp;
      struct icmpWriteStruct icmp;
      struct fragWriteStruct frag;
   } ipws_trans_union;
};

struct manInitStruct {
   struct argtimeval startime, now;
   arg_int8 initString[20];
   arg_uint32 localnet, netmask; 
   arg_uint16 reportInterval, dflagInterval; 
   arg_uint8 interfaceType, interfaceStatus;
};

struct manStatStruct {
   struct argtimeval startime, now;
   arg_uint16 reportInterval, dflagInterval;
   arg_uint8 interfaceType, interfaceStatus;
   arg_uint32 pktsRcvd, bytesRcvd, pktsDrop;
   arg_uint16 actTCPcons, cloTCPcons;
   arg_uint16 actUDPcons, cloUDPcons;
   arg_uint16 actIPcons,  cloIPcons;
   arg_uint16 actICMPcons,  cloICMPcons;
   arg_uint16 actFRAGcons,  cloFRAGcons;
};

struct WriteStruct {
   arg_uint32 status;
   union {
      struct    ipWriteStruct ip;
      struct   arpWriteStruct arp;
      struct   manInitStruct man_init;
      struct   manStatStruct man_stat;
   } ws_trans_union;
};

#define ws_ip   ws_trans_union.ip
#define ws_arp  ws_trans_union.arp
#define ws_init ws_trans_union.man_init
#define ws_stat ws_trans_union.man_stat

#define ws_ip_phys     ws_trans_union.ip.ws_phys
#define ws_ip_src      ws_trans_union.ip.src
#define ws_ip_dst      ws_trans_union.ip.dst
#define ws_ip_port     ws_trans_union.ip.port
#define ws_ip_inittcp  ws_trans_union.ip.ipws_trans_union.inittcp
#define ws_ip_tcp      ws_trans_union.ip.ipws_trans_union.tcp
#define ws_ip_udp      ws_trans_union.ip.ipws_trans_union.udp
#define ws_ip_icmp     ws_trans_union.ip.ipws_trans_union.icmp
#define ws_ip_frag     ws_trans_union.ip.ipws_trans_union.frag

#endif
