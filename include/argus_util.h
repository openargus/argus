/*
 * Argus Software.  Common include files - Utilities
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
 * $Id: //depot/argus/argus/include/argus_util.h#24 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#if !defined(Argus_util_h)
#define Argus_util_h

#include <netinet/in_systm.h>
#if defined(__OpenBSD__) || defined(HAVE_SOLARIS)
#include <netinet/in.h>
#endif
#include <netinet/ip.h>

#include <argus_parser.h>
#include <argus_def.h>

#include <argus/cons_out.h>

#include <argus/CflowdFlowPdu.h>


typedef void (*proc)(void);
typedef char *(*strproc)(void);

struct ArgusQueueHeader {
   struct ArgusQueueHeader *prv, *nxt;
   struct ArgusQueueStruct *queue;
   struct timeval lasttime, qtime;
   unsigned int status;
};

struct ArgusQueueStruct {
   struct ArgusQueueHeader qhdr;
   int count, turns, timeout, status, reclaim;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   struct ArgusQueueHeader *start, *end;
   struct ArgusFlowStruct **array;
};


struct ArgusMemoryHeader {
   struct ArgusMemoryHeader *nxt, *prv;
#if defined(__GNUC__)
   void *frame[3];
#endif
   unsigned int tag;
   unsigned short len;
   unsigned short offset;
};

struct ArgusMemoryList {
   struct ArgusMemoryHeader *start, *end;
#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
#endif
   int total, count, size;
   int out, in, freed;
};

#if defined(ARGUS_SASL)
#include <sasl/sasl.h>
#endif

#include <sys/stat.h>

#define ARGUS_DATA_SOURCE		0x01
#define ARGUS_CISCO_DATA_SOURCE		0x10
#define ARGUS_SFLOW_DATA_SOURCE		0x20


#define TSEQ_HASHSIZE      9029

#define ipaddr_string(p) ArgusGetName(ArgusParser, (u_char *)(p))

#if defined(argus_util)

#define IPPROTOSTR 134

char *ip_proto_string [IPPROTOSTR] = {"ip", "icmp", "igmp", "ggp",
   "ipnip", "st", "tcp", "ucl", "egp", "igp", "bbn-rcc-mon", "nvp-ii",
   "pup", "argus", "emcon", "xnet", "chaos", "udp", "mux", "dcn-meas",
   "hmp", "prm", "xns-idp", "trunk-1", "trunk-2", "leaf-1", "leaf-2",
   "rdp", "irtp", "iso-tp4", "netblt", "mfe-nsp", "merit-inp", "sep",
   "3pc", "idpr", "xtp", "ddp", "idpr-cmtp", "tp++", "il", "ipv6",
   "sdrp", "ipv6-route", "ipv6-frag", "idrp", "rsvp", "gre", "mhrp", "bna",
   "esp", "ah", "i-nlsp", "swipe", "narp", "mobile", "tlsp", "skip",
   "ipv6-icmp", "ipv6-no", "ipv6-opts", "any", "cftp", "any", "sat-expak", "kryptolan",
   "rvd", "ippc", "any", "sat-mon", "visa", "ipcv", "cpnx", "cphb", "wsn",
   "pvp", "br-sat-mon", "sun-nd", "wb-mon", "wb-expak", "iso-ip", "vmtp",
   "secure-vmtp", "vines", "ttp", "nsfnet-igp", "dgp", "tcf", "igrp",
   "ospfigp", "sprite-rpc", "larp", "mtp", "ax.25", "ipip", "micp",
   "aes-sp3-d", "etherip", "encap", "pri-enc", "gmtp", "ifmp", "pnni",
   "pim", "aris", "scps", "qnx", "a/n", "ipcomp", "snp", "compaq-peer",
   "ipx-n-ip", "vrrp", "pgm", "zero", "l2tp", "ddx", "iatp", "stp", "srp",
   "uti", "smp", "ptp", "isis", "fire", "crtp", "crudp", "sccopmce", "iplt",
   "sps", "pipe", "sctp", "fc",
};

#if defined(__OpenBSD__)
#include <netinet/in_systm.h>
#include <netinet/ip.h>
#endif

#include <netinet/ip_icmp.h>
#undef ICMP_MAXTYPE
#define ICMP_MAXTYPE	41
char *icmptypestr[ICMP_MAXTYPE + 1] = {
   "ECR", "   ", "   ", "UR" , "SRC", "RED",
   "AHA", "   ", "ECO", "RTA", "RTS", "TXD",
   "PAR", "TST", "TSR", "IRQ", "IRR", "MAS",
   "MSR", "SEC", "ROB", "ROB", "ROB", "ROB",
   "ROB", "ROB", "ROB", "ROB", "ROB", "ROB",
   "TRC", "DCE", "MHR", "WAY", "IAH", "MRQ",
   "MRP", "DNQ", "DNP", "SKP", "PHO",
};   


int ArgusSrcUserDataLen = 0;
int ArgusDstUserDataLen = 0;

void ArgusAdjustGlobalTime (struct timeval *, struct timeval *);
extern unsigned int thisnet, localaddr, localnet, netmask;
extern char *RaTimeFormat;
extern char  RaFieldDelimiter;

void *ArgusMalloc (int);
void *ArgusCalloc (int, int);
void ArgusFree (void *);
void ArgusFreeListRecord (void *buf);
void ArgusInitMallocList (int length);
void ArgusDeleteMallocList (void);
void *ArgusMallocListRecord (int length);

void ArgusLog (int, char *, ...);

void ArgusInitServarray(struct ArgusParserStruct *);

#else

extern void ArgusAdjustGlobalTime (struct timeval *);

extern void *ArgusMalloc (int);
extern void *ArgusCalloc (int, int);
extern void ArgusFree (void *);
extern void ArgusFreeListRecord (void *buf);
extern void ArgusInitMallocList (int length);
extern void ArgusDeleteMallocList (void);
extern void *ArgusMallocListRecord (int length);

extern void ArgusLog (int, char *, ...);

#endif 
#endif /* Argus_util_h */
