/*
 * Gargoyle Software.  Common include files. Utilities
 * Copyright (c) 2000-2015 QoSient, LLC
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

/* 
 * $Id: //depot/gargoyle/argus/include/argus_util.h#6 $
 * $DateTime: 2015/04/21 19:24:29 $
 * $Change: 3018 $
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
#define ARGUS_DOMAIN_SOURCE		0x100

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
void *ArgusMallocAligned(int, size_t);
void ArgusFree (void *);
void ArgusFreeListRecord (void *buf);
void ArgusInitMallocList (int length);
void ArgusDeleteMallocList (void);
void *ArgusMallocListRecord (int length);

void ArgusLog (int, char *, ...);
void setArgusLogDisplayPriority(int);

void ArgusInitServarray(struct ArgusParserStruct *);

#else

extern void ArgusAdjustGlobalTime (struct timeval *);

extern void *ArgusMalloc (int);
extern void *ArgusCalloc (int, int);
void *ArgusMallocAligned(int, size_t);
extern void ArgusFree (void *);
extern void ArgusFreeListRecord (void *buf);
extern void ArgusInitMallocList (int length);
extern void ArgusDeleteMallocList (void);
extern void *ArgusMallocListRecord (int length);

extern void ArgusLog (int, char *, ...);
extern void setArgusLogDisplayPriority (int);

#endif 
#endif /* Argus_util_h */
