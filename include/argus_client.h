/*
 * Argus Software.  Common include files. Client
 * Copyright (C) 2000-2015 QoSient, LLC.
 * All Rights Reserved
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
 * $Id: //depot/argus/argus/include/argus_client.h#16 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


#if !defined(ArgusClient_h)
#define ArgusClient_h
#endif


#include <unistd.h>

#include <sys/types.h>
#include <stdio.h>

#include <errno.h>
#include <fcntl.h>

#include <string.h>
#include <sys/time.h>

#include <netinet/in.h>
#include <string.h>
#include <sys/stat.h>

#include <argus_compat.h>

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#include <argus_def.h>
#include <argus_out.h>
#include <argus_os.h>


#define RA_TRANSDURATION        1
#define RA_AVGDURATION          2
#define RA_DELTADURATION        3

#define RA_MODELNAMETAGSTR	"RAGATOR_MODEL_NAME="
#define RA_PRESERVETAGSTR	"RAGATOR_PRESERVE_FIELDS="
#define RA_REPORTTAGSTR		"RAGATOR_REPORT_AGGREGATION="
#define RA_AUTOCORRECTSTR	"RAGATOR_AUTO_CORRECTION="
#define RA_HISTOGRAM		"RAGATOR_HISTOGRAM="
#define RA_MODELTAGSTR		"Model"
#define RA_FLOWTAGSTR		"Flow"

#define RA_MODELIST		1
#define RA_FLOWLIST		2

#define RA_FLOWPOLICYFIELDNUM	11
#define RA_MODELPOLICYFIELDNUM	8
  
#define RA_LABELSTRING		0
#define RA_POLICYID		1
#define RA_POLICYTYPE		2
#define RA_POLICYSRCADDR	3
#define RA_POLICYDSTADDR	4
#define RA_POLICYPROTO		5
#define RA_POLICYSRCPORT	6
#define RA_POLICYDSTPORT	7
#define RA_POLICYMODELST	8
#define RA_POLICYTIMEOUT	9
#define RA_POLICYIDLETIMEOUT	10

#define RA_MODIFIED		0x10000000

#define RA_CON			1
#define RA_DONE			2

#define RA_HASHTABLESIZE	0x1000
#define RA_SVCPASSED		0x010000
#define RA_SVCFAILED		0x020000
#define RA_SVCINCOMPLETE        0x040000
#define RA_SVCTEST		(RA_SVCFAILED|RA_SVCPASSED|RA_SVCINCOMPLETE)
#define RA_SVCDISCOVERY		0x080000
#define RA_SVCMULTICAST		0x100000


#define ARGUS_FAR_SRCADDR_MODIFIED      0x0100
#define ARGUS_FAR_DSTADDR_MODIFIED      0x0200
#define ARGUS_FAR_PROTO_MODIFIED        0x0400
#define ARGUS_FAR_SRCPORT_MODIFIED      0x0800
#define ARGUS_FAR_DSTPORT_MODIFIED      0x1000
#define ARGUS_FAR_TPVAL_MODIFIED        0x2000

#define ARGUS_FAR_RECORDREVERSE		0x4000

#define ARGUS_MAX_S_OPTIONS	34
#define ARGUS_MAX_SORT_ALG	34
#define MAX_SORT_ALG_TYPES	28

#define RASORTTIME		0
#define RASORTSTARTTIME		1
#define RASORTLASTTIME		2
#define RASORTTRANS   		3
#define RASORTDURATION		4
#define RASORTAVGDURATION	5
#define RASORTSRCADDR		6
#define RASORTDSTADDR		7
#define RASORTPROTOCOL		8
#define RASORTIPID   		9
#define RASORTSRCPORT		10
#define RASORTDSTPORT		11
#define RASORTSRCTOS		12
#define RASORTDSTTOS		13
#define RASORTSRCTTL		14
#define RASORTDSTTTL		15
#define RASORTBYTECOUNT		16
#define RASORTSRCBYTECOUNT	17
#define RASORTDSTBYTECOUNT	18
#define RASORTPKTSCOUNT		19
#define RASORTSRCPKTSCOUNT	20
#define RASORTDSTPKTSCOUNT      21
#define RASORTLOAD              22
#define RASORTRATE              23
#define RASORTLOSS              24
#define RASORTTRANREF           25
#define RASORTSEQ               26
#define RASORTSRCID             27

#define ARGUS_READINGPREHDR	1
#define ARGUS_READINGHDR		2
#define ARGUS_READINGBLOCK	4
#define ARGUS_READINGDATAGRAM	8


#define TSEQ_HASHSIZE		9029

#define ARGUS_MAX_PRINT_ALG      67
#define MAX_PRINT_ALG_TYPES     67

typedef struct ArgusRecord * (*ArgusNetFlowHandler)(u_char **);


struct ArgusInput {
   struct ArgusInput *nxt;
   unsigned int status;
   int mode, fd, in, out, offset;
   int ostart, ostop;
   u_int addr;
   unsigned short portnum;
   char *hostname, *filename;
   FILE *pipe;
   int major_version, minor_version;
   unsigned int ArgusLocalNet, ArgusNetMask;
   struct timeval ArgusLastTime;
   int ArgusMarInterval;
   struct stat statbuf;
   unsigned char *ArgusReadBuffer, *ArgusConvBuffer;
   unsigned char *ArgusReadPtr, *ArgusConvPtr, *ArgusReadBlockPtr;
   int ArgusReadSocketCnt, ArgusReadSocketSize;
   int ArgusReadSocketState, ArgusReadCiscoVersion;
   int ArgusReadSocketNum, ArgusReadSize;
   ArgusNetFlowHandler ArgusCiscoNetFlowParse;

#ifdef ARGUS_SASL
   sasl_conn_t *sasl_conn;
   int ArgusSaslBufCnt;
   unsigned char *ArgusSaslBuffer;
#endif

   struct ArgusRecord ArgusInitCon, ArgusManStart;
};

struct ArgusOutputStruct {
   char *filename;
   struct stat statbuf;
   FILE *fd;
};

#define ARGUSMONITOR_EQUAL      0x01000000
#define ARGUSMONITOR_NOTEQUAL   0x02000000
    
struct RaFlowModelStruct {
   char *desc;  
   int pindex, mindex; 
   int preserve, report, autocorrect;
   int *histotimevalues;
   int histostart, histoend, histobins;
   int histotimeseries;
    
   struct RaPolicyStruct **policy; 
   struct RaPolicyStruct **model; 
};
 
struct RaPolicyStruct { 
   u_int RaEntryType, RaPolicyId;
   struct ArgusCIDRAddr src, dst;
   u_short type; 
   u_char proto, pad;
   u_short sport, dport;
   u_int RaModelId, ArgusTimeout, ArgusIdleTimeout;
   char *str; 
};  


#if defined(HAVE_SOLARIS)
#include <sys/socket.h>
#endif

#define RA_MODIFIED		0x10000000


extern void ArgusLog (int, char *, ...);


#ifdef ArgusClient


#if defined(ARGUS_SASL)
int ArgusMaxSsf = 128;
int ArgusMinSsf = 40;
#endif

char *appOptstring = NULL;

char *RaPrintKeyWords[MAX_PRINT_ALG_TYPES] = {
   "time",
   "startime",
   "lasttime",
   "trans",
   "dur",
   "avgdur",
   "snet",
   "saddr",
   "dnet",
   "daddr",
   "proto",
   "sport",
   "dport",
   "tos",
   "stos",
   "dtos",
   "sttl",
   "dttl",
   "bytes",
   "sbytes",
   "dbytes",
   "pkts",
   "spkts",
   "dpkts",
   "sload",
   "dload",
   "load",
   "loss",
   "ploss",
   "srate",
   "drate",
   "rate",
   "srcid",
   "ind",
   "mac",
   "dir",
   "jitter",
   "sjitter",
   "djitter",
   "status",
   "ddur",
   "dstime",
   "dltime",
   "dspkts",
   "ddpkts",
   "dsbytes",
   "ddbytes",
   "pdspkts",
   "pddpkts",
   "pdsbytes",
   "pddbytes",
   "user",
   "tcpext",
   "win",
   "jdelay",
   "ldelay",
   "seq",
   "bins",
   "binnum",
   "mpls",
   "vlan",
   "vid",
   "vpri",
   "ipid",
   "srng",
   "erng",
   "svc",
};

extern struct ArgusInput *ArgusInput;
extern char *ArgusProgramName;
extern char *ArgusProgramOptions;
extern struct ArgusDSRHeader *ArgusThisDsrs[];

extern signed long long tcp_dst_bytes, tcp_src_bytes;
extern signed long long udp_dst_bytes, udp_src_bytes;
extern signed long long icmp_dst_bytes, icmp_src_bytes;
extern signed long long ip_dst_bytes, ip_src_bytes;

extern void ArgusDebug (int, char *, ...);
extern int setArgusRemoteFilter(unsigned char *);

void ArgusClientInit(struct ArgusParserStruct *);
void RaArgusInputComplete (struct ArgusInput *);
void RaParseComplete (int);

int RaParseType (char *);

void ArgusClientTimeout (void);
void parse_arg (int, char**);
void usage (void);

struct ArgusRecordStruct *RaCopyArgusRecordStruct (struct ArgusRecordStruct *);
signed long long RaGetActiveDuration (struct ArgusRecordStruct *);
signed long long RaGetuSecDuration (struct ArgusRecordStruct *);
signed long long RaGetuSecAvgDuration (struct ArgusRecordStruct *);

char RaLabelStr[1024], *RaLabel;

void RaProcessRecord (struct ArgusRecordStruct *);
void RaProcessManRecord (struct ArgusRecordStruct *);
void RaProcessFragRecord (struct ArgusRecordStruct *);
void RaProcessTCPRecord (struct ArgusRecordStruct *);
void RaProcessICMPRecord (struct ArgusRecordStruct *);
void RaProcessIGMPRecord (struct ArgusRecordStruct *);
void RaProcessUDPRecord (struct ArgusRecordStruct *);
void RaProcessIPRecord (struct ArgusRecordStruct *);
void RaProcessARPRecord (struct ArgusRecordStruct *);
void RaProcessNonIPRecord (struct ArgusRecordStruct *);

extern void ArgusLog (int, char *, ...);
extern int RaSendArgusRecord(struct ArgusRecordStruct *);

extern void ArgusClientTimeout (void);
int ArgusWriteConnection (struct ArgusInput *, u_char *, int);

char *RaGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

int RaParseProbeResourceFile (char **);
int RaProbeMonitorsThisAddr (unsigned int, unsigned int);

struct ArgusRecordStruct *ArgusGenerateRecordStruct (struct ArgusRecord *);
struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char);

void ArgusDeleteRecordStruct (struct ArgusRecordStruct *); 

struct ArgusListStruct *ArgusNewList (void);
void ArgusDeleteList (struct ArgusListStruct *, int);
int ArgusListEmpty (struct ArgusListStruct *);
int ArgusGetListCount(struct ArgusListStruct *);
void ArgusPushFrontList(struct ArgusListStruct *, void *, int);
void ArgusPushBackList(struct ArgusListStruct *, void *, int);
void *ArgusFrontList(struct ArgusListStruct *);
void *ArgusBackList(struct ArgusListStruct *);
void *ArgusPopBackList(struct ArgusListStruct *, int);
void *ArgusPopFrontList(struct ArgusListStruct *, int);

int ArgusCheckTime (struct ArgusRecordStruct *);

#else /* ArgusClient */


#if defined(ARGUS_SASL)
extern int ArgusMaxSsf;
extern int ArgusMinSsf;
#endif /* ARGUS_SASL */

extern char *appOptstring;

extern char *RaPrintKeyWords[MAX_PRINT_ALG_TYPES];
extern char *ArgusProgramName;
extern char *ArgusProgramOptions;

extern void ArgusDebug (int, char *, ...);
extern int setArgusRemoteFilter(unsigned char *);

extern void ArgusClientInit(struct ArgusParserStruct *);
extern void RaArgusInputComplete (struct ArgusInput *);
extern void RaParseComplete (int);

extern int RaParseType (char *);

extern void ArgusClientTimeout (void);
extern void parse_arg (int, char**);
extern void usage (void);

extern struct ArgusRecordStruct *RaCopyArgusRecordStruct (struct ArgusRecordStruct *);
extern signed long long RaGetActiveDuration (struct ArgusRecordStruct *);
extern signed long long RaGetuSecDuration (struct ArgusRecordStruct *);
extern signed long long RaGetuSecAvgDuration (struct ArgusRecordStruct *);

extern char RaLabelStr[1024], *RaLabel;

extern void RaProcessRecord (struct ArgusRecordStruct *);
extern void RaProcessManRecord (struct ArgusRecordStruct *);
extern void RaProcessFragRecord (struct ArgusRecordStruct *);
extern void RaProcessTCPRecord (struct ArgusRecordStruct *);
extern void RaProcessICMPRecord (struct ArgusRecordStruct *);
extern void RaProcessIGMPRecord (struct ArgusRecordStruct *);
extern void RaProcessUDPRecord (struct ArgusRecordStruct *);
extern void RaProcessIPRecord (struct ArgusRecordStruct *);
extern void RaProcessARPRecord (struct ArgusRecordStruct *);
extern void RaProcessNonIPRecord (struct ArgusRecordStruct *);

extern void ArgusLog (int, char *, ...);

extern char *RaGenerateLabel(struct ArgusParserStruct *, struct ArgusRecordStruct *);

extern int RaSendArgusRecord(struct ArgusRecordStruct *);
extern int RaProbeMonitorsThisAddr (unsigned int, unsigned int);

extern struct ArgusRecordStruct *ArgusGenerateRecordStruct (struct ArgusRecord *);
extern struct ArgusRecord *ArgusGenerateRecord (struct ArgusRecordStruct *, unsigned char);

extern void ArgusDeleteRecordStruct (struct ArgusRecordStruct *); 

extern struct ArgusListStruct *ArgusNewList (void);
extern void ArgusDeleteList (struct ArgusListStruct *, int);
extern int ArgusListEmpty (struct ArgusListStruct *);
extern int ArgusGetListCount(struct ArgusListStruct *);
extern void ArgusPushFrontList(struct ArgusListStruct *, void *);
extern void ArgusPushBackList(struct ArgusListStruct *, void *);
extern void *ArgusFrontList(struct ArgusListStruct *);
extern void *ArgusBackList(struct ArgusListStruct *);
extern void *ArgusPopBackList(struct ArgusListStruct *);
extern void *ArgusPopFrontList(struct ArgusListStruct *);

extern int ArgusCheckTime (struct ArgusRecordStruct *);

#endif
