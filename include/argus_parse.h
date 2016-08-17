/*
 * Argus Software Common include files -  parsing
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
 * $Id: //depot/argus/argus/include/argus_parse.h#17 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#if !defined(Argus_parse_h)
#define Argus_parse_h

#include <unistd.h>
#include <stdlib.h>
#include <netdb.h>

#include <syslog.h>

#include <argus_out.h>
#include <argus_def.h>
#include <argus_util.h>


#if !defined(MAXPATHNAMELEN)
#define MAXPATHNAMELEN          BUFSIZ
#endif

#define ARGUS_DEFAULTPORT	561

#define ARGUS_ENCODE_ASCII	0
#define ARGUS_ENCODE_64		1
#define ARGUS_ENCODE_32		2
 
struct naddrmem {
   struct naddrmem *nxt;
   unsigned int addr;
   unsigned short port;
};

struct ArgusInterfaceStruct {
   int value;
   char *label;
   char *desc;
};

struct ArgusModeStruct {
   struct ArgusModeStruct *nxt;
   char *mode;
};

#define MAXSTRLEN		4096
#define MAXTIME			100000
#define READ_REMOTE_CON		0x40000000
#define READ_LOCAL_CON		0x20000000

#define ARGUS_MAX_REMOTE_CONN		64
#define HASHNAMESIZE  4096


#if defined(ArgusParse)

struct timeval RaClientTimeout = {1,0};
#define MAXPROCSTATE		7

char *process_state_strings [MAXPROCSTATE] = {
   "REQ", "ACC", "EST", "CLO", "TIM", "RST", "FIN",
};

struct timeval ArgusGlobalTime;
struct timeval ArgusNowTime;

struct bpf_program ArgusFilterCode;

char *RaInputFilter[] = {NULL, NULL};

struct tm *RaTmStruct = NULL, RaTmStructBuf;
char *RaTimeFormat = "%d %b %y %T";
char  RaFieldDelimiter = '\0';

int RaPrintStartTime = 0;
int RaPrintLastTime = 0;
int RaCloseInputFd = 1;

struct ArgusFarHeaderStruct *ArgusThisFarHdrs[32];

struct naddrmem *naddrtable [HASHNAMESIZE];

void clearArgusWfile(void);
void setArgusWfile(char *, char *);

char *exceptfile =  NULL, *wfile = NULL;

struct ARGUS_INPUT *ArgusInput = NULL;
struct ARGUS_INPUT *ArgusInputFileList = NULL;
struct ARGUS_INPUT *ArgusRemoteHostList = NULL;

struct ArgusModeStruct *ArgusModeList = NULL;

char *tag_string = "Argus Version ";
int major_version = VERSION_MAJOR;
int minor_version = VERSION_MINOR;
int read_size = 0, detail = 0;
int read_mode = 0;

struct ArgusRecord *initCon = NULL;

unsigned int ArgusLocalNet, ArgusNetMask;

char ArgusOriginalBuffer[MAXSTRLEN];
struct ArgusRecord *ArgusOriginal = (struct ArgusRecord *) ArgusOriginalBuffer;

int totalrecords = 0;
int farrecords = 0;
int marrecords = 0;

int explicit_date = 0;
 
time_t starTimeFilter_t = 0;
time_t lastTimeFilter_t = 0;

time_t lasttime_t = 0;
time_t startime_t = 0;

struct tm starTimeFilter;
struct tm lastTimeFilter;

char *ArgusProgramName = NULL;
char *ArgusProgramArgs = NULL;
char *ArgusProgramOptions = NULL;
char *dataarg = NULL;
char *timearg = NULL;
char *servicesfile = NULL;
struct bpf_program ArgusFilterCode;

int ArgusGrepSource = 0;
int ArgusGrepDestination = 0;

int RaWriteOut = 1;

long long tcp_dst_count = 0;
long long tcp_src_count = 0;
long long udp_dst_count = 0;
long long udp_src_count = 0;
long long icmp_dst_count = 0;
long long icmp_src_count = 0;
long long ip_dst_count = 0;
long long ip_src_count = 0;
long long arp_dst_count = 0;
long long arp_src_count = 0;
long long nonip_dst_count = 0;
long long nonip_src_count = 0;

long long tcp_dst_bytes = 0;
long long tcp_src_bytes = 0;
long long udp_dst_bytes = 0;
long long udp_src_bytes = 0;
long long icmp_dst_bytes = 0;
long long icmp_src_bytes = 0;
long long ip_dst_bytes = 0;
long long ip_src_bytes = 0;
long long arp_dst_bytes = 0;
long long arp_src_bytes = 0;
long long nonip_dst_bytes = 0;
long long nonip_src_bytes = 0;

int hfield = 15;
int pfield = 5;
int Aflag = 0;
int aflag = 0;
int Bflag = 0;
int bflag = 0;
int eflag = 0;
char *estr = NULL;
int Dflag = 0;
int Eflag = 0;
int fflag = 0;
int gflag = 0;
int idflag = 0;
int Gflag = 0;
int cflag = 0;
int Cflag = 0;
int jflag = 0;
int Lflag = -1;
int lflag = 0;
int mflag = 0;
char *Mflag = NULL;
int nflag = 0;
int Nflag = 0;
int Normflag = 0;
int Netflag = 0;
int notNetflag = 0;
int oflag = 0;
int Oflag = 0;
int Wflag = 0;
int Fflag = 0;
int Hflag = 0;
char *Hstr = NULL;
int pflag = 0;
int Pflag = 0;
char *sflag = NULL;
int dflag = 0;
 
int qflag = 0;
int tflag = 0;
int uflag = 0;
char *ustr = NULL;
char *pstr = NULL;
int Uflag = 6;
int vflag = 0;
int Vflag = 0;
int iflag = 0;
 
int Iflag = 0;
int Tflag = 0;
int rflag = 0;
int Rflag = 0;
int Sflag = 0;
int xflag = 0;
int Xflag = 0;
int XMLflag = 0;

int zflag = 0;
int Zflag = 0;
 
long thiszone;
 
int total_nets = 0;
int total_hosts = 0;

struct ARGUS_INPUT *ArgusRemoteFDs[ARGUS_MAX_REMOTE_CONN];
int ArgusActiveServers = 0;

extern int ArgusAuthenticate (struct ARGUS_INPUT *);
extern void ArgusClientInit (void);
extern void usage (void);

extern void process_man (struct ArgusRecord *);
extern void process_tcp (struct ArgusRecord *);
extern void process_icmp (struct ArgusRecord *);
extern void process_udp (struct ArgusRecord *);
extern void process_ip (struct ArgusRecord *);
extern void process_arp (struct ArgusRecord *);
extern void process_non_ip (struct ArgusRecord *);

void ArgusShutDown (int);
extern void RaParseComplete (int);

void argus_parse_init (struct ARGUS_INPUT *);
char *argus_lookupdev(char *);

void read_udp_services (char *);

int ArgusHandleDatum (struct ArgusRecord *, struct bpf_program *);
void ArgusReformatRecord (struct ArgusRecord *, struct ArgusRecord *);

int ArgusReadConnection (struct ARGUS_INPUT *, char *);
void ArgusReadStream (void);
void ArgusProcessRecord (struct ArgusRecord *);

void ArgusGenerateCanonicalRecord (struct ArgusRecord *, struct ArgusCanonicalRecord *);

int ArgusGetServerSocket (struct ARGUS_INPUT *);
int ArgusAddFileList (char *);
void ArgusDeleteFileList (void);
int ArgusAddHostList (char *, int);
int ArgusAddModeList (char *);
void ArgusDeleteHostList (void);

int ArgusWriteNewLogfile (char *, struct ArgusRecord *);

int check_time (struct ArgusRecord *);
int parseUserDataArg (char **, char **, int);
int parseTimeArg (char **, char **, int, struct tm *);
int check_time_format (struct tm *tm, char *str);
int parseTime (struct tm *, struct tm *, char *);

#if defined(_LITTLE_ENDIAN)
void ArgusNtoH (struct ArgusRecord *argus);
void ArgusHtoN (struct ArgusRecord *argus);
#endif


#else /* ArgusParse */
 
extern char *ArgusProgramName;
extern char *ArgusProgramArgs;
extern char *process_state_strings [];

extern int ArgusGrepSource;
extern int ArgusGrepDestination;

extern struct timeval ArgusGlobalTime;
extern struct timeval ArgusNowTime;

extern char *RaSortAlgorithmStrings[];
extern int RaSortIndex;

extern struct tm *RaTmStruct;
extern char *RaInputFilter[];
extern char *RaTimeFormat;
extern char  RaFieldDelimiter;

extern int RaPrintStartTime;
extern int RaPrintLastTime;
extern int RaCloseInputFd;

extern u_int ArgusThisFarStatus;
extern struct ArgusFarHeaderStruct *ArgusThisFarHdrs[];

extern struct naddrmem *naddrtable [HASHNAMESIZE];

extern struct ArgusListStruct *ArgusWfileList;
extern char *exceptfile, *wfile;

extern struct ARGUS_INPUT *ArgusInput;
extern struct ARGUS_INPUT *ArgusInputFileList;
extern struct ARGUS_INPUT *ArgusRemoteHostList;
extern struct ArgusModeStruct *ArgusModeList;

extern char *tag_string;
extern int major_version;
extern int minor_version;
extern int read_size;
extern int read_mode;

extern struct ArgusRecord *initCon;

extern unsigned int ArgusLocalNet, ArgusNetMask;

extern struct ArgusRecord *ArgusOriginal;

extern int totalrecords;
extern int farrecords;
extern int marrecords;
extern int explicit_date;
 
extern time_t lasttime_t;
extern time_t startime_t;

extern struct tm starTimeFilter;
extern struct tm lastTimeFilter;

extern char *progname;
extern char *dataarg;
extern char *timearg;
extern char *servicesfile;

extern char *ArgusFlowModelFile;
extern struct bpf_program ArgusFilterCode;

extern char *cmdline;	/* For David Brumley's amazingly long cmdlines ;o) */ 

extern int RaWriteOut;

extern long long tcp_dst_count;
extern long long tcp_src_count;
extern long long udp_dst_count;
extern long long udp_src_count;
extern long long icmp_dst_count;
extern long long icmp_src_count;
extern long long ip_dst_count;
extern long long ip_src_count;
extern long long arp_dst_count;
extern long long arp_src_count;
extern long long nonip_dst_count;
extern long long nonip_src_count;

extern long long tcp_dst_bytes;
extern long long tcp_src_bytes;
extern long long udp_dst_bytes;
extern long long udp_src_bytes;
extern long long icmp_dst_bytes;
extern long long icmp_src_bytes;
extern long long ip_dst_bytes;
extern long long ip_src_bytes;
extern long long arp_dst_bytes;
extern long long arp_src_bytes;
extern long long nonip_dst_bytes;
extern long long nonip_src_bytes;

extern int hfield;
extern int pfield;
extern int Aflag;
extern int aflag;
extern int Bflag;
extern int bflag;
extern int eflag;
extern char *estr;
extern int Dflag;
extern int Eflag;
extern int fflag;
extern int gflag;
extern int idflag;
extern int Gflag;
extern int cflag;
extern int Cflag;
extern int jflag;
extern int Lflag;
extern int lflag;
extern int mflag;
extern char *Mflag;
extern int nflag;
extern int Nflag;
extern int Normflag;
extern int Netflag;
extern int notNetflag;
extern int oflag;
extern int Oflag;
extern int Wflag;
extern int Fflag;
extern int Hflag;
extern char *Hstr;
extern int pflag;
extern int Pflag;
extern char *sflag;
extern int dflag;

extern int qflag;
extern int tflag;
extern int uflag;
extern char *ustr;
extern char *pstr;
extern int Uflag;
extern int vflag;
extern int Vflag;
extern int iflag;

extern int Iflag;
extern int Tflag;
extern int rflag;
extern int Rflag;
extern int Sflag;
extern int xflag;
extern int Xflag;
extern int XMLflag;
extern int zflag;
extern int Zflag;

extern long thiszone;

extern int total_nets;
extern int total_hosts;

extern struct ARGUS_INPUT *ArgusRemoteFDs[ARGUS_MAX_REMOTE_CONN];
extern int ArgusActiveServers;

extern void ArgusShutDown (int);
extern void argus_parse_init (struct ARGUS_INPUT *);
extern char *argus_lookupdev(char *);

extern void read_udp_services (char *);

extern int ArgusHandleDatum (struct ArgusRecord *, struct bpf_program *);
extern void ArgusReformatRecord (struct ArgusRecord *, struct ArgusRecord *);
extern int ArgusReadRemoteConnection (int, struct bpf_program *);
extern int ArgusReadConnection (struct ARGUS_INPUT *, char *);
extern void ArgusReadStream (void);
extern void ArgusProcessRecord (struct ArgusRecord *);

extern void ArgusReadRemote (int, struct bpf_program *);
extern int read_file (int fd, struct bpf_program *);
extern void ArgusProcessRecord (struct ArgusRecord *);
extern void ArgusGenerateCanonicalRecord (struct ArgusRecord *, struct ArgusCanonicalRecord *);

extern int ArgusGetServerSocket (struct ARGUS_INPUT *);
extern int ArgusAddFileList (char *);
extern void ArgusDeleteFileList (void);
extern int ArgusAddHostList (char *, int);
extern int ArgusAddModeList (char *);
extern void ArgusDeleteHostList (void);

extern int ArgusWriteNewLogfile (char *, struct ArgusRecord *);

extern int check_time (struct ArgusRecord *);
extern int parseUserDataArg (char **, char **, int);
extern int parseTimeArg (char **, char **, int, struct tm *);
extern int check_time_format (struct tm *tm, char *str);
extern int parseTime (struct tm *, struct tm *, char *);

#if defined(_LITTLE_ENDIAN)
extern void ArgusNtoH (struct ArgusRecord *argus);
extern void ArgusHtoN (struct ArgusRecord *argus);
#endif

#endif

#if defined(RaMuxSource) || defined(RadiumSource)
#if !defined(NFC_AGGREGATIONDEFINITION_H)
#define NFC_AGGREGATIONDEFINITION_H

/* $Id: //depot/argus/argus/include/argus_parse.h#17 $
 * $Source: $
 *------------------------------------------------------------------
 * Definition of "Key" and "Value" fields used for purpose of 
 * aggregation
 *
 * Cisco NetFlow FlowCollector 3.0
 *
 * September 1998, Anders Fung
 *
 * Copyright (c) 1996-1998 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 * $Log: argus_parse.h,v $
 * Revision 1.1  2003/04/16 20:53:57  qosient
 * Modified for argus to argus conversion
 *
 * Revision 1.12  2003/02/05 23:43:53  qosient
 * Updated for new year in the copyright
 *
 * Revision 1.11  2002/04/01 22:41:01  qosient
 * Updated
 *
 * Revision 1.10  2002/04/01 15:39:32  qosient
 * Update for handling loss of remote when connected to multiple remotes.
 * Increase ARGUS_MAX_REMOTE_NUM and RADIUM_MAX_REMOTE_NUM.
 *
 * Revision 1.9  2002/03/25 17:49:49  qosient
 * Updated for correct copyright
 *
 * Revision 1.8  2002/03/25 17:38:32  qosient
 * Updated for correct interface status reporting
 *
 * Revision 1.6  2002/02/02 16:01:27  qosient
 * Updated for next versions of DSRs
 *
 * Revision 1.5  2002/02/01 14:10:00  qosient
 * Updated for libpcap-0.7.1 port
 *
 * Revision 1.4  2002/01/04 22:15:08  qosient
 * Updated
 *
 * Revision 1.3  2001/12/17 18:12:45  qosient
 * Mods to move ramux to radium
 *
 * Revision 1.2  2001/10/24 20:47:53  qosient
 * Updated
 *
 * Revision 1.5  2001/10/22 20:20:07  qosient
 * Updated and fixed for Lflag having bad default value
 *
 * Revision 1.4  2001/10/18 17:15:29  qosient
 * Fixed for output file fd handling issues, primarily for rapop
 *
 * Revision 1.3  2001/10/15 20:07:29  qosient
 * Updated for ramux issues with authentication. Stopped erasing password.
 *
 * Revision 1.2  2001/09/12 05:09:30  qosient
 * Updated
 *
 * Revision 1.1.1.1  2001/09/08 22:01:48  qosient
 * Argus Clients 1.0
 *
 * Revision 1.6  2001/09/03 04:58:51  argus
 * Lots of mods
 *
 * Revision 1.5  2001/07/17 12:38:45  argus
 * Updated
 *
 * Revision 1.4  2001/07/10 18:18:10  argus
 * Mods for ramon and rasort port
 *
 * Revision 1.3  2001/06/09 14:10:09  argus
 * Minor changes for -H option and formatting
 *
 * Revision 1.2  2001/06/07 19:50:45  argus
 * Updated
 *
 * Revision 1.1.1.1  2001/06/03 16:07:57  argus
 * Start of argus client distribution
 *
 * Revision 1.1.1.1  2001/03/24 05:14:27  argus
 * Imported from argus-2.0.0
 *
 * Revision 1.39  2001/03/06 23:30:41  argus
 * Fix for Davids incredibly long command lines.
 *
 * Revision 1.38  2001/02/03 21:39:08  argus
 * Mods to support -d option
 *
 * Revision 1.37  2000/12/19 16:19:41  argus
 * Mods to get ramon() to the same level as ra() with regard to dynamic
 * labels.  Also FreeBSD/NetBSD port support for racount().
 *
 * Revision 1.36  2000/12/19 05:59:03  argus
 * Mods to help in getting pretty output when not using -n.
 *
 * Revision 1.35  2000/12/10 20:59:13  argus
 * Mods to add support for RA_AUTH_PASS (pstr)
 *
 * Revision 1.34  2000/12/07 19:00:39  argus
 * Mods to convert from ArgusError to ArgusLog
 *
 * Revision 1.33  2000/12/07 17:51:48  argus
 * Move Uflag (precision option) to -p option.
 *
 * Revision 1.32  2000/11/23 01:58:29  argus
 * Mods to support GSSAPI authentication
 *
 * Revision 1.31  2000/11/16 15:20:34  argus
 * Update for SASL
 *
 * Revision 1.30  2000/11/13 21:51:38  argus
 * Mods to support ragrep().
 *
 * Revision 1.29  2000/11/13 15:05:14  argus
 * Fixes for raxml not printing out user data in all protocol types.
 *
 * Revision 1.28  2000/10/31 19:35:01  argus
 * Mods to support new timestats and user data.
 *
 * Revision 1.27  2000/10/27 13:45:42  argus
 * Fix support for multiple remote sources.
 *
 * Revision 1.26  2000/10/27 01:48:50  argus
 * Fixes for multiple source data.
 *
 * Revision 1.25  2000/10/26 15:38:09  argus
 * Mods for qflag defintions and some constants
 *
 * Revision 1.24  2000/10/25 22:23:30  argus
 * Mods to try to fix the LITTLE_ENDIAN issues for Neil.
 *
 * Revision 1.23  2000/10/16 21:55:48  argus
 * support for various .rc's.
 *
 * Revision 1.22  2000/10/11 12:51:37  argus
 * Added Zflag
 *
 * Revision 1.21  2000/10/10 14:50:51  argus
 * Fixes to support XML printing (print_time changes) and a bunch to support
 * TCP fixes.
 *
 * Revision 1.20  2000/10/05 15:04:47  argus
 * Addition of output labels for ra data.
 *
 * Revision 1.19  2000/10/03 23:04:29  argus
 * Mods for more complete cisco netflow parsing and -CS support.  Needs testing.
 *
 * Revision 1.18  2000/10/01 14:27:45  argus
 * Put the filter in a global so we can all get to it.
 *
 * Revision 1.17  2000/09/30 15:03:13  argus
 * Addition of netflow record definitions.
 *
 *------------------------------------------------------------------
 * $Endlog$
 */

/* 
 * AGGREGATION_DEFINITION describes the "Key" and "Value" fields seen in
 * the datafile. The definition comprise of keywords and delimiters. 
 * By reading the AGGREGATION_DEFINITION, one can interpret what and in what
 * order are the "Key" and "Value" fields being presented in the datafile.
 * Datafile consumers can also deduce what aggregation scheme is used 
 * by parsing AGGREGATION_DEFINITION..
 *
 * The order of keywords seen in the AGGREGATION_DEFINITION represents the true
 * order of the "Key" and "Value" fields presented in the datafile. Each 
 * keyword is delimited by either '|' or ','.
 *
 * As part of the new changes to the datafile header, the FORMAT field
 * will have a value of "B". Please note that the FORMAT may change 
 * if there is any change to any of the existing keywords, definition format,
 * adding new keyword, or any other header changes.
 * Also, the delimiter used in the datafile will be prepended at the 
 * beginning of each header. Since AGGREGATION_DEFINITION becomes the 2nd 
 * line of the header, the 1st line of the header will append a 
 * new field, namely "Header", which describes the total number of 
 * lines in the header.
 * 
 * The AGGREGATION_DEFINITION keywords have the following assignemnts ...
 *
 *      keyword           Description
 *      -------           -----------------------
 *      srcaddr           Source IP Address
 *      dstaddr           Destination IP Address
 *      src_subnet        Source SubNet
 *      dst_subnet        Destination SubNet
 *      src_mask          Source SubNet Mask 
 *      dst_mask          Destination SubNet Mask 
 *      src_user_subnet   Source User SubNet
 *      dst_user_subnet   Destination User SubNet
 *      src_as            Source AS
 *      dst_as            Destination AS
 *      srcport           Source Port
 *      dstport           Destination Port
 *      prot              Prot field
 *      protocol          Protocol (srcport, dstport, and prot lookup)
 *      input             Input Interface 
 *      output            Output Interface
 *      tos               Type of Service
 *      nexthop           Next Hop IP Address
 *
 *      pkts              Packets
 *      octets            Octets
 *      flows             Flow Count
 *      starttime         First Flow Stamp (UTC sec)
 *      endtime           Last Flow Stamp (UTC sec)
 *      activetime        Total Active Time (msec)
 */

/* Key Fields */
#define SRC_ADDR                      "srcaddr"
#define DST_ADDR                      "dstaddr"
#define SRC_SUBNET                    "src_subnet"
#define DST_SUBNET                    "dst_subnet"
#define SRC_SUBNET_MASK               "src_mask"
#define DST_SUBNET_MASK               "dst_mask"
#define SRC_USER_SUBNET               "src_user_subnet"
#define DST_USER_SUBNET               "dst_user_subnet"
#define SRC_AS                        "src_as"
#define DST_AS                        "dst_as"
#define SRC_PORT                      "srcport"
#define DST_PORT                      "dstport"
#define PROT                          "prot"
#define PROTOCOL_KEY                  "protocol"
#define IN_INTF                       "input"
#define OUT_INTF                      "output"
#define TOS_BIT                       "tos"
#define NEXT_HOP                      "nexthop"

/* Value Fields */
#define PACKET                        "pkts"
#define OCTET                         "octets"
#define FLOW_CNT                      "flows"
#define F_FLOW_STAMP                  "starttime"
#define L_FLOW_STAMP                  "endtime"
#define TOT_ACTIVE_TIME               "activetime"

/* Delimiter */                       /* Could be either "|" or "," */
#define DEL                           "%c" 

/* Aggregation Mask */
const char * const SourceNodeDef        = SRC_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DestNodeDef          = DST_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const HostMatrixDef        = SRC_ADDR DEL 
                                          DST_ADDR DEL 
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const SourcePortDef        = SRC_PORT DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DestPortDef          = DST_PORT DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const ProtocolDef          = PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailSourceNodeDef  = SRC_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailDestNodeDef    = DST_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const DetailHostMatrixDef  = SRC_ADDR DEL 
                                          DST_ADDR DEL 
                                          SRC_PORT DEL 
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL
                                          PACKET DEL OCTET DEL FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP;

const char * const DetailInterfaceDef   = SRC_ADDR DEL
                                          DST_ADDR DEL
                                          IN_INTF DEL
                                          OUT_INTF DEL
                                          NEXT_HOP DEL
                                          PACKET DEL OCTET DEL FLOW_CNT;

const char * const CallRecordDef        = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_PORT DEL  
                                          DST_PORT DEL  
                                          PROT DEL  
                                          TOS_BIT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const ASMatrixDef          = SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT; 

const char * const DetailASMatrixDef    = SRC_ADDR DEL
                                          DST_ADDR DEL
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          SRC_PORT DEL
                                          DST_PORT DEL
                                          PROTOCOL_KEY DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const NetMatrixDef         = SRC_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          DST_SUBNET DEL  
                                          DST_SUBNET_MASK DEL  
                                          OUT_INTF DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const ASHostMatrixDef      = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const HostMatrixInterfaceDef
                                        = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PROTOCOL_KEY DEL
                                          PACKET DEL  OCTET DEL  FLOW_CNT;

const char * const DetailCallRecordDef  = SRC_ADDR DEL  
                                          DST_ADDR DEL  
                                          SRC_PORT DEL  
                                          DST_PORT DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PROTOCOL_KEY DEL  
                                          TOS_BIT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterASDef          = SRC_AS DEL  
                                          DST_AS DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterProtoPortDef   = SRC_PORT DEL  
                                          DST_PORT DEL  
                                          PROT DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterSrcPrefixDef   = SRC_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          SRC_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterDstPrefixDef   = DST_SUBNET DEL  
                                          DST_SUBNET_MASK DEL  
                                          OUT_INTF DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;

const char * const RouterPrefixDef      = SRC_SUBNET DEL  
                                          DST_SUBNET DEL  
                                          SRC_SUBNET_MASK DEL  
                                          DST_SUBNET_MASK DEL  
                                          IN_INTF DEL  
                                          OUT_INTF DEL  
                                          SRC_AS DEL  
                                          DST_AS DEL  
                                          PACKET DEL  OCTET DEL  FLOW_CNT DEL
                                          F_FLOW_STAMP DEL L_FLOW_STAMP DEL 
                                          TOT_ACTIVE_TIME;
#endif


#if !defined(NFC_DATAFILE_H)
#define NFC_DATAFILE_H
/*
 *------------------------------------------------------------------ 
 * $Id: //depot/argus/argus/include/argus_parse.h#17 $
 * $Source: $
 *------------------------------------------------------------------
 * Definition of datafile formats.
 *
 * Binary datafile : Each binary datafiles contains a header and 
 *                   a list of records. 
 *
 *                   The header contains format, aggregation, 
 *                   agg_version, source, period, starttime, endtime, 
 *                   activetime, flows, missed, and records.
 * 
 *                   Each record structure contains a set of "Keys" 
 *                   and a "Values" that is specific to the 
 *                   aggregation scheme being used.
 *
 * Cisco NetFlow FlowCollector 3.0
 *
 * October 1998, Anders Fung
 *
 * Copyright (c) 1998 by Cisco Systems, Inc.
 * All rights reserved.
 *------------------------------------------------------------------
 * $Log: argus_parse.h,v $
 * Revision 1.1  2003/04/16 20:53:57  qosient
 * Modified for argus to argus conversion
 *
 * Revision 1.12  2003/02/05 23:43:53  qosient
 * Updated for new year in the copyright
 *
 * Revision 1.11  2002/04/01 22:41:01  qosient
 * Updated
 *
 * Revision 1.10  2002/04/01 15:39:32  qosient
 * Update for handling loss of remote when connected to multiple remotes.
 * Increase ARGUS_MAX_REMOTE_NUM and RADIUM_MAX_REMOTE_NUM.
 *
 * Revision 1.9  2002/03/25 17:49:49  qosient
 * Updated for correct copyright
 *
 * Revision 1.8  2002/03/25 17:38:32  qosient
 * Updated for correct interface status reporting
 *
 * Revision 1.6  2002/02/02 16:01:27  qosient
 * Updated for next versions of DSRs
 *
 * Revision 1.5  2002/02/01 14:10:00  qosient
 * Updated for libpcap-0.7.1 port
 *
 * Revision 1.4  2002/01/04 22:15:08  qosient
 * Updated
 *
 * Revision 1.3  2001/12/17 18:12:45  qosient
 * Mods to move ramux to radium
 *
 * Revision 1.2  2001/10/24 20:47:53  qosient
 * Updated
 *
 * Revision 1.5  2001/10/22 20:20:07  qosient
 * Updated and fixed for Lflag having bad default value
 *
 * Revision 1.4  2001/10/18 17:15:29  qosient
 * Fixed for output file fd handling issues, primarily for rapop
 *
 * Revision 1.3  2001/10/15 20:07:29  qosient
 * Updated for ramux issues with authentication. Stopped erasing password.
 *
 * Revision 1.2  2001/09/12 05:09:30  qosient
 * Updated
 *
 * Revision 1.1.1.1  2001/09/08 22:01:48  qosient
 * Argus Clients 1.0
 *
 * Revision 1.6  2001/09/03 04:58:51  argus
 * Lots of mods
 *
 * Revision 1.5  2001/07/17 12:38:45  argus
 * Updated
 *
 * Revision 1.4  2001/07/10 18:18:10  argus
 * Mods for ramon and rasort port
 *
 * Revision 1.3  2001/06/09 14:10:09  argus
 * Minor changes for -H option and formatting
 *
 * Revision 1.2  2001/06/07 19:50:45  argus
 * Updated
 *
 * Revision 1.1.1.1  2001/06/03 16:07:57  argus
 * Start of argus client distribution
 *
 * Revision 1.1.1.1  2001/03/24 05:14:27  argus
 * Imported from argus-2.0.0
 *
 * Revision 1.39  2001/03/06 23:30:41  argus
 * Fix for Davids incredibly long command lines.
 *
 * Revision 1.38  2001/02/03 21:39:08  argus
 * Mods to support -d option
 *
 * Revision 1.37  2000/12/19 16:19:41  argus
 * Mods to get ramon() to the same level as ra() with regard to dynamic
 * labels.  Also FreeBSD/NetBSD port support for racount().
 *
 * Revision 1.36  2000/12/19 05:59:03  argus
 * Mods to help in getting pretty output when not using -n.
 *
 * Revision 1.35  2000/12/10 20:59:13  argus
 * Mods to add support for RA_AUTH_PASS (pstr)
 *
 * Revision 1.34  2000/12/07 19:00:39  argus
 * Mods to convert from ArgusError to ArgusLog
 *
 * Revision 1.33  2000/12/07 17:51:48  argus
 * Move Uflag (precision option) to -p option.
 *
 * Revision 1.32  2000/11/23 01:58:29  argus
 * Mods to support GSSAPI authentication
 *
 * Revision 1.31  2000/11/16 15:20:34  argus
 * Update for SASL
 *
 * Revision 1.30  2000/11/13 21:51:38  argus
 * Mods to support ragrep().
 *
 * Revision 1.29  2000/11/13 15:05:14  argus
 * Fixes for raxml not printing out user data in all protocol types.
 *
 * Revision 1.28  2000/10/31 19:35:01  argus
 * Mods to support new timestats and user data.
 *
 * Revision 1.27  2000/10/27 13:45:42  argus
 * Fix support for multiple remote sources.
 *
 * Revision 1.26  2000/10/27 01:48:50  argus
 * Fixes for multiple source data.
 *
 * Revision 1.25  2000/10/26 15:38:09  argus
 * Mods for qflag defintions and some constants
 *
 * Revision 1.24  2000/10/25 22:23:30  argus
 * Mods to try to fix the LITTLE_ENDIAN issues for Neil.
 *
 * Revision 1.23  2000/10/16 21:55:48  argus
 * support for various .rc's.
 *
 * Revision 1.22  2000/10/11 12:51:37  argus
 * Added Zflag
 *
 * Revision 1.21  2000/10/10 14:50:51  argus
 * Fixes to support XML printing (print_time changes) and a bunch to support
 * TCP fixes.
 *
 * Revision 1.20  2000/10/05 15:04:47  argus
 * Addition of output labels for ra data.
 *
 * Revision 1.19  2000/10/03 23:04:29  argus
 * Mods for more complete cisco netflow parsing and -CS support.  Needs testing.
 *
 * Revision 1.18  2000/10/01 14:27:45  argus
 * Put the filter in a global so we can all get to it.
 *
 * Revision 1.17  2000/09/30 15:03:13  argus
 * Addition of netflow record definitions.
 *
 *------------------------------------------------------------------
 * $Endlog$
 */


#define LABEL_LEN         16
#define IP_LEN            15
#define ASCII_HEADER_LEN  511
#define BIN_FILE_SUFFIX   ".bin"


#if !defined(__NFC__)
enum Aggregation
{
  noAgg,             /* reserved */
  RawFlows,          /* Not supported in binary files */
  SourceNode,
  DestNode,
  HostMatrix,
  SourcePort,
  DestPort,
  Protocol,
  DetailDestNode,
  DetailHostMatrix,
  DetailInterface,
  CallRecord,
  ASMatrix,
  NetMatrix,
  DetailSourceNode,
  DetailASMatrix,
  ASHostMatrix,
  HostMatrixInterface,
  DetailCallRecord,
  RouterAS,
  RouterProtoPort,
  RouterSrcPrefix,
  RouterDstPrefix,
  RouterPrefix
};
#endif


typedef struct {
    u_short format;             /* Header format, it is 2 in this round */
    char    newline;            /* Newline character, '\n' */
    char    ascii_header[ASCII_HEADER_LEN];  /* Header in ASCII */
    u_char  aggregation;        /* Aggregation scheme used */
    u_char  agg_version;        /* Version of the aggregation scheme used */
    char    source[IP_LEN];     /* Source IP/Name */
    u_char  period;             /* Aggregation period, 0 means PARTIAL */
    u_long  starttime;          /* Beginning of aggregation period */
    u_long  endtime;            /* End of aggregation period */
    u_long  flows;              /* Number of flows aggregated */
    int     missed;             /* Number of flows missed, -1 means not avail*/
    u_long  records;            /* Number of records in this datafile */
} BinaryHeaderF2;

#define HEADER_FORMAT_2 2


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */

} BinaryRecord_SourceNode_V1;

#define SOURCENODE_V1 1


typedef struct {
                                /* Keys */
    u_long  dstaddr;            /* Destination IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DestNode_V1;

#define DESTNODE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_HostMatrix_V1;

#define HOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    char    srcport[LABEL_LEN]; /* Source Port Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_SourcePort_V1;

#define SOURCEPORT_V1 1


typedef struct {
                                /* Keys */
    char    dstport[LABEL_LEN]; /* Destination Port Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DestPort_V1;

#define DESTPORT_V1 1


typedef struct {
                                /* Keys */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_Protocol_V1;

#define PROTOCOL_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailSourceNode_V1;

#define DETAIL_SOURCENODE_V1 1


typedef struct {
                                /* Keys */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailDestNode_V1;

#define DETAIL_DESTNODE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
} BinaryRecord_DetailHostMatrix_V1;

#define DETAIL_HOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    u_long  nexthop;            /* Next Hop IP */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailInterface_V1;

#define DETAIL_INTERFACE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short srcport;            /* Source Port Number */
    u_short dstport;            /* Destination Port Number */
    u_char  prot;               /* Protocol Number */
    u_char  tos;                /* Type of Service */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_CallRecord_V1;

#define CALLRECORD_V1 1


typedef struct {
                                /* Keys */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_ASMatrix_V1;

#define ASMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_DetailASMatrix_V1;

#define DETAIL_ASMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short input;              /* Input Interface Number */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short output;             /* Output Interface Number */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_NetMatrix_V1;

#define NETMATRIX_V1 1


typedef struct {
                                /* Keys */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterAS_V1;

#define ROUTERAS_V1 1


typedef struct {
                                /* Keys */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    u_char  prot;               /* Protocol Number */
    u_char  pad;                /* Data alignment */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterProtoPort_V1;

#define ROUTERPROTOPORT_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short input;              /* Input Interface Number */
    char    src_as[LABEL_LEN];  /* Source AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterSrcPrefix_V1;

#define ROUTERSRCPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short output;             /* Output Interface Number */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterDstPrefix_V1;

#define ROUTERDSTPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  src_subnet;         /* Source SubNet */
    u_long  dst_subnet;         /* Destination SubNet */
    u_short src_mask;           /* Source SubNet Mask */
    u_short dst_mask;           /* Destination SubNet Mask */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_RouterPrefix_V1;

#define ROUTERPREFIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    src_as[LABEL_LEN];  /* Source AS */
    char    dst_as[LABEL_LEN];  /* Destination AS */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_ASHostMatrix_V1;

#define ASHOSTMATRIX_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    protocol[LABEL_LEN];/* Protocol Key */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
} BinaryRecord_HostMatrixInterface_V1;

#define HOSTMATRIXINTERFACE_V1 1


typedef struct {
                                /* Keys */
    u_long  srcaddr;            /* Source IP */
    u_long  dstaddr;            /* Destination IP */
    char    srcport[LABEL_LEN]; /* Source Port Key */
    char    dstport[LABEL_LEN]; /* Destination Port Key */
    u_short input;              /* Input Interface Number */
    u_short output;             /* Output Interface Number */
    char    protocol[LABEL_LEN];/* Protocol Key */
    u_char  tos;                /* Type of Service */
    u_char  pad;                /* Data alignment */
    u_short reserved;           /* Data alignment */

                                /* Values */
    u_long  pkts;               /* Packet count */
    u_long  octets;             /* Byte count */
    u_long  flows;              /* Flow count */
    u_long  starttime;          /* Start time */
    u_long  endtime;            /* End time */
    u_long  activetime;         /* Total Active Time */
} BinaryRecord_DetailCallRecord_V1;

#define DETAILCALLRECORD_V1 1


typedef struct {
    BinaryHeaderF2 header;
    union {
            BinaryRecord_SourceNode_V1          * srcnode;
            BinaryRecord_DestNode_V1            * dstnode;
            BinaryRecord_HostMatrix_V1          * hostmatrix;
            BinaryRecord_SourcePort_V1          * srcport;
            BinaryRecord_DestPort_V1            * dstport;
            BinaryRecord_Protocol_V1            * protocol;
            BinaryRecord_DetailSourceNode_V1    * detailsrcnode;
            BinaryRecord_DetailDestNode_V1      * detaildstnode;
            BinaryRecord_DetailHostMatrix_V1    * detailhostmatix;
            BinaryRecord_DetailInterface_V1     * detailinterface;
            BinaryRecord_CallRecord_V1          * callrecord;
            BinaryRecord_ASMatrix_V1            * asmatrix;
            BinaryRecord_DetailASMatrix_V1      * detailasmatrix;
            BinaryRecord_NetMatrix_V1           * netmatrix;
            BinaryRecord_ASHostMatrix_V1        * ashostmatrix;
            BinaryRecord_HostMatrixInterface_V1 * hostmatrixinterface;
            BinaryRecord_DetailCallRecord_V1    * detailcallrecord;
            BinaryRecord_RouterAS_V1            * routeras;
            BinaryRecord_RouterProtoPort_V1     * routerprotoport;
            BinaryRecord_RouterSrcPrefix_V1     * routersrcprefix;
            BinaryRecord_RouterDstPrefix_V1     * routerdstprefix;
            BinaryRecord_RouterPrefix_V1        * routerprefix;
    } record;
} BinaryDatafile;


#define MAX_BINARY_HEADER_F2 \
            (sizeof(BinaryHeaderF2))

#define MAX_BINARY_RECORD_SOURCE_NODE_SIZE \
            (sizeof(BinaryRecord_SourceNode_V1))

#define MAX_BINARY_RECORD_DESTINATION_NODE_SIZE \
            (sizeof(BinaryRecord_DestNode_V1))

#define MAX_BINARY_RECORD_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_HostMatrix_V1))

#define MAX_BINARY_RECORD_SOURCE_PORT_SIZE \
            (sizeof(BinaryRecord_SourcePort_V1))

#define MAX_BINARY_RECORD_DESTINATION_PORT_SIZE \
            (sizeof(BinaryRecord_DestPort_V1))

#define MAX_BINARY_RECORD_PROTOCOL_SIZE \
            (sizeof(BinaryRecord_Protocol_V1))

#define MAX_BINARY_RECORD_DETAIL_SOURCE_NODE_SIZE \
            (sizeof(BinaryRecord_DetailSourceNode_V1))

#define MAX_BINARY_RECORD_DETAIL_DESTINATION_NODE_SIZE \
            (sizeof(BinaryRecord_DetailDestNode_V1))

#define MAX_BINARY_RECORD_DETAIL_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_DetailHostMatrix_V1))

#define MAX_BINARY_RECORD_DETAIL_INTERFACE_SIZE \
            (sizeof(BinaryRecord_DetailInterface_V1))

#define MAX_BINARY_RECORD_CALL_RECORD_SIZE \
            (sizeof(BinaryRecord_CallRecord_V1))

#define MAX_BINARY_RECORD_AS_MATRIX_SIZE \
            (sizeof(BinaryRecord_ASMatrix_V1))

#define MAX_BINARY_RECORD_DETAIL_AS_MATRIX_SIZE \
            (sizeof(BinaryRecord_DetailASMatrix_V1))

#define MAX_BINARY_RECORD_NET_MATRIX_SIZE \
            (sizeof(BinaryRecord_NetMatrix_V1))

#define MAX_BINARY_RECORD_AS_HOST_MATRIX_SIZE \
            (sizeof(BinaryRecord_ASHostMatrix_V1))

#define MAX_BINARY_RECORD_HOST_MATRIX_INTERFACE_SIZE \
            (sizeof(BinaryRecord_HostMatrixInterface_V1))

#define MAX_BINARY_RECORD_DETAIL_CALL_RECORD_SIZE \
            (sizeof(BinaryRecord_DetailCallRecord_V1))

#define MAX_BINARY_RECORD_ROUTER_AS_SIZE \
            (sizeof(BinaryRecord_RouterAS_V1))

#define MAX_BINARY_RECORD_ROUTER_PROTO_PORT_SIZE \
            (sizeof(BinaryRecord_RouterProtoPort_V1))

#define MAX_BINARY_RECORD_ROUTER_SRC_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterSrcPrefix_V1))

#define MAX_BINARY_RECORD_ROUTER_DST_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterDstPrefix_V1))

#define MAX_BINARY_RECORD_ROUTER_PREFIX_SIZE \
            (sizeof(BinaryRecord_RouterPrefix_V1))

#endif /* __NFC_DATAFILE_H__ */

#endif /* RaMuxSource  ||  RadiumSource */
#endif /* ArgusParse_h */

