/*
 * Argus Software Common include files - Parser
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
 * $Id: //depot/argus/argus/include/argus_parser.h#21 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


#if !defined(Argus_parser_h)
#define Argus_parser_h

#include <argus_compat.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

#include <argus_debug.h>
#include <argus_def.h>
#include <argus_int.h>

#define ARGUS_PRINTSRC	0x0001
#define ARGUS_PRINTDST	0x0002
#define ARGUS_ACTTIME	0x0004
#define ARGUS_IDLETIME	0x0008
#define ARGUS_DIST	0x0010

#define ARGUS_PRINTGMT	0x0020
#define ARGUS_PRINTNET	0x0022

 
#define ARGUS_ENCODE_ASCII       0
#define ARGUS_ENCODE_64          1
#define ARGUS_ENCODE_32          2

#define ARGUS_MAX_S_OPTIONS      34 
#define HASHNAMESIZE		256

#define ARGUS_FORCE_LOCAL_SRC           0x02
#define ARGUS_FORCE_LOCAL_DST           0x04
#define ARGUS_SUGGEST_LOCAL_SRC         0x08
#define ARGUS_SUGGEST_LOCAL_DST         0x10

#define ARGUS_PORT_SERVICES             0x100
#define ARGUS_PORT_WELLKNOWN            0x200
#define ARGUS_PORT_REGISTERED           0x400

#define ARGUS_ADDR_DIR_MASK (ARGUS_SUGGEST_LOCAL_SRC | ARGUS_SUGGEST_LOCAL_DST | ARGUS_FORCE_LOCAL_SRC | ARGUS_FORCE_LOCAL_DST)
#define ARGUS_PORT_DIR_MASK (ARGUS_PORT_SERVICES | ARGUS_PORT_WELLKNOWN | ARGUS_PORT_REGISTERED)

#include <netinet/in.h>
 
struct h6namemem {
   struct in6_addr addr; 
   char *name; 
   struct h6namemem *nxt; 
}; 
 
struct hnamemem { 
   u_int addr; 
   char *name; 
   struct hnamemem *nxt; 
}; 

struct enamemem {
   u_short e_addr0; 
   u_short e_addr1; 
   u_short e_addr2; 
   char *e_name; 
   u_char *e_nsap;         /* used only for nsaptable[] */ 
   struct enamemem *e_nxt; 
}; 
 
 
struct protoidmem { 
   u_int p_oui; 
   u_short p_proto; 
   char *p_name; 
   struct protoidmem *p_nxt;
};

 
struct ArgusCIDRAddr {
   u_char type, len, masklen, opmask; 
   u_int addr[4], mask[4];
};

struct ArgusParserStruct {
   int status;
   char fflag, nflag, tflag, uflag, Wflag;
   char Iflag, Tflag, rflag, Rflag, Sflag, xflag;
   char Xflag, XMLflag, zflag, Zflag, pflag;

   int RaCumulativeMerge, RaFlowMajorModified;
   int RaAllocHashTableHealers, RaAllocArgusRecord;
   int RaThisActiveIndex, RaThisFlowNum;
   int RaThisModelNum, RaParseError;
   int ArgusSessionId, NonBlockingDNS, ArgusDSCodePoints;
   int ArgusDirectionFunction;

   char *RaFlowModelFile, *ArgusFlowModelFile, *ArgusRemoteFilter;
   struct RaFlowModelStruct *RaFlowModel;

   struct ArgusCIDRAddr ArgusCIDRBuffer, *ArgusCIDRPtr;

   struct ArgusModeStruct *ArgusModeList;
   struct ArgusInput *ArgusCurrentInput;

   int ArgusFilterFiledes[2];
   int ArgusControlFiledes[2];

   int ArgusSrvInit;
 
   unsigned int f_localnet, f_netmask;
   struct protoidmem protoidtable[HASHNAMESIZE];
   struct enamemem enametable[HASHNAMESIZE]; 
   struct enamemem nsaptable[HASHNAMESIZE]; 

 #define ARGUS_MAXEPROTODB   0x10000
   struct ArgusEtherTypeStruct *argus_eproto_db[ARGUS_MAXEPROTODB];
  
   struct h6namemem h6nametable[HASHNAMESIZE];
   struct hnamemem  hnametable[HASHNAMESIZE];
   struct hnamemem  tporttable[HASHNAMESIZE];
   struct hnamemem  uporttable[HASHNAMESIZE];
   struct hnamemem  eprototable[HASHNAMESIZE];
   struct hnamemem  nnametable[HASHNAMESIZE];
   struct hnamemem  llcsaptable[HASHNAMESIZE];
};


#define ARGUSMONITOR_EQUAL      0x01
#define ARGUSMONITOR_NOTEQUAL   0x02

struct ArgusCIDRAddr *RaParseCIDRAddr (struct ArgusParserStruct *, char *);

#if defined(Argus_Parser)
struct ArgusParserStruct *ArgusNewParser(char *);
void ArgusCloseParser(struct ArgusParserStruct *);
struct ArgusParserStruct *ArgusParser;

#else
extern struct ArgusParserStruct *ArgusNewParser(char *);
extern void ArgusCloseParser(struct ArgusParserStruct *);
extern struct ArgusParserStruct *ArgusParser;

#endif

#endif
