/*
 * Gargoyle Software.  Argus files - Output include files
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
 * $Id: //depot/gargoyle/argus/argus/ArgusOutput.h#7 $
 * $DateTime: 2015/04/21 19:24:29 $
 * $Change: 3018 $
 */



#ifndef ArgusOutput_h
#define ArgusOutput_h

#define ARGUS_MONITORPORT		561
#define ARGUS_MAXLISTEN			10

#define ARGUS_CLIENT_STARTUP_TIMEOUT    5

#include <unistd.h>
#if defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif
#include <limits.h>

#include <sys/socket.h>
#include <netdb.h>

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <strings.h>

#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>

#if defined(__NetBSD__)
#include <sys/sched.h>
#else
#include <sched.h>
#endif

#include <fcntl.h>
#include <signal.h>

#if !defined(ARGUS_TILERA)
#include <pcap.h>
#endif

#include <argus_filter.h>

#ifdef ARGUS_SASL
#include <sasl/sasl.h>
#endif

struct ArgusClientData {
   struct ArgusQueueHeader qhdr;
   int fd, type, ArgusClientStart;
   int ArgusFilterInitialized;
   struct timeval startime, lasttime;
   struct ArgusSocketStruct *sock;
   struct nff_program ArgusNFFcode;
   char *filename, *hostname, *filter;

#if defined(HAVE_GETADDRINFO)
   struct addrinfo *host;
#endif

#ifdef ARGUS_SASL
   sasl_conn_t *sasl_conn;
   struct {
      char *ipremoteport;
      char *iplocalport;
      sasl_ssf_t ssf;
      char *authid;
   } saslprops;
#endif
};

struct ArgusBindAddrStruct {
   struct ArgusListObjectStruct *nxt;
   char *addr;
};



struct ArgusOutputStruct {
   int type, status;
 
#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
#endif

   struct ArgusSourceStruct *ArgusSrc;
   struct ArgusModelerStruct *ArgusModel;
   struct ArgusListStruct *ArgusWfileList;

   struct ArgusListStruct *ArgusOutputList;
   struct ArgusListStruct *ArgusInputList;

   struct ArgusQueueStruct *ArgusClients;
   struct ArgusListStruct *ArgusBindAddrs;
   struct ArgusRecord *ArgusInitMar;

   long long ArgusTotalRecords, ArgusLastRecords;

   int ArgusWriteStdOut;
   int ArgusOutputSequence;

#if defined(HAVE_GETADDRINFO)
   struct addrinfo ArgusAddrInfo;
#endif

   int ArgusPortNum;
   int ArgusLfd[ARGUS_MAXLISTEN];
   int ArgusListens, nflag;
 
   char *ArgusBindPort;

   struct timeval ArgusGlobalTime;
   struct timeval ArgusStartTime;
   struct timeval ArgusReportTime;
   struct timeval ArgusLastMarUpdateTime;
   struct timeval ArgusMarReportInterval;
};

struct ArgusWfileStruct {
   struct ArgusListObjectStruct *nxt;
   char *filename;
   char *filter;
};


#if defined(ArgusOutput)

struct ArgusOutputStruct *ArgusOutputTask = NULL;

struct ArgusOutputStruct *ArgusNewOutput (struct ArgusSourceStruct *, struct ArgusModelerStruct *);

void ArgusCloseOutput (struct ArgusOutputStruct *);
 
void ArgusInitOutput (struct ArgusOutputStruct *);
void ArgusInitOutputProcess(void);

void *ArgusOutputProcess(void *);

int  ArgusTcpWrapper (int, struct sockaddr *);

void ArgusUsr1Sig (int);
void ArgusUsr2Sig (int);
void ArgusChildExit (int);

void ArgusClientError(void);
void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

#if defined(ARGUS_TILERA)
#else
extern char *ArgusFilterCompile(struct nff_program *, char *, int);
extern unsigned int argus_filter (struct bpf_insn *, unsigned char *);
#endif
extern int getArgusPortNum(void);

#else

#if defined(Argus)
int getArgusPortNum(struct ArgusOutputStruct *);
int getArgusPortType(struct ArgusOutputStruct *);
void setArgusPortNum(struct ArgusOutputStruct *, int);
 
void setArgusBindAddr (struct ArgusOutputStruct *, char *);
void setArgusBindPort (struct ArgusOutputStruct *, char *);
char *getArgusBindAddr (struct ArgusOutputStruct *);
char *getArgusBindPort (struct ArgusOutputStruct *);
#endif

extern struct timeval ArgusReportTime;
extern int ArgusPortNum;
extern char *ArgusBindAddr;
extern int ArgusOutfd;

extern struct ArgusOutputStruct *ArgusOutputTask;
extern struct ArgusOutputStruct *ArgusNewOutput (struct ArgusSourceStruct *, struct ArgusModelerStruct *);
extern void ArgusCloseOutput (struct ArgusOutputStruct *);

extern void ArgusInitOutput (struct ArgusOutputStruct *);
extern void ArgusInitOutputProcess(void);

extern void ArgusSendOutputData(int, struct ArgusRecord *);
extern int ArgusHandleData(struct ArgusSocketStruct *, unsigned char *, int, void *);
extern int ArgusHandleClientData(struct ArgusSocketStruct *, unsigned char *, int, void *);

extern void ArgusOutputProcess(void *);
extern void *ArgusClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

extern char *getArgusWfile(void);
extern void setArgusWfile(char *, char *);

extern struct timeval *getArgusMarReportInterval(struct ArgusOutputStruct *);
extern void setArgusMarReportInterval(struct ArgusOutputStruct *, char *);

extern void ArgusCheckClientStatus (struct ArgusOutputStruct *, int);
extern int  ArgusTcpWrapper (int, struct sockaddr *);

extern void ArgusCloseSocket (int);
extern void ArgusCloseClients (void);

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern void ArgusClientError(void);
extern void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

#endif
#endif /* #ifndef ArgusOutput_h */

