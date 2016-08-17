/*
 * Argus Software.  Argus files - Output include file
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
 * $Id: //depot/argus/argus/argus/ArgusOutput.h#23 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
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
   struct ArgusSourceStruct *ArgusSrc;
   struct ArgusModelerStruct *ArgusModel;
   struct ArgusListStruct *ArgusWfileList;

   struct ArgusListStruct *ArgusOutputList;
   struct ArgusListStruct *ArgusInputList;

   struct ArgusQueueStruct *ArgusClients;
   struct ArgusListStruct *ArgusBindAddrs;
   struct ArgusRecord *ArgusInitMar;

   long long ArgusTotalRecords, ArgusLastRecords;

   int status;

#if defined(ARGUS_THREADS)
   pthread_t thread;
   pthread_mutex_t lock;
#endif

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

int ArgusEstablishListen (struct ArgusOutputStruct *, char *);
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
extern int ArgusEstablishListen (struct ArgusOutputStruct *, char *);
extern int  ArgusTcpWrapper (int, struct sockaddr *);

extern void ArgusCloseSocket (int);
extern void ArgusCloseClients (void);

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern void ArgusClientError(void);
extern void ArgusInitClientProcess(struct ArgusClientData *, struct ArgusWfileStruct *);

#endif
#endif /* #ifndef ArgusOutput_h */

