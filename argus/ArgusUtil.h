/*
 * Argus Software.  Argus files - Utilities include files
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
 * Copyright (c) 1993, 1994 Carnegie Mellon University.
 * All rights reserved.
 *
 * Permission to use, copy, modify, and distribute this software and
 * its documentation for any purpose and without fee is hereby granted,
 * provided that the above copyright notice appear in all copies and
 * that both that copyright notice and this permission notice appear
 * in supporting documentation, and that the name of CMU not be
 * used in advertising or publicity pertaining to distribution of the
 * software without specific, written prior permission.
 *
 * CMU DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE, INCLUDING
 * ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS, IN NO EVENT SHALL
 * CMU BE LIABLE FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR
 * ANY DAMAGES WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS,
 * WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS
 * SOFTWARE.
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusUtil.h#33 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


/* ArgusUtil.h */

#ifndef ArgusUtil_h
#define ArgusUtil_h

#if defined(HAVE_STDLIB_H)
#include <stdlib.h>
#endif

#if defined(HAVE_STRINGS_H)
#include <strings.h>
#endif

#include <sys/time.h>
#include <sys/socket.h>

#include <net/if.h>

#include <argus_compat.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#define ARGUS_NOLOCK		0
#define ARGUS_LOCK		1

#define ARGUS_RFILE_LIST	1
#define ARGUS_WFILE_LIST	2
#define ARGUS_DEVICE_LIST	3
#define ARGUS_OUTPUT_LIST	4
#define ARGUS_EVENT_LIST	5
#define ARGUS_BIND_ADDR_LIST	6

struct ArgusListObjectStruct {
   struct ArgusListObjectStruct *nxt;
   void *obj;
};

struct ArgusListRecord {
   struct ArgusListObjectStruct *nxt;
   struct ArgusRecordHeader argus;
};

struct ArgusListStruct {
   struct ArgusListObjectStruct *start;
   struct ArgusListObjectStruct *end;

#if defined(ARGUS_THREADS)
   pthread_mutex_t lock;
   pthread_cond_t cond;
#endif
   unsigned int count, pushed, popped, loaded;
   struct timeval outputTime, reportTime;
};


#define ARGUS_PROCESS_NEXT_PASS		0x10

/*
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
*/

#include <ArgusOutput.h>


#define ARGUS_READINGPREHDR     1
#define ARGUS_READINGHDR        2
#define ARGUS_READINGBLOCK      4

#define ARGUS_WAS_FUNCTIONAL		0x10
#define ARGUS_SOCKET_COMPLETE		0x20
#define ARGUS_MAXRECORD			0x40000

struct ArgusSocketStruct {
   struct ArgusListStruct *ArgusSocketList;
   int fd, status, cnt, expectedSize, errornum;
   int ArgusLastRecord, ArgusReadState;
   struct timeval lastwrite;
   struct ArgusRecordStruct *rec;
   int length, writen;
   struct sockaddr sock;
   char *filename;
   void *obj;
   unsigned char *ptr, buf[ARGUS_MAXRECORD];
};

typedef int (*ArgusHandler)(struct ArgusSocketStruct *, unsigned char *, int, void *);


#if defined(ArgusUtil)

#if defined(_LITTLE_ENDIAN)
void ArgusNtoH (struct ArgusRecord *);
void ArgusHtoN (struct ArgusRecord *);
#endif

long long ArgusTimeDiff (struct timeval *, struct timeval *);
unsigned long long ArgusAbsTimeDiff (struct timeval *, struct timeval *);

struct ArgusListStruct *ArgusNewList(void);
void ArgusDeleteList(struct ArgusListStruct *, int);
 
int ArgusListEmpty (struct ArgusListStruct *);
int ArgusGetListCount (struct ArgusListStruct *);
 
int ArgusPushFrontList(struct ArgusListStruct *, struct ArgusListRecord *, int);
int ArgusPushBackList (struct ArgusListStruct *, struct ArgusListRecord *, int);
struct ArgusListRecord *ArgusPopFrontList (struct ArgusListStruct *, int);
void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *); 

struct ArgusQueueStruct *ArgusNewQueue (void);
void ArgusDeleteQueue (struct ArgusQueueStruct *);
 
int ArgusGetQueueCount(struct ArgusQueueStruct *);
 
void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
 
struct ArgusQueueHeader *ArgusPopQueue(struct ArgusQueueStruct *, int);
struct ArgusQueueHeader *ArgusPopBackQueue (struct ArgusQueueStruct *queue, int type);
struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
 
int ArgusCheckTimeout(struct ArgusModelerStruct *, struct timeval *, struct timeval *);

void ArgusProcessQueue(struct ArgusModelerStruct *, struct ArgusQueueStruct *, int);
void ArgusEmptyQueue(struct ArgusQueueStruct *);

void ArgusDeleteObject(struct ArgusFlowStruct *);

struct ArgusHashTableHeader *ArgusFindHashObject (struct ArgusHashTable *, struct ArgusSystemFlow *, unsigned short);
extern struct ArgusHashTableHeader *ArgusAddHashEntry (struct ArgusHashTable *, struct ArgusFlowStruct *, struct ArgusHashStruct *);
void ArgusRemoveHashEntry (struct ArgusHashTableHeader *);

struct ArgusSocketStruct * ArgusNewSocket (int fd);
void ArgusDeleteSocket (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusReadSocket (struct ArgusSocketStruct *, ArgusHandler, void *);
int ArgusWriteSocket (struct ArgusOutputStruct *, struct ArgusClientData *, struct ArgusRecordStruct *);
int ArgusWriteOutSocket (struct ArgusOutputStruct *, struct ArgusClientData *);

char *ArgusGetFlowString (struct ArgusFlowStruct *);

char *ArgusGetName(struct ArgusParserStruct *, unsigned char *);
char *ArgusGetV6Name(struct ArgusParserStruct *, unsigned char *);

void ArgusSetChroot(char *);

#ifdef ARGUSDEBUG
extern void ArgusDebug (int, char *, ...);
#endif

struct timeval *RaMinTime (struct timeval *, struct timeval *);
struct timeval *RaMaxTime (struct timeval *, struct timeval *); 

float RaDeltaFloatTime (struct timeval *, struct timeval *);

int RaDiffTime (struct timeval *, struct timeval *, struct timeval *); 
float RaGetFloatDuration (struct ArgusRecordStruct *); 
float RaGetFloatSrcDuration (struct ArgusRecordStruct *); 
float RaGetFloatDstDuration (struct ArgusRecordStruct *);
double ArgusFetchDuration (struct ArgusRecordStruct *);
double ArgusFetchSrcDuration (struct ArgusRecordStruct *);
double ArgusFetchDstDuration (struct ArgusRecordStruct *);
double ArgusFetchLoad (struct ArgusRecordStruct *);
double ArgusFetchSrcLoad (struct ArgusRecordStruct *);
double ArgusFetchDstLoad (struct ArgusRecordStruct *);
double ArgusFetchLoss (struct ArgusRecordStruct *);
double ArgusFetchSrcLoss (struct ArgusRecordStruct *);
double ArgusFetchDstLoss (struct ArgusRecordStruct *);
double ArgusFetchPercentLoss (struct ArgusRecordStruct *);
double ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *);
double ArgusFetchPercentDstLoss (struct ArgusRecordStruct *);
double ArgusFetchRate (struct ArgusRecordStruct *);
double ArgusFetchSrcRate (struct ArgusRecordStruct *);
double ArgusFetchDstRate (struct ArgusRecordStruct *);
double ArgusFetchAppByteRatio (struct ArgusRecordStruct *);

#else

 
#if defined(_LITTLE_ENDIAN)
extern void ArgusNtoH (struct ArgusRecord *);
extern void ArgusHtoN (struct ArgusRecord *);
#endif

extern long long ArgusTimeDiff (struct timeval *, struct timeval *);
extern unsigned long long ArgusAbsTimeDiff (struct timeval *, struct timeval *);
extern struct ArgusListStruct *ArgusNewList(void);
extern void ArgusDeleteList(struct ArgusListStruct *, int);

extern int ArgusListEmpty (struct ArgusListStruct *);
extern int ArgusGetListCount (struct ArgusListStruct *);

extern int ArgusPushFrontList(struct ArgusListStruct *, struct ArgusListRecord *, int);
extern int ArgusPushBackList (struct ArgusListStruct *, struct ArgusListRecord *, int);
extern struct ArgusListRecord *ArgusPopFrontList (struct ArgusListStruct *, int);
extern void ArgusLoadList(struct ArgusListStruct *, struct ArgusListStruct *); 

extern struct ArgusQueueStruct *ArgusNewQueue (void);
extern int ArgusDeleteQueue (struct ArgusQueueStruct *);

extern int ArgusGetQueueCount(struct ArgusQueueStruct *);

extern void ArgusPushQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);
extern int ArgusAddToQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

extern struct ArgusQueueHeader *ArgusPopQueue(struct ArgusQueueStruct *, int);
struct ArgusQueueHeader *ArgusPopBackQueue (struct ArgusQueueStruct *queue, int type);
extern struct ArgusQueueHeader *ArgusRemoveFromQueue(struct ArgusQueueStruct *, struct ArgusQueueHeader *, int);

extern int ArgusCheckTimeout(struct ArgusModelerStruct *, struct timeval *, struct timeval *);

extern void ArgusProcessQueue(struct ArgusModelerStruct *, struct ArgusQueueStruct *, int);
extern void ArgusEmptyQueue(struct ArgusQueueStruct *);

extern void ArgusDeleteObject(struct ArgusFlowStruct *obj);

struct ArgusHashTableHeader *ArgusFindHashObject (struct ArgusHashTable *, struct ArgusSystemFlow *, unsigned short);
extern struct ArgusHashTableHeader *ArgusAddHashEntry (struct ArgusHashTable *, struct ArgusFlowStruct *, struct ArgusHashStruct *);
extern void ArgusRemoveHashEntry (struct ArgusHashTableHeader *);

extern struct ArgusSocketStruct * ArgusNewSocket (int fd);
extern void ArgusDeleteSocket (struct ArgusOutputStruct *, struct ArgusClientData *);
extern int ArgusWriteSocket (struct ArgusOutputStruct *, struct ArgusClientData *, struct ArgusRecordStruct *);
extern int ArgusWriteOutSocket (struct ArgusOutputStruct *, struct ArgusClientData *);

extern char *ArgusGetFlowString (struct ArgusFlowStruct *);

extern char *ArgusGetName(struct ArgusParserStruct *, unsigned char *);
extern char *ArgusGetV6Name(struct ArgusParserStruct *, unsigned char *);

extern void ArgusSetChroot(char *);

#ifdef ARGUSDEBUG
extern void ArgusDebug (int, char *, ...);
#endif

  
extern struct timeval *RaMinTime (struct timeval *, struct timeval *);
extern struct timeval *RaMaxTime (struct timeval *, struct timeval *); 

extern float RaDeltaFloatTime (struct timeval *, struct timeval *);

extern int RaDiffTime (struct timeval *, struct timeval *, struct timeval *); 
extern float RaGetFloatDuration (struct ArgusRecordStruct *); 
extern float RaGetFloatSrcDuration (struct ArgusRecordStruct *); 
extern float RaGetFloatDstDuration (struct ArgusRecordStruct *);
extern double ArgusFetchDuration (struct ArgusRecordStruct *);
extern double ArgusFetchSrcDuration (struct ArgusRecordStruct *);
extern double ArgusFetchDstDuration (struct ArgusRecordStruct *);
extern double ArgusFetchLoad (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoad (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoad (struct ArgusRecordStruct *);
extern double ArgusFetchLoss (struct ArgusRecordStruct *);
extern double ArgusFetchSrcLoss (struct ArgusRecordStruct *);
extern double ArgusFetchDstLoss (struct ArgusRecordStruct *);
extern double ArgusFetchPercentLoss (struct ArgusRecordStruct *);
extern double ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *);
extern double ArgusFetchPercentDstLoss (struct ArgusRecordStruct *);
extern double ArgusFetchRate (struct ArgusRecordStruct *);
extern double ArgusFetchSrcRate (struct ArgusRecordStruct *);
extern double ArgusFetchDstRate (struct ArgusRecordStruct *);
extern double ArgusFetchAppByteRatio (struct ArgusRecordStruct *);

#endif
#endif
