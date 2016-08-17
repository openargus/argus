/*
 * Argus Software.  Argus files - Modeler
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusEvents.c#15 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusEvents)
#define ArgusEvents
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <math.h>
#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif
 
#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusUtil.h>
#include <argus_parser.h>
#include <argus_filter.h>
#include <ArgusEvents.h>


#if defined(ARGUS_THREADS)
#include <pthread.h>

void *ArgusEventsProcess(void *);
#endif



struct ArgusEventsStruct *
ArgusNewEvents ()
{
   struct ArgusEventsStruct *retn = NULL;

   if ((retn = (struct ArgusEventsStruct *) ArgusCalloc (1, sizeof (struct ArgusEventsStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewEvents() ArgusCalloc error %s\n", strerror(errno));

   if ((retn->ArgusEventsList = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewEvents() ArgusNewList %s\n", strerror(errno));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewEvents() returning retn 0x%x\n", retn);
#endif

   return (retn);
}



void
ArgusInitEvents (struct ArgusEventsStruct *events)
{
   if (events == NULL)
      return;

   events->ArgusModel      = ArgusModel;
   events->ArgusSrc        = ArgusSourceTask;
   events->ArgusOutputList = ArgusOutputTask->ArgusOutputList;

#if defined(ARGUS_THREADS)
   if ((events->ArgusEventsList != NULL) && (!(ArgusListEmpty(events->ArgusEventsList))))
      if ((pthread_create(&events->thread, NULL, ArgusEventsProcess, (void *) events)) != 0)
         ArgusLog (LOG_ERR, "ArgusNewEventProcessor() pthread_create error %s\n", strerror(errno));
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitEvents() done\n");
#endif
}

void
ArgusCloseEvents (struct ArgusEventsStruct *events)
{
   if (events != NULL) {
      events->status |= ARGUS_SHUTDOWN;

#if defined(ARGUS_THREADS)
      if (events->thread)
         pthread_cancel(events->thread);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCloseEvents() done\n");
#endif
}

#if defined(ARGUS_THREADS)
struct ArgusRecordStruct *ArgusGenerateEventRecord (struct ArgusEventsStruct *, struct ArgusEventRecordStruct *, unsigned char);

int
ArgusSortEventList (const void *item1, const void *item2)
{
   struct ArgusEventRecordStruct *event1 = *(struct ArgusEventRecordStruct **) item1;
   struct ArgusEventRecordStruct *event2 = *(struct ArgusEventRecordStruct **) item2;
   int retn = 0;

   if ((retn = (event1->poptime.tv_sec - event2->poptime.tv_sec)) == 0)
      retn = (event1->poptime.tv_nsec - event2->poptime.tv_nsec);

   return (retn);
}


#if !defined(TIMEVAL_TO_TIMESPEC)
void TIMEVAL_TO_TIMESPEC (struct timeval *, struct timespec *);
void
TIMEVAL_TO_TIMESPEC (struct timeval *tvp, struct timespec *ts)
{
   ts->tv_sec  = tvp->tv_sec;
   ts->tv_nsec = tvp->tv_usec * 1000;
}
#endif

void *
ArgusEventsProcess(void *arg)
{
   struct ArgusEventsStruct *events = (struct ArgusEventsStruct *) arg;
   struct ArgusEventRecordStruct *evtarray[1024];
   struct ArgusEventRecordStruct *evt;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   void *retn = NULL;
   int cnt, i;

   do {
      struct ArgusRecordStruct *rec = NULL;
      struct timespec tsbuf, *ts = &tsbuf;
      struct timespec rmtpb, *rmtp = &rmtpb;

      if (events->status & ARGUS_SHUTDOWN)
         break;

      if (!(ArgusListEmpty(events->ArgusEventsList))) {
         cnt = ArgusGetListCount(events->ArgusEventsList);
         memset(evtarray, 0, sizeof(evtarray));

         for (i = 0; i < cnt; i++) {
            if ((evt = (void *)ArgusPopFrontList(events->ArgusEventsList, ARGUS_LOCK)) != NULL) {
               evtarray[i] = evt;
               if (evt->poptime.tv_sec == 0) {
                  gettimeofday(tvp, 0L);
                  TIMEVAL_TO_TIMESPEC(tvp, &evt->poptime);
                  evt->poptime.tv_sec   += evt->interval;
                  evt->remaining.tv_sec  = evt->interval;

               } else {
                  struct timeval tvpbuf, *tvp = &tvpbuf;
                  gettimeofday(tvp, 0L);
                  TIMEVAL_TO_TIMESPEC(tvp, ts);
                  evt->remaining.tv_sec  = evt->poptime.tv_sec - ts->tv_sec;
                  evt->remaining.tv_nsec = evt->poptime.tv_nsec - ts->tv_nsec;

                  while ((evt->remaining.tv_nsec < 0) && (evt->remaining.tv_sec > 0)) {
                     evt->remaining.tv_sec  -= 1;
                     evt->remaining.tv_nsec += 1000000000;
                  }
               }

               ArgusPushBackList(events->ArgusEventsList, (struct ArgusListRecord *) evt, ARGUS_LOCK);
            }
         }

         qsort (evtarray, cnt, sizeof(evt), ArgusSortEventList);

         evt = evtarray[0];
         *ts = evt->remaining;

         if (events->status & ARGUS_SHUTDOWN)
            break;

         if ((ts->tv_sec > 0) || ((ts->tv_sec == 0) && (ts->tv_nsec > 100))) {
            while (nanosleep (ts, rmtp)) {
               *ts = *rmtp;
               if ((rmtp->tv_sec == 0) && (rmtp->tv_nsec == 0))
                  break;
               if (events->status & ARGUS_SHUTDOWN)
                  break;
            }
         }

         if (events->status & ARGUS_SHUTDOWN)
            break;

         if ((rec = ArgusGenerateEventRecord(events, evt, ARGUS_STATUS)) != NULL)
            ArgusPushBackList (events->ArgusOutputList, (struct ArgusListRecord *) rec, ARGUS_LOCK);

         if (evt->interval > 0) {
            gettimeofday(tvp, 0L);
            TIMEVAL_TO_TIMESPEC(tvp, &evt->poptime);
            evt->poptime.tv_sec   += evt->interval;
            evt->remaining.tv_sec  = evt->interval;

         } else {
            evtarray[0] = NULL;
            if (evt->entry)
               free(evt->entry);
            if (evt->method)
               free(evt->method);
            if (evt->filename)
               free(evt->filename);
            ArgusFree(evt);
         }
      }

#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusEventsProcess circuit done\n");
#endif

   } while (!(events->status & ARGUS_SHUTDOWN));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusEventsProcess() exiting\n");
#endif

   pthread_exit(retn);
   return(retn);
}


#define ARGUS_MAX_OS_STATUS	64512
#define ARGUS_MAX_OS_BUF	65536


struct ArgusRecordStruct *
ArgusGenerateEventRecord (struct ArgusEventsStruct *events, struct ArgusEventRecordStruct *evt, unsigned char status)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusRecord *rec = NULL;
   int ocnt = 0, cnt = 0, tcnt = 0, len = ARGUS_MAX_OS_BUF;
   struct timeval now, then;

   if ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (len)) == NULL)
      ArgusLog (LOG_ERR, "ArgusMallocListRecord returned NULL\n");

   memset ((char *)retn, 0, ARGUS_MAX_OS_STATUS);
   retn->hdr.type    = ARGUS_EVENT | ARGUS_VERSION;
   retn->hdr.cause   = status;

   gettimeofday(&then, 0L);

   rec = (struct ArgusRecord *) &retn->canon;

   if (strncmp(evt->method, "file", 4) == 0)  {
      int fd = 0;
      if ((fd = open(evt->filename, O_RDONLY)) > 0) {
#if defined(HAVE_ZLIB_H)
         if (evt->status & ARGUS_ZLIB_COMPRESS) {
            char buf[ARGUS_MAX_OS_STATUS], *ptr = buf;

            snprintf (buf, ARGUS_MAX_OS_STATUS - 1, "file:%s\n", evt->filename);
            tcnt = strlen(buf);
            if ((cnt = read(fd, &ptr[tcnt], (ARGUS_MAX_OS_STATUS - tcnt))) > 0) {
               uLong slen = cnt, dlen = (ARGUS_MAX_OS_STATUS - tcnt);
               if (compress((Bytef *) &rec->argus_event.data.array, &dlen, (Bytef *)&buf, slen) != Z_OK)
                  ArgusLog (LOG_ERR, "compress problem %s", strerror(errno));
               ocnt = cnt;
               cnt = dlen;
            }
         } else {
#endif
            char buf[ARGUS_MAX_OS_STATUS];

            snprintf(buf, ARGUS_MAX_OS_STATUS - 1, "file:%s\n", evt->filename);
            strcpy(rec->argus_event.data.array, buf);
            tcnt = strlen(rec->argus_event.data.array);
            cnt = read(fd, &rec->argus_event.data.array[tcnt], len - tcnt);
            ocnt = cnt;
#if defined(HAVE_ZLIB_H)
         }
#endif
         close(fd);
      }

   } else 
   if (strncmp(evt->method, "prog", 4) == 0)  {
      char result[ARGUS_MAX_OS_STATUS], *ptr = NULL;
      int terror = 0, len = ARGUS_MAX_OS_STATUS;
      FILE *fd = NULL;

      memset(result, 0, sizeof(result));
      snprintf(result, ARGUS_MAX_OS_STATUS - 1, "prog:%s\n", evt->filename);
      tcnt = strlen(result);

      if ((fd = popen(evt->filename, "r")) != NULL) {
         ptr = NULL;
         clearerr(fd);
         while ((!(feof(fd))) && (!(ferror(fd))) && (len > tcnt)) {
            if ((ptr = fgets(&result[tcnt], len - tcnt, fd)) == NULL) {
               if (ferror(fd)) {
                  terror++;
                  break;
               }
            } else {
               tcnt += strlen(ptr);
               if (strlen(ptr) == 0)
                  break;
            }
         }

         if (terror == 0)
            ptr = result;
         else
            ptr = NULL;
         pclose(fd);

      } else
         ArgusLog (LOG_WARNING, "ArgusGenerateEvent: System error: popen(%s) %s\n", evt->filename, strerror(errno));

      if (ptr != NULL) {
         char buf[ARGUS_MAX_OS_STATUS];

#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusGenerateEventRecord(%s:%s) returned %d bytes", evt->method, evt->filename, strlen(ptr));
#endif
#if defined(HAVE_ZLIB_H)
         if (evt->status & ARGUS_ZLIB_COMPRESS) {
            unsigned long slen = tcnt, dlen = ARGUS_MAX_OS_STATUS;
            if (compress((Bytef *) &rec->argus_event.data.array, &dlen, (Bytef *)ptr, slen) != Z_OK)
               ArgusLog (LOG_ERR, "compress problem %s", strerror(errno));
            ocnt = slen;
            cnt = dlen;
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusGenerateEventRecord(%s:%s) compress ratio %f", evt->method, evt->filename, cnt*1.0/ocnt*1.0);
#endif
         } else {
#endif
            ocnt = tcnt;
            strncpy(buf, ptr, ARGUS_MAX_OS_STATUS);
            strcpy((char *)&rec->argus_event.data.array, buf);
            cnt = strlen((char *)&rec->argus_event.data.array);
#if defined(HAVE_ZLIB_H)
         }
#endif
      }
   }
/*
struct ArgusEventStruct {
   struct ArgusDSRHeader       event;
   struct ArgusTransportStruct trans;
   struct ArgusEventTimeStruct  time;
   struct ArgusDataStruct       data;
};


struct ArgusFarStruct {
   struct ArgusFlow flow;
};

struct ArgusRecord {
   struct ArgusRecordHeader hdr;
   union {
      struct ArgusMarStruct     mar;
      struct ArgusFarStruct     far;
      struct ArgusEventStruct event;
   } ar_un;
};
*/
   if (cnt > 0) {
      struct ArgusTimeObject       *time = &rec->argus_event.time;
      struct ArgusTransportStruct *trans = &rec->argus_event.trans;
      struct ArgusDataStruct       *data = &rec->argus_event.data;
      int tlen = 1;

      gettimeofday(&now, 0L);

      time->hdr.type               = ARGUS_TIME_DSR;
      time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_TIMESTAMP | ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END;
      time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
      time->hdr.argus_dsrvl8.len   = 5;
      tlen += time->hdr.argus_dsrvl8.len;

      retn->dsrs[ARGUS_TIME_INDEX] = &time->hdr;
      retn->dsrindex |= 1 << ARGUS_TIME_INDEX;

      time->src.start.tv_sec  = then.tv_sec;
      time->src.start.tv_usec = then.tv_usec;
      time->src.end.tv_sec    = now.tv_sec;
      time->src.end.tv_usec   = now.tv_usec;

      trans->hdr.type              = ARGUS_TRANSPORT_DSR;
      trans->hdr.subtype           = ARGUS_SRCID | ARGUS_SEQ;
      trans->hdr.argus_dsrvl8.qual = events->ArgusSrc->type;
      trans->hdr.argus_dsrvl8.len  = 3;
      tlen += trans->hdr.argus_dsrvl8.len;

      retn->dsrs[ARGUS_TRANSPORT_INDEX] = &trans->hdr;
      retn->dsrindex |= 1 << ARGUS_TRANSPORT_INDEX;

      trans->srcid.a_un.value      = getArgusID(events->ArgusSrc);
      trans->seqnum                = events->ArgusSrc->ArgusModel->ArgusSeqNum++;

      data->hdr.type               = ARGUS_DATA_DSR;
      data->hdr.subtype            = ARGUS_LEN_16BITS | ARGUS_SRC_DATA;

      if (evt->status & ARGUS_ZLIB_COMPRESS)
         data->hdr.subtype        |= ARGUS_DATA_COMPRESS;

      len  = 2 + ((cnt + 3)/4);
      data->hdr.argus_dsrvl16.len  = len;
      data->count                  = cnt;
      data->size                   = ocnt;

      tlen += len;

      if ((retn->dsrs[ARGUS_SRCUSERDATA_INDEX] = ArgusCalloc(1, len * 4)) == NULL)
         ArgusLog (LOG_ERR, "ArgusGenerateEventRecord() ArgusCalloc error %s\n", strerror(errno));

      bcopy((char *)data, (char *)retn->dsrs[ARGUS_SRCUSERDATA_INDEX], len * 4);
      retn->dsrindex |= 1 << ARGUS_SRCUSERDATA_INDEX;

      retn->hdr.len = tlen;
      bcopy((char *)&retn->hdr, &rec->hdr, sizeof(rec->hdr));

#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusGenerateEventRecord(%s:%s) retn 0x%x cnt %d ocnt %d", evt->method, evt->filename, retn, cnt, ocnt);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusGenerateEventRecord(0x%x, %d) returning 0x%x", events, status, retn);
#endif

   return (retn);
}
#endif /* ARGUS_THREADS */
