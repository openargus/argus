/*
 * Argus Software.  Argus files - Utilities
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
 * $Id: //depot/argus/argus/argus/ArgusUtil.c#88 $
 * $DateTime: 2015/08/06 16:35:55 $
 * $Change: 3044 $
 */

/* ArgusUtil.c */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define _GNU_SOURCE

#if !defined(ArgusUtil)
#define ArgusUtil
#endif

#include <stdlib.h>
#include <inttypes.h>
#include <stdio.h>
#include <math.h>

#if defined(HAVE_SYS_VFS_H)
#include <sys/vfs.h>
#else
#include <sys/param.h>
#include <sys/mount.h>
#endif


#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif 

#if defined(ARGUS_SASL)
#include <sasl/sasl.h>
#endif 

#define Argus_Parser

#include <argus_compat.h>
#include <argus_parser.h>

#include <ArgusModeler.h>
#include <argus_dscodepoints.h>
#include <argus_encapsulations.h>


long long
ArgusTimeDiff (struct timeval *start, struct timeval *stop)
{
   long long retn, stime, etime;

   stime = (start->tv_sec * 1000000LL) + start->tv_usec;
   etime = (stop->tv_sec  * 1000000LL) +  stop->tv_usec;

   retn = stime - etime;
   return (retn);
}

unsigned long long
ArgusAbsTimeDiff (struct timeval *start, struct timeval *stop)
{
   unsigned long long retn = 0;
   struct timeval *t1 = start, *t2 = stop;

   if ((stop->tv_sec < start->tv_sec) || ((stop->tv_sec == start->tv_sec) &&
                                          (stop->tv_usec < start->tv_usec))) {
      t2 = start;
      t1 = stop;
   }

   retn = ((t2->tv_sec * 1000000LL) + t2->tv_usec) - 
          ((t1->tv_sec * 1000000LL) + t1->tv_usec);

   return (retn);
}


struct ArgusListStruct *
ArgusNewList ()
{
   struct ArgusListStruct *retn = NULL;
 
   if ((retn = (struct ArgusListStruct *) ArgusCalloc (1, sizeof (struct ArgusListStruct))) != NULL) {
      retn->start = NULL;
      retn->count = 0;
#if defined(ARGUS_THREADS)
      pthread_mutex_init(&retn->lock, NULL);
      pthread_cond_init(&retn->cond, NULL);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusNewList () returning %p\n", retn);
#endif
   return (retn);
}

void
ArgusDeleteList (struct ArgusListStruct *list, int type)
{
   if (list) {
#ifdef ARGUSDEBUG
      ArgusDebug (4, "ArgusDeleteList (%p, %d) %d items on list\n", list, type, list->count);
#endif
      while (list->start) {
         struct ArgusListRecord *retn = ArgusPopFrontList(list, ARGUS_LOCK);
         switch (type) {
             case ARGUS_RFILE_LIST: {
                struct ArgusRfileStruct *rfile = (struct ArgusRfileStruct *) retn;
                if (rfile->name != NULL)
                   free(rfile->name);
                ArgusFree(retn);
                break;
             }

             case ARGUS_WFILE_LIST: {
                struct ArgusWfileStruct *wfile = (struct ArgusWfileStruct *) retn;
                if (wfile->filename != NULL)
                   free(wfile->filename);
                if (wfile->filter != NULL)
                   free(wfile->filter);
                ArgusFree(retn);
                break;
             }

             case ARGUS_DEVICE_LIST: {
                struct ArgusDeviceStruct *device = (struct ArgusDeviceStruct *) retn;
                if (device->name != NULL)
                   free(device->name);
                ArgusFree(retn);
                break;
             }

             case ARGUS_OUTPUT_LIST:
                ArgusFreeListRecord(retn);
                break;

             case ARGUS_EVENT_LIST: {
                struct ArgusListObjectStruct *lobj = (struct ArgusListObjectStruct *) retn;
                if (lobj->obj != NULL) {
                   ArgusFree(lobj);
                }
                ArgusFree(retn);
                break;
            }

             case ARGUS_BIND_ADDR_LIST: {
                struct ArgusBindAddrStruct *baddr = (struct ArgusBindAddrStruct *) retn;
                if (baddr->addr != NULL) {
                   free(baddr->addr);
                }
                ArgusFree(retn);
                break;
            }
         }
      }
#if defined(ARGUS_THREADS)
      pthread_cond_destroy(&list->cond);
      pthread_mutex_destroy(&list->lock);
#endif
      ArgusFree (list);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteList (%p, %d) returning\n", list, type);
#endif
}

int
ArgusListEmpty (struct ArgusListStruct *list)
{
   return (list->count == 0);
}

int
ArgusGetListCount(struct ArgusListStruct *list)
{
   return (list->count);
}


int
ArgusPushFrontList(struct ArgusListStruct *list, struct ArgusListRecord *rec, int lstat)
{
   int retn = 0;

   if (list && rec) {
#if defined(ARGUS_THREADS)
      if (lstat)
         pthread_mutex_lock(&list->lock);
#endif
      if (list->start) {
         rec->nxt = list->start;
      } else {
         rec->nxt = NULL;
      }
      list->start = (struct ArgusListObjectStruct *) rec;
      if (list->end == NULL)
         list->end = (struct ArgusListObjectStruct *) rec;
      list->count++;
      list->pushed++;
#if defined(ARGUS_THREADS)
      if (lstat)
         pthread_mutex_unlock(&list->lock);
#endif
      retn++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusPushFrontList (%p, %p, %d) returning %p\n", list, rec, lstat);
#endif

   return (retn);
}

int
ArgusPushBackList(struct ArgusListStruct *list, struct ArgusListRecord *rec, int lstat)
{
   int retn = 0;

   if (list && rec) {
      rec->nxt = NULL;
   
#if defined(ARGUS_THREADS)
      if (lstat)
         pthread_mutex_lock(&list->lock);
#endif
      if (list->end) {
         list->end->nxt = (struct ArgusListObjectStruct *) rec;
      } else {
         list->start = (struct ArgusListObjectStruct *) rec;
      }
      list->end = (struct ArgusListObjectStruct *) rec;
      list->count++;
      list->pushed++;
#if defined(ARGUS_THREADS)
      if (lstat)
         pthread_mutex_unlock(&list->lock);
#endif
      retn++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusPushBackList (%p, %p, %d) returning %d\n", list, rec, lstat, retn);
#endif

   return (retn);
}


void
ArgusLoadList(struct ArgusListStruct *l1, struct ArgusListStruct *l2)
{
   if (l1 && l2) {
      int count;
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&l1->lock);
      pthread_mutex_lock(&l2->lock);
#endif
      count = l1->count;

      if (l2->start == NULL)
         l2->start = l1->start;
      else
         l2->end->nxt = l1->start;

      l2->end = l1->end;
      l2->count += count;

      l1->start = NULL;
      l1->end = NULL;
      l1->loaded += count;
      l1->count = 0;

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&l2->lock);
      pthread_mutex_unlock(&l1->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusLoadList (%p, %p) load %d objects\n", l1, l2, count);
#endif
   }
}


struct ArgusListRecord *
ArgusPopFrontList(struct ArgusListStruct *list, int lstat)
{
   struct ArgusListRecord *retn = NULL;

#if defined(ARGUS_THREADS)
   if (lstat)
      pthread_mutex_lock(&list->lock);
#endif
   if ((retn = (struct ArgusListRecord *) list->start)) {
      list->start = retn->nxt;
      list->count--;
      list->popped++;
      if (list->start == NULL) {
         list->end = NULL;
         if (list->count != 0)
            ArgusLog (LOG_ERR, "ArgusPopFrontList(%p, %d) list empty count is %d\n", list, lstat, list->count);
      }
   }
#if defined(ARGUS_THREADS)
   if (lstat)
      pthread_mutex_unlock(&list->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusPopFrontList (%p) returning\n", retn);
#endif

   return (retn);
}


struct ArgusQueueStruct *
ArgusNewQueue ()
{
   struct ArgusQueueStruct *retn =  NULL;

   if ((retn = (struct ArgusQueueStruct *) ArgusCalloc (1, sizeof (struct ArgusQueueStruct))) != NULL) {
      retn->count = 0;
#if defined(ARGUS_THREADS)
      pthread_mutex_init(&retn->lock, NULL);
#endif
      retn->start = NULL;
      retn->end   = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusNewQueue () returning %p\n", retn);
#endif

   return (retn);
}

void
ArgusDeleteQueue (struct ArgusQueueStruct *queue)
{
   struct ArgusQueueHeader *obj = NULL;

   if (queue != NULL) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&queue->lock); 
#endif

#ifdef ARGUSDEBUG
      if (queue->count > 0) 
         ArgusDebug (1, "ArgusDeleteQueue (%p) contains %d items\n", queue, queue->count);
#endif
      while ((obj = ArgusPopQueue(queue, ARGUS_LOCK)))
         ArgusFree(obj);

      if (queue->array != NULL) {
         ArgusFree(queue->array);
         queue->array = NULL;
      }

#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&queue->lock); 
#endif

#if defined(ARGUS_THREADS)
      pthread_mutex_destroy(&queue->lock);
#endif
      ArgusFree(queue);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteQueue (%p) returning\n", queue);
#endif
}



int
ArgusGetQueueCount(struct ArgusQueueStruct *queue)
{

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusGetQueueCount (%p) returning %d\n", queue, queue->count);
#endif

   return (queue->count);
}


void
ArgusPushQueue(struct ArgusQueueStruct *queue, struct ArgusQueueHeader *obj, int type)
{
#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_lock(&queue->lock); 
#endif
   if ((ArgusAddToQueue (queue, obj, ARGUS_NOLOCK)) > 0) {
      queue->start = queue->start->prv;
      queue->end   = queue->start->prv;
   }

#if defined(ARGUS_THREADS)
   if (type == ARGUS_LOCK)
      pthread_mutex_unlock(&queue->lock); 
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusPushQueue (%p, %p) returning\n", queue, obj);
#endif
}


int
ArgusAddToQueue(struct ArgusQueueStruct *queue, struct ArgusQueueHeader *obj, int type)
{
   int retn = 0;

   if (queue && obj) {
      if (obj->queue == NULL) {
#if defined(ARGUS_THREADS)
         if (type == ARGUS_LOCK)
            pthread_mutex_lock(&queue->lock); 
#endif
         if (queue->start != NULL) {
            obj->prv = queue->start->prv;
            queue->start->prv = obj;
            obj->nxt = queue->start;
            obj->prv->nxt = obj;
         } else {
            queue->start = obj;
            obj->nxt = obj;
            obj->prv = obj;
         }
         queue->end = obj;
         queue->count++;
#if defined(ARGUS_THREADS)
         if (type == ARGUS_LOCK)
            pthread_mutex_unlock(&queue->lock); 
#endif
         obj->queue = queue;

         if (ArgusSourceTask->ArgusReadingOffLine)
            obj->qtime = ArgusModel->ArgusGlobalTime;
         else
            gettimeofday(&obj->qtime, 0L);
         retn = 1;

      } else
         ArgusLog (LOG_ERR, "ArgusAddToQueue (%p, %p) obj in queue %p\n", queue, obj, obj->queue);
   } else
      ArgusLog (LOG_ERR, "ArgusAddToQueue (%p, %p) parameter error\n", queue, obj);

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusAddToQueue (%p, %p) returning %d\n", queue, obj, retn);
#endif

   return (retn);
}


struct ArgusQueueHeader *
ArgusPopQueue (struct ArgusQueueStruct *queue, int type)
{
   struct ArgusQueueHeader *retn = NULL;
   struct ArgusQueueHeader *obj = NULL;

   if (queue && queue->count) {
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_lock(&queue->lock); 
#endif
      if ((obj = (struct ArgusQueueHeader *) queue->start) != NULL) {
         queue->count--;

         if (queue->count) {
            if (queue->start == obj)
               queue->start = obj->nxt;

            obj->prv->nxt = obj->nxt;
            obj->nxt->prv = obj->prv;

            queue->end    = queue->start->prv;

         } else {
            queue->start = NULL;
            queue->end   = NULL;
         }
      }
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_unlock(&queue->lock); 
#endif

      if (obj != NULL) {
         obj->prv = NULL;
         obj->nxt = NULL;
         obj->queue = NULL;
         retn = obj;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusPopQueue (%p) returning %p\n", queue, retn);
#endif
   
   return(retn);
}

struct ArgusQueueHeader *
ArgusPopBackQueue (struct ArgusQueueStruct *queue, int type)
{
   struct ArgusQueueHeader *retn = NULL;
   struct ArgusQueueHeader *obj = NULL;

   if (queue && queue->count) {
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_lock(&queue->lock);
#endif
      if ((obj = (struct ArgusQueueHeader *) queue->end) != NULL) {
         queue->count--;

         if (queue->count) {
            if (queue->start == obj)
               queue->start = obj->nxt;

            obj->prv->nxt = obj->nxt;
            obj->nxt->prv = obj->prv;

            queue->end    = queue->start->prv;

         } else {
            queue->start = NULL;
            queue->end   = NULL;
         }
      }
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_unlock(&queue->lock);
#endif

      if (obj != NULL) {
         obj->prv = NULL;
         obj->nxt = NULL;
         obj->queue = NULL;
         retn = obj;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusPopBackQueue (%p) returning %p\n", queue, retn);
#endif

   return(retn);
}


struct ArgusQueueHeader *
ArgusRemoveFromQueue(struct ArgusQueueStruct *queue, struct ArgusQueueHeader *obj, int type)
{
   struct ArgusQueueHeader *retn = NULL;

   if ((queue != NULL) && (obj != NULL)) {
#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_lock(&queue->lock); 
#endif
      if (obj->queue == queue) {
         if (queue->count) {
            queue->count--;

            if (queue->count) {
               if (queue->start == obj)
                  queue->start = obj->nxt;

               obj->prv->nxt = obj->nxt;
               obj->nxt->prv = obj->prv;

               queue->end    = queue->start->prv;

            } else {
               queue->start = NULL;
               queue->end   = NULL;
            }
         }
         obj->prv = NULL;
         obj->nxt = NULL;
         obj->queue = NULL;
         retn = obj;
      }

#if defined(ARGUS_THREADS)
      if (type == ARGUS_LOCK)
         pthread_mutex_unlock(&queue->lock); 
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusRemoveFromQueue (%p, %p) returning %p\n", queue, obj, obj);
#endif

   return (retn);
}

#include <stdio.h>
#include <errno.h>


void
ArgusProcessQueue(struct ArgusModelerStruct *model, struct ArgusQueueStruct *queue, int status)
{
   struct ArgusFlowStruct *obj = NULL;
 
   switch (status) {
      case ARGUS_STOP:
      case ARGUS_SHUTDOWN:
#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusProcessQueue (%p, %d) Shuting Down with %d records\n", queue, status, queue->count);
#endif
         while (queue->count) {
            if ((obj = (struct ArgusFlowStruct *) ArgusPopBackQueue(queue, ARGUS_LOCK)) != NULL) {
               if (!(obj->status & ARGUS_RECORD_WRITTEN)) 
                  ArgusSendFlowRecord(model, obj, status);
               ArgusDeleteObject (obj);
            }
         }
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessQueue (%p, %d) returning\n", queue, status);
#endif
}


int
ArgusCheckTimeout(struct ArgusModelerStruct *model, struct timeval *ts, struct timeval *timeout)
{
   long long diff = 0, tdiff = 0;
   int retn;

   if (timeout->tv_sec < 0)  // if timeout is set to less that zero, then we never timeout.
      retn = 0;
   else {
      if ((timeout->tv_sec > 0) || (timeout->tv_usec > 0)) {
         diff  = ArgusTimeDiff (&model->ArgusGlobalTime, ts);
         tdiff = (timeout->tv_sec * 1000000LL + timeout->tv_usec);

         if (diff >= tdiff)
            retn = 1;
         else
            retn = 0;
      } else
         retn = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (11, "ArgusCheckTimeout (%p, %d.%06d, %d.%06d) diff %f returning %d\n", model, ts->tv_sec, ts->tv_usec,
                      timeout->tv_sec, timeout->tv_usec, (diff / 1000000.0), retn);
#endif

   return (retn);
}



void
ArgusDeleteObject(struct ArgusFlowStruct *obj)
{
   if (obj) {
      struct ArgusHashTableHeader *htblhdr;
      struct ArgusNetworkStruct *net = NULL;
      struct ArgusQueueStruct *queue;

      if ((queue = obj->qhdr.queue) != NULL) {
         if (ArgusRemoveFromQueue (queue, &obj->qhdr, ARGUS_LOCK)) {
            obj->qhdr.queue = NULL;
         } else 
            ArgusLog (LOG_ERR, "ArgusDeleteObject: race condition on queue %p\n", queue);
      }
 
      if ((htblhdr = obj->htblhdr) != NULL)  {
         ArgusRemoveHashEntry(htblhdr);
         obj->htblhdr = NULL;
      }

      if ((net = (struct ArgusNetworkStruct *) obj->dsrs[ARGUS_FRAG_INDEX]) != NULL) {
         if (net->hdr.subtype == ARGUS_NETWORK_SUBTYPE_FRAG) {
            struct ArgusFragObject *frag = &net->net_union.frag;
            struct ArgusFragOffsetStruct *fragOffset = frag->offsets.nxt;

            while ((fragOffset = frag->offsets.nxt) != NULL) {
               frag->offsets.nxt = fragOffset->nxt;
               free(fragOffset);
            }
            net->hdr.type = 0;
         }
      }

      if (obj->dsrs[ARGUS_SRCUSERDATA_INDEX] != NULL) {
         ArgusFree(obj->dsrs[ARGUS_SRCUSERDATA_INDEX]);
         obj->dsrs[ARGUS_SRCUSERDATA_INDEX] = NULL;
      }

      if (obj->dsrs[ARGUS_DSTUSERDATA_INDEX] != NULL) {
         ArgusFree(obj->dsrs[ARGUS_DSTUSERDATA_INDEX]);
         obj->dsrs[ARGUS_DSTUSERDATA_INDEX] = NULL;
      }

      if (obj->frag.start != NULL) {
         struct ArgusFlowStruct *frag;

         while ((frag = (void *) ArgusPopQueue(&obj->frag, ARGUS_LOCK))) {
            ArgusSendFlowRecord(ArgusModel, frag, ARGUS_TIMEOUT);
            ArgusDeleteObject(frag);
         }
      }

      ArgusFree(obj);
      ArgusModel->ArgusTotalClosedFlows++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteObject (%p) returning\n", obj);
#endif
}


int
ArgusUpdateTime (struct ArgusModelerStruct *model)
{
   long long ival = model->ival;
   long long diff;
   int retn = 0;

   if (model->ArgusUpdateTimer.tv_sec == 0) 
      model->ArgusUpdateTimer = model->ArgusGlobalTime;

   diff = ArgusTimeDiff(&model->ArgusGlobalTime, &model->ArgusUpdateTimer);

   if (diff >= 0) {
      retn = 1;

      if (diff > ival) 
         model->ArgusUpdateTimer = model->ArgusGlobalTime;

      model->ArgusUpdateTimer.tv_sec  += model->ArgusUpdateInterval.tv_sec;
      model->ArgusUpdateTimer.tv_usec += model->ArgusUpdateInterval.tv_usec;

      while (model->ArgusUpdateTimer.tv_usec >= 1000000) {
         model->ArgusUpdateTimer.tv_sec++; 
         model->ArgusUpdateTimer.tv_usec -= 1000000;
      }

   } else {

      if (ArgusSourceTask != NULL) {
         if (!(ArgusSourceTask->ArgusReadingOffLine)) {
            if (llabs(diff) > (ival * 2)) {

// something is wrong, so try to figure out if ArgusGlobalTime needs to be adjusted.
// Must be kernel time bug, so try to reset the ArgusUpdateTimer, and declare
// that the timer has popped.  Redefine global timer if needed.

               unsigned long long tdiff;
               struct timeval now;

               retn = 1;

               gettimeofday(&now, 0L);
               tdiff =  ArgusAbsTimeDiff(&now, &model->ArgusGlobalTime);

               if (tdiff > (ival * 2))
                  model->ArgusGlobalTime = now;

               model->ArgusUpdateTimer = model->ArgusGlobalTime;

               model->ArgusUpdateTimer.tv_sec  += model->ArgusUpdateInterval.tv_sec;
               model->ArgusUpdateTimer.tv_usec += model->ArgusUpdateInterval.tv_usec;

               while (model->ArgusUpdateTimer.tv_usec >= 1000000) {
                  model->ArgusUpdateTimer.tv_sec++;
                  model->ArgusUpdateTimer.tv_usec -= 1000000;
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   if (retn) {
      ArgusDebug (8, "ArgusUpdateTime (%p) global time %d.%06d update %d.%06d returning %d\n",
                   model, model->ArgusGlobalTime.tv_sec, model->ArgusGlobalTime.tv_usec,
                   model->ArgusUpdateTimer.tv_sec, model->ArgusUpdateTimer.tv_usec, retn);
   } else
      ArgusDebug (8, "ArgusUpdateTime (%p) not time\n", model);
#endif

   return (retn);
}

struct ArgusHashStats {
   int n, max;
};

struct ArgusHashTable *ArgusNewHashTable (size_t, int);
struct ArgusHashStats *ArgusHashTableStats = NULL;
int ArgusHashTableMax = 0;
void ArgusEmptyHashTable (struct ArgusHashTable *);
void ArgusDeleteHashTable (struct ArgusHashTable *);

struct ArgusHashTable *
ArgusNewHashTable (size_t size, int status)
{
   struct ArgusHashTable *retn = NULL;

   if ((retn = (struct ArgusHashTable *) ArgusCalloc (1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewHashTable: ArgusCalloc(1, %d) error %s\n", size, strerror(errno));

   if ((retn->array = (struct ArgusHashTableHeader **) ArgusCalloc (size, 
                                      sizeof (struct ArgusHashTableHeader *))) == NULL)
      ArgusLog (LOG_ERR, "RaMergeQueue: ArgusCalloc error %s\n", strerror(errno));

   retn->size = size;
#if defined(ARGUS_HASH_DEBUG)
   if ((retn->status = status) == ARGUSHASHTABLETRACK) {
      if (ArgusHashTableStats == NULL) {
         if ((ArgusHashTableStats = (struct ArgusHashStats *) ArgusCalloc (size, sizeof(struct ArgusHashStats))) == NULL)
            ArgusLog (LOG_ERR, "ArgusHashTableStats: ArgusCalloc(%d, %d) error %s\n",
                   size, sizeof(struct ArgusStatsObject), strerror(errno));
      }
   }
#endif
#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusNewHashTable (%d) returning %p\n", size, retn);
#endif

   return (retn);
}

void
ArgusDeleteHashTable (struct ArgusHashTable *htbl)
{

   if (htbl != NULL) {
      ArgusEmptyHashTable (htbl);

      if (htbl->array != NULL)
         ArgusFree(htbl->array);

      ArgusFree(htbl);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusDeleteHashTable (%p)\n", htbl);
#endif
}

void
ArgusEmptyHashTable (struct ArgusHashTable *htbl)
{
   struct ArgusHashTableHeader *htblhdr = NULL, *tmp;
   int i, count = 0, bins = 0;
 
#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&htbl->lock);
#endif
   for (i = 0; i < htbl->size; i++) {
      if ((htblhdr = htbl->array[i]) != NULL) {
         htblhdr->prv->nxt = NULL;
         while ((tmp = htblhdr) != NULL) {
            htblhdr = htblhdr->nxt;
            ArgusFree (tmp);
            htbl->items--;
            count++;
         }
         htbl->array[i] = NULL;
         htbl->bins--;
         bins++;
      }
   }


#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&htbl->lock);
#endif
 
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusEmptyHashTable (%p) cleared %d bins %d items\n", htbl, bins, count);
#endif
}


int
ArgusCreateFlowKey (struct ArgusModelerStruct *model, struct ArgusSystemFlow *flow, struct ArgusHashStruct *hstruct)
{
   unsigned int *ptr = (unsigned int *)&flow->flow_un;
   unsigned int *key = (unsigned int *) hstruct->key;
   int retn = 0, i, len = flow->hdr.argus_dsrvl8.len - 1;

   memset (hstruct, 0, sizeof(*hstruct));

   if (len > 0) {
      for (i = 0; i < len; i++)
         *key++ = *ptr++;

      hstruct->len = len;

      if (model->ArgusFlowKey & ARGUS_FLOW_KEY_VLAN) {
         *key++ = model->ArgusThisPacket8021QEncaps & 0x0FFF;
         hstruct->len++;
      }
   
      if (model->ArgusFlowKey & (ARGUS_FLOW_KEY_LOCAL_MPLS | ARGUS_FLOW_KEY_COMPLETE_MPLS)) {
         *key++ = model->ArgusThisMplsLabel;
         hstruct->len++;
      }

      if (model->ArgusFlowKey & (ARGUS_FLOW_KEY_LAYER_2 | ARGUS_FLOW_KEY_LAYER_2_MATRIX)) {
         struct ether_header *ep = model->ArgusThisEpHdr;
         if (ep) {
            int klen = (sizeof(*ep) + (sizeof(*key) - 1)) / sizeof(*key);
            if (model->state & ARGUS_DIRECTION) {
#ifndef ETH_ALEN
#define ETH_ALEN   6
#endif
               char *kptr = (char *) key;
               bcopy ((char *)&ep->ether_shost, kptr, ETH_ALEN); kptr += ETH_ALEN;
               bcopy ((char *)&ep->ether_dhost, kptr, ETH_ALEN); kptr += ETH_ALEN;
               bcopy ((char *)&ep->ether_type,  kptr, sizeof(ep->ether_type));

            } else
               bcopy (ep, key, sizeof(*ep));

            key += klen;
            hstruct->len += klen;
         }
      }

      ptr = hstruct->key;

      for (i = 0; i < hstruct->len; i++)
         hstruct->hash ^= *ptr++;

      hstruct->hash ^= hstruct->hash >> 16;
      hstruct->hash ^= hstruct->hash >> 8;
   }

   return (retn);
}


struct ArgusFlowStruct *
ArgusFindFlow (struct ArgusModelerStruct *model, struct ArgusHashStruct *hstruct)
{
   struct ArgusFlowStruct *retn = NULL;
   struct ArgusHashTableHeader *hashEntry = NULL, *target, *head;
   struct ArgusHashTable *table = model->ArgusHashTable;

   if (table && hstruct) {
      unsigned int hash = hstruct->hash;
      unsigned int ind = (hash % (table->size - 1)), i;

      if ((target = table->array[ind]) != NULL) {
         unsigned int *ptr3 = hstruct->key;
         int len = hstruct->len;
         head = target;

         do {
            if ((target->hstruct.hash == hash) && (target->hstruct.len == hstruct->len)) {
               unsigned int *ptr1 = target->hstruct.key;
               unsigned int *ptr2 = ptr3;

               if (len > 0) {
                  for (i = 0; i < len; i++)
                     if (*ptr1++ != *ptr2++)
                        break;
                  if (i == len) {
                     hashEntry = target;
                     break;
                  }

               } else 
                  hashEntry = target;
            }

            target = target->nxt;

         } while (target && (target != head) && (hashEntry == NULL));
    
         if (hashEntry != NULL) {
            if (hashEntry != head)
               table->array[ind] = hashEntry;
            retn = hashEntry->object;
         }
      }
   }
 
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusFindFlow () returning %p\n", retn);
#endif
  
   return (retn);
}

#define ARGUS_HASH_DEBUG	1

struct ArgusHashTableHeader *
ArgusAddHashEntry (struct ArgusHashTable *table, struct ArgusFlowStruct *flow, struct ArgusHashStruct *hstruct)
{
   struct ArgusHashTableHeader *retn = NULL, *start = NULL;

   if (table != NULL) {
      unsigned int hash = hstruct->hash;
      int ind;

      retn = &flow->htblbuf;
      memcpy(&retn->hstruct, hstruct, sizeof(*hstruct));
      retn->object = flow;

      ind = (hash % (table->size - 1));
      
      if ((start = table->array[ind]) != NULL) {
         retn->nxt = start;
         retn->prv = start->prv;
         retn->prv->nxt = retn;
         retn->nxt->prv = retn;
      } else {
         retn->prv = retn;
         retn->nxt = retn;
         table->bins++;
      }
      table->items++;

      table->array[ind] = retn;
      retn->htbl = table;
#if defined(ARGUS_HASH_DEBUG)
      if (table->status & ARGUSHASHTABLETRACK) {
         ArgusHashTableStats[ind].n++;
         if (ArgusHashTableStats[ind].max < ArgusHashTableStats[ind].n)
            ArgusHashTableStats[ind].max = ArgusHashTableStats[ind].n;

         if (ArgusHashTableMax < ArgusHashTableStats[ind].n)
            ArgusHashTableMax = ArgusHashTableStats[ind].n;
      }
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusAddHashEntry (%p) returning %p\n", flow, retn);
#endif

   return (retn);
}

 
void
ArgusRemoveHashEntry (struct ArgusHashTableHeader *htblhdr)
{
   if (htblhdr != NULL) {
      unsigned int hash = htblhdr->hstruct.hash;
      struct ArgusHashTable *table = htblhdr->htbl;

      if (table != NULL) {
         int ind = (hash % (table->size - 1));

         htblhdr->prv->nxt = htblhdr->nxt;
         htblhdr->nxt->prv = htblhdr->prv;

         if (htblhdr == table->array[ind]) {
            if (htblhdr == htblhdr->nxt) {
               table->array[ind] = NULL;
               table->bins--;
            } else
               table->array[ind] = htblhdr->nxt;
         }

         table->items--;

#if defined(ARGUS_HASH_DEBUG)
         if (table->status & ARGUSHASHTABLETRACK)
            ArgusHashTableStats[ind].n--;
#endif
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusRemoveHashEntry (%p) returning\n", htblhdr);
#endif
}


void ArgusZeroRecord (struct ArgusFlowStruct *);

void
ArgusZeroRecord (struct ArgusFlowStruct *flow)
{
   int i;

   flow->status &= ~ARGUS_RECORD_WRITTEN;
   flow->status &= ~0xF0;

   for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
      if (flow->dsrs[i] != NULL) {
         switch (i) {
            default:
               flow->dsrs[i] = NULL;
               break;

            case ARGUS_FLOW_INDEX: {
               struct ArgusFlow *tflow = (struct ArgusFlow *)flow->dsrs[i];
               tflow->hdr.argus_dsrvl8.qual &= ~ARGUS_FRAGMENT;
               break;
            }

            case ARGUS_TRANSPORT_INDEX:
            case ARGUS_MAC_INDEX:
               break;

            case ARGUS_JITTER_INDEX: {
               struct ArgusJitterStruct *jit = (void *)flow->dsrs[i];
               bzero ((char *)&jit->act, sizeof(struct ArgusJitterObject));
               bzero ((char *)&jit->idle, sizeof(struct ArgusJitterObject));
               jit->act.src.minval  = -1.0;
               jit->idle.src.minval = -1.0;
               jit->act.dst.minval  = -1.0;
               jit->idle.dst.minval = -1.0;
               break;
            }

            case ARGUS_IPATTR_INDEX: {
               struct ArgusIPAttrStruct *attr = (void *)flow->dsrs[i];
               attr->hdr.argus_dsrvl8.qual &= ~(ARGUS_IPATTR_SRC_FRAGMENTS | ARGUS_IPATTR_DST_FRAGMENTS);
               attr->src.status = 0; attr->src.options = 0;
               attr->dst.status = 0; attr->dst.options = 0;
               break;
            }

            case ARGUS_TIME_INDEX: {
               struct ArgusTimeObject *tim = (void *)flow->dsrs[i];
               bzero(&tim->src, sizeof(*tim) - 4);
               break;
            }

            case ARGUS_METRIC_INDEX: {
               struct ArgusMetricStruct *metric = (void *) flow->dsrs[i];
               bzero((&metric->hdr + 1), sizeof(*metric) - 4);
               break;
            }

            case ARGUS_NETWORK_INDEX: {
               struct ArgusNetworkStruct *net = NULL;
               if ((net = (struct ArgusNetworkStruct *) flow->dsrs[ARGUS_NETWORK_INDEX]) != NULL) {

                  switch (net->hdr.type) {
                     case ARGUS_NETWORK_DSR: {
                        switch (net->hdr.subtype) {
                           case ARGUS_NETWORK_SUBTYPE_FRAG: {
                              struct ArgusFragObject *frag = &net->net_union.frag;
                              struct ArgusFragOffsetStruct *fragOffset = frag->offsets.nxt;

                              while ((fragOffset = frag->offsets.nxt) != NULL) {
                                 frag->offsets.nxt = fragOffset->nxt;
                                 free(fragOffset);
                              }
                              bzero((char *)frag, sizeof(struct ArgusFragObject));
                              break;
                           }

                           case ARGUS_TCP_INIT:
                           case ARGUS_TCP_STATUS:
                           case ARGUS_TCP_PERF: {
                              struct ArgusTCPObject *tcp = &net->net_union.tcp;
                              tcp->src.status &= ~(ARGUS_RESET|ARGUS_PKTS_RETRANS|ARGUS_WINDOW_SHUT|ARGUS_OUTOFORDER|ARGUS_ECN_CONGESTED);
                              tcp->dst.status &= ~(ARGUS_RESET|ARGUS_PKTS_RETRANS|ARGUS_WINDOW_SHUT|ARGUS_OUTOFORDER|ARGUS_ECN_CONGESTED);
                              tcp->src.retrans  = 0;
                              tcp->dst.retrans  = 0;
                              tcp->src.flags    = 0;
                              tcp->dst.flags    = 0;
                              tcp->src.bytes    = 0;
                              tcp->dst.bytes    = 0;
                              tcp->src.winbytes = 0;
                              tcp->dst.winbytes = 0;
                              tcp->src.ackbytes = 0;
                              tcp->dst.ackbytes = 0;
                              tcp->src.seqbase  = tcp->src.seq;
                              tcp->dst.seqbase  = tcp->dst.seq;
                              break;
                           }

                           case ARGUS_RTP_FLOW: {
                              struct ArgusRTPObject *rtp = &net->net_union.rtp;
                              rtp->sdrop = 0;
                              rtp->ddrop = 0;
                              break;
                           }

                           case ARGUS_ESP_DSR: {
                              struct ArgusESPObject *esp = &net->net_union.esp;
                              esp->status  = 0;
                              esp->lostseq = 0;
                              break;
                           }
                        }
                        break;
                     }
                  }

                  net->hdr.argus_dsrvl8.qual = 0;
               }
               break;
            }

            case ARGUS_SRCUSERDATA_INDEX:
            case ARGUS_DSTUSERDATA_INDEX: {
               struct ArgusDataStruct *user = (struct ArgusDataStruct *) flow->dsrs[i];
               user->count = 0;
               memset (user->array, 0, user->size);
               break;
            }
         }
      }
   }

   memset(&flow->stime.act,  0, sizeof(flow->stime.act));
   memset(&flow->stime.idle, 0, sizeof(flow->stime.idle));
   memset(&flow->dtime.act,  0, sizeof(flow->dtime.act));
   memset(&flow->dtime.idle, 0, sizeof(flow->dtime.idle));

   flow->stime.act.minval  = 0xffffffff;
   flow->stime.idle.minval = 0xffffffff;
   flow->dtime.act.minval  = 0xffffffff;
   flow->dtime.idle.minval = 0xffffffff;

   flow->sipid = 0;
   flow->dipid = 0;
   flow->skey.n_strokes = 0;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusZeroRecord (%p) returning\n", flow);
#endif
}

/*
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
*/

struct ArgusSocketStruct *
ArgusNewSocket (int fd)
{
   struct ArgusSocketStruct *retn = NULL;
   int flags;

   if ((retn = ((struct ArgusSocketStruct *) ArgusCalloc (1, sizeof (struct ArgusSocketStruct)))) != NULL) {
      if ((retn->ArgusSocketList = ArgusNewList()) != NULL) {
         retn->fd = fd;
         flags = fcntl (fd, F_GETFL, 0);
         flags |= O_NONBLOCK;
         fcntl (fd, F_SETFL, flags);
      } else 
         ArgusLog(LOG_ERR, "ArgusNewSocket: ArgusNewList failed %s", strerror(errno));
   } else
      ArgusLog(LOG_ERR, "ArgusNewSocket: ArgusCalloc failed %s", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusNewSocket (%d) returning %p\n", fd, retn);
#endif

   return (retn);
}

void
ArgusDeleteSocket (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   struct ArgusSocketStruct *asock = client->sock;

   if (asock != NULL) {
      struct ArgusListStruct *list = asock->ArgusSocketList;

      while (!(ArgusListEmpty (list)))
         if (ArgusWriteOutSocket(output, client) < 0)
            break;

#ifdef ARGUSDEBUG
      if (!(ArgusListEmpty (list)))
         ArgusDebug(2, "ArgusDeleteSocket: list not empty");
#endif
      ArgusDeleteList(asock->ArgusSocketList, ARGUS_OUTPUT_LIST);

      close(asock->fd);
      asock->fd = -1;

      if (asock->filename) {
         free(asock->filename);
         asock->filename = NULL;
      }

      ArgusFree (asock);
      client->sock = NULL;
      client->fd = -1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusDeleteSocket (%p) returning\n", asock);
#endif
}


void
ArgusSetChroot(char *dir)
{
   if (chdir(dir) < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chdir to \"%s\": %s", dir, strerror(errno));

   if (chroot(dir) < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chroot to \"%s\": %s", dir, strerror(errno));

   if (chdir("/") < 0)
      ArgusLog(LOG_ERR, "ArgusSetChroot: failed to chdir to \"/\" after chroot: %s", dir, strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusSetChroot (%s) returning\n", dir);
#endif
}


#include <sys/stat.h>
#include <fcntl.h>

#define ARGUS_MAXERROR		200000
#define ARGUS_MAXWRITENUM	10000

int ArgusMaxListLength = 100000;
int ArgusCloseFile = 0;


extern struct ArgusRecord *ArgusGenerateInitialMar (struct ArgusOutputStruct *);

int
ArgusWriteSocket (struct ArgusOutputStruct *output, struct ArgusClientData *client, struct ArgusRecordStruct *rec)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = asock->ArgusSocketList;
   struct stat statbuf;
   int retn = 0, ocnt;

#if defined(HAVE_SOLARIS)
   struct statvfs statfsbuf;
#else
   struct statfs statfsbuf;
#endif

      if (ArgusListEmpty (list) && (asock->rec == NULL)) {
#ifdef ARGUSDEBUG
         if (asock->writen || asock->length)
            ArgusDebug (6, "ArgusWriteSocket: asock stats error %d %d\n", asock->writen, asock->length);
#endif
         if (client->host == NULL) {
         if (!(output->ArgusWriteStdOut) && (asock->filename)) {
            if (asock->lastwrite.tv_sec < output->ArgusModel->ArgusGlobalTime.tv_sec) {
               if (((stat (asock->filename, &statbuf)) < 0) || (ArgusCloseFile)) {
                  if (asock->fd != -1)
                     close(asock->fd);
                  if ((asock->fd = open (asock->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                     ArgusLog (LOG_ERR, "ArgusWriteSocket: open(%s, flags, 0x1a4) failed %s\n",
                        asock->filename, strerror(errno));
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusWriteSocket: created outfile %s\n", asock->filename);
#endif
               }

#if defined(HAVE_SOLARIS)
               retn = statvfs (asock->filename, &statfsbuf);
#else
               retn = statfs (asock->filename, &statfsbuf);
#endif

               if (retn == 0) {
                  if (statfsbuf.f_bfree > 100) {
                     if ((stat (asock->filename, &statbuf)) == 0) {
                        if (statbuf.st_size == 0) {
                           if (output->ArgusInitMar != NULL)
                              ArgusFree(output->ArgusInitMar);
                           output->ArgusInitMar = ArgusGenerateInitialMar(output);
                           ocnt = ntohs(output->ArgusInitMar->hdr.len) * 4;
#ifdef ARGUSDEBUG
                           ArgusDebug (6, "ArgusWriteSocket: write initial mar (%d, %p, %d)\n", 
                              asock->fd, output->ArgusInitMar, ocnt);
#endif
                           if (((retn = write (asock->fd, output->ArgusInitMar, ocnt))) < ocnt)
                              ArgusLog (LOG_ERR, "ArgusWriteSocket: write %s failed %s\n", asock->filename, strerror(errno));
                           ArgusFree(output->ArgusInitMar);
                           output->ArgusInitMar = NULL;
                        }
                     }

                  } else {
                     close(asock->fd);
                     asock->fd = -1;
                  }
               }
               asock->lastwrite = output->ArgusModel->ArgusGlobalTime;
            }
         }
         }

         if (asock->fd != -1) {
            if (ArgusGenerateRecord (output->ArgusModel, rec, 0, (struct ArgusRecord *)&asock->buf)) {
               int cnt = ((struct ArgusRecord *)&asock->buf)->hdr.len * 4;
#if defined(_LITTLE_ENDIAN)
               ArgusHtoN((struct ArgusRecord *)&asock->buf);
#endif
#ifdef ARGUS_SASL
               if (client->sasl_conn) {
                  unsigned int outputlen = 0;
                  const char *output =  NULL;
                  const int *ssfp;
                  int result;

                  if ((result = sasl_getprop(client->sasl_conn, SASL_SSF, (const void **) &ssfp)) != SASL_OK)
                     ArgusLog (LOG_ERR, "sasl_getprop: error %s\n", sasl_errdetail(client->sasl_conn));

                  if (ssfp && (*ssfp > 0)) {
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusHandleClientData: sasl_encode(%p, %p, %d, %p, %p)\n",
                                         client->sasl_conn, rec, cnt, &output, &outputlen);
#endif
                     if ((retn = sasl_encode(client->sasl_conn, (const char *) asock->buf, (unsigned int) cnt,
                                                                          &output, &outputlen)) == SASL_OK) {
#ifdef ARGUSDEBUG
                        ArgusDebug (6, "ArgusHandleClientData: sasl_encode returned %d bytes\n", outputlen);
#endif
                        if (outputlen < ARGUS_MAXRECORD) {
                           bcopy(output, asock->buf, outputlen);
                           cnt = outputlen;
                        } else
                           ArgusLog (LOG_ERR, "sasl_encode: returned too many bytes %d\n", outputlen);

                     } else
                        ArgusLog (LOG_ERR, "sasl_encode: failed returned %d\n", retn);
                  }
               }
#endif

#ifdef ARGUSDEBUG
               ArgusDebug (4, "ArgusWriteSocket: write record (%d, %p, %d)\n", asock->fd, &asock->buf, cnt);
#endif
               if (client->host != NULL) {
                  retn = sendto (asock->fd, &asock->buf, cnt, 0, client->host->ai_addr, client->host->ai_addrlen);
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteSocket: sendto (%d, %p, %d, ...) %d\n", asock->fd, &asock->buf, cnt, retn);
#endif
               } else {
                  retn = write (asock->fd, &asock->buf, cnt);
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteSocket: write (%d, %p, %d, ...) %d\n", asock->fd, &asock->buf, cnt, retn);
#endif
               }
               if (retn >= 0) {
                  asock->status |= ARGUS_WAS_FUNCTIONAL;
                  asock->errornum = 0;
                  if (retn != cnt) {
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusWriteSocket: write returned %d, scheduled record\n", retn);
#endif
                     asock->writen = retn;
                     asock->length = cnt;
                     asock->rec = ArgusCopyRecordStruct(rec);
                  } else {
                     asock->writen = 0;
                     asock->length = 0;
#ifdef ARGUSDEBUG
                     ArgusDebug (6, "ArgusWriteSocket: write successful %d\n", retn);
#endif
                  }

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteSocket: write returned %d, errno %d\n", retn, errno);
#endif
                  asock->writen = 0;
                  asock->length = cnt;
                  asock->rec = ArgusCopyRecordStruct(rec);

                  switch (errno) {
                     case ENOSPC:
                        if (asock->filename != NULL) {
                           close(asock->fd);
                           asock->fd = -1;
                           asock->rec = NULL;
                           asock->writen = 0;
                           asock->length = 0;
                           ArgusFreeListRecord(rec);
                           while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_LOCK)) != NULL)
                              ArgusFreeListRecord(rec);
                        }
                        break;

                     case EAGAIN:
                     case EINTR:
                        retn = 0;
                        break;

                     case EPIPE: {
                        if (!(asock->status & ARGUS_WAS_FUNCTIONAL)) {
                           retn = 0;
                        }
                        break;
                     }

                     default:
                        break;
                  }
               }

            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusWriteSocket: ArgusGenerateRecord returned zero\n");
#endif
            }
         }

      } else {
         if (list->count >= ArgusMaxListLength) {
            if (ArgusWriteOutSocket(output, client) < 0) {
#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&list->lock);
#endif
               if (list->count >= ArgusMaxListLength) {
                  struct ArgusRecordStruct *trec;
                  int i;
#define ARGUS_MAX_TOSS_RECORD	64
                  ArgusLog (LOG_WARNING, "ArgusWriteSocket: ArgusWriteOutSocket tossing records\n");

                  for (i = 0; i < ARGUS_MAX_TOSS_RECORD; i++)
                     if ((trec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
                        ArgusFreeListRecord(trec);
               }
#if defined(ARGUS_THREADS)
               pthread_mutex_unlock(&list->lock);
#endif
            }
         }

         if (asock->rec == NULL)
            asock->rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_LOCK);

#ifdef ARGUSDEBUG
         ArgusDebug (6, "ArgusWriteSocket (%p, %p, %p) schedule record\n", output, asock, rec);
#endif
         ArgusPushBackList (list, (struct ArgusListRecord *) ArgusCopyRecordStruct(rec), ARGUS_LOCK);
         retn = 0;
      }

#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusWriteSocket (%p, %p, %p) returning %d\n", output, asock, rec, retn);
#endif

   return (retn);
}



#define ARGUS_LISTREPORTLEN	50000
#define ARGUS_LISTREPORTTIME	30

int
ArgusWriteOutSocket (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   struct ArgusSocketStruct *asock = client->sock;
   struct ArgusListStruct *list = NULL;
   struct ArgusRecordStruct *rec = NULL;
   int retn = 0, count = 1, len, ocnt;
   struct stat statbuf;
   unsigned char *ptr;

   if ((list = asock->ArgusSocketList) != NULL) {
      if ((count = ArgusGetListCount(list)) > 0) {
         if (count > ARGUS_MAXWRITENUM)
            count = ARGUS_MAXWRITENUM;

         if (count == 1)
            count = 2;

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&list->lock);
#endif
         while ((asock->fd != -1 ) && count--) {
            if ((rec = asock->rec) != NULL) {
               ptr = (unsigned char *)&asock->buf;
               if (!(asock->writen)) {
                  if (!(output->ArgusWriteStdOut) && (asock->filename)) {
                     if (asock->lastwrite.tv_sec < output->ArgusModel->ArgusGlobalTime.tv_sec) {
                        if (((stat (asock->filename, &statbuf)) < 0) || (ArgusCloseFile)) {
                           close(asock->fd);
                           if ((asock->fd = open (asock->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                              ArgusLog (LOG_ERR, "ArgusWriteSocket: open(%s, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4) failed %s\n",
                                         asock->filename, strerror(errno));
#ifdef ARGUSDEBUG
                           ArgusDebug (2, "ArgusWriteOutSocket: created outfile %s\n", asock->filename);
#endif
                        }

                        if ((stat (asock->filename, &statbuf)) == 0) {
                           if (statbuf.st_size == 0) {
                              if (output->ArgusInitMar != NULL)
                                 ArgusFree(output->ArgusInitMar);
                              output->ArgusInitMar = ArgusGenerateInitialMar(output);
                              ocnt = sizeof(struct ArgusRecord);
                              if (((retn = write (asock->fd, output->ArgusInitMar, ocnt))) < ocnt)
                                 ArgusLog (LOG_ERR, "ArgusWriteSocket: write %s failed %s\n", asock->filename, strerror(errno));
                              ArgusFree(output->ArgusInitMar);
                              output->ArgusInitMar = NULL;
         
                           }
                        }
                        asock->lastwrite = output->ArgusModel->ArgusGlobalTime;
                     }
                  }
               }
               
               if ((asock->writen < asock->length) && ( asock->writen >= 0)) {
                  len = asock->length - asock->writen;

                  if (client->host != NULL) {
                     retn = sendto (asock->fd, (unsigned char *)&ptr[asock->writen], len, 0, client->host->ai_addr, client->host->ai_addrlen);
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusWriteSocket: sendto (%d, %p, %d, ...) %d\n", asock->fd, &asock->buf, len, retn);
#endif
                  } else {
                     retn = write(asock->fd, (unsigned char *)&ptr[asock->writen], len);
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusWriteSocket: write (%d, %p, %d, ...) %d\n", asock->fd, &asock->buf, len, retn);
#endif
                  }

                  if (retn >= 0) {
                     asock->errornum = 0;
                     asock->writen += retn;

                  } else {
                     switch (errno) {
                        case ENOSPC: {
                           if (asock->filename != NULL) {
                              close(asock->fd);
                              asock->fd = -1;
                              asock->rec = NULL;
                              asock->writen = 0;
                              asock->length = 0;
                              ArgusFreeListRecord(rec);
                              while ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL)
                                 ArgusFreeListRecord(rec);
                           }
                           break;
                        }

                        case EAGAIN:
                        case EINTR: {
                           if (!(output->ArgusWriteStdOut) && (asock->filename == NULL)) {
                              if (asock->errornum++ < ARGUS_MAXERROR) {
                                 retn = 0;
                              } else {
                              }

                           } else {
                              retn = 0;
                           }
                           break;
                        }

                        case EPIPE:
                           break;

                        default:
                           if (asock->errornum++ == 0)
                              ArgusLog (LOG_WARNING, "ArgusWriteOutSocket: write() %s\n", strerror(errno));
                           break;
                     }
                  }
               }
               
               if (asock->writen >= asock->length) {
                  gettimeofday(&list->outputTime, 0L);
                  ArgusFreeListRecord(rec);

#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteOutSocket: rec %p complete, %d count\n", rec, count);
#endif
                  asock->rec = NULL;
                  asock->writen = 0;
                  asock->length = 0;

                  if ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(list, ARGUS_NOLOCK)) != NULL) {
                     if (ArgusGenerateRecord (output->ArgusModel, rec, 0, (struct ArgusRecord *)&asock->buf)) {
                        int cnt = ((struct ArgusRecord *)&asock->buf)->hdr.len * 4;
#if defined(_LITTLE_ENDIAN)
                        ArgusHtoN((struct ArgusRecord *)&asock->buf);
#endif
#ifdef ARGUS_SASL
                        if (client->sasl_conn) {
                           unsigned int outputlen = 0;
                           const char *output =  NULL;
#ifdef ARGUSDEBUG
                           ArgusDebug (3, "ArgusHandleClientData: sasl_encode(%p, %p, %d, %p, %p)\n",
                                                                   client->sasl_conn, rec, cnt, &output, &outputlen);
#endif
                           if ((retn = sasl_encode(client->sasl_conn, (const char *) asock->buf, (unsigned int) cnt,
                                                      &output, &outputlen)) == SASL_OK) {
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "ArgusWriteOutSocket: sasl_encode returned %d bytes\n", outputlen);
#endif
                              if (outputlen < ARGUS_MAXRECORD) {
                                 bcopy(output, asock->buf, outputlen);
                                 cnt = outputlen;

                              } else
                                 ArgusLog (LOG_ERR, "sasl_encode: returned too many bytes %d\n", outputlen);

                           } else
                              ArgusLog (LOG_ERR, "sasl_encode: failed returned %d\n", retn);
                        }
#endif
                        asock->writen = 0;
                        asock->length = cnt;
                        asock->rec = rec;
#ifdef ARGUSDEBUG
                        ArgusDebug (6, "ArgusWriteOutSocket: posted record %p", rec);
#endif

                     } else {
#ifdef ARGUSDEBUG
                        ArgusDebug (6, "ArgusWriteOutSocket: ArgusGenerateRecord error! deleting record");
#endif
                        ArgusFreeListRecord(rec);
                     }
                  } else {
#ifdef ARGUSDEBUG
                     ArgusDebug (3, "ArgusWriteOutSocket: list %p is now empty", list);
#endif
                  }

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusWriteOutSocket: still work to be done for %p, len %d writen %d", rec, asock->length, asock->writen);
#endif
                  break;
               }

            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusWriteOutSocket: nothing to be done for %p, len %d writen %d", rec, asock->length, asock->writen);
#endif
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&list->lock);
#endif

#ifdef ARGUSDEBUG
         ArgusDebug (9, "ArgusWriteOutSocket(%p): queue empty\n", asock);
#endif
         
         if (asock->errornum >= ARGUS_MAXERROR) {
            ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(%p) maximum errors exceeded %d\n", asock, asock->errornum);
            retn = -1;
         }

         if ((count = ArgusGetListCount(list)) > ArgusMaxListLength) {
            ArgusLog (LOG_WARNING, "ArgusWriteOutSocket(%p) max queue exceeded %d\n", asock, count);
            retn = -1;
         }

#ifdef ARGUSDEBUG
         if (list) {
            ArgusDebug (6, "ArgusWriteOutSocket (%p) %d records waiting. returning %d\n", asock, count, retn);
         } else {
            ArgusDebug (6, "ArgusWriteOutSocket (%p) no list.  returning %d\n", asock, count, retn);
         }
#endif
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusWriteOutSocket (%p, %p) no list returning %d\n", output, client, retn);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusWriteOutSocket (%p, %p) returning %d\n", output, client, retn);
#endif

   return retn;
}


#if !defined(ArgusAddrtoName)
#define ArgusAddrtoName
#endif

#include <sys/socket.h>
#include <signal.h>
#include <netdb.h>

#include <argus_namedb.h>

#ifdef ETHER_SERVICE
struct ether_addr;

#ifdef HAVE_ETHER_HOSTTON
/*
 * XXX - do we need any of this if <netinet/if_ether.h> doesn't declare
 * ether_hostton()?
 */
#ifdef HAVE_NETINET_IF_ETHER_H
struct mbuf;            /* Squelch compiler warnings on some platforms for */
struct rtentry;         /* declarations in <net/if.h> */
#include <net/if.h>     /* for "struct ifnet" in "struct arpcom" on Solaris */
#include <netinet/if_ether.h>
#endif /* HAVE_NETINET_IF_ETHER_H */
#ifdef NETINET_ETHER_H_DECLARES_ETHER_HOSTTON
#include <netinet/ether.h>
#endif /* NETINET_ETHER_H_DECLARES_ETHER_HOSTTON */
#endif /* HAVE_ETHER_HOSTTON */
#endif

/*
 * hash tables for whatever-to-name translations

#define HASHNAMESIZE 4096

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

struct h6namemem h6nametable[HASHNAMESIZE];
struct hnamemem  hnametable[HASHNAMESIZE];
struct hnamemem  tporttable[HASHNAMESIZE];
struct hnamemem  uporttable[HASHNAMESIZE];
struct hnamemem  eprototable[HASHNAMESIZE];
struct hnamemem  nnametable[HASHNAMESIZE];
struct hnamemem  llcsaptable[HASHNAMESIZE];

struct enamemem {
   u_short e_addr0;
   u_short e_addr1;
   u_short e_addr2;
   char *e_name;
   u_char *e_nsap; 
   struct enamemem *e_nxt;
};

struct enamemem enametable[HASHNAMESIZE];
struct enamemem nsaptable[HASHNAMESIZE];

struct protoidmem {
   u_int p_oui;
   arg_uint16 p_proto;
   char *p_name;
   struct protoidmem *p_nxt;
};

struct protoidmem protoidtable[HASHNAMESIZE];
 */

/*
 * A faster replacement for inet_ntoa().
 */
char *
intoa(u_int addr)
{
   char *cp;
   u_int byte;
   int n;
   static char buf[sizeof(".xxx.xxx.xxx.xxx")];
/*
   addr = htonl(addr);
*/
   cp = &buf[sizeof buf];
   *--cp = '\0';

   n = 4;
   do {
      byte = addr & 0xff;
      *--cp = byte % 10 + '0';
      byte /= 10;
      if (byte > 0) {
         *--cp = byte % 10 + '0';
         byte /= 10;
         if (byte > 0)
            *--cp = byte + '0';
      }
      *--cp = '.';
      addr >>= 8;
   } while (--n > 0);

   return cp + 1;
}

/*
 * Return a name for the IP address pointed to by ap.  This address
 * is assumed to be in network byte order.
 */
char *
ArgusGetName(struct ArgusParserStruct *parser, u_char *ap)
{
   static struct hnamemem *p;      /* static for longjmp() */
   u_int addr;

#if !defined(TCPDUMP_ALIGN)
   addr = *(const u_int *)ap;
#else
   /*
    * Deal with alignment.
    */
   switch ((int)ap & 3) {

   case 0:
      addr = *(u_int *)ap;
      break;

   case 2:
      addr = ((u_int)*(u_short *)ap << 16) |
         (u_int)*(u_short *)(ap + 2);
      break;

   default:
      addr = ((u_int)ap[3] << 24) |
         ((u_int)ap[2] << 16) |
         ((u_int)ap[1] << 8) |
         (u_int)ap[0];
      break;
   }
#endif
   p = &parser->hnametable[addr % (HASHNAMESIZE-1)];
   for (; p->nxt; p = p->nxt) {
      if (p->addr == addr)
         if (p->name != NULL)
            return (p->name);
   }
   p->addr = addr;
   p->nxt = (struct hnamemem *)calloc(1, sizeof (*p));

   return (intoa(addr));
}


#include <sys/socket.h>
#include <arpa/inet.h>

#if !defined(INET6_ADDRSTRLEN)
#define INET6_ADDRSTRLEN	46
#endif

#if !defined(AF_INET6)
#define AF_INET6		23
#endif

char *
ArgusGetV6Name(struct ArgusParserStruct *parser, u_char *ap)
{
   struct in6_addr addr;
   char ntop_buf[INET6_ADDRSTRLEN];
   struct h6namemem *p;      /* static for longjmp() */
   const char *cp;

   memcpy(&addr, ap, sizeof(addr));

   p = &parser->h6nametable[*(u_int16_t *)&addr.s6_addr[14] & (HASHNAMESIZE-1)];
   for (; p->nxt; p = p->nxt) {
      if (memcmp(&p->addr, &addr, sizeof(addr)) == 0)
         return (p->name);
   }
   p->addr = addr;
   p->nxt = (struct h6namemem *)calloc(1, sizeof (*p));

   if ((cp = inet_ntop(AF_INET6, (const void *) &addr, ntop_buf, sizeof(ntop_buf))) != NULL)
      p->name = strdup(cp);

   return (p->name);
}

struct timeval *
RaMinTime (struct timeval *s1, struct timeval *s2)
{
   struct timeval *retn = s2;
 
   if ((s1->tv_sec < s2->tv_sec) || ((s1->tv_sec == s2->tv_sec) && (s1->tv_usec < s2->tv_usec)))
      retn = s1;
 
   return (retn);
}
 
 
struct timeval *
RaMaxTime (struct timeval *s1, struct timeval *s2)
{
   struct timeval *retn = s2;
 
   if ((s1->tv_sec > s2->tv_sec) || ((s1->tv_sec == s2->tv_sec) && (s1->tv_usec > s2->tv_usec)))
      retn = s1;
 
   return (retn);
}


float
RaDeltaFloatTime (struct timeval *s1, struct timeval *s2)
{
   float retn = 0.0;

   if (s1 && s2) {
      double v1 = (s1->tv_sec * 1.0) + (s1->tv_usec / 1000000.0);
      double v2 = (s2->tv_sec * 1.0) + (s2->tv_usec / 1000000.0);

      retn = v1 - v2;
   }

   return (retn);
}

int
RaDiffTime (struct timeval *s1, struct timeval *s2, struct timeval *diff)
{
   int retn = 0;

   if (s1 && s2 && diff) {
      bzero ((char *)diff, sizeof(*diff));

      double v1 = (s1->tv_sec * 1.0) + (s1->tv_usec / 1000000.0);
      double v2 = (s2->tv_sec * 1.0) + (s2->tv_usec / 1000000.0);
      double f, i;

      v1 -= v2;

      f = modf(v1, &i);

      diff->tv_sec  = i;
      diff->tv_usec = f * 1000000;

      retn = 1;
   }

   return (retn);
}


long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);

long long
ArgusDiffTime (struct ArgusTime *s1, struct ArgusTime *s2, struct timeval *diff)
{
   long long v1 = 0, v2 = 0;

   if (s1 && s2 && diff) {
      v1 = (s1->tv_sec * 1000000LL) + s1->tv_usec;
      v2 = (s2->tv_sec * 1000000LL) + s2->tv_usec;

      v1 -= v2;

      diff->tv_sec  = v1 / 1000000;
      diff->tv_usec = v1 % 1000000;
   }

   return (v1);
}


float
RaGetFloatDuration (struct ArgusRecordStruct *argus)
{
   float retn = 0;
   int sec = 0, usec = 0;

   if (argus->hdr.type & ARGUS_MAR) {
      struct ArgusRecord *rec = (struct ArgusRecord *) &argus->canon;

      sec  = rec->argus_mar.now.tv_sec  - rec->argus_mar.startime.tv_sec;
      usec = rec->argus_mar.now.tv_usec - rec->argus_mar.startime.tv_usec;

   } else {
      struct ArgusTimeObject *dtime = &argus->canon.time;
      struct timeval *stime = NULL, *ltime = NULL;
      struct timeval srctime, dsttime;
      unsigned int subtype = dtime->hdr.subtype & (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START |
                                                   ARGUS_TIME_SRC_END   | ARGUS_TIME_DST_END);
      if (subtype) {
         switch (subtype) {
            case ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START |
                 ARGUS_TIME_SRC_END   | ARGUS_TIME_DST_END: {

               srctime.tv_sec  = dtime->src.start.tv_sec;
               srctime.tv_usec = dtime->src.start.tv_usec;
               dsttime.tv_sec  = dtime->dst.start.tv_sec;
               dsttime.tv_usec = dtime->dst.start.tv_usec;

               stime = RaMinTime(&srctime, &dsttime);

               srctime.tv_sec  = dtime->src.end.tv_sec;
               srctime.tv_usec = dtime->src.end.tv_usec;
               dsttime.tv_sec  = dtime->dst.end.tv_sec;
               dsttime.tv_usec = dtime->dst.end.tv_usec;

               ltime = RaMaxTime(&srctime, &dsttime);
               break;
            }

            case ARGUS_TIME_SRC_START:
            case ARGUS_TIME_SRC_START | ARGUS_TIME_SRC_END: {

               srctime.tv_sec  = dtime->src.start.tv_sec;
               srctime.tv_usec = dtime->src.start.tv_usec;
               dsttime.tv_sec  = dtime->src.end.tv_sec;
               dsttime.tv_usec = dtime->src.end.tv_usec;

               stime = &srctime;
               ltime = &dsttime;
               break;
            }

            case ARGUS_TIME_DST_START:
            case ARGUS_TIME_DST_START | ARGUS_TIME_DST_END: {
               srctime.tv_sec  = dtime->dst.start.tv_sec;
               srctime.tv_usec = dtime->dst.start.tv_usec;
               dsttime.tv_sec  = dtime->dst.end.tv_sec;
               dsttime.tv_usec = dtime->dst.end.tv_usec;

               stime = &srctime;
               ltime = &dsttime;
               break;
            }

            case ARGUS_TIME_SRC_START | ARGUS_TIME_DST_END: {
               srctime.tv_sec  = dtime->src.start.tv_sec;
               srctime.tv_usec = dtime->src.start.tv_usec;
               dsttime.tv_sec  = dtime->dst.end.tv_sec;
               dsttime.tv_usec = dtime->dst.end.tv_usec;

               stime = &srctime;
               ltime = &dsttime;
               break;
            }

            default:
               break;
         }

      } else {
         srctime.tv_sec  = dtime->src.start.tv_sec;
         srctime.tv_usec = dtime->src.start.tv_usec;
         dsttime.tv_sec  = dtime->src.end.tv_sec;
         dsttime.tv_usec = dtime->src.end.tv_usec;

         stime = &srctime;
         ltime = &dsttime;
      }


      if (stime && ltime) {
         sec  = ltime->tv_sec  - stime->tv_sec;
         usec = ltime->tv_usec - stime->tv_usec;
      }
   }

   retn  = (sec * 1.0) + usec/1000000.0;
   return (retn);
}


float
RaGetFloatSrcDuration (struct ArgusRecordStruct *argus)
{
   float retn = 0.0;
   int sec = 0, usec = 0;

   if (argus->hdr.type & ARGUS_MAR) {

   } else {
      struct ArgusTimeObject *dtime = &argus->canon.time;
      struct ArgusTime *stime = &dtime->src.start;
      struct ArgusTime *ltime = &dtime->src.end;

      sec  = ltime->tv_sec  - stime->tv_sec;
      usec = ltime->tv_usec - stime->tv_usec;
      retn  = (sec * 1.0) + usec/1000000.0;
   }

   return (retn);
}


float
RaGetFloatDstDuration (struct ArgusRecordStruct *argus)
{
   float retn = 0.0;
   int sec = 0, usec = 0;

   if (argus->hdr.type & ARGUS_MAR) {

   } else {
      struct ArgusTimeObject *dtime = &argus->canon.time;
      struct ArgusTime *stime = &dtime->dst.start;
      struct ArgusTime *ltime = &dtime->dst.end;

      sec  = ltime->tv_sec  - stime->tv_sec;
      usec = ltime->tv_usec - stime->tv_usec;
      retn  = (sec * 1.0) + usec/1000000.0;
   }

   return (retn);
}


double  
ArgusFetchDuration (struct ArgusRecordStruct *ns) 
{ 
   double retn = RaGetFloatDuration(ns);
   return (retn); 
} 
  
double
ArgusFetchSrcDuration (struct ArgusRecordStruct *ns)
{ 
   double retn = RaGetFloatSrcDuration(ns);
   return (retn); 
} 
  
double
ArgusFetchDstDuration (struct ArgusRecordStruct *ns)
{
   double retn = RaGetFloatDstDuration(ns);
   return (retn);
}


double
ArgusFetchSrcLoad (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   float dur = 0.0;
   long long cnt1;
   double retn = 0.0;

   dur = ArgusFetchSrcDuration(ns);

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
      cnt1 = m1->src.pkts; 
   } else {
      cnt1 = 0;
   }
           
   if (dur > 0.0)
      retn = (cnt1 * 1.0)/dur;

   return (retn);
}

double
ArgusFetchDstLoad (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   struct timeval ts1buf, *ts1 = &ts1buf;
   struct timeval t1buf, *t1d = &t1buf;
   long long cnt1 = 0;
   float d1 = 0.0;
   double retn = 0;

   ts1->tv_sec  = ns->canon.time.src.start.tv_sec;
   ts1->tv_usec = ns->canon.time.src.start.tv_usec;

   t1d->tv_sec  = ns->canon.time.src.end.tv_sec;
   t1d->tv_usec = ns->canon.time.src.end.tv_usec;

   t1d->tv_sec  -= ts1->tv_sec; t1d->tv_usec -= ts1->tv_usec;
   if (t1d->tv_usec < 0) {t1d->tv_sec--; t1d->tv_usec += 1000000;}
   d1 = ((t1d->tv_sec * 1.0) + (t1d->tv_usec/1000000.0));
 
   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->dst.pkts; 
 
   if (d1 > 0.0)
      retn = (cnt1 * 1.0)/d1;
                     
   return (retn);
}


double
ArgusFetchLoad (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   struct timeval ts1buf, *ts1 = &ts1buf;
   struct timeval t1buf, *t1d = &t1buf;
   long long cnt1 = 0; 
   float d1 = 0.0; 
   double retn = 0;

   ts1->tv_sec  = ns->canon.time.src.start.tv_sec;
   ts1->tv_usec = ns->canon.time.src.start.tv_usec;

   t1d->tv_sec  = ns->canon.time.src.end.tv_sec;
   t1d->tv_usec = ns->canon.time.src.end.tv_usec;

   t1d->tv_sec  -= ts1->tv_sec; t1d->tv_usec -= ts1->tv_usec;
   if (t1d->tv_usec < 0) {t1d->tv_sec--; t1d->tv_usec += 1000000;}
   d1 = ((t1d->tv_sec * 1.0) + (t1d->tv_usec/1000000.0));

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.pkts + m1->dst.pkts; 

   if ((cnt1 > 0) && (d1 > 0.0))
      retn = (cnt1 * 1.0)/d1;
                    
   return (retn);
}


double
ArgusFetchLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)&ns->canon.flow;
         switch (flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                  case ARGUS_TYPE_IPV4: {
                     switch (ns->canon.flow.ip_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = (rtp->sdrop + rtp->ddrop) * 1.0;
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }
                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.src.pkts)
                                 retn = (tcp->src.retrans + tcp->dst.retrans) * 1.0;
                           }
                           break;
                        }
                        case IPPROTO_ESP: {
                           struct ArgusESPObject *esp = (void *)&ns->canon.net.net_union.esp;
                           if (esp != NULL) {
                              if (ns->canon.metric.src.pkts)
                                 retn = esp->lostseq * 1.0;
                           }
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_TYPE_IPV6: {
                     switch (flow->ipv6_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = (rtp->sdrop + rtp->ddrop) * 1.0;
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }

                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.src.pkts)
                                 retn = (tcp->src.retrans + tcp->dst.retrans) * 1.0;
                           }
                           break;
                        }
                     }
                  }
               }
               break;
            }
         }
      }
   }

   return (retn);
}


double
ArgusFetchSrcLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)&ns->canon.flow;
         switch (flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                  case ARGUS_TYPE_IPV4: {
                     switch (ns->canon.flow.ip_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = rtp->sdrop * 1.0;
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }
                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.src.pkts)
                                 retn = tcp->src.retrans * 1.0;
                           }
                           break;
                        }
                        case IPPROTO_ESP: {
                           struct ArgusESPObject *esp = (void *)&ns->canon.net.net_union.esp;
                           if (esp != NULL) {
                              if (ns->canon.metric.src.pkts)
                                 retn = esp->lostseq * 1.0;
                           }
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_TYPE_IPV6: {
                     switch (flow->ipv6_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = rtp->sdrop * 1.0;
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }

                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.src.pkts)
                                 retn = tcp->src.retrans * 1.0;
                           }
                           break;
                        }
                     }
                  }
               }
               break;
            }
         }
      }
   }

   return (retn);
}

double
ArgusFetchDstLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;

   if (ns) {
      if (ns->hdr.type & ARGUS_MAR) {
      } else {
         struct ArgusFlow *flow = (struct ArgusFlow *)&ns->canon.flow;
         switch (flow->hdr.subtype & 0x3F) {
            case ARGUS_FLOW_CLASSIC5TUPLE: {
               switch ((flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                  case ARGUS_TYPE_IPV4: {
                     switch (ns->canon.flow.ip_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = rtp->ddrop * 1.0;
                           }
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }
                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.dst.pkts)
                                 retn = tcp->dst.retrans * 1.0;
                           }
                           break;
                        }
                        case IPPROTO_ESP: {
                           struct ArgusESPObject *esp = (void *)&ns->canon.net.net_union.esp;
                           if (esp != NULL) {
                              if (ns->canon.metric.dst.pkts)
                                 retn = esp->lostseq * 1.0;
                           }
                        }
                     }
                     break;
                  }

                  case ARGUS_TYPE_IPV6: {
                     switch (flow->ipv6_flow.ip_p) {
                        case IPPROTO_UDP: {
                           if (ns->canon.net.hdr.subtype == ARGUS_RTP_FLOW) {
                              struct ArgusRTPObject *rtp = (void *)&ns->canon.net.net_union.rtp;
                              retn = rtp->ddrop * 1.0;
                           }
                           break;
                        }

                        case IPPROTO_ICMP: {
                           break;
                        }

                        case IPPROTO_TCP: {
                           struct ArgusTCPObject *tcp = (void *)&ns->canon.net.net_union.tcp;

                           if ((tcp != NULL) && (tcp->state != 0)) {
                              if (ns->canon.metric.dst.pkts)
                                 retn = tcp->dst.retrans * 1.0;
                           }
                           break;
                        }
                     }
                  }
               }
               break;
            }
         }
      }
   }

   return (retn);
}


double
ArgusFetchPercentLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      retn = ArgusFetchLoss(ns);
      pkts = ns->canon.metric.src.pkts + ns->canon.metric.dst.pkts;
      if (pkts > 0) {
         retn = (retn * 100.0)/((pkts * 1.0 )+ retn);
      } else
         retn = 0.0;
   }

   return (retn);
}

double
ArgusFetchPercentSrcLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      retn = ArgusFetchSrcLoss(ns);
      pkts = ns->canon.metric.src.pkts;
      if (pkts > 0) {
         retn = (retn * 100.0)/((pkts * 1.0) + retn);
      } else
         retn = 0.0;
   }

   return (retn);
}

double
ArgusFetchPercentDstLoss (struct ArgusRecordStruct *ns)
{
   double retn = 0.0;
   int pkts = 0;

   if (ns) {
      retn = ArgusFetchDstLoss(ns);
      pkts = ns->canon.metric.dst.pkts;
      if (pkts > 0) {
         retn = (retn * 100.0)/((pkts * 1.0) + retn);
      } else
         retn = 0.0;
   }

   return (retn);
}


double
ArgusFetchSrcRate (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   struct timeval ts1buf, *ts1 = &ts1buf;
   struct timeval t1buf, *t1d = &t1buf;
   long long cnt1 = 0;
   float d1, r1 = 0.0;
   double retn = 0;

   ts1->tv_sec  = ns->canon.time.src.start.tv_sec;
   ts1->tv_usec = ns->canon.time.src.start.tv_usec;

   t1d->tv_sec  = ns->canon.time.src.end.tv_sec;
   t1d->tv_usec = ns->canon.time.src.end.tv_usec;

   t1d->tv_sec  -= ts1->tv_sec; t1d->tv_usec -= ts1->tv_usec;
   if (t1d->tv_usec < 0) {t1d->tv_sec--; t1d->tv_usec += 1000000;}
   d1 = ((t1d->tv_sec * 1.0) + (t1d->tv_usec/1000000.0));

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->src.bytes * 8;

   if ((cnt1 > 0) && (d1 > 0.0))
      r1 = (cnt1 * 1.0)/d1;

   retn = r1;
   return (retn);
}

double
ArgusFetchDstRate (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   struct timeval ts1buf, *ts1 = &ts1buf;
   struct timeval t1buf,  *t1d = &t1buf;
   float d1, r1 = 0.0;
   long long cnt1 = 0;
   double retn = 0;

   ts1->tv_sec  = ns->canon.time.src.start.tv_sec;
   ts1->tv_usec = ns->canon.time.src.start.tv_usec;

   t1d->tv_sec  = ns->canon.time.src.end.tv_sec;
   t1d->tv_usec = ns->canon.time.src.end.tv_usec;

   t1d->tv_sec  -= ts1->tv_sec; t1d->tv_usec -= ts1->tv_usec;
   if (t1d->tv_usec < 0) {t1d->tv_sec--; t1d->tv_usec += 1000000;}
   d1 = ((t1d->tv_sec * 1.0) + (t1d->tv_usec/1000000.0));

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = m1->dst.bytes * 8;

   if ((cnt1 > 0) && (d1 > 0.0))
      r1 = (cnt1 * 1.0)/d1;

   retn = r1;
   return (retn);
}

double
ArgusFetchRate (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   struct timeval ts1buf, *ts1 = &ts1buf;
   struct timeval t1buf, *t1d = &t1buf;
   long long cnt1 = 0;
   float d1, r1 = 0.0;
   double retn = 0;

   ts1->tv_sec  = ns->canon.time.src.start.tv_sec;
   ts1->tv_usec = ns->canon.time.src.start.tv_usec;

   t1d->tv_sec  = ns->canon.time.src.end.tv_sec;
   t1d->tv_usec = ns->canon.time.src.end.tv_usec;

   t1d->tv_sec  -= ts1->tv_sec; t1d->tv_usec -= ts1->tv_usec;
   if (t1d->tv_usec < 0) {t1d->tv_sec--; t1d->tv_usec += 1000000;}
   d1 = ((t1d->tv_sec * 1.0) + (t1d->tv_usec/1000000.0));

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL)
      cnt1 = (m1->src.bytes + m1->dst.bytes) * 8;

   if ((cnt1 > 0) && (d1 > 0.0))
      r1 = (cnt1 * 1.0)/d1;

   retn = r1;
   return (retn);
}

double
ArgusFetchAppByteRatio (struct ArgusRecordStruct *ns)
{
   struct ArgusMetricStruct *m1 = NULL;
   double retn =  0.0;

   if ((m1 = (struct ArgusMetricStruct *) ns->dsrs[ARGUS_METRIC_INDEX]) != NULL) {
      double nvalue = (m1->src.appbytes - m1->dst.appbytes) * 1.0;
      double dvalue = (m1->src.appbytes + m1->dst.appbytes) * 1.0;

      if (dvalue > 0)
         retn = nvalue / dvalue;
      else
         retn = -0.0;
   }
   return (retn);
}
