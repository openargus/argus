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
 * $Id: //depot/argus/argus/argus/ArgusModeler.c#137 $
 * $DateTime: 2016/04/05 12:00:14 $
 * $Change: 3135 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif


#if !defined(ArgusModeler)
#define ArgusModeler
#endif

#include <unistd.h>
#include <stdlib.h>
#include <errno.h>

#include <argus.h>

#include <argus/bootp.h>
#include <signal.h>

#include <sched.h>
#include <errno.h>
#include <math.h>

#include <net/ppp.h>
#include <argus/extract.h>

#include <argus_ethertype.h>

extern int ArgusShutDownFlag;

extern struct ArgusHashTable *ArgusNewHashTable (size_t, int);
extern int ArgusUpdateParentFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *);
extern int ArgusControlPlaneProtocol (struct ArgusModelerStruct *, struct ArgusFlowStruct *);

unsigned short ArgusProcessUdpHdr (struct ArgusModelerStruct *, struct ip *, int);
unsigned short ArgusProcessTtpHdr (struct ArgusModelerStruct *, struct ip *, int);
int ArgusProcessGreHdr (struct ArgusModelerStruct *, struct ip *, int);
int ArgusProcessPPPHdr (struct ArgusModelerStruct *, char *, int);

extern void ArgusTCPKeystroke (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

struct ArgusModelerStruct *
ArgusCloneModeler(struct ArgusModelerStruct *src)
{
   struct ArgusModelerStruct *retn;

   if ((retn = (struct ArgusModelerStruct *) ArgusCalloc (1, sizeof (struct ArgusModelerStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusCloneModeler () ArgusCalloc error %s\n", strerror(errno));

   bcopy((char *)src, (char *)retn, sizeof(*src));

   retn->ArgusSrc           = NULL;
   retn->ArgusHashTable     = NULL;
   retn->hstruct            = NULL;
   retn->ArgusStatusQueue   = NULL;
   retn->ArgusTimeOutQueues = NULL;
   retn->ArgusThisFlow      = NULL;
   retn->ArgusOutputList    = NULL;

   bzero (retn->ArgusTimeOutQueue, sizeof(retn->ArgusTimeOutQueue));

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

   return (retn);
}


struct ArgusModelerStruct *
ArgusNewModeler()
{
   struct ArgusModelerStruct *retn = NULL;

   if ((retn = (struct ArgusModelerStruct *) ArgusCalloc (1, sizeof (struct ArgusModelerStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewModeler() returning %p\n", retn);
#endif 

   return (retn);
}



void *ArgusQueueManager(void *);

void
ArgusInitModeler(struct ArgusModelerStruct *model)
{
   struct timeval *tvp = NULL;
#if defined(ARGUS_HASH_DEBUG)
   int debug = ARGUSHASHTABLETRACK;
#else
   int debug = 0;
#endif

   bzero (model->ArgusTimeOutQueue, sizeof(model->ArgusTimeOutQueue));
   model->ArgusInProtocol = 1;
   model->ArgusMajorVersion = VERSION_MAJOR;
   model->ArgusMinorVersion = VERSION_MINOR;
   model->ArgusSnapLen = ARGUS_MINSNAPLEN;

   model->ArgusUpdateInterval.tv_usec = 200000;
   model->ival = ((model->ArgusUpdateInterval.tv_sec * 1000000LL) + model->ArgusUpdateInterval.tv_usec);

   if ((model->ArgusHashTable = ArgusNewHashTable(ARGUS_HASHTABLESIZE, debug)) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewHashTable error %s\n", strerror(errno));

   if ((model->hstruct = (struct ArgusHashStruct *) ArgusCalloc (1, sizeof (struct ArgusHashStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

   if ((model->ArgusStatusQueue = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewQueue error %s\n", strerror(errno));

   if ((model->ArgusTimeOutQueues = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusNewQueue error %s\n", strerror(errno));

/* align the ArgusThisFlow buffer */

   if ((model->ArgusThisFlow = (struct ArgusSystemFlow *) ArgusCalloc (1, sizeof (struct ArgusSystemFlow) + 32)) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewModeler () ArgusCalloc error %s\n", strerror(errno));

   model->ArgusOutputList = ArgusOutputTask->ArgusInputList;

   gettimeofday (&model->ArgusGlobalTime, 0L);
   ArgusModel->ArgusGlobalTime = model->ArgusGlobalTime;

   if ((model->ArgusThisLLC = (struct llc  *) ArgusCalloc (1, sizeof (struct llc ) + 32)) == NULL)
      ArgusLog (LOG_ERR, "ArgusInitModeler () ArgusCalloc error %s\n", strerror(errno));

   model->ArgusSeqNum = 1;
   model->ArgusReportAllTime = 1;

   if (!(model->ArgusFlowKey))
      model->ArgusFlowKey = ARGUS_FLOW_KEY_CLASSIC5TUPLE;

   if (!(model->ArgusFlowType)) {
      if (model->ArgusFlowKey == ARGUS_FLOW_KEY_CLASSIC5TUPLE)
         model->ArgusFlowType = ARGUS_BIDIRECTIONAL;
      else
         model->ArgusFlowType = ARGUS_UNIDIRECTIONAL;
   }

   model->ArgusQueueInterval.tv_usec  = 50000;
   model->ArgusListenInterval.tv_usec = 250000;

   model->ArgusIPTimeout    = (model->ArgusIPTimeout == 0) ? ARGUS_IPTIMEOUT : model->ArgusIPTimeout;
   model->ArgusTCPTimeout   = (model->ArgusTCPTimeout == 0) ? ARGUS_TCPTIMEOUT : model->ArgusTCPTimeout;
   model->ArgusICMPTimeout  = (model->ArgusICMPTimeout == 0) ? ARGUS_ICMPTIMEOUT : model->ArgusICMPTimeout;
   model->ArgusIGMPTimeout  = (model->ArgusIGMPTimeout == 0) ? ARGUS_IGMPTIMEOUT : model->ArgusIGMPTimeout;
   model->ArgusFRAGTimeout  = (model->ArgusFRAGTimeout == 0) ? ARGUS_FRAGTIMEOUT : model->ArgusFRAGTimeout;
   model->ArgusARPTimeout   = (model->ArgusARPTimeout == 0) ? ARGUS_ARPTIMEOUT : model->ArgusARPTimeout;
   model->ArgusOtherTimeout = (model->ArgusOtherTimeout == 0) ? ARGUS_OTHERTIMEOUT : model->ArgusOtherTimeout;

   if ((tvp = getArgusFarReportInterval(model)) != NULL)
      model->ArgusStatusQueue->timeout = tvp->tv_sec;

   model->ArgusTCPflag = 1;

   model->ArgusThisDir = 0;

   ArgusInitMallocList(sizeof(struct ArgusRecordStruct));

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitModeler(%p) done\n", model);
#endif 
}


void
ArgusCloseModeler(struct ArgusModelerStruct *model)
{
   struct ArgusRecordStruct *argus = NULL;

   if (model) {
      ArgusModelerCleanUp (model); 
   
      if (model->ArgusHashTable) {
         struct ArgusHashTable *htbl = model->ArgusHashTable;
         if (htbl->array)
            ArgusFree(htbl->array);
         ArgusFree(htbl);
         model->ArgusHashTable = NULL;
      }

      if (model->ArgusOutputList) {
         if ((argus = ArgusGenerateListRecord (model, NULL, ARGUS_STOP)) != NULL) {
            model->ArgusTotalSends++;
            ArgusPushBackList (model->ArgusOutputList, (struct ArgusListRecord *) argus, ARGUS_LOCK);

#if defined(ARGUS_THREADS)
            pthread_mutex_lock(&model->ArgusOutputList->lock);
            pthread_cond_signal(&model->ArgusOutputList->cond);
            pthread_mutex_unlock(&model->ArgusOutputList->lock);
#endif

#ifdef ARGUSDEBUG
            ArgusDebug (4, "ArgusCloseModeler(%p) pushing close record %p as rec %d\n", model, argus, ArgusGetListCount(model->ArgusOutputList));
#endif 
         } else 
            ArgusLog (LOG_ERR, "ArgusCloseModeler(%p) ArgusGenerateListRecord failed\n", model);

      }

      if (model->hstruct != NULL) {
         ArgusFree(model->hstruct);
         model->hstruct = NULL;
      }
      if (model->ArgusThisFlow != NULL) {
         ArgusFree(model->ArgusThisFlow);
         model->ArgusThisFlow = NULL;
      }
      if (model->ArgusStatusQueue != NULL) {
         ArgusDeleteQueue(model->ArgusStatusQueue);
         model->ArgusStatusQueue = NULL;
      }
      if (model->ArgusTimeOutQueues != NULL) {
         ArgusDeleteQueue(model->ArgusTimeOutQueues);
         model->ArgusTimeOutQueues = NULL;
      }
      if (model->ArgusThisLLC != NULL) {
         ArgusFree(model->ArgusThisLLC);
         model->ArgusThisLLC = NULL;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusCloseModeler(%p) Total Sends %d\n", model, model->ArgusTotalSends);
#endif 
}



void ArgusProcessQueueTimeout (struct ArgusModelerStruct *, struct ArgusQueueStruct *);
int ArgusQMTurns = 0;

void *
ArgusQueueManager(void *param)
{
   struct ArgusModelerStruct *model = param;
   struct ArgusQueueStruct *queue = NULL;
   void *retn = NULL;

/*
 * so there are two things to do.  
 *  1. process the status queue.  this is a FIFO
 *     queue, and any object at the end of the queue
 *     is printed and moved to the timeout queue.
 *     (objects can be moved by the packet handler,
 *      so locking is important here.
 *
 *  2. process the timeout queue.  this queue we can
 *     get to on a slower time scale, until resources
 *     are getting used up.
 */

   ArgusQMTurns++;

   if (model->ArgusStatusQueue != NULL)
      ArgusProcessQueueTimeout (model, model->ArgusStatusQueue);
   else
      return (retn);

   if ((model->ArgusTimeOutQueues != NULL) && (model->ArgusTimeOutQueues->count > 0)) {
      int i, cnt = model->ArgusTimeOutQueues->count;

      for (i = 0; i < cnt; i++) {
         queue = (struct ArgusQueueStruct *)ArgusPopQueue (model->ArgusTimeOutQueues, ARGUS_LOCK);
         ArgusProcessQueueTimeout (model, queue);
         ArgusAddToQueue (model->ArgusTimeOutQueues, &queue->qhdr, ARGUS_LOCK);
      }
   }

#ifdef ARGUSDEBUG
/*
   {
      struct timeval now, testime = {0,0}, update = {1,0};
      gettimeofday(&now, 0L);

      if (testime.tv_sec == 0) {
         testime = now;
      }

      if ((now.tv_sec  > testime.tv_sec) ||
         ((now.tv_sec == testime.tv_sec) &&
          (now.tv_usec >= testime.tv_usec)) ) {

         unsigned int qs = 0, count = 0, reclaim = 0;
         int i, cnt = model->ArgusTimeOutQueues->count;

         for (i = 0; i < cnt; i++) {
            queue = (struct ArgusQueueStruct *)ArgusPopQueue (model->ArgusTimeOutQueues, ARGUS_LOCK);
            qs++;
            count   += queue->count;
            reclaim += queue->reclaim;
            ArgusAddToQueue (model->ArgusTimeOutQueues, &queue->qhdr, ARGUS_LOCK);
         }

         ArgusDebug (7, "ArgusQueueManager() turns %-4d statusQueue %-4d qs %-2d items %-4d cache %-6lld resort %-6d reclaim %-6d new %-6lld sends %-8lld bsends %-8lld\n",
                       ArgusQMTurns, model->ArgusStatusQueue->count, qs, count, model->ArgusTotalCacheHits, model->ArgusStatusQueue->reclaim, reclaim,
                       model->ArgusTotalNewFlows, model->ArgusTotalSends, model->ArgusTotalBadSends);

         testime.tv_sec  += update.tv_sec;
         testime.tv_usec += update.tv_usec;
         if (testime.tv_usec > 1000000) {
            testime.tv_sec++;
            testime.tv_usec -= 1000000;
         }
      }
   }
*/
#endif 
 
   return (retn);
}


void
ArgusProcessQueueTimeout (struct ArgusModelerStruct *model, struct ArgusQueueStruct *queue)
{
   struct ArgusFlowStruct *last = NULL;
   int done = 0, timedout = 0;

   queue->turns++;
#if defined(ARGUS_THREADS)
   pthread_mutex_lock(&queue->lock);
#endif
   while ((!done)) {
      if (queue->start != NULL) {
         if ((last = (struct ArgusFlowStruct *) queue->start->prv) != NULL) {
            if (queue == model->ArgusStatusQueue) {
               struct timeval nowbuf, *now;

               if (ArgusSourceTask->ArgusReadingOffLine) {
                  now = &model->ArgusGlobalTime;
               } else {
                  now = &nowbuf;
                  gettimeofday(now, 0L);
               }

               if (ArgusCheckTimeout(model, &last->qhdr.qtime, getArgusFarReportInterval(model))) {
                  struct ArgusFlowStruct *frag;

                  timedout++;
                  ArgusRemoveFromQueue(queue, &last->qhdr, ARGUS_NOLOCK);

                  if ((frag = (struct ArgusFlowStruct *)last->frag.start) != NULL) {
                     struct timeval timeout = {2,0};
                     do {
                        struct ArgusFlowStruct *nxt = (struct ArgusFlowStruct *)frag->qhdr.nxt;
                        ArgusUpdateParentFlow(model, frag);

                        if (ArgusCheckTimeout(model, &frag->qhdr.qtime, &timeout))
                           ArgusDeleteObject(frag);

                        frag = nxt;

                     } while (last->frag.start && (frag != (struct ArgusFlowStruct *)last->frag.start));
                  }

                  if (!(last->status & ARGUS_RECORD_WRITTEN)) {
                     ArgusSendFlowRecord (model, last, last->status);
                  }

                  if (last->timeout > 0) {
                     if (last->timeout > ARGUSTIMEOUTQS)
                        last->timeout = ARGUSTIMEOUTQS;

                     if (model->ArgusTimeOutQueue[last->timeout] == NULL) {
                        model->ArgusTimeOutQueue[last->timeout] = ArgusNewQueue();
                        model->ArgusTimeOutQueue[last->timeout]->timeout = last->timeout;
                        ArgusPushQueue(model->ArgusTimeOutQueues, &model->ArgusTimeOutQueue[last->timeout]->qhdr, ARGUS_LOCK);
                     }

                     ArgusPushQueue(model->ArgusTimeOutQueue[last->timeout], &last->qhdr, ARGUS_LOCK);

                  } else
                     ArgusDeleteObject(last);

               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (10, "ArgusProcessQueueTimeout(%p, %p) done with %d records\n", model, queue, queue->count);
#endif 
                  done++;
               }

            } else {
               struct timeval timeout = {0,0};
               timeout.tv_sec = queue->timeout;

               if (ArgusCheckTimeout(model, &last->qhdr.qtime, &timeout)) {
                  ArgusRemoveFromQueue(queue, &last->qhdr, ARGUS_NOLOCK);
                  ArgusDeleteObject(last);
                  timedout++;
               } else {
                  done++;
               }
            }

         } else
            done++;

      } else 
         done++;
   }
#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&queue->lock);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessQueueTimeout(%p, %d) timedout %d remaining %d\n", model, queue->timeout, timedout, queue->count);
#endif 
}

void ArgusModelerStats(struct ArgusModelerStruct *);

void
ArgusModelerStats(struct ArgusModelerStruct *model)
{

}


#include <argus_ethertype.h>

#if !defined(__OpenBSD__)
#include <netinet/if_ether.h>
#endif

int ArgusProcessISLHdr (struct ArgusModelerStruct *, struct ether_header *, int);
int ArgusProcessNetbeuiHdr (struct ArgusModelerStruct *, struct ether_header *, int);
int ArgusProcessNetbiosHdr (struct ArgusModelerStruct *, struct ether_header *, int);
int ArgusProcessIsoclnsHdr (struct ArgusModelerStruct *, struct ether_header *, int);


#define ARGUS_ISL_ETHERHDR_LEN      26

int
ArgusProcessISLHdr (struct ArgusModelerStruct *model, struct ether_header *ep, int length)
{
   int type = (((unsigned char *)ep)[5] >> 4) & 0x0F;
   int retn = 0;

#define ARGUS_ISLTYPE_ETHER      0x0
#define ARGUS_ISLTYPE_TR         0x0
#define ARGUS_ISLTYPE_FDDI      0x2
#define ARGUS_ISLTYPE_ATM      0x3

   switch (type) {
      case ARGUS_ISLTYPE_ETHER:
         model->ArgusThisLength -= ARGUS_ISL_ETHERHDR_LEN;
         model->ArgusSnapLength -= ARGUS_ISL_ETHERHDR_LEN;
         model->ArgusThisUpHdr = ((unsigned char *)ep + ARGUS_ISL_ETHERHDR_LEN);
         model->ArgusThisEncaps |= ARGUS_ENCAPS_ISL;

         ep = (struct ether_header *) ((unsigned char *)ep + ARGUS_ISL_ETHERHDR_LEN);
         retn = ArgusProcessEtherHdr(model, ep, length - ARGUS_ISL_ETHERHDR_LEN);
   }
   return (retn);
}

int
ArgusProcessNetbeuiHdr (struct ArgusModelerStruct *model, struct ether_header *ep, int length)
{
   int retn = 0;
   return (retn);
}

int
ArgusProcessNetbiosHdr (struct ArgusModelerStruct *model, struct ether_header *ep, int length)
{
   int retn = 0;
   return (retn);
}


int
ArgusProcessIsoclnsHdr (struct ArgusModelerStruct *model, struct ether_header *ep, int length)
{
   int retn = 0;
   unsigned char *ptr = (unsigned char *)ep;

   ptr += 3;

   switch (*ptr) {
      case ARGUS_CLNS: model->ArgusThisNetworkFlowType = ARGUS_CLNS; break;
      case ARGUS_ESIS: model->ArgusThisNetworkFlowType = ARGUS_ESIS; break;
      case ARGUS_ISIS: model->ArgusThisNetworkFlowType = ARGUS_ISIS; break;
      case 0:          model->ArgusThisNetworkFlowType = ARGUS_NULLNS; break;
      default:         model->ArgusThisNetworkFlowType = ARGUS_CLNS; break;
   }

/*
   model->ArgusThisLength -= sizeof(struct llc);
   model->ArgusSnapLength -= sizeof(struct llc);
   model->ArgusThisUpHdr = (ptr + sizeof(struct llc));
*/
   model->ArgusThisLength -= 3;
   model->ArgusSnapLength -= 3;

   model->ArgusThisUpHdr = ptr;
   model->ArgusThisEncaps |= ARGUS_ENCAPS_LLC;
   return (retn);
}

#if !defined(IPV6_VERSION_MASK)
#define IPV6_VERSION_MASK   0xF0
#define IPV6_VERSION      0x60
#endif

unsigned short
ArgusDiscoverNetworkProtocol (unsigned char *ptr)
{
   unsigned short retn = ETHERTYPE_MPLS;

/* test for IPv4, IPv6, and vlan tags */

   if (ptr != NULL) {
      if ((((struct ip *)ptr)->ip_v == 4) && (((struct ip *)ptr)->ip_hl >= 5) &&
                (ntohs(((struct ip *)ptr)->ip_len) >= 20)) {
         retn = ETHERTYPE_IP;
      } else {
         if (((((struct ip6_hdr *)ptr)->ip6_vfc & IPV6_VERSION_MASK) == IPV6_VERSION) &&
                (ntohs(((struct ip6_hdr *)ptr)->ip6_plen) <= 2048)) {
            retn = ETHERTYPE_IPV6;
         } else {
            switch (ntohs(*(unsigned short *)(ptr + 2))) {
               case ETHERTYPE_IP:
               case ETHERTYPE_IPV6:
                  retn = ETHERTYPE_8021Q;
                  break;
               default:
                  retn = ARGUS_ETHER_HDR;
            }
         }
      }
   }

   return (retn);
}

void
ArgusParseMPLSLabel (unsigned int value, unsigned int *label, unsigned char *exp, unsigned char *bos, unsigned char *ttl)
{
   *label = value >> 12;
   *exp   = (value >> 9) & 0x07;
   *bos   = (value >> 8) & 0x01;
   *ttl   =  value & 0xFF;
}


/*
   ArgusProcessPacketHdrs - this routine should take in a pointer and
      a packet header type and process that header, returning the next
      layer type, or zero if the routine has found the IP layer.
      This is the entry point for handling packets from any of the
      source interface layers.
*/


int ArgusProcessPacketHdrs (struct ArgusModelerStruct *, char *, int, int);
int ArgusProcessPPPoEHdr (struct ArgusModelerStruct *, char *, int);
int ArgusProcessLLCHdr (struct ArgusModelerStruct *, char *, int);
int ArgusProcess80211Hdr (struct ArgusModelerStruct *, char *, int);
int ArgusProcessUDToEHdr (struct ArgusModelerStruct *, char *, int);
int ArgusProcessErspanIIHdr (struct ArgusModelerStruct *, char *, int);


int
ArgusProcessPacketHdrs (struct ArgusModelerStruct *model, char *p, int length, int type)
{
   int retn = 0;

   switch (type) {
      case ETHERTYPE_ERSPAN_II:
         model->ArgusThisNetworkFlowType = ETHERTYPE_ERSPAN_II;
         if ((retn = ArgusProcessErspanIIHdr(model, p, length)) < 0)
           model->ArgusThisUpHdr = (void *)p;
         break;

      case ETHERTYPE_TRANS_BRIDGE:
      case ARGUS_ETHER_HDR:
         model->ArgusThisNetworkFlowType =  ARGUS_ETHER_HDR;
         if ((retn = ArgusProcessEtherHdr(model, (struct ether_header *)p, length)) < 0)
            model->ArgusThisUpHdr = (void *)p;
         break;

      case ARGUS_802_11_HDR:
         model->ArgusThisNetworkFlowType = type;
         if ((retn = ArgusProcess80211Hdr(model, p, length)) < 0)
            model->ArgusThisUpHdr = (void *)p;
         break;

      case ETHERTYPE_PPP:
         model->ArgusThisNetworkFlowType = type;
         if ((retn = ArgusProcessPPPHdr(model, p, length)) < 0)
            model->ArgusThisUpHdr = (void *)p;
         break;

      case ETHERTYPE_PPPOED:
      case ETHERTYPE_PPPOES:
         model->ArgusThisNetworkFlowType = type;
         if ((retn = ArgusProcessPPPoEHdr(model, p, length)) < 0)
            model->ArgusThisUpHdr = (void *)p;
         break;

      case ETHERTYPE_UDTOE:
         model->ArgusThisNetworkFlowType = type;
         if ((retn = ArgusProcessUDToEHdr (model, p, length)) < 0)
            model->ArgusThisUpHdr = (void *)p;
         break;

      case ETHERTYPE_8021Q: {
         model->ArgusThisNetworkFlowType = type;
         model->ArgusThisPacket8021QEncaps = ntohs(*(unsigned short *)(p));
         model->ArgusThisEncaps |= ARGUS_ENCAPS_8021Q;

         retn = ntohs(*(unsigned short *)(p + 2));

         if (retn <= ETHERMTU) {  /* 802.3 Encapsulation */
            if (p[0] == 0x01 && p[1] == 0x00 &&
                p[2] == 0x0C && p[3] == 0x00 && p[4] == 0x00) {
                return (ArgusProcessISLHdr (model, (struct ether_header *)p, length));
            }

            model->ArgusThisUpHdr  += 4;
            model->ArgusThisLength -= 4;
            model->ArgusSnapLength -= 4;

            p = (void *) model->ArgusThisUpHdr;
            if ((retn = ArgusProcessLLCHdr(model, p, length)) < 0)
               model->ArgusThisUpHdr = (void *)p;

         } else {
            model->ArgusThisUpHdr += 4;
            model->ArgusThisLength -= 4;
            model->ArgusSnapLength -= 4;
         }
         break;
      }

      case ETHERTYPE_MPLS_MULTI:
      case ETHERTYPE_MPLS: {
         unsigned char exp, bos = 0, ttl;
         unsigned int labelbuf, *label = &labelbuf;

         model->ArgusThisNetworkFlowType = type;
         while (!(bos)) {
            unsigned int tlabel = ntohl(*(unsigned int *)(model->ArgusThisUpHdr));
            if (!(model->ArgusThisMplsLabelIndex)) {
               model->ArgusThisMplsLabel = tlabel;
               model->ArgusThisMplsLabelIndex++;
            }
            ArgusParseMPLSLabel (tlabel, label, &exp, &bos, &ttl);
            model->ArgusThisUpHdr  += 4;
            model->ArgusThisLength -= 4;
            model->ArgusSnapLength -= 4;
            model->ArgusThisEncaps |= ARGUS_ENCAPS_MPLS;

            retn = ArgusDiscoverNetworkProtocol(model->ArgusThisUpHdr);
         }
         break;
      }

      case ETHERTYPE_IP: {
         struct ip *ip = (struct ip *) p;

         if (STRUCTCAPTURED(model,*ip)) {
            if ((ntohs(ip->ip_len)) >= 20) {
               if (ip->ip_v == 4)
                  model->ArgusThisNetworkFlowType = ETHERTYPE_IP;
               else if (ip->ip_v == 6)
                  model->ArgusThisNetworkFlowType = ETHERTYPE_IPV6;

               model->ArgusThisIpHdr = (void *)ip;
               switch (ip->ip_p) {
                  case IPPROTO_TTP: { /* Preparation for Juniper TTP */
                     retn = ArgusProcessTtpHdr(model, ip, length);
                     break;
                  }
                  case IPPROTO_UDP: { /* RCP 4380 */
                     if (getArgusTunnelDiscovery(model))
                        retn = ArgusProcessUdpHdr(model, ip, length);
                     break;
                  }
                  case IPPROTO_GRE: { /* RFC 2784 */
                     retn = ArgusProcessGreHdr(model, ip, length);
                     break;
                  }
                  default:
                     retn = 0;
                     break;
               }

            } else
               break;
         }
         break;
      }

      case ETHERTYPE_IPV6:
         model->ArgusThisIpHdr = (void *)p;

      case ETHERTYPE_ARP:
      case ETHERTYPE_REVARP: {
         model->ArgusThisNetworkFlowType = type;
         retn = 0;
         break;
      }

      default:
         retn = -1;
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusProcessPacketHdrs(%p, %p, %d, %d) returning %d\n", model, p, length, type, retn);
#endif 

   return (retn);
}

struct teredoAuthHeader {
   unsigned char idlen, aulen;
};

struct teredoOriginHdr {
   unsigned char idlen, aulen;
};

#include <netinet/ip6.h>

struct teredo {
   unsigned short tid;
   struct teredoAuthHeader tauth;
};

struct ttp_header {
  u_char type;
  u_char priority;
  u_char proto;
  u_char queue;
  u_int ifl_input;
  u_short len;
  u_short destmask;
  u_int nh_index;
  u_int hint;
};


unsigned short
ArgusProcessTtpHdr (struct ArgusModelerStruct *model, struct ip *ip, int length)
{
   int retn = 0;
   int hlen = ip->ip_hl << 2;
   struct ttp_header *ttp = (struct ttp_header *) ((char *)ip + hlen);

   if (STRUCTCAPTURED(model, *ttp)) {
      ttp->ifl_input = ntohl(ttp->ifl_input);
      ttp->len       = ntohs(ttp->len);
      ttp->destmask  = ntohs(ttp->destmask);
      ttp->nh_index  = ntohl(ttp->nh_index);
      ttp->hint      = ntohl(ttp->hint);

      switch(ttp->type) {
         case 0x1:
         case 0x2: {
            int slen = (hlen + sizeof(*ttp));
            length -= slen;
            model->ArgusThisUpHdr  += slen;
            model->ArgusSnapLength -= slen;
            model->ArgusThisLength -= slen;
            retn = ArgusProcessPacketHdrs (model, (char *)(ttp + 1), length, ARGUS_ETHER_HDR);
            break;
         }

         case 0x3:
         case 0x4: {
            int slen = (hlen + sizeof(*ttp));
            length -= slen;
            model->ArgusThisUpHdr  += slen;
            model->ArgusSnapLength -= slen;
            model->ArgusThisLength -= slen;
            retn = ArgusProcessPacketHdrs (model, (char *)(ttp + 1), length, ETHERTYPE_IP);
            break;
         }

         case 0x0:
         default:
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessTtpHdr(%p, %p, %d) returning 0x%x\n", model, ip, length, retn);
#endif 
   return (retn);
}

unsigned short
ArgusProcessUdpHdr (struct ArgusModelerStruct *model, struct ip *ip, int length)
{
   int retn = 0;
   int len = 0, hlen = ip->ip_hl << 2;
   char *bp = ((char *)ip + hlen);
   struct udphdr *up = (struct udphdr *) bp;

   if (STRUCTCAPTURED(model, *up)) {
      unsigned short dport, sport;

      sport = ntohs(up->uh_sport);
      dport = ntohs(up->uh_dport);

      if (!((sport == 53) || (dport == 53))) {
         char *ptr = (char *) (up + 1);
         struct ip6_hdr *ipv6 = (struct ip6_hdr *) ptr;
         int isipv6 = 0;

         len += sizeof (*up);

         if (STRUCTCAPTURED(model, *ipv6)) {
            if ((isipv6 = (ipv6->ip6_vfc & IPV6_VERSION_MASK)) == IPV6_VERSION) {
               retn = ETHERTYPE_IPV6;
               len = ((char *) ipv6 - (char *)ip);
               model->ArgusThisEncaps |= ARGUS_ENCAPS_TEREDO;
               model->ArgusThisUpHdr  = (unsigned char *) ipv6;
               model->ArgusThisLength -= len;
               model->ArgusSnapLength -= len;
            } else {
               struct teredo *tptr = (struct teredo *) (up + 1);

               if (STRUCTCAPTURED(model, *tptr)) {
                  u_short type = ntohs(tptr->tid); 

                  int offset = 0;
                  switch (type) {
                     case 0x0000:  offset = 8; break;
                     case 0x0001:  offset = (4 + (tptr->tauth.idlen + tptr->tauth.aulen) + 8 + 1); break;
                     default: isipv6 = -1;
                  }

                  if (isipv6 == 0) {
                     ipv6 = (struct ip6_hdr *)(((u_char *)tptr) + offset);

                     if (STRUCTCAPTURED(model, *ipv6)) {
                        if ((isipv6 = (ipv6->ip6_vfc & IPV6_VERSION_MASK)) == IPV6_VERSION) {
                           retn = ETHERTYPE_IPV6;
                           len = ((char *) ipv6 - (char *)ip);
                           model->ArgusThisEncaps |= ARGUS_ENCAPS_TEREDO;
                           model->ArgusThisUpHdr  = (unsigned char *) ipv6;
                           model->ArgusThisLength -= len;
                           model->ArgusSnapLength -= len;

                        } else {
                           struct teredo *iptr = (struct teredo *) ((char *)tptr + offset);
                           if (STRUCTCAPTURED(model, *iptr)) {
                              u_short type = ntohs(iptr->tid); 
                              int offset = 0;
                              switch (type) {
                                 case 0x0000:  offset = 8; break;
                                 case 0x0001:  offset = (4 + (iptr->tauth.idlen + iptr->tauth.aulen) + 8 + 1); break;
                                 default: isipv6 = -1;
                              }

                              if (isipv6 == 0) {
                                 ipv6 = (struct ip6_hdr *)(((u_char *)iptr) + offset);
                                 if ((isipv6 = (ipv6->ip6_vfc & IPV6_VERSION_MASK)) == IPV6_VERSION) {
                                    retn = ETHERTYPE_IPV6;
                                    len = ((char *) ipv6 - (char *)ip);
                                    model->ArgusThisEncaps |= ARGUS_ENCAPS_TEREDO;
                                    model->ArgusThisUpHdr  = (unsigned char *) ipv6;
                                    model->ArgusThisLength -= len;
                                    model->ArgusSnapLength -= len;
                                 }
                              }
                           }
                        }
                     }
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessUdpHdr(%p, %p, %d) returning 0x%x\n", model, ip, length, retn);
#endif 

   return (retn);
}


#define GRE_VERS_MASK   0x0007          /* protocol version */
#define GRESRE_IP       0x0800          /* IP */
#define GRESRE_ASN      0xfffe          /* ASN */
#define GRE_CP          0x8000          /* checksum present */
#define GRE_RP          0x4000          /* routing present */
#define GRE_KP          0x2000          /* key present */
#define GRE_SP          0x1000          /* sequence# present */
#define GRE_sP          0x0800          /* source routing */
#define GRE_RECRS       0x0700          /* recursion count */
#define GRE_AP          0x0080          /* acknowledgment# present */

int
ArgusProcessGreHdr (struct ArgusModelerStruct *model, struct ip *ip, int length)
{
   int retn = 0, grelen = 4, hlen = ip->ip_hl << 2;
   char *bp = ((char *)ip + hlen);
   unsigned short flags;

   model->ArgusThisLength -= hlen;
   model->ArgusSnapLength -= hlen;
   length -= hlen;
      
   if (BYTESCAPTURED(model, *bp, 4)) {
      flags = EXTRACT_16BITS(bp);
      bp += sizeof(unsigned short);

      retn = EXTRACT_16BITS(bp);
      bp += sizeof(unsigned short);

      model->ArgusThisEncaps |= ARGUS_ENCAPS_GRE;

      switch(flags & GRE_VERS_MASK) {
         case 0: 
            if ((flags & GRE_CP) | (flags & GRE_RP)) {
               grelen += 4;
               bp += 4;
            }

            if (flags & GRE_KP) {
               bp += 4;
               grelen -= 4;
            }

            if (flags & GRE_SP) {
               bp += 4;
               grelen += 4;
            }

            if (flags & GRE_RP) {
               for (;;) {
                  u_int16_t af;
                  u_int8_t srelen;

                  if (BYTESCAPTURED(model, *bp, 4)) {
                     af = EXTRACT_16BITS(bp);
                     srelen = *(bp + 3);
                     bp += 4;
                     grelen -= 4;

                     if (af == 0 && srelen == 0)
                        break;

                     bp += srelen;
                     grelen += srelen;

                  } else
                     break;
               }
            }
            break;

         case 1:
            if (flags & GRE_KP) {
               bp += 4;
               grelen -= 4;
            }

            if (flags & GRE_SP) {
               bp += 4;
               grelen += 4;
            }

            if (flags & GRE_AP) {
               bp += 4;
               grelen += 4;
            }
            break;
      }

      model->ArgusThisUpHdr  = (unsigned char *) bp;
      model->ArgusThisLength -= grelen;
      model->ArgusSnapLength -= grelen;
      length -= grelen;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessGreHdr(%p, %p, %d) returning 0x%x\n", model, ip, length, retn);
#endif 

   return (retn);
}


int
ArgusProcessEtherHdr (struct ArgusModelerStruct *model, struct ether_header *ep, int length)
{
   int len = sizeof(struct ether_header);
   unsigned char *ptr;
   int retn = 0;

   length -= len;
   model->ArgusThisEpHdr           = ep;
   model->ArgusThisUpHdr           = (unsigned char *) (ep + 1);
   model->ArgusThisLength         -= len;
   model->ArgusSnapLength         -= len;

   model->ArgusThisIpHdr           = NULL;

   model->ArgusThisEncaps |= ARGUS_ENCAPS_ETHER;
   retn = ntohs(ep->ether_type);

   if (retn <= ETHERMTU) {  /* 802.3 Encapsulation */
      struct llc *llc = NULL;
      unsigned short ether_type = 0;

      ptr = (unsigned char *) ep;
      if (ptr[0] == 0x01 && ptr[1] == 0x00 &&
          ptr[2] == 0x0C && ptr[3] == 0x00 && ptr[4] == 0x00) {
          return (ArgusProcessISLHdr (model, ep, length));
      }

      ptr = (unsigned char *) model->ArgusThisUpHdr;
      llc = (struct llc *) ptr;

      if (BYTESCAPTURED(model,*llc, 3) && ((llc = model->ArgusThisLLC) != NULL)) {
         model->ArgusThisEncaps |= ARGUS_ENCAPS_LLC;

         bcopy((char *) ptr, (char *) llc, sizeof (struct llc));

#define ARGUS_IPX_TAG         100

         if (llc->ssap == LLCSAP_GLOBAL && llc->dsap == LLCSAP_GLOBAL) {
            model->ArgusThisNetworkFlowType = ARGUS_IPX_TAG;
            return (retn);
         }

         if ((((u_char *)ep)[0] == 0xf0) && (((u_char *)ep)[1] == 0xf0))
            return (ArgusProcessNetbeuiHdr (model, ep, length));

         if ((llc->ssap == LLCSAP_ISONS) && (llc->dsap == LLCSAP_ISONS) && (llc->llcui == LLC_UI))
            return(ArgusProcessIsoclnsHdr(model, (struct ether_header *)ptr, length));

         if ((llc->ssap == LLCSAP_SNAP) && (llc->dsap == LLCSAP_SNAP)) {
            if (llc->llcui == LLC_UI) {
               ((unsigned char *)&ether_type)[0] = ((unsigned char *)&llc->ethertype)[0];
               ((unsigned char *)&ether_type)[1] = ((unsigned char *)&llc->ethertype)[1];

               model->ArgusThisNetworkFlowType = ntohs(ether_type);
               retn = model->ArgusThisNetworkFlowType;

               model->ArgusThisLength -= sizeof(struct llc);
               model->ArgusSnapLength -= sizeof(struct llc);
               model->ArgusThisUpHdr = (ptr + sizeof(struct llc));
            }

         } else {
            if ((llc->llcu & LLC_U_FMT) == LLC_U_FMT) {
               model->ArgusThisUpHdr  += 3;
               model->ArgusThisLength -= 3;
               model->ArgusSnapLength -= 3;

               if ((llc->llcu & ~LLC_U_POLL) == LLC_XID) {
                  if (*model->ArgusThisUpHdr == LLC_XID_FI) {
                     model->ArgusThisUpHdr  += 3;
                     model->ArgusThisLength -= 3;
                     model->ArgusSnapLength -= 3;
                  }
               }
            } else {
               model->ArgusThisUpHdr  += 4;
               model->ArgusThisLength -= 4;
               model->ArgusSnapLength -= 4;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessEtherHdr(%p, %d) returning 0x%x\n", ep, length, retn);
#endif 

   return (retn);
}


#include <argus/ieee802_11.h>

extern int ArgusExtract802_11HeaderLength(u_int16_t);


int
ArgusProcess80211Hdr (struct ArgusModelerStruct *model, char *p, int length)
{
   int retn = 0, hdrlen;

   u_int16_t fc;

   fc = EXTRACT_LE_16BITS(p);
   hdrlen = ArgusExtract802_11HeaderLength(fc);

   switch (FC_TYPE(fc)) {
      case T_MGMT:
      case T_CTRL:
         break;

      case T_DATA: {
         if (!(DATA_FRAME_IS_NULL(FC_SUBTYPE(fc)))) {
            if (model->ArgusSrc->ArgusThisRadioTap.flags & IEEE80211_RADIOTAP_F_DATAPAD)
               hdrlen = ((hdrlen + 3) / 4) * 4;

            if (FC_WEP(fc)) {
            } else {
               retn = ArgusProcessLLCHdr(model, p + hdrlen, length - hdrlen);
            }
         }
         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcess80211Hdr(%p, %p, %d) returning 0x%x\n", model, p, length, retn);
#endif 

   return(retn);
}


int
ArgusProcessLLCHdr (struct ArgusModelerStruct *model, char *p, int length)
{
   int retn = 0;
   struct llc *llc = NULL;
   unsigned short ether_type = 0;
   unsigned char *ptr = (unsigned char *) p;
/*
   ptr = (unsigned char *) model->ArgusThisUpHdr;
*/
   llc = (struct llc *) ptr;

   if (BYTESCAPTURED(model,*llc,3)) {
      model->ArgusThisEncaps |= ARGUS_ENCAPS_LLC;

      llc = model->ArgusThisLLC;
      bcopy((char *) ptr, (char *) llc, sizeof (struct llc));

#define ARGUS_IPX_TAG         100

      if (llc->ssap == LLCSAP_GLOBAL && llc->dsap == LLCSAP_GLOBAL) {
         model->ArgusThisNetworkFlowType = ARGUS_IPX_TAG;
         return (retn);
      }

      if ((((u_char *)p)[0] == 0xf0) && (((u_char *)p)[1] == 0xf0))
         return (ArgusProcessNetbeuiHdr (model, (struct ether_header *)p, length));

      if ((llc->ssap == LLCSAP_ISONS) && (llc->dsap == LLCSAP_ISONS) && (llc->llcui == LLC_UI))
         return(ArgusProcessIsoclnsHdr(model, (struct ether_header *)ptr, length));

      if ((llc->ssap == LLCSAP_SNAP) && (llc->dsap == LLCSAP_SNAP)) {
         if (llc->llcui == LLC_UI) {
            ((unsigned char *)&ether_type)[0] = ((unsigned char *)&llc->ethertype)[0];
            ((unsigned char *)&ether_type)[1] = ((unsigned char *)&llc->ethertype)[1];

            retn = ntohs(ether_type);

            model->ArgusThisLength -= sizeof(struct llc);
            model->ArgusSnapLength -= sizeof(struct llc);
            model->ArgusThisUpHdr = (ptr + sizeof(struct llc));
         }

      } else {
         if ((llc->llcu & LLC_U_FMT) == LLC_U_FMT) {
            model->ArgusThisUpHdr  += 3;
            model->ArgusThisLength -= 3;
            model->ArgusSnapLength -= 3;

            if ((llc->llcu & ~LLC_U_POLL) == LLC_XID) {
               if (*model->ArgusThisUpHdr == LLC_XID_FI) {
                  model->ArgusThisUpHdr  += 3;
                  model->ArgusThisLength -= 3;
                  model->ArgusSnapLength -= 3;
               }
            }

         } else {
            model->ArgusThisUpHdr  += 4;
            model->ArgusThisLength -= 4;
            model->ArgusSnapLength -= 4;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessLLCHdr(%p, %p, %d) returning 0x%x\n", model, p, length, retn);
#endif 

   return(retn);
}


int
ArgusProcessPPPHdr (struct ArgusModelerStruct *model, char *p, int length)
{
   u_int proto = 0;
   int retn = 0, hdr_len = 0;

   if (length >= PPP_HDRLEN) {
      model->ArgusThisEncaps |= ARGUS_ENCAPS_PPP;
      switch (EXTRACT_16BITS(p)) {
         case (PPP_WITHDIRECTION_IN  << 8 | PPP_CONTROL):
            p += 2;
            length -= 2;
            hdr_len += 2;
            break;
        case (PPP_WITHDIRECTION_OUT << 8 | PPP_CONTROL):
            p += 2;
            length -= 2;
            hdr_len += 2;
            break;
        case (PPP_ADDRESS << 8 | PPP_CONTROL):
            p += 2;                     /* ACFC not used */
            length -= 2;
            hdr_len += 2;
            break;

        default:
            break;
      }

      if (*p % 2) {
         proto = *p;
         p++;
         length--;
         hdr_len++;
      } else {
         proto = EXTRACT_16BITS(p);
         p += 2;                     /* ACFC not used */
         length -= 2;
         hdr_len += 2;
      }

      switch (proto) {
         case PPP_IP:
            model->ArgusThisNetworkFlowType = PPP_IP;
            retn = ETHERTYPE_IP;
            break;

         case PPP_IPV6:
            model->ArgusThisNetworkFlowType = PPP_IPV6;
            retn = ETHERTYPE_IPV6;
            break;

         case PPP_OSI:
         case PPP_NS:
         case PPP_DECNET:
         case PPP_APPLE:
         case PPP_IPX:
         case PPP_VJC:
         case PPP_VJNC:
         case PPP_BRPDU:
         case PPP_STII:
         case PPP_VINES:

         case PPP_MPLS_UCAST:
         case PPP_MPLS_MCAST:

         case PPP_COMP:
         case PPP_HELLO:
         case PPP_LUXCOM:
         case PPP_SNS:
         case PPP_IPCP:
         case PPP_OSICP:
         case PPP_NSCP:
         case PPP_DECNETCP:
         case PPP_APPLECP:
         case PPP_IPXCP:
         case PPP_STIICP:
         case PPP_VINESCP:
         case PPP_IPV6CP:
         case PPP_CCP:
            break;

         case PPP_LCP:
         case PPP_PAP:
         case PPP_LQM:
         case PPP_CHAP:
         case PPP_BACP:
         case PPP_BAP:
         case PPP_MP:
            break;
      }

      model->ArgusThisUpHdr  += hdr_len;
      model->ArgusThisLength -= hdr_len;
      model->ArgusSnapLength -= hdr_len;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessPPPHdr(%p, %p, %d) returning %d\n", model, p, length, retn);
#endif 
   return (retn);
}


#define PPPOE_HDRLEN    6

int
ArgusProcessPPPoEHdr (struct ArgusModelerStruct *model, char *p, int length)
{
   const u_char *pload = (u_char *)p + PPPOE_HDRLEN;
   int retn = 0, hdr_len = PPPOE_HDRLEN;
   u_int proto;

   model->ArgusThisEncaps |= ARGUS_ENCAPS_ETHER | ARGUS_ENCAPS_PPP;

   if (!p[1]) {
      switch(EXTRACT_16BITS(p)) {
         case (PPP_WITHDIRECTION_IN  << 8 | PPP_CONTROL):
            pload += 2;
            hdr_len += 2;
            break;
         case (PPP_WITHDIRECTION_OUT << 8 | PPP_CONTROL):
            pload += 2;
            hdr_len += 2;
            break;
         case (PPP_ADDRESS << 8 | PPP_CONTROL):
            pload += 2;                     /* ACFC not used */
            hdr_len += 2;
            break;
         default:
            break;
      }
      if (*pload % 2) {
         proto = *pload;             /* PFC is used */
         pload++;
         hdr_len++;
        } else {
         proto = EXTRACT_16BITS(pload);
         pload += 2;
         hdr_len += 2;
      }
      switch (proto) {
         case PPP_IP:
            model->ArgusThisNetworkFlowType = PPP_IP;
            retn = ETHERTYPE_IP;
            break;

         case PPP_IPV6:
            model->ArgusThisNetworkFlowType = PPP_IPV6;
            retn = ETHERTYPE_IPV6;
            break;

         case PPP_OSI:
         case PPP_NS:
         case PPP_DECNET:
         case PPP_APPLE:
         case PPP_IPX:
         case PPP_VJC:
         case PPP_VJNC:
         case PPP_BRPDU:
         case PPP_STII:
         case PPP_VINES:

         case PPP_MPLS_UCAST:
         case PPP_MPLS_MCAST:

         case PPP_COMP:
         case PPP_HELLO:
         case PPP_LUXCOM:
         case PPP_SNS:
         case PPP_IPCP:
         case PPP_OSICP:
         case PPP_NSCP:
         case PPP_DECNETCP:
         case PPP_APPLECP:
         case PPP_IPXCP:
         case PPP_STIICP:
         case PPP_VINESCP:
         case PPP_IPV6CP:
         case PPP_CCP:
         case PPP_LCP:
         case PPP_PAP:
         case PPP_LQM:
         case PPP_CHAP:
         case PPP_BACP:
         case PPP_BAP:
         case PPP_MP:
            break;
      }
      model->ArgusThisUpHdr  += hdr_len;
      model->ArgusThisLength -= hdr_len;
      model->ArgusSnapLength -= hdr_len;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessPPPoEHdr(%p, %p, %d) returning %d\n", model, p, length, retn);
#endif 
   return (retn);
}

#define UDT2_DATA_PACKET        0x00
#define UDT2_CONTROL_PACKET     0x80
#define UDT2_PACKET_MASK        0x80

#define UDT2_HANDSHAKE          0x00
#define UDT2_KEEPALIVE          0x01
#define UDT2_ACK                0x02
#define UDT2_NACK               0x03
#define UDT2_ACK2               0x06

int
ArgusProcessUDToEHdr (struct ArgusModelerStruct *model, char *p, int length)
{
   int retn = 0;

   p += 2;  //  add 2 byte pad
   model->ArgusThisEncaps |= ARGUS_ENCAPS_UDT;
   model->ArgusThisUpHdr  += 2;
   model->ArgusThisLength -= 2;
   model->ArgusSnapLength -= 2;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessUDToEHdr(%p, %p, %d) returning %d\n", model, p, length, retn);
#endif
   return (retn);
}


int ArgusProcessErspanIIHdr(struct ArgusModelerStruct *model, char *p, int length)
{
   int retn = 0;
   struct erspan_ii_header *erspan;

   if ((erspan = (struct erspan_ii_header *) p) != NULL) {
      if (length <= sizeof (struct erspan_ii_header))
         return retn;
    
      if ( ERSPAN_VER(erspan) != 0x1)
           return retn;
    
      model->ArgusThisEncaps |= ARGUS_ENCAPS_ERSPAN_II;
      model->ArgusThisUpHdr = (unsigned char *)p + sizeof(struct erspan_ii_header);
      model->ArgusThisLength -= sizeof(struct erspan_ii_header);
      model->ArgusSnapLength -= sizeof(struct erspan_ii_header);
      retn = ARGUS_ETHER_HDR;
   }
   return retn;
}


int ArgusProcessLcpPacket (struct ArgusSourceStruct *, struct lcp_hdr *, int, struct timeval *);

int
ArgusProcessLcpPacket (struct ArgusSourceStruct *src, struct lcp_hdr *lcp, int length, struct timeval *tvp)
{
   struct ArgusModelerStruct *model = src->ArgusModel;
   struct ArgusSystemFlow *tflow = NULL;
   struct ArgusFlowStruct *flow;
   int retn = 0, status = 0;

   model->ArgusTotalPacket++;
   model->state &= ~ARGUS_DIRECTION;

   if (!(length) && !(tvp) && !(lcp))
      ArgusModelerCleanUp (model);
   else {
      if ((tflow = ArgusCreateLcpFlow(model, lcp)) != NULL) {
         ArgusCreateFlowKey(model, tflow, model->hstruct);

         if ((flow = ArgusFindFlow (model, model->hstruct)) == NULL) {
            if ((flow = ArgusNewFlow(model, model->ArgusThisFlow, model->hstruct, model->ArgusStatusQueue)) != NULL) {
               if (getArgusControlMonitor(model))
                  flow->userlen = ARGUS_MAXSNAPLEN;
               status = ARGUS_START;  
            }

         } else
            status = ARGUS_STATUS; 

         if (flow != NULL) {
            switch (lcp->code) {
               case PPP_LCP_CONF_REQ:
                  break;
               case PPP_LCP_CONF_ACK:
                  break;
               case PPP_LCP_CONF_NACK:
                  break;
               case PPP_LCP_CONF_REJ:
                  break;
               case PPP_LCP_TERM_REQ:
                  break;
               case PPP_LCP_TERM_ACK:
                  break;
               case PPP_LCP_CODE_REJ:
                  break;
               case PPP_LCP_PROTO_REJ:
                  break;
               case PPP_LCP_ECHO_REQ:
                  break;
               case PPP_LCP_ECHO_REPLY:
                  break;
               case PPP_LCP_DISCARD:
                  break;
            }
            ArgusUpdateFlow (model, flow, status, 1);
         }
      }
   }

   if (ArgusUpdateTime (model)) {
      ArgusQueueManager(model); 
#if !defined(ARGUS_THREADS)
      ArgusOutputProcess(ArgusOutputTask); 
#endif
   }

   if (ArgusShutDownFlag)
      ArgusShutDown(0);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessLcpPacket(%p, %p, %d, %p) returning %d\n", model, lcp, length, tvp, retn);
#endif 
   return (retn);
}

int ArgusProcessPacket (struct ArgusSourceStruct *, char *, int, struct timeval *, int);

int
ArgusProcessPacket (struct ArgusSourceStruct *src, char *p, int length, struct timeval *tvp, int type)
{
   struct ArgusModelerStruct *model = src->ArgusModel;
   struct ArgusSystemFlow *tflow = NULL;
   struct ArgusFlowStruct *flow = NULL;
   char *ptr = p;
   float value;
   int retn = 0;

   model->ArgusTotalPacket++;

   if (model->ArgusSrc->sNflag >= model->ArgusTotalPacket)
      return (retn);

   model->ArgusThisInterface = src->ArgusThisIndex;
   model->ArgusThisStats = NULL;
   model->ArgusThisEpHdr = NULL;
   model->ArgusThisIpHdr = NULL;
   model->ArgusThisMplsLabelIndex = 0;
   model->ArgusThisNetworkFlowType = 0;
   model->ArgusInProtocol = 1;

   if ((value = getArgusRealTime (model->ArgusSrc)) > 0) {
      long long tdiff, rtdiff;
      int tvalue;

      gettimeofday(&model->ArgusNowTime, 0L);
/*
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusProcessPacket: now %d.%06d global %d.%06d \n",
                          model->ArgusNowTime.tv_sec, model->ArgusNowTime.tv_usec,
                          model->ArgusGlobalTime.tv_sec, model->ArgusGlobalTime.tv_usec);
#endif 
*/
      if (model->ArgusLastPacketTimer.tv_sec) {
         tdiff  = ArgusTimeDiff (tvp, &model->ArgusLastPacketTimer);
         rtdiff = ArgusTimeDiff (&model->ArgusNowTime, &model->ArgusAdjustedTimer);
         tvalue = (int)(rtdiff * value);

         if (tvalue > 0) {
            struct timespec tsbuf, *ts = &tsbuf;
            if (tvalue < 100000) {
                  ts->tv_sec  = 0;
                  ts->tv_nsec = tvalue * 1000;
            } else {
                  ts->tv_sec  = 0;
                  ts->tv_nsec = 100000000;
            }
            nanosleep (ts, NULL);

            while (((tdiff - tvalue) > 0) && !(ArgusShutDownFlag)) {
#ifdef ARGUSDEBUG
               ArgusDebug (8, "ArgusProcessPacket: stalling tdiff %lld  rtdiff %lld  tvalue %d\n", tdiff, rtdiff, tvalue);
#endif 
               model->ArgusGlobalTime = model->ArgusLastPacketTimer;
               model->ArgusGlobalTime.tv_sec  += (tvalue / 1000000);
               model->ArgusGlobalTime.tv_usec += (tvalue % 1000000);

               while (model->ArgusGlobalTime.tv_usec > 1000000) {
                  model->ArgusGlobalTime.tv_sec++;
                  model->ArgusGlobalTime.tv_usec -= 1000000;
               }

               if (ArgusUpdateTime (model)) {
                  ArgusQueueManager(model);
                  ArgusModelerStats(model);
#if !defined(ARGUS_THREADS)
                  ArgusOutputProcess(ArgusOutputTask);
#endif
               }

               gettimeofday(&model->ArgusNowTime, 0L);
               rtdiff = ArgusTimeDiff (&model->ArgusNowTime, &model->ArgusAdjustedTimer);
               tvalue = (long long)(rtdiff * value);
            }
         }
      }

      model->ArgusGlobalTime = *tvp;
      model->ArgusLastPacketTimer = *tvp;
      model->ArgusAdjustedTimer   = model->ArgusNowTime;
   }

   if (!(length) && !(tvp) && !(p) && !(ArgusShutDownFlag))
      ArgusModelerCleanUp (model); 
   else {
      model->ArgusThisUpHdr = (unsigned char *)p;
      model->ArgusThisBytes = length;

      while (type > 0)
         if ((type = ArgusProcessPacketHdrs (model, ptr, model->ArgusThisLength, type)) >= 0)
            ptr = (char *)model->ArgusThisUpHdr;

      if (model->ArgusThisEpHdr)
         ptr = (char *)model->ArgusThisEpHdr;

      if ((tflow = ArgusCreateFlow(model, ptr, length)) != NULL) {
         ArgusCreateFlowKey(model, tflow, model->hstruct);

         if ((flow = ArgusFindFlow (model, model->hstruct)) != NULL) {
            struct ArgusQueueStruct *queue;

            if ((queue = flow->qhdr.queue) != NULL) {
               model->ArgusTotalCacheHits++;
               if (queue == model->ArgusStatusQueue) {
                  if (ArgusCheckTimeout(model, &flow->qhdr.qtime, getArgusFarReportInterval(model))) {
                     ArgusProcessQueueTimeout (model, model->ArgusStatusQueue);
                     ArgusRemoveFromQueue(flow->qhdr.queue, &flow->qhdr, ARGUS_LOCK);
                     ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                     queue->reclaim++;
                  }
 
               } else {
                  if (!(tflow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)) {
                     ArgusRemoveFromQueue(queue, &flow->qhdr, ARGUS_LOCK);
                     ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                  }
               }

               if ((flow->qhdr.lasttime.tv_sec  < model->ArgusGlobalTime.tv_sec) ||
                  ((flow->qhdr.lasttime.tv_sec == model->ArgusGlobalTime.tv_sec) &&
                   (flow->qhdr.lasttime.tv_usec < model->ArgusGlobalTime.tv_usec))) {

                  flow->qhdr.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                  flow->qhdr.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
               }

               ArgusUpdateFlow (model, flow, ARGUS_STATUS, 1);

            } else {
               struct ArgusFlowStruct *nflow;
               ArgusRemoveHashEntry(flow->htblhdr);
               flow->htblhdr = NULL;
               if ((nflow = ArgusNewFlow(model, (struct ArgusSystemFlow *)flow->dsrs[ARGUS_FLOW_INDEX], model->hstruct, model->ArgusStatusQueue)) != NULL)
                  ArgusUpdateFlow (model, nflow, ARGUS_STATUS, 1);
            }

         } else {
            if ((flow = ArgusNewFlow(model, model->ArgusThisFlow, model->hstruct, model->ArgusStatusQueue)) != NULL)
               ArgusUpdateFlow (model, flow, ARGUS_START, 1);
         }
      }
      if (flow == NULL)
         retn = 1;
   }

   if (ArgusUpdateTime (model)) {
      ArgusQueueManager (model);
#if !defined(ARGUS_THREADS)
      ArgusOutputProcess(ArgusOutputTask);
#endif
   }

   if (ArgusShutDownFlag)
      ArgusShutDown(0);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusProcessPacket(%p, %p, %d, %p, %d) returning %d\n", model, p, length, tvp, type, retn);
#endif 
   return (retn);
}

int
ArgusProcessIpPacket (struct ArgusModelerStruct *model, struct ip *ip, int length, struct timeval *tvp)
{
   struct ArgusSystemFlow *tflow = NULL;
   struct ArgusFlowStruct *flow = NULL;
   char *ptr = (char *)ip;

   int retn = 0, pass = 0, type = ETHERTYPE_IP; 


   model->ArgusTotalPacket++;

   while (type > 0)
      if ((type = ArgusProcessPacketHdrs (model, ptr, model->ArgusThisLength, type)) >= 0)
         ptr = (char *)model->ArgusThisUpHdr;

   ip = model->ArgusThisIpHdr;

   if (model->ArgusSrc->sNflag >= model->ArgusTotalPacket)
      return (retn);

   model->state &= ~ARGUS_DIRECTION;

   if (!(length) && !(tvp) && !(ip))
      ArgusModelerCleanUp (model); 

   else {
      if (ip->ip_v == 4) {
         model->ArgusThisNetworkFlowType = ETHERTYPE_IP;
         pass = STRUCTCAPTURED(model,*ip);
      } else {
         struct ip6_hdr *ipv6 = (struct ip6_hdr *) ip;
         model->ArgusThisNetworkFlowType = ETHERTYPE_IPV6;
         pass = STRUCTCAPTURED(model,*ipv6);
      }
/*
      model->ArgusThisIpHdr = (unsigned char *)ip;
      model->ArgusThisUpHdr = (unsigned char *)ip;
*/
      model->ArgusThisBytes = length;

      if (pass) {
         if ((tflow = ArgusCreateFlow(model, ip, length)) != NULL) {
            ArgusCreateFlowKey (model, tflow, model->hstruct);
            if ((flow = ArgusFindFlow (model, model->hstruct)) != NULL) {
               struct ArgusQueueStruct *queue;

               if ((queue = flow->qhdr.queue) != NULL) {
                  model->ArgusTotalCacheHits++;

                  if ((queue = flow->qhdr.queue) == model->ArgusStatusQueue) {
                     if (ArgusCheckTimeout(model, &flow->qhdr.qtime, getArgusFarReportInterval(model))) {
                        if (flow != (struct ArgusFlowStruct *) queue->start->prv)
                           ArgusProcessQueueTimeout (model, model->ArgusStatusQueue);       // if this record is timed out, all entries in status queue need to be timed out
                        if (!(flow->status & ARGUS_RECORD_WRITTEN))
                           ArgusSendFlowRecord (model, flow, flow->status);
                        ArgusRemoveFromQueue(flow->qhdr.queue, &flow->qhdr, ARGUS_LOCK);
                        ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                        queue->reclaim++;

                     }

                  } else {
                     if (queue) {
                        ArgusRemoveFromQueue(queue, &flow->qhdr, ARGUS_LOCK);
                        ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                     }
                  }

                  if ((flow->qhdr.lasttime.tv_sec  < model->ArgusGlobalTime.tv_sec) ||
                     ((flow->qhdr.lasttime.tv_sec == model->ArgusGlobalTime.tv_sec) &&
                      (flow->qhdr.lasttime.tv_usec < model->ArgusGlobalTime.tv_usec))) {

                     flow->qhdr.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                     flow->qhdr.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                  }

                  ArgusUpdateFlow (model, flow, ARGUS_STATUS, 1);

               } else {
                  struct ArgusFlowStruct *nflow;
                  ArgusRemoveHashEntry(flow->htblhdr);
                  flow->htblhdr = NULL;
                  if ((nflow = ArgusNewFlow(model, (struct ArgusSystemFlow *)flow->dsrs[ARGUS_FLOW_INDEX], model->hstruct, model->ArgusStatusQueue)) != NULL)
                     ArgusUpdateFlow (model, nflow, ARGUS_STATUS, 1);
               }

            } else {
               if ((flow = ArgusNewFlow(model, model->ArgusThisFlow, model->hstruct, model->ArgusStatusQueue)) != NULL)
                  ArgusUpdateFlow (model, flow, ARGUS_START, 1);
            }
         }
      }
      if (flow == NULL)
         retn = 1;
   }

   if (ArgusUpdateTime (model)) { 
      ArgusQueueManager (model); 
#if !defined(ARGUS_THREADS)
      ArgusOutputProcess(ArgusOutputTask); 
#endif
   }

   if (ArgusShutDownFlag)
      ArgusShutDown(0);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessIpPacket(%p, %d, %p) returning %d\n", ip, length, tvp, retn);
#endif 

   return (retn);
}

int
ArgusProcessEtherPacket (struct ArgusModelerStruct *model, struct ether_header *ep, int length, struct timeval *tvp)
{
   struct ArgusSystemFlow *tflow = NULL;
   struct ArgusFlowStruct *flow = NULL;
   int retn = 0, type;

   char *ptr = (char *)ep;

   model->ArgusTotalPacket++;

   if (model->ArgusSrc->sNflag >= model->ArgusTotalPacket)
      return (retn);

   model->state &= ~ARGUS_DIRECTION;

   if (!(length) && !(tvp) && !(ep))
      ArgusModelerCleanUp (model); 

   else {
      if (STRUCTCAPTURED(model,*ep)) {
         type = ARGUS_ETHER_HDR;
         model->ArgusThisBytes = length;

         while (type) {
            type = ArgusProcessPacketHdrs (model, ptr, model->ArgusThisLength, type);
            ptr = (char *)model->ArgusThisUpHdr;
         }

         if ((tflow = ArgusCreateFlow(model, model->ArgusThisEpHdr, length)) != NULL) {
            ArgusCreateFlowKey(model, tflow, model->hstruct);
            if ((flow = ArgusFindFlow (model, model->hstruct)) != NULL) {
               struct ArgusQueueStruct *queue;

               if ((queue = flow->qhdr.queue) != NULL) {
                  model->ArgusTotalCacheHits++;
                  if ((queue = flow->qhdr.queue) == model->ArgusStatusQueue) {
                     if (ArgusCheckTimeout(model, &flow->qhdr.qtime, getArgusFarReportInterval(model))) {
                        if (flow != (struct ArgusFlowStruct *) queue->start->prv) 
                           ArgusProcessQueueTimeout (model, model->ArgusStatusQueue);       // if this record is not last, other entries in status queue need to be timed out
                        if (!(flow->status & ARGUS_RECORD_WRITTEN))
                           ArgusSendFlowRecord (model, flow, flow->status);
                        ArgusRemoveFromQueue(flow->qhdr.queue, &flow->qhdr, ARGUS_LOCK);
                        ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                        queue->reclaim++;
                     }
 
                  } else {
                     if (queue) {
                        ArgusRemoveFromQueue(queue, &flow->qhdr, ARGUS_LOCK);
                        ArgusPushQueue(model->ArgusStatusQueue, &flow->qhdr, ARGUS_LOCK);
                     }
                  }

                  if ((flow->qhdr.lasttime.tv_sec  < model->ArgusGlobalTime.tv_sec) ||
                     ((flow->qhdr.lasttime.tv_sec == model->ArgusGlobalTime.tv_sec) &&
                      (flow->qhdr.lasttime.tv_usec < model->ArgusGlobalTime.tv_usec))) {

                     flow->qhdr.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
                     flow->qhdr.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
                  }

                  ArgusUpdateFlow (model, flow, ARGUS_STATUS, 1);

               } else {
                  struct ArgusFlowStruct *nflow;
                  ArgusRemoveHashEntry(flow->htblhdr);
                  flow->htblhdr = NULL;
                  if ((nflow = ArgusNewFlow(model, (struct ArgusSystemFlow *)flow->dsrs[ARGUS_FLOW_INDEX], model->hstruct, model->ArgusStatusQueue)) != NULL)
                     ArgusUpdateFlow (model, nflow, ARGUS_STATUS, 1);
               }

            } else {
               if ((flow = ArgusNewFlow(model, model->ArgusThisFlow, model->hstruct, model->ArgusStatusQueue)) != NULL)
                  ArgusUpdateFlow (model, flow, ARGUS_START, 1);
            }
         }
      }
      if (flow == NULL)
         retn = 1;
   }

   if (ArgusUpdateTime (model)) {
      ArgusQueueManager (model);
#if !defined(ARGUS_THREADS)
      ArgusOutputProcess(ArgusOutputTask);
#endif
   }

   if (ArgusShutDownFlag)
      ArgusShutDown(0);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusProcessEtherPacket(%p, %d, %p) returning %d\n", ep, length, tvp, retn);
#endif 

   return (retn);
}


void *
ArgusCreateFlow (struct ArgusModelerStruct *model, void *ptr, int length)
{
   void *retn = model->ArgusThisFlow;
   struct ether_header *ep = ptr;
   unsigned int keys = model->ArgusFlowKey;
   unsigned int index = 0;
   int i;

   model->state &= ~ARGUS_DIRECTION;
   memset (model->ArgusThisFlow, 0, sizeof(*model->ArgusThisFlow));

   for (i = 0; (keys && (i < ARGUS_FLOW_KEYS)); i++) {
      index = 0x01 << i;
      if (keys & index) {
         switch (index) {
            case ARGUS_FLOW_KEY_CLASSIC5TUPLE:
            case ARGUS_FLOW_KEY_LAYER_3_MATRIX:
               switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
                  case ETHERTYPE_IP: {
                     retn = ArgusCreateIPv4Flow (model, (struct ip *)model->ArgusThisIpHdr);
                     return (retn);
                  }
                  case ETHERTYPE_IPV6: {
                     retn = ArgusCreateIPv6Flow (model, (struct ip6_hdr *)model->ArgusThisIpHdr);
                     return (retn);
                  }
                  case ETHERTYPE_ARP:
                  case ETHERTYPE_REVARP: {
                     model->ArgusThisLength = length;
                     retn = ArgusCreateArpFlow (model, ep);
                     return (retn);
                  }

                  case ARGUS_802_11_HDR: {
                     model->ArgusThisLength = length;
                     retn = ArgusCreate80211Flow (model, ptr);
                     return (retn);
                  }

                  case ARGUS_ISIS:
                     retn = ArgusCreateIsisFlow (model, (struct isis_common_header *) model->ArgusThisUpHdr);
                     return (retn);

                  case ETHERTYPE_UDTOE:
                     retn = ArgusCreateUDTFlow (model, (struct udt_header *) model->ArgusThisUpHdr);
                     return (retn);
              }

              if (model->ArgusThisIpHdr) {
                 model->ArgusThisNetworkFlowType &= 0xFFFF0000;
                 model->ArgusThisNetworkFlowType |= ETHERTYPE_IP;
                 retn = ArgusCreateIPv4Flow (model, (struct ip *)model->ArgusThisIpHdr);
                 break;
              }

/* drop through to here if above protocols didn't do it */
            case ARGUS_FLOW_KEY_LAYER_2_MATRIX:
               if (ep != NULL) {
                  int dstgteq = 1, i;
                  model->ArgusThisLength = length;
                  model->ArgusThisFlow->hdr.type            = ARGUS_FLOW_DSR;
                  model->ArgusThisFlow->hdr.subtype         = ARGUS_FLOW_CLASSIC5TUPLE;
                  model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ETHER;
                  model->ArgusThisFlow->hdr.argus_dsrvl8.len  = 5;

#if !defined(ETH_ALEN)
#define ETH_ALEN   6
#endif
                  if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
                     for (i = 0; i < ETH_ALEN; i++) {
                        if (((unsigned char *)&ep->ether_shost)[i] != ((unsigned char *)&ep->ether_dhost)[i]) {
                           if (((unsigned char *)&ep->ether_shost)[i] > ((unsigned char *)&ep->ether_dhost)[i])
                              dstgteq = 0;
                           break;
                        }
                     }
                  }

                  if (dstgteq) {
                     bcopy ((char *) ep, (char *)&model->ArgusThisFlow->mac_flow.ehdr, sizeof (struct ether_header));
                  } else {
                     model->state |= ARGUS_DIRECTION;
                     bcopy ((char *)&ep->ether_shost, (char *)&model->ArgusThisFlow->mac_flow.ehdr.ether_dhost, ETH_ALEN);
                     bcopy ((char *)&ep->ether_dhost, (char *)&model->ArgusThisFlow->mac_flow.ehdr.ether_shost, ETH_ALEN);
                  }
                  model->ArgusThisFlow->mac_flow.ehdr.ether_type = ntohs(ep->ether_type);

                  if (model->ArgusThisEncaps & ARGUS_ENCAPS_LLC) {
                     model->ArgusThisFlow->mac_flow.ehdr.ether_type = 0;
                     switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
                        case ARGUS_CLNS:
                        case ARGUS_ESIS:
                        case ARGUS_NULLNS:
                           break;

                        default:
                           model->ArgusThisNetworkFlowType &= ~(0xFFFF);
                           break;
                     }
                     if (dstgteq) {
                        model->ArgusThisFlow->mac_flow.ssap = model->ArgusThisLLC->ssap;
                        model->ArgusThisFlow->mac_flow.dsap = model->ArgusThisLLC->dsap;
                     } else {
                        model->ArgusThisFlow->mac_flow.ssap = model->ArgusThisLLC->dsap;
                        model->ArgusThisFlow->mac_flow.dsap = model->ArgusThisLLC->ssap;
                     }
                  } else {
                     model->ArgusThisFlow->mac_flow.ssap = 0;
                     model->ArgusThisFlow->mac_flow.dsap = 0;
                  }
               }
               break;

            case ARGUS_FLOW_KEY_LOCAL_MPLS:
            case ARGUS_FLOW_KEY_COMPLETE_MPLS:
               break;

            case ARGUS_FLOW_KEY_VLAN:
               break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusCreateFlow() returning %p\n", retn);
#endif 

   return (retn);
}


int ArgusGenerateStartRecords = 0;

struct ArgusFlowStruct *
ArgusNewFlow (struct ArgusModelerStruct *model, struct ArgusSystemFlow *flow, struct ArgusHashStruct *hstruct, struct ArgusQueueStruct *queue)
{
   struct ArgusFlowStruct *retn = NULL;
   int timeout = ARGUS_OTHERTIMEOUT, userlen = 0;
   int len = flow->hdr.argus_dsrvl8.len;

   if (len > 0) {
      model->ArgusTotalNewFlows++;
      userlen = getArgusUserDataLen(model);

      if ((retn = (struct ArgusFlowStruct *) ArgusCalloc (1, sizeof(*retn))) != NULL) {
         int value;
         retn->status          = ARGUS_START;
         retn->state           = model->state & ARGUS_DIRECTION;
         retn->trans           = model->ArgusTransactionNum++;
         retn->userlen         = userlen;

         retn->srcint          = -1;
         retn->dstint          = -1;

         if (queue != NULL) {
            retn->qhdr.lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
            retn->qhdr.lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
         }

         retn->dsrs[ARGUS_FLOW_INDEX] = (struct ArgusDSRHeader *) &retn->canon.flow.hdr;
         retn->canon.flow.hdr = flow->hdr;

         bcopy ((char *)&flow->flow_un, (char *)&retn->canon.flow.flow_un, (flow->hdr.argus_dsrvl8.len - 1) * 4);
         retn->dsrindex |= 1 << ARGUS_FLOW_INDEX;

         if (retn->state & ARGUS_DIRECTION)
            retn->dsrs[ARGUS_FLOW_INDEX]->subtype |= ARGUS_REVERSE;

         if (hstruct != NULL) {
            if ((retn->htblhdr = ArgusAddHashEntry (model->ArgusHashTable, retn, hstruct)) != NULL) {
               if (queue != NULL)
                  ArgusPushQueue(queue, &retn->qhdr, ARGUS_LOCK);
            } else
               ArgusLog (LOG_ERR, "ArgusNewFlow() ArgusAddHashEntry error %s.\n", strerror(errno));
         }

         if ((value = getArgusKeystroke(model)) > 0) {
            if (value & ARGUS_SSH_KEYSTROKE)
               retn->status |= ARGUS_SSH_MONITOR;
            retn->skey.prev_pno = 0 - model->ArgusKeyStroke.gpc_max;
         }

      } else
         ArgusLog (LOG_WARNING, "ArgusNewFlow() ArgusMalloc error %s.\n", strerror(errno));

      switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
         case ETHERTYPE_IPV6: 
         case ETHERTYPE_IP:
            timeout = model->ArgusIPTimeout;
            model->ArgusTotalIPFlows++;
            if (ArgusControlPlaneProtocol(model, retn))
               retn->userlen = ARGUS_MAXSNAPLEN;
            break;
 
         case ETHERTYPE_ARP:
         case ETHERTYPE_REVARP:
            timeout = model->ArgusARPTimeout;
            model->ArgusTotalNonIPFlows++;
            if (getArgusControlMonitor(model))
               retn->userlen = ARGUS_MAXSNAPLEN;
            break;
 
         case ARGUS_ISIS:
            timeout = ARGUS_OTHERTIMEOUT;
            model->ArgusTotalNonIPFlows++;
            if (getArgusControlMonitor(model))
               retn->userlen = ARGUS_MAXSNAPLEN;
            break;
 
         default:
            model->ArgusTotalNonIPFlows++;
            timeout = ARGUS_OTHERTIMEOUT;
            break;
      }

      retn->timeout         = timeout;

   } else
      ArgusLog (LOG_WARNING, "ArgusNewFlow() flow key is not correct len equals zero\n");

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusNewFlow() returning %p\n", retn);
#endif 

   return (retn);
}


extern void ArgusZeroRecord(struct ArgusFlowStruct *);
void ArgusUpdateBasicFlow (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);


void
ArgusUpdateBasicFlow (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow, unsigned char state)
{
   struct ArgusTransportStruct *trans;
   struct ArgusTimeStruct *dtime, *otime = NULL;
   struct ArgusEncapsStruct *encaps;
   struct ArgusMetricStruct *metric;
   struct ArgusNetworkStruct *net;
   struct ArgusMplsStruct *mpls;
   struct ArgusVlanStruct *vlan;
   struct ArgusTimeObject *time;
   struct ArgusJitterStruct *jitter;
   model->ArgusTotalUpdates++;

   if (flow->status & ARGUS_RECORD_WRITTEN)
      ArgusZeroRecord(flow);

   model->ArgusThisDir = ((flow->state & ARGUS_DIRECTION) == (model->state & ARGUS_DIRECTION));

   if ((trans = (struct ArgusTransportStruct *) flow->dsrs[ARGUS_TRANSPORT_INDEX]) == NULL) {
      struct ArgusDeviceStruct *device = model->ArgusSrc->ArgusInterface[model->ArgusSrc->ArgusThisIndex].ArgusDevice;

      flow->dsrs[ARGUS_TRANSPORT_INDEX] = &flow->canon.trans.hdr;
      trans = (struct ArgusTransportStruct *) flow->dsrs[ARGUS_TRANSPORT_INDEX];
      trans->hdr.type              = ARGUS_TRANSPORT_DSR;
      trans->hdr.subtype           = ARGUS_SRCID | ARGUS_SEQ;
      trans->hdr.argus_dsrvl8.len  = 3;

      trans->srcid.a_un.value      = device->ArgusID.a_un.value;
      trans->hdr.argus_dsrvl8.qual = device->idtype;

      flow->dsrindex |= 0x01 << ARGUS_TRANSPORT_INDEX;
   }

   if (model->ArgusThisDir) {
      if (flow->srcint >= 0) {
         if (flow->srcint != model->ArgusThisInterface) {
            flow->canon.encaps.hdr.argus_dsrvl8.qual |= ARGUS_SRC_INT_CHANGED;
         }
      } else
         flow->srcint = model->ArgusThisInterface;
   } else {
      if (flow->dstint >= 0) {
         if (flow->dstint != model->ArgusThisInterface) {
            flow->canon.encaps.hdr.argus_dsrvl8.qual |= ARGUS_DST_INT_CHANGED;
         }
      } else 
         flow->dstint = model->ArgusThisInterface;
   }

   if ((encaps = (struct ArgusEncapsStruct *) flow->dsrs[ARGUS_ENCAPS_INDEX]) == NULL) {
      flow->dsrs[ARGUS_ENCAPS_INDEX] = (struct ArgusDSRHeader *) &flow->canon.encaps.hdr;
      encaps = (struct ArgusEncapsStruct *) flow->dsrs[ARGUS_ENCAPS_INDEX];
      memset(encaps, 0, sizeof(*encaps));
      encaps->hdr.type              = ARGUS_ENCAPS_DSR;
      encaps->hdr.argus_dsrvl8.len  = 3;
      flow->dsrindex |= 0x01 << ARGUS_ENCAPS_INDEX;

      if (model->ArgusThisDir)
         encaps->src = model->ArgusThisEncaps;
      else
         encaps->dst = model->ArgusThisEncaps;

   } else {
      if (model->ArgusThisDir) {
         if (flow->canon.encaps.src != model->ArgusThisEncaps) {
            if (flow->canon.encaps.src) 
               flow->canon.encaps.hdr.argus_dsrvl8.qual |= ARGUS_SRC_CHANGED;
            flow->canon.encaps.src |= model->ArgusThisEncaps;
         }
   
      } else {
         if (flow->canon.encaps.dst != model->ArgusThisEncaps) {
            if (flow->canon.encaps.dst) 
               flow->canon.encaps.hdr.argus_dsrvl8.qual |= ARGUS_DST_CHANGED;
            flow->canon.encaps.dst |= model->ArgusThisEncaps;
         }
      }
   }

   if ((metric = (struct ArgusMetricStruct *) flow->dsrs[ARGUS_METRIC_INDEX]) == NULL) {
      metric = (struct ArgusMetricStruct *)&flow->canon.metric.hdr;
      memset(metric, 0, sizeof(*metric));
      flow->dsrs[ARGUS_METRIC_INDEX] = (struct ArgusDSRHeader *) metric;
      metric->hdr.type               = ARGUS_METER_DSR;
      metric->hdr.argus_dsrvl8.len   = (sizeof(struct ArgusMetricStruct) + 3) / 4;

      flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
   }

   if ((time = (struct ArgusTimeObject *) flow->dsrs[ARGUS_TIME_INDEX]) == NULL) {
      time = &flow->canon.time;
      memset(time, 0, sizeof(*time));
      flow->dsrs[ARGUS_TIME_INDEX] = (struct ArgusDSRHeader *) time;
      time->hdr.type               = ARGUS_TIME_DSR;
      time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_TIMESTAMP;
      time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
      time->hdr.argus_dsrvl8.len   = 3;

      if (model->ArgusThisDir) {
         dtime = &time->src;
         otime = &time->dst;
      } else {
         dtime = &time->dst;
         otime = &time->src;
      }
      dtime->start.tv_sec  = model->ArgusGlobalTime.tv_sec;
      dtime->start.tv_usec = model->ArgusGlobalTime.tv_usec;

   } else {
      if (model->ArgusThisDir) {
         dtime = &time->src;
         otime = &time->dst;
      } else {
         dtime = &time->dst;
         otime = &time->src;
      }
      if (dtime->start.tv_sec == 0) {
         dtime->start.tv_sec  = model->ArgusGlobalTime.tv_sec;
         dtime->start.tv_usec = model->ArgusGlobalTime.tv_usec;
         if (otime->start.tv_sec) {
            time->hdr.subtype           = ARGUS_TIME_ABSOLUTE_RANGE;
         }

      } else {
         dtime->end.tv_sec  = model->ArgusGlobalTime.tv_sec;
         dtime->end.tv_usec = model->ArgusGlobalTime.tv_usec;
         time->hdr.subtype  = ARGUS_TIME_ABSOLUTE_RANGE;
      }
   }

   flow->dsrindex |= 1 << ARGUS_TIME_INDEX;

   if (getArgusmflag (model)) {
      struct ArgusMacStruct *mac;
      if ((mac = (struct ArgusMacStruct *) flow->dsrs[ARGUS_MAC_INDEX]) == NULL) {
         if (model->ArgusThisEpHdr != NULL) {
            mac = (struct ArgusMacStruct *) &flow->canon.mac.hdr;
            memset(mac, 0, sizeof(*mac));
            flow->dsrs[ARGUS_MAC_INDEX] = &mac->hdr;
            mac->hdr.type                = ARGUS_MAC_DSR;
            mac->hdr.subtype             = 0;
            mac->hdr.argus_dsrvl8.qual   = 0;
            mac->hdr.argus_dsrvl8.len    = 5;

            if (model->ArgusThisDir) {
               bcopy ((char *)model->ArgusThisEpHdr, (char *)&mac->mac.mac_union.ether, sizeof(struct ether_header));
            } else {
               bcopy ((char *)&model->ArgusThisEpHdr->ether_dhost, 
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_shost, sizeof(struct ether_addr));
               bcopy ((char *)&model->ArgusThisEpHdr->ether_shost, 
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_dhost, sizeof(struct ether_header));
            }
            mac->mac.mac_union.ether.ehdr.ether_type = ntohs(model->ArgusThisEpHdr->ether_type); 

            flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
         }

      } else {
         if (model->ArgusThisDir) {
            if (bcmp ((char *)&model->ArgusThisEpHdr->ether_shost,
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_shost, sizeof(struct ether_addr)) ||
                bcmp ((char *)&model->ArgusThisEpHdr->ether_dhost,
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_dhost, sizeof(struct ether_addr)) ||
               mac->mac.mac_union.ether.ehdr.ether_type != ntohs(model->ArgusThisEpHdr->ether_type))
               mac->hdr.argus_dsrvl8.qual |= ARGUS_SRC_MULTIPATH;

         } else {
            if (bcmp ((char *)&model->ArgusThisEpHdr->ether_dhost, 
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_shost, sizeof(struct ether_addr)) ||
                bcmp ((char *)&model->ArgusThisEpHdr->ether_shost, 
                      (char *)&mac->mac.mac_union.ether.ehdr.ether_dhost, sizeof(struct ether_addr)) ||
               mac->mac.mac_union.ether.ehdr.ether_type != ntohs(model->ArgusThisEpHdr->ether_type)) 
               mac->hdr.argus_dsrvl8.qual |= ARGUS_DST_MULTIPATH;
         }
      }
   }

   if ((net = (struct ArgusNetworkStruct *) flow->dsrs[ARGUS_NETWORK_INDEX]) == NULL) {
      net = (struct ArgusNetworkStruct *) &flow->canon.net;
      memset(net, 0, sizeof(*net));
      flow->dsrs[ARGUS_NETWORK_INDEX] = (struct ArgusDSRHeader *) net;

      if ((state == ARGUS_START) && (model->ArgusThisFlow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT)) {
         net->hdr.type              = ARGUS_NETWORK_DSR;
         net->hdr.subtype           = ARGUS_NETWORK_SUBTYPE_FRAG;
         net->hdr.argus_dsrvl8.qual = 0;
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusFragObject) + 3)/4) + 1;
      } else {
         net->hdr.type              = ARGUS_NETWORK_DSR;
         net->hdr.argus_dsrvl8.len  = 1;
         flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
      }
   }
   if (model->ArgusThisEncaps & ARGUS_ENCAPS_MPLS) {
      int test = 0, value;
      if ((mpls = (struct ArgusMplsStruct *) flow->dsrs[ARGUS_MPLS_INDEX]) == NULL) {
         mpls = (struct ArgusMplsStruct *) &flow->canon.mpls;
         memset(mpls, 0, sizeof(*mpls));
         flow->dsrs[ARGUS_MPLS_INDEX] = (struct ArgusDSRHeader *) mpls;
         mpls->hdr.type                = ARGUS_MPLS_DSR;
         mpls->hdr.subtype             = 0;
         mpls->hdr.argus_dsrvl8.qual   = 0;
         mpls->hdr.argus_dsrvl8.len    = 1;
         flow->dsrindex |= 1 << ARGUS_MPLS_INDEX;
      } else 
         test++;

      if (model->ArgusThisDir) {
         value = mpls->hdr.argus_dsrvl8.qual & 0x0F;
         mpls->hdr.argus_dsrvl8.qual = ((model->ArgusThisMplsLabelIndex & 0x0F) << 4) | value;
         mpls->slabel = model->ArgusThisMplsLabel;

      } else {
         value = mpls->hdr.argus_dsrvl8.qual & 0xF0;
         mpls->hdr.argus_dsrvl8.qual = (model->ArgusThisMplsLabelIndex & 0x0F) | value;
         mpls->dlabel = model->ArgusThisMplsLabel;
      }
   }

   if (model->ArgusThisEncaps & ARGUS_ENCAPS_8021Q) {
      if ((vlan = (struct ArgusVlanStruct *) flow->dsrs[ARGUS_VLAN_INDEX]) == NULL) {
         vlan = (struct ArgusVlanStruct *) &flow->canon.vlan;
         memset(vlan, 0, sizeof(*vlan));
         flow->dsrs[ARGUS_VLAN_INDEX] = (struct ArgusDSRHeader *) vlan;
         vlan->hdr.type               = ARGUS_VLAN_DSR;
         vlan->hdr.subtype            = 0;
         vlan->hdr.argus_dsrvl8.qual  = 0;
         vlan->hdr.argus_dsrvl8.len   = 2;
         flow->dsrindex |= 1 << ARGUS_VLAN_INDEX;
      }

      if (model->ArgusThisDir) {
         vlan->sid = model->ArgusThisPacket8021QEncaps;
         vlan->hdr.argus_dsrvl8.qual |= ARGUS_SRC_VLAN;

      } else {
         vlan->did = model->ArgusThisPacket8021QEncaps;
         vlan->hdr.argus_dsrvl8.qual |= ARGUS_DST_VLAN;
      }
   }

   if (model->ArgusGenerateTime) {
      if ((jitter = (struct ArgusJitterStruct *) flow->dsrs[ARGUS_JITTER_INDEX]) == NULL) {
         jitter = (struct ArgusJitterStruct *) &flow->canon.jitter;
         memset(jitter, 0, sizeof(*jitter));
         flow->dsrs[ARGUS_JITTER_INDEX]    = (struct ArgusDSRHeader *) jitter;
         jitter->hdr.type                  = ARGUS_JITTER_DSR;
         jitter->hdr.subtype               = 0;
         jitter->hdr.argus_dsrvl8.len      = 1;

         flow->dsrindex |= 1 << ARGUS_JITTER_INDEX;

         bzero((char *)&jitter->act,  sizeof(struct ArgusJitterObject));
         bzero((char *)&jitter->idle, sizeof(struct ArgusJitterObject));

         memset(&flow->stime.act,  0, sizeof(flow->stime.act));
         memset(&flow->stime.idle, 0, sizeof(flow->stime.idle));
         memset(&flow->dtime.act,  0, sizeof(flow->dtime.act));
         memset(&flow->dtime.idle, 0, sizeof(flow->dtime.idle));
         flow->stime.act.minval  = 0xffffffff;
         flow->stime.idle.minval = 0xffffffff;
         flow->dtime.act.minval  = 0xffffffff;
         flow->dtime.idle.minval = 0xffffffff;
      }
   }
}


struct ArgusFlowStruct *
ArgusUpdateFlow (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow, unsigned char state, unsigned char update)
{
   struct ArgusFlowStruct *retn = flow;

   ArgusUpdateBasicFlow (model, flow, state);

   if (model->ArgusThisIpHdr) {
      struct ArgusIPAttrStruct *attr = NULL;

      if ((attr = (struct ArgusIPAttrStruct *) flow->dsrs[ARGUS_IPATTR_INDEX]) == NULL) {
         flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
         attr = &flow->canon.attr;
         memset(attr, 0, sizeof(*attr));
         attr->hdr.type              = ARGUS_IPATTR_DSR;
         attr->hdr.subtype           = 0;
         attr->hdr.argus_dsrvl8.qual = 0;
         attr->hdr.argus_dsrvl8.len  = 1;
         flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
      }

#if !defined(IPTOS_CE)
#define IPTOS_CE                0x01    /* congestion experienced */
#define IPTOS_ECT               0x02    /* ECN-capable transport */
#endif

      switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
         case ETHERTYPE_IP: {
            struct ip *iphdr = (struct ip *) model->ArgusThisIpHdr;
            u_short ip_off = ntohs(iphdr->ip_off);

            if (model->ArgusThisDir) {
               if (!(attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC;
               }

               attr->src.ttl = iphdr->ip_ttl;
               attr->src.tos = iphdr->ip_tos;
               attr->src.ip_id = iphdr->ip_id;

               if ((attr->src.options = model->ArgusOptionIndicator) != 0)
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_OPTIONS;
               if ((attr->src.tos & (IPTOS_CE | IPTOS_ECT)) == (IPTOS_CE | IPTOS_ECT))
                  attr->src.status |= ARGUS_ECN_CONGESTED;
            } else {
               if (!(attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST;
               }

               attr->dst.ttl = iphdr->ip_ttl;
               attr->dst.tos = iphdr->ip_tos;
               attr->dst.ip_id = iphdr->ip_id;

               if ((attr->dst.options = model->ArgusOptionIndicator) != 0)
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_OPTIONS;
     
               if ((attr->dst.tos & (IPTOS_CE | IPTOS_ECT)) == (IPTOS_CE | IPTOS_ECT))
                  attr->dst.status |= ARGUS_ECN_CONGESTED;
            }

            retn = ArgusUpdateState (model, flow, state, update);

            if ((model->ArgusFlowKey & ARGUS_FLOW_KEY_CLASSIC5TUPLE) &&
                (((ip_off & 0x1fff) == 0) && (ip_off & IP_MF))) {
/*
         This is also a fragment, so we need to setup the expected fragment
         cache, so we can find the fragments that will be coming in.
         So get the fragment flow descriptor, and either find the flow
         or install one.  If the fragment descriptor exists, then we're
         now able to update the parent flow, if it hasn't been done.

         Add this fragment to the parents fragment list, so we can find
         them if we have to deallocate the parent.
*/
               struct ArgusSystemFlow *fflow = NULL;
               struct ArgusFlowStruct *frag = NULL;
               int tstate = model->state;

               if ((fflow = ArgusCreateFRAGFlow (model, iphdr, ETHERTYPE_IP)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCreateFRAGFlow() returned NULL.\n");

               ArgusCreateFlowKey(model, fflow, model->hstruct);
                  
               if ((frag = ArgusFindFlow (model, model->hstruct)) == NULL) {
                  if ((frag = ArgusNewFlow (model, fflow, model->hstruct, &flow->frag)) == NULL)
                     ArgusLog (LOG_ERR, "ArgusNewFragFlow() returned NULL.\n");
                
                  memset (&frag->canon.net, 0, sizeof(struct ArgusFragObject) + 4);
                  frag->canon.net.hdr.type            = ARGUS_NETWORK_DSR;
                  frag->canon.net.hdr.subtype         = ARGUS_NETWORK_SUBTYPE_FRAG;
                  frag->canon.net.hdr.argus_dsrvl8.qual = 0;
                  frag->canon.net.hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusFragObject) + 3)/4) + 1;
                  frag->dsrs[ARGUS_FRAG_INDEX] = (struct ArgusDSRHeader *) &frag->canon.net.hdr;

                  frag->canon.net.net_union.frag.parent = flow;
                  frag->canon.net.net_union.frag.frag_id = iphdr->ip_id;

                  ArgusUpdateBasicFlow (model, frag, state);

               } else {
                  struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)frag->dsrs[ARGUS_FRAG_INDEX];
                  struct ArgusFragObject *ofrag = &net->net_union.frag;

                  net->hdr.argus_dsrvl8.qual |= ARGUS_FRAG_OUT_OF_ORDER;
                  if (ofrag->parent == NULL) {
                     ofrag->parent = flow;
                     if (frag->qhdr.queue != &flow->frag) {
                        ArgusRemoveFromQueue(frag->qhdr.queue, &frag->qhdr, ARGUS_LOCK);
                        ArgusAddToQueue(&flow->frag, &frag->qhdr, ARGUS_LOCK);
                     }
                  }
               }

               if (ArgusUpdateFRAGState (model, frag, state, ETHERTYPE_IP))
                  ArgusDeleteObject (frag);

               model->state = tstate;

               if (model->ArgusThisDir) 
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_FRAGMENTS;
               else
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_FRAGMENTS;
   
            }
            break;
         }

         case ETHERTYPE_IPV6: {
            struct ip6_hdr *iphdr  = (struct ip6_hdr *) model->ArgusThisIpHdr;
            unsigned int flowid    = iphdr->ip6_flow;
            unsigned short ftos    = (flowid >> 16);
            unsigned char tos      = ((ntohs(ftos) >> 4) & 0x00FF);
            unsigned char ttl      = iphdr->ip6_hlim;
            struct ip6_frag *tfrag = NULL;

            if (model->ArgusThisDir) {
               if (!(attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC)) {
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC;
               }
               attr->src.ttl = ttl;
               attr->src.tos = tos;
               attr->src.ip_id = 0;
               if ((attr->src.options = model->ArgusOptionIndicator) != 0)
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_OPTIONS;
               if ((attr->src.tos & (IPTOS_CE | IPTOS_ECT)) == (IPTOS_CE | IPTOS_ECT))
                  attr->src.status |= ARGUS_ECN_CONGESTED;
            } else {
               if (!(attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST)) {
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST;
               }
               attr->dst.ttl = ttl;
               attr->dst.tos = tos;
               attr->dst.ip_id = 0;
               if ((attr->dst.options = model->ArgusOptionIndicator) != 0)
                  attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_OPTIONS;

               if ((attr->dst.tos & (IPTOS_CE | IPTOS_ECT)) == (IPTOS_CE | IPTOS_ECT))
                  attr->dst.status |= ARGUS_ECN_CONGESTED;
            }

            retn = ArgusUpdateState (model, flow, state, update);

            if ((model->ArgusFlowKey & ARGUS_FLOW_KEY_CLASSIC5TUPLE) &&
                (((tfrag = model->ArgusThisIpv6Frag) != NULL) && (((ntohs(tfrag->ip6f_offlg) & IP6F_OFF_MASK) == 0) &&
                                                                        (tfrag->ip6f_offlg  & IP6F_MORE_FRAG)))) {
/*
         This is also a fragment, so we need to setup the expected fragment
         cache, so we can find the fragments that will be coming in.
         So get the fragment flow descriptor, and either find the flow
         or install one.  If the fragment descriptor exists, then we're
         now able to update the parent flow, if it hasn't been done.

         Add this fragment to the parents fragment list, so we can find
         them if we have to deallocate the parent.
*/

               struct ArgusSystemFlow *fflow = NULL;
               struct ArgusFlowStruct *frag = NULL;
               int tstate = model->state;

               if ((fflow = ArgusCreateFRAGFlow (model, iphdr, ETHERTYPE_IPV6)) != NULL) {
                  ArgusCreateFlowKey(model, fflow, model->hstruct);
                     
                  if ((frag = ArgusFindFlow (model, model->hstruct)) == NULL) {

/* ok so here things are correct, we're going to schedule the expected frag struct
   onto the parent flow, and proceed */

                     if ((frag = ArgusNewFlow (model, fflow, model->hstruct, &flow->frag)) == NULL)
                        ArgusLog (LOG_ERR, "ArgusNewFragFlow() returned NULL.\n");
                   
                     memset (&frag->canon.net, 0, sizeof(struct ArgusFragObject) + 4);
                     frag->canon.net.hdr.type             = ARGUS_NETWORK_DSR;
                     frag->canon.net.hdr.subtype          = ARGUS_NETWORK_SUBTYPE_FRAG;
                     frag->canon.net.hdr.argus_dsrvl8.qual = 0;
                     frag->canon.net.hdr.argus_dsrvl8.len  = (sizeof(struct ArgusFragObject) + 3)/4 + 1;
                     frag->dsrs[ARGUS_FRAG_INDEX] = (struct ArgusDSRHeader *) &frag->canon.net.hdr;

                     frag->canon.net.net_union.frag.parent = flow;

                     ArgusUpdateBasicFlow (model, frag, state);

                  } else {

/* oops, here we've seen parts of the fragment and are just now seeing the 0 offset
   fragment, so need to move the frag from the general run queue and put it on this
   parent frag queue */

                     if (frag->dsrs[ARGUS_FRAG_INDEX] != NULL)
                        frag->dsrs[ARGUS_FRAG_INDEX]->argus_dsrvl8.qual |= ARGUS_FRAG_OUT_OF_ORDER;

                     if (frag->qhdr.queue != &flow->frag) {
                        ArgusRemoveFromQueue(frag->qhdr.queue, &frag->qhdr, ARGUS_LOCK);
                        ArgusAddToQueue(&flow->frag, &frag->qhdr, ARGUS_LOCK);
                     }
                  }

                  if (ArgusUpdateFRAGState (model, frag, state, ETHERTYPE_IPV6))
                     ArgusDeleteObject (frag);
                  model->state = tstate;

                  if (model->ArgusThisDir)
                     attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_SRC_FRAGMENTS;
                  else
                     attr->hdr.argus_dsrvl8.qual |= ARGUS_IPATTR_DST_FRAGMENTS;
               }

            }
         }
      }

   } else 
      retn = ArgusUpdateState (model, flow, state, update);

   if ((state == ARGUS_START) && ArgusGenerateStartRecords)
      ArgusSendFlowRecord(model, flow, ARGUS_START);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateFlow (%p, %d) returning %p\n", flow, state, retn);
#endif 
   return (retn);
}

void
ArgusTallyStats (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow)
{
   struct ArgusMetricStruct *metric = (void *)flow->dsrs[ARGUS_METRIC_INDEX];
   int bytes = model->ArgusThisBytes;

   if (metric != NULL) { 
      if (model->ArgusThisDir) 
         model->ArgusThisStats = &metric->src;
      else
         model->ArgusThisStats = &metric->dst;

      model->ArgusThisStats->pkts++;
      model->ArgusThisStats->bytes += bytes;
   }

   if (model->ArgusGeneratePacketSize) {
      struct ArgusPacketSizeStruct *psize = (void *)flow->dsrs[ARGUS_PSIZE_INDEX];
      struct ArgusPacketSizeObject *tpsize;

      if (psize == NULL) {
         psize = &flow->canon.psize;
         memset (psize, 0, sizeof(*psize));
         psize->hdr.type     = ARGUS_PSIZE_DSR;
         psize->src.psizemin = 0xFFFF;
         psize->dst.psizemin = 0xFFFF;
         flow->dsrs[ARGUS_PSIZE_INDEX] = &flow->canon.psize.hdr;
         flow->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
      }

      if (model->ArgusThisDir)
         tpsize = &psize->src;
      else
         tpsize = &psize->dst;

      if (bytes > tpsize->psizemax)
         tpsize->psizemax = bytes;
      if (bytes < tpsize->psizemin)
         tpsize->psizemin = bytes;
   }

   if (model->ArgusGenerateTime) {
      struct ArgusTimeStat  *ArgusThisTime;
      struct ArgusTimeStats *ArgusThisTimeStat;
      unsigned long long ArgusThisInterval, tout;
      struct timeval timeout;

      if (model->ArgusThisDir) {
         ArgusThisTime = &flow->stime;
      } else {
         ArgusThisTime = &flow->dtime;
      }

      if (model->ArgusInProtocol)
         ArgusThisTimeStat = &ArgusThisTime->act;
      else
         ArgusThisTimeStat = &ArgusThisTime->idle;

      if ((ArgusThisTime->lasttime.tv_sec  < model->ArgusGlobalTime.tv_sec) ||
         ((ArgusThisTime->lasttime.tv_sec == model->ArgusGlobalTime.tv_sec) &&
          (ArgusThisTime->lasttime.tv_usec < model->ArgusGlobalTime.tv_usec))) {

         if (ArgusThisTime->lasttime.tv_sec > 0) {
            if ((ArgusThisInterval = ArgusAbsTimeDiff (&model->ArgusGlobalTime, &ArgusThisTime->lasttime)) > 0) {
               timeout = *getArgusFarReportInterval (model);
               tout = (timeout.tv_sec * 1000000LL) + timeout.tv_usec;

               if (tout > 0) {
                  if (ArgusThisInterval < (tout * 2)) {
                     if (ArgusThisTimeStat->minval > ArgusThisInterval)
                        ArgusThisTimeStat->minval = ArgusThisInterval;

                     if (ArgusThisTimeStat->maxval < ArgusThisInterval)
                        ArgusThisTimeStat->maxval = ArgusThisInterval;

                     ArgusThisTimeStat->sum     += ArgusThisInterval;
                     ArgusThisTimeStat->sumsqrd += (double)ArgusThisInterval * (double)ArgusThisInterval;
                     ArgusThisTimeStat->n++;
                  }
               }
            }
         }

         ArgusThisTime->lasttime.tv_sec  = model->ArgusGlobalTime.tv_sec;
         ArgusThisTime->lasttime.tv_usec = model->ArgusGlobalTime.tv_usec;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusTallyStats (0x%x, 0x%x) returning\n", model, flow);
#endif 
}


void ArgusUpdateMACState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

void
ArgusUpdateMACState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{

}


int ArgusUpdateICMPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);
int ArgusUpdateICMPv6State (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

struct ArgusFlowStruct *
ArgusUpdateState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state, unsigned char update)
{
   struct ArgusFlowStruct *retn = flowstr;
   struct ArgusSystemFlow *flow;
   unsigned short proto;
   unsigned char ip_p;

   if ((flowstr->status & 0xF0) == 0) {
      flowstr->status |= state & 0xF0; 
   } else {
      switch (state & 0xF0) {
         case ARGUS_START:
         case ARGUS_STOP:
         case ARGUS_TIMEOUT:
         case ARGUS_SHUTDOWN:
         case ARGUS_CLOSED:
         case ARGUS_ERROR:
            flowstr->status &= ~0xF0;
            flowstr->status |= state & 0xF0; 
            break;
      }
   }

   ArgusUpdateMACState(model, flowstr, &state);

   flow = (struct ArgusSystemFlow *) flowstr->dsrs[ARGUS_FLOW_INDEX];

   switch (proto = (model->ArgusThisNetworkFlowType & 0xFFFF)) {
      case ETHERTYPE_IPV6: 
      case ETHERTYPE_IP: {
         if (proto == ETHERTYPE_IPV6)
            ip_p = flow->ipv6_flow.ip_p;
         else
            ip_p = flow->ip_flow.ip_p;
            
         if (model->ArgusThisFlow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {
            ArgusTallyStats (model, flowstr);
            if (ArgusUpdateFRAGState (model, flowstr, state, proto)) {
               ArgusDeleteObject(flowstr);
               return(NULL);
            }

         } else {
            switch (ip_p) {
               case IPPROTO_TCP: {
                  if (model->ArgusKeyStroke.status)
                     ArgusTCPKeystroke(model, flowstr, &state);

                  ArgusUpdateTCPState (model, flowstr, &state);

                  if (flowstr->timeout != model->ArgusTCPTimeout)
                     flowstr->timeout = model->ArgusTCPTimeout;
                  break;
               }

               case IPPROTO_ICMP:
                  ArgusUpdateICMPState (model, flowstr, &state);
                  if (flowstr->timeout != model->ArgusICMPTimeout)
                     flowstr->timeout = model->ArgusICMPTimeout;
                  break;

               case IPPROTO_ICMPV6:
                  ArgusUpdateICMPv6State (model, flowstr, &state);
                  if (flowstr->timeout != model->ArgusICMPTimeout)
                     flowstr->timeout = model->ArgusICMPTimeout;
                  break;

               case IPPROTO_IGMP:
                  if (flowstr->timeout == model->ArgusIGMPTimeout)
                     flowstr->timeout = model->ArgusIGMPTimeout;
                  break;

               case IPPROTO_UDP:
                  ArgusUpdateUDPState (model, flowstr, &state);
                  if (flowstr->timeout == model->ArgusIPTimeout)
                     flowstr->timeout = model->ArgusIPTimeout;
                  break;

               case IPPROTO_ESP:
                  ArgusUpdateESPState (model, flowstr, &state);
                  if (flowstr->timeout == model->ArgusIPTimeout)
                     flowstr->timeout = model->ArgusIPTimeout;
                  break;

               default:
                  if (flowstr->timeout == model->ArgusIPTimeout)
                     flowstr->timeout = model->ArgusIPTimeout;
                  break;
            }
         }
         break;
      }
      
      case ETHERTYPE_ARP:
      case ETHERTYPE_REVARP: 
         ArgusUpdateArpState (model, flowstr, &state);
         break;

      default:
         break;
   }

   if (update) {
      if (!(model->ArgusThisFlow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT))
         ArgusTallyStats (model, flowstr);

      ArgusUpdateAppState (model, flowstr, state); 
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateState (%p, %d) returning %d\n", flowstr, state, retn);
#endif 

   return (retn);
}


/*
    ArgusGenerateRecord
    Build the contiguous argus output record for output.
    Struct ArgusRecord is really just an array of 32-bit values, so lets build
    it that way to deal with 32 and 64-bit machines. 
*/

struct ArgusRecord *
ArgusGenerateRecord (struct ArgusModelerStruct *model, struct ArgusRecordStruct *rec,
                    unsigned char state, struct ArgusRecord *retn)
{

   if (rec) {
      switch (rec->hdr.type & 0xF0) {
         case ARGUS_FAR:
         case ARGUS_EVENT:
         case ARGUS_NETFLOW: {
            unsigned int ind, dsrindex, *dsrptr;
            int i, x, len = 0, dsrlen = 1;
            struct ArgusDSRHeader *dsr;

            bcopy ((char *)&rec->hdr, (char *)&retn->hdr, sizeof(retn->hdr));
            dsrptr = (unsigned int *)&retn->ar_un.mar;

            dsrindex = rec->dsrindex;

            if (!(dsrindex & (0x01 << ARGUS_TIME_INDEX)))
               ArgusLog (LOG_ERR, "ArgusGenerateRecord: time dsr not set");

            for (i = 0, ind = 1; (dsrindex && (i < ARGUSMAXDSRTYPE)); i++, ind <<= 1) {
               if ((dsr = rec->dsrs[i]) != NULL) {
                  len = ((dsr->type & 0x80) ? 1 : 
                         ((dsr->type == ARGUS_DATA_DSR) ? dsr->argus_dsrvl16.len :
                                                          dsr->argus_dsrvl8.len  ));
                  switch (i) {
                     default:
                        for (x = 0; x < len; x++)
                           *dsrptr++ = ((unsigned int *)rec->dsrs[i])[x];
                        break;

                     case ARGUS_FLOW_INDEX: {
                        switch (dsr->subtype) {
                           case ARGUS_FLOW_ARP:
                              switch (dsr->argus_dsrvl8.qual & 0x1F) {
                                 case ARGUS_TYPE_RARP: {
                                    struct ArgusRarpFlow *rarp = &((struct ArgusFlow *)dsr)->flow_un.rarp;
                                    dsr->argus_dsrvl8.len = 4 + ((rarp->hln * 2) + 3)/4;
                                    len = dsr->argus_dsrvl8.len;

                                    dsrptr[0] = ((unsigned int *)dsr)[0];
                                    dsrptr[1] = ((unsigned int *)dsr)[1];
                                    dsrptr[2] = ((unsigned int *)dsr)[2];
                                    dsrptr[3] = ((unsigned int *)dsr)[3];

                                    bcopy (&rarp->shaddr, &((char *)&dsrptr[4])[0],         rarp->hln);
                                    bcopy (&rarp->dhaddr, &((char *)&dsrptr[4])[rarp->hln], rarp->hln);
                                    dsrptr += dsr->argus_dsrvl8.len;
                                    break;
                                 }

                                 case ARGUS_TYPE_ARP: {
                                    struct ArgusArpFlow *arp = &((struct ArgusFlow *)dsr)->flow_un.arp;
                                    dsr->argus_dsrvl8.len = 4 + (arp->hln + 3)/4;
                                    len = dsr->argus_dsrvl8.len;

                                    dsrptr[0] = ((unsigned int *)dsr)[0];
                                    dsrptr[1] = ((unsigned int *)dsr)[1];
                                    dsrptr[2] = ((unsigned int *)dsr)[2];
                                    dsrptr[3] = ((unsigned int *)dsr)[3];
                                    dsrptr[4] = ((unsigned int *)dsr)[4];
                                    bcopy (&arp->haddr,  &((char *)&dsrptr[5])[0], arp->hln);
                                    dsrptr += dsr->argus_dsrvl8.len;
                                    break;
                                 }
                              }  
                              break;

                           default:
                              for (x = 0; x < len; x++)
                                 *dsrptr++ = ((unsigned int *)rec->dsrs[i])[x];
                              break;
                        }
                        break;
                     }

                     case ARGUS_NETWORK_INDEX: {
                        switch (dsr->subtype) {
                           case ARGUS_TCP_INIT: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)rec->dsrs[i];
                              struct ArgusTCPObject *tobj = &net->net_union.tcp;
                              struct ArgusTCPInitStatus *tcp = (void *)(dsrptr + 1);
                              *dsrptr       = *(unsigned int *)&net->hdr;
                              tcp->status   = tobj->status;
                              tcp->seqbase  = tobj->src.seqbase;
                              tcp->options  = tobj->options;
                              tcp->flags    = tobj->src.flags;
                              tcp->winshift = tobj->src.winshift;
                              dsrptr       += len;
                              break;
                           }

                           case ARGUS_TCP_STATUS: {
                              struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)rec->dsrs[i];
                              struct ArgusTCPObject *tobj = &net->net_union.tcp;
                              struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)(dsrptr + 1);
                              *dsrptr     = *(unsigned int *)&net->hdr;
                              tcp->status = tobj->status;
                              tcp->src    = tobj->src.flags;
                              tcp->dst    = tobj->dst.flags;
                              bzero(&tcp->pad, sizeof(tcp->pad));
                              dsrptr     += len;
                              break;
                           }

                           default:
                              for (x = 0; x < len; x++)
                                 *dsrptr++ = ((unsigned int *)rec->dsrs[i])[x];
                              break;
                        }
                        break;
                     }

                     case ARGUS_TIME_INDEX: {
                        struct ArgusTimeObject *dtime = (struct ArgusTimeObject *) dsr;
                        struct ArgusTime *mint, *maxt;
                        unsigned char subtype = 0;
                        unsigned char tlen = 1;

                        if (model->ArgusReportAllTime) {
                           if (dtime->src.start.tv_sec) {
                              subtype |= ARGUS_TIME_SRC_START;
                              tlen += 2;
                           }
                           if (dtime->src.end.tv_sec) {
                              subtype |= ARGUS_TIME_SRC_END;
                              tlen += 2;
                           }
                           if (dtime->dst.start.tv_sec) {
                              subtype |= ARGUS_TIME_DST_START;
                              tlen += 2;
                           }
                           if (dtime->dst.end.tv_sec) {
                              subtype |= ARGUS_TIME_DST_END;
                              tlen += 2;
                           }

                           dtime->hdr.argus_dsrvl8.len = tlen;
                           dtime->hdr.subtype &= ~(0x78);
                           dtime->hdr.subtype |= subtype;

                           *dsrptr++ = ((unsigned int *)rec->dsrs[i])[0];

                           for (x = 0; x < 4; x++) {
                              if (subtype & (ARGUS_TIME_SRC_START << x)) {
                                 switch (ARGUS_TIME_SRC_START << x) {
                                    case ARGUS_TIME_SRC_START:
                                       *dsrptr++ = dtime->src.start.tv_sec;
                                       *dsrptr++ = dtime->src.start.tv_usec;
                                       break;
                                    case ARGUS_TIME_SRC_END:
                                       *dsrptr++ = dtime->src.end.tv_sec;
                                       *dsrptr++ = dtime->src.end.tv_usec;
                                       break;
                                    case ARGUS_TIME_DST_START:
                                       *dsrptr++ = dtime->dst.start.tv_sec;
                                       *dsrptr++ = dtime->dst.start.tv_usec;
                                       break;
                                    case ARGUS_TIME_DST_END:
                                       *dsrptr++ = dtime->dst.end.tv_sec;
                                       *dsrptr++ = dtime->dst.end.tv_usec;
                                       break;
                                 }
                              }
                           }
                           len = tlen;

                        } else {
                           struct ArgusTime tmax = {0, 0}, tmin = {0xEFFFFFFF,0};
                           struct ArgusTime *atime;

                           for (x = 0; x < 4; x++) {
                              switch (ARGUS_TIME_SRC_START << x) {
                                 case ARGUS_TIME_SRC_START: atime = &dtime->src.start; break;
                                 case ARGUS_TIME_SRC_END:   atime = &dtime->src.end; break;
                                 case ARGUS_TIME_DST_START: atime = &dtime->dst.start; break;
                                 case ARGUS_TIME_DST_END:   atime = &dtime->dst.end; break;
                              }

                              if (atime->tv_sec) {
                                 if ((tmax.tv_sec  < atime->tv_sec)  ||
                                    ((tmax.tv_sec == atime->tv_sec) &&
                                     (tmax.tv_usec < atime->tv_usec))) {
                                    tmax  = *atime;
                                 }

                                 if ((tmin.tv_sec  > atime->tv_sec) ||
                                    ((tmin.tv_sec == atime->tv_sec) &&
                                     (tmin.tv_sec  > atime->tv_sec))) {
                                    tmin  = *atime;
                                 }
                              }
                           }

                           maxt = &tmax;
                           mint = &tmin;

                           if ((maxt->tv_sec  != mint->tv_sec) ||
                              ((maxt->tv_sec  == mint->tv_sec) &&
                               (maxt->tv_usec != mint->tv_usec))) {
                              dsr->argus_dsrvl8.len = 5;
                              len = 5;
                           } else {
                              dsr->argus_dsrvl8.len = 3;
                              len = 3;
                           }

                           *dsrptr++ = ((unsigned int *)rec->dsrs[i])[0];
                           *dsrptr++ = mint->tv_sec;
                           *dsrptr++ = mint->tv_usec;
                           if (len == 5) {
                              *dsrptr++ = maxt->tv_sec;
                              *dsrptr++ = maxt->tv_usec;
                           }
                        }
                        break;
                     }

                     case ARGUS_METRIC_INDEX: {
                        struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *) dsr;
                        unsigned char type = 0;

                        if ((metric->src.pkts + metric->dst.pkts) > 0) {
                           if (metric->src.pkts && metric->dst.pkts) {
                              if ((0xFF >= metric->src.pkts)  && (0xFF >= metric->dst.pkts) &&
                                  (0xFF >= metric->src.bytes) && (0xFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_BYTE;
                              else
                              if ((0xFFFF >= metric->src.bytes) && (0xFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_SHORT;
                              else
                              if ((0xFFFFFFFF >= metric->src.bytes) && (0xFFFFFFFF >= metric->dst.bytes))
                                 type = ARGUS_SRCDST_INT;
                              else
                                 type = ARGUS_SRCDST_LONGLONG;

                           } else {
                              if (metric->src.pkts) {
                                 if (0xFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->src.bytes)
                                    type = ARGUS_SRC_INT;
                                 else
                                    type = ARGUS_SRC_LONGLONG;
                              } else {
                                 if (0xFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_SHORT;
                                 else
                                 if (0xFFFFFFFF >= metric->dst.bytes)
                                    type = ARGUS_DST_INT;
                                 else
                                    type = ARGUS_DST_LONGLONG;
                              }
                           }
                        }

                        dsr = (struct ArgusDSRHeader *)dsrptr;
                        dsr->type    = ARGUS_METER_DSR;

                        if (getArgusAflag(model) && (metric->src.appbytes || metric->dst.appbytes)) {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES_APP;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->src.appbytes;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[4] = (unsigned char) metric->dst.bytes;
                                 ((unsigned char *)(dsr + 1))[5] = (unsigned char) metric->dst.appbytes;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[4] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[5] = ((unsigned short) metric->dst.appbytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 7;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[4] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[5] = ((unsigned int) metric->dst.appbytes);
                                 break;

                              case ARGUS_SRC_BYTE: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->src.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->src.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->src.appbytes);
                                 break;
                              }
                              case ARGUS_SRC_SHORT: {
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->src.appbytes);
                                 break;
                              }
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->src.appbytes);
                                 break;
                              case ARGUS_DST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = ((unsigned char) metric->dst.pkts);
                                 ((unsigned char *)(dsr + 1))[1] = ((unsigned char) metric->dst.bytes);
                                 ((unsigned char *)(dsr + 1))[2] = ((unsigned char) metric->dst.appbytes);
                                 break;
                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.appbytes);
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 4;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.appbytes);
                                 break;
                           }
                        } else {
                           dsr->subtype = ARGUS_METER_PKTS_BYTES;
                           switch (type) {
                              case ARGUS_SRCDST_BYTE:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned char *)(dsr + 1))[0] = (unsigned char) metric->src.pkts;
                                 ((unsigned char *)(dsr + 1))[1] = (unsigned char) metric->src.bytes;
                                 ((unsigned char *)(dsr + 1))[2] = (unsigned char) metric->dst.pkts;
                                 ((unsigned char *)(dsr + 1))[3] = (unsigned char) metric->dst.bytes;
                                 break;
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->src.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->src.bytes);
                                 ((unsigned short *)(dsr + 1))[2] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[3] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 ((unsigned int *)(dsr + 1))[2] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[3] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_SRCDST_LONGLONG:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 9;
                                 break;

                              case ARGUS_SRC_SHORT: {
                                 unsigned short value;
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 value = metric->src.pkts;
                                 ((unsigned short *)(dsr + 1))[0] = value;
                                 value = metric->src.bytes;
                                 ((unsigned short *)(dsr + 1))[1] = value;
                                 break;
                              }
                              case ARGUS_SRC_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->src.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->src.bytes);
                                 break;
                              case ARGUS_SRC_LONGLONG:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 break;

                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = ((unsigned short) metric->dst.pkts);
                                 ((unsigned short *)(dsr + 1))[1] = ((unsigned short) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_INT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned int *)(dsr + 1))[0] = ((unsigned int) metric->dst.pkts);
                                 ((unsigned int *)(dsr + 1))[1] = ((unsigned int) metric->dst.bytes);
                                 break;
                              case ARGUS_DST_LONGLONG:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 5;
                                 ((unsigned int *)(dsr + 1))[0] = (((unsigned int *)&metric->dst.pkts)[0]);
                                 ((unsigned int *)(dsr + 1))[1] = (((unsigned int *)&metric->dst.pkts)[1]);
                                 ((unsigned int *)(dsr + 1))[2] = (((unsigned int *)&metric->dst.bytes)[0]);
                                 ((unsigned int *)(dsr + 1))[3] = (((unsigned int *)&metric->dst.bytes)[1]);
                                 break;
                           }
                        }
                        len     = dsr->argus_dsrvl8.len;
                        dsrptr += len;
                        break;
                     }

                     case ARGUS_PSIZE_INDEX: {
                        struct ArgusPacketSizeStruct *psize  = (struct ArgusPacketSizeStruct *) dsr;
                        unsigned char type = 0;

                        if ((psize->src.psizemax > 0) && (psize->dst.psizemax > 0))
                           type = ARGUS_SRCDST_SHORT;
                        else
                        if (psize->src.psizemax > 0)
                           type = ARGUS_SRC_SHORT;
                        else
                        if (psize->dst.psizemax > 0)
                           type = ARGUS_DST_SHORT;

                        if (type != 0) {
                           dsr = (struct ArgusDSRHeader *)dsrptr;
                           dsr->type    = ARGUS_PSIZE_DSR;
                           dsr->subtype = 0;

                           switch (type) {
                              case ARGUS_SRCDST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 3;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 ((unsigned short *)(dsr + 1))[2] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[3] = psize->dst.psizemax;
                                 break;

                              case ARGUS_SRC_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->src.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->src.psizemax;
                                 break;

                              case ARGUS_DST_SHORT:
                                 dsr->argus_dsrvl8.qual = type;
                                 dsr->argus_dsrvl8.len = 2;
                                 ((unsigned short *)(dsr + 1))[0] = psize->dst.psizemin;
                                 ((unsigned short *)(dsr + 1))[1] = psize->dst.psizemax;
                                 break;

                              default:
                                 ArgusLog (LOG_ERR, "ArgusGenerateRecord: packet size type not defined");
                                 break;
                           }
                           dsr->argus_dsrvl8.qual = type;
                           len = dsr->argus_dsrvl8.len;
                           dsrptr += len;
                        } else
                           len = 0;
                        break;
                     }

                     case ARGUS_MPLS_INDEX: {
                        struct ArgusMplsStruct *mpls  = (struct ArgusMplsStruct *) dsr;
                        struct ArgusMplsStruct *tmpls = (struct ArgusMplsStruct *) dsrptr;
                        unsigned char subtype = mpls->hdr.subtype & ~(ARGUS_MPLS_SRC_LABEL | ARGUS_MPLS_DST_LABEL);

                        *dsrptr++ = *(unsigned int *)dsr;
                        tmpls->hdr.argus_dsrvl8.len = 1;

                        if (((mpls->hdr.argus_dsrvl8.qual & 0xF0) >> 4) > 0) {
                           subtype |= ARGUS_MPLS_SRC_LABEL;
                           *dsrptr++ = mpls->slabel;
                           tmpls->hdr.argus_dsrvl8.len++;
                        }
                        if ((mpls->hdr.argus_dsrvl8.qual & 0x0F) > 0) {
                           subtype |= ARGUS_MPLS_DST_LABEL;
                           *dsrptr++ = mpls->dlabel;
                           tmpls->hdr.argus_dsrvl8.len++;
                        }
                        tmpls->hdr.subtype = subtype;
                        len = tmpls->hdr.argus_dsrvl8.len;
                        break;
                     }

                     case ARGUS_JITTER_INDEX: {
                        struct ArgusJitterStruct *jitter = (struct ArgusJitterStruct *) dsr;
                        struct ArgusJitterStruct *tjit   = (struct ArgusJitterStruct *) dsrptr;
                        int size = sizeof(jitter->act.src)/4;
                              
                        *dsrptr++ = *(unsigned int *)dsr; 
                        tjit->hdr.argus_dsrvl8.len = 1;
                                 
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_ACTIVE_JITTER) {
                           unsigned int *tptr = (unsigned int *)&jitter->act.src;
                           for (x = 0; x < size; x++)
                              *dsrptr++ = *tptr++;
                           tjit->hdr.argus_dsrvl8.len += size;
                        }        
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_SRC_IDLE_JITTER) {
                           unsigned int *tptr = (unsigned int *)&jitter->idle.src;
                           for (x = 0; x < size; x++)
                              *dsrptr++ = *tptr++;
                           tjit->hdr.argus_dsrvl8.len += size;
                        }     
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_ACTIVE_JITTER) {
                           unsigned int *tptr = (unsigned int *)&jitter->act.dst;
                           for (x = 0; x < size; x++)
                              *dsrptr++ = *tptr++;
                           tjit->hdr.argus_dsrvl8.len += size;
                        }     
                        if (jitter->hdr.argus_dsrvl8.qual & ARGUS_DST_IDLE_JITTER) {
                           unsigned int *tptr = (unsigned int *)&jitter->idle.dst;
                           for (x = 0; x < size; x++)
                              *dsrptr++ = *tptr++;
                           tjit->hdr.argus_dsrvl8.len += size;
                        }     
                                 
                        len = tjit->hdr.argus_dsrvl8.len;
                        break;   
                     }

                     case ARGUS_IPATTR_INDEX: {
                        struct ArgusIPAttrStruct *attr  = (struct ArgusIPAttrStruct *) dsr;
                        struct ArgusIPAttrStruct *tattr = (struct ArgusIPAttrStruct *) dsrptr;

                        *dsrptr++ = *(unsigned int *)dsr;
                        tattr->hdr.argus_dsrvl8.len = 1;

                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) {
                           *dsrptr++ = *(unsigned int *)&attr->src;
                           tattr->hdr.argus_dsrvl8.len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS) {
                           *dsrptr++ = attr->src.options;
                           tattr->hdr.argus_dsrvl8.len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) {
                           *dsrptr++ = *(unsigned int *)&attr->dst;
                           tattr->hdr.argus_dsrvl8.len++;
                        }
                        if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS) {
                           *dsrptr++ = attr->dst.options;
                           tattr->hdr.argus_dsrvl8.len++;
                        }
                        len = tattr->hdr.argus_dsrvl8.len;
                        break;
                     }

/* user capture data buffers are passed to the output
      model as (struct ArgusDataStruct *) buffers, not as
      pointers to sections of the canonical record.
      Seems wierd but is saves us a few copies        */

                     case ARGUS_SRCUSERDATA_INDEX:
                     case ARGUS_DSTUSERDATA_INDEX: {
                        unsigned short *sptr;
                        struct ArgusDataStruct *user = (struct ArgusDataStruct *) dsr;
                        len = 2 + (user->count + 3)/4;

                        sptr = (unsigned short *)&user->hdr.argus_dsrvl8;
                        *sptr = len;

                        for (x = 0; x < len; x++)
                           *dsrptr++ = ((unsigned int *)user)[x];

                        break;
                     }
                  }
                  dsrlen += len;
               }
               dsrindex &= ~ind;
            }

            retn->hdr.len = dsrlen;
            break;
         }
         case ARGUS_MAR: {
            bcopy ((char *)&rec->canon, (char *) retn, rec->hdr.len * 4);
            retn->hdr = rec->hdr;
            if (state)
               retn->hdr.cause = (state & 0xF0) | (retn->hdr.cause & 0x0F);
            break;
         }
      }
         
   } else {
      retn->hdr.type = ARGUS_MAR;
      retn->hdr.type  |= ARGUS_VERSION;
      retn->hdr.cause = state & 0xF0;
      retn->hdr.len = 1;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusGenerateRecord (0x%x, %d) done\n", rec, state);
#endif 
   return (retn);
}


struct ArgusRecordStruct *ArgusCopyRecordStruct (struct ArgusRecordStruct *);

#define ARGUS_MAX_OS_STATUS     4204

struct ArgusRecordStruct *
ArgusCopyRecordStruct (struct ArgusRecordStruct *rec)
{
   struct ArgusRecordStruct *retn = NULL;
   int i;

   if (rec) {
      switch (rec->hdr.type & 0xF0) {
         case ARGUS_EVENT: {
            if ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (ARGUS_MAX_OS_STATUS)) != NULL)
               bcopy ((char *)rec, (char *)retn, ARGUS_MAX_OS_STATUS);
            break;
         }

         case ARGUS_FAR: {
            if ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (sizeof(*retn))) != NULL) {
               bcopy ((char *)&rec->hdr, (char *)&retn->hdr, sizeof (rec->hdr));
               bcopy ((char *)&rec->canon, (char *)&retn->canon, sizeof (rec->canon));

               retn->status    = rec->status;
               retn->trans     = rec->trans;
               retn->timeout   = rec->timeout;

               if ((retn->dsrindex = rec->dsrindex)) {
                  for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                     if (rec->dsrs[i] != NULL) {
                        switch (i) {
                           case ARGUS_TRANSPORT_INDEX: retn->dsrs[i] = &retn->canon.trans.hdr; break;
                           case ARGUS_TIME_INDEX:      retn->dsrs[i] = &retn->canon.time.hdr; break;
                           case ARGUS_FLOW_INDEX:      retn->dsrs[i] = &retn->canon.flow.hdr; break;
                           case ARGUS_METRIC_INDEX:    retn->dsrs[i] = &retn->canon.metric.hdr; break;
                           case ARGUS_NETWORK_INDEX:   retn->dsrs[i] = &retn->canon.net.hdr; break;
                           case ARGUS_IPATTR_INDEX:    retn->dsrs[i] = &retn->canon.attr.hdr; break;
                           case ARGUS_JITTER_INDEX:    retn->dsrs[i] = &retn->canon.jitter.hdr; break;
                           case ARGUS_ICMP_INDEX:      retn->dsrs[i] = &retn->canon.icmp.hdr; break;
                           case ARGUS_ENCAPS_INDEX:    retn->dsrs[i] = &retn->canon.encaps.hdr; break;
                           case ARGUS_PSIZE_INDEX:     retn->dsrs[i] = &retn->canon.psize.hdr; break;
                           case ARGUS_MAC_INDEX:       retn->dsrs[i] = &retn->canon.mac.hdr; break;
                           case ARGUS_VLAN_INDEX:      retn->dsrs[i] = &retn->canon.vlan.hdr; break;
                           case ARGUS_MPLS_INDEX:      retn->dsrs[i] = &retn->canon.mpls.hdr; break;

                           case ARGUS_SRCUSERDATA_INDEX:
                           case ARGUS_DSTUSERDATA_INDEX: {
                              struct ArgusDataStruct *user = (struct ArgusDataStruct *) rec->dsrs[i];
                              if (user->count > 0) {
                                 if ((retn->dsrs[i] = (void *) ArgusCalloc(1, (8 + user->size))) != NULL) {
                                    bcopy ((char *)rec->dsrs[i], (char *)retn->dsrs[i], 8 + user->count);
                                 } else {
                                    retn->dsrindex &= ~(0x01 << i);
                                 }
                                 break;
                              }
                           }
                        }

                     } else {
                        switch (i) {
                           case ARGUS_SRCUSERDATA_INDEX:
                           case ARGUS_DSTUSERDATA_INDEX:
                              if (retn->dsrs[i] != NULL)
                                 ArgusFree(retn->dsrs[i]);
                              break;
                        }
                        retn->dsrs[i] = NULL;
                        retn->dsrindex &= ~(0x01 << i);
                     }
                  }
               }

               retn->srate     = rec->srate;
               retn->drate     = rec->drate;
               retn->sload     = rec->sload;
               retn->dload     = rec->dload;
               retn->pcr       = rec->pcr;
               retn->sploss    = rec->sploss;
               retn->dploss    = rec->dploss;
            }
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCopyRecordStruct (0x%x) done\n", rec);
#endif 

   return (retn);
}


struct ArgusRecordStruct *
ArgusGenerateListRecord (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow, unsigned char state)
{
   struct ArgusRecordStruct *retn = NULL;
   int dsrlen = 1, i;

   if ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (sizeof(*retn))) != NULL) {
      if (flow) {
         bcopy ((char *)&flow->canon, (char *)&retn->canon, sizeof (flow->canon));
         if ((retn->dsrindex = flow->dsrindex) != 0) {
            for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
               if (flow->dsrs[i] != NULL) {
                  switch (i) {
                     case ARGUS_TRANSPORT_INDEX:   retn->dsrs[i] = &retn->canon.trans.hdr; break;
                     case ARGUS_TIME_INDEX:        retn->dsrs[i] = &retn->canon.time.hdr; break;
                     case ARGUS_ENCAPS_INDEX:      retn->dsrs[i] = &retn->canon.encaps.hdr; break;
                     case ARGUS_FLOW_INDEX:        retn->dsrs[i] = &retn->canon.flow.hdr; break;
                     case ARGUS_METRIC_INDEX:      retn->dsrs[i] = &retn->canon.metric.hdr; break;
                     case ARGUS_PSIZE_INDEX:       retn->dsrs[i] = &retn->canon.psize.hdr; break;
                     case ARGUS_IPATTR_INDEX:      retn->dsrs[i] = &retn->canon.attr.hdr; break;
                     case ARGUS_MAC_INDEX:         retn->dsrs[i] = &retn->canon.mac.hdr; break;
                     case ARGUS_ICMP_INDEX:        retn->dsrs[i] = &retn->canon.icmp.hdr; break;

/* pass the user data buffer into the list record */
                     case ARGUS_SRCUSERDATA_INDEX:
                     case ARGUS_DSTUSERDATA_INDEX: {
                        struct ArgusDataStruct *data = (struct ArgusDataStruct *) retn->dsrs[i];
                        retn->dsrs[i] = flow->dsrs[i];
                        flow->dsrs[i] = NULL;
                        if (data != NULL) {
                           ArgusFree(data);
                        }
                        break;
                     }

                     case ARGUS_NETWORK_INDEX: {
                        switch (retn->canon.net.hdr.subtype & 0x7F) {
                           case ARGUS_TCP_STATUS:
                           case ARGUS_TCP_PERF:
                              ArgusTCPFlowRecord (&retn->canon.net, state);
                              retn->dsrs[i] = &retn->canon.net.hdr;
                              break;

                           case ARGUS_ESP_DSR:
                              ArgusESPFlowRecord (&retn->canon.net, state);
                              retn->dsrs[i] = &retn->canon.net.hdr;
                              break;

                           default:
                              retn->dsrs[i] = &retn->canon.net.hdr;
                              break;
                        }
                        break;
                     }

                     case ARGUS_MPLS_INDEX:        retn->dsrs[i] = &retn->canon.mpls.hdr; break;
                     case ARGUS_VLAN_INDEX:        retn->dsrs[i] = &retn->canon.vlan.hdr; break;

                     case ARGUS_JITTER_INDEX: {
                        struct ArgusJitterStruct *jitter  = &retn->canon.jitter;

                        if ((flow->stime.act.n || flow->dtime.act.n) ||(flow->stime.idle.n || flow->dtime.idle.n)) {
                           
                           jitter->hdr.argus_dsrvl8.qual = 0;
                           jitter->hdr.argus_dsrvl8.len  = 1;

                           if (flow->stime.act.n) {
                              struct ArgusStatsObject *tjit = (struct ArgusStatsObject *) (&jitter->act.src);
                              tjit->n       = flow->stime.act.n;
                              tjit->minval  = flow->stime.act.minval;
                              tjit->maxval  = flow->stime.act.maxval;
                              tjit->meanval = flow->stime.act.sum/flow->stime.act.n;
                              tjit->stdev   = (sqrt ((flow->stime.act.sumsqrd/flow->stime.act.n) -
                                                      pow ((flow->stime.act.sum)/flow->stime.act.n, 2.0))) * 1;
                              
                              jitter->hdr.argus_dsrvl8.qual |= ARGUS_SRC_ACTIVE_JITTER;
                              jitter->hdr.argus_dsrvl8.len  += sizeof(*tjit)/4;
                              tjit++;
                           }

                           if (flow->stime.idle.n) {
                              struct ArgusStatsObject *tjit = (struct ArgusStatsObject *) (&jitter->idle.src);
                              tjit->n       = flow->stime.idle.n;
                              tjit->minval  = flow->stime.idle.minval;
                              tjit->maxval  = flow->stime.idle.maxval;
                              tjit->meanval = flow->stime.idle.sum/flow->stime.idle.n;
                              tjit->stdev   = (sqrt ((flow->stime.idle.sumsqrd/flow->stime.idle.n) -
                                                      pow ((flow->stime.idle.sum)/flow->stime.idle.n, 2.0))) * 1;

                              jitter->hdr.argus_dsrvl8.qual |= ARGUS_SRC_IDLE_JITTER;
                              jitter->hdr.argus_dsrvl8.len  += sizeof(*tjit)/4;
                              tjit++;
                           }

                           if (flow->dtime.act.n) {
                              struct ArgusStatsObject *tjit = (struct ArgusStatsObject *) (&jitter->act.dst);
                              tjit->n       = flow->dtime.act.n;
                              tjit->minval  = flow->dtime.act.minval;
                              tjit->maxval  = flow->dtime.act.maxval;
                              tjit->meanval = flow->dtime.act.sum/flow->dtime.act.n;
                              tjit->stdev   = (sqrt ((flow->dtime.act.sumsqrd/flow->dtime.act.n) -
                                                      pow ((flow->dtime.act.sum)/flow->dtime.act.n, 2.0))) * 1;

                              jitter->hdr.argus_dsrvl8.qual |= ARGUS_DST_ACTIVE_JITTER;
                              jitter->hdr.argus_dsrvl8.len  += sizeof(*tjit)/4;
                              tjit++;
                           }

                           if (flow->dtime.idle.n) {
                              struct ArgusStatsObject *tjit = (struct ArgusStatsObject *) (&jitter->idle.dst);
                              tjit->n       = flow->dtime.act.n;
                              tjit->n       = flow->dtime.idle.n;
                              tjit->minval  = flow->dtime.idle.minval;
                              tjit->maxval  = flow->dtime.idle.maxval;
                              tjit->meanval = flow->dtime.idle.sum/flow->dtime.idle.n;
                              tjit->stdev   = (sqrt ((flow->dtime.idle.sumsqrd/flow->dtime.idle.n) -
                                                      pow ((flow->dtime.idle.sum)/flow->dtime.idle.n, 2.0))) * 1;

                              jitter->hdr.argus_dsrvl8.qual |= ARGUS_DST_IDLE_JITTER;
                              jitter->hdr.argus_dsrvl8.len  += sizeof(*tjit)/4;
                              tjit++;
                           }
             
                           retn->dsrs[i] = (struct ArgusDSRHeader *)jitter;

                        } else {
                           retn->dsrindex &= ~ARGUS_JITTER_INDEX;
                           retn->dsrs[i] = NULL;
                        }

                        break;
                     }

                     case ARGUS_BEHAVIOR_INDEX: {
                        struct ArgusBehaviorStruct *actor = &retn->canon.actor;
                        retn->dsrs[i] = NULL;
                        int value;

                        if ((value = getArgusKeystroke(model)) > 0) {
                           actor->hdr.type    = ARGUS_BEHAVIOR_DSR;
                           actor->hdr.subtype = 0;
                           actor->hdr.argus_dsrvl8.len = sizeof(*actor)/4;
                           actor->keyStroke.src.n_strokes = flow->skey.n_strokes;
                           actor->keyStroke.dst.n_strokes = 0;

                           if (flow->skey.n_pkts >= model->ArgusKeyStroke.n_min) {
                              if ((value == ARGUS_SSH_KEYSTROKE) && (flow->status & ARGUS_SSH_MONITOR)) {
                                 actor->hdr.subtype = ARGUS_SSH_KEYSTROKE;
                                 retn->dsrs[i] = (struct ArgusDSRHeader *)actor;
                              } else
                              if (value == ARGUS_TCP_KEYSTROKE) {
                                 actor->hdr.subtype = ARGUS_TCP_KEYSTROKE;
                                 retn->dsrs[i] = (struct ArgusDSRHeader *)actor;
                              }
                           }

                        }
                        if (retn->dsrs[i] == NULL) {
                           actor->keyStroke.src.n_strokes = 0;
                           actor->keyStroke.dst.n_strokes = 0;
                           retn->dsrindex &= ~ARGUS_BEHAVIOR_INDEX;
                        }
                        break;
                     }
                  }

                  if (retn->dsrs[i]) {
                     dsrlen += ((retn->dsrs[i]->type & 0x80) ? 1 : 
                               ((retn->dsrs[i]->type == ARGUS_DATA_DSR) ? retn->dsrs[i]->argus_dsrvl16.len :
                                                                           retn->dsrs[i]->argus_dsrvl8.len  ));
                  }

               } else {
                  switch (i) {
                     case ARGUS_SRCUSERDATA_INDEX:
                     case ARGUS_DSTUSERDATA_INDEX:
                        if (retn->dsrs[i] != NULL)
                           ArgusFree(retn->dsrs[i]);
                  }

                  retn->dsrs[i] = NULL;
                  retn->dsrindex &= ~(0x01 << i);
               }
            }

         } else {
            if (retn->dsrs[ARGUS_SRCUSERDATA_INDEX] != NULL) {
               ArgusFree(retn->dsrs[ARGUS_SRCUSERDATA_INDEX]);
               retn->dsrs[ARGUS_SRCUSERDATA_INDEX] = NULL;
               retn->dsrindex &= ~(0x01 << ARGUS_SRCUSERDATA_INDEX);
            }
            if (retn->dsrs[ARGUS_DSTUSERDATA_INDEX] != NULL) {
               ArgusFree(retn->dsrs[ARGUS_DSTUSERDATA_INDEX]);
               retn->dsrs[ARGUS_DSTUSERDATA_INDEX] = NULL;
               retn->dsrindex &= ~(0x01 << ARGUS_DSTUSERDATA_INDEX);
            }
         }

         retn->srate     = ArgusFetchSrcRate(retn);
         retn->drate     = ArgusFetchDstRate(retn);
         retn->sload     = ArgusFetchSrcLoad(retn);
         retn->dload     = ArgusFetchDstRate(retn);
         retn->pcr       = ArgusFetchAppByteRatio(retn);
         retn->sploss    = ArgusFetchPercentSrcLoss(retn);
         retn->dploss    = ArgusFetchPercentDstLoss(retn);

      } else {
         retn->dsrindex = 0;
         bzero ((char *)&retn->canon, sizeof(retn->canon));
         bzero ((char *)&retn->dsrs, sizeof(retn->dsrs));
      }

      if (!(flow) && ((state == ARGUS_STOP) || (state == ARGUS_ERROR))) {
         retn->hdr.type = ARGUS_MAR;
         retn->status    = 0;
         retn->trans     = 0;
         retn->timeout   = 0;

      } else {
         retn->hdr.type  = flow->canon.hdr.type | ARGUS_FAR;
         retn->status    = flow->status;
         retn->trans     = flow->trans;
         retn->timeout   = flow->timeout;
      }

      retn->hdr.type  |= ARGUS_VERSION;
      retn->hdr.cause = state & 0xF0;
      retn->hdr.len = dsrlen;

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusMallocListRecord (%d) returned NULL\n", sizeof(*retn)); 
#endif 
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusGenerateListRecord (%p, %p, %d) returning %p\n", model, flow, state, retn);
#endif 
   return (retn);
}


void
ArgusSendFlowRecord (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow, unsigned char state)
{
   struct ArgusRecordStruct *argus;
#ifdef ARGUSDEBUG
   int scheduled = 0;
#endif

   if (flow != NULL) {
      if (model->ArgusOutputList) {
         struct ArgusFlowStruct *frag;
         if ((frag = (struct ArgusFlowStruct *)flow->frag.start) != NULL) {
            do {
               ArgusUpdateParentFlow(model, frag);
               frag = (struct ArgusFlowStruct *)frag->qhdr.nxt;
            } while (frag != (struct ArgusFlowStruct *)flow->frag.start);
         }

         if (flow->canon.metric.src.pkts || flow->canon.metric.dst.pkts) {
            if (flow->canon.trans.seqnum == 0) {
               if ((flow->canon.trans.seqnum = model->ArgusSeqNum++) == 0xFFFFFFFF)
                  flow->canon.trans.seqnum = model->ArgusSeqNum++;
            }

            if ((argus = ArgusGenerateListRecord (model, flow, state)) != NULL) {
               ArgusPushBackList (model->ArgusOutputList, (struct ArgusListRecord *) argus, ARGUS_LOCK);
               flow->status |= ARGUS_RECORD_WRITTEN;
               model->ArgusTotalSends++;
#ifdef ARGUSDEBUG
               scheduled = 1;
#endif

#if defined(ARGUS_THREADS)
               pthread_mutex_lock(&model->ArgusOutputList->lock);
               pthread_cond_signal(&model->ArgusOutputList->cond);
               pthread_mutex_unlock(&model->ArgusOutputList->lock);
#endif
            }

#ifdef ARGUSDEBUG
            if (scheduled)
               ArgusDebug (9, "ArgusSendFlowRecord (%p, %p, %d) scheduled %p\n", model, flow, state, argus);
            else
               ArgusDebug (9, "ArgusSendFlowRecord (%p, %p, %d) done\n", model, flow, state);
#endif 
         } else {
            model->ArgusTotalBadSends++;
         }

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (3, "ArgusSendFlowRecord (%p, %p, %d) no model->ArgusOutputList\n", model, flow, state);
#endif 
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusSendFlowRecord (%p, %p, %d) no flow provided\n", model, flow, state);
#endif 
   }
}


void
ArgusModelerCleanUp (struct ArgusModelerStruct *model)
{
   struct ArgusQueueStruct *queue;

   if ((model->ArgusTimeOutQueues != NULL) && (model->ArgusTimeOutQueues->count > 0)) {
      int i, cnt = model->ArgusTimeOutQueues->count;

      for (i = 0; i < cnt; i++) {
         queue = (struct ArgusQueueStruct *)ArgusPopQueue (model->ArgusTimeOutQueues, ARGUS_LOCK);
         if (queue->count) {
#ifdef ARGUSDEBUG
            ArgusDebug (9, "ArgusModelerCleanUp(%p) ArgusProcessQueue(%p) timeout queue with %d records\n", model, queue, queue->count);
#endif 
            ArgusProcessQueue (model, queue, ARGUS_SHUTDOWN);
         }
         ArgusDeleteQueue (queue);
      }
      ArgusDeleteQueue (model->ArgusTimeOutQueues);
      model->ArgusTimeOutQueues = NULL;
   }

   if (model->ArgusStatusQueue) {
      queue = model->ArgusStatusQueue;

#ifdef ARGUSDEBUG
      ArgusDebug (8, "ArgusModelerCleanUp(%p) ArgusProcessQueue(%p) status queue with %d records %d sent\n", model, queue, queue->count, model->ArgusTotalSends);
#endif 

      if (queue->count)
         ArgusProcessQueue (model, queue, ARGUS_SHUTDOWN);

      ArgusDeleteQueue (queue);
      model->ArgusStatusQueue = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusModelerCleanUp (%p) returning\n", model);
#endif 
}

int ArgusCmp(void *, void *, int);

int
ArgusCmp(void *p1, void *p2, int len)
{
   unsigned int *c1 = p1, *c2 = p2;
   int retn = 0, i = 0;

   for (; i < len; i++, c1++, c2++)
      if (*c1 != *c2)
         break;

   if (i != len)
      retn = c1[i] - c2[i];

   return(retn);
}


void *
ArgusCreateIPv6Flow (struct ArgusModelerStruct *model, struct ip6_hdr *ip)
{
   void *retn = NULL;
   struct ArgusSystemFlow *tflow;

   if ((ip != NULL) && STRUCTCAPTURED(model, *ip)) {
      int nxt, done = 0, i = 0;
      unsigned int *sp  = (unsigned int*) &ip->ip6_src;
      unsigned int *dp  = (unsigned int*) &ip->ip6_dst;
      unsigned short alen, sport = 0, dport = 0;
      unsigned int *rsp, *rdp;
#ifdef _LITTLE_ENDIAN
//    unsigned plen;
//    plen = ntohs(ip->ip6_plen);
#endif 

      tflow = model->ArgusThisFlow;
      rsp = (unsigned int *)&tflow->ipv6_flow.ip_src;
      rdp = (unsigned int *)&tflow->ipv6_flow.ip_dst;

      tflow->ipv6_flow.flow = 0;

      nxt = ip->ip6_nxt;
      model->ArgusThisIpHdr = ip;

      alen = sizeof(ip->ip6_src)/sizeof(int);
      if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
         while ((i < alen) && (*dp == *sp)) {    /* copy while they are equal */
            *rsp++ = *sp++;                     /* leave pointers where they are not */
            *rdp++ = *dp++;
            i++;
         }
         if (i < alen) {
            if (ntohl(*sp) < ntohl(*dp)) {
               unsigned int *tmp = rdp;
               rdp = rsp;
               rsp = tmp;
               model->state |= ARGUS_DIRECTION;
            }
            while (i < alen) {
               *rsp++ = *sp++;
               *rdp++ = *dp++;
               i++;
            }
         }
      } else {
         for (i = 0; i < alen; i++) {
            *rsp++ = *sp++;
            *rdp++ = *dp++;
         }
      }

      model->ArgusThisIpv6Frag = NULL;
      model->ArgusThisLength -= sizeof(*ip);
      model->ArgusSnapLength -= sizeof(*ip);

      model->ArgusThisUpHdr = (unsigned char *)(ip + 1);
      ip++;
       
      while (!done) {
         switch (nxt) {
            case IPPROTO_FRAGMENT: {
               int offset = ((((struct ip6_hbh *)ip)->ip6h_len + 1) << 3);
               struct ip6_frag *tfrag = (struct ip6_frag *) ip;

               model->ArgusThisIpv6Frag = tfrag;
               nxt = *(char *)ip;

               if ((ntohs(tfrag->ip6f_offlg & IP6F_OFF_MASK)) != 0)
                  done++;

               ip = (struct ip6_hdr *)((char *)ip + offset);
               model->ArgusThisLength -= offset;
               model->ArgusSnapLength -= offset;
               model->ArgusThisUpHdr  += offset;
               break;
            }

            case IPPROTO_HOPOPTS:
            case IPPROTO_DSTOPTS:
            case IPPROTO_ROUTING: {
               int offset = ((((struct ip6_hbh *)ip)->ip6h_len + 1) << 3);
               nxt = *(char *)ip;
               ip = (struct ip6_hdr *)((char *)ip + offset);
               model->ArgusThisLength -= offset;
               model->ArgusSnapLength -= offset;
               model->ArgusThisUpHdr  += offset;
               break;
            }

            default:
               done++;
               break;
         }
      }

      tflow->hdr.type       = ARGUS_FLOW_DSR;
      retn = tflow;

      if (model->ArgusFlowKey & ARGUS_FLOW_KEY_CLASSIC5TUPLE) {
         tflow->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
         tflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
         tflow->hdr.argus_dsrvl8.len  = 11;
         tflow->ipv6_flow.ip_p       = nxt;

         if ((model->ArgusThisIpv6Frag) && ((ntohs(model->ArgusThisIpv6Frag->ip6f_offlg & IP6F_OFF_MASK)) != 0)) {
            tflow->fragv6_flow.ip_id = model->ArgusThisIpv6Frag->ip6f_ident;
            tflow->hdr.argus_dsrvl8.qual |= ARGUS_FRAGMENT;
         } else {
            if (nxt == IPPROTO_AH) {
               struct AHHeader *ah = (struct AHHeader *) model->ArgusThisUpHdr;

               model->ArgusThisEncaps |= ARGUS_ENCAPS_AH;

               if (STRUCTCAPTURED(model, *ah)) {
                  nxt = ah->nxt;
                  model->ArgusThisUpHdr = (unsigned char *)(ah + 1);
                  tflow->ipv6_flow.ip_p = nxt;
               }
            }

            switch (nxt) {
               case IPPROTO_TCP: {
                  struct tcphdr *tp = (struct tcphdr *) model->ArgusThisUpHdr;
                  if (model->state & ARGUS_DIRECTION) {
                     dport = ntohs(tp->th_sport);
                     sport = ntohs(tp->th_dport);
                  } else {
                     sport = ntohs(tp->th_sport);
                     dport = ntohs(tp->th_dport);
                  }
                  tflow->ipv6_flow.sport = sport;
                  tflow->ipv6_flow.dport = dport;
                  break;
               }

               case IPPROTO_UDP: {
                  struct udphdr *up = (struct udphdr *) model->ArgusThisUpHdr;
                  if (model->state & ARGUS_DIRECTION) {
                     dport = ntohs(up->uh_sport);
                     sport = ntohs(up->uh_dport);
                  } else {
                     sport = ntohs(up->uh_sport);
                     dport = ntohs(up->uh_dport);
                  }
                  tflow->ipv6_flow.sport = sport;
                  tflow->ipv6_flow.dport = dport;
                  break;
               }

               case IPPROTO_ESP:
                  retn = ArgusCreateESPv6Flow(model, ip);
                  break;

               case IPPROTO_ICMPV6:
                  retn = ArgusCreateICMPv6Flow(model, (struct icmp6_hdr *)model->ArgusThisUpHdr);
                  break;
              
               case IPPROTO_IGMP: 
                  retn = ArgusCreateIGMPv6Flow(model, (struct igmp *)model->ArgusThisUpHdr);
                  break;

               default:
                  tflow->ipv6_flow.sport = sport;
                  tflow->ipv6_flow.dport = dport;
                  break;
            }
         }

      } else {
         if (model->ArgusFlowKey & ARGUS_FLOW_KEY_LAYER_3_MATRIX) {
            tflow->hdr.subtype          = ARGUS_FLOW_LAYER_3_MATRIX;
            tflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
            tflow->hdr.argus_dsrvl8.len  = 9;
            tflow->ipv6_flow.sport = 0;
            tflow->ipv6_flow.dport = 0;
            tflow->ipv6_flow.ip_p = 0;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusCreateIPv6Flow (0x%x, 0x%x) returning %d\n", model, ip, retn);
#endif 

   return (retn);
}


void *
ArgusCreateIPv4Flow (struct ArgusModelerStruct *model, struct ip *ip)
{
   void *retn = model->ArgusThisFlow;
   unsigned char *nxtHdr = (unsigned char *)((char *)ip + (ip->ip_hl << 2));
   struct ip tipbuf, *tip = &tipbuf;
   arg_uint16 sport = 0, dport = 0;
   arg_uint8  proto, tp_p = 0;
   arg_uint32 len;
   int hlen, ArgusOptionLen;

   if ((ip != NULL) && STRUCTCAPTURED(model, *ip)) {
      model->ArgusThisIpHdr = ip;
 
#ifdef _LITTLE_ENDIAN
      bzero(tip, sizeof(*tip));
      tip->ip_len = ntohs(ip->ip_len);
      tip->ip_id  = ntohs(ip->ip_id);
      tip->ip_v   = ip->ip_v;
      tip->ip_hl  = ip->ip_hl;
      tip->ip_off = ntohs(ip->ip_off);
      tip->ip_src.s_addr =  ntohl(ip->ip_src.s_addr);
      tip->ip_dst.s_addr =  ntohl(ip->ip_dst.s_addr);
#else
      tip = ip;
#endif 
   
      hlen = tip->ip_hl << 2;
      len = (tip->ip_len - hlen);

      model->ArgusOptionIndicator = '\0';
      if ((ArgusOptionLen = (hlen - sizeof (struct ip))) > 0)
         model->ArgusOptionIndicator = ArgusParseIPOptions ((unsigned char *) (ip + 1), ArgusOptionLen);
      else
         model->ArgusOptionIndicator = 0;

      model->ArgusThisLength  = len;
      model->ArgusSnapLength -= hlen;

      if (model->ArgusFlowKey & ARGUS_FLOW_KEY_CLASSIC5TUPLE) {
         bzero ((char *)model->ArgusThisFlow, sizeof(*model->ArgusThisFlow));
         model->ArgusThisFlow->hdr.type             = ARGUS_FLOW_DSR;
         model->ArgusThisFlow->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
         model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
         model->ArgusThisFlow->hdr.argus_dsrvl8.len  = 5;

         proto = ip->ip_p;

         if (!(tip->ip_off & 0x1fff)) {
            if (proto == IPPROTO_AH) {
               struct AHHeader *ah = (struct AHHeader *) nxtHdr;

               model->ArgusThisEncaps |= ARGUS_ENCAPS_AH;

               if (STRUCTCAPTURED(model, *ah)) {
                  proto = ah->nxt;
                  nxtHdr = (unsigned char *)(ah + 1);
               }
            }

            model->ArgusThisUpHdr = nxtHdr;

            switch (proto) {
               case IPPROTO_ESP:
                  retn = ArgusCreateESPFlow (model, ip);
                  return (retn);
 
               case IPPROTO_ICMP:
                  retn = ArgusCreateICMPFlow (model, ip);
                  return (retn);
 
               case IPPROTO_IGMP:
                  retn = ArgusCreateIGMPFlow (model, ip);
                  return (retn);

               case IPPROTO_TCP: {
                  model->ArgusThisFlow->ip_flow.smask = 0;
                  model->ArgusThisFlow->ip_flow.dmask = 0;
                  if (len >= sizeof (struct tcphdr)) {
                     struct tcphdr *tp = (struct tcphdr *) nxtHdr;
                     if (BYTESCAPTURED(model, *tp, 4)) {
                        sport = ntohs(tp->th_sport);
                        dport = ntohs(tp->th_dport);
                     }
                  }
                  break;
               } 
               case IPPROTO_UDP: {
                  model->ArgusThisFlow->ip_flow.smask = 0;
                  model->ArgusThisFlow->ip_flow.dmask = 0;
                  if (len >= sizeof (struct udphdr)) {
                     struct udphdr *up = (struct udphdr *) nxtHdr;
                     if (BYTESCAPTURED(model, *up, 4)) {
                        sport = ntohs(up->uh_sport);
                        dport = ntohs(up->uh_dport);
                     }
                     if ((sport == 53) || (dport == 53)) {
                        unsigned short pad = ntohs(*(u_int16_t *)(up + 1));
                        bcopy(&pad, &model->ArgusThisFlow->ip_flow.smask, 2);
                     }
                  }
                  break;
               }

               default:
                  break;
            }

            if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL)
               if ((tip->ip_src.s_addr > tip->ip_dst.s_addr) ||
                   ((tip->ip_src.s_addr == tip->ip_dst.s_addr) &&
                    sport > dport))
                  model->state |= ARGUS_DIRECTION;

            if (model->state & ARGUS_DIRECTION) {
               model->ArgusThisFlow->hdr.subtype     |= ARGUS_REVERSE;
               model->ArgusThisFlow->ip_flow.ip_src   = tip->ip_dst.s_addr;
               model->ArgusThisFlow->ip_flow.ip_dst   = tip->ip_src.s_addr;
                  model->ArgusThisFlow->ip_flow.sport = dport;
               model->ArgusThisFlow->ip_flow.dport    = sport;
            } else {
               model->ArgusThisFlow->ip_flow.ip_src   = tip->ip_src.s_addr;
               model->ArgusThisFlow->ip_flow.ip_dst   = tip->ip_dst.s_addr;
               model->ArgusThisFlow->ip_flow.sport    = sport;
               model->ArgusThisFlow->ip_flow.dport    = dport;
            }

            model->ArgusThisFlow->ip_flow.ip_p        = proto;
            model->ArgusThisFlow->ip_flow.tp_p        = tp_p;

         } else {
            if (model->ArgusFlowType == ARGUS_BIDIRECTIONAL) {
               if (tip->ip_src.s_addr > tip->ip_dst.s_addr) {
                  model->state |= ARGUS_DIRECTION;
                  model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_DIRECTION;
                  model->ArgusThisFlow->hdr.subtype           |= ARGUS_REVERSE;
               }
            }

            model->ArgusThisFlow->hdr.argus_dsrvl8.qual |= ARGUS_FRAGMENT;

            if (model->state & ARGUS_DIRECTION) {
               model->ArgusThisFlow->frag_flow.ip_dst = tip->ip_src.s_addr;
               model->ArgusThisFlow->frag_flow.ip_src = tip->ip_dst.s_addr;
            } else {
               model->ArgusThisFlow->frag_flow.ip_src = tip->ip_src.s_addr;
               model->ArgusThisFlow->frag_flow.ip_dst = tip->ip_dst.s_addr;
            }
            model->ArgusThisFlow->frag_flow.ip_p      = proto;
            model->ArgusThisFlow->frag_flow.ip_id     = tip->ip_id;
         }

      } else {
         if (model->ArgusFlowKey & ARGUS_FLOW_KEY_LAYER_3_MATRIX) {
            model->ArgusThisFlow->hdr.type             = ARGUS_FLOW_DSR;
            model->ArgusThisFlow->hdr.subtype          = ARGUS_FLOW_LAYER_3_MATRIX;
            model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
            model->ArgusThisFlow->hdr.argus_dsrvl8.len  = 3;

            switch (model->ArgusFlowType) {
               case ARGUS_UNIDIRECTIONAL:
                  break;
               case ARGUS_BIDIRECTIONAL: {
                  if (tip->ip_src.s_addr > tip->ip_dst.s_addr)
                     model->state |= ARGUS_DIRECTION;
                  break;
               }
            }

            if (model->state & ARGUS_DIRECTION) {
               model->ArgusThisFlow->ip_flow.ip_src   = tip->ip_dst.s_addr;
               model->ArgusThisFlow->ip_flow.ip_dst   = tip->ip_src.s_addr;
            } else {
               model->ArgusThisFlow->ip_flow.ip_src   = tip->ip_src.s_addr;
               model->ArgusThisFlow->ip_flow.ip_dst   = tip->ip_dst.s_addr;
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "ArgusCreateIPv4Flow (0x%x, 0x%x) returning 0x%x\n", model, ip, retn);
#endif 

   return (retn);
}

#if !defined(IPOPT_RA)
#define IPOPT_RA	148
#endif

unsigned short
ArgusParseIPOptions (unsigned char *ptr, int len)
{
   unsigned short retn = 0;
   int offset = 0;

   for (; len > 0; ptr += offset, len -= offset) {
      switch (*ptr) {
         case IPOPT_EOL:      break;
         case IPOPT_NOP:      break;
         case IPOPT_RA:       retn |= ARGUS_RTRALERT; break;
         case IPOPT_TS:       retn |= ARGUS_TIMESTAMP; break;
         case IPOPT_RR:       retn |= ARGUS_RECORDROUTE; break;
         case IPOPT_SECURITY: retn |= ARGUS_SECURITY; break;
         case IPOPT_LSRR:     retn |= ARGUS_LSRCROUTE; break;
         case IPOPT_SSRR:     retn |= ARGUS_SSRCROUTE; break;
         case IPOPT_SATID:    retn |= ARGUS_SATID; break;
         default:             break;
      }

      if ((*ptr == IPOPT_EOL) || (*ptr == IPOPT_NOP))
         offset = 1;
      else {
         offset = ptr[1];
         if (!(offset && (offset <= len)))
            break;
      }
   }

   return (retn);
}

void
setArgusIpTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusIPTimeout = value;
   }
}

void
setArgusTcpTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusTCPTimeout = value;
   }
}

void
setArgusIcmpTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusICMPTimeout = value;
   }
}

void
setArgusIgmpTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusIGMPTimeout = value;
   }
}

void
setArgusFragTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusFRAGTimeout = value;
   }
}

void
setArgusArpTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusARPTimeout = value;
   }
}

void
setArgusOtherTimeout (struct ArgusModelerStruct *model, int value)
{
   if (model != NULL) {
      model->ArgusOtherTimeout = value;
   }
}

int
getArgusmflag (struct ArgusModelerStruct *model)
{
   return(model->Argusmflag);
}


void
setArgusFlowType (struct ArgusModelerStruct *model, int value)
{
   model->ArgusFlowType = value;
}

void
setArgusFlowKey (struct ArgusModelerStruct *model, int value)
{
   model->ArgusFlowKey |= value;
}

void
setArgusSynchronize (struct ArgusModelerStruct *model, int value)
{
   model->ArgusSelfSynchronize = value;
}


void
setArgusmflag (struct ArgusModelerStruct *model, int value)
{
   model->Argusmflag = value;
}

int
getArgusGenerateTime(struct ArgusModelerStruct *model)
{
   return (model->ArgusGenerateTime);
}

void
setArgusGenerateTime(struct ArgusModelerStruct *model, int value)
{
   model->ArgusGenerateTime = value;
}

int
getArgusGeneratePacketSize(struct ArgusModelerStruct *model)
{
   return (model->ArgusGeneratePacketSize);
}

void
setArgusGeneratePacketSize(struct ArgusModelerStruct *model, int value)
{
   model->ArgusGeneratePacketSize = value;
}

int
getArgusKeystroke(struct ArgusModelerStruct *model)
{
   return (model->ArgusKeyStroke.status);
}

void
setArgusKeystroke(struct ArgusModelerStruct *model, int value)
{
   model->ArgusKeyStroke.status = value;
}

#if !defined(HAVE_STRTOF) && !defined(CYGWIN)
float strtof (char *, char **);
#endif


void
setArgusKeystrokeVariable(struct ArgusModelerStruct *model, char *kstok)
{
   float fval = 0;
   long ival = 0;
   char *tptr;

   if (!(strncasecmp(kstok, "DC_MIN=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.dc_min = ival;
   } else
   if (!(strncasecmp(kstok, "DC_MAX=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.dc_max = ival;
   } else
   if (!(strncasecmp(kstok, "GS_MAX=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.gs_max = ival;
   } else
   if (!(strncasecmp(kstok, "DS_MIN=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.ds_min = ival;
   } else
   if (!(strncasecmp(kstok, "DS_MAX=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.ds_max = ival;
   } else
   if (!(strncasecmp(kstok, "IC_MIN=", 6))) {
      ival = strtol(&kstok[7], (char **)&tptr, 10);
      model->ArgusKeyStroke.ic_min = ival;
   } else
   if (!(strncasecmp(kstok, "LCS_MAX=", 7))) {
      ival = strtol(&kstok[8], (char **)&tptr, 10);
      model->ArgusKeyStroke.lcs_max = ival;
   } else
   if (!(strncasecmp(kstok, "GPC_MAX=", 7))) {
      ival = strtol(&kstok[8], (char **)&tptr, 10);
      model->ArgusKeyStroke.gpc_max = ival;
   } else
   if (!(strncasecmp(kstok, "ICR_MIN=", 7))) {
      fval = strtof(&kstok[8], (char **)&tptr);
      model->ArgusKeyStroke.icr_min = fval;
   } else
   if (!(strncasecmp(kstok, "ICR_MAX=", 7))) {
      fval = strtof(&kstok[8], (char **)&tptr);
      model->ArgusKeyStroke.icr_max = fval;
   }

}

int
getArgusTunnelDiscovery (struct ArgusModelerStruct *model)
{
   return(model->ArgusTunnelDiscovery);
}

void
setArgusTunnelDiscovery (struct ArgusModelerStruct *model, int value)
{
   model->ArgusTunnelDiscovery = value;
}

int
getArgusTrackDuplicates (struct ArgusModelerStruct *model)
{
   return(model->ArgusTrackDuplicates);
}

void
setArgusTrackDuplicates (struct ArgusModelerStruct *model, int value)
{
   model->ArgusTrackDuplicates = value;
}

int
getArgusUserDataLen (struct ArgusModelerStruct *model)
{
   return (model->ArgusUserDataLen);
}

void
setArgusUserDataLen (struct ArgusModelerStruct *model, int value)
{
   model->ArgusUserDataLen = value;
}

int
getArgusMajorVersion(struct ArgusModelerStruct *model) {
   return (model->ArgusMajorVersion);
}

void
setArgusMajorVersion(struct ArgusModelerStruct *model, int value)
{
   model->ArgusMajorVersion = value;
}

int
getArgusMinorVersion(struct ArgusModelerStruct *model) {
   return (model->ArgusMinorVersion);
}

void
setArgusMinorVersion(struct ArgusModelerStruct *model, int value)
{
   model->ArgusMinorVersion = value;
}

struct timeval *
getArgusFarReportInterval(struct ArgusModelerStruct *model) {
   return (&model->ArgusFarReportInterval);
}

unsigned int
getArgusLocalNet(struct ArgusModelerStruct *model) {
   return (model->ArgusLocalNet);
}

unsigned int
getArgusNetMask(struct ArgusModelerStruct *model) {
   return (model->ArgusNetMask);
}

void
setArgusLocalNet(struct ArgusModelerStruct *model, unsigned int value)
{
   model->ArgusLocalNet = value;
}

int
getArgusResponseStatus(struct ArgusModelerStruct *model) {
   return (model->ArgusResponseStatus);
}
 
void
setArgusResponseStatus(struct ArgusModelerStruct *model, int value)
{
   model->ArgusResponseStatus = value;
}

int
getArgusIpTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusIPTimeout);
}

int
getArgusTcpTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusTCPTimeout);
}

int
getArgusIcmpTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusICMPTimeout);
}

int
getArgusIgmpTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusIGMPTimeout);
}

int
getArgusFragTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusFRAGTimeout);
}

int
getArgusArpTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusFRAGTimeout);
}

int
getArgusOtherTimeout(struct ArgusModelerStruct *model) {
   return (model->ArgusFRAGTimeout);
}



struct timeval *
getArgusQueueInterval(struct ArgusModelerStruct *model) {
   return (&model->ArgusQueueInterval);
}

struct timeval *
getArgusListenInterval(struct ArgusModelerStruct *model) {
   return (&model->ArgusListenInterval);
}


#include <string.h>
#include <ctype.h>
#include <math.h>

void
setArgusFarReportInterval (struct ArgusModelerStruct *model, char *value)
{
   float fvalue;
   char *ptr;
   int i = *value;

   if (((ptr = strchr(value, '.')) != NULL) || isdigit(i)) {
      int ivalue = 0;

      if (ptr != NULL) {
         fvalue = atof(value);
         model->ArgusFarReportInterval.tv_sec  = floorf(fvalue);
         model->ArgusFarReportInterval.tv_usec = fabs(remainderf(fvalue, 1.0) * 1000000);

      } else {
         if (isdigit(i)) {
            ivalue = atoi(value);
            model->ArgusFarReportInterval.tv_sec = ivalue;
         }
      }
   }
}

int
getArgusAflag (struct ArgusModelerStruct *model)
{
   return (model->ArgusAflag);
}

void
setArgusAflag(struct ArgusModelerStruct *model, int value)
{
   model->ArgusAflag = value;
}

int
getArgusTCPflag(struct ArgusModelerStruct *model) {
   return (model->ArgusTCPflag);
}

void
setArgusTCPflag(struct ArgusModelerStruct *model, int value)
{
   model->ArgusTCPflag = value;
}


int
getArgusdflag(struct ArgusModelerStruct *model) {
   return (Argusdflag);
}

void
setArgusdflag(struct ArgusModelerStruct *model, int value)
{
   if (Argusdflag && !(value)) {
   }
 
   if (value) {
   }
 
   Argusdflag = value;
}

void
setArgusLink(struct ArgusModelerStruct *model, unsigned int value)
{
   model->ArgusLink = value;
}

void
setArgusNetMask(struct ArgusModelerStruct *model, unsigned int value)
{
   model->ArgusNetMask = value;
}

void
setArgusTimeReport(struct ArgusModelerStruct *model, int value)
{
   model->ArgusReportAllTime = value;
}

