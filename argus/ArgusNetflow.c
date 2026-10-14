/*
 * Argus-5.0 Software.  Argus files - Netflow processing
 * Copyright (c) 2000-2024 QoSient, LLC
 * All rights reserved.
 *
 * This program is free software, released under the GNU General
 * Public License; you can redistribute it and/or modify it under the terms
 * of the GNU General Public License as published by the Free Software
 * Foundation; either version 3, or any later version.
 *
 * Other licenses are available through QoSient, LLC.
 * Inquire at info@qosient.com.
 *
 * This program is distributed WITHOUT ANY WARRANTY; without even the
 * implied warranty of * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 * See the * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.
 *
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusNetflow.c#23 $
 * $DateTime: 2011/01/26 17:21:20 $
 * $Change: 2089 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusNetflow)
#define ArgusNetflow

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <math.h>

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusUtil.h>
#include <ArgusNetflow.h>

#include <arpa/inet.h>

struct ArgusCiscoHeaderContext;

static struct ArgusRecord *ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *, struct ArgusModelerStruct *, struct ArgusQueueStruct *, struct ArgusCiscoHeaderContext *, u_char *, int);
static int ArgusParseCiscoRecordV9Template (struct ArgusModelerStruct *, struct ArgusQueueStruct *, struct ArgusCiscoHeaderContext *, u_char *, int);
static int ArgusParseCiscoRecordV9OptionTemplate (struct ArgusModelerStruct *, struct ArgusQueueStruct *, u_char *, int);

#define ARGUS_CISCO_TEMPLATE_HASH_SIZE 257

struct ArgusCiscoTemplateStruct {
   struct ArgusCiscoTemplateStruct *next;
   struct ArgusCiscoTemplateStruct *hash_next;
   uint16_t template_id;
   int length, count;
   size_t record_length;
   struct timeval lasttime;
   CiscoFlowTemplateHeaderV9_t *tHdr;
};

struct ArgusCiscoSourceStruct {
   struct ArgusQueueHeader qhdr;
   uint32_t srcid;
   unsigned char address_type;
   unsigned char saddr[16];
    struct timeval startime, lasttime;
    struct ArgusCiscoTemplateStruct *templates;
   struct ArgusCiscoTemplateStruct *template_hash[ARGUS_CISCO_TEMPLATE_HASH_SIZE];
};

struct ArgusCiscoTemplateUpdate {
   struct ArgusCiscoTemplateUpdate *next;
   uint16_t template_id;
   int length, count;
   size_t record_length;
   CiscoFlowTemplateHeaderV9_t *tHdr;
};

struct ArgusCiscoHeaderContext {
   int counter;
   unsigned int data_flowsets;
   unsigned int data_records;
   unsigned int template_updates;
   uint32_t flow_sequence;
   uint32_t source_id;
   uint32_t sys_uptime;
   unsigned char source_address_type;
   unsigned char source_address[16];
   struct ArgusCiscoSourceStruct *source;
   struct timeval export_time;
};

#define ARGUS_TEMPLATE_TIMEOUT 1800
#ifndef ARGUS_CISCO_TEMPLATE_SOURCE_MAX
#define ARGUS_CISCO_TEMPLATE_SOURCE_MAX 256
#endif
#ifndef ARGUS_CISCO_TEMPLATE_MAX
#define ARGUS_CISCO_TEMPLATE_MAX 1024
#endif
#ifndef ARGUS_CISCO_TEMPLATE_FLOWSET_MAX
#define ARGUS_CISCO_TEMPLATE_FLOWSET_MAX 128
#endif
#ifndef ARGUS_CISCO_TEMPLATE_DATAGRAM_MAX
#define ARGUS_CISCO_TEMPLATE_DATAGRAM_MAX ARGUS_CISCO_TEMPLATE_FLOWSET_MAX
#endif
#ifndef ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX
#define ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX 1024
#endif
#ifndef ARGUS_CISCO_DATA_RECORD_DATAGRAM_MAX
#define ARGUS_CISCO_DATA_RECORD_DATAGRAM_MAX ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX
#endif
#ifndef ARGUS_CISCO_DATA_FLOWSET_DATAGRAM_MAX
#define ARGUS_CISCO_DATA_FLOWSET_DATAGRAM_MAX 128
#endif
#define ARGUS_CISCO_V9_RECORD_MAX (UINT16_MAX - sizeof(CiscoFlowEntryV9_t))
#ifndef ARGUS_CISCO_TEMPLATE_CACHE_BYTES_MAX
#define ARGUS_CISCO_TEMPLATE_CACHE_BYTES_MAX (16U * 1024U * 1024U)
#endif
#define ARGUS_CISCO_TEMPLATE_CACHE_LIMIT_LOGGED 0x40000000
#define ARGUS_CISCO_DATA_RECORD_LIMIT_LOGGED 0x20000000
#define ARGUS_CISCO_DATA_FLOWSET_LIMIT_LOGGED 0x10000000

static int
ArgusNetflowHasBytes(const u_char *ptr, const u_char *end, size_t length)
{
   return (ptr != NULL && end != NULL && ptr <= end &&
           length <= (size_t)(end - ptr));
}

static uint16_t
ArgusNetflowGet16(const u_char *ptr)
{
   uint16_t value;

   memcpy(&value, ptr, sizeof(value));
   return ntohs(value);
}

static uint32_t
ArgusNetflowGet32(const u_char *ptr)
{
   uint32_t value;

   memcpy(&value, ptr, sizeof(value));
   return ntohl(value);
}

static uint64_t
ArgusNetflowGet64(const u_char *ptr)
{
   return ((uint64_t)ArgusNetflowGet32(ptr) << 32) |
           ArgusNetflowGet32(ptr + sizeof(uint32_t));
}

static size_t
ArgusCiscoAddressLength(unsigned char address_type)
{
   switch (address_type) {
      case ARGUS_TYPE_IPV4:
         return sizeof(uint32_t);
      case ARGUS_TYPE_IPV6:
         return 16;
      default:
         return 0;
   }
}

static void
ArgusSetCiscoExporter(struct ArgusCiscoHeaderContext *context,
                      const struct ArgusModelerStruct *model)
{
   const struct ArgusSystemFlow *flow;
   int reverse;

   if (context == NULL)
      return;

   context->source_address_type = 0;
   bzero(context->source_address, sizeof(context->source_address));
   if (model == NULL || (flow = model->ArgusThisFlow) == NULL)
      return;

   reverse = (flow->hdr.subtype & ARGUS_REVERSE) != 0;
   switch (flow->hdr.argus_dsrvl8.qual) {
      case ARGUS_TYPE_IPV4:
         context->source_address_type = ARGUS_TYPE_IPV4;
         bcopy(reverse ? &flow->ip_flow.ip_dst : &flow->ip_flow.ip_src,
               context->source_address, sizeof(flow->ip_flow.ip_src));
         break;
      case ARGUS_TYPE_IPV6:
         context->source_address_type = ARGUS_TYPE_IPV6;
         bcopy(reverse ? flow->ipv6_flow.ip_dst : flow->ipv6_flow.ip_src,
               context->source_address, sizeof(flow->ipv6_flow.ip_src));
         break;
   }
}

static int
ArgusCiscoSourceMatches(const struct ArgusCiscoSourceStruct *src,
                        const struct ArgusCiscoHeaderContext *context)
{
   size_t address_length;

   if (src == NULL || context == NULL || src->srcid != context->source_id ||
       src->address_type != context->source_address_type)
      return 0;

   address_length = ArgusCiscoAddressLength(src->address_type);
   return address_length == 0 ||
          memcmp(src->saddr, context->source_address, address_length) == 0;
}

static struct ArgusCiscoSourceStruct *
ArgusFindCiscoSource(struct ArgusQueueStruct *tqueue,
                     const struct ArgusCiscoHeaderContext *context)
{
   struct ArgusCiscoSourceStruct *retn = NULL;
   int i, count;

   if (tqueue == NULL || context == NULL)
      return(retn);

   count = tqueue->count;
   for (i = 0; i < count; i++) {
      struct ArgusCiscoSourceStruct *src =
         (struct ArgusCiscoSourceStruct *)ArgusPopQueue(tqueue, ARGUS_LOCK);

      if (src == NULL)
         break;
       if (ArgusCiscoSourceMatches(src, context))
          retn = src;
      ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
      if (retn != NULL)
         break;
   }

   return(retn);
}

static struct ArgusCiscoTemplateStruct *
ArgusFindCiscoTemplate(struct ArgusCiscoSourceStruct *src, uint16_t template_id)
{
   struct ArgusCiscoTemplateStruct *template;

   if (src == NULL)
      return NULL;

   for (template = src->template_hash[template_id % ARGUS_CISCO_TEMPLATE_HASH_SIZE];
        template != NULL; template = template->hash_next) {
      if (template->template_id == template_id)
         return template;
   }

   return NULL;
}

static void
ArgusUnlinkCiscoTemplateHash(struct ArgusCiscoSourceStruct *src,
                             struct ArgusCiscoTemplateStruct *old)
{
   struct ArgusCiscoTemplateStruct **template;

   if (src == NULL || old == NULL)
      return;

   for (template = &src->template_hash[old->template_id % ARGUS_CISCO_TEMPLATE_HASH_SIZE];
        *template != NULL; template = &(*template)->hash_next) {
      if (*template == old) {
         *template = old->hash_next;
         return;
      }
   }
}

static void
ArgusRemoveCiscoTemplate(struct ArgusCiscoSourceStruct *src, uint16_t template_id)
{
   struct ArgusCiscoTemplateStruct **template;
   struct ArgusCiscoTemplateStruct *old;

   if (src == NULL)
      return;

   old = ArgusFindCiscoTemplate(src, template_id);
   if (old == NULL)
      return;

   for (template = &src->templates; *template != NULL; template = &(*template)->next) {
      if (*template == old) {
         *template = old->next;
         break;
      }
   }
   ArgusUnlinkCiscoTemplateHash(src, old);
   if (old->tHdr != NULL)
      ArgusFree(old->tHdr);
   ArgusFree(old);
}

static void
ArgusFreeCiscoSource(struct ArgusCiscoSourceStruct *src)
{
   if (src == NULL)
      return;

   while (src->templates != NULL) {
      struct ArgusCiscoTemplateStruct *template = src->templates;

      src->templates = template->next;
      if (template->tHdr != NULL)
         ArgusFree(template->tHdr);
      ArgusFree(template);
   }
   ArgusFree(src);
}

static void
ArgusExpireCiscoTemplateCache(struct ArgusQueueStruct *tqueue, const struct timeval *now)
{
   int i, count;

   if (tqueue == NULL || now == NULL)
      return;

   count = tqueue->count;
   for (i = 0; i < count; i++) {
      struct ArgusCiscoSourceStruct *src =
         (struct ArgusCiscoSourceStruct *)ArgusPopQueue(tqueue, ARGUS_LOCK);

      if (src == NULL)
         break;
      {
         struct ArgusCiscoTemplateStruct **template = &src->templates;

         while (*template != NULL) {
            if (now->tv_sec >= (*template)->lasttime.tv_sec &&
                (now->tv_sec - (*template)->lasttime.tv_sec) >= ARGUS_TEMPLATE_TIMEOUT) {
                struct ArgusCiscoTemplateStruct *old = *template;

                *template = old->next;
                ArgusUnlinkCiscoTemplateHash(src, old);
                if (old->tHdr != NULL)
                  ArgusFree(old->tHdr);
               ArgusFree(old);
            } else
               template = &(*template)->next;
         }
      }
      if (src->templates == NULL)
         ArgusFreeCiscoSource(src);
      else
         ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
   }
}

static void
ArgusCiscoTemplateCacheUsage(struct ArgusQueueStruct *tqueue, size_t *bytes, unsigned int *templates)
{
   int i, count;

   if (bytes != NULL)
      *bytes = 0;
   if (templates != NULL)
      *templates = 0;
   if (tqueue == NULL || bytes == NULL || templates == NULL)
      return;

   count = tqueue->count;
   for (i = 0; i < count; i++) {
      struct ArgusCiscoSourceStruct *src =
         (struct ArgusCiscoSourceStruct *)ArgusPopQueue(tqueue, ARGUS_LOCK);
      struct ArgusCiscoTemplateStruct *template;

      if (src == NULL)
         break;
      for (template = src->templates; template != NULL; template = template->next) {
         if (template->length > 0) {
            if ((size_t)template->length > (size_t)-1 - *bytes)
               *bytes = (size_t)-1;
            else
               *bytes += template->length;
         }
         if (*templates != (unsigned int)-1)
            (*templates)++;
      }
      ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK);
   }
}

static int
ArgusCiscoTemplateUpdateHasLater(const struct ArgusCiscoTemplateUpdate *update)
{
   const struct ArgusCiscoTemplateUpdate *next;

   if (update == NULL)
      return 0;

   for (next = update->next; next != NULL; next = next->next) {
      if (next->template_id == update->template_id)
         return 1;
   }

   return 0;
}

static void
ArgusLogCiscoTemplateCacheLimit(struct ArgusQueueStruct *tqueue)
{
   if (tqueue != NULL && !(tqueue->status & ARGUS_CISCO_TEMPLATE_CACHE_LIMIT_LOGGED)) {
      ArgusLog(LOG_WARNING,
         "Argus NetFlow v9 template cache limit reached (sources=%u templates=%u bytes=%zu); rejecting new templates\n",
         (unsigned int)ARGUS_CISCO_TEMPLATE_SOURCE_MAX,
         (unsigned int)ARGUS_CISCO_TEMPLATE_MAX,
         (size_t)ARGUS_CISCO_TEMPLATE_CACHE_BYTES_MAX);
      tqueue->status |= ARGUS_CISCO_TEMPLATE_CACHE_LIMIT_LOGGED;
   }
}

static void
ArgusLogCiscoDataRecordLimit(struct ArgusQueueStruct *tqueue)
{
   if (tqueue != NULL && !(tqueue->status & ARGUS_CISCO_DATA_RECORD_LIMIT_LOGGED)) {
      ArgusLog(LOG_WARNING,
         "Argus NetFlow v9 data record limit reached (flowset=%u datagram=%u); skipping remaining records\n",
         (unsigned int)ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX,
         (unsigned int)ARGUS_CISCO_DATA_RECORD_DATAGRAM_MAX);
      tqueue->status |= ARGUS_CISCO_DATA_RECORD_LIMIT_LOGGED;
   }
}

static void
ArgusLogCiscoDataFlowsetLimit(struct ArgusQueueStruct *tqueue)
{
   if (tqueue != NULL && !(tqueue->status & ARGUS_CISCO_DATA_FLOWSET_LIMIT_LOGGED)) {
      ArgusLog(LOG_WARNING,
         "Argus NetFlow v9 data FlowSet limit reached (datagram=%u); skipping remaining FlowSets\n",
         (unsigned int)ARGUS_CISCO_DATA_FLOWSET_DATAGRAM_MAX);
      tqueue->status |= ARGUS_CISCO_DATA_FLOWSET_LIMIT_LOGGED;
   }
}

static void
ArgusFreeCiscoTemplateUpdates(struct ArgusCiscoTemplateUpdate *updates)
{
   while (updates != NULL) {
      struct ArgusCiscoTemplateUpdate *next = updates->next;

      if (updates->tHdr != NULL)
         ArgusFree(updates->tHdr);
      ArgusFree(updates);
      updates = next;
   }
}

void
ArgusDeleteCiscoTemplateCache(struct ArgusModelerStruct *model)
{
   struct ArgusQueueStruct *tqueue;
   struct ArgusCiscoSourceStruct *src;

   if (model == NULL || (tqueue = model->ArgusCiscoTemplateQueue) == NULL)
      return;

   while ((src = (struct ArgusCiscoSourceStruct *)ArgusPopQueue(tqueue, ARGUS_LOCK)) != NULL)
      ArgusFreeCiscoSource(src);
   ArgusDeleteQueue(tqueue);
   model->ArgusCiscoTemplateQueue = NULL;
}

void
ArgusParseCiscoRecord (struct ArgusModelerStruct *model, void *input)
{
   int ArgusReadSocketState = ARGUS_READINGPREHDR;
   int ArgusReadSocketSize = 0;
   unsigned short ArgusReadCiscoVersion = 0;
   unsigned int ArgusRecordsRemaining = 0;
   size_t input_length;
   struct ArgusCiscoHeaderContext context;
   u_char *ptr = input;
   u_char *end;
// unsigned short ArgusReadSocketNum;

   if (model == NULL || ptr == NULL || model->ArgusThisSnapEnd == NULL ||
       model->ArgusThisLength < 0 || model->ArgusSnapLength < 0)
      return;

   input_length = (size_t)model->ArgusThisLength;
   if (input_length > (size_t)model->ArgusSnapLength)
      input_length = (size_t)model->ArgusSnapLength;
   if (!ArgusNetflowHasBytes(ptr, model->ArgusThisSnapEnd, input_length))
      return;
   end = ptr + input_length;

    if (ptr == end)
       return;

    bzero(&context, sizeof(context));
    if (model->ArgusCiscoTemplateQueue == NULL) {
       if ((model->ArgusCiscoTemplateQueue = ArgusNewQueue()) == NULL) {
          ArgusLog (LOG_ERR, "ArgusParseCiscoRecord () ArgusNewQueue error %s\n", strerror(errno));
          return;
       }
    }
    ArgusExpireCiscoTemplateCache(model->ArgusCiscoTemplateQueue,
                                  &model->ArgusGlobalTime);

   while (ptr < end) {
      switch (ArgusReadSocketState) {
         case ARGUS_READINGPREHDR: {
            if (!ArgusNetflowHasBytes(ptr, end, sizeof(ArgusReadCiscoVersion)))
               return;

            memcpy(&ArgusReadCiscoVersion, ptr, sizeof(ArgusReadCiscoVersion));
            ArgusReadCiscoVersion = ntohs(ArgusReadCiscoVersion);
//          ArgusReadSocketNum  = ntohs(*sptr);
            ArgusReadSocketState = ARGUS_READINGHDR;
            break;
         }

         case ARGUS_READINGHDR: {
#ifdef ARGUSDEBUG
            ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p, %p) read record header\n", model, ptr);
#endif
            switch (ArgusReadCiscoVersion) {
               case CISCO_VERSION_1: {
                  CiscoFlowHeaderV1_t header, *ArgusNetFlow = &header;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                   ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                    context.sys_uptime  = ntohl(ArgusNetFlow->sysUptime);
                    ArgusRecordsRemaining = ntohs(ArgusNetFlow->count);
                    context.counter  = ArgusRecordsRemaining;
                    context.export_time.tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                    context.export_time.tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                   if (ArgusRecordsRemaining >
                       (size_t)(end - (ptr + ArgusReadSocketSize)) / sizeof(CiscoFlowEntryV1_t))
                      return;
                   break;
               }

               case CISCO_VERSION_5: {
                  CiscoFlowHeaderV5_t header, *ArgusNetFlow = &header;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                    context.sys_uptime  = ntohl(ArgusNetFlow->sysUptime);
                    context.flow_sequence  = ntohl(ArgusNetFlow->flow_sequence);
                    ArgusRecordsRemaining = ntohs(ArgusNetFlow->count);
                    context.counter  = ArgusRecordsRemaining;
                    context.export_time.tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                    context.export_time.tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                   if (ArgusRecordsRemaining >
                       (size_t)(end - (ptr + ArgusReadSocketSize)) / sizeof(CiscoFlowEntryV5_t))
                      return;
                   break;
               }

                case CISCO_VERSION_6: {
                  CiscoFlowHeaderV6_t header, *ArgusNetFlow = &header;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                    context.sys_uptime  = ntohl(ArgusNetFlow->sysUptime);
                    context.flow_sequence  = ntohl(ArgusNetFlow->flow_sequence);
                    ArgusRecordsRemaining = ntohs(ArgusNetFlow->count);
                    context.counter  =  0;
                    context.export_time.tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                    context.export_time.tv_usec = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                   if (ArgusRecordsRemaining >
                       (size_t)(end - (ptr + ArgusReadSocketSize)) / sizeof(CiscoFlowEntryV6_t))
                      return;
                   break;
               }

               case CISCO_VERSION_7: {
                  CiscoFlowHeaderV7_t header, *ArgusNetFlow = &header;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                    context.sys_uptime  = ntohl(ArgusNetFlow->sysUptime);
                    context.flow_sequence    = ntohl(ArgusNetFlow->flow_sequence);
                    ArgusRecordsRemaining = ntohs(ArgusNetFlow->count);
                    context.counter    =  0;
                    context.export_time.tv_sec     = ntohl(ArgusNetFlow->unix_secs);
                    context.export_time.tv_usec    = ntohl(ArgusNetFlow->unix_nsecs)/1000;
                   if (ArgusRecordsRemaining >
                       (size_t)(end - (ptr + ArgusReadSocketSize)) / sizeof(CiscoFlowEntryV7_t))
                      return;
                   break;
               }

               case CISCO_VERSION_8: {
                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(CiscoFlowHeaderV8_t)))
                     return;
                  ArgusReadSocketSize = sizeof(CiscoFlowHeaderV8_t);
                  break;
               }

               case CISCO_VERSION_9: {
                  CiscoFlowHeaderV9_t header, *ArgusNetFlow = &header;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  ArgusReadSocketSize  = sizeof(*ArgusNetFlow);

                   context.sys_uptime         = ntohl(ArgusNetFlow->sysUptime);
                   context.export_time.tv_sec  = ntohl(ArgusNetFlow->unix_secs);
                   context.export_time.tv_usec = 0;
                   context.flow_sequence       = ntohl(ArgusNetFlow->package_sequence);
                   context.counter             = ntohs(ArgusNetFlow->count);
                   context.source_id           = ntohl(ArgusNetFlow->source_id);
                   context.data_flowsets       = 0;
                   context.data_records        = 0;
                   context.template_updates    = 0;
                   context.source              = NULL;
                   ArgusSetCiscoExporter(&context, model);

                  break;
               }

               default: {
#ifdef ARGUSDEBUG
                  ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p) read header\n", ptr);
#endif
                  return;
               }
            }
            ptr += ArgusReadSocketSize;
            ArgusReadSocketState = ARGUS_READINGBLOCK;
            break;
         }

          case ARGUS_READINGBLOCK: {
             struct ArgusSystemFlow flowbuf, *sflow = &flowbuf;
             struct ArgusHashStruct hbuf, *hstruct = &hbuf;
             struct ArgusFlowStruct *flow = NULL;

             if (ArgusReadCiscoVersion >= CISCO_VERSION_1 &&
                 ArgusReadCiscoVersion <= CISCO_VERSION_7 &&
                 ArgusRecordsRemaining == 0)
                return;

#ifdef ARGUSDEBUG
            ArgusDebug (7, "ArgusReadCiscoStreamSocket (%p, %p) read record complete\n", model, ptr);
#endif
            switch (ArgusReadCiscoVersion) {
               case CISCO_VERSION_1: {
                  CiscoFlowEntryV1_t entry, *ArgusNetFlow = &entry;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                      time->src.start.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.start.tv_sec  += context.export_time.tv_sec;

                      time->src.start.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.start.tv_usec += context.export_time.tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                      time->src.end.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.end.tv_sec  += context.export_time.tv_sec;

                      time->src.end.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.end.tv_usec += context.export_time.tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->flags;

                           if (ArgusNetFlow->flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->flags & TH_ACK) || (ArgusNetFlow->flags & TH_PUSH) || (ArgusNetFlow->flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusV3TransportStruct *trans = (struct ArgusV3TransportStruct *)&flow->canon.trans;
                        trans->hdr.type                      = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype                   = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual         = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len          = 3;
                        trans->srcid.a_un.ipv4               = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                                model->ArgusThisFlow->ip_flow.ip_dst :
                                                                model->ArgusThisFlow->ip_flow.ip_src ;

                         trans->seqnum                        = context.flow_sequence + context.counter++;
                        flow->dsrindex                      |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX]    = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                   ArgusRecordsRemaining--;
                   ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_5: {
                  CiscoFlowEntryV5_t entry, *ArgusNetFlow = &entry;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     int timeval, secs, usecs;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                      secs  = context.export_time.tv_sec  + ((timeval - (int)context.sys_uptime) / 1000);
                      usecs = context.export_time.tv_usec + ((timeval - (int)context.sys_uptime) % 1000) * 1000;

                     time->src.start.tv_sec  = secs;

                     if (usecs < 0) {
                        time->src.start.tv_sec--;
                        usecs += 1000000;
                     } else 
                     if (usecs > 1000000) {
                        time->src.start.tv_sec++;
                        usecs -= 1000000;
                     }
                     time->src.start.tv_usec = usecs;

                     timeval = ntohl(ArgusNetFlow->last);
                      secs  = context.export_time.tv_sec  + ((timeval - (int)context.sys_uptime) / 1000);
                      usecs = context.export_time.tv_usec + ((timeval - (int)context.sys_uptime) % 1000) * 1000;

                     time->src.end.tv_sec  = secs;

                     if (usecs < 0) {
                        time->src.end.tv_sec--;
                        usecs += 1000000;
                     } else 
                     if (usecs > 1000000) {
                        time->src.end.tv_sec++;
                        usecs -= 1000000;
                     } 
                     time->src.end.tv_usec = usecs;

                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusV3TransportStruct *trans = (struct ArgusV3TransportStruct *)&flow->canon.trans;
                        trans->hdr.type                      = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype                   = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual         = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len          = 3;
                        trans->srcid.a_un.ipv4               = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                                model->ArgusThisFlow->ip_flow.ip_dst :
                                                                model->ArgusThisFlow->ip_flow.ip_src ;

                         trans->seqnum                        = context.flow_sequence + context.counter++;
                        flow->dsrindex                      |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX]    = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                   ArgusRecordsRemaining--;
                   ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_6: {
                  CiscoFlowEntryV6_t entry, *ArgusNetFlow = &entry;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                      time->src.start.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.start.tv_sec  += context.export_time.tv_sec;

                      time->src.start.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.start.tv_usec += context.export_time.tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                      time->src.end.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.end.tv_sec  += context.export_time.tv_sec;

                      time->src.end.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.end.tv_usec += context.export_time.tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusV3TransportStruct *trans = (struct ArgusV3TransportStruct *)&flow->canon.trans;
                        trans->hdr.type                      = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype                   = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual         = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len          = 3;
                        trans->srcid.a_un.ipv4               = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                                model->ArgusThisFlow->ip_flow.ip_dst :
                                                                model->ArgusThisFlow->ip_flow.ip_src ;

                         trans->seqnum                        = context.flow_sequence + context.counter++;
                        flow->dsrindex                      |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX]    = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                   ArgusRecordsRemaining--;
                   ptr += sizeof(*ArgusNetFlow);
                  break;
               }

                case CISCO_VERSION_7: {
                  CiscoFlowEntryV7_t entry, *ArgusNetFlow = &entry;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(*ArgusNetFlow)))
                     return;
                  memcpy(ArgusNetFlow, ptr, sizeof(*ArgusNetFlow));
                  bzero(sflow, sizeof(*sflow));
                  bzero(hstruct, sizeof(*hstruct));

                  sflow->hdr.type              = ARGUS_FLOW_DSR;
                  sflow->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
                  sflow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                  sflow->hdr.argus_dsrvl8.len  = 5;
                  sflow->ip_flow.ip_src = ntohl(ArgusNetFlow->srcaddr);
                  sflow->ip_flow.ip_dst = ntohl(ArgusNetFlow->dstaddr);
 
                  sflow->ip_flow.smask = ArgusNetFlow->src_mask;
                  sflow->ip_flow.dmask = ArgusNetFlow->dst_mask;
 
                  switch (sflow->ip_flow.ip_p = ArgusNetFlow->prot) {
                     case IPPROTO_TCP:
                     case IPPROTO_UDP:
                        sflow->ip_flow.sport  = ntohs(ArgusNetFlow->srcport);
                        sflow->ip_flow.dport  = ntohs(ArgusNetFlow->dstport);
                     break;
 
                     case IPPROTO_ICMP:
                        sflow->icmp_flow.type  = ((char *)&ArgusNetFlow->dstport)[0];
                        sflow->icmp_flow.code  = ((char *)&ArgusNetFlow->dstport)[1];
                     break;
                  }

                  ArgusCreateFlowKey(model, sflow, hstruct);
                  if ((flow = ArgusNewFlow(model, sflow, NULL, NULL)) != NULL) {
                     struct ArgusTimeObject *time = &flow->canon.time;
                     long timeval;

                     flow->canon.hdr.type         = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;

                     time->hdr.type               = ARGUS_TIME_DSR;
                     time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                     time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                     time->hdr.argus_dsrvl8.len   = 5;               

                     timeval = ntohl(ArgusNetFlow->first);
                      time->src.start.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.start.tv_sec  += context.export_time.tv_sec;

                      time->src.start.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.start.tv_usec += context.export_time.tv_usec;

                     if (time->src.start.tv_usec >= 1000000) {
                        time->src.start.tv_sec++;
                        time->src.start.tv_usec -= 1000000;
                     }

                     timeval = ntohl(ArgusNetFlow->last);
                      time->src.end.tv_sec   = (timeval - (long)context.sys_uptime)/1000;
                      time->src.end.tv_sec  += context.export_time.tv_sec;

                      time->src.end.tv_usec  = ((timeval - (long)context.sys_uptime)%1000) * 1000;
                      time->src.end.tv_usec += context.export_time.tv_usec;

                     if (time->src.end.tv_usec >= 1000000) {
                        time->src.end.tv_sec++;
                        time->src.end.tv_usec -= 1000000;
                     }

                     time->src.start.tv_usec = (time->src.start.tv_usec / 1000) * 1000;
                     time->src.end.tv_usec  = (time->src.end.tv_usec / 1000) * 1000;
                     flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                     flow->dsrs[ARGUS_TIME_INDEX] = (void *)time;

                     {
                        struct ArgusAsnStruct *asn  = &flow->canon.asn;
                        asn->hdr.type               = ARGUS_ASN_DSR;
                        asn->hdr.subtype            = 0;
                        asn->hdr.argus_dsrvl8.qual  = 0;
                        asn->hdr.argus_dsrvl8.len   = 3;
                        asn->src_as                 = ArgusNetFlow->src_as;
                        asn->dst_as                 = ArgusNetFlow->dst_as;
                        flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                        flow->dsrs[ARGUS_ASN_INDEX] = (void *)asn;
                     }

                     {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;
                        metric->hdr.type              = ARGUS_METER_DSR;
                        metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                        metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                        metric->hdr.argus_dsrvl8.len  = 3;

                        metric->src.pkts  = ntohl(ArgusNetFlow->pkts);
                        metric->src.bytes = ntohl(ArgusNetFlow->bytes);
                        flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                        flow->dsrs[ARGUS_METRIC_INDEX] = (void *)metric;
                     }

                     {
                        struct ArgusMacStruct *mac = &flow->canon.mac;
                        mac->hdr.type              = ARGUS_MAC_DSR;
                        mac->hdr.subtype           = 0;
                        mac->hdr.argus_dsrvl8.len  = 5;
                        ArgusNetFlow->input = ntohs(ArgusNetFlow->input);
                        ArgusNetFlow->output = ntohs(ArgusNetFlow->output);
#if defined(HAVE_SOLARIS)
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost.ether_addr_octet[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost.ether_addr_octet[4], 2);
#else
                        bcopy((char *)&ArgusNetFlow->input, (char *)&mac->mac.mac_union.ether.ehdr.ether_shost[4], 2);
                        bcopy((char *)&ArgusNetFlow->output,(char *)&mac->mac.mac_union.ether.ehdr.ether_dhost[4], 2);
#endif
                        flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                        flow->dsrs[ARGUS_MAC_INDEX] = (void *)mac;
                     }

                     {
                        if (ArgusNetFlow->prot == IPPROTO_TCP) {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;

                           net->hdr.type              = ARGUS_NETWORK_DSR;
                           net->hdr.subtype           = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len  = 3;
                           net->net_union.tcpstatus.src = ArgusNetFlow->tcp_flags;

                           if (ArgusNetFlow->tcp_flags & TH_RST) 
                              tcp->status |= ARGUS_RESET;
          
                           if (ArgusNetFlow->tcp_flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;
          
                           if ((ArgusNetFlow->tcp_flags & TH_ACK) || (ArgusNetFlow->tcp_flags & TH_PUSH) || (ArgusNetFlow->tcp_flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;
          
                           switch (ArgusNetFlow->tcp_flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):  
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;
             
                              case (TH_SYN|TH_ACK): 
                                 tcp->status |= ARGUS_SAW_SYN_SENT;  
                                 if (ntohl(ArgusNetFlow->pkts) > 1)
                                    tcp->status &= ~(ARGUS_CON_ESTABLISHED);
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                        }
                     }
                     if (model->ArgusThisFlow && (model->ArgusThisFlow->ip_flow.ip_src != 0)) {
                        struct ArgusV3TransportStruct *trans = (struct ArgusV3TransportStruct *)&flow->canon.trans;
                        trans->hdr.type                      = ARGUS_TRANSPORT_DSR;
                        trans->hdr.subtype                   = ARGUS_SRCID | ARGUS_SEQ;
                        trans->hdr.argus_dsrvl8.qual         = ARGUS_TYPE_IPV4;
                        trans->hdr.argus_dsrvl8.len          = 3;
                        trans->srcid.a_un.ipv4               = (model->ArgusThisFlow->hdr.subtype & ARGUS_REVERSE) ?
                                                                model->ArgusThisFlow->ip_flow.ip_dst :
                                                                model->ArgusThisFlow->ip_flow.ip_src ;

                         trans->seqnum                        = context.flow_sequence + context.counter++;
                        flow->dsrindex                      |= 1 << ARGUS_TRANSPORT_INDEX;
                        flow->dsrs[ARGUS_TRANSPORT_INDEX]    = (void *)trans;
                     }
                     {
                        struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                        attr->hdr.type               = ARGUS_IPATTR_DSR;
                        attr->hdr.subtype            = 0;
                        attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                        attr->hdr.argus_dsrvl8.len   = 2;
                        attr->src.tos                = ArgusNetFlow->tos;
                        attr->src.ttl                = 0;
                        attr->src.ip_id              = 0;
                        flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                        flow->dsrs[ARGUS_IPATTR_INDEX] = (void *)attr;
                     }
                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
                  }

                   ArgusRecordsRemaining--;
                   ptr += sizeof(*ArgusNetFlow);
                  break;
               }

               case CISCO_VERSION_8: {
                  return;
               }

               case CISCO_VERSION_9: {
                  CiscoFlowEntryV9_t flowset;
                  uint16_t flowset_id, flowset_len;

                  if (!ArgusNetflowHasBytes(ptr, end, sizeof(flowset)))
                     return;
                  memcpy(&flowset, ptr, sizeof(flowset));

                  flowset_id = ntohs(flowset.flowset_id);
                  flowset_len = ntohs(flowset.length);
                  if (flowset_len < sizeof(flowset) ||
                      !ArgusNetflowHasBytes(ptr, end, flowset_len))
                     return;

                  switch (flowset_id) {
                     case k_CiscoV9TemplateFlowsetId:
                         if (!ArgusParseCiscoRecordV9Template(model, model->ArgusCiscoTemplateQueue,
                               &context, ptr + sizeof(flowset), flowset_len - sizeof(flowset)))
                           return;
                        break;

                     case k_CiscoV9OptionsFlowsetId:
                         if (!ArgusParseCiscoRecordV9OptionTemplate(model, model->ArgusCiscoTemplateQueue,
                              ptr + sizeof(flowset), flowset_len - sizeof(flowset)))
                           return;
                        break;

                     default:
                        if (flowset_id >= k_CiscoV9MinRecordFlowsetId)
                           ArgusParseCiscoRecordV9Data(ArgusParser, model,
                               model->ArgusCiscoTemplateQueue, &context, ptr, flowset_len);
                        break;
                  }

                  ptr += flowset_len;
                  break;
               }

               default:
                  return;
            }
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusParseCiscoRecord(%p, %p)", model, ptr);
#endif 
}

void
ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *model, void *ptr)
{
#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV5 (%p, %p)\n", model, ptr);
#endif
}

void
ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *model, void *ptr)
{
#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusParseCiscoRecordV6 (%p, %p)\n", model, ptr);
#endif
}


extern long long ArgusDiffTime (struct ArgusTime *, struct ArgusTime *, struct timeval *);

typedef struct value {
   union {
      uint8_t   val8[16];
      uint16_t  val16[8];
      uint32_t  val32[4];
      uint64_t  val64[2];
      uint64_t val128[2];
   };
} value_t;


static struct ArgusRecord *
ArgusParseCiscoRecordV9Data (struct ArgusParserStruct *parser, struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, struct ArgusCiscoHeaderContext *context, u_char *ptr, int len)
{
   struct ArgusRecord *retn = NULL;
   struct ArgusCiscoTemplateStruct *template = NULL;
   struct ArgusCiscoSourceStruct *src = NULL;
   int ArgusParsingIPv6 = 0;
   const u_char *end;
   uint16_t flowset_id, length;

   if (model == NULL || tqueue == NULL || context == NULL || ptr == NULL ||
       len < (int)sizeof(CiscoFlowEntryV9_t))
      return(retn);

   end = ptr + len;
   if (!ArgusNetflowHasBytes(ptr, end, sizeof(CiscoFlowEntryV9_t)))
      return(retn);

   flowset_id = ArgusNetflowGet16(ptr);
   length = ArgusNetflowGet16(ptr + sizeof(uint16_t));
   if (length < sizeof(CiscoFlowEntryV9_t) || (size_t)length > (size_t)len)
      return(retn);

   end = ptr + length;
   if (context->data_flowsets >= ARGUS_CISCO_DATA_FLOWSET_DATAGRAM_MAX) {
      ArgusLogCiscoDataFlowsetLimit(tqueue);
      return(retn);
   }
   context->data_flowsets++;

   src = context->source;
   if (src == NULL || !ArgusCiscoSourceMatches(src, context)) {
      src = ArgusFindCiscoSource(tqueue, context);
      context->source = src;
   }
   if (src == NULL)
      return(retn);
   template = ArgusFindCiscoTemplate(src, flowset_id);

//  using the matching template, parse out a single record.  we need to update ptr and
//  len so that they represent marching through the buffer, parsing out the records.
//  

   {
      CiscoFlowTemplateHeaderV9_t *tHdr = NULL;
      CiscoFlowTemplateFlowEntryV9_t *tData;

       if (template != NULL && (tHdr = template->tHdr) != NULL) {
          size_t template_len = template->length;
         size_t expected_template_len;

          if (template_len < sizeof(*tHdr) ||
              tHdr->count > ((template_len - sizeof(*tHdr)) / sizeof(*tData)))
             return(retn);

         expected_template_len = sizeof(*tHdr) +
            ((size_t)tHdr->count * sizeof(*tData));
         if (template_len != expected_template_len)
            return(retn);

          if ((template->lasttime.tv_sec + ARGUS_TEMPLATE_TIMEOUT) > model->ArgusGlobalTime.tv_sec) {
               int i, count = tHdr->count;
               unsigned int flowset_records = 0;
               size_t record_len = template->record_length;
              struct ArgusFlowStruct flowbuf, *flow = &flowbuf;
              u_char *sptr = ptr + sizeof(CiscoFlowEntryV9_t);

              if (record_len == 0 || record_len > ARGUS_CISCO_V9_RECORD_MAX ||
                  record_len > (size_t)(end - sptr))
                 return(retn);

// process an entire flow set

               while (record_len <= (size_t)(end - sptr) &&
                      flowset_records < ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX &&
                      context->data_records < ARGUS_CISCO_DATA_RECORD_DATAGRAM_MAX) {
                   unsigned char recordbuf[4098];
                   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) &recordbuf[4];
                  bzero(flow, sizeof(*flow));

                  tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);
                  retn = NULL;

                  for (i = 0; i < count; i++) {
                     value_t value;

                      bzero(&value, sizeof(value));

                      switch (tData->length) {
                        case  1: value.val8[0] = *sptr; break;
                        case  2: value.val16[0] = ArgusNetflowGet16(sptr); break;
                        case  4: value.val32[0] = ArgusNetflowGet32(sptr); break;
                        case  8: value.val64[0] = ArgusNetflowGet64(sptr); break;
                        case 16: bcopy(sptr, &value.val128, 16); break;
                      }
                     sptr += tData->length;

                     switch (tData->type) {
                        case k_CiscoV9InBytes: {
                           flow->canon.metric.src.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPackets: {
                           flow->canon.metric.src.pkts = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9Flows: {
                           break;
                        }
                        case k_CiscoV9InProtocol: {
                           flow->canon.flow.flow_un.ipv6.ip_p = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcTos: {
                           flow->canon.attr.src.tos = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9TcpFlags: {
                           struct ArgusNetworkStruct *net = &flow->canon.net;
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                           unsigned char flags =  value.val8[0];

                           net->hdr.type                = ARGUS_NETWORK_DSR;
                           net->hdr.subtype             = ARGUS_TCP_STATUS;
                           net->hdr.argus_dsrvl8.len    = 3;
                           net->net_union.tcpstatus.src = flags;

                           if (flags & TH_RST)
                              tcp->status |= ARGUS_RESET;

                           if (flags & TH_FIN)
                              tcp->status |= ARGUS_FIN;

                           if ((flags & TH_ACK) || (flags & TH_PUSH) || (flags & TH_URG))
                              tcp->status |= ARGUS_CON_ESTABLISHED;

                           switch (flags & (TH_SYN|TH_ACK)) {
                              case (TH_SYN):
                                 tcp->status |= ARGUS_SAW_SYN;
                                 break;

                              case (TH_SYN|TH_ACK):
                                 break;
                           }
                           flow->dsrindex |= 1 << ARGUS_NETWORK_INDEX;
                           flow->dsrs[ARGUS_NETWORK_INDEX] = (void *)net;
                           break;
                        }
                        case k_CiscoV9L4SrcPort: {
                           flow->canon.flow.flow_un.ipv6.sport = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4SrcAddr: {
                           flow->canon.flow.flow_un.ipv6.ip_src[0] = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMask: {
                           /* value.val8[0] is an attacker-controlled mask length (0-255) taken
                            * directly from the NetFlow v9 record. A shift amount of 32 or a
                            * negative amount (mask length > 32) is undefined behavior in C, so
                            * clamp explicitly: 0 => no mask bits, >=32 => full mask. */
                           uint32_t mask;
                           if (value.val8[0] == 0)
                              mask = 0;
                           else if (value.val8[0] >= 32)
                              mask = 0xffffffff;
                           else
                              mask = 0xffffffff << (32 - value.val8[0]);
                           flow->canon.flow.flow_un.ipv6.ip_src[3] = mask;
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9InputSnmp: {
                           break;
                        }
                        case k_CiscoV9L4DstPort: {
                           flow->canon.flow.flow_un.ipv6.dport = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV4DstAddr: {
                           flow->canon.flow.flow_un.ipv6.ip_dst[0] = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9DstMask: {
                           /* see k_CiscoV9SrcMask above for rationale */
                           uint32_t mask;
                           if (value.val8[0] == 0)
                              mask = 0;
                           else if (value.val8[0] >= 32)
                              mask = 0xffffffff;
                           else
                              mask = 0xffffffff << (32 - value.val8[0]);
                           flow->canon.flow.flow_un.ipv6.ip_dst[3] = mask;
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9OutputSnmp: {
                           break;
                        }
                        case k_CiscoV9IpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9SrcAS: {
                           flow->canon.asn.src_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           flow->dsrs[ARGUS_ASN_INDEX] = &flow->canon.asn.hdr;
                           break;
                        }
                        case k_CiscoV9DstAS: {
                           flow->canon.asn.dst_as = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_ASN_INDEX;
                           flow->dsrs[ARGUS_ASN_INDEX] = &flow->canon.asn.hdr;
                           break;
                        }
                        case k_CiscoV9BgpIpV4NextHop: {
                           break;
                        }
                        case k_CiscoV9MulDstPkts: {
                           break;
                        }
                        case k_CiscoV9MulDstBytes: {
                           break;
                        }
                        case k_CiscoV9LastSwitched: {
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                            secs  = ((timeval - context->sys_uptime) / 1000);
                            usecs = ((timeval - context->sys_uptime) % 1000) * 1000;

                            flow->canon.time.src.end.tv_sec   = context->export_time.tv_sec  + secs;
                           if (usecs < 0) {
                              flow->canon.time.src.end.tv_sec--;
                              usecs += 1000000;
                           }
                            flow->canon.time.src.end.tv_usec  = context->export_time.tv_usec + usecs;

                           flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           flow->dsrs[ARGUS_TIME_INDEX] = &flow->canon.time.hdr;
                           break;
                        }
                        case k_CiscoV9FirstSwitched: {
                           long timeval = (tData->length == 2) ? value.val16[0] : value.val32[0];
                           int secs, usecs;

                            secs  = ((timeval - context->sys_uptime) / 1000);
                            usecs = ((timeval - context->sys_uptime) % 1000) * 1000;

                            flow->canon.time.src.start.tv_sec   = context->export_time.tv_sec  + secs;
                           if (usecs < 0) {
                              flow->canon.time.src.start.tv_sec--;
                              usecs += 1000000;
                           }
                            flow->canon.time.src.start.tv_usec  = context->export_time.tv_usec + usecs;

                           flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                           flow->dsrs[ARGUS_TIME_INDEX] = &flow->canon.time.hdr;
                           break;
                        }
                        case k_CiscoV9OutBytes: {
/*
                           flow->canon.metric.dst.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9OutPkts: {
/*
                           flow->canon.metric.dst.pkts = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
*/
                           break;
                        }
                        case k_CiscoV9MinPktLen: {
                           flow->canon.psize.src.psizemin = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           flow->dsrs[ARGUS_PSIZE_INDEX] = &flow->canon.psize.hdr;
                           break;
                        }
                        case k_CiscoV9MaxPktLen: {
                           flow->canon.psize.src.psizemax = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_PSIZE_INDEX;
                           flow->dsrs[ARGUS_PSIZE_INDEX] = &flow->canon.psize.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6SrcAddr: {
                           bcopy (&value, &flow->canon.flow.flow_un.ipv6.ip_src, 16);
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IpV6DstAddr: {
                           bcopy (&value, &flow->canon.flow.flow_un.ipv6.ip_dst, 16);
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           ArgusParsingIPv6 = 1;
                           break;
                        }
                        case k_CiscoV9IPV6SrcMask: {
                           break;
                        }
                        case k_CiscoV9IpV6DstMask: {
                           break;
                        }
                        case k_CiscoV9IpV6FlowLabel: {
                           break;
                        }
                        case k_CiscoV9IpV6IcmpType: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->type = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IpV6MulIgmpType: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingInterval: {
                           break;
                        }
                        case k_CiscoV9IpV6SamplingAlgorithm: {
                           break;
                        }
                        case k_CiscoV9FlowActiveTimeout: {
                           break;
                        }
                        case k_CiscoV9FlowInactiveTimeout: {
                           break;
                        }
                        case k_CiscoV9EngineType: {
                           break;
                        }
                        case k_CiscoV9EngineID: {
                           break;
                        }
                        case k_CiscoV9TotalBytesExp: {
                           break;
                        }
                        case k_CiscoV9TotalPktsExp: {
                           break;
                        }
                        case k_CiscoV9TotalFlowsExp: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelType: {
                           break;
                        }
                        case k_CiscoV9MplsTopLabelIPAddr: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerID: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerMode: {
                           break;
                        }
                        case k_CiscoV9FlowSamplerRandomInt: {
                           break;
                        }

                        case k_CiscoV9MinTtl: {
                           flow->canon.attr.src.ttl = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9MaxTtl: {
                           flow->canon.attr.src.ttl = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9IPv4IpId: {
                           flow->canon.attr.src.ip_id = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9DstTos: {
                           flow->canon.attr.dst.tos = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_IPATTR_INDEX;
                           flow->dsrs[ARGUS_IPATTR_INDEX] = &flow->canon.attr.hdr;
                           break;
                        }
                        case k_CiscoV9SrcMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9DstMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9SrcVlan: {
                           flow->canon.vlan.sid = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           flow->dsrs[ARGUS_VLAN_INDEX] = &flow->canon.vlan.hdr;
                           break;
                        }
                        case k_CiscoV9DstVlan: {
                           flow->canon.vlan.did = value.val16[0];
                           flow->dsrindex |= 1 << ARGUS_VLAN_INDEX;
                           flow->dsrs[ARGUS_VLAN_INDEX] = &flow->canon.vlan.hdr;
                           break;
                        }
                        case k_CiscoV9IpProtocolVersion: {
                           break;
                        }
                        case k_CiscoV9Direction: {
                           break;
                        }
                        case k_CiscoV9IpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9BgpIpV6NextHop: {
                           break;
                        }
                        case k_CiscoV9IpV6OptionHeaders: {
                           break;
                        }
                        case k_CiscoV9MplsLabel1: {
                           break;
                        }
                        case k_CiscoV9MplsLabel2: {
                           break;
                        }
                        case k_CiscoV9MplsLabel3: {
                           break;
                        }
                        case k_CiscoV9MplsLabel4: {
                           break;
                        }
                        case k_CiscoV9MplsLabel5: {
                           break;
                        }
                        case k_CiscoV9MplsLabel6: {
                           break;
                        }
                        case k_CiscoV9MplsLabel7: {
                           break;
                        }
                        case k_CiscoV9MplsLabel8: {
                           break;
                        }
                        case k_CiscoV9MplsLabel9: {
                           break;
                        }
                        case k_CiscoV9MplsLabel10: {
                           break;
                        }
                        case k_CiscoV9InDstMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9OutSrcMac: {
                           flow->dsrindex |= 1 << ARGUS_MAC_INDEX;
                           flow->dsrs[ARGUS_MAC_INDEX] = &flow->canon.mac.hdr;
                           break;
                        }
                        case k_CiscoV9IfName: {
                           break;
                        }
                        case k_CiscoV9IfDesc: {
                           break;
                        }
                        case k_CiscoV9SampleName: {
                           break;
                        }
                        case k_CiscoV9InPermanentBytes: {
                           flow->canon.metric.src.bytes = value.val32[0];
                           flow->dsrindex |= 1 << ARGUS_METRIC_INDEX;
                           flow->dsrs[ARGUS_METRIC_INDEX] = &flow->canon.metric.hdr;
                           break;
                        }
                        case k_CiscoV9InPermanentPkts: {
                           break;
                        }
                        case k_CiscoV9FragmentOffset: {
                           break;
                        }
                        case k_CiscoV9ForwardingStatus: {
                           break;
                        }
                        case k_CiscoV9PostDSCP: {
                           break;
                        }
                        case k_CiscoV9NatInsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9NatOutsideGlobalAddr: {
                           break;
                        }
                        case k_CiscoV9postNatL4SrcPort: {
                           break;
                        }
                        case k_CiscoV9postNatL4DstPort: {
                           break;
                        }
                        case k_CiscoV9postNatEvent: {
                           break;
                        }
                        case k_CiscoV9IngressVRFID: {
                           break;
                        }
                        case k_CiscoV9ConnId: {
                           break;
                        }
                        case k_CiscoV9IcmpType: {
                           break;
                        }
                        case k_CiscoV9IcmpCode: {
                           break;
                        }
                        case k_CiscoV9IcmpTypeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->type = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoV9IcmpCodeV6: {
                           struct ArgusICMPv6Flow *icmpv6Flow = &flow->canon.flow.icmpv6_flow;
                           icmpv6Flow->code = value.val8[0];
                           flow->dsrindex |= 1 << ARGUS_FLOW_INDEX;
                           flow->dsrs[ARGUS_FLOW_INDEX] = &flow->canon.flow.hdr;
                           break;
                        }
                        case k_CiscoEventTimeMilliSec: {
                           break;
                        }
                        case k_CiscoEventTimeMicroSec: {
                           break;
                        }
                        case k_CiscoEventTimeNanoSec:  {
                           break;
                        }
                     }
                     tData++;
                  }

                  {
                     struct timeval tdiffbuf, *tdiff = &tdiffbuf;
                     flow->canon.hdr.type    = ARGUS_FAR | ARGUS_NETFLOW | ARGUS_VERSION;
                     flow->canon.hdr.cause   = ARGUS_STATUS;
                     flow->canon.hdr.len     = 1;

                     if (!(flow->dsrindex & (1 << ARGUS_TIME_INDEX))) {
                        struct ArgusTimeObject *ato = &flow->canon.time;
                         ato->src.start.tv_sec   = context->export_time.tv_sec;
                         ato->src.start.tv_usec  = ((long)(context->sys_uptime)%1000) * 1000;
 
                        if (ato->src.start.tv_usec >= 1000000) {
                           ato->src.start.tv_sec++;
                           ato->src.start.tv_usec -= 1000000;
                        }
                        ato->src.end = ato->src.start;
                        flow->dsrindex |= 1 << ARGUS_TIME_INDEX;
                        flow->dsrs[ARGUS_TIME_INDEX] = (void *)ato;
                     }

                     if (ArgusDiffTime(&flow->canon.time.src.end, &flow->canon.time.src.start, tdiff) == 0) {
                        struct ArgusMetricStruct *metric = &flow->canon.metric;

#define ARGUS_DEFAULT_RATE	1000000.0f
                        if (metric->src.pkts > 1) {
                           double dtime = (metric->src.pkts * 1.0) / ARGUS_DEFAULT_RATE;
                           double itime;
                           double ftime = modf(dtime, &itime);
                           flow->canon.time.src.end.tv_sec  = flow->canon.time.src.start.tv_sec  + (itime);
                           flow->canon.time.src.end.tv_usec = flow->canon.time.src.start.tv_usec + (ftime * 1000000);
                           if (flow->canon.time.src.end.tv_usec >= 1000000) {
                              flow->canon.time.src.end.tv_usec  -= 1000000;
                              flow->canon.time.src.end.tv_sec++;
                           }
                        }
                     }

                     for (i = 0; i < ARGUSMAXDSRTYPE; i++) {
                        if (flow->dsrindex & (1 << i)) {
                           switch(i) {
                              case ARGUS_FLOW_INDEX: {
                                 flow->canon.flow.hdr.type              = ARGUS_FLOW_DSR;
                                 flow->canon.flow.hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;

                                 if (ArgusParsingIPv6) {
                                    flow->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV6;
                                    flow->canon.flow.hdr.argus_dsrvl8.len  = 11;

                                 } else {
                                    struct ArgusFlow tflow;
                                    bzero(&tflow, sizeof(tflow));
                                    tflow.flow_un.ip.ip_src = flow->canon.flow.flow_un.ipv6.ip_src[0];
                                    tflow.flow_un.ip.ip_dst = flow->canon.flow.flow_un.ipv6.ip_dst[0];
                                    tflow.flow_un.ip.ip_p   = flow->canon.flow.flow_un.ipv6.ip_p;
                                    tflow.flow_un.ip.sport  = flow->canon.flow.flow_un.ipv6.sport;
                                    tflow.flow_un.ip.dport  = flow->canon.flow.flow_un.ipv6.dport;
                                    tflow.flow_un.ip.smask  = flow->canon.flow.flow_un.ipv6.ip_src[3];
                                    tflow.flow_un.ip.dmask  = flow->canon.flow.flow_un.ipv6.ip_dst[3];

                                    flow->canon.flow.hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
                                    flow->canon.flow.hdr.argus_dsrvl8.len  = 5;
                                    bcopy(&tflow.flow_un.ip, &flow->canon.flow.flow_un.ip, sizeof(tflow.flow_un.ip));
                                 }  

                                 bcopy(&flow->canon.flow, dsr, flow->canon.flow.hdr.argus_dsrvl8.len * 4);
                                 dsr += flow->canon.flow.hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += flow->canon.flow.hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_TIME_INDEX: {
                                 struct ArgusTimeObject *time = &flow->canon.time;
                                 time->hdr.type               = ARGUS_TIME_DSR;
                                 time->hdr.subtype            = ARGUS_TIME_ABSOLUTE_RANGE;
                                 time->hdr.argus_dsrvl8.qual  = ARGUS_TYPE_UTC_MICROSECONDS;
                                 time->hdr.argus_dsrvl8.len   = 5;
                                 bcopy(time, dsr, time->hdr.argus_dsrvl8.len * 4);
                                 dsr += time->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += time->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_ASN_INDEX: {
                                 struct ArgusAsnStruct *asn  = &flow->canon.asn;
                                 asn->hdr.type               = ARGUS_ASN_DSR;
                                 asn->hdr.subtype            = 0;
                                 asn->hdr.argus_dsrvl8.qual  = 0;
                                 asn->hdr.argus_dsrvl8.len   = 3;
                                 bcopy(asn, dsr, asn->hdr.argus_dsrvl8.len * 4);
                                 dsr += asn->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += asn->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_METRIC_INDEX: {
                                 struct ArgusMetricStruct *metric = &flow->canon.metric;
                                 int pkts, bytes;

                                 metric->hdr.type              = ARGUS_METER_DSR;
                                 metric->hdr.subtype           = ARGUS_METER_PKTS_BYTES;
                                 metric->hdr.argus_dsrvl8.qual = ARGUS_SRC_INT;
                                 metric->hdr.argus_dsrvl8.len  = 3;

                                 pkts  = metric->src.pkts;
                                 bytes = metric->src.bytes;

                                 bcopy(&metric->hdr, dsr, 4);
                                 bcopy(&pkts,  dsr+1, 4);
                                 bcopy(&bytes, dsr+2, 4);

                                 dsr += metric->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += metric->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_NETWORK_INDEX: {
                                 struct ArgusNetworkStruct *net = &flow->canon.net;
                                 bcopy(net, dsr, net->hdr.argus_dsrvl8.len * 4);
                                 dsr += net->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += net->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_MAC_INDEX: {
                                 struct ArgusMacStruct *mac = &flow->canon.mac;
                                 mac->hdr.type              = ARGUS_MAC_DSR;
                                 mac->hdr.subtype           = 0;
                                 mac->hdr.argus_dsrvl8.len  = 5;
                                 bcopy(mac, dsr, mac->hdr.argus_dsrvl8.len * 4);
                                 dsr += mac->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += mac->hdr.argus_dsrvl8.len;
                                 break;
                              }

                              case ARGUS_IPATTR_INDEX: {
                                 struct ArgusIPAttrStruct *attr = &flow->canon.attr;
                                 attr->hdr.type               = ARGUS_IPATTR_DSR;
                                 attr->hdr.subtype            = 0;
                                 attr->hdr.argus_dsrvl8.qual  = ARGUS_IPATTR_SRC;
                                 attr->hdr.argus_dsrvl8.len   = 2;
                                 bcopy(attr, dsr, attr->hdr.argus_dsrvl8.len * 4);
                                 dsr += attr->hdr.argus_dsrvl8.len;
                                 flow->canon.hdr.len += attr->hdr.argus_dsrvl8.len;
                              }
                           }
                        }
                     }

                     ArgusSendFlowRecord (model, flow, ARGUS_STATUS);
#ifdef ARGUSDEBUG
                      ArgusDebug (4, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) new flow %p\n", parser, model, tqueue, ptr, context->counter, retn);
#endif
                   }
                   ArgusParsingIPv6 = 0;
                    context->counter = context->counter - 1;
                   flowset_records++;
                   context->data_records++;
              }
              if (record_len <= (size_t)(end - sptr) &&
                  (flowset_records >= ARGUS_CISCO_DATA_RECORD_FLOWSET_MAX ||
                   context->data_records >= ARGUS_CISCO_DATA_RECORD_DATAGRAM_MAX))
                 ArgusLogCiscoDataRecordLimit(tqueue);
                src->lasttime = model->ArgusGlobalTime;

            } else {
                ArgusRemoveCiscoTemplate(src, flowset_id);
            }
         }
    }

#ifdef ARGUSDEBUG
    ArgusDebug (5, "ArgusParseCiscoRecordV9Data (%p, %p, %p, %p, %d) returning %p\n", parser, model, tqueue, ptr, context->counter, retn);
#endif
   return(retn);
}

static int
ArgusParseCiscoRecordV9Template (struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, struct ArgusCiscoHeaderContext *context, u_char *ptr, int len)
{
   struct ArgusCiscoTemplateUpdate *updates = NULL, *last = NULL;
   struct ArgusCiscoSourceStruct *src = NULL;
   struct ArgusCiscoTemplateStruct *template;
   const u_char *end;
   size_t cache_bytes, projected_bytes;
   unsigned int cache_templates, projected_templates;
   unsigned int update_count = 0;
   int retn = 0;

   if (model == NULL || tqueue == NULL || context == NULL || ptr == NULL || len < 0)
      return(retn);

   end = ptr + len;
   while (ptr < end) {
      struct ArgusCiscoTemplateUpdate *update;
      CiscoFlowTemplateHeaderV9_t *tHdr;
       CiscoFlowTemplateFlowEntryV9_t *tData;
       uint16_t template_id, count;
       size_t slen, record_length = 0;
      int i;

      if (!ArgusNetflowHasBytes(ptr, end, sizeof(CiscoFlowTemplateHeaderV9_t)))
         goto done;

      template_id = ArgusNetflowGet16(ptr);
      count = ArgusNetflowGet16(ptr + sizeof(uint16_t));
       if (count == 0 ||
           count > ((size_t)(end - (ptr + sizeof(CiscoFlowTemplateHeaderV9_t))) /
                    sizeof(CiscoFlowTemplateFlowEntryV9_t)))
          goto done;
       if (update_count >= ARGUS_CISCO_TEMPLATE_FLOWSET_MAX ||
           context->template_updates >= ARGUS_CISCO_TEMPLATE_DATAGRAM_MAX)
          goto done;

      slen = sizeof(*tHdr) + ((size_t)count * sizeof(*tData));
      if ((tHdr = (CiscoFlowTemplateHeaderV9_t *)ArgusCalloc(1, slen)) == NULL) {
         ArgusLog(LOG_ERR, "ArgusCalloc(%d, %zu) error %s\n", count, slen, strerror(errno));
         goto done;
      }

      tHdr->template_id = template_id;
      tHdr->count = count;
      tData = (CiscoFlowTemplateFlowEntryV9_t *)(tHdr + 1);
      for (i = 0; i < count; i++) {
         const u_char *field = ptr + sizeof(*tHdr) + (i * sizeof(*tData));

          tData[i].type = ArgusNetflowGet16(field);
          tData[i].length = ArgusNetflowGet16(field + sizeof(uint16_t));
          if (tData[i].length == 0 ||
              tData[i].length > ARGUS_CISCO_V9_RECORD_MAX - record_length) {
             ArgusFree(tHdr);
             goto done;
          }
          record_length += tData[i].length;
      }

      if ((update = (struct ArgusCiscoTemplateUpdate *)ArgusCalloc(1, sizeof(*update))) == NULL) {
         ArgusLog(LOG_ERR, "ArgusCalloc(%d, %zu) error %s\n", 1, sizeof(*update), strerror(errno));
         ArgusFree(tHdr);
         goto done;
      }
      update->template_id = template_id;
       update->length = slen;
       update->count = count;
       update->record_length = record_length;
       update->tHdr = tHdr;
      if (last != NULL)
         last->next = update;
      else
         updates = update;
       last = update;
       update_count++;
       context->template_updates++;
       ptr += slen;
   }

   if (updates == NULL) {
      retn = 1;
      goto done;
   }

   src = ArgusFindCiscoSource(tqueue, context);
   ArgusCiscoTemplateCacheUsage(tqueue, &cache_bytes, &cache_templates);
   if (src == NULL && tqueue->count >= ARGUS_CISCO_TEMPLATE_SOURCE_MAX) {
      ArgusLogCiscoTemplateCacheLimit(tqueue);
      goto done;
   }

   projected_bytes = cache_bytes;
   projected_templates = cache_templates;
   for (last = updates; last != NULL; last = last->next) {
      if (!ArgusCiscoTemplateUpdateHasLater(last)) {
         template = (src == NULL) ? NULL :
            ArgusFindCiscoTemplate(src, last->template_id);
         if (template != NULL) {
            if ((size_t)template->length > projected_bytes) {
               ArgusLogCiscoTemplateCacheLimit(tqueue);
               goto done;
            }
            projected_bytes -= template->length;
         } else if (projected_templates == (unsigned int)-1) {
            ArgusLogCiscoTemplateCacheLimit(tqueue);
            goto done;
         } else
            projected_templates++;

         if (last->length > (size_t)-1 - projected_bytes) {
            ArgusLogCiscoTemplateCacheLimit(tqueue);
            goto done;
         }
         projected_bytes += last->length;
      }
   }
   if (projected_templates > ARGUS_CISCO_TEMPLATE_MAX ||
       projected_bytes > ARGUS_CISCO_TEMPLATE_CACHE_BYTES_MAX) {
      ArgusLogCiscoTemplateCacheLimit(tqueue);
      goto done;
   }

   if (src == NULL) {
       if ((src = (struct ArgusCiscoSourceStruct *)ArgusCalloc(1, sizeof(*src))) == NULL) {
          ArgusLog(LOG_ERR, "ArgusParseCiscoRecordV9Template: ArgusCalloc(%d, %zu) error %s\n", 1, sizeof(*src), strerror(errno));
          goto done;
       }
       src->srcid = context->source_id;
       src->address_type = context->source_address_type;
       bcopy(context->source_address, src->saddr, sizeof(src->saddr));
       src->startime = model->ArgusGlobalTime;
      src->lasttime = model->ArgusGlobalTime;
      if (!ArgusAddToQueue(tqueue, &src->qhdr, ARGUS_LOCK)) {
         ArgusFreeCiscoSource(src);
         src = NULL;
         goto done;
       }
    }
   context->source = src;

   while (updates != NULL) {
       struct ArgusCiscoTemplateUpdate *update = updates;

       updates = update->next;
      if (ArgusCiscoTemplateUpdateHasLater(update)) {
         ArgusFree(update->tHdr);
         ArgusFree(update);
         continue;
      }
      template = ArgusFindCiscoTemplate(src, update->template_id);
      if (template == NULL) {
         if ((template = (struct ArgusCiscoTemplateStruct *)ArgusCalloc(1, sizeof(*template))) == NULL) {
            ArgusLog(LOG_ERR, "ArgusParseCiscoRecordV9Template: ArgusCalloc(%d, %zu) error %s\n", 1, sizeof(*template), strerror(errno));
            updates = update;
            goto done;
          }
          template->template_id = update->template_id;
          template->next = src->templates;
          template->hash_next = src->template_hash[template->template_id % ARGUS_CISCO_TEMPLATE_HASH_SIZE];
          src->templates = template;
          src->template_hash[template->template_id % ARGUS_CISCO_TEMPLATE_HASH_SIZE] = template;
       }
      if (template->tHdr != NULL)
         ArgusFree(template->tHdr);
      template->tHdr = update->tHdr;
       template->length = update->length;
       template->count = update->count;
       template->record_length = update->record_length;
       template->lasttime = model->ArgusGlobalTime;
      update->tHdr = NULL;
      ArgusFree(update);
   }
   src->lasttime = model->ArgusGlobalTime;
   retn = 1;

done:
   ArgusFreeCiscoTemplateUpdates(updates);
#ifdef ARGUSDEBUG
   ArgusDebug(5, "ArgusParseCiscoRecordV9Template (%p, %p, %p, %d) returning %d\n",
      model, src, ptr, len, retn);
#endif
   return(retn);
}

static int
ArgusParseCiscoRecordV9OptionTemplate (struct ArgusModelerStruct *model, struct ArgusQueueStruct *tqueue, u_char *ptr, int len)
{
   int retn = (model != NULL && tqueue != NULL && ptr != NULL && len >= 0);

#ifdef ARGUSDEBUG
   ArgusDebug(5, "ArgusParseCiscoRecordV9OptionTemplate (%p, %p) returning %d\n", model, ptr, retn);
#endif
   return(retn);
}

#endif
