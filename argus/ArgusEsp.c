/*
 * Argus Software.  Argus files - ESP layer processing
 * Copyright (c) 2000-2020 QoSient, LLC
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


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusEsp)
#define ArgusEsp
#endif


#include <stdio.h>
#include <argus_compat.h>
#include <ArgusModeler.h>

#include <errno.h>
#include <string.h>


struct esphdr {
   unsigned int spi, seq;
};


struct ArgusSystemFlow *
ArgusCreateESPv6Flow (struct ArgusModelerStruct *model, struct ip6_hdr *ip)
{
   struct ArgusSystemFlow *retn = NULL;
/*
   struct esphdr *esp = (struct esphdr *) model->ArgusThisUpHdr;

struct ArgusESPv6Flow {
   unsigned int ip_src[4], ip_dst[4];
#if defined(_LITTLE_ENDIAN)
   unsigned int flow:20;
   unsigned int resv:4;
   unsigned int ip_p:8;
#else
   unsigned int ip_p:8;
   unsigned int resv:4;
   unsigned int flow:20;
#endif 
   unsigned int spi;
};
*/

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusCreateESPv6Flow(0x%x) returning %d\n", ip, retn);
#endif 

   return (retn);
}

struct ArgusSystemFlow *
ArgusCreateESPFlow (struct ArgusModelerStruct *model, struct ip *ip)
{
   struct ArgusSystemFlow *retn = NULL;
   struct esphdr *esp = (struct esphdr *) model->ArgusThisUpHdr;

   if (STRUCTCAPTURED(model, *esp)) {
      struct ArgusESPFlow *espFlow = &model->ArgusThisFlow->esp_flow;
 
      retn = model->ArgusThisFlow;
      model->state &= ~ARGUS_DIRECTION;
 
      retn->hdr.type             = ARGUS_FLOW_DSR;
      retn->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
      retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_IPV4;
      retn->hdr.argus_dsrvl8.len  = 5;

      espFlow->ip_src = ntohl(ip->ip_src.s_addr);
      espFlow->ip_dst = ntohl(ip->ip_dst.s_addr);
      espFlow->ip_p   = ip->ip_p;
      espFlow->pad    = 0;
      espFlow->spi    = ntohl(esp->spi);
   }

#ifdef ARGUSDEBUG
  ArgusDebug (6, "ArgusCreateESPFlow(0x%x) returning 0x%x\n", ip, retn);
#endif 

   return (retn);
}

void ArgusUpdateESPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

void
ArgusUpdateESPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
   struct esphdr *esp = (struct esphdr *) model->ArgusThisUpHdr;
   struct ArgusESPObject *espObj = &net->net_union.esp;

   if (STRUCTCAPTURED(model, *esp)) {
#ifdef _LITTLE_ENDIAN
      esp->spi = ntohl(esp->spi);
      esp->seq = ntohl(esp->seq);
#endif 
      if (*state == ARGUS_START) {
         net->hdr.type             = ARGUS_NETWORK_DSR;
         net->hdr.subtype          = ARGUS_ESP_DSR;
         net->hdr.argus_dsrvl8.qual = 0;
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusESPObject)+3))/4 + 1;

         flowstr->dsrs[ARGUS_NETWORK_INDEX] = (void *) net;

         bzero ((char *)espObj, sizeof(*espObj));
         flowstr->timeout = ARGUS_IPTIMEOUT;

         espObj->spi     = esp->spi;
         espObj->lastseq = esp->seq;
         
      } else {

         if (!(espObj->status & ARGUS_ESP_SEQFAILURE)) {
#define ARGUS_ESP_WINDOW	0x10000
            int diff  = esp->seq - espObj->lastseq;
            if (esp->seq < espObj->lastseq) {
               if (diff > 0)
                  espObj->status |= ARGUS_ESP_ROLLOVER;
            }

            if (diff != 1) {
               if ((diff == 0) || (abs(diff) > ARGUS_ESP_WINDOW)) {
                  espObj->status |= ARGUS_ESP_SEQFAILURE;
                  if (diff)
                     espObj->lastseq = esp->seq;

               } else {
                  if (diff > 0) {
                     espObj->status |= ARGUS_SRC_PKTS_DROP;
                     espObj->lostseq += (diff - 1);
                     espObj->lastseq = esp->seq;
                  } else {
                     espObj->lostseq--;
                     espObj->status |= ARGUS_SRC_OUTOFORDER;
                  }
               }

            } else
               espObj->lastseq = esp->seq;
         }
      }
   }
   
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateESPState(0x%x, %d) returning\n", flowstr, *state);
#endif 
}


#include <argus_out.h>

void ArgusESPFlowRecord (struct ArgusNetworkStruct *net, unsigned char state);

void
ArgusESPFlowRecord (struct ArgusNetworkStruct *net, unsigned char state)
{
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusESPFlowRecord(0x%x, %d) returning\n", net, state);
#endif 
}
