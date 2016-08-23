/*
 * Gargoyle Software.  Argus files - Lcp flow processing
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
 * $Id: //depot/gargoyle/argus/argus/ArgusLcp.c#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusLcp
#define ArgusLcp
#endif


#include <stdio.h>
#include <ArgusModeler.h>

#include <errno.h>
#include <string.h>


struct ArgusSystemFlow *
ArgusCreateLcpFlow (struct ArgusModelerStruct *model, struct lcp_hdr *lcp)
{
   struct ArgusSystemFlow *retn = NULL;

   if (STRUCTCAPTURED(model, *lcp)) {
      struct ArgusLcpFlow *lcpFlow = &model->ArgusThisFlow->lcp_flow;
 
      retn = model->ArgusThisFlow;
      model->state &= ~ARGUS_DIRECTION;
 
      retn->hdr.type             = ARGUS_FLOW_DSR;
      retn->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
      retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_LCP;
      retn->hdr.argus_dsrvl8.len  = 5;

      lcpFlow->code = lcp->code;
      lcpFlow->id   = lcp->id;
   }

#ifdef ARGUSDEBUG
  ArgusDebug (4, "ArgusCreateLcpFlow(0x%x, 0x%x) returning 0x%x\n", model, lcp, retn);
#endif 

   return (retn);
}

void ArgusUpdateLCPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

void
ArgusUpdateLCPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
   struct lcp_hdr *lcp = (struct lcp_hdr *) model->ArgusThisUpHdr;
   struct ArgusLCPObject *lcpObj = &net->net_union.lcp;

   if (STRUCTCAPTURED(model, *lcp)) {
#ifdef _LITTLE_ENDIAN
#endif 
      if (*state == ARGUS_START) {
         net->hdr.type             = ARGUS_NETWORK_DSR;
         net->hdr.subtype          = ARGUS_LCP_DSR;
         net->hdr.argus_dsrvl8.qual = 0;
         net->hdr.argus_dsrvl8.len  = ((sizeof(struct ArgusLCPObject)+3))/4 + 1;
/*

struct ArgusLCPObject {
   unsigned int status;
   unsigned int state, options;
};

*/
         flowstr->dsrs[ARGUS_NETWORK_INDEX] = (void *) net;

         bzero ((char *)lcpObj, sizeof(*lcpObj));
         flowstr->timeout = ARGUS_IPTIMEOUT;

      } else {
      }
   }
   
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateLCPState(0x%x, %d) returning\n", flowstr, *state);
#endif 
}


#include <argus_out.h>

void ArgusLCPFlowRecord (struct ArgusNetworkStruct *net, unsigned char state);

void
ArgusLCPFlowRecord (struct ArgusNetworkStruct *net, unsigned char state)
{
#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusLCPFlowRecord(0x%x, %d) returning\n", net, state);
#endif 
}
