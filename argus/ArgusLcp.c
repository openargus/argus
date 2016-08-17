/*
 * Argus Software.  Argus files - main argus processing
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
 * $Id: //depot/argus/argus/argus/ArgusLcp.c#8 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
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
