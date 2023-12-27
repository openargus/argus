/*
 * Gargoyle Software.  Argus files - UDP Protocol processing
 * Copyright (c) 2000-2024 QoSient, LLC
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
 * $Id: //depot/gargoyle/argus/argus/ArgusUdp.c#5 $
 * $DateTime: 2015/06/22 17:59:06 $
 * $Change: 3024 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusUdp)
#define ArgusUdp
#endif

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>

#include <argus/bootp.h>

void ArgusUpdateUDPState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char *);

void
ArgusUpdateUDPState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char *state)
{
   struct udphdr *up = (struct udphdr *) model->ArgusThisUpHdr;
   u_char *nxtHdr = (u_char *)(up + 1);

   if (STRUCTCAPTURED(model, *up)) {
      model->ArgusThisLength -= sizeof(*up);
      model->ArgusSnapLength -= sizeof(*up);
      model->ArgusThisUpHdr = nxtHdr;

      if (*state == ARGUS_START) {

      } else {
         if ((flowstr->canon.metric.src.pkts + flowstr->canon.metric.dst.pkts) > 2) {
            flowstr->timeout = ARGUS_IPTIMEOUT;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusUpdateUDPState(0x%x, %d) returning\n", flowstr, state);
#endif

}


#include <argus_out.h>

void ArgusUDPFlowRecord (struct ArgusFlowStruct *, struct ArgusRecord *, unsigned char);

void
ArgusUDPFlowRecord (struct ArgusFlowStruct *flow, struct ArgusRecord *argus, unsigned char state)
{
}
