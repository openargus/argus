/*
 * Argus Software.  Argus files - UDP protocol
 * Copyright (c) 2000-2020 QoSient, LLC
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
struct bootp *bp;

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
