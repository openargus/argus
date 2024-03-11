/*
 * Argus-5.0 Software.  Argus files - UDP Protocol processing
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
