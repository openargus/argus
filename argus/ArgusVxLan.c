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
 * $Id$
 * $DateTime: 2014/05/14 12:53:31 $
 * $Change: 2827 $
 */

#if !defined(ArgusVxLan)
#define ArgusVxLan

#include <ArgusModeler.h>
#include <ArgusVxLan.h>

unsigned short ArgusParseVxLan (struct ArgusModelerStruct *, void *);

struct vxlanhdr {
   unsigned char flgs, res[3];
   unsigned int vni;
};

unsigned short
ArgusParseVxLan (struct ArgusModelerStruct *model, void *ptr)
{
   unsigned short retn = 0;
   struct vxlanhdr *vxl = ptr;

   if (STRUCTCAPTURED(model, *vxl)) {
      if (vxl->flgs == 0x08) {
         unsigned int vni = ntohl(vxl->vni) >> 8;
         int len = ((unsigned char *) (vxl + 1)) - model->ArgusThisUpHdr;

         retn = ARGUS_ETHER_HDR;
         model->ArgusThisVxLanVni = vni;
         model->ArgusThisEncaps |= ARGUS_ENCAPS_VXLAN;
         model->ArgusThisUpHdr  = (unsigned char *)(vxl + 1);
         model->ArgusThisLength -= len;
         model->ArgusSnapLength -= len;

         if (model->ppc && (model->ppc[ARGUS_VXLAN_PROTO] == 1))
            model->ArgusMatchProtocol++;
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusParseVxLan(%p, %p) vni is %d\n", model, ptr, vni);
#endif
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusParseVxLan(%p, %p) returning %d\n", model, ptr, retn);
#endif
   return (retn);
}


#endif
