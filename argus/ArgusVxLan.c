/*
 * Gargoyle Software.  Argus files - UDP Protocol processing
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
 * $Id$
 * $DateTime: 2014/05/14 12:53:31 $
 * $Change: 2827 $
 */

#if !defined(ArgusVxLan)
#define ArgusVxLan

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
