/*
 * --------------------------------------------------------------------------------
 * 
 * 2019-2021 CounterFlow AI, Inc.
 * Proprietary & Confidential. All Rights Reserved.
 * 
 * This software is a proprietary fork of Argus, commercially licensed from
 * QoSient, LLC by CounterFlow AI in 2019.
 * 
 * Refactored and enhanced with numerous features and functions.
 *
 * ArgusVxLan support written by 
 * Carter Bullard
 *
 * 
 */

#if !defined(ArgusVxLan)
#define ArgusVxLan

#include <ArgusVxLan.h>

unsigned short ArgusParseVxLan(struct ArgusModelerStruct *, void *);

struct vxlanhdr
{
   unsigned char flgs, res[3];
   unsigned int vni;
};

unsigned short
ArgusParseVxLan(struct ArgusModelerStruct *model, void *ptr)
{
   unsigned short retn = 0;
   struct vxlanhdr *vxl = ptr;

   if (getArgusVxLanParsing(model))
   {
      if (STRUCTCAPTURED(model, *vxl))
      {
         if (vxl->flgs == 0x08)
         {
            unsigned int vni = ntohl(vxl->vni) >> 8;
            int len = ((unsigned char *)(vxl + 1)) - model->ArgusThisUpHdr;

            retn = ARGUS_ETHER_HDR;
            model->ArgusThisVxLanVni = vni;
            model->ArgusThisEncaps |= ARGUS_ENCAPS_VXLAN;
            model->ArgusThisUpHdr = (unsigned char *)(vxl + 1);
            model->ArgusThisLength -= len;
            model->ArgusSnapLength -= len;

#ifdef ARGUSDEBUG
            ArgusDebug(2, "ArgusParseVxLan(%p, %p) vni is %d\n", model, ptr, vni);
#endif
         }
      }
   }
#ifdef ARGUSDEBUG
   ArgusDebug(1, "ArgusParseVxLan(%p, %p) returning %d\n", model, ptr, retn);
#endif
   return (retn);
}

#endif
