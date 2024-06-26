/*
 * Argus-5.0 Software.  Argus files - UDP Protocol processing - Geneve
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

#if !defined(ArgusGeneve)
#define ArgusGeneve

#include <ArgusGeneve.h>

unsigned short ArgusParseGeneve (struct ArgusModelerStruct *, void *);

/*
 * Geneve header, draft-ietf-nvo3-geneve
 *
 *    0                   1                   2                   3
 *    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |Ver|  Opt Len  |O|C|    Rsvd.  |          Protocol Type        |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |        Virtual Network Identifier (VNI)       |    Reserved   |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                    Variable Length Options                    |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *
 * Options:
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |          Option Class         |      Type     |R|R|R| Length  |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 *    |                      Variable Option Data                     |
 *    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 */

struct genevehdr {
   unsigned char ver_opt;
   unsigned char flags;
   unsigned short ptype;
   unsigned int vni;
};

#define VER_SHIFT 6
#define HDR_OPTS_LEN_MASK 0x3F

#define FLAG_OAM      (1 << 7)
#define FLAG_CRITICAL (1 << 6)
#define FLAG_R1       (1 << 5)
#define FLAG_R2       (1 << 4)
#define FLAG_R3       (1 << 3)
#define FLAG_R4       (1 << 2)
#define FLAG_R5       (1 << 1)
#define FLAG_R6       (1 << 0)

#define OPT_TYPE_CRITICAL (1 << 7)
#define OPT_LEN_MASK 0x1F

static const struct tok geneve_flag_values[] = {
   { FLAG_OAM, "O" },
   { FLAG_CRITICAL, "C" },
   { FLAG_R1, "R1" },
   { FLAG_R2, "R2" },
   { FLAG_R3, "R3" },
   { FLAG_R4, "R4" },
   { FLAG_R5, "R5" },
   { FLAG_R6, "R6" },
   { 0, NULL }
};


extern void *ArgusCreateIPv4Flow (struct ArgusModelerStruct *, struct ip *);
extern void *ArgusCreateIPv6Flow (struct ArgusModelerStruct *, struct ip6_hdr *);

unsigned short
ArgusParseGeneve (struct ArgusModelerStruct *model, void *ptr)
{
   struct argus_geneve *gen = model->ArgusThisGeneve;
   int genlen = 4, hlen = 0, pass = 0;
   struct genevehdr *genhdr = ptr;
   struct ip *ip = (struct ip *) model->ArgusThisUpHdr;

   unsigned short retn = 0;
   u_int version;
   u_int optlen;
   uint32_t vni;
   int len;

   if (ip->ip_v == 4) {
      ArgusCreateIPv4Flow (model, (struct ip *)model->ArgusThisUpHdr);
      bcopy(model->ArgusThisFlow, model->ArgusThisGeneve->tflow, sizeof(*model->ArgusThisFlow));
   } else {
      ArgusCreateIPv6Flow (model, (struct ip6_hdr *)model->ArgusThisUpHdr);
      bcopy(model->ArgusThisFlow, model->ArgusThisGeneve->tflow, sizeof(*model->ArgusThisFlow));
   }

   if (STRUCTCAPTURED(model, *genhdr)) {
      version = genhdr->ver_opt >> VER_SHIFT;
      optlen = (genhdr->ver_opt & OPT_LEN_MASK) << 2;
      retn = ntohs(genhdr->ptype);
      gen->ver_opt = genhdr->ver_opt;
      gen->flags = genhdr->flags;
      gen->vni = ntohl(genhdr->vni) >> 8;

      len = ((unsigned char *) (genhdr + 1) + optlen) - model->ArgusThisUpHdr;
      model->ArgusThisEncaps |= ARGUS_ENCAPS_GENEVE;
      model->ArgusThisUpHdr  = (unsigned char *)(genhdr + 1) + optlen;
      model->ArgusThisLength -= len;
      model->ArgusSnapLength -= len;

#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusParseGeneve(%p, %p) vni is %d\n", model, ptr, vni);
#endif
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusParseGeneve(%p, %p) returning %d\n", model, ptr, retn);
#endif
   return (retn);
}


#endif
