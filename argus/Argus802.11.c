/*
 * Argus-5.0 Software. Argus files - 802.11 Wireless processing
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
 * $Id: //depot/gargoyle/argus/argus/Argus802.11.c#4 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(Argus80211)
#define Argus80211
#endif

#include <stdio.h>
#include <argus_compat.h>
#include <ArgusModeler.h>
#include <argus/ieee802_11.h>

#include <string.h>
#include <errno.h>

static void ArgusParse80211MgmtBody(struct ArgusModelerStruct *, struct mgmt_body_t *, const u_char *, int);
int ArgusExtract802_11HeaderLength(u_int16_t);


#if !defined(ETH_ALEN)
#define ETH_ALEN   6
#endif

struct ArgusSystemFlow *
ArgusCreate80211Flow (struct ArgusModelerStruct *model, void *ptr) 
{
   struct ArgusSystemFlow *retn = NULL;
   struct mgmt_body_t pbody;
   const struct mgmt_header_t *hp = (const struct mgmt_header_t *) ptr;
   u_char *p;
   int hdrlen;
   u_int16_t fc;

   /* Nothing below can be read safely until we know the 2-byte frame-control field
    * itself is captured -- ArgusProcess80211Hdr() now checks this before calling us for
    * the ARGUS_802_11_HDR dispatch path, but ArgusCreateFlow() (ArgusModeler.c) also
    * calls us directly for the ARGUS_802_11_HDR flow-key case, so re-check here rather
    * than relying on every caller to have done so (see F-13,
    * security-review/findings-log.md). */
   if (!BYTESCAPTURED(model, *(char *)ptr, 2))
      return (retn);

   fc = EXTRACT_LE_16BITS(ptr);
   hdrlen = ArgusExtract802_11HeaderLength(fc);

   p = (u_char *) ptr + hdrlen;

   bzero(&pbody, sizeof(pbody));

   /* Every management-frame subtype below reads fixed-size fields out of the body
    * starting at `p` (capability_info, listen_interval, status_code, aid, timestamp,
    * beacon_interval) before ever reaching ArgusParse80211MgmtBody()'s TLV loop -- none
    * of that was previously checked against the captured buffer. mgmt_max_offset is the
    * largest fixed-body offset used by any of the case blocks below (timestamp +
    * beacon_interval + capability_info, the ST_PROBE_RESPONSE/ST_BEACON case), so
    * checking once against BYTESCAPTURED up front here is sufficient for all subtypes'
    * fixed-field reads. */
   if (FC_TYPE(fc) == T_MGMT) {
      switch (FC_SUBTYPE(fc)) {
         case ST_ASSOC_REQUEST:
         case ST_REASSOC_REQUEST:
            if (!BYTESCAPTURED(model, *p, IEEE802_11_CAPINFO_LEN + IEEE802_11_LISTENINT_LEN))
               return (retn);
            break;

         case ST_ASSOC_RESPONSE:
         case ST_REASSOC_RESPONSE:
            if (!BYTESCAPTURED(model, *p, IEEE802_11_CAPINFO_LEN + IEEE802_11_STATUS_LEN + IEEE802_11_AID_LEN))
               return (retn);
            break;

         case ST_PROBE_RESPONSE:
         case ST_BEACON:
            if (!BYTESCAPTURED(model, *p, IEEE802_11_TSTAMP_LEN + IEEE802_11_BCNINT_LEN + IEEE802_11_CAPINFO_LEN))
               return (retn);
            break;

         default:
            break;
      }
   }

   switch (FC_TYPE(fc)) {
      case T_MGMT: {
         int offset = 0;

         switch (FC_SUBTYPE(fc)) {
            case ST_ASSOC_REQUEST:
            case ST_REASSOC_REQUEST:
               pbody.capability_info = EXTRACT_LE_16BITS(p);
               offset += IEEE802_11_CAPINFO_LEN;
               pbody.listen_interval = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_LISTENINT_LEN;
               ArgusParse80211MgmtBody(model, &pbody, p, offset);
               break;

            case ST_ASSOC_RESPONSE:
            case ST_REASSOC_RESPONSE:
               pbody.capability_info = EXTRACT_LE_16BITS(p);
               offset += IEEE802_11_CAPINFO_LEN;
               pbody.status_code = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_STATUS_LEN;
               pbody.aid = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_AID_LEN;
               ArgusParse80211MgmtBody(model, &pbody, p, offset);
               break;

            case ST_PROBE_REQUEST:
               ArgusParse80211MgmtBody(model, &pbody, p, offset);
               break;

            case ST_PROBE_RESPONSE:
            case ST_BEACON: {
               memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
               offset += IEEE802_11_TSTAMP_LEN;
               pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_BCNINT_LEN;
               pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_CAPINFO_LEN;
               ArgusParse80211MgmtBody(model, &pbody, p, offset);
               break;
            }

            case ST_ATIM:
               break;
            case ST_DISASSOC:
               break;

            case ST_AUTH:
            case ST_DEAUTH:
               break;
         }
         break;
      }

      case T_CTRL: {
         switch (FC_SUBTYPE(fc)) {
            case CTRL_PS_POLL:
               break;
            case CTRL_RTS:
               break;
            case CTRL_CTS:
               break;
            case CTRL_ACK:
               break;
            case CTRL_CF_END:
               break;
            case CTRL_END_ACK:
               break;
            default:
               break;
         }
         break;
      }

      case T_DATA: {
         if (FC_WEP(fc)) {
         } else {
         }
         break;
      }
   }

   /* mgmt_header_t's da/sa/bssid fields (read below via hp->) sit at fixed offsets within
    * the fixed-size mgmt_header_t itself -- STRUCTCAPTURED(model, *(char *)ptr) only
    * validates 1 byte (the size of the object actually named, `*(char *)ptr`), not the
    * full struct mgmt_header_t that hp->da/sa/bssid index into. Use BYTESCAPTURED against
    * sizeof(*hp) instead (see F-13, security-review/findings-log.md). */
   if (BYTESCAPTURED(model, *(char *)ptr, sizeof(*hp))) {
      retn = model->ArgusThisFlow;
      retn->hdr.type              = ARGUS_FLOW_DSR;
      retn->hdr.subtype           = ARGUS_FLOW_CLASSIC5TUPLE;
      retn->hdr.argus_dsrvl8.qual = ARGUS_TYPE_WLAN;
      retn->hdr.argus_dsrvl8.len  = (sizeof(struct ArgusWlanFlow) + 3)/4 + 1;

      bcopy ((char *)&hp->da,    (char *)&model->ArgusThisFlow->wlan_flow.dhost, ETH_ALEN);
      bcopy ((char *)&hp->sa,    (char *)&model->ArgusThisFlow->wlan_flow.shost, ETH_ALEN);
      bcopy ((char *)&hp->bssid, (char *)&model->ArgusThisFlow->wlan_flow.bssid, ETH_ALEN);

      switch (FC_TYPE(fc)) {
         case T_MGMT: {
            switch (FC_SUBTYPE(fc)) {
               case ST_ASSOC_REQUEST:
               case ST_ASSOC_RESPONSE:
               case ST_REASSOC_REQUEST:
               case ST_REASSOC_RESPONSE:
               case ST_PROBE_REQUEST:
               case ST_PROBE_RESPONSE:
               case ST_BEACON: {
                  if (pbody.ssid_status == PRESENT) {
                     /* pbody.ssid.length is validated in ArgusParse80211MgmtBody() against
                      * both sizeof(pbody.ssid.ssid)-1 and the destination array's bound
                      * before this struct is ever populated -- safe to bcopy here using
                      * the same length. */
                     bcopy((char *)pbody.ssid.ssid, model->ArgusThisFlow->wlan_flow.ssid, pbody.ssid.length);
                  }
                  break;
               }
            }
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreate80211Flow (0x%x, 0x%x) returning %d\n", model, ptr, retn);
#endif
   return (retn);
}


int
ArgusExtract802_11HeaderLength(u_int16_t fc)
{
   switch (FC_TYPE(fc)) {
      case T_MGMT:
         return MGMT_HDRLEN;
      case T_CTRL:
         switch (FC_SUBTYPE(fc)) {
            case CTRL_PS_POLL:
               return CTRL_PS_POLL_HDRLEN;
            case CTRL_RTS:
               return CTRL_RTS_HDRLEN;
            case CTRL_CTS:
               return CTRL_CTS_HDRLEN;
            case CTRL_ACK:
               return CTRL_ACK_HDRLEN;
            case CTRL_CF_END:
               return CTRL_END_HDRLEN;
            case CTRL_END_ACK:
               return CTRL_END_ACK_HDRLEN;
            default:
               return 0;
         }
      case T_DATA: {
         int len = (FC_TO_DS(fc) && FC_FROM_DS(fc)) ? 30 : 24;
         if (DATA_FRAME_IS_QOS(FC_SUBTYPE(fc)))
            len += 2;
         return len;
      }
      default:
         return 0;
   }
}

static void
ArgusParse80211MgmtBody(struct ArgusModelerStruct *model, struct mgmt_body_t *pbody, const u_char *p, int offset)
{
   /*
    * We haven't seen any elements yet.
    */
   pbody->challenge_status = NOT_PRESENT;
   pbody->ssid_status = NOT_PRESENT;
   pbody->rates_status = NOT_PRESENT;
   pbody->ds_status = NOT_PRESENT;
   pbody->cf_status = NOT_PRESENT;
   pbody->tim_status = NOT_PRESENT;

   for (;;) {
      /* Every iteration starts by reading the 1-byte element-id tag at p+offset --
       * confirm it is actually captured before dereferencing it. None of this loop's
       * reads were previously checked against the captured buffer at all (see F-13,
       * security-review/findings-log.md) -- only against the destination struct's max
       * field size, which bounds how much can be *written* but not whether the *source*
       * bytes are actually present in the capture. */
      if (!BYTESCAPTURED(model, *(p + offset), 1))
         return;

      switch (*(p + offset)) {
      case E_SSID:
         /* Present, possibly truncated */
         pbody->ssid_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 2))
            return;
         memcpy(&pbody->ssid, p + offset, 2);
         offset += 2;
         if (pbody->ssid.length != 0) {
            if (pbody->ssid.length >
                sizeof(pbody->ssid.ssid) - 1)
               return;
            if (!BYTESCAPTURED(model, *(p + offset), pbody->ssid.length))
               return;
            memcpy(&pbody->ssid.ssid, p + offset,
                pbody->ssid.length);
            offset += pbody->ssid.length;
         }
         pbody->ssid.ssid[pbody->ssid.length] = '\0';
         /* Present and not truncated */
         pbody->ssid_status = PRESENT;
         break;
      case E_CHALLENGE:
         /* Present, possibly truncated */
         pbody->challenge_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 2))
            return;
         memcpy(&pbody->challenge, p + offset, 2);
         offset += 2;
         if (pbody->challenge.length != 0) {
            if (pbody->challenge.length >
                sizeof(pbody->challenge.text) - 1)
               return;
            if (!BYTESCAPTURED(model, *(p + offset), pbody->challenge.length))
               return;
            memcpy(&pbody->challenge.text, p + offset,
                pbody->challenge.length);
            offset += pbody->challenge.length;
         }
         pbody->challenge.text[pbody->challenge.length] = '\0';
         /* Present and not truncated */
         pbody->challenge_status = PRESENT;
         break;
      case E_RATES:
         /* Present, possibly truncated */
         pbody->rates_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 2))
            return;
         memcpy(&(pbody->rates), p + offset, 2);
         offset += 2;
         if (pbody->rates.length != 0) {
            if (pbody->rates.length > sizeof pbody->rates.rate)
               return;
            if (!BYTESCAPTURED(model, *(p + offset), pbody->rates.length))
               return;
            memcpy(&pbody->rates.rate, p + offset,
                pbody->rates.length);
            offset += pbody->rates.length;
         }
         /* Present and not truncated */
         pbody->rates_status = PRESENT;
         break;
      case E_DS:
         /* Present, possibly truncated */
         pbody->ds_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 3))
            return;
         memcpy(&pbody->ds, p + offset, 3);
         offset += 3;
         /* Present and not truncated */
         pbody->ds_status = PRESENT;
         break;
      case E_CF:
         /* Present, possibly truncated */
         pbody->cf_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 8))
            return;
         memcpy(&pbody->cf, p + offset, 8);
         offset += 8;
         /* Present and not truncated */
         pbody->cf_status = PRESENT;
         break;
      case E_TIM:
         /* Present, possibly truncated */
         pbody->tim_status = TRUNCATED;
         if (!BYTESCAPTURED(model, *(p + offset), 2))
            return;
         memcpy(&pbody->tim, p + offset, 2);
         offset += 2;
         if (!BYTESCAPTURED(model, *(p + offset), 3))
            return;
         memcpy(&pbody->tim.count, p + offset, 3);
         offset += 3;

         if (pbody->tim.length <= 3)
            break;
         if (pbody->tim.length - 3 > (int)sizeof pbody->tim.bitmap)
            return;
         if (!BYTESCAPTURED(model, *(p + (pbody->tim.length - 3)), (pbody->tim.length - 3)))
            return;
         memcpy(pbody->tim.bitmap, p + (pbody->tim.length - 3),
             (pbody->tim.length - 3));
         offset += pbody->tim.length - 3;
         /* Present and not truncated */
         pbody->tim_status = PRESENT;
         break;
      default:
         return;
      }
   }
}
