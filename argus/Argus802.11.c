/*
 * Argus Software.  Argus files - Arp Procession
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
 * $Id: //depot/argus/argus/argus/Argus802.11.c#10 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
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

static void ArgusParse80211MgmtBody(struct mgmt_body_t *, const u_char *, int);
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

   u_int16_t fc = EXTRACT_LE_16BITS(ptr);
   int hdrlen = ArgusExtract802_11HeaderLength(fc);

   u_char *p = (u_char *) ptr + hdrlen;

   bzero(&pbody, sizeof(pbody));

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
               ArgusParse80211MgmtBody(&pbody, p, offset);
               break;

            case ST_ASSOC_RESPONSE:
            case ST_REASSOC_RESPONSE:
               pbody.capability_info = EXTRACT_LE_16BITS(p);
               offset += IEEE802_11_CAPINFO_LEN;
               pbody.status_code = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_STATUS_LEN;
               pbody.aid = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_AID_LEN;
               ArgusParse80211MgmtBody(&pbody, p, offset);
               break;

            case ST_PROBE_REQUEST:
               ArgusParse80211MgmtBody(&pbody, p, offset);
               break;

            case ST_PROBE_RESPONSE:
            case ST_BEACON: {
               memcpy(&pbody.timestamp, p, IEEE802_11_TSTAMP_LEN);
               offset += IEEE802_11_TSTAMP_LEN;
               pbody.beacon_interval = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_BCNINT_LEN;
               pbody.capability_info = EXTRACT_LE_16BITS(p+offset);
               offset += IEEE802_11_CAPINFO_LEN;
               ArgusParse80211MgmtBody(&pbody, p, offset);
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

   if (STRUCTCAPTURED(model, *(char *)ptr)) {
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
ArgusParse80211MgmtBody(struct mgmt_body_t *pbody, const u_char *p, int offset)
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
      switch (*(p + offset)) {
      case E_SSID:
         /* Present, possibly truncated */
         pbody->ssid_status = TRUNCATED;
         memcpy(&pbody->ssid, p + offset, 2);
         offset += 2;
         if (pbody->ssid.length != 0) {
            if (pbody->ssid.length >
                sizeof(pbody->ssid.ssid) - 1)
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
         memcpy(&pbody->challenge, p + offset, 2);
         offset += 2;
         if (pbody->challenge.length != 0) {
            if (pbody->challenge.length >
                sizeof(pbody->challenge.text) - 1)
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
         memcpy(&(pbody->rates), p + offset, 2);
         offset += 2;
         if (pbody->rates.length != 0) {
            if (pbody->rates.length > sizeof pbody->rates.rate)
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
         memcpy(&pbody->ds, p + offset, 3);
         offset += 3;
         /* Present and not truncated */
         pbody->ds_status = PRESENT;
         break;
      case E_CF:
         /* Present, possibly truncated */
         pbody->cf_status = TRUNCATED;
         memcpy(&pbody->cf, p + offset, 8);
         offset += 8;
         /* Present and not truncated */
         pbody->cf_status = PRESENT;
         break;
      case E_TIM:
         /* Present, possibly truncated */
         pbody->tim_status = TRUNCATED;
         memcpy(&pbody->tim, p + offset, 2);
         offset += 2;
         memcpy(&pbody->tim.count, p + offset, 3);
         offset += 3;

         if (pbody->tim.length <= 3)
            break;
         if (pbody->tim.length - 3 > (int)sizeof pbody->tim.bitmap)
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
