/*
 * Argus Software.  Argus files - Modeler
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusIsis.c#11 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusIsis
#define ArgusIsis
#endif


#include <ArgusModeler.h>

void ArgusUpdateIsisState (struct ArgusModelerStruct *, struct ArgusFlowStruct *, unsigned char);
void ArgusInitializeIsis (struct ArgusModelerStruct *, struct ArgusFlowStruct *);
void ArgusIsisFlowRecord (struct ArgusFlowStruct *, struct ArgusRecord *, unsigned char);
static int isis_cksum(const u_int16_t *, u_int);

#define ISIS_COMMON_HEADER_SIZE (sizeof(struct isis_common_header))
#define ISIS_IIH_LAN_HEADER_SIZE (sizeof(struct isis_iih_lan_header))
#define ISIS_IIH_PTP_HEADER_SIZE (sizeof(struct isis_iih_ptp_header))
#define ISIS_LSP_HEADER_SIZE (sizeof(struct isis_lsp_header))
#define ISIS_CSNP_HEADER_SIZE (sizeof(struct isis_csnp_header))
#define ISIS_PSNP_HEADER_SIZE (sizeof(struct isis_psnp_header))

int mask2plen (u_int32_t);

struct ArgusSystemFlow *ArgusCreateEtherFlow (struct ArgusModelerStruct *, struct ether_header *);


struct ArgusSystemFlow *
ArgusCreateEtherFlow (struct ArgusModelerStruct *model, struct ether_header *ep) 
{
   struct ArgusSystemFlow *retn = NULL;

   if (ep != NULL) {
      int dstgteq = 1, i;
      model->ArgusThisFlow->hdr.type             = ARGUS_FLOW_DSR;
      model->ArgusThisFlow->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
      model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ETHER;
      model->ArgusThisFlow->hdr.argus_dsrvl8.len  = 5;
#ifndef ETH_ALEN
#define ETH_ALEN   6
#endif
      for (i = 0; i < ETH_ALEN; i++) {
         if (((unsigned char *)&ep->ether_shost)[i] != ((unsigned char *)&ep->ether_dhost)[i])
            if (((unsigned char *)&ep->ether_shost)[i] > ((unsigned char *)&ep->ether_dhost)[i])
               dstgteq = 0;
            break;
      }

      if (dstgteq) {
         bcopy ((char *) ep, (char *)&model->ArgusThisFlow->mac_flow.ehdr, sizeof (struct ether_header));
      } else {
         model->state |= ARGUS_DIRECTION;
         bcopy ((char *)&ep->ether_shost, (char *)&model->ArgusThisFlow->mac_flow.ehdr.ether_dhost, ETH_ALEN);
         bcopy ((char *)&ep->ether_dhost, (char *)&model->ArgusThisFlow->mac_flow.ehdr.ether_shost, ETH_ALEN);
      }
      model->ArgusThisFlow->mac_flow.ehdr.ether_type = ep->ether_type;

      if (model->ArgusThisEncaps & ARGUS_ENCAPS_LLC) {
         model->ArgusThisFlow->mac_flow.ehdr.ether_type = 0;
         switch (model->ArgusThisNetworkFlowType & 0xFFFF) {
            case ARGUS_ISIS:
               model->ArgusThisFlow->mac_flow.ehdr.ether_type = ARGUS_ISIS;
               break;

            case ARGUS_CLNS:
            case ARGUS_ESIS:
            case ARGUS_NULLNS:
               break;

            default:
               model->ArgusThisNetworkFlowType &= ~(0xFFFF);
               break;
         }
         if (dstgteq) {
            model->ArgusThisFlow->mac_flow.ssap = model->ArgusThisLLC->ssap;
            model->ArgusThisFlow->mac_flow.dsap = model->ArgusThisLLC->dsap;
         } else {
            model->ArgusThisFlow->mac_flow.ssap = model->ArgusThisLLC->dsap;
            model->ArgusThisFlow->mac_flow.dsap = model->ArgusThisLLC->ssap;
         }
      } else {
         model->ArgusThisFlow->mac_flow.ssap = 0;
         model->ArgusThisFlow->mac_flow.dsap = 0;
      }

      retn = model->ArgusThisFlow;
   }

   return (retn);
}


/*
extern char *etheraddr_string(u_char *);
static char *isis_print_id(const u_int8_t *, int);
*/
char *bittok2str(const struct tok *, const char *, int);
const char *tok2str(const struct tok *lp, const char *fmt, int);
int print_unknown_data(const u_char *, const char *, int);


struct ArgusSystemFlow *
ArgusCreateIsisFlow (struct ArgusModelerStruct *model, struct isis_common_header *header) 
{
   struct ArgusSystemFlow *retn = NULL;
   struct ether_header *ep = model->ArgusThisEpHdr;
   u_int8_t pdu_type, *optr, *pptr;
   int length;

   if (header && STRUCTCAPTURED(ArgusModel, *header)) {
      length = model->ArgusThisLength;
      optr = (unsigned char *)header;
      pptr = optr + (ISIS_COMMON_HEADER_SIZE);

      if ((header->version == ISIS_VERSION) && (header->pdu_version == ISIS_VERSION) &&
         ((header->id_length == SYSTEM_ID_LEN) || (header->id_length == 0))) {

         struct ArgusIsisFlow *isis = &model->ArgusThisFlow->isis_flow;
/*
         id_length = (header->id_length == 0) ? 6 : header->id_length;
         max_area  = (header->max_area == 0) ? 3 : header->max_area;
*/
         model->ArgusThisFlow->hdr.type             = ARGUS_FLOW_DSR;
         model->ArgusThisFlow->hdr.subtype          = ARGUS_FLOW_CLASSIC5TUPLE;
         model->ArgusThisFlow->hdr.argus_dsrvl8.qual = ARGUS_TYPE_ISIS;
         model->ArgusThisFlow->hdr.argus_dsrvl8.len  = ((sizeof(*isis) + 3)/4) + 1;

         bcopy ((char *)&ep->ether_shost, (char *)&isis->esrc, 6);
         bcopy ((char *)&ep->ether_dhost, (char *)&isis->edst, 6);

	 isis->proto_version = header->version;

         switch (pdu_type = header->pdu_type) {
            case L1_LAN_IIH:
            case L2_LAN_IIH: {
               const struct isis_iih_lan_header *header_iih_lan = (const struct isis_iih_lan_header *)pptr;
               if (header->fixed_len == (ISIS_COMMON_HEADER_SIZE+ISIS_IIH_LAN_HEADER_SIZE)) {
                  isis->pdu_type = pdu_type;
                  bzero ((char *)&isis->isis_un.hello.srcid, sizeof(isis->isis_un.hello.srcid));
                  bzero ((char *)&isis->isis_un.hello.lanid, sizeof(isis->isis_un.hello.lanid));
                  bcopy ((char *)&header_iih_lan->source_id, (char *)&isis->isis_un.hello.srcid, SYSTEM_ID_LEN);
                  bcopy ((char *)&header_iih_lan->lan_id, (char *)&isis->isis_un.hello.lanid, NODE_ID_LEN);

                  retn = model->ArgusThisFlow;
                  {
                     u_int16_t *ptr = (u_int16_t *) (((long)pptr & 0x01) ? (pptr - 1) : pptr);
                     int tlen = (length - ISIS_COMMON_HEADER_SIZE);

                     if (BYTESCAPTURED(ArgusModel, ptr, tlen))
                        isis->chksum = isis_cksum(ptr, tlen);
                     else
                        isis->chksum =  0;
                  }
               }
               break; 
            }

            case L1_LSP:
            case L2_LSP: {
               const struct isis_lsp_header *header_lsp = (const struct isis_lsp_header *)pptr;
               if (header->fixed_len == (ISIS_COMMON_HEADER_SIZE+ISIS_LSP_HEADER_SIZE)) {
                  isis->pdu_type = pdu_type;
                  bcopy ((char *)&header_lsp->lsp_id, (char *)&isis->isis_un.lsp.lspid, LSP_ID_LEN);
                  isis->isis_un.lsp.seqnum = EXTRACT_32BITS(header_lsp->sequence_number);
		  isis->chksum = EXTRACT_16BITS(header_lsp->checksum);
                  retn = model->ArgusThisFlow;
               }
               break;
            }

            case PTP_IIH: {
               u_int16_t *ptr = (u_int16_t *) (((long)pptr & 0x01) ? (pptr - 1) : pptr);
               int tlen = (length - ISIS_COMMON_HEADER_SIZE);

               if (BYTESCAPTURED(ArgusModel, ptr, tlen))
                  isis->chksum = isis_cksum(ptr, tlen);
               else
                  isis->chksum =  0;
               break;
            }

            case L1_CSNP:
            case L2_CSNP: {
               const struct isis_csnp_header *header_csnp = (const struct isis_csnp_header *)pptr;
               if (header->fixed_len == (ISIS_COMMON_HEADER_SIZE+ISIS_CSNP_HEADER_SIZE)) {
                  isis->pdu_type = pdu_type;
                  bcopy ((char *)&header_csnp->source_id, (char *)&isis->isis_un.csnp.srcid, NODE_ID_LEN);
                  {
                     u_int16_t *ptr = (u_int16_t *) (((long)pptr & 0x01) ? (pptr - 1) : pptr);
                     int tlen = (length - ISIS_COMMON_HEADER_SIZE);

                     if (BYTESCAPTURED(ArgusModel, ptr, tlen))
                        isis->chksum = isis_cksum(ptr, tlen);
                     else
                        isis->chksum =  0;
                  }
                  retn = model->ArgusThisFlow;
               }
               break;
            }

            case L1_PSNP:
            case L2_PSNP: {
               const struct isis_psnp_header *header_psnp = (const struct isis_psnp_header *)pptr;
               if (header->fixed_len == (ISIS_COMMON_HEADER_SIZE+ISIS_PSNP_HEADER_SIZE)) {
                  isis->pdu_type = pdu_type;
                  bcopy ((char *)&header_psnp->source_id, (char *)&isis->isis_un.psnp.srcid, NODE_ID_LEN);
                  retn = model->ArgusThisFlow;
                  {
                     u_int16_t *ptr = (u_int16_t *) (((long)pptr & 0x01) ? (pptr - 1) : pptr);
                     int tlen = (length - ISIS_COMMON_HEADER_SIZE);

                     if (BYTESCAPTURED(ArgusModel, ptr, tlen))
                        isis->chksum = isis_cksum(ptr, tlen);
                     else
                        isis->chksum =  0;
                  }
               }
               break;
            }

            default:
               break;
         }
      }
   }

   if (retn == NULL)
      retn = ArgusCreateEtherFlow (model, ep);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusCreateIsisFlow (0x%x) returning %d\n", ep, retn);
#endif

   return (retn);
}


void
ArgusUpdateIsisState (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flowstr, unsigned char state)
{
   const struct isis_common_header *header = (const struct isis_common_header *) model->ArgusThisUpHdr;
   const u_int8_t *pptr;

   if (flowstr) {
      if (header && STRUCTCAPTURED(model, *header)) {
         pptr = model->ArgusThisUpHdr + (ISIS_COMMON_HEADER_SIZE);

         model->ArgusThisLength += 5;  /* fudge ? */
         model->ArgusSnapLength += 5;  /* fudge ? */

         if (state == ARGUS_START) {
            struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *) &flowstr->canon.net;
            net->hdr.type             = ARGUS_NETWORK_DSR;
            net->hdr.subtype          = ARGUS_ISIS_DSR;
            net->hdr.argus_dsrvl8.qual = 0;
            net->hdr.argus_dsrvl8.len  = (sizeof (struct ArgusIsisObject) + 3)/4;
            flowstr->dsrs[ARGUS_NETWORK_INDEX] = &flowstr->canon.net.hdr;
            bcopy ((char *)header, (char *)&flowstr->canon.net.net_union.isis.common, sizeof(*header));

            switch (header->pdu_type) {
               case L1_LAN_IIH:
               case L2_LAN_IIH: {
                  const struct isis_iih_lan_header *header_iih_lan;
                  header_iih_lan = (const struct isis_iih_lan_header *)pptr;
                  bcopy ((char *)header_iih_lan, (char *)&flowstr->canon.net.net_union.isis.isis_un.iih_lan,
                     sizeof(*header_iih_lan));
                  break;
               }

               case L1_LSP:
               case L2_LSP: {
                  const struct isis_lsp_header *header_lsp;
                  header_lsp = (const struct isis_lsp_header *)pptr;
                  bcopy ((char *)header_lsp, (char *)&flowstr->canon.net.net_union.isis.isis_un.lsp,
                     sizeof(*header_lsp));
                  break;
               }

               case PTP_IIH:
                  break;

               case L1_CSNP:
               case L2_CSNP: {
                  const struct isis_csnp_header *header_csnp;
                  header_csnp = (const struct isis_csnp_header *)pptr;
                  bcopy ((char *)header_csnp, (char *)&flowstr->canon.net.net_union.isis.isis_un.csnp,
                     sizeof(*header_csnp));
                  break;
               }

               case L1_PSNP:
               case L2_PSNP: {
                  const struct isis_psnp_header *header_psnp;
                  header_psnp = (const struct isis_psnp_header *)pptr;
                  bcopy ((char *)header_psnp, (char *)&flowstr->canon.net.net_union.isis.isis_un.psnp,
                     sizeof(*header_psnp));
                  break;
               }
            }

         } else {
            flowstr->userlen = 0;
         }
      }
   }

/*
   isis_print(model->ArgusThisUpHdr, model->ArgusThisLength);
   printf ("\n");
*/
}


void
ArgusInitializeIsis (struct ArgusModelerStruct *model, struct ArgusFlowStruct *flow)
{
/*
   unsigned char rev = flow->state.rev, dir = flow->state.dir;
   flow->ArgusTransactionNum = ArgusTransactionNum++;
                                                                                                                           
   bzero ((char *)&flow->state, sizeof(flow->state));
   flow->state.rev = rev;
   flow->state.dir = dir;
                                                                                                                           
   flow->state.src.active.minval = 0x7FFFFFFF;
   flow->state.dst.active.minval = 0x7FFFFFFF;
*/
                                                                                                                           
   flow->qhdr.lasttime.tv_sec  = 0;
   flow->qhdr.lasttime.tv_usec = 0;

   if (model->ArgusSrc->ArgusReadingOffLine)
      flow->qhdr.qtime = ArgusModel->ArgusGlobalTime;
   else
      gettimeofday(&flow->qhdr.qtime, 0L);
                                                                                                                           
   ArgusUpdateFlow (model, flow, ARGUS_START, 1);
}



void
ArgusIsisFlowRecord (struct ArgusFlowStruct *flow, struct ArgusRecord *argus, unsigned char state)
{
}


/*
static char *
print_nsap(register const u_int8_t *pptr, register int nsap_length)
{
   int nsap_idx;
   static char nsap_ascii_output[sizeof("xx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xxxx.xx")];
   char *junk_buf = nsap_ascii_output;

   if (nsap_length < 1 || nsap_length > 20) {
      snprintf(nsap_ascii_output, sizeof(nsap_ascii_output), "illegal length");
      return (nsap_ascii_output);
   }

   for (nsap_idx = 0; nsap_idx < nsap_length; nsap_idx++) {
      snprintf(junk_buf,
      sizeof(nsap_ascii_output) - (junk_buf - nsap_ascii_output), "%02x", *pptr++);
      junk_buf += strlen(junk_buf);
      if (((nsap_idx & 1) == 0) && (nsap_idx + 1 < nsap_length)) {
         *junk_buf++ = '.';
      }
   }
   *(junk_buf) = '\0';
   return (nsap_ascii_output);
}
*/


/* shared routine for printing system, node and lsp-ids */
/*
static char *
isis_print_id(const u_int8_t *cp, int id_len)
{
   int i;
   static char id[sizeof("xxxx.xxxx.xxxx.yy-zz")];
   char *pos = id;

   for (i = 1; i <= SYSTEM_ID_LEN; i++) {
      snprintf(pos, sizeof(id) - (pos - id), "%02x", *cp++);

   pos += strlen(pos);
   if (i == 2 || i == 4)
      *pos++ = '.';
   }
   if (id_len >= NODE_ID_LEN) {
      snprintf(pos, sizeof(id) - (pos - id), ".%02x", *cp++);
      pos += strlen(pos);
   }
   if (id_len == LSP_ID_LEN)
      snprintf(pos, sizeof(id) - (pos - id), "-%02x", *cp);

   return (id);
}
*/

/* print the 4-byte metric block which is common found in the old-style TLVs */
/*
static int
isis_print_metric_block (const struct isis_metric_block *isis_metric_block)
{
   printf(", Default Metric: %d, %s",
           ISIS_LSP_TLV_METRIC_VALUE(isis_metric_block->metric_default),
           ISIS_LSP_TLV_METRIC_IE(isis_metric_block->metric_default) ? "External" : "Internal");
   if (!ISIS_LSP_TLV_METRIC_SUPPORTED(isis_metric_block->metric_delay))
      printf("\n\t\t  Delay Metric: %d, %s",
               ISIS_LSP_TLV_METRIC_VALUE(isis_metric_block->metric_delay),
               ISIS_LSP_TLV_METRIC_IE(isis_metric_block->metric_delay) ? "External" : "Internal");
   if (!ISIS_LSP_TLV_METRIC_SUPPORTED(isis_metric_block->metric_expense))
      printf("\n\t\t  Expense Metric: %d, %s",
               ISIS_LSP_TLV_METRIC_VALUE(isis_metric_block->metric_expense),
               ISIS_LSP_TLV_METRIC_IE(isis_metric_block->metric_expense) ? "External" : "Internal");
   if (!ISIS_LSP_TLV_METRIC_SUPPORTED(isis_metric_block->metric_error))
      printf("\n\t\t  Error Metric: %d, %s",
               ISIS_LSP_TLV_METRIC_VALUE(isis_metric_block->metric_error),
               ISIS_LSP_TLV_METRIC_IE(isis_metric_block->metric_error) ? "External" : "Internal");
   return(1);
}

static int
isis_print_tlv_ip_reach (const u_int8_t *cp, const char *ident, int length)
{
   int prefix_len;
   const struct isis_tlv_ip_reach *tlv_ip_reach;

   tlv_ip_reach = (const struct isis_tlv_ip_reach *)cp;

   while (length > 0) {
      if ((size_t)length < sizeof(*tlv_ip_reach)) {
         printf("short IPv4 Reachability (%d vs %lu)", length, (unsigned long)sizeof(*tlv_ip_reach));
         return (0);
      }

      prefix_len = mask2plen(EXTRACT_32BITS(tlv_ip_reach->mask));

      if (prefix_len == -1)
         printf("%sIPv4 prefix: %s mask %s", ident,
                ipaddr_string((tlv_ip_reach->prefix)),
                ipaddr_string((tlv_ip_reach->mask)));
      else
         printf("%sIPv4 prefix: %15s/%u", ident,
                ipaddr_string((tlv_ip_reach->prefix)),
                prefix_len);

      printf(", Distribution: %s, Metric: %u, %s",
                       ISIS_LSP_TLV_METRIC_UPDOWN(tlv_ip_reach->isis_metric_block.metric_default) ? "down" : "up",
                       ISIS_LSP_TLV_METRIC_VALUE(tlv_ip_reach->isis_metric_block.metric_default),
                       ISIS_LSP_TLV_METRIC_IE(tlv_ip_reach->isis_metric_block.metric_default) ? "External" : "Internal");

      if (!ISIS_LSP_TLV_METRIC_SUPPORTED(tlv_ip_reach->isis_metric_block.metric_delay))
         printf("%s  Delay Metric: %u, %s",
                           ident,
                           ISIS_LSP_TLV_METRIC_VALUE(tlv_ip_reach->isis_metric_block.metric_delay),
                           ISIS_LSP_TLV_METRIC_IE(tlv_ip_reach->isis_metric_block.metric_delay) ? "External" : "Internal");
                
      if (!ISIS_LSP_TLV_METRIC_SUPPORTED(tlv_ip_reach->isis_metric_block.metric_expense))
         printf("%s  Expense Metric: %u, %s",
                           ident,
                           ISIS_LSP_TLV_METRIC_VALUE(tlv_ip_reach->isis_metric_block.metric_expense),
                           ISIS_LSP_TLV_METRIC_IE(tlv_ip_reach->isis_metric_block.metric_expense) ? "External" : "Internal");
                
      if (!ISIS_LSP_TLV_METRIC_SUPPORTED(tlv_ip_reach->isis_metric_block.metric_error))
         printf("%s  Error Metric: %u, %s",
                           ident,
                           ISIS_LSP_TLV_METRIC_VALUE(tlv_ip_reach->isis_metric_block.metric_error),
                           ISIS_LSP_TLV_METRIC_IE(tlv_ip_reach->isis_metric_block.metric_error) ? "External" : "Internal");

      length -= sizeof(struct isis_tlv_ip_reach);
      tlv_ip_reach++;
   }

   return (1);
}
*/

/*
 * this is the common IP-REACH subTLV decoder it is called
 * from various EXTD-IP REACH TLVs (135,235,236,237)
 */

/*
static int
isis_print_ip_reach_subtlv (const u_int8_t *tptr,int subt,int subl,const char *ident)
{
   printf ("%s%s subTLV #%u, length: %u", ident,
               tok2str(isis_ext_ip_reach_subtlv_values, "unknown", subt), subt, subl);

   switch(subt) {
      case SUBTLV_EXTD_IP_REACH_ADMIN_TAG32:
         while (subl >= 4) {
            printf (", 0x%08x (=%u)", EXTRACT_32BITS(tptr), EXTRACT_32BITS(tptr));
            tptr += 4;
            subl -= 4;
         }
         break;

      case SUBTLV_EXTD_IP_REACH_ADMIN_TAG64:
         while (subl >= 8) {
            printf (", 0x%08x%08x", EXTRACT_32BITS(tptr), EXTRACT_32BITS(tptr+4));
            tptr += 8;
            subl -= 8;
         }
         break;

      default:
         if (!print_unknown_data (tptr,"\n\t\t    ", subl))
            return (0);
         break;
    }

    return (1);
   
trunctlv:
    printf ("%spacket exceeded snapshot", ident);
    return (0);
}
*/


/*
 * this is the common IS-REACH subTLV decoder it is called
 * from isis_print_ext_is_reach()
 */

/*
static int
isis_print_is_reach_subtlv (const u_int8_t *tptr,int subt,int subl,const char *ident) {
   int priority_level;
   union {
      float f; 
      u_int32_t i;
   } bw;

   printf("%s%s subTLV #%u, length: %u", ident,
               tok2str(isis_ext_is_reach_subtlv_values, "unknown", subt), subt, subl);

   switch(subt) {
      case SUBTLV_EXT_IS_REACH_ADMIN_GROUP:      
      case SUBTLV_EXT_IS_REACH_LINK_LOCAL_REMOTE_ID:
      case SUBTLV_EXT_IS_REACH_LINK_REMOTE_ID:
      if (subl >= 4) {
         printf(", 0x%08x", EXTRACT_32BITS(tptr));
         if (subl == 8)
            printf(", 0x%08x", EXTRACT_32BITS(tptr+4));
      }
      break;

      case SUBTLV_EXT_IS_REACH_IPV4_INTF_ADDR:
      case SUBTLV_EXT_IS_REACH_IPV4_NEIGHBOR_ADDR:
         if (subl >= 4)
            printf(", %s", ipaddr_string(tptr));
         break;

      case SUBTLV_EXT_IS_REACH_MAX_LINK_BW :
      case SUBTLV_EXT_IS_REACH_RESERVABLE_BW:  
         if (subl >= 4) {
            bw.i = EXTRACT_32BITS(tptr);
            printf(", %.3f Mbps", bw.f*8/1000000 );
         }
         break;

      case SUBTLV_EXT_IS_REACH_UNRESERVED_BW :
         if (subl >= 32) {
            for (priority_level = 0; priority_level < 8; priority_level++) {
               bw.i = EXTRACT_32BITS(tptr);
               printf("%s  priority level %d: %.3f Mbps", ident, priority_level, bw.f*8/1000000 );
               tptr += 4;
            }
         }
         break;

      case SUBTLV_EXT_IS_REACH_TE_METRIC:
            if (subl >= 3)
              printf(", %u", EXTRACT_24BITS(tptr));
            break;
      case SUBTLV_EXT_IS_REACH_LINK_PROTECTION_TYPE:
            if (subl >= 2) {
              printf(", %s, Priority %u",
         bittok2str(gmpls_link_prot_values, "none", *tptr),
                   *(tptr+1));
            }
            break;
      case SUBTLV_EXT_IS_REACH_INTF_SW_CAP_DESCR:
         if (subl >= 36) {
            printf("%s  Interface Switching Capability:%s", ident,
                   tok2str(gmpls_switch_cap_values, "Unknown", *(tptr)));
            printf(", LSP Encoding: %s",
                   tok2str(gmpls_encoding_values, "Unknown", *(tptr+1)));
            tptr+=4;
            printf("%s  Max LSP Bandwidth:",ident);
            for (priority_level = 0; priority_level < 8; priority_level++) {
               bw.i = EXTRACT_32BITS(tptr);
               printf("%s    priority level %d: %.3f Mbps", ident,
                       priority_level,
                       bw.f*8/1000000 );
               tptr+=4;
            }
            subl-=36;
            if(subl>0){
               if(!print_unknown_data(tptr,"\n\t\t    ", subl-36))
                  return(0);
            }
         }
         break;

      default:
         if(!print_unknown_data(tptr,"\n\t\t    ", subl))
            return(0);
         break;
   }
   return(1);

trunctlv:
    printf("%spacket exceeded snapshot",ident);
    return(0);
}
*/


/*
 * this is the common IS-REACH decoder it is called
 * from various EXTD-IS REACH style TLVs (22,24,222)
 */

/*
static int
isis_print_ext_is_reach (const u_int8_t *tptr,const char *ident, int tlv_type)
{
   char ident_buffer[20];
   int subtlv_type,subtlv_len,subtlv_sum_len;
   int proc_bytes = 0;
    
   printf("%sIS Neighbor: %s", ident, isis_print_id(tptr, NODE_ID_LEN));
   tptr+=(NODE_ID_LEN);

   if (tlv_type != TLV_IS_ALIAS_ID) {
      printf(", Metric: %d",EXTRACT_24BITS(tptr));
      tptr += 3;
   }
        
   subtlv_sum_len = *(tptr++);
   proc_bytes = NODE_ID_LEN + 3 + 1;
   printf(", %ssub-TLVs present",subtlv_sum_len ? "" : "no ");
   if (subtlv_sum_len) {
      printf(" (%u)",subtlv_sum_len);
      while (subtlv_sum_len>0) {
         subtlv_type = *(tptr++);
         subtlv_len = *(tptr++);
         snprintf (ident_buffer, sizeof(ident_buffer), "%s  ",ident);
         if (!isis_print_is_reach_subtlv(tptr,subtlv_type,subtlv_len,ident_buffer))
            return (0);
         tptr += subtlv_len;
         subtlv_sum_len -= (subtlv_len+2);
         proc_bytes += (subtlv_len+2);
      }
   }
   return(proc_bytes);
}
*/


/*
 * this is the common Multi Topology ID decoder
 * it is called from various MT-TLVs (222,229,235,237)
 */

/*
static int
isis_print_mtid (const u_int8_t *tptr,const char *ident) {
    
   printf("%s%s", ident, tok2str(isis_mt_values,
                   "Reserved for IETF Consensus",
                   ISIS_MASK_MTID(EXTRACT_16BITS(tptr))));

   printf(" Topology (0x%03x), Flags: [%s]",
           ISIS_MASK_MTID(EXTRACT_16BITS(tptr)),
           bittok2str(isis_mt_flag_values, "none",ISIS_MASK_MTFLAGS(EXTRACT_16BITS(tptr))));

   return(2);
}
*/

/*
 * this is the common extended IP reach decoder
 * it is called from TLVs (135,235,236,237)
 * we process the TLV and optional subTLVs and return
 * the amount of processed bytes
 */

/*
static int
isis_print_extd_ip_reach (const u_int8_t *tptr, const char *ident, u_int16_t afi) {

    char ident_buffer[20];
    u_int8_t prefix[16];
    u_int metric, status_byte, bit_length, byte_length, sublen, processed, subtlvtype, subtlvlen;

    metric = EXTRACT_32BITS(tptr);
    processed=4;
    tptr+=4;
    
    if (afi == IPV4) {
        status_byte=*(tptr++);
        bit_length = status_byte&0x3f;
        processed++;
#ifdef INET6
    } else if (afi == IPV6) {
        status_byte=*(tptr++);
        bit_length=*(tptr++);
        processed+=2;
#endif
    } else
        return (0);

    byte_length = (bit_length + 7) / 8;
   
    memset(prefix, 0, 16);
    memcpy(prefix,tptr,byte_length);
    tptr+=byte_length;
    processed+=byte_length;

    if (afi == IPV4)
        printf("%sIPv4 prefix: %15s/%u",
               ident,
               ipaddr_string(prefix),
               bit_length);
#ifdef INET6
    if (afi == IPV6)
        printf("%sIPv6 prefix: %s/%u",
               ident,
               ip6addr_string(prefix),
               bit_length);
#endif 
   
    printf(", Distribution: %s, Metric: %u",
           ISIS_MASK_TLV_EXTD_IP_UPDOWN(status_byte) ? "down" : "up",
           metric);

    if (afi == IPV4 && ISIS_MASK_TLV_EXTD_IP_SUBTLV(status_byte))
        printf(", sub-TLVs present");
#ifdef INET6
    if (afi == IPV6)
        printf(", %s%s",
               ISIS_MASK_TLV_EXTD_IP6_IE(status_byte) ? "External" : "Internal",
               ISIS_MASK_TLV_EXTD_IP6_SUBTLV(status_byte) ? ", sub-TLVs present" : "");
#endif
    
    if ((ISIS_MASK_TLV_EXTD_IP_SUBTLV(status_byte)  && afi == IPV4) ||
        (ISIS_MASK_TLV_EXTD_IP6_SUBTLV(status_byte) && afi == IPV6)) {
        sublen=*(tptr++);
        processed+=sublen+1;
        printf(" (%u)",sublen);
        
        while (sublen>0) {
            subtlvtype=*(tptr++);
            subtlvlen=*(tptr++);
            snprintf(ident_buffer, sizeof(ident_buffer), "%s  ",ident);
            if(!isis_print_ip_reach_subtlv(tptr,subtlvtype,subtlvlen,ident_buffer))
                return(0);
            tptr+=subtlvlen;
            sublen-=(subtlvlen+2);
        }
    }
    return (processed);
}
*/


static int
isis_cksum(const u_int16_t *tptr, u_int len)
{
   int32_t c0 = 0, c1 = 0;
   len = (len + 1) / 2;

   while ((int)--len >= 0) {
#if defined(_LITTLE_ENDIAN)
      c0 += htons(*tptr++);
#else
      c0 += *tptr++;
#endif
      c0 %= 0xffff;
      c1 += c0;
      c1 %= 0xffff;
   }
   return (c0 | c1);
}


/*
 * Verify the checksum.  See 8473-1, Appendix C, section C.4.

static int
osi_cksum(const u_int8_t *tptr, u_int len)
{
   int32_t c0 = 0, c1 = 0;

   while ((int)--len >= 0) {
      c0 += *tptr++;
      c0 %= 255;
      c1 += c0;
      c1 %= 255;
   }
   return (c0 | c1);
}
 */

/* 
 * Convert a 32-bit netmask to prefixlen if possible
 * the function returns the prefix-len; if plen == -1
 * then conversion was not possible;
 */
 
int
mask2plen (u_int32_t mask)
{
        u_int32_t bitmasks[33] = {
                0x00000000,
                0x80000000, 0xc0000000, 0xe0000000, 0xf0000000,
                0xf8000000, 0xfc000000, 0xfe000000, 0xff000000,
                0xff800000, 0xffc00000, 0xffe00000, 0xfff00000,
                0xfff80000, 0xfffc0000, 0xfffe0000, 0xffff0000,
                0xffff8000, 0xffffc000, 0xffffe000, 0xfffff000,
                0xfffff800, 0xfffffc00, 0xfffffe00, 0xffffff00,
                0xffffff80, 0xffffffc0, 0xffffffe0, 0xfffffff0,
                0xfffffff8, 0xfffffffc, 0xfffffffe, 0xffffffff
        };
        int prefix_len = 32;

        /* let's see if we can transform the mask into a prefixlen */
        while (prefix_len >= 0) {
                if (bitmasks[prefix_len] == mask)
                        break;
                prefix_len--;
        }
        return (prefix_len);
}


/*
 *  this is a generic routine for printing unknown data;
 *  we pass on the linefeed plus indentation string to
 *  get a proper output - returns 0 on error
 */

int
print_unknown_data(const u_char *cp, const char *ident, int len)
{
   printf ("%s\n", ident);
   ArgusPrintHex(cp, len);
   return(1); /* everything is ok */
}

/*
 * Convert a token value to a string; use "fmt" if not found.
 */


const char *
tok2str(const struct tok *lp, const char *fmt, int v)
{
	static char buf[128];

	while (lp->s != NULL) {
		if (lp->v == v)
			return (lp->s);
		++lp;
	}
	if (fmt == NULL)
		fmt = "#%d";
	(void)snprintf(buf, sizeof(buf), fmt, v);
	return (buf);
}

/*
 * Convert a bit token value to a string; use "fmt" if not found.
 * this is useful for parsing bitfields, the output strings are comma seperated
 */


char *
bittok2str(const struct tok *lp, const char *fmt, int v)
{
        static char buf[256]; /* our stringbuffer */
        int buflen=0;
        register int rotbit; /* this is the bit we rotate through all bitpositions */
        register int tokval;

	while (lp->s != NULL) {
            tokval=lp->v;   /* load our first value */
            rotbit=1;
            while (rotbit != 0) {
                /*
                 * lets AND the rotating bit with our token value
                 * and see if we have got a match
                 */
		if (tokval == (v&rotbit)) {
                    /* ok we have found something */
                    buflen+=snprintf(buf+buflen, sizeof(buf)-buflen, "%s, ",lp->s);
                    break;
                }
                rotbit=rotbit<<1; /* no match - lets shift and try again */
            }
            lp++;
	}

        if (buflen != 0) { /* did we find anything */
            /* yep, set the the trailing zero 2 bytes before to eliminate the last comma & whitespace */
            buf[buflen-2] = '\0';
            return (buf);
        }
        else {
            /* bummer - lets print the "unknown" message as advised in the fmt string if we got one */
            if (fmt == NULL)
		fmt = "#%d";
            (void)snprintf(buf, sizeof(buf), fmt, v);
            return (buf);
        }
}
