/*
 * Argus Software.  Common library routines - Utilities
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
 * $Id: //depot/argus/argus/common/argus_util.c#85 $
 * $DateTime: 2015/08/05 22:33:18 $
 * $Change: 3042 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef argus_util
#define argus_util
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>

#if (HAVE_SYSLOG_H)
#include <syslog.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>

#include <netinet/in.h>
#include <net/if.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <rpc/types.h>

#if defined(HAVE_XDR)
#include <rpc/xdr.h>
#endif

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

#include <string.h>
#include <argus_compat.h>

#include <argus.h>
#include <argus_os.h>
#include <argus_parser.h>

#include <ArgusModeler.h>

#include <argus_ethertype.h>
#include <argus_dscodepoints.h>
#include <argus_encapsulations.h>



#if defined(AIX)
#include <time.h>
#endif

#ifndef AF_INET6
#define AF_INET6	23
#endif

#ifdef HAVE_ETHER_HOSTTON
/*
 * XXX - do we need any of this if <netinet/if_ether.h> doesn't declare
 * ether_hostton()?
 */
#ifdef HAVE_NETINET_IF_ETHER_H
struct mbuf;            /* Squelch compiler warnings on some platforms for */
struct rtentry;         /* declarations in <net/if.h> */
#include <net/if.h>     /* for "struct ifnet" in "struct arpcom" on Solaris */
#include <netinet/if_ether.h>
#endif /* HAVE_NETINET_IF_ETHER_H */
#ifdef NETINET_ETHER_H_DECLARES_ETHER_HOSTTON
#include <netinet/ether.h>
#endif /* NETINET_ETHER_H_DECLARES_ETHER_HOSTTON */
#endif /* HAVE_ETHER_HOSTTON */


extern char *ArgusProgramName;

void ArgusInitAddrtoname(struct ArgusParserStruct *, u_int, u_int);
void ArgusInitServarray(struct ArgusParserStruct *);
void ArgusInitEprotoarray(struct ArgusParserStruct *);
void ArgusInitProtoidarray(struct ArgusParserStruct *);
void ArgusInitEtherarray(struct ArgusParserStruct *);
void ArgusInitLlcsaparray(struct ArgusParserStruct *);

void ArgusFreeEtherarray(struct ArgusParserStruct *);
void ArgusFreeServarray(struct ArgusParserStruct *);
void ArgusFreeProtoidarray(struct ArgusParserStruct *);
void ArgusFreeLlcsaparray(struct ArgusParserStruct *);

u_int ipaddrtonetmask(u_int);
u_int getnetnumber( u_int);

 
struct ArgusParserStruct *
ArgusNewParser(char *progname)
{
   struct ArgusParserStruct *retn = NULL;
 
   if ((retn  = (struct ArgusParserStruct *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewParser(%s) ArgusCalloc error %s", progname, strerror(errno));
 
   retn->ArgusCIDRPtr = &retn->ArgusCIDRBuffer;
   ArgusInitAddrtoname (retn, 0L, 0L);
   retn->pflag = 6;

   return (retn);
}

void
ArgusCloseParser(struct ArgusParserStruct *parser)
{
   ArgusFreeEtherarray(parser);
   ArgusFreeServarray(parser);
   ArgusFreeProtoidarray(parser);
   ArgusFreeLlcsaparray(parser);
/*
   ArgusFreeEprotoarray(parser);
   ArgusFreeDSCodepointarray(parser);
*/
}


void
ArgusAdjustGlobalTime (struct timeval *global, struct timeval *now)
{
   struct timeval ArgusTimeDelta;

   ArgusTimeDelta.tv_sec  = now->tv_sec  - global->tv_sec;
   ArgusTimeDelta.tv_usec = now->tv_usec - global->tv_usec;
 
   global->tv_sec  = now->tv_sec  - ArgusTimeDelta.tv_sec;
   global->tv_usec = now->tv_usec - ArgusTimeDelta.tv_usec;
 
   if (global->tv_usec < 0) {
      global->tv_sec--;
      global->tv_usec += 1000000;
   } else {
      if (global->tv_usec > 1000000) {
         global->tv_sec++;
         global->tv_usec -= 1000000;
      }
   }
}

extern char *print_time(struct timeval *);


#ifdef ARGUSDEBUG
void ArgusDebug (int d, char *fmt, ...);

#include <sys/time.h>

void
ArgusDebug (int d, char *fmt, ...)
{
   struct timeval now;
   extern int Argusdflag, daemonflag;
   char buf[MAXSTRLEN], *ptr;
   va_list ap;

   if (d <= Argusdflag) {
      va_start (ap, fmt);

      gettimeofday (&now, 0L);

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusMainLock);
      {
         pthread_t ptid;
         char pbuf[128];
         int i;

         bzero(pbuf, sizeof(pbuf));
         ptid = pthread_self();
         for (i = 0; i < sizeof(ptid); i++) {
            snprintf (&pbuf[i*2], 3, "%02hhx", ((char *)&ptid)[i]);
         }
         (void) snprintf (buf, MAXSTRLEN, "%s[%d.%s]: %s ", ArgusProgramName, (int)getpid(), pbuf, print_time(&now));
      }
      ptr = &buf[strlen(buf)];

      (void) vsnprintf (ptr, 1024, fmt, ap);
      ptr = &buf[strlen(buf)];
      if (*fmt) {
         fmt += (int) strlen (fmt);
         if (fmt[-1] != '\n')
            snprintf (ptr, 2, "\n");
      }

      if (daemonflag) {
#ifdef HAVE_SYSLOG
         syslog (LOG_ALERT, "%s", buf);
#endif
      } else
         fprintf (stderr, "%s", buf);

      pthread_mutex_unlock(&ArgusMainLock);
#else
      (void) snprintf (buf, MAXSTRLEN, "%s[%d]: %s ", ArgusProgramName, (int)getpid(), print_time(&now));
      ptr = &buf[strlen(buf)];

      (void) vsnprintf (ptr, 1024, fmt, ap);
      ptr = &buf[strlen(buf)];
      if (*fmt) {
         fmt += (int) strlen (fmt);
         if (fmt[-1] != '\n')
            snprintf (ptr, 2, "\n");
      }

      if (daemonflag) {
#ifdef HAVE_SYSLOG
         syslog (LOG_ALERT, "%s", buf);
#endif
      } else
         fprintf (stderr, "%s", buf);
#endif
      va_end (ap);
   }
}
#endif

#include <math.h>
#if !defined(HAVE_STRTOF) && !defined(CYGWIN)
float strtof (char *, char **);
 
float
strtof (char *str, char **ptr)
{
   double ipart = 0.0, fpart = 0.0, multi = 0.0;
   float retn = 0.0;
   char *dptr;
   int i;
 
   if ((dptr = strchr (str, '.')) != NULL) {
      int len = 0;
      *dptr++ = 0;
      len = strlen(dptr);
      i = atoi(dptr);
      multi = pow(10.0, len * 1.0);
      fpart = i * 1.0/multi;
   }

   ipart = atoi(str);

   retn = ipart + fpart;
   return(retn);
}
#endif

void ArgusPrintHex (const u_char *, u_int);

#if !defined(ntohll)
  #if defined(_LITTLE_ENDIAN)
    #if defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__) || defined(__sun__)
      #include <argus/extract.h>
      #define ntohll(x) EXTRACT_64BITS(&x)
      #define htonll(x) EXTRACT_64BITS(&x)
    #else
      #include <byteswap.h>
      #define ntohll(x) bswap_64(x)
      #define htonll(x) bswap_64(x)
    #endif
  #else
    #define ntohll(x) x
    #define htonll(x) x
  #endif
#endif

void ArgusNtoH (struct ArgusRecord *);
void ArgusHtoN (struct ArgusRecord *);

#include <argus_def.h>

void
ArgusNtoH (struct ArgusRecord *argus)
{
#if defined(_LITTLE_ENDIAN)
   struct ArgusRecordHeader *hdr = &argus->hdr;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) (hdr + 1);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         argus->hdr.len = ntohs(argus->hdr.len);
         argus->argus_mar.status            = ntohl(argus->argus_mar.status);
         argus->argus_mar.argusid            = ntohl(argus->argus_mar.argusid);
         argus->argus_mar.localnet          = ntohl(argus->argus_mar.localnet);
         argus->argus_mar.netmask           = ntohl(argus->argus_mar.netmask);
         argus->argus_mar.nextMrSequenceNum = ntohl(argus->argus_mar.nextMrSequenceNum);
         argus->argus_mar.startime.tv_sec   = ntohl(argus->argus_mar.startime.tv_sec);
         argus->argus_mar.startime.tv_usec  = ntohl(argus->argus_mar.startime.tv_usec);
         argus->argus_mar.now.tv_sec        = ntohl(argus->argus_mar.now.tv_sec);
         argus->argus_mar.now.tv_usec       = ntohl(argus->argus_mar.now.tv_usec);
         argus->argus_mar.reportInterval    = ntohs(argus->argus_mar.reportInterval);
         argus->argus_mar.argusMrInterval    = ntohs(argus->argus_mar.argusMrInterval);

         argus->argus_mar.pktsRcvd          = ntohll(argus->argus_mar.pktsRcvd);
         argus->argus_mar.bytesRcvd         = ntohll(argus->argus_mar.bytesRcvd);
         argus->argus_mar.drift             = ntohll(argus->argus_mar.drift);

         argus->argus_mar.records           = ntohl(argus->argus_mar.records);
         argus->argus_mar.flows             = ntohl(argus->argus_mar.flows);
         argus->argus_mar.dropped           = ntohl(argus->argus_mar.dropped);
         argus->argus_mar.queue             = ntohl(argus->argus_mar.queue);
         argus->argus_mar.output            = ntohl(argus->argus_mar.output);
         argus->argus_mar.clients           = ntohl(argus->argus_mar.clients);
         argus->argus_mar.bufs              = ntohl(argus->argus_mar.bufs);
         argus->argus_mar.bytes             = ntohl(argus->argus_mar.bytes);

         argus->argus_mar.thisid            = ntohl(argus->argus_mar.thisid);
         argus->argus_mar.record_len        = ntohl(argus->argus_mar.record_len);
         break;
      }

      case ARGUS_EVENT: {
         struct ArgusDSRHeader       *event = (struct ArgusDSRHeader *)&argus->argus_event.event;
         struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *)&argus->argus_event.trans;
         struct ArgusEventTimeStruct  *time = (struct ArgusEventTimeStruct *)&argus->argus_event.time;
         struct ArgusDataStruct       *data = (struct ArgusDataStruct *)&argus->argus_event.data;

         event->argus_dsrfl.data = ntohs(event->argus_dsrfl.data);

         if (trans->hdr.subtype & ARGUS_SEQ)
            trans->seqnum = ntohl(trans->seqnum);

         if (trans->hdr.subtype & ARGUS_SRCID) {
            switch (trans->hdr.argus_dsrvl8.qual) {
               case ARGUS_TYPE_INT:
                  trans->srcid.a_un.value = ntohl(trans->srcid.a_un.value);
                  break;
               case ARGUS_TYPE_IPV4:
                  trans->srcid.a_un.ipv4  = ntohl(trans->srcid.a_un.ipv4);
                  break;

               case ARGUS_TYPE_IPV6:
               case ARGUS_TYPE_ETHER:
               case ARGUS_TYPE_STRING:
                  break;
            }
         }

         time->start.tv_sec  = ntohl(time->start.tv_sec);
         time->start.tv_usec = ntohl(time->start.tv_usec);
         time->duration      = ntohl(time->duration);

         if (data->hdr.subtype & ARGUS_LEN_16BITS)
            data->hdr.argus_dsrvl16.len = ntohs(data->hdr.argus_dsrvl16.len);

         data->size  = ntohs(data->size);
         data->count = ntohs(data->count);
         break;
      }


      case ARGUS_FAR: {
         hdr->len = ntohs(hdr->len);
         if (hdr->len > 1) {
            int cnt;
            while ((char *) dsr < ((char *) argus + (hdr->len * 4))) {
               switch (dsr->type & 0x7F) {
                  case ARGUS_FLOW_DSR: {
                     struct ArgusFlow *flow = (struct ArgusFlow *) dsr;

                     switch (flow->hdr.subtype & 0x3F) {
                        case ARGUS_FLOW_CLASSIC5TUPLE: {
                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_IPV4:
                                 flow->ip_flow.ip_src = ntohl(flow->ip_flow.ip_src);
                                 flow->ip_flow.ip_dst = ntohl(flow->ip_flow.ip_dst);
                                 switch (flow->ip_flow.ip_p) {
                                    case IPPROTO_TCP:
                                    case IPPROTO_UDP:
                                       flow->ip_flow.sport = ntohs(flow->ip_flow.sport);
                                       flow->ip_flow.dport = ntohs(flow->ip_flow.dport);
                                       break;
                                    case IPPROTO_ESP:
                                       flow->esp_flow.spi = ntohl(flow->esp_flow.spi);
                                       break;
                                    case IPPROTO_IGMP:
                                       flow->igmp_flow.ip_id = ntohs(flow->igmp_flow.ip_id);
                                       break;
                                 }
                                 break; 

                              case ARGUS_TYPE_IPV6: {
                                 unsigned int *iptr = (unsigned int *)&flow->ipv6_flow;
                                 iptr[8] = ntohl(iptr[8]);

                                 if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {
                                    flow->fragv6_flow.ip_id = ntohl(flow->fragv6_flow.ip_id);
                                 } else {
                                    switch (flow->ipv6_flow.ip_p) {
                                       case IPPROTO_TCP:
                                       case IPPROTO_UDP:
                                          flow->ipv6_flow.sport = ntohs(flow->ipv6_flow.sport);
                                          flow->ipv6_flow.dport = ntohs(flow->ipv6_flow.dport);
                                          break;
                                       case IPPROTO_ESP:
                                          flow->esp6_flow.spi = ntohl(flow->esp6_flow.spi);
                                          break;
                                    }
                                 }
                                 break; 
                              }

                              case ARGUS_TYPE_ETHER: {
                                 struct ArgusEtherMacFlow *mac = (struct ArgusEtherMacFlow *) &flow->mac_flow;
                                 mac->ehdr.ether_type = ntohs(mac->ehdr.ether_type);
                                 break;
                              }

                              case ARGUS_TYPE_ISIS: {
                                 struct ArgusIsisFlow *isis = (struct ArgusIsisFlow *) &flow->isis_flow;
                                 switch (isis->pdu_type = ntohl(isis->pdu_type)) {
                                    case L1_LAN_IIH:
                                    case L2_LAN_IIH:
                                       break;

                                    case L1_CSNP:
                                    case L2_CSNP:
                                       break;

                                    case L1_PSNP:
                                    case L2_PSNP:
                                       break;

                                    case L1_LSP:
                                    case L2_LSP:
                                       isis->isis_un.lsp.seqnum = ntohl(isis->isis_un.lsp.seqnum);
                                       break;
                                 }
                                 isis->chksum = ntohl(isis->chksum);
                                 break;
                              }
                           }
                           break; 
                        }

                        case ARGUS_FLOW_ARP: {
                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_RARP: {
                                 struct ArgusRarpFlow *rarp = (struct ArgusRarpFlow *) &flow->rarp_flow;
                                 rarp->hrd = ntohs(rarp->hrd);
                                 rarp->pro = ntohs(rarp->pro);
                                 rarp->op  = ntohs(rarp->op);
                                 if (rarp->pln == 4) {
                                    rarp->arp_tpa = ntohl(rarp->arp_tpa);
                                 }
                                 break;
                              }
                              case ARGUS_TYPE_ARP: {
                                 struct ArgusArpFlow *arp = (struct ArgusArpFlow *) &flow->arp_flow;
                                 arp->hrd = ntohs(arp->hrd);
                                 arp->pro = ntohs(arp->pro);
                                 arp->op  = ntohs(arp->op);
                                 if (arp->pln == 4) {
                                    arp->arp_spa = ntohl(arp->arp_spa);
                                    arp->arp_tpa = ntohl(arp->arp_tpa);
                                 }
                                 break;
                              }
                           }
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_ENCAPS_DSR: {
                     struct ArgusEncapsStruct *encaps = (struct ArgusEncapsStruct *) dsr;
                     encaps->src = ntohl(encaps->src);
                     encaps->dst = ntohl(encaps->dst);
                     break;
                  }

                  case ARGUS_IPATTR_DSR: {
                     struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
                     unsigned int *dsrptr = (unsigned int *)(dsr + 1);

                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) {
                        struct ArgusIPAttrObject *aobj = (struct ArgusIPAttrObject *) dsrptr;
                        aobj->ip_id = ntohs(aobj->ip_id);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS) {
                        *dsrptr = ntohl(*dsrptr);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) {
                        struct ArgusIPAttrObject *aobj = (struct ArgusIPAttrObject *) dsrptr;
                        aobj->ip_id = ntohs(aobj->ip_id);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS) {
                        *dsrptr = ntohl(*dsrptr);
                        dsrptr++;
                     }
                     break;
                  }

                  case ARGUS_ICMP_DSR: {
                     struct ArgusIcmpStruct *icmp = (struct ArgusIcmpStruct *) dsr;
                     icmp->iseq      = ntohs(icmp->iseq);
                     icmp->osrcaddr  = ntohl(icmp->osrcaddr);
                     icmp->odstaddr  = ntohl(icmp->odstaddr);
                     icmp->isrcaddr  = ntohl(icmp->isrcaddr);
                     icmp->idstaddr  = ntohl(icmp->idstaddr);
                     icmp->igwaddr   = ntohl(icmp->igwaddr);
                     break;
                  }

                  case ARGUS_TRANSPORT_DSR: {
                     struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;

                     if (trans->hdr.subtype & ARGUS_SEQ)
                           trans->seqnum = ntohl(trans->seqnum);

                     if (trans->hdr.subtype & ARGUS_SRCID) {
                        switch (trans->hdr.argus_dsrvl8.qual) {
                           case ARGUS_TYPE_INT:
                              trans->srcid.a_un.value = ntohl(trans->srcid.a_un.value);
                              break;
                           case ARGUS_TYPE_IPV4:
                              trans->srcid.a_un.value = ntohl(trans->srcid.a_un.value);
                              break;

                           case ARGUS_TYPE_IPV6:
                           case ARGUS_TYPE_ETHER:
                           case ARGUS_TYPE_STRING:
                              break;
                        }
                     }
                     break;
                  }

                  case ARGUS_TIME_DSR: {
                     unsigned int x, *dtime = (unsigned int *) dsr; 
       
                     for (x = 1; x < dsr->argus_dsrvl8.len; x++)
                        dtime[x] = ntohl(dtime[x]);
                     break; 
                  }

                  case ARGUS_METER_DSR: {
                     if (dsr->subtype & ARGUS_METER_PKTS_BYTES) {
                        switch (dsr->argus_dsrvl8.qual & 0x0F) {
                           case ARGUS_SRCDST_BYTE:
                              break;
                           case ARGUS_SRCDST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = ntohs(((unsigned short *)(dsr + 1))[2]);
                              ((unsigned short *)(dsr + 1))[3] = ntohs(((unsigned short *)(dsr + 1))[3]);
                              break;
                           case ARGUS_SRCDST_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = ntohl(((unsigned int *)(dsr + 1))[2]);
                              ((unsigned int *)(dsr + 1))[3] = ntohl(((unsigned int *)(dsr + 1))[3]);
                              break;
                           case ARGUS_SRC_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              break;
                           case ARGUS_SRC_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              break;
                           case ARGUS_SRC_LONGLONG:
                              break;
                           case ARGUS_DST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              break;
                           case ARGUS_DST_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              break;
                        }

                     } else 
                     if (dsr->subtype & ARGUS_METER_PKTS_BYTES_APP) {
                        switch (dsr->argus_dsrvl8.qual & 0x0F) {
                           case ARGUS_SRCDST_BYTE:
                           case ARGUS_SRC_BYTE:
                           case ARGUS_DST_BYTE:
                              break;
                           case ARGUS_SRCDST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = ntohs(((unsigned short *)(dsr + 1))[2]);
                              ((unsigned short *)(dsr + 1))[3] = ntohs(((unsigned short *)(dsr + 1))[3]);
                              ((unsigned short *)(dsr + 1))[4] = ntohs(((unsigned short *)(dsr + 1))[4]);
                              ((unsigned short *)(dsr + 1))[5] = ntohs(((unsigned short *)(dsr + 1))[5]);
                              break;
                           case ARGUS_SRCDST_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = ntohl(((unsigned int *)(dsr + 1))[2]);
                              ((unsigned int *)(dsr + 1))[3] = ntohl(((unsigned int *)(dsr + 1))[3]);
                              ((unsigned int *)(dsr + 1))[4] = ntohl(((unsigned int *)(dsr + 1))[4]);
                              ((unsigned int *)(dsr + 1))[5] = ntohl(((unsigned int *)(dsr + 1))[5]);
                              break;
                           case ARGUS_SRC_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = ntohs(((unsigned short *)(dsr + 1))[2]);
                              break;
                           case ARGUS_SRC_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = ntohl(((unsigned int *)(dsr + 1))[2]);
                              break;
                           case ARGUS_SRC_LONGLONG:
                              break;
                           case ARGUS_DST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = ntohs(((unsigned short *)(dsr + 1))[2]);
                              break;
                           case ARGUS_DST_INT:
                              ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = ntohl(((unsigned int *)(dsr + 1))[2]);
                              break;
                        }
                     }
                     break;
                  }

                  case ARGUS_PSIZE_DSR: {
                     switch (dsr->argus_dsrvl8.qual & 0x0F) {
                        case ARGUS_SRCDST_SHORT:
                           ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                           ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                           ((unsigned short *)(dsr + 1))[2] = ntohs(((unsigned short *)(dsr + 1))[2]);
                           ((unsigned short *)(dsr + 1))[3] = ntohs(((unsigned short *)(dsr + 1))[3]);
                           break;

                        case ARGUS_SRC_SHORT:
                        case ARGUS_DST_SHORT:
                           ((unsigned short *)(dsr + 1))[0] = ntohs(((unsigned short *)(dsr + 1))[0]);
                           ((unsigned short *)(dsr + 1))[1] = ntohs(((unsigned short *)(dsr + 1))[1]);
                           break;

                        case ARGUS_SRCDST_INT:
                           ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                           ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                           ((unsigned int *)(dsr + 1))[2] = ntohl(((unsigned int *)(dsr + 1))[2]);
                           ((unsigned int *)(dsr + 1))[3] = ntohl(((unsigned int *)(dsr + 1))[3]);
                           break;

                        case ARGUS_SRC_INT:
                        case ARGUS_DST_INT:
                           ((unsigned int *)(dsr + 1))[0] = ntohl(((unsigned int *)(dsr + 1))[0]);
                           ((unsigned int *)(dsr + 1))[1] = ntohl(((unsigned int *)(dsr + 1))[1]);
                           break;
                     }
                     break;
                  }

                  case ARGUS_NETWORK_DSR: {
                     struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                     switch (net->hdr.subtype) {
                        case ARGUS_TCP_INIT: {
                           struct ArgusTCPInitStatus *tcp = (void *)&net->net_union.tcpstatus;
                           tcp->status       = ntohl(tcp->status);
                           tcp->seqbase      = ntohl(tcp->seqbase);
                           tcp->options      = ntohl(tcp->options);
                           tcp->win          = ntohs(tcp->win);
                           break;
                        }
                        case ARGUS_TCP_STATUS: {
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                           tcp->status       = ntohl(tcp->status);
                           break;
                        }
                        case ARGUS_TCP_PERF: {
                           struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                           tcp->status       = ntohl(tcp->status);
                           tcp->state        = ntohl(tcp->state);
                           tcp->options      = ntohl(tcp->options);
                           tcp->synAckuSecs  = ntohl(tcp->synAckuSecs);
                           tcp->ackDatauSecs = ntohl(tcp->ackDatauSecs);

                           tcp->src.lasttime.tv_sec  = ntohl(tcp->src.lasttime.tv_sec);
                           tcp->src.lasttime.tv_usec = ntohl(tcp->src.lasttime.tv_usec);
                           tcp->src.status = ntohl(tcp->src.status);
                           tcp->src.seqbase = ntohl(tcp->src.seqbase);
                           tcp->src.seq = ntohl(tcp->src.seq);
                           tcp->src.ack = ntohl(tcp->src.ack);
                           tcp->src.winnum = ntohl(tcp->src.winnum);
                           tcp->src.bytes = ntohl(tcp->src.bytes);
                           tcp->src.retrans = ntohl(tcp->src.retrans);
                           tcp->src.ackbytes = ntohl(tcp->src.ackbytes);
                           tcp->src.winbytes = ntohl(tcp->src.winbytes);
                           tcp->src.win = ntohs(tcp->src.win);

                           if (dsr->argus_dsrvl8.len > (((sizeof(struct ArgusTCPObject) - sizeof(struct ArgusTCPObjectMetrics))+3)/4 + 1)) {
                              tcp->dst.lasttime.tv_sec  = ntohl(tcp->dst.lasttime.tv_sec);
                              tcp->dst.lasttime.tv_usec = ntohl(tcp->dst.lasttime.tv_usec);
                              tcp->dst.status = ntohl(tcp->dst.status);
                              tcp->dst.seqbase = ntohl(tcp->dst.seqbase);
                              tcp->dst.seq = ntohl(tcp->dst.seq);
                              tcp->dst.ack = ntohl(tcp->dst.ack);
                              tcp->dst.winnum = ntohl(tcp->dst.winnum);
                              tcp->dst.bytes = ntohl(tcp->dst.bytes);
                              tcp->dst.retrans = ntohl(tcp->dst.retrans);
                              tcp->dst.ackbytes = ntohl(tcp->dst.ackbytes);
                              tcp->dst.winbytes = ntohl(tcp->dst.winbytes);
                              tcp->dst.win = ntohs(tcp->dst.win);
                           }
                           break;
                        }

                        case ARGUS_ESP_DSR: {
                           struct ArgusESPObject *espObj = (struct ArgusESPObject *)&net->net_union.esp;
                           espObj->status  = ntohl(espObj->status);
                           espObj->spi     = ntohl(espObj->spi);
                           espObj->lastseq = ntohl(espObj->lastseq);
                           espObj->lostseq = ntohl(espObj->lostseq);
                           break;
                        }
                        case ARGUS_RTP_FLOW: {
                           struct ArgusRTPObject *rtpObj = (struct ArgusRTPObject *)&net->net_union.rtp;
                           rtpObj->state       = ntohl(rtpObj->state);
                           rtpObj->src.rh_seq  = ntohs(rtpObj->src.rh_seq);
                           rtpObj->src.rh_time = ntohl(rtpObj->src.rh_time);
                           rtpObj->src.rh_ssrc = ntohl(rtpObj->src.rh_ssrc);

                           rtpObj->dst.rh_seq  = ntohs(rtpObj->dst.rh_seq);
                           rtpObj->dst.rh_time = ntohl(rtpObj->dst.rh_time);
                           rtpObj->dst.rh_ssrc = ntohl(rtpObj->dst.rh_ssrc);

                           rtpObj->sdrop       = ntohs(rtpObj->sdrop);
                           rtpObj->ddrop       = ntohs(rtpObj->ddrop);
                           rtpObj->ssdev       = ntohs(rtpObj->ssdev);
                           rtpObj->dsdev       = ntohs(rtpObj->dsdev);
                           break;
                        }
                        case ARGUS_RTCP_FLOW: {
                           struct ArgusRTCPObject *rtcpObj = (struct ArgusRTCPObject *)&net->net_union.rtcp;
                           rtcpObj->src.rh_len   = ntohs(rtcpObj->src.rh_len);
                           rtcpObj->src.rh_ssrc  = ntohl(rtcpObj->src.rh_ssrc);

                           rtcpObj->dst.rh_len   = ntohs(rtcpObj->dst.rh_len);
                           rtcpObj->dst.rh_ssrc  = ntohl(rtcpObj->dst.rh_ssrc);

                           rtcpObj->sdrop = ntohs(rtcpObj->sdrop);
                           rtcpObj->ddrop = ntohs(rtcpObj->ddrop);
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_VLAN_DSR: {
                     struct ArgusVlanStruct *vlan = (struct ArgusVlanStruct *) dsr;
                     vlan->sid = ntohs(vlan->sid);
                     vlan->did = ntohs(vlan->did);
                     break;
                  }

                  case ARGUS_MPLS_DSR: {
                     struct ArgusMplsStruct *mpls = (struct ArgusMplsStruct *) dsr;
                     unsigned int *label = (unsigned int *)(dsr + 1);
                     int num, i;

                     if ((num = ((mpls->hdr.argus_dsrvl8.qual & 0xF0) >> 4)) > 0) {
                        for (i = 0; i < num; i++) {
                           *label = ntohl(*label);
                           label++;
                        }
                     }
                     if ((num = (mpls->hdr.argus_dsrvl8.qual & 0x0F)) > 0) {
                        for (i = 0; i < num; i++) {
                           *label = ntohl(*label);
                           label++;
                        }
                     }
                     break;
                  }
                   
                  case ARGUS_JITTER_DSR: {
#if defined(HAVE_XDR)
                     struct ArgusJitterStruct *jit = (struct ArgusJitterStruct *) dsr;
                     struct ArgusStatsObject *stat = (struct ArgusStatsObject *) (dsr + 1);
                     int len = (jit->hdr.argus_dsrvl8.len - 1) * 4;
                     XDR xdrbuf, *xdrs = &xdrbuf;
                     char buf[sizeof(*stat)];

                     while (len > 0) {
                        bcopy ((char *)stat, buf, sizeof(*stat));
                        xdrmem_create(xdrs, buf, sizeof(*stat), XDR_DECODE);
                        xdr_int(xdrs, &stat->n);
                        xdr_float(xdrs, &stat->minval);
                        xdr_float(xdrs, &stat->meanval);
                        xdr_float(xdrs, &stat->stdev);
                        xdr_float(xdrs, &stat->maxval);

                        len -= sizeof (*stat);
                        stat++;
                     }
#endif
                     break;
                  }

                  case ARGUS_DATA_DSR: {
                     struct ArgusDataStruct *data = (struct ArgusDataStruct *) dsr;
                     data->size  = ntohs(data->size);
                     data->count = ntohs(data->count);
                     break;
                  }

                  case ARGUS_BEHAVIOR_DSR: {
                     struct ArgusBehaviorStruct *actor = (struct ArgusBehaviorStruct *) dsr;
                     actor->keyStroke.src.n_strokes  = ntohl(actor->keyStroke.src.n_strokes);
                     actor->keyStroke.dst.n_strokes  = ntohl(actor->keyStroke.dst.n_strokes);
                     break;
                  }
               }

               if ((cnt = ((dsr->type & 0x80) ? 1 : 
                          ((dsr->type == ARGUS_DATA_DSR) ? ntohs(dsr->argus_dsrvl16.len) :
                                                          dsr->argus_dsrvl8.len)) * 4) > 0) {
                  if (dsr->type == ARGUS_DATA_DSR)
                     dsr->argus_dsrvl16.len = ntohs(dsr->argus_dsrvl16.len);

                  dsr = (struct ArgusDSRHeader *)((char *)dsr + cnt);

               } else
                  break;
            }
         }
         break;
      }
   }
#endif
}


void
ArgusHtoN (struct ArgusRecord *argus)
{
#if defined(_LITTLE_ENDIAN)
   struct ArgusRecordHeader *hdr = &argus->hdr;
   struct ArgusDSRHeader *dsr = (struct ArgusDSRHeader *) (hdr + 1);

   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR: {
         argus->argus_mar.status            = htonl(argus->argus_mar.status);
         argus->argus_mar.argusid           = htonl(argus->argus_mar.argusid);
         argus->argus_mar.localnet          = htonl(argus->argus_mar.localnet);
         argus->argus_mar.netmask           = htonl(argus->argus_mar.netmask);
         argus->argus_mar.nextMrSequenceNum = htonl(argus->argus_mar.nextMrSequenceNum);
         argus->argus_mar.startime.tv_sec   = htonl(argus->argus_mar.startime.tv_sec);
         argus->argus_mar.startime.tv_usec  = htonl(argus->argus_mar.startime.tv_usec);
         argus->argus_mar.now.tv_sec        = htonl(argus->argus_mar.now.tv_sec);
         argus->argus_mar.now.tv_usec       = htonl(argus->argus_mar.now.tv_usec);
         argus->argus_mar.reportInterval    = htons(argus->argus_mar.reportInterval);
         argus->argus_mar.argusMrInterval   = htons(argus->argus_mar.argusMrInterval);

         argus->argus_mar.pktsRcvd          = htonll(argus->argus_mar.pktsRcvd);
         argus->argus_mar.bytesRcvd         = htonll(argus->argus_mar.bytesRcvd);
         argus->argus_mar.drift             = htonll(argus->argus_mar.drift);

         argus->argus_mar.records           = htonl(argus->argus_mar.records);
         argus->argus_mar.flows             = htonl(argus->argus_mar.flows);
         argus->argus_mar.dropped           = htonl(argus->argus_mar.dropped);
         argus->argus_mar.queue             = htonl(argus->argus_mar.queue);
         argus->argus_mar.output            = htonl(argus->argus_mar.output);
         argus->argus_mar.clients           = htonl(argus->argus_mar.clients);
         argus->argus_mar.bufs              = htonl(argus->argus_mar.bufs);
         argus->argus_mar.bytes             = htonl(argus->argus_mar.bytes);

         argus->argus_mar.thisid            = htonl(argus->argus_mar.thisid);
         argus->argus_mar.record_len        = htonl(argus->argus_mar.record_len);
         break;
      }

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         if (argus->hdr.len > 1) {
            int cnt;
            while ((char *) dsr < ((char *) argus + (hdr->len * 4))) {
               switch (dsr->type & 0x7F) {
                  case ARGUS_FLOW_DSR: {
                     struct ArgusFlow *flow = (struct ArgusFlow *) dsr;

                     switch (flow->hdr.subtype & 0x3F) {
                        case ARGUS_FLOW_CLASSIC5TUPLE: {
                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_IPV4:
                                 flow->ip_flow.ip_src = htonl(flow->ip_flow.ip_src);
                                 flow->ip_flow.ip_dst = htonl(flow->ip_flow.ip_dst);
                                 switch (flow->ip_flow.ip_p) {
                                    case IPPROTO_TCP:
                                    case IPPROTO_UDP:
                                       flow->ip_flow.sport = htons(flow->ip_flow.sport);
                                       flow->ip_flow.dport = htons(flow->ip_flow.dport);
                                       break;
                                    case IPPROTO_ESP:
                                       flow->esp_flow.spi = htonl(flow->esp_flow.spi);
                                       break;
                                    case IPPROTO_IGMP:
                                       flow->igmp_flow.ip_id = htons(flow->igmp_flow.ip_id);
                                       break;
                                 }
                                 break; 

                              case ARGUS_TYPE_IPV6: {
                                 unsigned int *iptr = (unsigned int *)&flow->ipv6_flow;
                                 if (flow->hdr.argus_dsrvl8.qual & ARGUS_FRAGMENT) {
                                    flow->fragv6_flow.ip_id = htonl(flow->fragv6_flow.ip_id);
                                 } else {
                                    switch (flow->ipv6_flow.ip_p) {
                                       case IPPROTO_TCP:
                                       case IPPROTO_UDP:
                                          flow->ipv6_flow.sport = htons(flow->ipv6_flow.sport);
                                          flow->ipv6_flow.dport = htons(flow->ipv6_flow.dport);
                                          break;

                                       case IPPROTO_ICMPV6:
                                          flow->icmpv6_flow.id = htons(flow->icmpv6_flow.id);
                                          break;

                                       case IPPROTO_ESP:
                                          flow->esp6_flow.spi = htonl(flow->esp6_flow.spi);
                                          break;
                                    }
                                 } 
                                 iptr[8] = htonl(iptr[8]);
                                 break; 
                              }

                              case ARGUS_TYPE_ETHER: {
                                 struct ArgusEtherMacFlow *mac = (struct ArgusEtherMacFlow *) &flow->mac_flow;
                                 mac->ehdr.ether_type = htons(mac->ehdr.ether_type);
                                 break;
                              }

                              case ARGUS_TYPE_ISIS: {
                                 struct ArgusIsisFlow *isis = (struct ArgusIsisFlow *) &flow->isis_flow;
                                 switch (isis->pdu_type = htonl(isis->pdu_type)) {
                                    case L1_LAN_IIH:
                                    case L2_LAN_IIH:
                                       break;

                                    case L1_CSNP:
                                    case L2_CSNP:
                                       break;

                                    case L1_PSNP:
                                    case L2_PSNP:
                                       break;

                                    case L1_LSP:
                                    case L2_LSP:
                                       isis->isis_un.lsp.seqnum = htonl(isis->isis_un.lsp.seqnum);
                                       break;
                                 }
                                 isis->chksum = htonl(isis->chksum);
                                 break;
                              }
                           
                              case ARGUS_TYPE_RARP: {
                                 struct ArgusRarpFlow *rarp = (struct ArgusRarpFlow *) &flow->rarp_flow;
                                 rarp->arp_tpa = htonl(rarp->arp_tpa);
                                 break;
                              }
/* 
                              case ARGUS_TYPE_ARP: {
                                 struct ArgusArpLegacyFlow *arp = (struct ArgusArpLegacyFlow *) &flow->flow_un;
                                 arp->arp_spa = htonl(arp->arp_spa);
                                 arp->arp_tpa = htonl(arp->arp_tpa);
                                 break;
                              } 
*/
                           }
                           break; 
                        }

                        case ARGUS_FLOW_ARP: {
                           switch (flow->hdr.argus_dsrvl8.qual & 0x1F) {
                              case ARGUS_TYPE_RARP: {
                                 struct ArgusRarpFlow *rarp = (struct ArgusRarpFlow *) &flow->rarp_flow;
                                 rarp->hrd = htons(rarp->hrd);
                                 rarp->pro = htons(rarp->pro);
                                 rarp->op  = htons(rarp->op);
                                 if (rarp->pln == 4) {
                                    rarp->arp_tpa = htonl(rarp->arp_tpa);
                                 }
                                 break;
                              }
                              case ARGUS_TYPE_ARP: {
                                 struct ArgusArpFlow *arp = (struct ArgusArpFlow *) &flow->arp_flow;
                                 arp->hrd = htons(arp->hrd);
                                 arp->pro = htons(arp->pro);
                                 arp->op  = htons(arp->op);
                                 if (arp->pln == 4) {
                                    arp->arp_spa = htonl(arp->arp_spa);
                                    arp->arp_tpa = htonl(arp->arp_tpa);
                                 }
                                 break;
                              }
                           }  
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_ENCAPS_DSR: {
                     struct ArgusEncapsStruct *encaps = (struct ArgusEncapsStruct *) dsr;
                     encaps->src = htonl(encaps->src);
                     encaps->dst = htonl(encaps->dst);
                     break;
                  }

                  case ARGUS_IPATTR_DSR: {
                     struct ArgusIPAttrStruct *attr = (struct ArgusIPAttrStruct *) dsr;
                     unsigned int *dsrptr = (unsigned int *)(dsr + 1);

                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC) {
                        struct ArgusIPAttrObject *aobj = (struct ArgusIPAttrObject *) dsrptr;
                        aobj->ip_id = htons(aobj->ip_id);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_SRC_OPTIONS) {
                        *dsrptr = htonl(*dsrptr);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST) {
                        struct ArgusIPAttrObject *aobj = (struct ArgusIPAttrObject *) dsrptr;
                        aobj->ip_id = htons(aobj->ip_id);
                        dsrptr++;
                     }
                     if (attr->hdr.argus_dsrvl8.qual & ARGUS_IPATTR_DST_OPTIONS) {
                        *dsrptr = htonl(*dsrptr);
                        dsrptr++;
                     }
                     break;
                  }

                  case ARGUS_ICMP_DSR: {
                     struct ArgusIcmpStruct *icmp = (struct ArgusIcmpStruct *) dsr;
                     icmp->iseq      = htons(icmp->iseq);
                     icmp->osrcaddr  = htonl(icmp->osrcaddr);
                     icmp->odstaddr  = htonl(icmp->odstaddr);
                     icmp->isrcaddr  = htonl(icmp->isrcaddr);
                     icmp->idstaddr  = htonl(icmp->idstaddr);
                     icmp->igwaddr   = htonl(icmp->igwaddr);
                     break;
                  }

                  case ARGUS_TRANSPORT_DSR: {
                     struct ArgusTransportStruct *trans = (struct ArgusTransportStruct *) dsr;

                     if (trans->hdr.subtype & ARGUS_SEQ)
                           trans->seqnum = htonl(trans->seqnum);

                     if (trans->hdr.subtype & ARGUS_SRCID) {
                        switch (trans->hdr.argus_dsrvl8.qual) {
                           case ARGUS_TYPE_INT:
                              trans->srcid.a_un.value = htonl(trans->srcid.a_un.value);
                              break;
                           case ARGUS_TYPE_IPV4:
                              trans->srcid.a_un.value = htonl(trans->srcid.a_un.value);
                              break;

                           case ARGUS_TYPE_IPV6:
                           case ARGUS_TYPE_ETHER:
                           case ARGUS_TYPE_STRING:
                              break;
                        }
                     }
                     break;
                  }

                  case ARGUS_TIME_DSR: {
                     unsigned int x, *dtime = (unsigned int *) dsr; 
       
                     for (x = 1; x < dsr->argus_dsrvl8.len; x++)
                        dtime[x] = htonl(dtime[x]);
                     break; 
                  }

                  case ARGUS_METER_DSR: {
                     if (dsr->subtype & ARGUS_METER_PKTS_BYTES) {
                        switch (dsr->argus_dsrvl8.qual & 0x0F) {
                           case ARGUS_SRCDST_BYTE:
                              break;
                           case ARGUS_SRCDST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = htons(((unsigned short *)(dsr + 1))[2]);
                              ((unsigned short *)(dsr + 1))[3] = htons(((unsigned short *)(dsr + 1))[3]);
                              break;
                           case ARGUS_SRCDST_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = htonl(((unsigned int *)(dsr + 1))[2]);
                              ((unsigned int *)(dsr + 1))[3] = htonl(((unsigned int *)(dsr + 1))[3]);
                              break;
                           case ARGUS_SRCDST_LONGLONG:
                              break;
                           case ARGUS_SRC_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              break;
                           case ARGUS_SRC_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              break;
                           case ARGUS_SRC_LONGLONG:
                              break;
                           case ARGUS_DST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              break;
                           case ARGUS_DST_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              break;
                           case ARGUS_DST_LONGLONG:
                              break;

                        }
                     } else 
                     if (dsr->subtype & ARGUS_METER_PKTS_BYTES_APP) {
                        switch (dsr->argus_dsrvl8.qual & 0x0F) {
                           case ARGUS_SRCDST_BYTE:
                           case ARGUS_SRC_BYTE:
                           case ARGUS_DST_BYTE:
                              break;
                           case ARGUS_SRCDST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = htons(((unsigned short *)(dsr + 1))[2]);
                              ((unsigned short *)(dsr + 1))[3] = htons(((unsigned short *)(dsr + 1))[3]);
                              ((unsigned short *)(dsr + 1))[4] = htons(((unsigned short *)(dsr + 1))[4]);
                              ((unsigned short *)(dsr + 1))[5] = htons(((unsigned short *)(dsr + 1))[5]);
                              break;
                           case ARGUS_SRCDST_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = htonl(((unsigned int *)(dsr + 1))[2]);
                              ((unsigned int *)(dsr + 1))[3] = htonl(((unsigned int *)(dsr + 1))[3]);
                              ((unsigned int *)(dsr + 1))[4] = htonl(((unsigned int *)(dsr + 1))[4]);
                              ((unsigned int *)(dsr + 1))[5] = htonl(((unsigned int *)(dsr + 1))[5]);
                              break;
                           case ARGUS_SRC_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = htons(((unsigned short *)(dsr + 1))[2]);
                              break;
                           case ARGUS_SRC_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = htonl(((unsigned int *)(dsr + 1))[2]);
                              break;
                           case ARGUS_DST_SHORT:
                              ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                              ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                              ((unsigned short *)(dsr + 1))[2] = htons(((unsigned short *)(dsr + 1))[2]);
                              break;
                           case ARGUS_DST_INT:
                              ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                              ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                              ((unsigned int *)(dsr + 1))[2] = htonl(((unsigned int *)(dsr + 1))[2]);
                              break;
                        }
                     }
                     break;
                  }

                  case ARGUS_PSIZE_DSR: {
                     switch (dsr->argus_dsrvl8.qual & 0x0F) {
                        case ARGUS_SRCDST_SHORT:
                           ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                           ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                           ((unsigned short *)(dsr + 1))[2] = htons(((unsigned short *)(dsr + 1))[2]);
                           ((unsigned short *)(dsr + 1))[3] = htons(((unsigned short *)(dsr + 1))[3]);
                           break;

                        case ARGUS_SRC_SHORT:
                        case ARGUS_DST_SHORT:
                           ((unsigned short *)(dsr + 1))[0] = htons(((unsigned short *)(dsr + 1))[0]);
                           ((unsigned short *)(dsr + 1))[1] = htons(((unsigned short *)(dsr + 1))[1]);
                           break;

                        case ARGUS_SRCDST_INT:
                           ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                           ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                           ((unsigned int *)(dsr + 1))[2] = htonl(((unsigned int *)(dsr + 1))[2]);
                           ((unsigned int *)(dsr + 1))[3] = htonl(((unsigned int *)(dsr + 1))[3]);
                           break;

                        case ARGUS_SRC_INT:
                        case ARGUS_DST_INT:
                           ((unsigned int *)(dsr + 1))[0] = htonl(((unsigned int *)(dsr + 1))[0]);
                           ((unsigned int *)(dsr + 1))[1] = htonl(((unsigned int *)(dsr + 1))[1]);
                           break;
                     }
                     break;
                  }

                  case ARGUS_NETWORK_DSR: {
                     struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)dsr;
                     switch (net->hdr.subtype) {
                        case ARGUS_TCP_INIT: {
                           struct ArgusTCPInitStatus *tcp = (void *)&net->net_union.tcpinit;
                           tcp->status       = htonl(tcp->status);
                           tcp->seqbase      = htonl(tcp->seqbase);
                           tcp->options      = htonl(tcp->options);
                           tcp->win          = htons(tcp->win);
                           break;
                        }
                        case ARGUS_TCP_STATUS: {
                           struct ArgusTCPStatus *tcp = (struct ArgusTCPStatus *)&net->net_union.tcpstatus;
                           tcp->status       = htonl(tcp->status);
                           break;
                        }
                        case ARGUS_TCP_PERF: {
                           struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                           tcp->status       = htonl(tcp->status);
                           tcp->state        = htonl(tcp->state);
                           tcp->options      = htonl(tcp->options);
                           tcp->synAckuSecs  = htonl(tcp->synAckuSecs);
                           tcp->ackDatauSecs = htonl(tcp->ackDatauSecs);

                           tcp->src.lasttime.tv_sec  = htonl(tcp->src.lasttime.tv_sec);
                           tcp->src.lasttime.tv_usec = htonl(tcp->src.lasttime.tv_usec);
                           tcp->src.status = htonl(tcp->src.status);
                           tcp->src.seqbase = htonl(tcp->src.seqbase);
                           tcp->src.seq = htonl(tcp->src.seq);
                           tcp->src.ack = htonl(tcp->src.ack);
                           tcp->src.winnum = htonl(tcp->src.winnum);
                           tcp->src.bytes = htonl(tcp->src.bytes);
                           tcp->src.retrans = htonl(tcp->src.retrans);
                           tcp->src.ackbytes = htonl(tcp->src.ackbytes);
                           tcp->src.winbytes = htonl(tcp->src.winbytes);
                           tcp->src.win = htons(tcp->src.win);

                           if (dsr->argus_dsrvl8.len > (((sizeof(struct ArgusTCPObject) - sizeof(struct ArgusTCPObjectMetrics))+3)/4 + 1)) {
                              tcp->dst.lasttime.tv_sec  = htonl(tcp->dst.lasttime.tv_sec);
                              tcp->dst.lasttime.tv_usec = htonl(tcp->dst.lasttime.tv_usec);
                              tcp->dst.status = htonl(tcp->dst.status);
                              tcp->dst.seqbase = htonl(tcp->dst.seqbase);
                              tcp->dst.seq = htonl(tcp->dst.seq);
                              tcp->dst.ack = htonl(tcp->dst.ack);
                              tcp->dst.winnum = htonl(tcp->dst.winnum);
                              tcp->dst.bytes = htonl(tcp->dst.bytes);
                              tcp->dst.retrans = htonl(tcp->dst.retrans);
                              tcp->dst.ackbytes = htonl(tcp->dst.ackbytes);
                              tcp->dst.winbytes = htonl(tcp->dst.winbytes);
                              tcp->dst.win = htons(tcp->dst.win);
                           }
                           break;
                        }

                        case ARGUS_ESP_DSR: {
                           struct ArgusESPObject *espObj = (struct ArgusESPObject *)&net->net_union.esp;
                           espObj->status  = htonl(espObj->status);
                           espObj->spi     = htonl(espObj->spi);
                           espObj->lastseq = htonl(espObj->lastseq);
                           espObj->lostseq = htonl(espObj->lostseq);
                           break;
                        }
                        case ARGUS_RTP_FLOW: {
                           struct ArgusRTPObject *rtpObj = (struct ArgusRTPObject *)&net->net_union.rtp;
                           rtpObj->state       = htonl(rtpObj->state);
                           rtpObj->src.rh_seq  = htons(rtpObj->src.rh_seq);
                           rtpObj->src.rh_time = htonl(rtpObj->src.rh_time);
                           rtpObj->src.rh_ssrc = htonl(rtpObj->src.rh_ssrc);

                           rtpObj->dst.rh_seq  = htons(rtpObj->dst.rh_seq);
                           rtpObj->dst.rh_time = htonl(rtpObj->dst.rh_time);
                           rtpObj->dst.rh_ssrc = htonl(rtpObj->dst.rh_ssrc);

                           rtpObj->sdrop       = htons(rtpObj->sdrop);
                           rtpObj->ddrop       = htons(rtpObj->ddrop);
                           rtpObj->ssdev       = htons(rtpObj->ssdev);
                           rtpObj->dsdev       = htons(rtpObj->dsdev);
                           break;
                        }
                        case ARGUS_RTCP_FLOW: {
                           struct ArgusRTCPObject *rtcpObj = (struct ArgusRTCPObject *)&net->net_union.rtcp;
                           rtcpObj->src.rh_len   = htons(rtcpObj->src.rh_len);
                           rtcpObj->src.rh_ssrc  = htonl(rtcpObj->src.rh_ssrc);

                           rtcpObj->dst.rh_len   = htons(rtcpObj->dst.rh_len);
                           rtcpObj->dst.rh_ssrc  = htonl(rtcpObj->dst.rh_ssrc);

                           rtcpObj->sdrop = htons(rtcpObj->sdrop);
                           rtcpObj->ddrop = htons(rtcpObj->ddrop);
                           break;
                        }
                     }
                     break;
                  }

                  case ARGUS_VLAN_DSR: {
                     struct ArgusVlanStruct *vlan = (struct ArgusVlanStruct *) dsr;
                     vlan->sid = htons(vlan->sid);
                     vlan->did = htons(vlan->did);
                     break;
                  }

                  case ARGUS_MPLS_DSR: {
                     struct ArgusMplsStruct *mpls = (struct ArgusMplsStruct *) dsr;
                     unsigned int *label = (unsigned int *)(dsr + 1);
                     int num, i;

                     if ((num = ((mpls->hdr.argus_dsrvl8.qual & 0xF0) >> 4)) > 0) {
                        for (i = 0; i < num; i++) {
                           *label = htonl(*label);
                           label++;
                        }
                     }
                     if ((num = (mpls->hdr.argus_dsrvl8.qual & 0x0F)) > 0) {
                        for (i = 0; i < num; i++) {
                           *label = htonl(*label);
                           label++;
                        }
                     }
                     break;
                  }

                  case ARGUS_JITTER_DSR: {
#if defined(HAVE_XDR)
                     struct ArgusJitterStruct *jit = (struct ArgusJitterStruct *) dsr;
                     struct ArgusStatsObject *stat = (struct ArgusStatsObject *) (dsr + 1);
                     int len = (jit->hdr.argus_dsrvl8.len - 1) * 4;
                     XDR xdrbuf, *xdrs = &xdrbuf;
                     char buf[sizeof(*stat)];

                     while (len > 0) {
                        memset(buf, 0, sizeof(buf));
                        xdrmem_create(xdrs, buf, sizeof(*stat), XDR_ENCODE);
                        xdr_int(xdrs, &stat->n);
                        xdr_float(xdrs, &stat->minval);
                        xdr_float(xdrs, &stat->meanval);
                        xdr_float(xdrs, &stat->stdev);
                        xdr_float(xdrs, &stat->maxval);

                        bcopy(buf, stat, sizeof(*stat));
                        len -= sizeof (*stat);
                        stat++;
                     }
#endif
                     break;
                  }

                  case ARGUS_DATA_DSR: {
                     struct ArgusDataStruct *data = (struct ArgusDataStruct *) dsr;
                     data->size  = htons(data->size);
                     data->count = htons(data->count);
                     break;
                  }

                  case ARGUS_BEHAVIOR_DSR: {
                     struct ArgusBehaviorStruct *actor = (struct ArgusBehaviorStruct *) dsr;
                     actor->keyStroke.src.n_strokes  = htonl(actor->keyStroke.src.n_strokes);
                     actor->keyStroke.dst.n_strokes  = htonl(actor->keyStroke.dst.n_strokes);
                     break;
                  }
               }

               if ((cnt = ((dsr->type & 0x80) ? 1 : 
                          ((dsr->type == ARGUS_DATA_DSR) ? dsr->argus_dsrvl16.len :
                                                          dsr->argus_dsrvl8.len)) * 4) > 0) {
                  if (dsr->type == ARGUS_DATA_DSR)
                     dsr->argus_dsrvl16.len = htons(dsr->argus_dsrvl16.len);

                  dsr = (struct ArgusDSRHeader *)((char *)dsr + cnt);

               } else
                  break;
            }
         }
         break;
      }
   }

   hdr->len = htons(hdr->len);
#endif
}


void
ArgusPrintHex (const u_char *bp, u_int length)
{
   const u_short *sp;
   u_int i;
   int nshorts;

   sp = (u_short *)bp;
   nshorts = (u_int) length / sizeof(u_short);
   i = 0;
   while (--nshorts >= 0) {
      if ((i++ % 8) == 0) {
         (void)printf("\n\t");
      }
      (void)printf(" %04x", ntohs(*sp++));
   }

   if (length & 1) {
      if ((i % 8) == 0)
         (void)printf("\n\t");

      (void)printf(" %02x", *(u_char *)sp);
   }
   (void)printf("\n");
   fflush(stdout);
}



char *ArgusProcessStr = NULL;

void
ArgusPrintDirection (char *buf, struct ArgusRecordStruct *argus, int len)
{
   switch (argus->hdr.type & 0xF0) {
      case ARGUS_MAR:
         break;

      case ARGUS_EVENT:
      case ARGUS_NETFLOW:
      case ARGUS_FAR: {
         struct ArgusMetricStruct *metric = (struct ArgusMetricStruct *)argus->dsrs[ARGUS_METRIC_INDEX];
         struct ArgusFlow *flow = (struct ArgusFlow *)argus->dsrs[ARGUS_FLOW_INDEX];
         struct ArgusNetworkStruct *net = (struct ArgusNetworkStruct *)argus->dsrs[ARGUS_NETWORK_INDEX];
         int type, src_count = 0, dst_count = 0;

         if (metric == NULL) {
            sprintf (buf, "%*.*s ", len, len, "   ");
         } else {
            char dirStr[16];
            sprintf (dirStr, "%s", "<->");

            if ((dst_count = metric->dst.pkts) == 0)
               dirStr[0] = ' ';
            if ((src_count = metric->src.pkts) == 0)
               dirStr[2] = ' ';
            if ((src_count == 0) && (dst_count == 0))
               dirStr[1] = ' ';

            if (flow != NULL) {
               switch (flow->hdr.subtype & 0x3F) {
                  case ARGUS_FLOW_CLASSIC5TUPLE: {
                     switch (type = (flow->hdr.argus_dsrvl8.qual & 0x1F)) {
                        case ARGUS_TYPE_IPV4:
                           switch (flow->ip_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 if (net != NULL) {
                                    struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                    if (!((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT))) {
                                       dirStr[1] = '?';
                                    }
                                    if ((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT)) {
                                       if (flow->hdr.subtype & ARGUS_REVERSE) {
                                          dirStr[0] = '<';
                                          dirStr[2] = ' ';
                                       } else {
                                          dirStr[0] = ' ';
                                          dirStr[2] = '>';
                                       }
                                    }
                                 }
                              }
                              break;
                           }
                           break;  

                        case ARGUS_TYPE_IPV6:
                           switch (flow->ipv6_flow.ip_p) {
                              case IPPROTO_TCP: {
                                 if (net != NULL) {
                                    struct ArgusTCPObject *tcp = (struct ArgusTCPObject *)&net->net_union.tcp;
                                    if (!((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT))) {
                                       dirStr[1] = '?';
                                    } else {
                                       if ((tcp->status & ARGUS_SAW_SYN) || (tcp->status & ARGUS_SAW_SYN_SENT)) {
                                          if (flow->hdr.subtype & ARGUS_REVERSE) {
                                             dirStr[0] = '<';
                                             dirStr[2] = ' ';
                                          } else {
                                             dirStr[0] = ' ';
                                             dirStr[2] = '>';
                                          }
                                       }
                                    }
                                 }
                              }
                              break;
                           }
                           break;  

                        case ARGUS_TYPE_RARP:
                           sprintf (dirStr, "%s", "tel");
                           break;

                        case ARGUS_TYPE_ARP:
                           sprintf (dirStr, "%s", "who");
                           break;
                     } 
                     break;
                  }

                  case ARGUS_FLOW_ARP: {
                     sprintf (dirStr, "%s", "who");
                     break;
                  }
               }
            }
         }

         break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (10, "ArgusPrintDirection (%p, %p, %d)", buf, argus, len);
#endif
}


int ArgusAllocMax   = 0;
int ArgusAllocBytes = 0;
int ArgusAllocTotal = 0;
int ArgusFreeTotal  = 0;

struct ArgusMemoryList memory = {NULL, 0};

#define ARGUS_ALLOC	0x45672381
/*
#define ARGUS_ALIGN	128
*/

void *     
ArgusMalloc (int bytes) 
{          
   void *retn = NULL; 
   int offset;
 
   if (bytes) {
      if (ArgusAllocTotal++ == 0) {
#if defined(ARGUS_THREADS)
         pthread_mutex_init(&memory.lock, NULL);
#endif
      }
      ArgusAllocBytes += bytes;
      if (ArgusAllocMax < ArgusAllocBytes)
         ArgusAllocMax = ArgusAllocBytes;

#if defined(ARGUS_ALIGN)
      offset = ARGUS_ALIGN;
#else
      offset = 0;
#endif

#if !defined(ARGUSMEMDEBUG)
      retn = (void *) malloc (bytes + offset);
#else
      if ((retn = (u_int *) malloc (bytes + sizeof(struct ArgusMemoryHeader) + offset)) != NULL) {
         struct ArgusMemoryHeader *mem = (struct ArgusMemoryHeader *)retn;
         mem->tag = ARGUS_ALLOC;
         mem->len = bytes;
         mem->offset = offset;
#if defined(__GNUC__)
         mem->frame[0] = __builtin_return_address(0);
         mem->frame[1] = __builtin_return_address(1);
         mem->frame[2] = __builtin_return_address(2);
#endif
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&memory.lock);
#endif
         if (memory.start) {
            mem->nxt = memory.start;
            mem->prv = memory.end;
            mem->prv->nxt = mem;
            mem->nxt->prv = mem;
            memory.end = mem;
         } else {
            memory.start = mem;
            memory.end = mem;
            mem->nxt = mem;
            mem->prv = mem;
         }
         memory.count++;
         memory.total++;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&memory.lock);
#endif
         retn = (void *)(mem + 1);
      }
#endif

#if defined(ARGUS_ALIGN)
      if (retn != NULL) {
         unsigned short toff;
         toff = ((unsigned long)retn & (offset - 1));
         toff = offset - toff;
         retn = (void *)((char *)retn + toff);
         ((unsigned short *)retn)[-1] = toff;
      }
#endif
   }
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusMalloc (%d) returning %p\n", bytes, retn); 
#endif
   return (retn); 
}

void *
ArgusCalloc (int nitems, int bytes)
{
   int offset, total = nitems * bytes;
   void *retn = NULL;

   if (total) {
      if (ArgusAllocTotal++ == 0) {
#if defined(ARGUS_THREADS)
         pthread_mutex_init(&memory.lock, NULL);
#endif
      }
      ArgusAllocBytes += total;
      if (ArgusAllocMax < ArgusAllocBytes)
         ArgusAllocMax = ArgusAllocBytes;

#if defined(ARGUS_ALIGN)
      offset = ARGUS_ALIGN;
#else
      offset = 0;
#endif

#if !defined(ARGUSMEMDEBUG)
      retn = calloc (1, total + offset);
#else
      if ((retn = calloc (1, total + sizeof(struct ArgusMemoryHeader) + offset)) != NULL) {
         struct ArgusMemoryHeader *mem = retn;
         mem->tag = ARGUS_ALLOC;
         mem->len = total;
         mem->offset = offset;
#if defined(__GNUC__)
         mem->frame[0] = __builtin_return_address(0);
         mem->frame[1] = __builtin_return_address(1);
         mem->frame[2] = __builtin_return_address(2);
#endif

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&memory.lock);
#endif
         if (memory.start) {
            mem->nxt = memory.start;
            mem->prv = memory.start->prv;
            mem->prv->nxt = mem;
            mem->nxt->prv = mem;
            memory.end = mem;
         } else {
            memory.start = mem;
            memory.end = mem;
            mem->nxt = mem;
            mem->prv = mem;
         }
         memory.total++;
         memory.count++;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&memory.lock);
#endif
         retn = (void *)(mem + 1);
      }
#endif

#if defined(ARGUS_ALIGN)
      if (retn != NULL) {
         unsigned short toff;
         toff = ((unsigned long)retn & (offset - 1));
         toff = offset - toff;
         retn = (void *)((char *)retn + toff);
         ((unsigned short *)retn)[-1] = toff;
      }
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusCalloc (%d, %d) returning %p\n", nitems, bytes, retn);
#endif
   return (retn);
}


void
ArgusFree (void *buf)
{
   void *ptr = buf;

   if (ptr) {
      ArgusFreeTotal++;
#if defined(ARGUSMEMDEBUG)
      {
         struct ArgusMemoryHeader *mem = ptr;
#if defined(ARGUS_ALIGN)
         unsigned short offset = ((unsigned short *)mem)[-1];
         mem = (void *)((char *)mem - offset);
#endif
         mem--;
         if (mem->tag != ARGUS_ALLOC)
            ArgusLog (LOG_ERR, "ArgusFree: buffer error %p", ptr);

#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&memory.lock);
#endif
         if (memory.count == 1) {
            memory.start = NULL;
            memory.end = NULL;
         } else {
            mem->prv->nxt = mem->nxt;
            mem->nxt->prv = mem->prv;
            if (mem == memory.start) {
               memory.start = mem->nxt;
            } else if (mem == memory.end) {
               memory.end = mem->prv;
            }
         }
         ArgusAllocBytes -= mem->len;
         memory.count--;
#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&memory.lock);
#endif
         ptr = mem;
      }
#else
#if defined(ARGUS_ALIGN)
      {
         unsigned short offset;
         if ((offset = ((unsigned short *)ptr)[-1]) > 0)
            ptr = (void *)((char *)ptr - offset);
      }
#endif
#endif
      free (ptr);
   }
#ifdef ARGUSDEBUG
   ArgusDebug (6, "ArgusFree (%p)\n", buf);
#endif
}

/* 
   the argus malloc list is the list of free MallocLists for the system.
   these are blocks that are used to convey flow data from the modeler
   to the output processor.  They are fixed length blocks, and so no need
   to malloc and free, so just keep them in a list when they aren't being
   used.  we keep 2000 in the list when demand goes below this, and we
   start with 20, when we initialize the modeler.  no more than 1M records.

   so, when something asks for one, we take it off the list if there is
   one, and if not we just create one and return the buffer.  The buffer
   has a memory header in front so that the records can be put in the 
   list when they are freed, without corrupting the headers that were
   in the last block.  Be sure and respect that so other routines
   don't stomp on our header.
*/


#define ARGUS_MEMORY_MAX	1000000
#define ARGUS_MEMORY_HI_THRESH	2000
#define ARGUS_MEMORY_LOW_THRESH	20

struct ArgusMemoryList *ArgusMallocList = NULL;

void
ArgusInitMallocList (int length)
{
   struct ArgusMemoryList *retn = NULL;
   int memlen = length + sizeof(struct ArgusMemoryHeader);

   if (ArgusMallocList != NULL) {
      if (length == ArgusMallocList->size)
         return;
      else
         ArgusLog(LOG_ERR, "ArgusInitMallocList called with multiple sizes");
   }

#if defined(ARGUS_THREADS)
   if (ArgusModel)
      pthread_mutex_lock(&ArgusModel->lock);
#endif

   if ((retn = (struct ArgusMemoryList *) ArgusCalloc(1, sizeof(*ArgusMallocList))) == NULL)
         ArgusLog(LOG_ERR, "ArgusInitMallocList ArgusCalloc %s", strerror(errno));

   retn->size = length;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
   pthread_mutex_lock(&retn->lock);
#endif

   ArgusMallocList = retn;

   while (ArgusMallocList->count < ARGUS_MEMORY_LOW_THRESH) {
      struct ArgusMemoryHeader *mem;
      if ((mem = (struct ArgusMemoryHeader *) ArgusCalloc (1, memlen)) != NULL) {
         if (ArgusMallocList->end) {
            ArgusMallocList->end->nxt = mem;
         } else {
            ArgusMallocList->start = mem;
            ArgusMallocList->count = 0;
         }
         ArgusMallocList->end = mem;
         ArgusMallocList->count++;
         ArgusMallocList->total++;
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_unlock(&ArgusMallocList->lock);
   if (ArgusModel)
      pthread_mutex_unlock(&ArgusModel->lock);
#endif

#ifdef ARGUSDEBUG 
   ArgusDebug (6, "ArgusInitMallocList (%d) returning\n", length);
#endif
   return;
}

void
ArgusDeleteMallocList (void)
{
   struct ArgusMemoryList *retn = NULL;
   struct ArgusMemoryHeader *crt, *rel;
 
   if (ArgusMallocList != NULL) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusMallocList->lock);
#endif
      retn = ArgusMallocList;
      ArgusMallocList = NULL;
 
      if ((crt = retn->start) != NULL) {
         while (crt != NULL) {
            rel = crt;
            crt = crt->nxt;
            ArgusFree(rel);
         }
      }
 
#if defined(ARGUS_THREADS)
      pthread_mutex_destroy(&retn->lock);
#endif
      ArgusFree(retn);
   }
}


void *
ArgusMallocListRecord (int length)
{
   struct ArgusMemoryHeader *mem = NULL;
   int memlen = length + sizeof(struct ArgusMemoryHeader);
   void *retn = NULL;

   if (ArgusMallocList == NULL)
      ArgusInitMallocList(length);

   if (length == ArgusMallocList->size) {
#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&ArgusMallocList->lock);
#endif
      if (ArgusMallocList->start == NULL) {
         if (ArgusMallocList->total < ARGUS_MEMORY_MAX) {
            if ((mem = (struct ArgusMemoryHeader *) ArgusCalloc (1, memlen)) == NULL)
               ArgusLog(LOG_ERR, "ArgusMallocListRecord ArgusCalloc %s", strerror(errno));

            mem->len = length;
            ArgusMallocList->total++;
            ArgusMallocList->out++;
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusMallocList memory pool exhausted (%d : %d)\n", ArgusMallocList->total, ARGUS_MEMORY_MAX);
#endif
         }

      } else {
         mem = ArgusMallocList->start;
         ArgusMallocList->start = mem->nxt;
         ArgusMallocList->out++;
         ArgusMallocList->count--;

         if (ArgusMallocList->start == NULL) {
            ArgusMallocList->end = NULL;
            ArgusMallocList->count = 0;
         }
      }
#if defined(ARGUS_THREADS)
      pthread_mutex_unlock(&ArgusMallocList->lock);
#endif

   } else {
      if ((mem = (struct ArgusMemoryHeader *) ArgusCalloc (1, length + sizeof(struct ArgusMemoryHeader))) == NULL)
         ArgusLog(LOG_ERR, "ArgusMallocListRecord ArgusCalloc %s", strerror(errno));
   }

   if (mem != NULL)
      retn = (void *)(mem + 1);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusMallocListRecord (%d) returning %p total %d out %d\n", length, retn, ArgusMallocList->total, ArgusMallocList->out);
#endif
   return (retn);
}


void
ArgusFreeListRecord (void *buf)
{
   if (buf != NULL) {
      struct ArgusMemoryHeader *mem = (struct ArgusMemoryHeader *)buf;
      struct ArgusRecordStruct *rec = buf;

/*
      struct ArgusHashTableHdr *htblhdr;
      struct ArgusQueueStruct *nsq;

      if ((htblhdr = rec->htblhdr) != NULL) {
#ifdef ARGUSDEBUG 
         ArgusDebug (5, "ArgusFreeListRecord (0x%x) htbldr 0x%x\n", buf, htblhdr);
#endif
      }

      if ((nsq = rec->nsq) != NULL) {
#ifdef ARGUSDEBUG 
      ArgusDebug (5, "ArgusFreeListRecord (%p) nsq %p\n", buf, nsq);
#endif
      }
*/
      if (rec->dsrs[ARGUS_SRCUSERDATA_INDEX] != NULL) {
         ArgusFree(rec->dsrs[ARGUS_SRCUSERDATA_INDEX]);
         rec->dsrs[ARGUS_SRCUSERDATA_INDEX] = NULL;
      }

      if (rec->dsrs[ARGUS_DSTUSERDATA_INDEX] != NULL) {
         ArgusFree(rec->dsrs[ARGUS_DSTUSERDATA_INDEX]);
         rec->dsrs[ARGUS_DSTUSERDATA_INDEX] = NULL;
      }

      mem = mem - 1;

      if ((ArgusMallocList == NULL) || (mem->len != ArgusMallocList->size)) {
         ArgusFree(mem);

      } else {
#if defined(ARGUS_THREADS)
         if (pthread_mutex_lock(&ArgusMallocList->lock) == 0) {
#endif
            if (ArgusMallocList->count < ARGUS_MEMORY_HI_THRESH) {
               mem->nxt = NULL;
               if (ArgusMallocList->end != NULL)
                  ArgusMallocList->end->nxt = mem;
   
               ArgusMallocList->end = mem;
   
               if (ArgusMallocList->start == NULL)
                  ArgusMallocList->start = mem;
   
               ArgusMallocList->count++;
   
            } else {
               ArgusMallocList->total--;
               ArgusFree(mem);
            }

            ArgusMallocList->in++;

#if defined(ARGUS_THREADS)
            pthread_mutex_unlock(&ArgusMallocList->lock);
         }
#endif
      }
   }

#ifdef ARGUSDEBUG 
   ArgusDebug (5, "ArgusFreeListRecord (%p) returning\n", buf);
#endif
   return;
}

extern void ArgusShutDown (int);

struct ArgusLogPriorityStruct {
   int priority;
   char *label;
};

#define ARGUSPRIORITYSTR	8
struct ArgusLogPriorityStruct ArgusPriorityStr[ARGUSPRIORITYSTR] =
{
   { LOG_EMERG,   "ArgusEmergency" },
   { LOG_ALERT,   "    ArgusAlert" },
   { LOG_CRIT,    " ArgusCritical" },
   { LOG_ERR,     "    ArgusError" },
   { LOG_WARNING, "  ArgusWarning" },
   { LOG_NOTICE,  "   ArgusNotice" },
   { LOG_INFO,    "     ArgusInfo" },
   { LOG_DEBUG,   "    ArgusDebug" },
};

      

#include <sys/time.h>

void
ArgusLog (int priority, char *fmt, ...)
{
   va_list ap;
   char buf[1024], *ptr = buf;
   struct timeval now;

#ifdef HAVE_SYSLOG
   gettimeofday (&now, 0L);

   (void) snprintf (buf, 1024, "%s ", print_time(&now));
   ptr = &buf[strlen(buf)];
#else
   int i;
   char *label;

   if (priority == LOG_NOTICE)
      return;

   gettimeofday (&now, 0L);

#if defined(ARGUS_THREADS)
   {
      pthread_t ptid;
      char pbuf[128];
      int i;

      bzero(pbuf, sizeof(pbuf));
      ptid = pthread_self();
      for (i = 0; i < sizeof(ptid); i++) {
         snprintf (&pbuf[i*2], 3, "%02hhx", ((char *)&ptid)[i]);
      }
      (void) snprintf (buf, 1024, "%s[%d.%s]: %s ", ArgusProgramName, (int)getpid(), pbuf, print_time(&now));
   }
#else
   (void) snprintf (buf, 1024, "%s[%d]: %s ", ArgusProgramName, (int)getpid(), print_time(&now));
#endif

   ptr = &buf[strlen(buf)];
#endif

   va_start (ap, fmt);
   (void) vsnprintf (ptr, 1024, fmt, ap);
   ptr = &buf[strlen(buf)];
   va_end (ap);

   if (daemonflag) {
#ifdef HAVE_SYSLOG
      syslog (LOG_ALERT, "%s", buf);
#endif
   } else {
      char *label = NULL;
      int i;
      if (*fmt) {
         fmt += (int) strlen (fmt);
         if (fmt[-1] != '\n')
            snprintf (ptr, 2, "\n");
      }

      for (i = 0; i < ARGUSPRIORITYSTR; i++)
         if (ArgusPriorityStr[i].priority == priority) {
            label = ArgusPriorityStr[i].label;
            break;
         }

      fprintf (stderr, "%s: %s", label, buf);
   }

   switch (priority) {
      case LOG_ERR: ArgusShutDown(1); break;
      default: break;
   }
}


void ArgusRecordDump (struct ArgusRecord *);
void ArgusDump (const u_char *, int);

#define HEXDUMP_BYTES_PER_LINE 16
#define HEXDUMP_SHORTS_PER_LINE (HEXDUMP_BYTES_PER_LINE / 2)
#define HEXDUMP_HEXSTUFF_PER_SHORT 5 /* 4 hex digits and a space */
#define HEXDUMP_HEXSTUFF_PER_LINE \
                (HEXDUMP_HEXSTUFF_PER_SHORT * HEXDUMP_SHORTS_PER_LINE)


void
ArgusRecordDump (struct ArgusRecord *argus)
{
   int length = argus->hdr.len;
   const u_char *cp = (const u_char *) argus;

   ArgusDump (cp, length);
}


#include <ctype.h>

void
ArgusDump (const u_char *cp, int length)
{
   u_int oset = 0;
   register u_int i;
   register int s1, s2;
   register int nshorts;
   char hexstuff[HEXDUMP_SHORTS_PER_LINE*HEXDUMP_HEXSTUFF_PER_SHORT+1], *hsp;
   char asciistuff[HEXDUMP_BYTES_PER_LINE+1], *asp;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusDump (%p, %d)\n", cp, length);
#endif

   nshorts = length / sizeof(u_short);
   i = 0;
   hsp = hexstuff; asp = asciistuff;
   while (--nshorts >= 0) {
           s1 = *cp++;
           s2 = *cp++;
           (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
               " %02x%02x", s1, s2);
           hsp += HEXDUMP_HEXSTUFF_PER_SHORT;
           *(asp++) = (isgraph(s1) ? s1 : '.');
           *(asp++) = (isgraph(s2) ? s2 : '.');
           if (++i >= HEXDUMP_SHORTS_PER_LINE) {
               *hsp = *asp = '\0';
               (void)printf("\n0x%04x\t%-*s\t%s",
                            oset, HEXDUMP_HEXSTUFF_PER_LINE,
                            hexstuff, asciistuff);
               i = 0; hsp = hexstuff; asp = asciistuff;
               oset += HEXDUMP_BYTES_PER_LINE;
           }
   }
   if (length & 1) {
      s1 = *cp++;
      (void)snprintf(hsp, sizeof(hexstuff) - (hsp - hexstuff),
               " %02x", s1);
           hsp += 3;
           *(asp++) = (isgraph(s1) ? s1 : '.');
           ++i;
   }
   if (i > 0) {
           *hsp = *asp = '\0';
           (void)printf("\n0x%04x\t%-*s\t%s",
                        oset, HEXDUMP_HEXSTUFF_PER_LINE,
                        hexstuff, asciistuff);
   }
}


extern char *ArgusProgramName;
extern int uflag, pflag;

char ArgusPrintTimeBuf[64];

char *
print_time(struct timeval *tvp)
{
   char timeZoneBuf[32];
   char *retn = ArgusPrintTimeBuf, *ptr;
   struct tm *tm, tmbuf;

   bzero (timeZoneBuf, sizeof(timeZoneBuf));
   bzero (ArgusPrintTimeBuf, sizeof(ArgusPrintTimeBuf));

   if ((tm = localtime_r ((time_t *)&tvp->tv_sec, &tmbuf)) != NULL) {
#if !defined(HAVE_STRFTIME)
      snprintf (retn, 32, "%9d", (int) tvp->tv_sec);
#else
      if (uflag)
         snprintf (retn, 32, "%9d", (int) tvp->tv_sec);
      else
         strftime ((char *) retn, 64, RaTimeFormat, tm);
#endif

      if (pflag) {
         ptr = &retn[strlen(retn)];
         snprintf (ptr, 32, ".%06d", (int) tvp->tv_usec);
         ptr[pflag + 1] = '\0';

      }
   } else
      retn = NULL;

   return (retn);
}

#define ArgusAddrtoName

#include <netdb.h>
#include <argus_namedb.h>
#include <argus_ethernames.h>

/* Find the hash node that corresponds the ether address 'ep'. */

static inline struct enamemem *
lookup_emem(struct ArgusParserStruct *parser, const u_char *ep)
{
   u_int i, j, k;
   struct enamemem *tp;

   k = (ep[0] << 8) | ep[1];
   j = (ep[2] << 8) | ep[3];
   i = (ep[4] << 8) | ep[5];

   tp = &parser->enametable[(i ^ j) % (HASHNAMESIZE-1)];
   while (tp->e_nxt)
      if (tp->e_addr0 == i &&
          tp->e_addr1 == j &&
          tp->e_addr2 == k)
         return tp;
      else
         tp = tp->e_nxt;
   tp->e_addr0 = i;
   tp->e_addr1 = j;
   tp->e_addr2 = k;
   tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));

   return tp;
}

/*
   Find the hash node that corresponds the NSAP 'nsap'.

static inline struct enamemem *
lookup_nsap(struct ArgusParserStruct *parser, const u_char *nsap)
{
   u_int i, j, k;
   int nlen = *nsap;
   struct enamemem *tp;
   const u_char *ensap = nsap + nlen - 6;

   if (nlen > 6) {
      k = (ensap[0] << 8) | ensap[1];
      j = (ensap[2] << 8) | ensap[3];
      i = (ensap[4] << 8) | ensap[5];
   }
   else
      i = j = k = 0;

   tp = &parser->nsaptable[(i ^ j) % (HASHNAMESIZE-1)];
   while (tp->e_nxt)
      if (tp->e_addr0 == i &&
          tp->e_addr1 == j &&
          tp->e_addr2 == k &&
          tp->e_nsap[0] == nlen &&
          bcmp((char *)&(nsap[1]),
         (char *)&(tp->e_nsap[1]), nlen) == 0)
         return tp;
      else
         tp = tp->e_nxt;
   tp->e_addr0 = i;
   tp->e_addr1 = j;
   tp->e_addr2 = k;
   tp->e_nsap = (u_char *) calloc(1, nlen + 1);
   bcopy(nsap, tp->e_nsap, nlen + 1);
   tp->e_nxt = (struct enamemem *)calloc(1, sizeof(*tp));

   return tp;
}

*/

/* Find the hash node that corresponds the protoid 'pi'. */

static inline struct protoidmem *
lookup_protoid(struct ArgusParserStruct *parser, const u_char *pi)
{
   u_int i, j;
   struct protoidmem *tp;

   /* 5 octets won't be aligned */
   i = (((pi[0] << 8) + pi[1]) << 8) + pi[2];
   j =   (pi[3] << 8) + pi[4];
   /* XXX should be endian-insensitive, but do big-endian testing  XXX */

   tp = &parser->protoidtable[(i ^ j) % (HASHNAMESIZE-1)];
   while (tp->p_nxt)
      if (tp->p_oui == i && tp->p_proto == j)
         return tp;
      else
         tp = tp->p_nxt;
   tp->p_oui = i;
   tp->p_proto = j;
   tp->p_nxt = (struct protoidmem *)calloc(1, sizeof(*tp));

   return tp;
}


void
ArgusInitServarray(struct ArgusParserStruct *parser)
{
#if !defined(CYGWIN)
   struct servent *sv;
   struct hnamemem *table;
   int i;

   while ((sv = getservent()) != NULL) {
      int port = ntohs(sv->s_port);
      i = port % (HASHNAMESIZE-1);
      if (strcmp(sv->s_proto, "tcp") == 0)
         table = &parser->tporttable[i];
      else if (strcmp(sv->s_proto, "udp") == 0)
         table = &parser->uporttable[i];
      else
         continue;

      while (table->name)
         table = table->nxt;
      if (parser->nflag > 1) {
         char buf[32];

         (void)snprintf(buf, 32, "%d", port);
         table->name = strdup(buf);
      } else
         table->name = strdup(sv->s_name);
      table->addr = port;
      table->nxt = (struct hnamemem *)calloc(1, sizeof(*table));
   }

   parser->ArgusSrvInit = 1;
   endservent();
#endif
}

void
ArgusFreeServarray(struct ArgusParserStruct *parser)
{
   int i, x;
   for (i = 0; i < HASHNAMESIZE; i++) {
      struct hnamemem *table;

      for (x = 0; x < 2; x++) {
         switch (x) {
            case 0: table = parser->tporttable; break;
            case 1: table = parser->uporttable; break;
         }

         if ((struct hnamemem *)&table[i].name != NULL) {
            struct hnamemem *tp, *sp;
            free(table[i].name);
            if ((tp = (struct hnamemem *)table[i].nxt) != NULL) {
               do {
                  if (tp->name != NULL)
                     free (tp->name);
                  sp = tp->nxt;
                  free(tp);
               } while ((tp = sp) != NULL);
            }
         }
      }
   }
}

void
ArgusInitEprotoarray(struct ArgusParserStruct *parser)
{
   struct ArgusEtherTypeStruct *p = argus_ethertype_names;

   bzero ((char *)parser->argus_eproto_db, sizeof (parser->argus_eproto_db));

   while (p->range != NULL) {
      int i, start, end;
      char *ptr;
      
      start = atoi(p->range);

      if ((ptr = strchr(p->range, '-')) != NULL)
         end = atoi(ptr + 1);
      else
         end = start;

      for (i = start; i < (end + 1); i++)
         parser->argus_eproto_db[i] = p;

      p++;
   }
}


/*
 * SNAP proto IDs with org code 0:0:0 are actually encapsulated Ethernet
 * types.
 */



void
ArgusInitProtoidarray(struct ArgusParserStruct *parser)
{
   struct ArgusEtherTypeStruct *p;
   struct protoidmem *tp;
   u_char protoid[5];
   int i;

   bzero(&protoid, sizeof(protoid));
   bzero(&parser->protoidtable, sizeof(parser->protoidtable));

   for (i = 0; i < ARGUS_MAXEPROTODB; i++) {
      if ((p = parser->argus_eproto_db[i]) != NULL) {
         protoid[3] = i;
         tp = lookup_protoid(parser, protoid);
         tp->p_name = p->tag;
      }
   }
}

void
ArgusFreeProtoidarray(struct ArgusParserStruct *parser)
{
   int i;

   for (i = 0; i < HASHNAMESIZE; i++) {
      struct protoidmem *sp = &parser->protoidtable[i], *tp;

      if ((tp = sp->p_nxt) != NULL) {
         do {
            sp = tp->p_nxt;
            free(tp);
         } while ((tp = sp) != NULL);
      }
   }
}

static struct etherlist {
   u_char addr[6];
   char *name;
} etherlist[] = {
   {{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff }, "Broadcast" },
   {{ 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 }, NULL }
};

/*
 * Initialize the ethers hash table.  We take two different approaches
 * depending on whether or not the system provides the ethers name
 * service.  If it does, we just wire in a few names at startup,
 * and etheraddr_string() fills in the table on demand.  If it doesn't,
 * then we suck in the entire /etc/ethers file at startup.  The idea
 * is that parsing the local file will be fast, but spinning through
 * all the ethers entries via NIS & next_etherent might be very slow.
 *
 * XXX argus_next_etherent doesn't belong in the pcap interface, but
 * since the pcap module already does name-to-address translation,
 * it's already does most of the work for the ethernet address-to-name
 * translation, so we just argus_next_etherent as a convenience.
 */


void
ArgusInitEtherarray(struct ArgusParserStruct *parser)
{
   struct etherlist *el;
   struct enamemem *tp;
#ifndef ETHER_SERVICE
   struct argus_etherent *ep;
   FILE *fp;

   /* Suck in entire ethers file */
   fp = fopen(PCAP_ETHERS_FILE, "r");
   if (fp != NULL) {
      while ((ep = argus_next_etherent(fp)) != NULL) {
         tp = lookup_emem(parser, ep->addr);
         tp->e_name = strdup(ep->name);
      }
      (void)fclose(fp);
   }
#endif

   /* Hardwire some ethernet names */
   for (el = etherlist; el->name != NULL; ++el) {
#if defined(ETHER_SERVICE) && !defined(linux) && !defined(CYGWIN)
      /* Use yp/nis version of name if available */
      char wrk[256];
      if (ether_ntohost(wrk, (struct ether_addr *)el->addr) == 0) {
         tp = lookup_emem(parser, el->addr);
         tp->e_name = strdup(wrk);
      }
#else
      /* install if not already present */
      tp = lookup_emem(parser, el->addr);
      if (tp->e_name == NULL)
         tp->e_name = el->name;
#endif
   }
}

void
ArgusFreeEtherarray(struct ArgusParserStruct *parser)
{
   int i;

   for (i = 0; i < HASHNAMESIZE; i++) {
      struct enamemem *tp, *sp;
      if ((tp = (struct enamemem *)parser->enametable[i].e_nxt) != NULL) {
         do {
            sp = tp->e_nxt;
            free(tp);
            tp = sp;
         } while ((tp = sp) != NULL);
      }
   }
}

#include <argus_int.h>

static struct ArgusTokenStruct llcsap_db[] = {
   { LLCSAP_NULL,   "null" },
   { LLCSAP_8021B_I,   "gsap" },
   { LLCSAP_8021B_G,   "isap" },
   { LLCSAP_SNAPATH,   "snapath" },
   { LLCSAP_IP,      "ipsap" },
   { LLCSAP_SNA1,   "sna1" },
   { LLCSAP_SNA2,   "sna2" },
   { LLCSAP_PROWAYNM,   "p-nm" },
   { LLCSAP_TI,      "ti" },
   { LLCSAP_BPDU,   "stp" },
   { LLCSAP_RS511,   "eia" },
   { LLCSAP_ISO8208,   "x25" },
   { LLCSAP_XNS,   "xns" },
   { LLCSAP_NESTAR,   "nestar" },
   { LLCSAP_PROWAYASLM,   "p-aslm" },
   { LLCSAP_ARP,   "arp" },
   { LLCSAP_SNAP,   "snap" },
   { LLCSAP_VINES1,   "vine1" },
   { LLCSAP_VINES2,   "vine2" },
   { LLCSAP_NETWARE,   "netware" },
   { LLCSAP_NETBIOS,   "netbios" },
   { LLCSAP_IBMNM,   "ibmnm" },
   { LLCSAP_RPL1,   "rpl1" },
   { LLCSAP_UB,      "ub" },
   { LLCSAP_RPL2,   "rpl2" },
   { LLCSAP_ISONS,   "clns" },
   { LLCSAP_GLOBAL,   "gbl" },
   { 0,             NULL }
};

void
ArgusInitLlcsaparray(struct ArgusParserStruct *parser)
{
   int i;
   struct hnamemem *table;

   for (i = 0; llcsap_db[i].s != NULL; i++) {
      table = &parser->llcsaptable[llcsap_db[i].v];
      while (table->name)
         table = table->nxt;
      table->name = llcsap_db[i].s;
      table->addr = llcsap_db[i].v;
      table->nxt = (struct hnamemem *)calloc(1, sizeof(*table));
   }
}

void
ArgusFreeLlcsaparray(struct ArgusParserStruct *parser)
{
   int i;
   struct hnamemem *table;

   for (i = 0; llcsap_db[i].s != NULL; i++) {
      struct hnamemem *ttbl;
      table = &parser->llcsaptable[llcsap_db[i].v];
      if ((table = table->nxt) != NULL) {
         do {
            ttbl = table;
            table = table->nxt;
            free(ttbl);
         } while (table);
      }
   }
}

char *argus_dscodes[0x100];
void ArgusInitDSCodepointarray(struct ArgusParserStruct *);
struct ArgusDSCodePointStruct *ArgusSelectDSCodesTable(struct ArgusParserStruct *);

struct ArgusDSCodePointStruct *
ArgusSelectDSCodesTable(struct ArgusParserStruct *parser)
{
   struct ArgusDSCodePointStruct *retn = NULL;

   switch (parser->ArgusDSCodePoints) {
      case ARGUS_IANA_DSCODES: retn = argus_dscodepoints; break;
      case ARGUS_DISA_DSCODES: retn = argus_disa_dscodepoints; break;
   }
   return (retn);
}

void
ArgusInitDSCodepointarray(struct ArgusParserStruct *parser)
{
   struct ArgusDSCodePointStruct *argus_dsctable = argus_dscodepoints;
   int i;

   bzero (&argus_dscodes, sizeof(argus_dscodes));

   if ((argus_dsctable = ArgusSelectDSCodesTable(parser)) != NULL) {
      for (i = 0; argus_dsctable[i].label != NULL; i++)
         argus_dscodes[(int)argus_dsctable[i].code] = argus_dsctable[i].label;
   }
}


/*
 * Initialize the address to name translation machinery.  We map all
 * non-local IP addresses to numeric addresses if fflag is true (i.e.,
 * to prevent blocking on the nameserver).  localnet is the IP address
 * of the local network.  mask is its subnet mask.
 */



void
ArgusInitAddrtoname(struct ArgusParserStruct *parser, u_int localnet, u_int mask)
{
   if (parser->fflag) {
      parser->f_localnet = localnet;
      parser->f_netmask = mask;
   }

   if (parser->nflag > 1)
      /*
       * Simplest way to suppress names.
       */
      return;

   ArgusInitEtherarray(parser);
   ArgusInitServarray(parser);
   ArgusInitEprotoarray(parser);
   ArgusInitLlcsaparray(parser);
   ArgusInitProtoidarray(parser);
   ArgusInitDSCodepointarray(parser);
}


#ifndef __GNUC__
#define inline
#endif

/*
 * Convert a port name to its port and protocol numbers.
 * We assume only TCP or UDP.
 * Return 0 upon failure.
 */
int
argus_nametoport(char *name, int *port, int *proto)
{
   struct protoent *pp = NULL;
   struct servent *sp = NULL;
   char *pname = NULL, *other;

#ifdef ARGUSDEBUG
   ArgusDebug (8, "argus_nametoport (%s, .., ..) starting\n", name);
#endif

   if ((proto != NULL) && (*proto != -1)) {
#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport (%s, .., %d) calling getprotobynumber\n", name, *proto);
#endif
      if ((pp = getprotobynumber(*proto)) != NULL) {
         pname = pp->p_name;
      } else
         ArgusLog(LOG_ERR, "getprotobynumber(%d) returned NULL %s", *proto, strerror(errno));
   }

   if (name != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport: calling getservbyname(%s, %s)\n", name, pname);
#endif
      sp = getservbyname(name, pname);

#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport: getservbyname() returned %p\n", sp);
#endif
   }

   if (sp != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport: sp is %p\n", sp);
#endif
      *port = ntohs(sp->s_port);

#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport (%s, .., ..) calling argus_nametoproto(%s)\n", sp->s_proto);
#endif

      *proto = argus_nametoproto(sp->s_proto);
      /*
       * We need to check /etc/services for ambiguous entries.
       * If we find the ambiguous entry, and it has the
       * same port number, change the proto to PROTO_UNDEF
       * so both TCP and UDP will be checked.
       */
      if (*proto == IPPROTO_TCP)
         other = "udp";
      else
         other = "tcp";

      sp = getservbyname(name, other);
      if (sp != 0) {
         if (*port != ntohs(sp->s_port))
            /* Can't handle ambiguous names that refer
               to different port numbers. */
            ArgusLog(LOG_ERR, "ambiguous port %s in /etc/services values %d and %d", name, *port, ntohs(sp->s_port));
         *proto = PROTO_UNDEF;
      }

#ifdef ARGUSDEBUG
      ArgusDebug (8, "argus_nametoport (%s, %d, %d)\n", name, *port, *proto);
#endif
      return 1;
   }

#if defined(ultrix) || defined(__osf__)
   /* Special hack in case NFS isn't in /etc/services */
   if (strcmp(name, "nfs") == 0) {
      *port = 2049;
      *proto = PROTO_UNDEF;
      return 1;
   }
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (8, "argus_nametoport (%s, %d, %d)\n", name, *port, *proto);
#endif

   return 0;
}

int
argus_nametoproto(char *str)
{
   struct protoent *p;

   p = getprotobyname(str);
   if (p != 0)
      return p->p_proto;
   else
      return PROTO_UNDEF;
}


int
argus_nametoeproto(char *s)
{
   struct ArgusEtherTypeStruct *p = argus_ethertype_names;

   while (p->tag != 0) {
      if (strcmp(p->tag, s) == 0) {
         return atoi(p->range);
      }
      p += 1;
   }

   return PROTO_UNDEF;
}

u_int
__argus_atoin(char *s, u_int *addr)
{
   u_int n;
   int len;

   *addr = 0;
   len = 0;
   while (1) {
      n = 0;
      while (*s && *s != '.')
         n = n * 10 + *s++ - '0';
      *addr <<= 8;
      *addr |= n & 0xff;
      len += 8;
      if (*s == '\0') {
         *addr = *addr;
         return len;
      }
      ++s;
   }
   /* NOTREACHED */
}

u_int
__argus_atodn(char *s)
{
#define AREASHIFT 10
#define AREAMASK 0176000
#define NODEMASK 01777

   u_int addr = 0;
   u_int node, area;

   if (sscanf((char *)s, "%d.%d", (int *) &area, (int *) &node) != 2)
      ArgusLog (LOG_ERR,"malformed decnet address '%s'", s);

   addr = (area << AREASHIFT) & AREAMASK;
   addr |= (node & NODEMASK);

   return(addr);
}

/*
 * Convert 's' which has the form "xx:xx:xx:xx:xx:xx" into a new
 * ethernet address.  Assumes 's' is well formed.
 */

/* Hex digit to integer. */
 
int xdtoi(int);
 
int
xdtoi(int c)
{
   if (isdigit(c))
      return c - '0';
   else if (islower(c))
      return c - 'a' + 10;
   else
      return c - 'A' + 10;
}


u_char *
argus_ether_aton(char *s)
{
   register u_char *ep, *e;
   register u_int d;

   e = ep = (u_char *)malloc(6);

   while (*s) {
      if (*s == ':')
         s += 1;
      d = xdtoi(*s++);
      if (isxdigit((int)*s)) {
         d <<= 4;
         d |= xdtoi(*s++);
      }
      *ep++ = d;
   }

   return (e);
}

#ifndef HAVE_ETHER_HOSTTON 
u_char *
argus_ether_hostton(char *name)
{
   register struct argus_etherent *ep;
   register u_char *ap;
   static FILE *fp = NULL;
   static int init = 0;

   if (!init) {
      fp = fopen(PCAP_ETHERS_FILE, "r");
      ++init;
      if (fp == NULL)
         return (NULL);
   } else if (fp == NULL)
      return (NULL);
   else
      rewind(fp);
   
   while ((ep = argus_next_etherent(fp)) != NULL) {
      if (strcmp(ep->name, name) == 0) {
         ap = (u_char *)malloc(6);
         if (ap != NULL) {
            memcpy(ap, ep->addr, 6);
            return (ap);
         }
         break;
      }
   }
   return (NULL);
}
#else
#if !defined(HAVE_DECL_ETHER_HOSTTON) || !HAVE_DECL_ETHER_HOSTTON
#ifndef HAVE_STRUCT_ETHER_ADDR
struct ether_addr {
   unsigned char ether_addr_octet[6];
};
#endif
#if !defined(__APPLE_CC__) && !defined(__APPLE__)
extern int ether_hostton(const char *, struct ether_addr *);
#endif
#endif

u_char *
argus_ether_hostton(char *name)
{
   register u_char *ap;
   u_char a[6];

   ap = NULL;
   if (ether_hostton((char*)name, (struct ether_addr *)a) == 0) {
      ap = (u_char *)malloc(6);
      if (ap != NULL)
         memcpy(ap, a, 6);
   }
   return (ap);
}
#endif

u_short
__argus_nametodnaddr(char *name)
{
#ifndef   DECNETLIB
   ArgusLog (LOG_ERR,"decnet name support not included, '%s' cannot be translated\n", name);
   return(0);
#else
   struct nodeent *getnodebyname();
   struct nodeent *nep;
   u_short res;

   nep = getnodebyname(name);
   if (nep == ((struct nodeent *)0))
      ArgusLog (LOG_ERR,"unknown decnet host name '%s'\n", name);

   memcpy((char *)&res, (char *)nep->n_addr, sizeof(u_short));

   return(res);
#endif
}

 
u_int
ipaddrtonetmask(u_int addr)
{
   if (IN_CLASSA (addr)) return IN_CLASSA_NET;
   if (IN_CLASSB (addr)) return IN_CLASSB_NET;
   if (IN_CLASSC (addr)) return IN_CLASSC_NET;
   if (IN_CLASSD (addr)) return 0xFFFFFFFF;
   else return 0;
}
 
 
u_int
getnetnumber( u_int addr)
{
   if (IN_CLASSA (addr)) return (addr >> 24 );
   if (IN_CLASSB (addr)) return (addr >> 16 );
   if (IN_CLASSC (addr)) return (addr >>  8 );
   if (IN_CLASSD (addr)) return (addr >>  0 );
   else return 0;
}

static char hex[] = "0123456789abcdef"; 
char etheraddrbuf[32];

char *
etheraddr_string(struct ArgusParserStruct *parser, u_char *ep)
{
   char *cp = etheraddrbuf;
   u_int i, j;

   bzero (cp, sizeof(etheraddrbuf));
   if ((j = *ep >> 4) != 0)
      *cp++ = hex[j];
   *cp++ = hex[*ep++ & 0xf];
   for (i = 5; (int)--i >= 0;) {
      *cp++ = ':';
      if ((j = *ep >> 4) != 0)
         *cp++ = hex[j];
      *cp++ = hex[*ep++ & 0xf];
   }
   return (etheraddrbuf);
}


/*
   There are two types of addresses to parse, IPv4 and IPv6
   addresses.  An address is in the form:
     dd[.:][:][dd]/n

   where n is the number significant bits in the address.
*/
int ArgusNumTokens (char *, char);
   
int
ArgusNumTokens (char *str, char tok)
{
   int retn = 0;
   if (str != NULL) {
      while ((str = strchr(str, tok)) != NULL) {
         retn++;
         str++;
      }
   }
   return (retn);
}


struct ArgusCIDRAddr *
RaParseCIDRAddr (struct ArgusParserStruct *parser, char *addr)
{
   struct ArgusCIDRAddr *retn = NULL;
   char *ptr = NULL, *mask = NULL, strbuf[128], *str = strbuf;

   snprintf (str, 128, "%s", addr);
   if (parser->ArgusCIDRPtr == NULL)
      parser->ArgusCIDRPtr = &parser->ArgusCIDRBuffer;

   retn = parser->ArgusCIDRPtr;
   retn->type     = 0;
   retn->len      = 0;
   retn->masklen  = 0;
   memset(&retn->addr, 0, sizeof(retn->addr));

   if ((ptr = strchr(str, '!')) != NULL) {
      retn->opmask = ARGUSMONITOR_NOTEQUAL;
      str = ptr + 1;
   }

   if ((mask = strchr (str, '/')) != NULL) {
      *mask++ = '\0';
      retn->masklen = strtol((const char *)mask, (char **)&ptr, 10);
      if (ptr == mask) {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "RaParseCIDRAddr: format error: mask length incorrect.\n", retn);
#endif
         return (NULL);
      }
   }

   if ((ptr = strchr (str, ':')) != NULL)
      retn->type = AF_INET6;
   else
   if ((ptr = strchr (str, '.')) != NULL)
      retn->type = AF_INET;
  
   if (!(retn->type))
      retn->type = (retn->masklen > 32) ? AF_INET6 : AF_INET;
   
   switch (retn->type) {
      case AF_INET: {
         int i, len = sizeof(struct in_addr);
 
         retn->len = len;
         for (i = 0; (i < len) && str; i++) {
            long int tval = strtol(str, (char **)&ptr, 10);
            if (ptr != NULL) {
               if (strlen(ptr) > 0) {
                  if (*ptr++ != '.') {
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "RaParseCIDRAddr: format error: IPv4 addr format.\n");
#endif
                     return(NULL);
                  }
               } else
                  ptr = NULL;

               retn->addr[0] |= (tval << ((len - (i + 1)) * 8));
            }
            str = ptr;
         }

         if (!(retn->masklen)) retn->masklen = 32;
         retn->mask[0] = 0xFFFFFFFF << (32 - retn->masklen);
         break;
      }

      case AF_INET6: {
         unsigned short *val = (unsigned short *)&retn->addr;
         int ind = 0, len = sizeof(retn->addr)/sizeof(unsigned short);
         int fsecnum = 8, lsecnum = 0, rsecnum = 0, i, masklen;
         char *sstr = NULL, *ipv4addr = NULL;

         retn->len = sizeof(retn->addr);
         if ((sstr = strstr(str, "::")) != NULL) {
            *sstr++ = '\0';
            *sstr++ = '\0';
            if (strlen(str))
               fsecnum = ArgusNumTokens(str,  ':') + 1;
            if (strlen(sstr))
               lsecnum = ArgusNumTokens(sstr, ':') + 1;
            if (!(retn->masklen))
               retn->masklen = 128;
         } else
            sstr = str;

         if (strchr (sstr, '.')) {
            lsecnum += (lsecnum > 0) ? 1 : 2;
            if ((ipv4addr = strrchr(sstr, ':')) == NULL) {
               ipv4addr = sstr;
               sstr = NULL;
            } else {
               *ipv4addr++ = '\0';
            }
         }

         if (fsecnum + lsecnum) {
            rsecnum = 8 - (fsecnum + lsecnum);
            if (fsecnum) {
               while (str && *str && (ind++ < len)) {
                  *val++ = htons(strtol(str, (char **)&ptr, 16));

                  if (ptr != NULL) {
                     if (strlen(ptr) > 0) {
                        if (*ptr++ != ':') {
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "RaParseCIDRAddr: format error: IPv4 addr format.\n");
#endif
                           return(NULL);
                        }
                     } else
                        ptr = NULL;
                  }
                  str = ptr;
               }
            }

            for (i = 0; i < rsecnum; i++)
               *val++ = 0;
            if (lsecnum) {
               if ((str = sstr) != NULL) {
                  while (str && (ind++ < len)) {
                     *val++ = htons(strtol(str, (char **)&ptr, 16));

                     if (ptr != NULL) {
                        if (strlen(ptr) > 0) {
                           if (*ptr++ != ':') {
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "RaParseCIDRAddr: format error: IPv4 addr format.\n");
#endif
                              return(NULL);
                           }
                        } else
                           ptr = NULL;
                     }
                     str = ptr;
                  }
               }
            }

            if (ipv4addr) {
               unsigned char *cval = (unsigned char *)&retn->addr[3];
               int ind = 0, len = sizeof(struct in_addr);
 
               while (ipv4addr && (ind++ < len)) {
                  *cval++ = strtol(ipv4addr, (char **)&ptr, 10);
                  if (ptr != NULL) {
                     if (strlen(ptr) > 0) {
                        if (*ptr++ != '.') {
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "RaParseCIDRAddr: format error: IPv4 addr format.\n");
#endif
                           return(NULL);
                        }
                     } else
                        ptr = NULL;
                  }
                  ipv4addr = ptr;
               }
               retn->masklen = 128;
            }
         }

         if (!(retn->masklen)) {
            retn->masklen = (((char *)val - (char *)&retn->addr)) * 8;
         }

         for (i = 0; i < 4; i++) retn->mask[i] = 0;

         if ((masklen = retn->masklen) > 0) {
            unsigned int *mask = &retn->mask[0];

            while (masklen) {
               if (masklen > 32) {
                  *mask++ = 0xFFFFFFFF;
                  masklen -= 32;
               } else {
                  *mask = 0xFFFFFFFF << masklen;
                  masklen = 0;
               }
            }
         }
         break;
      }

      default:
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (9, "RaParseCIDRAddr: returning %p \n", retn);
#endif
   
   return (retn);
}

#if !defined(HAVE_FLOORF)
/*  floorf.c: Returns the integer smaller or equal than x

    Copyright (C) 2001, 2002  Jesus Calvino-Fraga, jesusc@ieee.org

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307 USA */

/* Version 1.0 - Initial release */

float floorf (float x)
{
    long r;
    r=x;
    if (r<=0)
        return (r+((r>x)?-1:0));
    else
        return r;
}
#endif

#if !defined(HAVE_REMAINDERF)

/* no copyright on remainderf - Author LB */
float remainderf(float x, float y)
{
    float r;
    r = x - ((int) (x/y+0.5)) * y;
    return r;
}
#endif
