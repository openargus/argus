/*
 * Argus Software.  Argus files - Input processing
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
 * $Id: //depot/argus/argus/argus/ArgusSource.c#134 $
 * $DateTime: 2016/04/05 12:00:14 $
 * $Change: 3135 $
 */

/*
 * ArgusSource.c - Argus packet source routines.
 *
 * written by Carter Bullard
 * QoSient, LLC
 * Tue Aug  8 08:13:36 EDT 2000
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#define ARGUS_NEW_INTERFACE_STRATEGY   1   

#if !defined(ArgusSource)
#define ArgusSource
#endif

#include <stdlib.h>
#if defined(__APPLE_CC__) || defined(__APPLE__)
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <sys/ioctl.h>
#include <net/bpf.h>
#endif


#if defined(HAVE_NETINET_IN_H)
#include <netinet/in.h>
#endif

#if defined(HAVE_ARPA_INET_H)
#include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ctype.h>
#include <argus.h>

#include <sys/mman.h>
#include <net/ppp.h>
#if !defined(PPP_HDRLEN)
#define PPP_HDRLEN      4       /* length of PPP header */
#endif

void ArgusGetInterfaceStatus (struct ArgusSourceStruct *src);
void setArgusPcapBufSize (struct ArgusSourceStruct *, int);


struct ArgusDeviceStruct *
ArgusCloneDevice(struct ArgusDeviceStruct *dev)
{
   struct ArgusDeviceStruct *retn = NULL;

   if ((retn = (void *) ArgusCalloc(1, sizeof(*retn))) == NULL)
      ArgusLog (LOG_ERR, "ArgusCloseDevice: ArgusCalloc error %s\n", strerror(errno));

   retn->status = dev->status;
   retn->type   = dev->type;
   retn->link   = dev->link;

   bcopy((char *)&dev->ArgusID, (char *)&retn->ArgusID, sizeof(dev->ArgusID));
   retn->idtype = dev->idtype;
   retn->name   = strdup(dev->name);

   return (retn);
}

struct ArgusSourceStruct *
ArgusCloneSource(struct ArgusSourceStruct *src)
{
   struct ArgusSourceStruct *retn =  NULL;
   int i;

   if ((retn = (struct ArgusSourceStruct *) ArgusCalloc (1, sizeof (struct ArgusSourceStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusCloneSource: ArgusCalloc error %s\n", strerror(errno));

   retn->state  = src->state;
   retn->status = src->status;
   retn->mode   = src->mode;

   retn->ArgusPcapBufSize   = src->ArgusPcapBufSize;

   if (src->ArgusDeviceList) {
      int i, count = src->ArgusDeviceList->count;

      retn->ArgusDeviceList = ArgusNewList();
      for (i = 0; i < count; i++) {
         struct ArgusDeviceStruct *dev, *device = (struct ArgusDeviceStruct *) ArgusPopFrontList(src->ArgusDeviceList, ARGUS_LOCK);
         if ((dev = ArgusCloneDevice(device)) == NULL)
            ArgusLog (LOG_ERR, "ArgusCloneSource: ArgusCloneDevice error %s\n", strerror(errno));

         ArgusPushBackList(retn->ArgusDeviceList, (struct ArgusListRecord *) dev, ARGUS_LOCK);
         ArgusPushBackList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);
      }
   }

   if (src->ArgusInputFilter)
      retn->ArgusInputFilter = strdup(src->ArgusInputFilter);

   if (src->ArgusWriteOutPacketFile)
      retn->ArgusWriteOutPacketFile = strdup(src->ArgusWriteOutPacketFile);

   retn->ArgusDumpPacket = src->ArgusDumpPacket;
   retn->ArgusDumpPacketOnError = src->ArgusDumpPacketOnError;

   retn->ArgusStartTime = src->ArgusStartTime;
   retn->ArgusEndTime = src->ArgusEndTime;
   retn->lasttime =  retn->lasttime;

   retn->ArgusSnapLength = src->ArgusSnapLength;
   retn->ArgusThisLength = src->ArgusThisLength;

   retn->ArgusInterfaceType = src->ArgusInterfaceType;
   retn->ArgusInterfaceStatus = src->ArgusInterfaceStatus;

   retn->Argustflag = src->Argustflag;
   retn->sNflag = src->sNflag;
   retn->eNflag = src->eNflag;
   retn->kflag = src->kflag;
   retn->pflag = src->pflag;
   retn->uflag = src->uflag;
   retn->Tflag = src->Tflag;

   retn->ArgusInterfaceIndex = src->ArgusInterfaceIndex;
   retn->ArgusThisIndex = src->ArgusThisIndex;
   retn->ArgusInterfaces = src->ArgusInterfaces;

   for (i = 0; i < src->ArgusInterfaceIndex; i++)
      bcopy(&src->ArgusInterface[i], &retn->ArgusInterface[i], sizeof(src->ArgusInterface[i]));

   retn->ArgusInputPacketFileType = src->ArgusInputPacketFileType;
   retn->ArgusReadingOffLine = src->ArgusReadingOffLine;

   retn->Argusbpflag  = src->Argusbpflag;
   retn->ArgusCaptureFlag = src->ArgusCaptureFlag;

   retn->ArgusSnapLen = src->ArgusSnapLen;

   retn->Argusfflag = src->Argusfflag;
   retn->ArgusOflag  = src->ArgusOflag;
   retn->Arguspflag = src->Arguspflag;

   retn->ArgusArgv = src->ArgusArgv;
   retn->ArgusOptind = src->ArgusOptind;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusCloneSource(%p) returning %p\n", src, retn);
#endif
   return (retn);
}


struct ArgusSourceStruct *
ArgusNewSource(struct ArgusModelerStruct *model)
{
   struct ArgusSourceStruct *retn =  NULL;
 
   if ((retn = (struct ArgusSourceStruct *) ArgusCalloc (1, sizeof (struct ArgusSourceStruct))) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewSource: ArgusCalloc error %s\n", strerror(errno));

   retn->ArgusModel = model;
   retn->sNflag = -1;
   retn->eNflag = -1;
   retn->ArgusSnapLen = ARGUS_MINSNAPLEN;

#if defined(ARGUS_THREADS)
   if (pthread_mutex_init(&retn->lock, NULL))
      ArgusLog (LOG_ERR, "ArgusNewSource: pthread_mutex_init error\n");

   if (pthread_cond_init(&retn->cond, NULL))
      ArgusLog (LOG_ERR, "ArgusNewSource: pthread_cond_init errors\n");
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusNewSource(%p) returning %p\n", model, retn);
#endif

   return (retn);
}

void setArgusThreadCount (struct ArgusSourceStruct *, char *);
int getArgusThreadCount (struct ArgusSourceStruct *);
#define ARGUS_MAX_THREADS       64

int
getArgusThreadCount (struct ArgusSourceStruct *src)
{
   return(src->tflag);
}

void
setArgusThreadCount (struct ArgusSourceStruct *src, char *arg)
{
   char *ptr = NULL;
   int num = 0;
  
   if (src != NULL) {
      num = (int)strtol(arg, (char **)&ptr, 10);
      if (ptr == arg)
         ArgusLog (LOG_ERR, "setArgusThreadCount format error %s not integer\n", arg);

      if ((src->tflag = num) > ARGUS_MAX_THREADS)
         ArgusLog (LOG_ERR, "setArgusThreadCount error %d tooo many threads\n", num);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "setArgusThreadCount(%p, %d)\n", src, num);
#endif
}


#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

int ArgusOpenDevice(struct ArgusSourceStruct *, struct ArgusDeviceStruct *, struct ArgusInterfaceStruct *);
int ArgusOpenInterface(struct ArgusSourceStruct *, struct ArgusDeviceStruct *, struct ArgusInterfaceStruct *);

int
ArgusOpenDevice(struct ArgusSourceStruct *src, struct ArgusDeviceStruct *device, struct ArgusInterfaceStruct *inf)
{
   int retn = 0, count, i, cnt = src->ArgusInterfaces;

   if (device) {
      if (device->list && (count = device->list->count)) {
         for (i = 0; i < count; i++) {
            struct ArgusDeviceStruct *dev = (struct ArgusDeviceStruct *) ArgusPopFrontList(device->list, ARGUS_LOCK);
            src->ArgusInterfaces += ArgusOpenInterface(src, dev, &src->ArgusInterface[src->ArgusInterfaces]);
            ArgusPushBackList(device->list, (struct ArgusListRecord *) device, ARGUS_LOCK);
         }

      } else {
         src->ArgusInterfaces += ArgusOpenInterface(src, device, &src->ArgusInterface[src->ArgusInterfaces]);
      }
   }

   retn = (src->ArgusInterfaces - cnt);
   return retn;
}

int
ArgusOpenInterface(struct ArgusSourceStruct *src, struct ArgusDeviceStruct *device, struct ArgusInterfaceStruct *inf)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   int type, retn = 0;

   extern int ArgusShutDownFlag;

   if (ArgusShutDownFlag) {
      ArgusShutDown(0);
      return retn;
   }

   if ((device == NULL) || (device->name == NULL)) {
      if (inf->ArgusDevice)
         device = inf->ArgusDevice;
      else
         return retn;
   }

   inf->ArgusDevice = device;

#ifdef HAVE_PCAP_SET_BUFFER_SIZE
   if ((inf->ArgusPd = pcap_create(device->name, errbuf)) != NULL) {
      pcap_set_snaplen(inf->ArgusPd, src->ArgusSnapLen);
      pcap_set_promisc(inf->ArgusPd, !src->Arguspflag);
      pcap_set_timeout(inf->ArgusPd, 100);

      if (src->ArgusPcapBufSize > 0) {
         pcap_set_buffer_size(inf->ArgusPd, src->ArgusPcapBufSize);
#ifdef ARGUSDEBUG
         ArgusDebug (4, "ArgusOpenInterface() pcap_set_buffer_size(%p, %d)\n", src, src->ArgusPcapBufSize);
#endif
      }
      switch (retn = pcap_activate(inf->ArgusPd)) {
         case PCAP_ERROR_ACTIVATED:
         case PCAP_ERROR_NO_SUCH_DEVICE:
         case PCAP_ERROR_PERM_DENIED:
#if defined(PCAP_ERROR_PROMISC_PERM_DENIED)
         case PCAP_ERROR_PROMISC_PERM_DENIED:
#endif
         case PCAP_ERROR:  {
            ArgusLog (LOG_WARNING, "ArgusOpenInterface %s: %s\n", device->name, pcap_geterr(inf->ArgusPd));
            pcap_close(inf->ArgusPd);
            inf->ArgusPd = NULL;
            retn = 0;
            break;
         }

         case PCAP_ERROR_IFACE_NOT_UP:
         case PCAP_WARNING_PROMISC_NOTSUP:
#if defined(PCAP_WARNING_TSTAMP_TYPE_NOTSUP)
         case PCAP_WARNING_TSTAMP_TYPE_NOTSUP:
#endif
         case PCAP_WARNING:
         default: 
            retn = 1;
      }
#else
   if ((inf->ArgusPd = pcap_open_live(device->name, src->ArgusSnapLen, !src->Arguspflag, 100, errbuf)) != NULL) {
#endif
      if (inf->ArgusPd != NULL) {
            pcap_setnonblock(inf->ArgusPd, 1, errbuf);

            if (device->dltname != NULL) {
#ifdef HAVE_PCAP_SET_DATALINK
               if (pcap_set_datalink(inf->ArgusPd, device->dlt) < 0)
                  ArgusLog(LOG_ERR, "%s", pcap_geterr(inf->ArgusPd));
#else
               /*
                * We don't actually support changing the
                * data link type, so we only let them
                * set it to what it already is.
                */

               if (device->dlt != pcap_datalink(inf->ArgusPd))
                  ArgusLog(LOG_ERR, "%s is not one of the DLTs supported by this device\n", device->dltname);
#endif
            }

#if defined(__APPLE_CC__) || defined(__APPLE__)
            {   int v = 1; ioctl(pcap_fileno(inf->ArgusPd), BIOCIMMEDIATE, &v);  }
#endif
            src->ArgusInputPacketFileType = ARGUSLIBPPKTFILE;
            inf->ArgusInterfaceType = ARGUSLIBPPKTFILE;
            memset((char *)&inf->ifr, 0, sizeof(inf->ifr));
            strncpy(inf->ifr.ifr_name, device->name, sizeof(inf->ifr.ifr_name));
            if (!((pcap_lookupnet (device->name, (u_int *)&inf->ArgusLocalNet,
                                                 (u_int *)&inf->ArgusNetMask, errbuf)) < 0)) {
#if defined(_LITTLE_ENDIAN)
               inf->ArgusLocalNet = ntohl(inf->ArgusLocalNet);
               inf->ArgusNetMask  = ntohl(inf->ArgusNetMask);
#endif
            }

            type = pcap_datalink(inf->ArgusPd);

            if ((inf->ArgusCallBack = Arguslookup_pcap_callback(type)) == NULL)
               ArgusLog (LOG_ERR, "unsupported device type %d\n", type);
            retn = 1;
      }
#ifdef HAVE_PCAP_SET_BUFFER_SIZE
   }
#else
   }
#endif
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusOpenInterface(%p, '%s') returning %d\n", src, inf->ArgusDevice->name, retn);
#endif
   return retn;
}

#if defined(CYGWIN)
#include <pcap.h>
#endif

#define MAX_RECEIVE_PACKETS (2000)

int
ArgusInitSource (struct ArgusSourceStruct *src)
{
   char errbuf[PCAP_ERRBUF_SIZE];
   char *cmdbuf = NULL;
   int retn = 0, i = 0;

   src->ArgusInterfaces = 0;
   bzero ((char *)&src->ArgusInterface, sizeof(src->ArgusInterface));

   if (src->ArgusDeviceList == NULL) {
      pcap_if_t *d;

      if (pcap_findalldevs(&src->ArgusPacketDevices, errbuf) == -1)
         ArgusLog (LOG_ERR, "ArgusInitSource: pcap_findalldevs_ex %s\n", errbuf);

      for (d = src->ArgusPacketDevices; d != NULL; d = d->next) {
#if defined(CYGWIN)
         printf ("%d. %s", ++i, d->name);
         if (d->description)
            printf (" (%s)\n", d->description);
         else
            printf ("\n");
#else
         i++;
#if defined(ARGUS_NEW_INTERFACE_STRATEGY)
         setArgusDevice (src, d->name, ARGUS_LIVE_DEVICE, 0);
#endif
#endif
      }
#if defined(ARGUS_NEW_INTERFACE_STRATEGY)
      if (i == 0) 
         ArgusLog (LOG_ERR, "ArgusInitSource: no interfaces\n");
#endif

      pcap_freealldevs(src->ArgusPacketDevices);

#if defined(CYGWIN)
      exit(1);
#else
#if !defined(ARGUS_NEW_INTERFACE_STRATEGY)
      setArgusDevice (src, pcap_lookupdev (errbuf), ARGUS_LIVE_DEVICE, 0);
#endif
#endif
   }

   if (src->ArgusDeviceList) {
      int count = src->ArgusDeviceList->count;

      for (i = 0; i < count; i++) {
         struct ArgusDeviceStruct *device = (struct ArgusDeviceStruct *) ArgusPopFrontList(src->ArgusDeviceList, ARGUS_LOCK);

         if (device != NULL) {
            switch (device->type) {
               case ARGUS_LIVE_DEVICE:
                  src->ArgusInterfaces += ArgusOpenDevice(src, device, &src->ArgusInterface[src->ArgusInterfaces]);
                  break;

               case ARGUS_FILE_DEVICE:
                  src->ArgusInterfaces += ArgusOpenInputPacketFile(src, device, &src->ArgusInterface[i]);
                  break;
            }
            ArgusPushBackList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);
         }
      }
   }

   if (src->ArgusInterfaces > 0) {
      if (setuid(getuid()) != 0)
         ArgusLog (LOG_ERR, "ArgusInitSource: setuid %s\n",  strerror(errno));

      cmdbuf = ArgusCopyArgv(&src->ArgusArgv[src->ArgusOptind]);

      if (cmdbuf) {
         if (src->ArgusInputFilter)
            ArgusFree(src->ArgusInputFilter);

         src->ArgusInputFilter = cmdbuf;
      }

      if (src->ArgusInputFilter != NULL) {
         for (i = 0; i < src->ArgusInterfaces; i++) {
            if (src->ArgusInterface[i].ArgusPd) {
               bzero ((char *) &src->ArgusInterface[i].ArgusFilter, sizeof (struct bpf_program));

               if (pcap_compile (src->ArgusInterface[i].ArgusPd, &src->ArgusInterface[i].ArgusFilter, src->ArgusInputFilter, getArgusOflag(src), src->ArgusInterface[i].ArgusNetMask) < 0)
                  ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[i].ArgusPd));

               if (src->Argusbpflag) {
                  Argusbpf_dump (&src->ArgusInterface[i].ArgusFilter, src->Argusbpflag);
                  exit(0);
               }

               if (src->ArgusInputPacketFileType == ARGUSLIBPPKTFILE) {
                  if (src->ArgusInputFilter != NULL) {
                     if (pcap_setfilter (src->ArgusInterface[i].ArgusPd, &src->ArgusInterface[i].ArgusFilter) < 0)
                        ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[i].ArgusPd));
                  }
               }
            }
         }
      }

      if (src->ArgusWriteOutPacketFile) {
         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      src->ArgusModel = ArgusCloneModeler(ArgusModel);
      src->ArgusModel->ArgusSrc = src;
      ArgusInitModeler(src->ArgusModel);

#if defined(ARGUS_THREADS)
      if (pthread_mutex_init(&src->lock, NULL))
         ArgusLog (LOG_ERR, "ArgusInitSource: pthread_mutex_init error\n");

      if (pthread_cond_init(&src->cond, NULL))
         ArgusLog (LOG_ERR, "ArgusInitSource: pthread_cond_init error\n");
#endif

      retn = 1;

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusInitSource: no packet sources for this device.");
#endif
   }
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitSource(%p) returning %d\n", src, retn);
#endif

   return retn;
}


int
ArgusCloseSource(struct ArgusSourceStruct *src)
{
   int i;

   if (src) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusCloseSource(%p) starting\n", src);
#endif
      for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
         if (src->srcs[i] != NULL) {
            ArgusCloseSource (src->srcs[i]);
         }
      }

#if defined(ARGUS_THREADS)
      if (src->thread)
         pthread_join(src->thread, NULL);
#endif

      for (i = 0; i < src->ArgusInterfaces; i++) {
         if (src->ArgusInterface[i].ArgusPd) {
            pcap_close(src->ArgusInterface[i].ArgusPd);
            src->ArgusInterface[i].ArgusPd = NULL;
         }
      }

      if (src->ArgusPcapOutFile)
         pcap_dump_close(src->ArgusPcapOutFile);

      if (src->ArgusInputFilter)
         ArgusFree (src->ArgusInputFilter);

      if (src->ArgusDeviceList) {
         ArgusDeleteList(src->ArgusDeviceList, ARGUS_DEVICE_LIST);
      }

      if (src->ArgusRfileList != NULL)
         ArgusDeleteList (src->ArgusRfileList, ARGUS_RFILE_LIST);

      if (src->ArgusModel != NULL)
         ArgusCloseModeler(src->ArgusModel);

      src->status |= ARGUS_SHUTDOWN;

#if defined(ARGUS_THREADS)
      pthread_mutex_lock(&src->lock);
      pthread_cond_signal(&src->cond);
      pthread_mutex_unlock(&src->lock);
#endif
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCloseSource(%p) done\n", src);
#endif
   return (0);
}

void
ArgusDeleteSource(struct ArgusSourceStruct *src)
{
   int i;

   if (src) {
#ifdef ARGUSDEBUG
      ArgusDebug (3, "ArgusDeleteSource(%p) starting\n", src);
#endif
      for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
         if (src->srcs[i] != NULL) {
            if (src->srcs[i]->ArgusModel != NULL)
               ArgusFree (src->srcs[i]->ArgusModel);
            ArgusFree (src->srcs[i]);
            src->srcs[i] = NULL;
         } else
            break;
      }

      ArgusFree (src);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCloseSource(%p) done\n", src);
#endif
}


unsigned int
getArgusID(struct ArgusSourceStruct *src)
{
#ifdef ARGUSDEBUG
   ArgusDebug (7, "getArgusID(%p) done\n", src);
#endif

   return (src->ArgusID.a_un.value);
}

unsigned int
getArgusIDType(struct ArgusSourceStruct *src)
{
#ifdef ARGUSDEBUG
   ArgusDebug (7, "getArgusIDType(%p) done\n", src);
#endif

   return (src->type);
}


void
setArgusID(struct ArgusSourceStruct *src, void *ptr, unsigned int type)
{
   src->ArgusID.a_un.value = 0;
   switch (type) {
      case ARGUS_TYPE_STRING: bcopy((char *)ptr, &src->ArgusID.a_un.str, strlen((char *)ptr)); break;
      case ARGUS_TYPE_INT:    src->ArgusID.a_un.value = atoi((char *)ptr); break;
      case ARGUS_TYPE_IPV4:   src->ArgusID.a_un.ipv4 = ntohl(*(unsigned int *)ptr); break;
   }
   src->type = type;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "setArgusID(%p, %p, 0x%x) done", src, ptr, type);
#endif
}

void
setArgusPcapBufSize (struct ArgusSourceStruct *src, int size)
{
   if (src != NULL) {
      src->ArgusPcapBufSize = size;
   }
#ifdef ARGUSDEBUG
   ArgusDebug (3, "setArgusPcapBufSize(%p, %d)\n", src, size);
#endif
}

unsigned char
getArgusInterfaceStatus(struct ArgusSourceStruct *src)
{
   return (src->ArgusInterfaceStatus);
}
 
void
setArgusInterfaceStatus(struct ArgusSourceStruct *src, unsigned char value)
{
   src->ArgusInterfaceStatus = value;
 
#ifdef ARGUSDEBUG
   ArgusDebug (1, "setArgusInterfaceStatus(%p, %d)\n", src, value);
#endif
}

 
int
getArgusSnapLen(struct ArgusSourceStruct *src)
{
   return (src->ArgusSnapLen);
}
 
void
setArgusSnapLen(struct ArgusSourceStruct *src, int value)
{
   src->ArgusSnapLen = value;
}

int
getArgusfflag(struct ArgusSourceStruct *src)
{
   return (src->Argusfflag);
}

int
getArgusbpflag(struct ArgusSourceStruct *src)
{
   return (src->Argusbpflag);
}

int
getArguspflag(struct ArgusSourceStruct *src)
{
   return (src->Arguspflag);
}

int
getArgusOflag(struct ArgusSourceStruct *src)
{
   return (src->ArgusOflag);
}

void
setArgusfflag(struct ArgusSourceStruct *src, int value)
{
   src->Argusfflag = value;
}

void
setArgusbpflag(struct ArgusSourceStruct *src, int value)
{
   src->Argusbpflag = value;
}

void
setArguspflag(struct ArgusSourceStruct *src, int value)
{
   src->Arguspflag = value;
}

void
setArgusOflag(struct ArgusSourceStruct *src, int value)
{
   src->ArgusOflag = value;
}

void
setArgusCaptureFlag(struct ArgusSourceStruct *src, int value)
{
   src->ArgusCaptureFlag = value;
}

char *
getArgusDevice (struct ArgusSourceStruct *src)
{
   struct ArgusDeviceStruct *device = NULL;
   char *retn = NULL;

   if (src->ArgusDeviceList != NULL) {
      if ((device = (struct ArgusDeviceStruct *) ArgusPopFrontList(src->ArgusDeviceList, ARGUS_LOCK)) != NULL)
         ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);
   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "getArgusDevice(%p) src->ArgusDeviceList is NULL\n", src);
#endif
   }

   if (device != NULL)
      retn = device->name;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "getArgusDevice(%p) returning %s\n", src, retn);
#endif
   return (retn);
}

/*
 * The syntax for specifying this either on the command line or in this file:
 *    -i ind:all
 *    -i dup:en0,en1
 *    -i bond:en0,en1
 *    -i dup:[bond:en0,en1],en2
 *    -i en0 -i en1  (equivalent '-i ind:en0,en1')
 *    -i en0 en1     (equivalent '-i bond:en0,en1')
 * 
*/

int ArgusCheckPcapDevices(pcap_if_t *, char *);

int
ArgusCheckPcapDevices(pcap_if_t *alldevs, char *tok)
{
   int retn = 0;
   pcap_if_t *d;

   if (!(strncmp("all", tok, 3))) {
      if (alldevs != NULL)
         retn = 1;
   } else {
      for (d = alldevs; d != NULL; d = d->next) {
         if (!strcmp(tok, d->name)) {
            retn = 1;
            break;
         }
      }
   }
   return(retn);
}


// The syntax for specifying this either on the command line or in this file:
//    -i ind:all
//    -i dup:en0,en1/srcid
//    -i bond:en0,en1/srcid
//    -i dup:[bond:en0,en1],en2/srcid
//    -i en0/srcid -i en1/srcid  (equivalent '-i ind:en0/srcid,en1/srcid')
//    -i en0 en1     (equivalent '-i bond:en0,en1')

void
setArgusDevice (struct ArgusSourceStruct *src, char *cmd, int type, int mode)
{
   if (src->ArgusDeviceList == NULL)
      src->ArgusDeviceList = ArgusNewList();

   if (cmd) {
      struct ArgusDeviceStruct *device = NULL;
      char errbuf[PCAP_ERRBUF_SIZE];
      char *params = strdup(cmd);
      pcap_if_t *alldevs = NULL, *d;
      char *ptr = NULL;
#if defined(CYGWIN)
      int i = 0, num, ref = 0;
#else
      struct ArgusDeviceStruct *dev = NULL;
      int cnt = 0, status;
      char *tok;
#endif

//    if (type == ARGUS_LIVE_DEVICE)
//       if (pcap_findalldevs(&alldevs, errbuf) == -1)
//          ArgusLog (LOG_ERR, "setArgusDevice: pcap_findalldevs %s\n", errbuf);

#if !defined(CYGWIN)
// we need to parse this bad thing and construct the devices struct

      if (!(strncmp("ind:", params, 4))) {
         ptr = &params[4];
         status = ARGUS_TYPE_IND;
      } else
      if (!(strncmp("dup:", params, 4))) {
         ptr = &params[4];
         status = ARGUS_TYPE_DUPLEX;
      } else
      if (!(strncmp("bond:", params, 5))) {
         ptr = &params[5];
         status = ARGUS_TYPE_BOND;
      } else {
         ptr = params;
         status = ARGUS_TYPE_IND;
      }

      while ((tok = strtok(ptr, " ,")) != NULL) {
         char *srcid = NULL, *dlt = NULL, *sptr = NULL;
         cnt++;

         switch (type) {
            case ARGUS_LIVE_DEVICE: {
               if ((sptr = strchr (tok, '/')) != NULL) {
                  *sptr++ = '\0';
                  srcid = sptr;
               }

               if ((sptr = strchr (tok, '(')) != NULL) {
                  *sptr++ = '\0';
                  dlt = sptr;
                  if ((sptr = strchr (dlt, ')')) != NULL)
                     *sptr = '\0';
               }

               if (!(strncmp("any", tok, 3))) {
                  setArgusDevice (src, pcap_lookupdev (errbuf), ARGUS_LIVE_DEVICE, 0);
                  break;
               } else
               if (!(strncmp("all", tok, 3))) {
                  if (alldevs != NULL) {
                     for (d = alldevs; d != NULL; d = d->next) {
                        if (!(d->flags & PCAP_IF_LOOPBACK)) {
                           if ((dev = (struct ArgusDeviceStruct *) ArgusCalloc(1, sizeof(*device))) == NULL)
                              ArgusLog (LOG_ERR, "setArgusDevice ArgusCalloc %s\n", strerror(errno));

                           dev->name = strdup(d->name);
                           dev->status = status;
                           dev->type = type;
                           if (dlt != NULL) {
#if defined(HAVE_PCAP_DATALINK_NAME_TO_VAL)
                              dev->dlt = pcap_datalink_name_to_val(dlt);
#else
                              dev->dlt = 0;
#endif
                              dev->dltname = strdup(dlt);
                           }

                           switch (status) {
                              case ARGUS_TYPE_IND:
                                 ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) dev, ARGUS_LOCK);
                                 break;

                              case ARGUS_TYPE_BOND:
                              case ARGUS_TYPE_DUPLEX:
                                 if (device == NULL) {
                                    if ((device = (struct ArgusDeviceStruct *) ArgusCalloc(1, sizeof(*device))) == NULL)
                                       ArgusLog (LOG_ERR, "setArgusDevice ArgusCalloc %s\n", strerror(errno));
                                    device->name = strdup(cmd);
                                    device->status = status;
                                    device->type = type;
                                    device->list = ArgusNewList();
                                 }
                                 ArgusPushFrontList(device->list, (struct ArgusListRecord *) dev, ARGUS_LOCK);
                                 break;
                           }
                        }
                     }
                  }

                  break;
               }

               // Deliberate fall through to process specific interface name
            }

            case ARGUS_FILE_DEVICE: {
               if ((dev = (struct ArgusDeviceStruct *) ArgusCalloc(1, sizeof(*device))) == NULL)
                        ArgusLog (LOG_ERR, "setArgusDevice ArgusCalloc %s\n", strerror(errno));

               dev->name = strdup(tok);
               dev->status = status;
               dev->type = type;
               dev->mode = mode;
               if (dlt != NULL) {
#if defined(HAVE_PCAP_DATALINK_NAME_TO_VAL)
                  dev->dlt = pcap_datalink_name_to_val(dlt);
#else
                  dev->dlt = 0;
#endif
                  dev->dltname = strdup(dlt);
               }

               switch (status) {
                  case ARGUS_TYPE_IND:
                     ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) dev, ARGUS_LOCK);
                     break;

                  case ARGUS_TYPE_BOND:
                  case ARGUS_TYPE_DUPLEX:
                     if (device == NULL) {
                        if ((device = (struct ArgusDeviceStruct *) ArgusCalloc(1, sizeof(*device))) == NULL)
                           ArgusLog (LOG_ERR, "setArgusDevice ArgusCalloc %s\n", strerror(errno));
                        device->name = strdup(cmd);
                        device->status = status;
                        device->type = type;
                        device->list = ArgusNewList();
                     }
                     ArgusPushFrontList(device->list, (struct ArgusListRecord *) dev, ARGUS_LOCK);
                     break;
               }
               break;
            }
         }

         if (dev != NULL) {
            if (srcid != NULL) {
               struct ArgusAddrStruct ArgusID = ArgusSourceTask->ArgusID;
               int type = ArgusSourceTask->type;

               ArgusParseSourceID (ArgusSourceTask, srcid);
               dev->ArgusID = ArgusSourceTask->ArgusID;
               dev->idtype  = ArgusSourceTask->type;

               ArgusSourceTask->type = type;
               ArgusSourceTask->ArgusID = ArgusID;

            } else {
               dev->ArgusID = ArgusSourceTask->ArgusID;
               dev->idtype  = ArgusSourceTask->type;
            }
         }

         ptr = NULL;
      }

      if (device != NULL)
         ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);
      
#else
// on cygwin, you get integers not interface names 

      if (device == NULL) {
         if ((device = (struct ArgusDeviceStruct *) ArgusCalloc(1, sizeof(*device))) == NULL)
            ArgusLog (LOG_ERR, "setArgusDevice ArgusCalloc %s\n", strerror(errno));
         device->type = type;
      }

      device->status = ARGUS_TYPE_IND;
      num = (int)strtol(cmd, (char **)&ptr, 10);
      if (ptr != cmd) 
         ref = 1;
      if (!(strncmp(cmd, "any", 3))) {
         ref = 1;
         num = 1;
      }

      for (d = alldevs; d != NULL; d = d->next) {
         i++;
         if (ref) {
            if (i == num) {
               device->name = strdup(d->name);
               break;
            }
         } else {
            if (!strcmp(cmd, d->name)) {
               device->name = strdup(d->name);
               break;
            }
         }
      }
      if (i == 0) 
         ArgusLog (LOG_ERR, "setArgusDevice: no interfaces\n");

      ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);
#endif
      free(params);
      if (alldevs != NULL)
         pcap_freealldevs(alldevs);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "setArgusDevice(%s) returning\n", cmd);
#endif
}

void
clearArgusDevice (struct ArgusSourceStruct *src)
{
   struct ArgusListStruct *list;
   struct ArgusListRecord *retn;

   if ((list = src->ArgusDeviceList) != NULL) {
      while ((retn = ArgusPopFrontList(list, ARGUS_LOCK)) != NULL) {
         struct ArgusDeviceStruct *device = (struct ArgusDeviceStruct *) retn;
         if (device->list && device->list->count) {
            struct ArgusListRecord *lrec;
            while ((lrec = ArgusPopFrontList(device->list, ARGUS_LOCK)) != NULL) {
               struct ArgusDeviceStruct *tdev = (struct ArgusDeviceStruct *) lrec;
               if (tdev->name != NULL)
                  free(tdev->name);
               ArgusFree(lrec);
            }
         }
         if (device->name != NULL)
            free(device->name);
         ArgusFree(retn);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "clearArgusDevice(%p) returning\n", src);
#endif
}


char *
getArgusrfile (struct ArgusSourceStruct *src)
{
   struct ArgusRfileStruct *rfile = NULL;
   char *retn = NULL;

   if (src->ArgusRfileList != NULL) {
      rfile = (struct ArgusRfileStruct *) src->ArgusRfileList->start;
      retn = rfile->name;
   }
   return (retn);
}


void ArgusSortFileList (struct ArgusListStruct *);

void
setArgusrfile (struct ArgusSourceStruct *src, char *value)
{
   if (src->ArgusRfileList == NULL)
      src->ArgusRfileList = ArgusNewList();

   if (value) {
      struct ArgusRfileStruct *rfile;
      struct stat statbuf;
      char *tok, *ptr = value;

      while ((tok = strtok (ptr, " \t")) != NULL) {
         char *tptr;
         int mode = 0;
         if (strcmp("-", tok)) {
            if ((tptr = strstr (tok, "cisco:")) != NULL) {
               mode = ARGUS_CISCO_DATA_SOURCE;
               tok = tptr + 6;
            } else
            if ((tptr = strstr (tok, "sflow:")) != NULL) {
               mode = ARGUS_SFLOW_DATA_SOURCE;
               tok = tptr + 6;
            }
            if (stat(tok, &statbuf) < 0)
               ArgusLog (LOG_ERR, "input file '%s': %s", tok, strerror(errno));
         }

         if ((rfile = (struct ArgusRfileStruct *) ArgusCalloc(1, sizeof(*rfile))) == NULL)
            ArgusLog (LOG_ERR, "setArgusrfile ArgusCalloc %s\n", strerror(errno));

         rfile->name = strdup(tok);
         rfile->mode = mode;
         ArgusPushBackList(src->ArgusRfileList, (struct ArgusListRecord *) rfile, ARGUS_LOCK);

//       setArgusDevice(src, tok, ARGUS_FILE_DEVICE, rfile->mode);
         ptr = NULL;
      }

      ArgusSortFileList (src->ArgusRfileList);
   }
}

int
getArgusMoatTshFile (struct ArgusSourceStruct *src)
{
   return(src->Argustflag);
}

void
setArgusMoatTshFile (struct ArgusSourceStruct *src, int value)
{
   src->Argustflag = value;
}

float
getArgusRealTime (struct ArgusSourceStruct *src)
{
   return(src->Tflag);
}


void
setArgusRealTime (struct ArgusSourceStruct *src, float value)
{
   src->Tflag = value;
}


void
setArgusWriteOutPacketFile (struct ArgusSourceStruct *src, char *file)
{
   src->ArgusWriteOutPacketFile = strdup(file);
}


#define ARGUSMOATLEN      44
#define ARGUSMOATTSHTCPLEN   40

int ArgusMoatTshRead (struct ArgusSourceStruct *);

int
ArgusMoatTshRead (struct ArgusSourceStruct *src)
{
   struct ArgusMoatTshPktHdr MoatTshBuffer[2], *ArgusMoatPktHdr = &MoatTshBuffer[0];
   int retn = 0, length = 0;
   struct ip *iphdr = NULL;

   bzero (ArgusMoatPktHdr, sizeof(MoatTshBuffer));
 
   if ((retn = read(pcap_fileno(src->ArgusInterface[0].ArgusPd), ArgusMoatPktHdr, ARGUSMOATLEN)) == ARGUSMOATLEN) {
      ArgusMoatPktHdr->interface = 0;
#if defined(_LITTLE_ENDIAN)
      src->ArgusModel->ArgusGlobalTime.tv_sec  = ntohl(ArgusMoatPktHdr->sec);
      src->ArgusModel->ArgusGlobalTime.tv_usec = ntohl(*((int *)&ArgusMoatPktHdr->interface));
#else
      src->ArgusModel->ArgusGlobalTime.tv_sec  = ArgusMoatPktHdr->sec;
#endif

#if defined(ARGUS_NANOSECONDS)
      src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
      ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;

      iphdr = &ArgusMoatPktHdr->ip;

#if defined(_LITTLE_ENDIAN)
      length = ntohs(iphdr->ip_len);
#else
      length = iphdr->ip_len;
#endif
      src->ArgusThisLength  = length;

      switch (iphdr->ip_p) {
         case IPPROTO_ICMP:
         case IPPROTO_TCP:
         default:
            src->ArgusSnapLength  = ARGUSMOATTSHTCPLEN;
            break;
      }

      src->ArgusThisSnapEnd = (((unsigned char *)iphdr) + src->ArgusSnapLength);

      if ((src->ArgusInputFilter == NULL) ||
           (bpf_filter(src->ArgusInterface[0].ArgusFilter.bf_insns, (u_char *)iphdr, src->ArgusSnapLength, src->ArgusSnapLen))) {

         ArgusProcessIpPacket (src->ArgusModel, iphdr, length, &src->ArgusModel->ArgusGlobalTime);
      }

   } else
      close(pcap_fileno(src->ArgusInterface[0].ArgusPd));

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusMoatTshRead() returning %d\n", retn);
#endif

   return (retn);
}


int
ArgusSnoopRead (struct ArgusSourceStruct *src)
{
   int retn = 0, len = 0;
   struct pcap_pkthdr pcap_pkthdr;
   struct ArgusSnoopPktHdr SnoopPktHdr;
   unsigned char ArgusPacketBuf[1540];

   if ((retn = read(pcap_fileno(src->ArgusInterface[0].ArgusPd), &SnoopPktHdr, sizeof(SnoopPktHdr))) == sizeof(SnoopPktHdr)) {
#if defined(_LITTLE_ENDIAN)
      SnoopPktHdr.len            = ntohl(SnoopPktHdr.len);
      SnoopPktHdr.tlen           = ntohl(SnoopPktHdr.tlen);
      SnoopPktHdr.argtvp.tv_sec  = ntohl(SnoopPktHdr.argtvp.tv_sec);
      SnoopPktHdr.argtvp.tv_usec = ntohl(SnoopPktHdr.argtvp.tv_usec);
#endif
      if ((len = ((SnoopPktHdr.tlen + 3) & 0xFFFFFFC)) < 1500) {
         if ((retn = read(pcap_fileno(src->ArgusInterface[0].ArgusPd), ArgusPacketBuf, len)) == len) {
            pcap_pkthdr.ts.tv_sec  = SnoopPktHdr.argtvp.tv_sec;
            pcap_pkthdr.ts.tv_usec = SnoopPktHdr.argtvp.tv_usec;
            pcap_pkthdr.caplen = SnoopPktHdr.tlen;
            pcap_pkthdr.len    = SnoopPktHdr.len;

            if ((src->ArgusInputFilter == NULL) ||
               (bpf_filter(src->ArgusInterface[0].ArgusFilter.bf_insns, ArgusPacketBuf, SnoopPktHdr.tlen, src->ArgusSnapLen))) {
 
               src->ArgusInterface[0].ArgusCallBack (NULL, &pcap_pkthdr, ArgusPacketBuf);
            }
         }
      }

   } else
      close(pcap_fileno(src->ArgusInterface[0].ArgusPd));

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusSnoopRead() returning %d\n", retn);
#endif

   return (retn);
}


#include <argus_dag.h>

#define ERF_REC_LEN_MAX         (1<<16)

int ArgusErfRead (struct ArgusSourceStruct *);

int
ArgusErfRead (struct ArgusSourceStruct *src)
{
   int retn = 0, len = 0;
   unsigned char *ArgusPacketBuf = NULL;
   dag_record_t DagPktHdr;

#define DAG_REC_SIZE      16

   if (src->ArgusInterface[0].ArgusPacketBuffer == NULL) 
      src->ArgusInterface[0].ArgusPacketBuffer = src->ArgusInterface[0].ArgusPacketBufferBuffer; 

   if ((ArgusPacketBuf = src->ArgusInterface[0].ArgusPacketBuffer) != NULL) {
      if ((retn = read(src->ArgusInterface[0].ArgusPcap.fd, &DagPktHdr, DAG_REC_SIZE)) == DAG_REC_SIZE) {

         len = ntohs(DagPktHdr.rlen) - DAG_REC_SIZE;

         if ((retn = read(src->ArgusInterface[0].ArgusPcap.fd, ArgusPacketBuf, len)) == len) {
            ArgusDagPacket ((void *)src, (void *)&DagPktHdr, (const u_char *)ArgusPacketBuf);
         } else {
            if (retn == 0) 
               close(src->ArgusInterface[0].ArgusPcap.fd);
            else
               ArgusLog(LOG_ERR, "ArgusErfRead: read error %s", strerror(errno));
         }
      } else
         if (retn == 0) 
            close(src->ArgusInterface[0].ArgusPcap.fd);
         else
            ArgusLog(LOG_ERR, "ArgusErfRead: read error %s", strerror(errno));

   } else
      close(src->ArgusInterface[0].ArgusPcap.fd);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusErfRead() returning %d\n", retn);
#endif

   return (retn);
}


pcap_handler
Arguslookup_dag_callback (int type)
{
   pcap_handler retn = NULL;
   struct callback *callback;
#ifdef ARGUSDEBUG
   char *name = NULL;
#endif
 
   for (callback = ArgusSourceCallbacks; callback->function; ++callback)
      if (type == callback->type) {
         retn = callback->function;
#ifdef ARGUSDEBUG
         name = callback->fname;
#endif
         break;
      }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "Arguslookup_dag_callback(%d) returning %s: %p\n", type, name, retn);
#endif

   return (retn);
}

pcap_handler
Arguslookup_pcap_callback (int type)
{
   pcap_handler retn = NULL;
   struct callback *callback;
 
   for (callback = ArgusSourceCallbacks; callback->function; ++callback)
      if (type == callback->type) {
         retn = callback->function;
         break;
      }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "Arguslookup_pcap_callback(%d) returning %p\n", type, retn);
#endif

   return (retn);
}


void
ArgusParseSourceID (struct ArgusSourceStruct *src, char *optarg)
{

   if (optarg && (*optarg == '"')) {
      int slen;
      optarg++;
      if (optarg[strlen(optarg) - 1] == '\n')
         optarg[strlen(optarg) - 1] = '\0';
      if (optarg[strlen(optarg) - 1] == '\"')
         optarg[strlen(optarg) - 1] = '\0';
      slen = strlen(optarg);
      if (slen > 4) optarg[4] = '\0';
      setArgusID (src, optarg, ARGUS_TYPE_STRING);
      
   } else
   if (optarg && isalnum((int)*optarg)) {
      char *ptr;
      long num;

      if ((num = strtol(optarg, (char **)&ptr, 10)) == 0)
         if (errno == EINVAL)
            ArgusLog(LOG_ERR, "ArgusParseSourceID error: %s format incorrect", optarg);

      if (ptr == &optarg[strlen(optarg)]) {
         setArgusID (src, optarg, ARGUS_TYPE_INT);

      } else {
         int retn, done = 0;

#if defined(HAVE_INET_ATON)
         struct in_addr pin;
 
         if (inet_aton(optarg, &pin)) {
            setArgusID (src, &pin.s_addr, ARGUS_TYPE_IPV4);
            done++;
         }
#endif

         if (!done) {
#if defined(HAVE_GETADDRINFO)
            struct addrinfo *host, hints;

            bzero(&hints, sizeof(hints));
            hints.ai_family   = AF_INET;

            if ((retn = getaddrinfo(optarg, NULL, NULL, &host)) == 0) {
               struct addrinfo *hptr = host;
               do {
                  switch (host->ai_family) {
                     case AF_INET:  {
                        struct sockaddr_in *sa = (struct sockaddr_in *) host->ai_addr;
                        unsigned int value;
                        bcopy ((char *)&sa->sin_addr, (char *)&value, 4);

                        setArgusID (src, &value, ARGUS_TYPE_IPV4);
                        done++;
                        break;
                     }
                  }
                  host = host->ai_next;
               } while (host != NULL);

               freeaddrinfo(hptr);

            } else {
               switch (retn) {
                  case EAI_AGAIN:
                     ArgusLog(LOG_ERR, "dns server not available");
                     break;
                  case EAI_NONAME: {
                     ArgusLog(LOG_ERR, "srcid %s unknown", optarg);
                     break;
                  }
#if defined(EAI_ADDRFAMILY)
                  case EAI_ADDRFAMILY:
                     ArgusLog(LOG_ERR, "srcid %s has no IP address", optarg);
                     break;
#endif
                  case EAI_SYSTEM:
                     ArgusLog(LOG_ERR, "srcid %s name server error %s", optarg, strerror(errno));
                     break;
               }
            }

#else  // HAVE_GETADDRINFO
            struct hostent *host;

            if ((host = gethostbyname(optarg)) != NULL) {
               if ((host->h_addrtype == 2) && (host->h_length == 4)) {
                  unsigned int value;
                  bcopy ((char *) *host->h_addr_list, (char *)&value, host->h_length);
                  setArgusID (src, &value,  ARGUS_TYPE_IPV4);

               } else
                  ArgusLog (LOG_ERR, "Probe ID %s error %s\n", optarg, strerror(errno));

            } else {
               if (optarg && isdigit((int)*optarg)) {
                  setArgusID (src, optarg, ARGUS_TYPE_INT);
               } else
                  ArgusLog (LOG_ERR, "Probe ID value %s is not appropriate (%s)\n", optarg, strerror(errno));
            }
#endif
         }
      }

   } else
      ArgusLog (LOG_ERR, "Probe ID value %s is not appropriate\n", optarg);
}


#if !defined(ARGUS_TILERA)
int ArgusProcessLcpPacket (struct ArgusSourceStruct *, struct lcp_hdr *, int, struct timeval *);
int ArgusProcessPacket (struct ArgusSourceStruct *, char *, int, struct timeval *, int);


void
ArgusEtherPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   unsigned int caplen = h->caplen;
   unsigned int length = h->len;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;

#if defined(ARGUS_NANOSECONDS)
      tvp->tv_usec *= 1000;
#endif

   if (p != NULL) {
      unsigned int ind = src->ArgusThisIndex;

#define ARGUS_TIME_THRESHOLD   30

      if ((src->marktime.tv_sec) && !(src->ArgusReadingOffLine)) {
         if ((tvp->tv_sec < (src->marktime.tv_sec - ARGUS_TIME_THRESHOLD)) ||
             (tvp->tv_sec > (src->marktime.tv_sec + (10 * ARGUS_TIME_THRESHOLD)))) {

//          ArgusLog (LOG_WARNING, "ArgusInterface timestamps wayyy out of order: now %d then %d\n", tvp->tv_sec, src->lasttime.tv_sec);

            if (src->ArgusDumpPacketOnError && (src->ArgusWriteOutPacketFile != NULL)) {
               if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
                  if (src->ArgusPcapOutFile != NULL) {
                     pcap_dump_close(src->ArgusPcapOutFile);
                     src->ArgusPcapOutFile = NULL;
                  }
  
                  if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
                     ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
               }

#if defined(HAVE_PCAP_DUMP_FTELL)
               src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
               pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);

#if defined(HAVE_PCAP_DUMP_FLUSH)
               pcap_dump_flush(src->ArgusPcapOutFile);
#endif
            }
            return;
         }
      }

      if (src->ArgusReadingOffLine)
         src->ArgusInputOffset = ftell(src->ArgusPacketInput);

      ArgusModel->ArgusGlobalTime = *tvp;
      src->ArgusModel->ArgusGlobalTime  = *tvp;
      src->lasttime = *tvp;

      if (src->ArgusDumpPacket && (src->ArgusWriteOutPacketFile != NULL)) {
         if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
            if (src->ArgusPcapOutFile != NULL) {
               pcap_dump_close(src->ArgusPcapOutFile);
               src->ArgusPcapOutFile = NULL;
            }
   
            if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
               ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
         }

#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }

      if (p && (length >= sizeof(struct ether_header))) {
         struct ether_header *ep;
 
         src->ArgusInterface[ind].ArgusTotalPkts++;
         src->ArgusInterface[ind].ArgusTotalBytes += length;
         src->ArgusInterface[ind].ArgusPacketBuffer = (u_char *) p;
         ep = (struct ether_header *) p;

         src->ArgusModel->ArgusThisLength  = length;
         src->ArgusModel->ArgusSnapLength  = caplen;
         src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
         src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_ETHER;

         if (ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR))
            if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
               pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusEtherPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

#define TYPE_LEGACY       0
#define TYPE_HDLC_POS     1
#define TYPE_ETH          2
#define TYPE_ATM          3
#define TYPE_AAL5         4

#if !defined(ntohll)
#if defined(_LITTLE_ENDIAN)
#if defined(__FreeBSD__) || defined(__OpenBSD__) || defined(__NetBSD__) || defined(__APPLE__) || defined(__sun__)
#include <argus/extract.h>
#define ntohll(x) EXTRACT_64BITS(&x)
#define htonll(x) EXTRACT_64BITS(&x)
#else
#if defined(HAVE_SOLARIS)
#include <byteswap.h>
#define ntohll(x) bswap_64(x)
#define htonll(x) bswap_64(x)
#endif
#endif
#else
#define ntohll(x) x
#define htonll(x) x
#endif
#endif


void 
ArgusDagPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (void *) user;
   dag_record_t *hdr = (void *) h;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int length, caplen;
   unsigned long long ts;
   struct stat statbuf;
   int ind = src->ArgusThisIndex;

   length = ntohs(hdr->wlen);
   caplen = ntohs(hdr->rlen) - DAG_REC_SIZE;

   src->ArgusInterface[ind].ArgusTotalPkts++;
   src->ArgusInterface[ind].ArgusTotalBytes += length;

   ts = hdr->ts;

   tvp->tv_sec  = (ts >> 32);

#if defined(ARGUS_NANOSECONDS)
   ts = (ts & 0xfffffffcULL) * 1000000000; 
   tvp->tv_usec = (int)(ts >> 32);
#else
   ts = (ts & 0xffffffffULL) * 1000000;
   ts += 0x80000000; /* rounding */
   tvp->tv_usec = (int)(ts >> 32);
   if (tvp->tv_usec >= 1000000) {
      tvp->tv_usec -= 1000000;
      tvp->tv_sec++;
   }
#endif

   if ((src->marktime.tv_sec) && !(src->ArgusReadingOffLine)) {
      if ((tvp->tv_sec < (src->marktime.tv_sec - ARGUS_TIME_THRESHOLD)) ||
          (tvp->tv_sec > (src->marktime.tv_sec + ARGUS_TIME_THRESHOLD))) {

//       ArgusLog (LOG_WARNING, "ArgusInterface timestamps wayyy out of order: now %d then %d\n", tvp->tv_sec, src->lasttime.tv_sec);

         if (src->ArgusDumpPacketOnError && (src->ArgusWriteOutPacketFile != NULL)) {
            if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
               if (src->ArgusPcapOutFile != NULL) {
                  pcap_dump_close(src->ArgusPcapOutFile);
                  src->ArgusPcapOutFile = NULL;
               }

               if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
                  ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
            }

#if defined(HAVE_PCAP_DUMP_FTELL)
            src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
            pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);

#if defined(HAVE_PCAP_DUMP_FLUSH)
            pcap_dump_flush(src->ArgusPcapOutFile);
#endif
         }  
         return;
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->lasttime = *tvp;

   if (p && length) {
      switch (hdr->type) {
         case TYPE_LEGACY:
            break;

         case TYPE_HDLC_POS: {
            int retn = 0, offset = 0, linktype = 0;
            unsigned short proto = 0;
            unsigned short value;

#if defined(_LITTLE_ENDIAN)
            value = ntohs(*(unsigned short *)p);
#else
            value = (*(unsigned short *)p);
#endif

            if (value == 0xFF03) {
               linktype = DLT_PPP_SERIAL;
               if ((p[0] == PPP_ADDRESS) && (p[1] == PPP_CONTROL)) {
                  p += 2; length -= 2;
               }
               if (*p & 01) {
                  proto = *p; p++; length -= 1;
               } else {
#if defined(_LITTLE_ENDIAN)
                  proto = ntohs(*(u_short *)p);
#else
                  proto = *(u_short *)p;
#endif
                  p += 2; length -= 2;
               }
 
            } else {
               linktype = DLT_CHDLC;
#if defined(_LITTLE_ENDIAN)
               proto = ntohs(*(u_short *)&p[2]);
#else
               proto = *(u_short *)p;
#endif

#if !defined(CHDLC_HDRLEN)
#define CHDLC_HDRLEN      4
#endif
               offset = CHDLC_HDRLEN;
               p = src->ArgusInterface[ind].ArgusPacketBuffer + offset;
               length -= offset;
            }

            if (src->ArgusInterface[ind].ArgusTotalPkts == 1)
               src->ArgusInterface[ind].ArgusPcap.linktype = linktype;

            src->ArgusModel->ArgusThisLength  = length;
            src->ArgusModel->ArgusSnapLength  = caplen;
            src->ArgusModel->ArgusThisSnapEnd = src->ArgusInterface[ind].ArgusPacketBuffer + caplen;

            switch (proto) {
               case PPP_LCP:
                  retn = ArgusProcessLcpPacket (src, (struct lcp_hdr *)p, length, tvp);
                  break;

               case ETHERTYPE_IP:      /*XXX*/
               case PPP_IP:
                  retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IP);
                  break;

               case PPP_IPV6:
               case ETHERTYPE_IPV6:    /*XXX*/
                  retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IPV6);
                  break;

               case ETHERTYPE_MPLS:
                  retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS);
                  break;

               case ETHERTYPE_MPLS_MULTI:
                  retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS_MULTI);
                  break;

               default:
                  break;
            }

            if (retn)
               if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
                  pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
            break;
         }

         case TYPE_ETH: {
            if (src->ArgusInterface[ind].ArgusTotalPkts == 1)
               src->ArgusInterface[ind].ArgusPcap.linktype = DLT_EN10MB;

            p += 2;

            src->ArgusModel->ArgusThisLength  = length - 2;
            src->ArgusModel->ArgusSnapLength  = caplen - 2;
            src->ArgusModel->ArgusThisSnapEnd = (u_char *)p + (caplen - 2);
            if (ArgusProcessPacket (src, (char *)p, length, tvp, ARGUS_ETHER_HDR))
               if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
                  pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
            break;
         }

         case TYPE_ATM:
         case TYPE_AAL5: {
            if (src->ArgusInterface[ind].ArgusTotalPkts == 1)
               src->ArgusInterface[ind].ArgusPcap.linktype = DLT_ATM_RFC1483;
            break;
         }

         default: {
            if (src->ArgusInterface[ind].ArgusTotalPkts == 1)
               src->ArgusInterface[ind].ArgusPcap.linktype = DLT_NULL;
            break;
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusDagPacket (%p, %p) returning\n", src, hdr);
#endif
}


void
ArgusTokenPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusTokenPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


#include <net/arcnet.h>

void
ArgusArcnetPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct ether_header *ep = (struct ether_header *) src->ArgusInterface[src->ArgusThisIndex].ArgusPacketBufferBuffer;
   struct arc_header *ap = (struct arc_header *) p;
   u_char arc_type = ap->arc_type;
   struct stat statbuf;
   int archdrlen = 0;

   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }
   
   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   if (src->ArgusModel->ArgusGlobalTime.tv_sec < 0) {
      ArgusLog (LOG_ERR, "ArgusArcnetPacket (%p, %p, %p) libpcap timestamp out of range %d.%d\n",
              user, h, p, src->ArgusModel->ArgusGlobalTime.tv_sec, src->ArgusModel->ArgusGlobalTime.tv_usec);
   }

   src->ArgusInterface[src->ArgusThisIndex].ArgusPacketBuffer = src->ArgusInterface[src->ArgusThisIndex].ArgusPacketBufferBuffer; 

   switch (arc_type) {
      case ARCTYPE_IP_OLD:
      case ARCTYPE_ARP_OLD:
      case ARCTYPE_DIAGNOSE:
         archdrlen = ARC_HDRLEN;
         break;

      default:
         if (ap->arc_flag == 0xff) {
            archdrlen = ARC_HDRNEWLEN_EXC;
         } else {
            archdrlen = ARC_HDRNEWLEN;
         }
         break;
   }

   length -= archdrlen;
   caplen -= archdrlen;
   p += archdrlen;
   
   bcopy (p, (char *)ep, caplen);

   src->ArgusModel->ArgusThisLength  = length;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_ARCNET;

   if (ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR)) 
      if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusArcnetPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusAtmClipPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusAtmClipPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusLoopPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusLoopPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusHdlcPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   int ind = src->ArgusThisIndex;
   struct stat statbuf;

   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int caplen = h->caplen;
   unsigned int length = h->len;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif


   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   src->ArgusInterface[ind].ArgusTotalPkts++;
   src->ArgusInterface[ind].ArgusTotalBytes += length;
   src->ArgusInterface[ind].ArgusPacketBuffer = (u_char *) p;

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime = *tvp;

   if (p && length) {
      int retn = 0, offset = 0;
      unsigned short proto = 0;
      unsigned short value;

#define CHDLC_UNICAST           0x0f
#define CHDLC_BCAST             0x8f
#define CHDLC_TYPE_SLARP        0x8035
#define CHDLC_TYPE_CDP          0x2000

#if defined(_LITTLE_ENDIAN)
      value = ntohs(*(unsigned short *)p);
#else
      value = (*(unsigned short *)p);
#endif
      switch (value) {
         case CHDLC_UNICAST:
         case CHDLC_BCAST:
         case CHDLC_TYPE_SLARP:
         case CHDLC_TYPE_CDP:
         default:
            src->ArgusModel->ArgusThisEncaps = ARGUS_ENCAPS_CHDLC;
            break;
      }

#if defined(_LITTLE_ENDIAN)
      proto = ntohs(*(u_short *)&p[2]);
#else
      proto = *(u_short *)&p[2];
#endif

#if !defined(CHDLC_HDRLEN)
#define CHDLC_HDRLEN      4
#endif
      offset = CHDLC_HDRLEN;
      p = (unsigned char *) (src->ArgusInterface[ind].ArgusPacketBuffer + offset);
      length -= offset;

      src->ArgusModel->ArgusThisLength  = length;
      src->ArgusModel->ArgusSnapLength  = caplen;
      src->ArgusModel->ArgusThisSnapEnd = (src->ArgusInterface[ind].ArgusPacketBuffer + caplen);

      switch (proto) {
         case ETHERTYPE_IP:
            retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IP);
            break;

         case ETHERTYPE_IPV6:
            retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IPV6);
            break;

         case ETHERTYPE_MPLS:
            retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS);
            break;

         case ETHERTYPE_MPLS_MULTI:
            retn = ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS_MULTI);
            break;
      }

      if (retn)
         if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
            pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusHdlcPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusPppHdlcPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   int ind = src->ArgusThisIndex;
   struct stat statbuf;

   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int caplen = h->caplen;
   unsigned int length = h->len;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   src->ArgusInterface[ind].ArgusTotalPkts++;
   src->ArgusInterface[ind].ArgusTotalBytes += length;
   src->ArgusInterface[ind].ArgusPacketBuffer = (u_char *) p;

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_HDLC;

   if (p && length) {
      unsigned short proto = 0;
      unsigned short value;
      int offset = 0;

#if defined(_LITTLE_ENDIAN)
      value = ntohs(*(unsigned short *)p);
#else
      value = (*(unsigned short *)p);
#endif
      if (value == 0xFF03) {
         src->ArgusModel->ArgusThisEncaps  |= ARGUS_ENCAPS_PPP;
         if ((p[0] == PPP_ADDRESS) && (p[1] == PPP_CONTROL)) {
            p += 2; length -= 2;
         }
         if (*p & 01) {
            proto = *p; p++; length -= 1;
         } else {
#if defined(_LITTLE_ENDIAN)
            proto = ntohs(*(u_short *)p);
#else
            proto = *(u_short *)p;
#endif
            p += 2; length -= 2;
         }
      } else {
#if defined(_LITTLE_ENDIAN)
         proto = ntohs(*(u_short *)&p[2]);
#else
         proto = *(u_short *)p;
#endif

#if !defined(CHDLC_HDRLEN)
#define CHDLC_HDRLEN      4
#endif
         src->ArgusModel->ArgusThisEncaps = ARGUS_ENCAPS_CHDLC;
         offset = CHDLC_HDRLEN;
         p = (unsigned char *) (src->ArgusInterface[ind].ArgusPacketBuffer + offset);
         length -= offset;
      }

      src->ArgusModel->ArgusThisLength  = length;
      src->ArgusModel->ArgusSnapLength  = caplen;
      src->ArgusModel->ArgusThisSnapEnd = (src->ArgusInterface[ind].ArgusPacketBuffer + caplen);

      switch (proto) {
         case PPP_LCP:
            ArgusProcessLcpPacket (src, (struct lcp_hdr *)p, length, tvp);
            break;

         case ETHERTYPE_IP:      /*XXX*/
         case PPP_IP:
            ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IP);
            break;

         case PPP_IPV6:
         case ETHERTYPE_IPV6:    /*XXX*/
            ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IPV6);
            break;

         case PPP_MPLS_UCAST:
         case ETHERTYPE_MPLS:
            ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS);
            break;

         case PPP_MPLS_MCAST:
         case ETHERTYPE_MPLS_MULTI:
            ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_MPLS_MULTI);
            break;

         case PPP_OSI:
         case PPP_NS:
         case PPP_DECNET:
         case PPP_APPLE:
         case PPP_IPX:
         case PPP_VJC:
         case PPP_VJNC:
         case PPP_BRPDU:
         case PPP_STII:
         case PPP_VINES:
         case PPP_COMP:
         case PPP_HELLO:
         case PPP_LUXCOM:
         case PPP_SNS:
         case PPP_IPCP:
         case PPP_OSICP:
         case PPP_NSCP:
         case PPP_DECNETCP:
         case PPP_APPLECP:
         case PPP_IPXCP:
         case PPP_STIICP:
         case PPP_VINESCP:
         case PPP_IPV6CP:
         case PPP_CCP:
         case PPP_PAP:
         case PPP_LQM:
         case PPP_CHAP:
         case PPP_BACP:
         case PPP_BAP:
         case PPP_MP:

         default:
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusPppHdlcPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusPppEtherPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusPppEtherPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}



void
Argus802_11Packet (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;

   src->ArgusModel->ArgusThisLength  = length;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)p) + caplen;

   src->ArgusModel->ArgusThisEncaps = ARGUS_ENCAPS_802_11;

   if (ArgusProcessPacket (src, (char *)p, length, tvp, ARGUS_802_11_HDR)) 
      if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "Argus802_11Packet (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusLtalkPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusLtalkPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusJuniperPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct juniper_l2info_t l2info;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif
   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL))
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;

   if (juniper_parse_header(p, h, &l2info) != 0) {
      src->ArgusModel->ArgusThisLength  = length - l2info.header_len;
      src->ArgusModel->ArgusSnapLength  = caplen;
      src->ArgusModel->ArgusThisSnapEnd = ((u_char *)p) + caplen;

      src->ArgusModel->ArgusThisEncaps = ARGUS_ENCAPS_JUNIPER;

      p += l2info.header_len;

      if (ArgusProcessPacket (src, (char *)p, length, tvp, ARGUS_ETHER_HDR))
         if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
            pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusJuniperPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

void
ArgusIpNetPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusIpNetPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

int
ip_heuristic_guess(register const u_char *p, u_int length)
{
    switch(p[0]) {
    case 0x45:
    case 0x46:
    case 0x47:
    case 0x48:
    case 0x49:
    case 0x4a:
    case 0x4b:
    case 0x4c:
    case 0x4d:
    case 0x4e:
    case 0x4f:
//   ip_print(gndo, p, length);
	    break;
#ifdef INET6
    case 0x60:
    case 0x61:
    case 0x62:
    case 0x63:
    case 0x64:
    case 0x65:
    case 0x66:
    case 0x67:
    case 0x68:
    case 0x69:
    case 0x6a:
    case 0x6b:
    case 0x6c:
    case 0x6d:
    case 0x6e:
    case 0x6f:
//      ip6_print(p, length);
        break;
#endif
    default:
        return 0; /* did not find a ip header */
        break;
    }
    return 1; /* we printed an v4/v6 packet */
}

int
juniper_read_tlv_value(const u_char *p, u_int tlv_type, u_int tlv_len)
{
   int tlv_value;

   /* TLVs < 128 are little endian encoded */
   if (tlv_type < 128) {
       switch (tlv_len) {
       case 1:
           tlv_value = *p;
           break;
       case 2:
           tlv_value = EXTRACT_LE_16BITS(p);
           break;
       case 3:
           tlv_value = EXTRACT_LE_24BITS(p);
           break;
       case 4:
           tlv_value = EXTRACT_LE_32BITS(p);
           break;
       default:
           tlv_value = -1;
           break;
       }
   } else {
       /* TLVs >= 128 are big endian encoded */
       switch (tlv_len) {
       case 1:
           tlv_value = *p;
           break;
       case 2:
           tlv_value = EXTRACT_16BITS(p);
           break;
       case 3:
           tlv_value = EXTRACT_24BITS(p);
           break;
       case 4:
           tlv_value = EXTRACT_32BITS(p);
           break;
       default:
           tlv_value = -1;
           break;
       }
   }
   return tlv_value;
}

static int
juniper_parse_header (const u_char *p, const struct pcap_pkthdr *h, struct juniper_l2info_t *l2info)
{
    struct juniper_cookie_table_t *lp = juniper_cookie_table;
    u_int idx, jnx_ext_len, jnx_header_len = 0;
    u_int8_t tlv_type,tlv_len;
#ifdef DLT_JUNIPER_ATM2
    u_int32_t control_word;
#endif
    const u_char *tptr;

    l2info->header_len = 0;
    l2info->cookie_len = 0;
    l2info->proto = 0;


    l2info->length = h->len;
    l2info->caplen = h->caplen;
//  TCHECK2(p[0],4);
    l2info->flags = p[3];
    l2info->direction = p[3]&JUNIPER_BPF_PKT_IN;
    
    if (EXTRACT_24BITS(p) != JUNIPER_MGC_NUMBER) { /* magic number found ? */
        return 0;
    } 

    /* magic number + flags */
    jnx_header_len = 4;

    /* extensions present ?  - calculate how much bytes to skip */
    if ((l2info->flags & JUNIPER_BPF_EXT ) == JUNIPER_BPF_EXT ) {

        tptr = p+jnx_header_len;

        /* ok to read extension length ? */
///     TCHECK2(tptr[0], 2);
        jnx_ext_len = EXTRACT_16BITS(tptr);
        jnx_header_len += 2;
        tptr +=2;
        
        /* nail up the total length -
         * just in case something goes wrong
         * with TLV parsing */
        jnx_header_len += jnx_ext_len;
        
//      TCHECK2(tptr[0], jnx_ext_len);
        while (jnx_ext_len > JUNIPER_EXT_TLV_OVERHEAD) {
            tlv_type = *(tptr++);
            tlv_len = *(tptr++);
            
            /* sanity check */
            if (tlv_type == 0 || tlv_len == 0)
                break;
            
            juniper_read_tlv_value(tptr, tlv_type, tlv_len);
            switch (tlv_type) {
            case JUNIPER_EXT_TLV_IFD_NAME:
                /* FIXME */
                break;
            case JUNIPER_EXT_TLV_IFD_MEDIATYPE:
            case JUNIPER_EXT_TLV_TTP_IFD_MEDIATYPE:
                break;
            case JUNIPER_EXT_TLV_IFL_ENCAPS:
            case JUNIPER_EXT_TLV_TTP_IFL_ENCAPS:
                break;
            case JUNIPER_EXT_TLV_IFL_IDX: /* fall through */
            case JUNIPER_EXT_TLV_IFL_UNIT:
            case JUNIPER_EXT_TLV_IFD_IDX:
            default:
                break;
            }
            
            tptr+=tlv_len;
            jnx_ext_len -= tlv_len+JUNIPER_EXT_TLV_OVERHEAD;
        }
    } 
    
    if ((l2info->flags & JUNIPER_BPF_NO_L2 ) == JUNIPER_BPF_NO_L2 ) {            
        /* there is no link-layer present -
         * perform the v4/v6 heuristics
         * to figure out what it is
         */
//      TCHECK2(p[jnx_header_len+4],1);
        if(ip_heuristic_guess(p+jnx_header_len+4,l2info->length-(jnx_header_len+4)) == 0)
            printf("no IP-hdr found!");

        l2info->header_len=jnx_header_len+4;
        return 0; /* stop parsing the output further */
        
    }
    l2info->header_len = jnx_header_len;
    p+=l2info->header_len;
    l2info->length -= l2info->header_len;
    l2info->caplen -= l2info->header_len;

    /* search through the cookie table and copy values matching for our PIC type */
    while (lp->s != NULL) {
        if (lp->pictype == l2info->pictype) {

            l2info->cookie_len += lp->cookie_len;

            switch (p[0]) {
            case LS_COOKIE_ID:
                l2info->cookie_type = LS_COOKIE_ID;
                l2info->cookie_len += 2;
                break;
            case AS_COOKIE_ID:
                l2info->cookie_type = AS_COOKIE_ID;
                l2info->cookie_len = 8;
                break;
            
            default:
                l2info->bundle = l2info->cookie[0];
                break;
            }


#ifdef DLT_JUNIPER_MFR
            /* MFR child links don't carry cookies */
            if (l2info->pictype == DLT_JUNIPER_MFR &&
                (p[0] & MFR_BE_MASK) == MFR_BE_MASK) {
                l2info->cookie_len = 0;
            }
#endif

            l2info->header_len += l2info->cookie_len;
            l2info->length -= l2info->cookie_len;
            l2info->caplen -= l2info->cookie_len;

            if (l2info->cookie_len > 0) {
//              TCHECK2(p[0],l2info->cookie_len);
                for (idx = 0; idx < l2info->cookie_len; idx++) {
                    l2info->cookie[idx] = p[idx]; /* copy cookie data */
                }
            }

            l2info->proto = EXTRACT_16BITS(p+l2info->cookie_len); 
            break;
        }
        ++lp;
    }
    p+=l2info->cookie_len;

    /* DLT_ specific parsing */
    switch(l2info->pictype) {
#ifdef DLT_JUNIPER_MLPPP
    case DLT_JUNIPER_MLPPP:
        switch (l2info->cookie_type) {
        case LS_COOKIE_ID:
            l2info->bundle = l2info->cookie[1];
            break;
        case AS_COOKIE_ID:
            l2info->bundle = (EXTRACT_16BITS(&l2info->cookie[6])>>3)&0xfff;
            l2info->proto = (l2info->cookie[5])&JUNIPER_LSQ_L3_PROTO_MASK;            
            break;
        default:
            l2info->bundle = l2info->cookie[0];
            break;
        }
        break;
#endif
#ifdef DLT_JUNIPER_MLFR
    case DLT_JUNIPER_MLFR:
        switch (l2info->cookie_type) {
        case LS_COOKIE_ID:
            l2info->bundle = l2info->cookie[1];
            l2info->proto = EXTRACT_16BITS(p);        
            l2info->header_len += 2;
            l2info->length -= 2;
            l2info->caplen -= 2;
            break;
        case AS_COOKIE_ID:
            l2info->bundle = (EXTRACT_16BITS(&l2info->cookie[6])>>3)&0xfff;
            l2info->proto = (l2info->cookie[5])&JUNIPER_LSQ_L3_PROTO_MASK;
            break;
        default:
            l2info->bundle = l2info->cookie[0];
            l2info->header_len += 2;
            l2info->length -= 2;
            l2info->caplen -= 2;
            break;
        }
        break;
#endif
#ifdef DLT_JUNIPER_MFR
    case DLT_JUNIPER_MFR:
        switch (l2info->cookie_type) {
        case LS_COOKIE_ID:
            l2info->bundle = l2info->cookie[1];
            l2info->proto = EXTRACT_16BITS(p);        
            l2info->header_len += 2;
            l2info->length -= 2;
            l2info->caplen -= 2;
            break;
        case AS_COOKIE_ID:
            l2info->bundle = (EXTRACT_16BITS(&l2info->cookie[6])>>3)&0xfff;
            l2info->proto = (l2info->cookie[5])&JUNIPER_LSQ_L3_PROTO_MASK;
            break;
        default:
            l2info->bundle = l2info->cookie[0];
            break;
        }
        break;
#endif
#ifdef DLT_JUNIPER_ATM2
    case DLT_JUNIPER_ATM2:
//      TCHECK2(p[0],4);
        /* ATM cell relay control word present ? */
        if (l2info->cookie[7] & ATM2_PKT_TYPE_MASK) {
            control_word = EXTRACT_32BITS(p);
            /* some control word heuristics */
            switch(control_word) {
            case 0: /* zero control word */
            case 0x08000000: /* < JUNOS 7.4 control-word */
            case 0x08380000: /* cntl word plus cell length (56) >= JUNOS 7.4*/
                l2info->header_len += 4;
                break;
            default:
                break;
            }
        }
        break;
#endif
#ifdef DLT_JUNIPER_GGSN
    case DLT_JUNIPER_GGSN:
        break;
#endif
#ifdef DLT_JUNIPER_ATM1
    case DLT_JUNIPER_ATM1:
        break;
#endif
#ifdef DLT_JUNIPER_PPP
    case DLT_JUNIPER_PPP:
        break;
#endif
#ifdef DLT_JUNIPER_CHDLC
    case DLT_JUNIPER_CHDLC:
        break;
#endif
#ifdef DLT_JUNIPER_ETHER
    case DLT_JUNIPER_ETHER:
        break;
#endif
#ifdef DLT_JUNIPER_FRELAY
    case DLT_JUNIPER_FRELAY:
        break;
#endif

    default:
        break;
    }
    
    return 1; /* everything went ok so far. continue parsing */
}

#define PRISM_HDR_LEN      144

#define WLANCAP_MAGIC_COOKIE_V1   0x80211001

#define DIDmsg_lnxind_wlansniffrm      0x0041
#define DIDmsg_lnxind_wlansniffrm_hosttime   0x1041
#define DIDmsg_lnxind_wlansniffrm_mactime   0x2041
#define DIDmsg_lnxind_wlansniffrm_channel   0x3041
#define DIDmsg_lnxind_wlansniffrm_rssi      0x4041
#define DIDmsg_lnxind_wlansniffrm_sq      0x5041
#define DIDmsg_lnxind_wlansniffrm_signal   0x6041
#define DIDmsg_lnxind_wlansniffrm_noise      0x7041
#define DIDmsg_lnxind_wlansniffrm_rate      0x8041
#define DIDmsg_lnxind_wlansniffrm_istx      0x9041
#define DIDmsg_lnxind_wlansniffrm_frmlen   0xA041

struct prism_value {
   u_int32_t did;
   u_int16_t status, len;
   u_int32_t data;
};

struct prism_header {
   u_int32_t msgcode, msglen;
   u_char devname[16];
   struct prism_value hosttime;
   struct prism_value mactime;
   struct prism_value channel;
   struct prism_value rssi;
   struct prism_value sq;
   struct prism_value signal;
   struct prism_value noise;
   struct prism_value rate;
   struct prism_value istx;
   struct prism_value frmlen;
};


/*
 * For DLT_PRISM_HEADER; like DLT_IEEE802_11, but with an extra header,
 * containing information such as radio information, which we
 * currently ignore.
 *
 * If, however, the packet begins with WLANCAP_MAGIC_COOKIE_V1, it's
 * really DLT_IEEE802_11_RADIO (currently, on Linux, there's no
 * ARPHRD_ type for DLT_IEEE802_11_RADIO, as there is a
 * ARPHRD_IEEE80211_PRISM for DLT_PRISM_HEADER, so
 * ARPHRD_IEEE80211_PRISM is used for DLT_IEEE802_11_RADIO, and
 * the first 4 bytes of the header are used to indicate which it is).
 */

void
ArgusPrismPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct prism_header *phdr = (struct prism_header *) p;
   u_int caplen = h->caplen, phdrlen = sizeof (*phdr);

   if (caplen < 4) 
      return;

   if (EXTRACT_32BITS(p) == WLANCAP_MAGIC_COOKIE_V1)
      Argus802_11RadioPacket (user, h, p + PRISM_HDR_LEN);

   if (caplen < PRISM_HDR_LEN)
      return;

/*
   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusThisLength  = length;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_PRISM;
*/

   if (phdr->hosttime.len != 4) {

#define swapl(n)   (((((unsigned long)(n) & 0xFF)) << 24) | \
         ((((unsigned long)(n) & 0xFF00)) << 8) | \
         ((((unsigned long)(n) & 0xFF0000)) >> 8) | \
         ((((unsigned long)(n) & 0xFF000000)) >> 24))
#define swaps(n)   (((((unsigned short)(n) & 0xFF)) << 8) | (((unsigned short)(n) & 0xFF00) >> 8))

      phdr->msgcode = swapl(phdr->msgcode);
      phdr->msglen  = swapl(phdr->msglen);
      phdr->hosttime.did    = swapl(phdr->hosttime.did);
      phdr->hosttime.status = swaps(phdr->hosttime.status);
      phdr->hosttime.len    = swaps(phdr->hosttime.len);
      phdr->hosttime.data   = swapl(phdr->hosttime.data);
      phdr->mactime.did     = swapl(phdr->mactime.did);
      phdr->mactime.status  = swaps(phdr->mactime.status);
      phdr->mactime.len     = swaps(phdr->mactime.len);
      phdr->mactime.data    = swapl(phdr->mactime.data);
      phdr->channel.did     = swapl(phdr->channel.did);
      phdr->channel.status  = swaps(phdr->channel.status);
      phdr->channel.len     = swaps(phdr->channel.len);
      phdr->channel.data    = swapl(phdr->channel.data);
      phdr->rssi.did        = swapl(phdr->rssi.did);
      phdr->rssi.status     = swaps(phdr->rssi.status);
      phdr->rssi.len        = swaps(phdr->rssi.len);
      phdr->rssi.data       = swapl(phdr->rssi.data);
      phdr->sq.did          = swapl(phdr->sq.did);
      phdr->sq.status       = swaps(phdr->sq.status);
      phdr->sq.len          = swaps(phdr->sq.len);
      phdr->sq.data         = swapl(phdr->sq.data);
      phdr->signal.did      = swapl(phdr->signal.did);
      phdr->signal.status   = swaps(phdr->signal.status);
      phdr->signal.len      = swaps(phdr->signal.len);
      phdr->signal.data     = swapl(phdr->signal.data);
      phdr->noise.did       = swapl(phdr->noise.did);
      phdr->noise.status    = swaps(phdr->noise.status);
      phdr->noise.len       = swaps(phdr->noise.len);
      phdr->noise.data      = swapl(phdr->noise.data);
      phdr->rate.did        = swapl(phdr->rate.did);
      phdr->rate.status     = swaps(phdr->rate.status);
      phdr->rate.len        = swaps(phdr->rate.len);
      phdr->rate.data       = swapl(phdr->rate.data);
      phdr->istx.did        = swapl(phdr->istx.did);
      phdr->istx.status     = swaps(phdr->istx.status);
      phdr->istx.len        = swaps(phdr->istx.len);
      phdr->istx.data       = swapl(phdr->istx.data);
      phdr->frmlen.did      = swapl(phdr->frmlen.did);
      phdr->frmlen.status   = swaps(phdr->frmlen.status);
      phdr->frmlen.len      = swaps(phdr->frmlen.len);
      phdr->frmlen.data     = swapl(phdr->frmlen.data);
   }

   if ((phdrlen == PRISM_HDR_LEN) && ((void *)(phdr + 1) == (p + PRISM_HDR_LEN)))
      Argus802_11Packet (user, h, p + PRISM_HDR_LEN);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusPrismPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


struct avs_header {
   u_int32_t version, length;
   u_int64_t mactime, hosttime;
   u_int32_t phytype, channel;
   u_int32_t datarate, antenna;
   u_int32_t priority, ssi_type;
   u_int32_t ssi_signal, ssi_noise;
   u_int32_t preamble, encoding;
};

void
Argus802_11RadioAvsPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct avs_header *ahdr = (struct avs_header *) p;
   u_int32_t caplen = h->caplen, caphdr_len;

   caphdr_len = EXTRACT_32BITS(p + 4);
   if (caphdr_len < 8)
      return;
   
   if (caplen < caphdr_len)
      return;
   
   Argus802_11Packet (user, h, (u_char *)(ahdr + 1));

#ifdef ARGUSDEBUG 
   ArgusDebug (8, "Argus802_11RadioAvsPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


static int ArgusParseRadioTapField(struct cpack_state *, u_int32_t, struct ieee80211_radiotap *);

void
Argus802_11RadioPacket (u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct ieee80211_radiotap_header *rthdr = (struct ieee80211_radiotap_header *) p;
   struct pcap_pkthdr phdr = *h;
   u_int32_t rthdr_len;

#define BITNO_32(x) (((x) >> 16) ? 16 + BITNO_16((x) >> 16) : BITNO_16((x)))
#define BITNO_16(x) (((x) >> 8) ? 8 + BITNO_8((x) >> 8) : BITNO_8((x)))
#define BITNO_8(x) (((x) >> 4) ? 4 + BITNO_4((x) >> 4) : BITNO_4((x)))
#define BITNO_4(x) (((x) >> 2) ? 2 + BITNO_2((x) >> 2) : BITNO_2((x)))
#define BITNO_2(x) (((x) & 2) ? 1 : 0)
#define BIT(n)  (1U << n)
#define IS_EXTENDED(__p)        \
            (EXTRACT_LE_32BITS(__p) & BIT(IEEE80211_RADIOTAP_EXT)) != 0

   struct cpack_state cpacker;
   u_int32_t present, next_present;
   u_int32_t *presentp, *last_presentp;
   enum ieee80211_radiotap_type bit;
   int bit0;
   u_char *iter;

   if ((rthdr_len = rthdr->it_len) < 8)
      return;

   bzero(&src->ArgusThisRadioTap, sizeof(src->ArgusThisRadioTap));

   if (h->caplen < rthdr_len)
      return;

   for (last_presentp = &rthdr->it_present; IS_EXTENDED(last_presentp) && (u_char*)(last_presentp + 1) <= p + rthdr_len; last_presentp++);

   /* are there more bitmap extensions than bytes in header? */
   if (IS_EXTENDED(last_presentp))
      return;

   iter = (u_char*)(last_presentp + 1);

   if (cpack_init(&cpacker, (u_int8_t *)iter, rthdr_len - (iter - p)) != 0)
      return;

  /* Assume no flags */
  /* Assume no Atheros padding between 802.11 header and body */
   for (bit0 = 0, presentp = &rthdr->it_present; presentp <= last_presentp; presentp++, bit0 += 32) {
      for (present = EXTRACT_LE_32BITS(presentp); present; present = next_present) {
         /* clear the least significant bit that is set */
         next_present = present & (present - 1);

         /* extract the least significant bit that is set */
         bit = (enum ieee80211_radiotap_type) (bit0 + BITNO_32(present ^ next_present));

         if (ArgusParseRadioTapField(&cpacker, bit, &src->ArgusThisRadioTap) != 0)
            goto out;
      }
   }

out:
   phdr.len    -= rthdr_len;
   phdr.caplen -= rthdr_len;

   Argus802_11Packet (user, (const struct pcap_pkthdr *)&phdr, ((u_char *)rthdr + rthdr_len));

#undef BITNO_32
#undef BITNO_16
#undef BITNO_8
#undef BITNO_4
#undef BITNO_2
#undef BIT

#ifdef ARGUSDEBUG
   ArgusDebug (3, "Argus802_11RadioPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


void
ArgusIpPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct ip *ip = (struct ip *) p;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *) ip) + caplen;
   src->ArgusModel->ArgusThisEncaps  = 0;

   if (p) {
      src->ArgusModel->ArgusThisIpHdr   = ip;
      src->ArgusModel->ArgusThisLength  = length;
      ArgusProcessIpPacket (src->ArgusModel, ip, length, tvp);
   }


#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusIpPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


#define ENC_HDRLEN      12

/* From $OpenBSD: mbuf.h,v 1.56 2002/01/25 15:50:23 art Exp $   */
#define M_CONF          0x0400  /* packet was encrypted (ESP-transport) */
#define M_AUTH          0x0800  /* packet was authenticated (AH) */

struct enchdr {
        u_int32_t af;
        u_int32_t spi;
        u_int32_t flags;
};

void
ArgusEncPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct ip *ip = (struct ip *) (p + ENC_HDRLEN);
   unsigned int caplen = h->caplen - ENC_HDRLEN;
   unsigned int length = h->len    - ENC_HDRLEN;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *) ip) + caplen;

   src->ArgusModel->ArgusThisEncaps |= ARGUS_ENCAPS_SPI;

   if (p) {
      src->ArgusModel->ArgusThisIpHdr   = ip;
      src->ArgusModel->ArgusThisLength  = length;
      if (ArgusProcessPacket (src, (char *)p, length, tvp, ETHERTYPE_IP)) 
         if (src->ArgusDumpPacketOnError && (src->ArgusPcapOutFile != NULL))
            pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusEncPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


#if defined(ultrix) || defined(__alpha)
static int   fddi_bitswap = 0;
#else
static int   fddi_bitswap = 1;
#endif

int fddipad = FDDIPAD;

#define FDDI_HDRLEN (sizeof(struct fddi_header))

static u_char fddi_bit_swap[] = {
   0x00, 0x80, 0x40, 0xc0, 0x20, 0xa0, 0x60, 0xe0,
   0x10, 0x90, 0x50, 0xd0, 0x30, 0xb0, 0x70, 0xf0,
   0x08, 0x88, 0x48, 0xc8, 0x28, 0xa8, 0x68, 0xe8,
   0x18, 0x98, 0x58, 0xd8, 0x38, 0xb8, 0x78, 0xf8,
   0x04, 0x84, 0x44, 0xc4, 0x24, 0xa4, 0x64, 0xe4,
   0x14, 0x94, 0x54, 0xd4, 0x34, 0xb4, 0x74, 0xf4,
   0x0c, 0x8c, 0x4c, 0xcc, 0x2c, 0xac, 0x6c, 0xec,
   0x1c, 0x9c, 0x5c, 0xdc, 0x3c, 0xbc, 0x7c, 0xfc,
   0x02, 0x82, 0x42, 0xc2, 0x22, 0xa2, 0x62, 0xe2,
   0x12, 0x92, 0x52, 0xd2, 0x32, 0xb2, 0x72, 0xf2,
   0x0a, 0x8a, 0x4a, 0xca, 0x2a, 0xaa, 0x6a, 0xea,
   0x1a, 0x9a, 0x5a, 0xda, 0x3a, 0xba, 0x7a, 0xfa,
   0x06, 0x86, 0x46, 0xc6, 0x26, 0xa6, 0x66, 0xe6,
   0x16, 0x96, 0x56, 0xd6, 0x36, 0xb6, 0x76, 0xf6,
   0x0e, 0x8e, 0x4e, 0xce, 0x2e, 0xae, 0x6e, 0xee,
   0x1e, 0x9e, 0x5e, 0xde, 0x3e, 0xbe, 0x7e, 0xfe,
   0x01, 0x81, 0x41, 0xc1, 0x21, 0xa1, 0x61, 0xe1,
   0x11, 0x91, 0x51, 0xd1, 0x31, 0xb1, 0x71, 0xf1,
   0x09, 0x89, 0x49, 0xc9, 0x29, 0xa9, 0x69, 0xe9,
   0x19, 0x99, 0x59, 0xd9, 0x39, 0xb9, 0x79, 0xf9,
   0x05, 0x85, 0x45, 0xc5, 0x25, 0xa5, 0x65, 0xe5,
   0x15, 0x95, 0x55, 0xd5, 0x35, 0xb5, 0x75, 0xf5,
   0x0d, 0x8d, 0x4d, 0xcd, 0x2d, 0xad, 0x6d, 0xed,
   0x1d, 0x9d, 0x5d, 0xdd, 0x3d, 0xbd, 0x7d, 0xfd,
   0x03, 0x83, 0x43, 0xc3, 0x23, 0xa3, 0x63, 0xe3,
   0x13, 0x93, 0x53, 0xd3, 0x33, 0xb3, 0x73, 0xf3,
   0x0b, 0x8b, 0x4b, 0xcb, 0x2b, 0xab, 0x6b, 0xeb,
   0x1b, 0x9b, 0x5b, 0xdb, 0x3b, 0xbb, 0x7b, 0xfb,
   0x07, 0x87, 0x47, 0xc7, 0x27, 0xa7, 0x67, 0xe7,
   0x17, 0x97, 0x57, 0xd7, 0x37, 0xb7, 0x77, 0xf7,
   0x0f, 0x8f, 0x4f, 0xcf, 0x2f, 0xaf, 0x6f, 0xef,
   0x1f, 0x9f, 0x5f, 0xdf, 0x3f, 0xbf, 0x7f, 0xff,
};

static inline void
Argusextract_fddi_addrs(const struct fddi_header *fp, struct ether_header *ehdr)
{
   char *fsrc = (char *)&ehdr->ether_shost;
   char *fdst = (char *)&ehdr->ether_dhost;
   int i;

   if (fddi_bitswap) {
      for (i = 0; i < 6; ++i)
         fdst[i] = fddi_bit_swap[fp->fddi_dhost[i]];
      for (i = 0; i < 6; ++i)
         fsrc[i] = fddi_bit_swap[fp->fddi_shost[i]];
   }
   else {
      bcopy ((char *) fp->fddi_dhost, fdst, 6);
      bcopy ((char *) fp->fddi_shost, fsrc, 6);
   }
}

int
ArgusCreatePktFromFddi(const struct fddi_header *fp, struct ether_header *ep, int length)
{
   unsigned char *ptr;
   unsigned int retn = 0;
   struct llc *llc;
 
   if ((fp->fddi_fc & FDDIFC_CLFF) == FDDIFC_LLC_ASYNC) {
      Argusextract_fddi_addrs (fp, ep);

      llc = (struct llc *)(fp + 1);
 
      if (llc->ssap == LLCSAP_SNAP && llc->dsap == LLCSAP_SNAP && llc->llcui == LLC_UI) {
         ((struct ether_header *) ep)->ether_type = EXTRACT_16BITS(&llc->ethertype[0]);
         ptr = (unsigned char *)(llc + 1);
         length -= (sizeof(struct fddi_header) + sizeof(struct llc));
         bcopy ((char *)ptr, (char *)(ep + 1), length);
         retn = length + sizeof(struct ether_header);
      }
   }

   return (retn);
}

void
ArgusFddiPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   const struct fddi_header *fp = (struct fddi_header *)p;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   int ind = src->ArgusThisIndex;
   struct ether_header *ep;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   ep = (struct ether_header *) src->ArgusInterface[ind].ArgusPacketBuffer;

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusThisLength  = length;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_FDDI;

   src->ArgusInterface[ind].ArgusPacketBuffer = src->ArgusInterface[ind].ArgusPacketBufferBuffer;
   if (p && (length = ArgusCreatePktFromFddi(fp, ep, length))) {
      if (p && length)
         ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusFddiPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


#define ARGUS_802_6_MAC_HDR_LEN      20
#define ARGUS_ATM_HDR_OFFSET      8

void
ArgusATMPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int caplen = h->caplen;
   unsigned int length = h->len;
   int ind = src->ArgusThisIndex;
   struct ether_header *ep;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   ep = (struct ether_header *) src->ArgusInterface[ind].ArgusPacketBuffer;

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusInterface[ind].ArgusPacketBuffer = src->ArgusInterface[ind].ArgusPacketBufferBuffer;

   if (caplen > 8) {
      if (p[0] != 0xaa || p[1] != 0xaa || p[2] != 0x03) {
         if (caplen > 28) {
            p += ARGUS_802_6_MAC_HDR_LEN;
            length -= ARGUS_802_6_MAC_HDR_LEN;
            caplen -= ARGUS_802_6_MAC_HDR_LEN;
         } else
            return;
      }
   } else
      return;
   
   ep->ether_type = ((p[6] << 8) | p[7]);
   length -= ARGUS_ATM_HDR_OFFSET;
   caplen -= ARGUS_ATM_HDR_OFFSET;
   p += ARGUS_ATM_HDR_OFFSET;
   
   bcopy (p, (char *)(ep + 1), caplen);

   length += sizeof(*ep);
   caplen += sizeof(*ep);

   src->ArgusModel->ArgusThisLength  = length;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ep) + caplen;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_ATM;

   ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusATMPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


void
ArgusPppPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct ip *ip = (struct ip *) (p + PPP_HDRLEN);
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   if (p && (length > PPP_HDRLEN)) {
      ArgusModel->ArgusGlobalTime = *tvp;
      src->ArgusModel->ArgusGlobalTime  = *tvp;
      src->ArgusModel->ArgusSnapLength  = caplen;
      src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ip) + (caplen - PPP_HDRLEN);
      src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_PPP;

      length -= PPP_HDRLEN;

      src->ArgusModel->ArgusThisLength  = length;

      ArgusProcessIpPacket (src->ArgusModel, ip, length, tvp);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusPppPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}



#define ARGUS_PPPBSDOS_HDR_LEN       24


void
ArgusPppBsdosPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   unsigned int length = h->len, hdrlen = 0;
   unsigned int caplen = h->caplen;
   unsigned short ptype = 0;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = (u_char *) p + caplen;
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_PPP;

   if (p[0] == PPP_ADDRESS && p[1] == PPP_CONTROL) {
      p += 2;
      hdrlen = 2;
   }

   if (*p & 01) {                  /* Retrieve the protocol type */
      ptype = *p;                  /* Compressed protocol field */
      p++;
      hdrlen += 1;
   } else {
#if defined(_LITTLE_ENDIAN)
      ptype = ntohs(*(u_short *)p);
#else
      ptype = *(u_short *)p;
#endif
      p += 2;
      hdrlen += 2;
   }

   length -= hdrlen;
   if (ptype == PPP_IP)
      if (p && (length > 0)) {
         src->ArgusModel->ArgusThisLength  = length;
         ArgusProcessIpPacket (src->ArgusModel, (struct ip *) p, length, tvp);
      }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusPppBsdosPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

#if defined(__NetBSD__) || defined(__FreeBSD__)
#include <sys/param.h>
#include <sys/mbuf.h>
#endif

#include <net/slcompress.h>
#include <net/slip.h>


/* XXX BSD/OS 2.1 compatibility */

#if !defined(ARGUS_SLIP_HDR_LEN) && defined(SLC_BPFHDR)
#define SLIP_HDRLEN SLC_BPFHDR
#define SLX_DIR 0
#define SLX_CHDR (SLC_BPFHDRLEN - 1)
#define CHDR_LEN (SLC_BPFHDR - SLC_BPFHDRLEN)
#else

#endif


void
ArgusSlipPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct timeval tvpbuf, *tvp = &tvpbuf;
   struct ip *ip = (struct ip *) (p + SLIP_HDRLEN);
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   struct stat statbuf;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   src->ArgusModel->ArgusGlobalTime  = *tvp;
   src->ArgusModel->ArgusSnapLength  = caplen;
   src->ArgusModel->ArgusThisSnapEnd = ((u_char *)ip) + (caplen - SLIP_HDRLEN);
   src->ArgusModel->ArgusThisEncaps  = ARGUS_ENCAPS_SLIP;

   if (p && (length > SLIP_HDRLEN)) {
      length -= SLIP_HDRLEN;

      src->ArgusModel->ArgusThisLength  = length;

      ArgusProcessIpPacket (src->ArgusModel, ip, length, tvp);
   }

 
#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusSlipPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}


#include <argus/sll.h>

#if !defined(ETHER_ADDR_LEN)
#define ETHER_ADDR_LEN  6
#endif


void
ArgusSllPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct ArgusModelerStruct *model = src->ArgusModel;
   unsigned int length = h->len;
   unsigned int caplen = h->caplen;
   const struct sll_header *sllp = NULL;
   struct timeval tvpbuf, *tvp = &tvpbuf;

   unsigned char buf[2048];
   struct ether_header *ep = (struct ether_header *)buf;
   struct stat statbuf;
   u_short pkttype;

   tvp->tv_sec  = h->ts.tv_sec;
   tvp->tv_usec = h->ts.tv_usec;
#if defined(ARGUS_NANOSECONDS)
   tvp->tv_usec *= 1000;
#endif

   if (src->ArgusReadingOffLine)
      src->ArgusInputOffset = ftell(src->ArgusPacketInput);

   ArgusModel->ArgusGlobalTime = *tvp;
   model->ArgusGlobalTime  = *tvp;

   if (src->ArgusWriteOutPacketFile) {
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   sllp = (const struct sll_header *)p;
   memcpy((void *)&ep->ether_shost, sllp->sll_addr, ETHER_ADDR_LEN);

#if defined(_LITTLE_ENDIAN)
   pkttype = ntohs(sllp->sll_pkttype);
#else
   pkttype = sllp->sll_pkttype;
#endif

   if (pkttype != LINUX_SLL_OUTGOING) {
      if (pkttype == LINUX_SLL_BROADCAST)
         memset((void *)&ep->ether_dhost, 0xFF, ETHER_ADDR_LEN);
      else {
         memset((void *)&ep->ether_dhost, 0, ETHER_ADDR_LEN);
         if (pkttype == LINUX_SLL_MULTICAST)
#if defined(HAVE_SOLARIS)
            ep->ether_dhost.ether_addr_octet[0] = 0x01;
#else
            ep->ether_dhost[0] = 0x01;
#endif
         else
#if defined(HAVE_SOLARIS)
            ep->ether_dhost.ether_addr_octet[ETHER_ADDR_LEN-1] = 0x01;
#else
            ep->ether_dhost[ETHER_ADDR_LEN-1] = 0x01;
#endif
      }
   } else {
      /*
       * We sent this packet; we don't know whether it's
       * broadcast, multicast, or unicast, so just make
       * the destination address all 0's.
       */
      memset((void *)&ep->ether_dhost, 0, ETHER_ADDR_LEN);
   }

   length -= SLL_HDR_LEN;
   caplen -= SLL_HDR_LEN;
   p += SLL_HDR_LEN;
 
   ep->ether_type = sllp->sll_protocol;
 
   memcpy((ep + 1), p, caplen);

   model->ArgusThisSnapEnd = (unsigned char *)(ep + caplen);
   model->ArgusThisLength  = length;
   model->ArgusSnapLength  = caplen;
   model->ArgusThisEncaps  = ARGUS_ENCAPS_SLL;

   ArgusProcessPacket (src, (char *)ep, length, tvp, ARGUS_ETHER_HDR);

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusSllPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}

/*
 * Byte-swap a 32-bit number.
 * ("htonl()" or "ntohl()" won't work - we want to byte-swap even on
 * big-endian platforms.)
 */
#define SWAPLONG(y) \
((((y)&0xff)<<24) | (((y)&0xff00)<<8) | (((y)&0xff0000)>>8) | (((y)>>24)&0xff))

#define NULL_HDRLEN 4

#define BSD_AF_INET             2
#define BSD_AF_NS               6               /* XEROX NS protocols */
#define BSD_AF_ISO              7
#define BSD_AF_APPLETALK        16
#define BSD_AF_IPX              23
#define BSD_AF_INET6_BSD        24      /* OpenBSD (and probably NetBSD), BSD/OS */
#define BSD_AF_INET6_FREEBSD    28
#define BSD_AF_INET6_DARWIN     30

void
ArgusNullPacket(u_char *user, const struct pcap_pkthdr *h, const u_char *p)
{
   struct ArgusSourceStruct *src = (struct ArgusSourceStruct *) user;
   struct pcap_pkthdr hbuf;
   unsigned int family;

   if (src->ArgusWriteOutPacketFile) {
      struct stat statbuf;
      if (stat(src->ArgusWriteOutPacketFile, &statbuf) < 0) {
         if (src->ArgusPcapOutFile != NULL) {
            pcap_dump_close(src->ArgusPcapOutFile);
            src->ArgusPcapOutFile = NULL;
         }

         if ((src->ArgusPcapOutFile = pcap_dump_open(src->ArgusInterface[0].ArgusPd, src->ArgusWriteOutPacketFile)) == NULL)
            ArgusLog (LOG_ERR, "%s\n", pcap_geterr (src->ArgusInterface[0].ArgusPd));
      }

      if (src->ArgusDumpPacket && (src->ArgusPcapOutFile != NULL)) {
#if defined(HAVE_PCAP_DUMP_FTELL)
         src->ArgusPacketOffset = pcap_dump_ftell(src->ArgusPcapOutFile);
#endif
         pcap_dump((u_char *)src->ArgusPcapOutFile, h, p);
      }
   }

   memcpy((char *)&family, (char *)p, sizeof(family));
   memcpy((char *)&hbuf, (char *)h, sizeof(*h));

   if ((family & 0xFFFF0000) != 0)
      family = SWAPLONG(family);

   hbuf.len    -= NULL_HDRLEN;
   hbuf.caplen -= NULL_HDRLEN;
   p           += NULL_HDRLEN;
 
   switch (family) {
      case BSD_AF_INET:
      case BSD_AF_INET6_BSD:     
      case BSD_AF_INET6_FREEBSD: 
      case BSD_AF_INET6_DARWIN:
         ArgusIpPacket (user, &hbuf, p);
         break;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (8, "ArgusNullPacket (%p, %p, %p) returning\n", user, h, p);
#endif
}
#endif

#include <sys/ioctl.h>

#if defined(HAVE_SOLARIS)
#include <sys/sockio.h>
#endif


void *ArgusEventsProcess(void *);
extern int getArguspidflag (void);
extern char * ArgusCreatePIDFile (struct ArgusSourceStruct *, char *, char *);
extern char *ArgusPidFile;
extern char *ArgusPidPath;


void
ArgusSourceProcess (struct ArgusSourceStruct *stask)
{
#if defined(ARGUS_THREADS)
   struct timeval tvp;
   struct timespec tsbuf, *ts = &tsbuf;
   int ArgusThreadCount = 0, ArgusThreads = 0;
#endif
   extern uid_t new_uid;
   extern gid_t new_gid;

   if (stask->ArgusRfileList != NULL) {
      struct ArgusRfileStruct *rfile = (struct ArgusRfileStruct *) stask->ArgusRfileList->start;
      int i, count = stask->ArgusRfileList->count;

      if (setuid(getuid()) != 0)
         ArgusLog (LOG_ERR, "ArgusInitSource: setuid %s\n",  strerror(errno));

      if (stask->ArgusDeviceList)
         clearArgusDevice(stask);
      
      for (i = 0; i < count; i++) {
         stask->mode = rfile->mode;
         setArgusDevice(stask, rfile->name, ARGUS_FILE_DEVICE, rfile->mode);
         rfile = (struct ArgusRfileStruct *) rfile->nxt;
      }
    } else 
      if (!(stask->ArgusDeviceList))
         setArgusDevice (stask, "any", ARGUS_LIVE_DEVICE, 0);

   if (stask->ArgusDeviceList) {
#if defined(ARGUS_THREADS)
      int i, count = stask->ArgusDeviceList->count;
      ArgusThreadCount = 0;
#endif

      if (!(stask->ArgusReadingOffLine))
         ArgusLog(LOG_ALERT, "started");

      if (daemonflag)
         if (getArguspidflag() && ((ArgusPidFile = ArgusCreatePIDFile (ArgusSourceTask, ArgusPidPath, ArgusProgramName)) == NULL))
            ArgusLog (LOG_ERR, "daemon cannot create pid file");

#if defined(ARGUS_THREADS)
      for (i = 0; i < count; i++) {
         struct ArgusDeviceStruct *device = (struct ArgusDeviceStruct *) ArgusPopFrontList(stask->ArgusDeviceList, ARGUS_LOCK);

         if (device != NULL) {
            struct ArgusSourceStruct *src = NULL;

            src = ArgusCloneSource(stask);
            clearArgusDevice(src);

            gettimeofday (&src->marktime, 0L);

            if (device->ArgusID.a_un.value != 0) {
               src->ArgusID = device->ArgusID;
            } else {
               device->ArgusID = stask->ArgusID;
               device->idtype  = stask->type;
               src->ArgusID    = stask->ArgusID;
               src->type       = stask->type;
            }
            src->type    = device->type;

            ArgusPushBackList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);

            if (ArgusInitSource (src) > 0) {
               stask->srcs[ArgusThreads] = src;

               if (new_gid > 0) {
                  if (setgid(new_gid) < 0)
                     ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));
               }
               if (new_uid > 0) {
                  if (setuid(new_uid) < 0)
                     ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));
               }

               if ((pthread_create(&src->thread, NULL, ArgusGetPackets, (void *) src)) != 0)
                  ArgusLog (LOG_ERR, "ArgusNewEventProcessor() pthread_create error %s\n", strerror(errno));

               ArgusThreads++;
               ArgusThreadCount++;
            }
         }
      }
#else
      ArgusInitSource (stask);
      if (new_gid > 0) {
         if (setgid(new_gid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));
      }
      if (new_uid > 0) {
         if (setuid(new_uid) < 0)
            ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));
      }
      ArgusGetPackets (stask);

#endif /* ARGUS_THREADS */
   }

#if defined(ARGUS_THREADS)
   do {
      int retn = 0, i;

      gettimeofday (&tvp, 0L);
      ts->tv_sec  = tvp.tv_sec + 0;
      ts->tv_nsec = (tvp.tv_usec * 1000) + 0;
      ts->tv_sec++;

      if ((retn = pthread_mutex_lock(&stask->lock))) {
         switch (retn) {
            case EINVAL:
               ArgusLog(LOG_ERR, "ArgusSourceProcess: pthread_mutex_lock() error EINVAL\n");
               break;
            case EDEADLK:
               ArgusLog(LOG_ERR, "ArgusSourceProcess: pthread_mutex_lock() error EDEADLK\n");
               break;
         }
      }
      if ((retn = pthread_cond_timedwait(&stask->cond, &stask->lock, ts))) {
         switch (retn) {
            case EINVAL:
               ArgusLog(LOG_ERR, "ArgusSourceProcess: pthread_cond_timedwait() error EINVAL\n");
               break;
            case ETIMEDOUT:
               break;
         }
      }

      for (i = 0; i < ArgusThreadCount; i++) {
         gettimeofday (&stask->srcs[i]->marktime, 0L);
         if (stask->srcs[i]->status & ARGUS_SHUTDOWN) {
            pthread_t thread;
            void *ptr = NULL;
            if ((thread = stask->srcs[i]->thread) != 0)
               pthread_join(thread, &ptr);

#ifdef ARGUSDEBUG
            ArgusDebug (2, "ArgusSourceProcess: ArgusGetPackets[%d] done\n", i);
#endif
            ArgusThreads--;
            stask->srcs[i]->status &= ~ARGUS_SHUTDOWN;
         }
      }

      pthread_mutex_unlock(&stask->lock);

   } while (!(stask->status & ARGUS_SHUTDOWN) && (ArgusThreads > 0));
#endif /* ARGUS_THREADS */
}

void *
ArgusGetPackets (void *arg)
{
   void *retn = NULL;
   struct ArgusSourceStruct *src = arg;
   fd_set ArgusReadMask, ArgusWriteMask, ArgusExceptMask;
   int noerror = 1;

   struct timeval wait;
   int tmp, width = 0, fd;
   int i, fds[ARGUS_MAXINTERFACE];

#if defined(ARGUS_PLURIBUS)
   int notselectable = 1;
#else
   int notselectable = 0;
#endif

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;

   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif /* ARGUS_THREADS */

   if (src != NULL) {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusGetPackets (%p) starting\n", src);
#endif

#if defined(HAVE_SOLARIS)
      sigignore (SIGPIPE);
#else
      signal (SIGPIPE, SIG_IGN);
#endif
      FD_ZERO(&ArgusReadMask);
      FD_ZERO(&ArgusWriteMask);
      FD_ZERO(&ArgusExceptMask);

      wait.tv_sec = 0; wait.tv_usec = 200000;

      ArgusGetInterfaceStatus(src);
      gettimeofday (&src->ArgusStartTime, 0L);

#if defined(ARGUS_NANOSECONDS)
      src->ArgusModel->ArgusStartTime.tv_usec *= 1000;
#endif
      for (i = 0; i < ARGUS_MAXINTERFACE; i++)
         fds[i] = -1;

      if (src->ArgusInterface[0].ArgusPd) {
         int found = 0, up = 0;

         switch (src->ArgusInterface[0].ArgusInterfaceType) {
            case ARGUSERFPKTFILE: {
               if (src->ArgusInterface[0].ArgusPcap.fd) {
                  for (i = 0; i < src->ArgusInterfaces; i++) {
                     do {
                        FD_SET(src->ArgusInterface[i].ArgusPcap.fd, &ArgusReadMask);
                        width = src->ArgusInterface[i].ArgusPcap.fd + 1;
                        if (select (width + 1, &ArgusReadMask, NULL, NULL, &wait) > 0) {
                           ArgusErfRead(src);
                           if (src->eNflag > 0)
                              src->eNflag--;
                        } else
                           break;

                     } while (noerror && (src->eNflag != 0) && (!(ArgusShutDownStarted)));
                  }
               }
               break;
            }

            default: {
               for (i = 0; i < src->ArgusInterfaces; i++) {
                  if (src->ArgusInterface[i].ArgusPd) {
                     found++;
#if !defined(CYGWIN) && !defined(WIN32) && !defined(MSDOS)
#if defined(HAVE_PCAP_GET_SELECTABLE_FD)
                     if (pcap_get_selectable_fd(src->ArgusInterface[i].ArgusPd) < 0)
#endif
                        notselectable++;
#endif
#ifdef ARGUSDEBUG
                     ArgusDebug (1, "ArgusGetPackets: interface %s %s selectable\n",
                        src->ArgusInterface[i].ifr.ifr_name, (notselectable ? "is not" : "is"));
#endif
                     if ((src->ArgusInterface[i].ifr.ifr_flags & IFF_UP) != 0) {
                        up++;
                        if ((fd = pcap_fileno(src->ArgusInterface[i].ArgusPd)) >= 0) {
                           fds[i] = fd;
                           setArgusInterfaceStatus(src, 1);
                           FD_SET(pcap_fileno(src->ArgusInterface[i].ArgusPd), &ArgusReadMask);
                           if (width < fd)
                              width = fd;
                        }
                     } else
                        setArgusInterfaceStatus(src, 0);
                  } else
                     setArgusInterfaceStatus(src, 0);
               }

               if (!(src->ArgusReadingOffLine)) {
                  do {
#if defined(CYGWIN)
                     struct pcap_pkthdr *header;
                     const u_char *pkt_data;

                     if ((tmp = pcap_next_ex(src->ArgusInterface[0].ArgusPd, &header, &pkt_data)) >= 0) {
                        if ( tmp > 0) {
                           src->ArgusThisIndex = 0;
                           src->ArgusInterface[0].ArgusCallBack((char *)src, header, pkt_data);
                        } else
                           gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);

                     } else {
                        gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
                        noerror = 0;
                     }
                     ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;
#else
                     if (notselectable) {
                        int pkts = 0;

                        for (i = 0; i < src->ArgusInterfaces; i++) {
                           int cnt = 0;
                           if (src->ArgusInterface[i].ArgusPd) {
                              src->ArgusThisIndex = i;
                              {
#if defined(HAVE_PCAP_NEXT_EX)
                                 struct pcap_pkthdr *header;
                                 const u_char *pkt_data;
                                 if ((cnt = pcap_next_ex(src->ArgusInterface[i].ArgusPd, &header, &pkt_data)) >= 0) {
                                    if (cnt > 0) {
                                       pkts++;
                                       src->ArgusInterface[i].ArgusCallBack((u_char *)src, header, pkt_data);
                                    } else
                                       break;
                                 } else
                                    noerror = 0;
#else
                                 if ((cnt = pcap_dispatch(src->ArgusInterface[i].ArgusPd, 1, src->ArgusInterface[i].ArgusCallBack, (u_char *)src)) > 0) {
                                    pkts++;
                                 } else {
                                    if (cnt < 0)
                                       noerror = 0;
                                 }
#endif
                              }
                              found++;
                           }
                        }

                        if (pkts == 0) {
                           struct timespec tsbuf = {0, 50000}, *ts = &tsbuf;
                           gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
#if defined(ARGUS_NANOSECONDS)
                           src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
                           ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;
                           nanosleep(ts, NULL);
                        }

                     } else {
                        if (up && ((tmp = select (width + 1, &ArgusReadMask, NULL, NULL, &wait)) >= 0)) {
                           found = 0;
#ifdef ARGUSDEBUG
                           ArgusDebug (10, "ArgusGetPackets: select() returned %d\n", tmp);
#endif
                           if (tmp > 0) {
                              for (i = 0; i < src->ArgusInterfaces; i++) {
                                 if ((fd = fds[i]) != -1) {
                                    if (FD_ISSET(fd, &ArgusReadMask)) {
                                       found++;
                                       src->ArgusThisIndex = i;
                                       switch (src->ArgusInterface[i].ArgusInterfaceType) {
                                          case ARGUSLIBPPKTFILE:
                                             if ((pcap_dispatch (src->ArgusInterface[i].ArgusPd, 1, src->ArgusInterface[i].ArgusCallBack, (u_char *)src)) < 0) {
                                                if (!(strncmp (pcap_geterr(src->ArgusInterface[i].ArgusPd), "recvfrom", 8))) {
#ifdef ARGUSDEBUG
                                                   ArgusDebug (3, "ArgusGetPackets: pcap_dispatch() returned %s\n", pcap_geterr(src->ArgusInterface[i].ArgusPd));
#endif

                                                } else
                                                   noerror = 0;
                                             } else {
#ifdef ARGUSDEBUG
                                                ArgusDebug (9, "ArgusGetPackets: pcap_dispatch() interface %s %d up\n", src->ArgusInterface[i].ArgusDevice, up);
#endif
                                             }
                                             break;
                
                                          case ARGUSERFPKTFILE:
                                             if (ArgusErfRead (src) < 0)
                                                noerror = 0;
                                             break;

                                          case ARGUSSNOOPKTFILE:
                                             if (ArgusSnoopRead (src) < 0)
                                                noerror = 0;
                                             break;

                                          case ARGUSMOATTSHPKTFILE:
                                             if (ArgusMoatTshRead (src) < 0)
                                                noerror = 0;
                                             break;

                                       }
                                       if (src->eNflag > 0)
                                          src->eNflag--;
                                    }
                                 }
                              }

                           } else {
                              gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
#if defined(ARGUS_NANOSECONDS)
                              src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
                              ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;

#if defined(ARGUS_NEEDS_LIBPCAP_WORKAROUND)
/* libpcap workaround */
                              int pkts = 0, cnt, ret;

                              do {
                                 cnt = 0;
                                 for (i = 0; i < src->ArgusInterfaces; i++) {
                                    if ((fd = fds[i]) != -1) {
#if defined(HAVE_PCAP_NEXT_EX)
                                       struct pcap_pkthdr *header;
                                       const u_char *pkt_data;
                                       if ((ret = pcap_next_ex(src->ArgusInterface[i].ArgusPd, &header, &pkt_data)) > 0) {
                                          pkts++;
                                          cnt += ret;
                                          src->ArgusThisIndex = i;
                                          src->ArgusInterface[i].ArgusCallBack((u_char *)src, header, pkt_data);
                                       } else
                                          if (ret < 0)
                                             noerror = 0;
#else
                                       src->ArgusThisIndex = i;
                                       if ((ret = pcap_dispatch(src->ArgusInterface[i].ArgusPd, 1, src->ArgusInterface[i].ArgusCallBack, (u_char *)src)) > 0) {
                                          pkts++;
                                          cnt += ret;
                                       } else {
                                          if (ret < 0)
                                             noerror = 0;
                                       }
#endif
                                    }
                                 }
                              } while (cnt > 0);

                              if (!pkts) {
                                 struct timespec tsbuf = {0, 50000}, *ts = &tsbuf;
                                 nanosleep(ts, NULL);
 
                                 gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
#if defined(ARGUS_NANOSECONDS)
                                 src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
                                 ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;
#ifdef ARGUSDEBUG
                                 ArgusDebug (9, "ArgusGetPackets: select() timeout %d up interfaces\n", up);
#endif
                              }
#endif
                           }

                        } else {
                           gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
#if defined(ARGUS_NANOSECONDS)
                           src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
                           ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;
                           if (up) {
#ifdef ARGUSDEBUG
                              ArgusDebug (3, "ArgusGetPackets: select() returned %s\n", strerror(errno));
#endif
                           } else {
                              struct timespec tsbuf = {0, 250000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
                              ArgusDebug (5, "ArgusGetPackets: no interfaces up: sleeping\n");
#endif
                              nanosleep(ts, NULL);
                           }
                        }
                        width = 0;
                        found = 0;
                        up = 0;
                        FD_ZERO(&ArgusReadMask);

                        for (i = 0; i < src->ArgusInterfaces; i++) {
                           if (src->ArgusInterface[i].ArgusPd && ((fd = pcap_fileno(src->ArgusInterface[i].ArgusPd)) >= 0)) {
                              found++;
                              fds[i] = fd;

                              if (src->ArgusInterface[i].ifr.ifr_flags & IFF_UP) {
                                 up++;
                                 FD_SET(pcap_fileno(src->ArgusInterface[i].ArgusPd), &ArgusReadMask);
                                 if (width < pcap_fileno(src->ArgusInterface[i].ArgusPd))
                                    width = pcap_fileno(src->ArgusInterface[i].ArgusPd);
                              }

                           } else {
                              fds[i] = -1;
                              ArgusOpenInterface(src, NULL, &src->ArgusInterface[i]);
                              found++;
                           }
                        }

                        wait.tv_sec = 0; wait.tv_usec = 500000;
                     }
          #endif  
                     if (ArgusUpdateTime (src->ArgusModel)) {
                        ArgusGetInterfaceStatus(src);
                        ArgusQueueManager(src->ArgusModel);
#if !defined(ARGUS_THREADS)
                        ArgusOutputProcess(ArgusOutputTask);
#endif
                     }

                  } while (noerror && (src->eNflag != 0) && (!(ArgusShutDownStarted)));
               
               } else {
                  extern int ArgusShutDownFlag;
                  long ioffset = 0, offset = 0;

                  ioffset = ftell(src->ArgusPacketInput);
                  offset = ioffset;

                  for (i = 0; i < src->ArgusInterfaces; i++) {
                     int retn = 0;
                     src->ArgusThisIndex = i;

                     if (getArgusfflag(src)) {  // reading the tail of the file, so be ready to sleep if nothing there
                        do {
                           char *estr;

                           if (offset > 0)
                              fseek(src->ArgusPacketInput, offset, SEEK_SET);

                           if ((retn = pcap_dispatch (src->ArgusInterface[i].ArgusPd, 1, src->ArgusInterface[i].ArgusCallBack, (u_char *)src)) < 0) {
                              if ((estr = pcap_geterr(src->ArgusInterface[i].ArgusPd)) != NULL) {
#ifdef ARGUSDEBUG
                                    ArgusDebug (2, "ArgusGetPackets () pcap_dispatch returned %s\n", estr);
#endif
                              }

                           }
                              if (retn > 0) {
                                 if (src->eNflag > 0)
                                    src->eNflag -= retn;
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "ArgusGetPackets () pcap_dispatch read %d packets\n", retn);
#endif
                                 offset = src->ArgusInputOffset;

                              } else {
                                 struct timespec tsbuf = {0, 100000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
                                 ArgusDebug (2, "ArgusGetPackets () pcap_dispatch read 0 packets...sleeping", retn);
#endif
                                 nanosleep(ts, NULL);

                                 gettimeofday (&src->ArgusModel->ArgusGlobalTime, NULL);
#if defined(ARGUS_NANOSECONDS)
                                 src->ArgusModel->ArgusGlobalTime.tv_usec *= 1000;
#endif
                                 ArgusModel->ArgusGlobalTime = src->ArgusModel->ArgusGlobalTime;
                              }

#if !defined(ARGUS_THREADS)
                           ArgusOutputProcess(ArgusOutputTask);
#endif
                        } while (getArgusfflag(src) && (src->eNflag != 0) && !ArgusShutDownFlag);

                     } else {
                        for (i = 0; i < src->ArgusInterfaces; i++) {
                           src->ArgusThisIndex = i;
                           if ((pcap_dispatch (src->ArgusInterface[i].ArgusPd, src->eNflag, src->ArgusInterface[i].ArgusCallBack, (u_char *)src)) < 0) {
                              if (!(strncmp (pcap_geterr(src->ArgusInterface[i].ArgusPd), "recvfrom", 8))) {
                                 ArgusLog (LOG_ERR, "ArgusGetPackets: pcap_dispatch() returned %s\n", pcap_geterr(src->ArgusInterface[i].ArgusPd));
                              }
                           }
#if !defined(ARGUS_THREADS)
                           ArgusOutputProcess(ArgusOutputTask);
#endif
                        }
                     }
                  }
               }
            }
         }
      }

      setArgusFarReportInterval (src->ArgusModel, "0");
      ArgusQueueManager(src->ArgusModel);
#if !defined(ARGUS_THREADS)
      ArgusOutputProcess(ArgusOutputTask);
#endif

      gettimeofday (&src->ArgusEndTime, 0L);
#if defined(ARGUS_NANOSECONDS)
      src->ArgusEndTime.tv_usec *= 1000;
#endif
   }

#if defined(ARGUS_THREADS)
#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGetPackets () returning\n");
#endif

   if (src != NULL) src->status |= ARGUS_SHUTDOWN;
   pthread_exit(retn);
#endif /* ARGUS_THREADS */

   return (retn);
}


void
Argusbpf_dump(struct bpf_program *p, int option)
{
   struct bpf_insn *insn;
   int i, n = p->bf_len;

   insn = p->bf_insns;
   if (option > 2) {
      fprintf(stdout, "%d\n", n);
      for (i = 0; i < n; ++insn, ++i) {
         fprintf(stdout, "%lu %lu %lu %lu\n", (long) insn->code,
                (long) insn->jt, (long) insn->jf, (long) insn->k);
      }
      return;
   }
   if (option > 1) {
      for (i = 0; i < n; ++insn, ++i) {
         fprintf(stdout, "{ 0x%x, %d, %d, 0x%08x },\n",
                insn->code, insn->jt, insn->jf, (int) insn->k);
      }
      return;
   }

   for (i = 0; i < n; ++insn, ++i)
      fprintf (stdout, "%s\n", bpf_image(insn, i));
}




#include <sys/types.h>
#include <sys/stat.h>
#if defined(HAVE_FCNTL_H)
#include <fcntl.h>
#endif
 
#define ARGUSSNOOPTAG  "snoop"
 
int
ArgusOpenInputPacketFile(struct ArgusSourceStruct *src, struct ArgusDeviceStruct *device, struct ArgusInterfaceStruct *inf)
{
   char readbuf[256], errbuf[256];
   int ch, rlen, type;
   int retn = 0;

   if (device != NULL) {
      inf->ArgusDevice = device;

      if (strcmp(device->name, "-")) {
         if ((src->ArgusPacketInput = fopen(device->name, "r")) == NULL) {
            snprintf (errbuf, PCAP_ERRBUF_SIZE - 1, "%s: %s\n", device->name, strerror(errno));
         }
      } else
         src->ArgusPacketInput = stdin;

#if defined(HAVE_PCAP_FOPEN_OFFLINE)
      inf->ArgusPd = pcap_fopen_offline(src->ArgusPacketInput, errbuf);
#else
      inf->ArgusPd = pcap_open_offline(device->name, errbuf);
#endif

      if (inf->ArgusPd != NULL) {
         src->ArgusInputPacketFileType = ARGUSLIBPPKTFILE;
         inf->ArgusInterfaceType = ARGUSLIBPPKTFILE;
         inf->ArgusDevice = (struct ArgusDeviceStruct *) device;
         type = pcap_datalink(inf->ArgusPd);

         if ((inf->ArgusCallBack = Arguslookup_pcap_callback(type)) == NULL)
            ArgusLog(LOG_ERR, "ArgusOpenInputPacketFile(%s) unsupported device type %d\n", device->name, type);

         inf->ArgusLocalNet = 0;
         inf->ArgusNetMask = 0;
         src->ArgusReadingOffLine++;
         retn = 1;

      } else {
         if (strcmp(device->name, "-")) {
            if ((src->ArgusPacketInput = fopen(device->name, "r")) == NULL) {
               snprintf (errbuf, PCAP_ERRBUF_SIZE - 1, "%s: %s\n", device->name, strerror(errno));
            }
         } else
            src->ArgusPacketInput = stdin;

         if (src->ArgusPacketInput) {
            if ((strstr (device->name, ".erf")) != NULL) {
               if ((inf->ArgusPcap.fd = open (device->name, O_RDONLY, NULL)) >= 0) {
                  inf->ArgusPcap.snapshot = 1500;
                  inf->ArgusPcap.linktype = DLT_EN10MB;
                  inf->ArgusInterfaceType = ARGUSERFPKTFILE;
                  src->ArgusInputPacketFileType = ARGUSERFPKTFILE;
                  inf->ArgusDevice = device;
                  src->ArgusReadingOffLine++;
                  retn = 1;
               } else
                  ArgusLog(LOG_ERR, "ArgusOpenInputPacketFile(%s) error. %s\n", device->name, strerror(errno));
            } else
            if (getArgusMoatTshFile(src)) {
               if (src->ArgusPacketInput == stdin) {
                  inf->ArgusPcap.fd = 0;
                  inf->ArgusPcap.snapshot = 1500;
                  inf->ArgusPcap.linktype = DLT_EN10MB;
                  inf->ArgusInterfaceType = ARGUSMOATTSHPKTFILE;
                  src->ArgusInputPacketFileType = ARGUSMOATTSHPKTFILE;
                  inf->ArgusDevice = device;
                  src->ArgusReadingOffLine++;
                  retn = 1;
               } else
               if ((inf->ArgusPcap.fd = open (device->name, O_RDONLY, NULL)) >= 0) {
                  inf->ArgusPcap.snapshot = 1500;
                  inf->ArgusPcap.linktype = DLT_EN10MB;
                  inf->ArgusInterfaceType = ARGUSMOATTSHPKTFILE;
                  src->ArgusInputPacketFileType = ARGUSMOATTSHPKTFILE;
                  inf->ArgusDevice = device;
                  src->ArgusReadingOffLine++;
                  retn = 1;

               } else
                  ArgusLog(LOG_ERR, "ArgusOpenInputPacketFile(%s) error. %s\n", device->name, strerror(errno));
            } else
            if ((ch = fgetc(src->ArgusPacketInput)) != EOF) {
               ungetc(ch, src->ArgusPacketInput);
               if ((rlen = fread ((char *)readbuf, 1, sizeof(ARGUSSNOOPTAG),
                                        src->ArgusPacketInput)) == sizeof(ARGUSSNOOPTAG)) {
                  if ((strncmp((char *)readbuf, ARGUSSNOOPTAG, sizeof(ARGUSSNOOPTAG)) == 0)) {
                     fclose(src->ArgusPacketInput);
                     if ((inf->ArgusPcap.fd = open (device->name, O_RDONLY, NULL)) >= 0) {
                        lseek(inf->ArgusPcap.fd, 16, SEEK_SET);
                        inf->ArgusPcap.snapshot = 1500;
                        inf->ArgusPcap.linktype = DLT_EN10MB;
                        src->ArgusInputPacketFileType = ARGUSSNOOPKTFILE;
                        inf->ArgusDevice = device;
                        src->ArgusReadingOffLine++;
                        retn = 1;
                     }
      
                  } else {
                     snprintf (errbuf, PCAP_ERRBUF_SIZE - 1, "%s, unknown packet file format", device->name);
                  }
               } else {
                  snprintf (errbuf, PCAP_ERRBUF_SIZE - 1, "Error reading %s. Read %d bytes", device->name, rlen);
               }
            } else {
               snprintf (errbuf, PCAP_ERRBUF_SIZE - 1, "Error reading %s. stream empty", device->name);
            }

            inf->ArgusLocalNet = 0;
            inf->ArgusNetMask = 0;
         }

         if (retn == 0)
            ArgusLog (LOG_ALERT, "ArgusOpenInputPacketFile: pcap_open_offline: %s", errbuf);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusOpenInputPacketFile(%p) returning %d\n", errbuf, retn);
#endif
   return (retn);
}


#include <sys/stat.h>
#include <fcntl.h>
#include <net/if.h>
#include <sys/ioctl.h>

int ArgusGetInterfaceFD = -1;

void
ArgusGetInterfaceStatus (struct ArgusSourceStruct *src)
{
   struct ArgusDeviceStruct *device = NULL;
   char errbuf[PCAP_ERRBUF_SIZE];
   struct ifreq ifr;
   int fd, i;

   extern int ArgusShutDownFlag;

   if (ArgusShutDownFlag) {
      ArgusShutDown(0);
      return;
   }

   if (src && src->ArgusDeviceList)
      if ((device = (struct ArgusDeviceStruct *) ArgusPopFrontList(src->ArgusDeviceList, ARGUS_LOCK)) != NULL)
         ArgusPushFrontList(src->ArgusDeviceList, (struct ArgusListRecord *) device, ARGUS_LOCK);

   if (device == NULL)
      return;

   if ((strstr(device->name, "dag")) || (strstr(device->name, "napa")) || 
       (strstr(device->name, "dna")) || (strstr(device->name, "zc"))   ||
      ((strstr(device->name, "eth")) && (strstr(device->name, "@")))) {
      for (i = 0; i < src->ArgusInterfaces; i++) {
         if (src->ArgusInterface[i].ArgusPd)
            bzero ((char *)&src->ArgusInterface[i].ifr, sizeof(ifr));

         src->ArgusInterface[i].ifr.ifr_flags |= IFF_UP;
         setArgusInterfaceStatus(src, 1);
      }
      return;
   }

   if (strstr(device->name, "default")) {
      for (i = 0; i < src->ArgusInterfaces; i++) {
         if (src->ArgusInterface[i].ArgusPd && (pcap_fileno(src->ArgusInterface[i].ArgusPd) > 0))
            bzero ((char *)&src->ArgusInterface[i].ifr, sizeof(ifr));

         src->ArgusInterface[i].ifr.ifr_flags |= IFF_UP;
         setArgusInterfaceStatus(src, 1);
      }
      return;
   }

   if (ArgusGetInterfaceFD < 0)
      if ((ArgusGetInterfaceFD = socket(PF_INET, SOCK_DGRAM, 0)) < 0)
         ArgusLog(LOG_ERR, "ArgusGetInterfaceStatus: socket %s", strerror(errno));

   fd = ArgusGetInterfaceFD;

   for (i = 0; i < src->ArgusInterfaces; i++) {
      if (src->ArgusInterface[i].ArgusPd && (pcap_fileno(src->ArgusInterface[i].ArgusPd) > 0)) {
         memcpy ((char *)&ifr, (char *)&src->ArgusInterface[i].ifr, sizeof(ifr));

#if !defined(CYGWIN)
         if ((ioctl(fd, SIOCGIFFLAGS, (char *)&src->ArgusInterface[i].ifr)) < 0) {
            if (src->ArgusInterface[i].ArgusPd) {
               pcap_close(src->ArgusInterface[i].ArgusPd);
               src->ArgusInterface[i].ArgusPd = NULL;
               return;
            }
         }
#else
         src->ArgusInterface[i].ifr.ifr_flags |= IFF_UP;
         setArgusInterfaceStatus(src, 1);
#endif
         if ((ifr.ifr_flags & IFF_UP) != (src->ArgusInterface[i].ifr.ifr_flags & IFF_UP)) {
            setArgusInterfaceStatus(src, (src->ArgusInterface[i].ifr.ifr_flags & IFF_UP) ? 1 : 0);
 
            if (!((pcap_lookupnet (src->ArgusInterface[i].ArgusDevice->name, 
                         (u_int *)&src->ArgusInterface[i].ArgusLocalNet,
                         (u_int *)&src->ArgusInterface[i].ArgusNetMask, errbuf)) < 0)) {
#if defined(_LITTLE_ENDIAN)
               src->ArgusInterface[i].ArgusLocalNet = ntohl(src->ArgusInterface[i].ArgusLocalNet);
               src->ArgusInterface[i].ArgusNetMask  = ntohl(src->ArgusInterface[i].ArgusNetMask);
#endif
            }
            ArgusLog (LOG_ALERT, "ArgusGetInterfaceStatus: interface %s is %s\n", src->ArgusInterface[i].ifr.ifr_name,
               (src->ArgusInterface[i].ifr.ifr_flags & IFF_UP) ? "up" : "down");
         }

         pcap_stats (src->ArgusInterface[i].ArgusPd, &src->ArgusInterface[i].ArgusStat);
      } else {
      }
   }

   return;
}

int RaSortFileList (const void *, const void *);

int
RaSortFileList (const void *item1, const void *item2)
{
   struct ArgusRfileStruct *file1 = *(struct ArgusRfileStruct **) item1;
   struct ArgusRfileStruct *file2 = *(struct ArgusRfileStruct **) item2;

   return (strcmp (file1->name, file2->name));
}



void
ArgusSortFileList (struct ArgusListStruct *list)
{
   struct ArgusRfileStruct *rfile;
   void **array = NULL;
   int i = 0, count = 0;

   if ((list != NULL) && (count = list->count)) {
      if ((array = ArgusCalloc (count, sizeof(rfile))) == NULL)
         ArgusLog (LOG_ERR, "ArgusSortFileList: ArgusCalloc %s", strerror(errno));

      while ((rfile = (void *)ArgusPopFrontList(list, ARGUS_LOCK)) != NULL)
         array[i++] = rfile;

      if (i != count)
         ArgusLog (LOG_ERR, "ArgusSortFileList: integrity failure");

      qsort (array, i, sizeof(rfile), RaSortFileList);

      for (i = 0; i < count; i++)
         ArgusPushFrontList(list, (struct ArgusListRecord *) array[i], ARGUS_LOCK);

      ArgusFree (array);
   }

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusSortFileList(%p)\n", list);
#endif
}


static int
ArgusParseRadioTapField(struct cpack_state *s, u_int32_t bit, struct ieee80211_radiotap *rtap)
{
   union {
      int8_t      i8;
      u_int8_t    u8;
      int16_t    i16;
      u_int16_t  u16;
      u_int32_t  u32;
      u_int64_t  u64;
   } u, u2, u3, u4;

   int rc;

   switch (bit) {
      case IEEE80211_RADIOTAP_FLAGS:
         rc = cpack_uint8(s, &u.u8);
         break;
      case IEEE80211_RADIOTAP_RATE:
      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
      case IEEE80211_RADIOTAP_DB_ANTNOISE:
      case IEEE80211_RADIOTAP_ANTENNA:
         rc = cpack_uint8(s, &u.u8);
         break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
         rc = cpack_int8(s, &u.i8);
         break;
      case IEEE80211_RADIOTAP_CHANNEL:
         rc = cpack_uint16(s, &u.u16);
         if (rc != 0)
            break;
         rc = cpack_uint16(s, &u2.u16);
         break;
      case IEEE80211_RADIOTAP_FHSS:
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
      case IEEE80211_RADIOTAP_TX_ATTENUATION:
         rc = cpack_uint16(s, &u.u16);
         break;
      case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
         rc = cpack_uint8(s, &u.u8);
         break;
      case IEEE80211_RADIOTAP_DBM_TX_POWER:
         rc = cpack_int8(s, &u.i8);
         break;
      case IEEE80211_RADIOTAP_TSFT:
         rc = cpack_uint64(s, &u.u64);
         break;
      case IEEE80211_RADIOTAP_XCHANNEL:
         rc = cpack_uint32(s, &u.u32);
         if (rc != 0)
            break;
         rc = cpack_uint16(s, &u2.u16);
         if (rc != 0)
            break;
         rc = cpack_uint8(s, &u3.u8);
         if (rc != 0)
            break;
         rc = cpack_uint8(s, &u4.u8);
         break;
      default:
         /* this bit indicates a field whose
          * size we do not know, so we cannot
          * proceed.  Just print the bit number.
          */
         return -1;
   }

   if (rc != 0) 
      return rc;

/*
struct ieee80211_radiotap {
   struct ieee80211_radiotap_header hdr;
   u_int64_t                        tsft;
   u_int16_t                        txchan, rxchan;
   u_int16_t                        fhss;
   u_int8_t                         rate;
   u_int8_t                         dbm_antsignal;
   u_int8_t                         dbm_antnoise;
   u_int8_t                         db_antsignal;
   u_int8_t                         db_antnoise;
   u_int16_t                        lock_quality;
   u_int16_t                        tx_attenuation;
   u_int16_t                        db_tx_attenuation;
   u_int8_t                         dbm_tx_power;
   u_int8_t                         flags;
   u_int8_t                         antenna;
   struct ieee80211_xchannel        xchan;
};
*/

   switch (bit) {
      case IEEE80211_RADIOTAP_TSFT:
         rtap->tsft = u.u64;
         break;
      case IEEE80211_RADIOTAP_CHANNEL:
         break;
      case IEEE80211_RADIOTAP_FHSS:
         rtap->fhss = u.u16;
         break;
      case IEEE80211_RADIOTAP_RATE:
         rtap->rate = u.u8;
         break;
      case IEEE80211_RADIOTAP_DBM_ANTSIGNAL:
         rtap->dbm_antsignal = u.u8;
         break;
      case IEEE80211_RADIOTAP_DBM_ANTNOISE:
         rtap->dbm_antnoise = u.u8;
         break;
      case IEEE80211_RADIOTAP_DB_ANTSIGNAL:
         rtap->db_antsignal = u.u8;
         break;
      case IEEE80211_RADIOTAP_DB_ANTNOISE:
         rtap->db_antnoise = u.u8;
         break;
      case IEEE80211_RADIOTAP_LOCK_QUALITY:
         rtap->lock_quality = u.u16;
         break;
      case IEEE80211_RADIOTAP_TX_ATTENUATION:
         rtap->tx_attenuation = u.u16;
         break;
      case IEEE80211_RADIOTAP_DB_TX_ATTENUATION:
         rtap->db_tx_attenuation = u.u16;
         break;
      case IEEE80211_RADIOTAP_DBM_TX_POWER:
         rtap->dbm_tx_power = u.u8;
         break;
      case IEEE80211_RADIOTAP_FLAGS:
         rtap->flags = u.u8;
         break;
      case IEEE80211_RADIOTAP_ANTENNA:
         rtap->antenna = u.u8;
         break;
      case IEEE80211_RADIOTAP_XCHANNEL:
         break;
   }

   return 0;
}

/*-
 * Copyright (c) 2003, 2004 David Young.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of David Young may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY DAVID YOUNG ``AS IS'' AND ANY
 * EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A
 * PARTICULAR PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL DAVID
 * YOUNG BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED
 * TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
 * ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY
 * OF SUCH DAMAGE.
 */

#include <stdlib.h>
#include <string.h>

static u_int8_t *
cpack_next_boundary(u_int8_t *buf, u_int8_t *p, size_t alignment)
{
	size_t misalignment = (size_t)(p - buf) % alignment;

	if (misalignment == 0)
		return p;

	return p + (alignment - misalignment);
}

/* Advance to the next wordsize boundary. Return NULL if fewer than
 * wordsize bytes remain in the buffer after the boundary.  Otherwise,
 * return a pointer to the boundary.
 */
static u_int8_t *
cpack_align_and_reserve(struct cpack_state *cs, size_t wordsize)
{
	u_int8_t *next;

	/* Ensure alignment. */
	next = cpack_next_boundary(cs->c_buf, cs->c_next, wordsize);

	/* Too little space for wordsize bytes? */
	if (next - cs->c_buf + wordsize > cs->c_len)
		return NULL;

	return next;
}

int
cpack_init(struct cpack_state *cs, u_int8_t *buf, size_t buflen)
{
	memset(cs, 0, sizeof(*cs));

	cs->c_buf = buf;
	cs->c_len = buflen;
	cs->c_next = cs->c_buf;

	return 0;
}

/* Unpack a 64-bit unsigned integer. */
int
cpack_uint64(struct cpack_state *cs, u_int64_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_64BITS(next);

	/* Move pointer past the u_int64_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 32-bit unsigned integer. */
int
cpack_uint32(struct cpack_state *cs, u_int32_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_32BITS(next);

	/* Move pointer past the u_int32_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack a 16-bit unsigned integer. */
int
cpack_uint16(struct cpack_state *cs, u_int16_t *u)
{
	u_int8_t *next;

	if ((next = cpack_align_and_reserve(cs, sizeof(*u))) == NULL)
		return -1;

	*u = EXTRACT_LE_16BITS(next);

	/* Move pointer past the u_int16_t. */
	cs->c_next = next + sizeof(*u);
	return 0;
}

/* Unpack an 8-bit unsigned integer. */
int
cpack_uint8(struct cpack_state *cs, u_int8_t *u)
{
	/* No space left? */
	if ((size_t)(cs->c_next - cs->c_buf) >= cs->c_len)
		return -1;

	*u = *cs->c_next;

	/* Move pointer past the u_int8_t. */
	cs->c_next++;
	return 0;
}
