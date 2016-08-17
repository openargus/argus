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
 * $Id: //depot/argus/argus/argus/ArgusOutput.c#81 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusOutput)
#define ArgusOutput
#endif

#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <math.h>

#if defined(HAVE_ZLIB_H)
#include <zlib.h>
#endif
 
#include <argus.h>
#include <argus_parser.h>
#include <argus_filter.h>

#if defined(ARGUS_THREADS)
#include <pthread.h>
#endif

void *ArgusOutputProcess(void *);

#if defined(ARGUS_TILERA)
extern int ArgusFirstTile;
#endif

struct timeval *getArgusMarReportInterval(struct ArgusOutputStruct *);
void setArgusMarReportInterval(struct ArgusOutputStruct *, char *);

struct ArgusRecord *ArgusGenerateInitialMar (struct ArgusOutputStruct *);
struct ArgusRecordStruct *ArgusGenerateSupplementalMarRecord (struct ArgusOutputStruct *, unsigned char);
struct ArgusRecordStruct *ArgusGenerateStatusMarRecord (struct ArgusOutputStruct *, unsigned char);

int RaDiffTime (struct timeval *, struct timeval *, struct timeval *);

struct ArgusOutputStruct *
ArgusNewOutput (struct ArgusSourceStruct *src, struct ArgusModelerStruct *model)
{
   struct ArgusOutputStruct *retn = NULL;

   if ((retn = (struct ArgusOutputStruct *) ArgusCalloc (1, sizeof (struct ArgusOutputStruct))) == NULL)
     ArgusLog (LOG_ERR, "ArgusNewOutput() ArgusCalloc error %s\n", strerror(errno));

   gettimeofday (&retn->ArgusGlobalTime, 0L);
#if defined(ARGUS_NANOSECONDS)
   retn->ArgusGlobalTime.tv_usec *= 1000;
#endif
   retn->ArgusStartTime = retn->ArgusGlobalTime;

   retn->ArgusReportTime.tv_sec   = retn->ArgusGlobalTime.tv_sec + retn->ArgusMarReportInterval.tv_sec;
   retn->ArgusReportTime.tv_usec += retn->ArgusMarReportInterval.tv_usec;
   retn->ArgusLastMarUpdateTime   = retn->ArgusGlobalTime;

   if ((retn->ArgusClients = ArgusNewQueue()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewOutput: clients queue %s", strerror(errno));

   if ((retn->ArgusOutputList = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewOutput: ArgusNewList %s", strerror(errno));

   if ((retn->ArgusInputList = ArgusNewList()) == NULL)
      ArgusLog (LOG_ERR, "ArgusNewOutput: ArgusNewList %s", strerror(errno));

   retn->ArgusSrc   = src;
   retn->ArgusModel = model;

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&retn->lock, NULL);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusNewOutput() returning retn %p\n", retn);
#endif

   return (retn);
}


#ifdef ARGUS_SASL
int iptostring(const struct sockaddr *, socklen_t, char *, unsigned);

static int
ArgusSaslLog (void *context __attribute__((unused)), int priority, const char *message)
{
  const char *label;

  if (! message)
    return SASL_BADPARAM;

  switch (priority) {
     case SASL_LOG_ERR:  label = "Error"; break;
     case SASL_LOG_NOTE: label = "Info"; break;
     default:            label = "Other"; break;
  }

#ifdef ARGUSDEBUG
  ArgusDebug(1, "ArgusSaslLog %s: %s", label, message);
#endif 

  return SASL_OK;
}

//#ifdef _LP64
//#define PLUGINDIR "/usr/lib64/sasl2"
//#else

#define PLUGINDIR "/usr/lib/sasl2"

//#endif


char *searchpath = NULL;

static int
ArgusSaslGetPath(void *context __attribute__((unused)), char ** path)
{
  if (! path)
    return SASL_BADPARAM;
  if (searchpath)
    *path = searchpath;
   else 
    *path = PLUGINDIR;

#ifdef ARGUSDEBUG
  ArgusDebug(2, "SASL path %s", *path);
#endif

  return SASL_OK;
}

//typedef struct sasl_callback {
//    /* Identifies the type of the callback function.
//     * Mechanisms must ignore callbacks with id's they don't recognize.
//     */
//    unsigned long id;
//    int (*proc)(void);   /* Callback function.  Types of arguments vary by 'id' */
//    void *context;
//} sasl_callback_t;

typedef int (*funcptr)();

static const struct sasl_callback argus_cb[] = {
    { SASL_CB_LOG, (funcptr)&ArgusSaslLog, NULL },
    { SASL_CB_LIST_END, NULL, NULL }
};
#endif

void
ArgusInitOutput (struct ArgusOutputStruct *output)
{
   struct ArgusWfileStruct *wfile;
   extern char *chroot_dir;
   extern uid_t new_uid;
   extern gid_t new_gid;
   int i, len = 0, retn = 0;

#if defined(ARGUS_THREADS)
   extern pthread_attr_t *ArgusAttr;
#endif

   ArgusParser = ArgusNewParser(ArgusProgramName);

   if (output->ArgusInitMar != NULL)
      ArgusFree (output->ArgusInitMar);

   if ((output->ArgusInitMar = ArgusGenerateInitialMar(output)) == NULL)
      ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusGenerateInitialMar error %s", strerror(errno));

   len = ntohs(output->ArgusInitMar->hdr.len) * 4;

   for (i = 0; i < ARGUS_MAXLISTEN; i++)
      output->ArgusLfd[i] = -1;

   if (output->ArgusPortNum != 0) {
      char errbuf[256];
      if (ArgusEstablishListen (output, errbuf) < 0)
         ArgusLog (LOG_ERR, "%s", errbuf);
   }

   if (chroot_dir != NULL)
      ArgusSetChroot(chroot_dir);

   if (new_gid > 0) {
      if (setegid(new_gid) < 0)
         ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));
   }
   if (new_uid > 0) {
      if (seteuid(new_uid) < 0)
         ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));
   }

   if (output->ArgusWfileList) {
      struct ArgusListRecord *sfile= output->ArgusWfileList->start->obj;
      do {
         if ((wfile = (struct ArgusWfileStruct *) ArgusPopFrontList(output->ArgusWfileList, ARGUS_LOCK)) != NULL) {
            struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

            if (client == NULL)
               ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusCalloc %s", strerror(errno));

            if (strcmp (wfile->filename, "-")) {
               if ((!(strncmp (wfile->filename, "argus-udp://", 12))) ||
                   (!(strncmp (wfile->filename, "udp://", 6)))) {

                  char *baddr = strstr (wfile->filename, "udp://");
                  baddr = &baddr[6];

#if defined(HAVE_GETADDRINFO)
                  struct addrinfo hints, *hp = NULL, *bhp = NULL;
                  int retn = 0, numerichost = 1;
                  char *port, *ptr;

                  if ((port = strchr(baddr, ':')) != NULL) {
                     *port++ = '\0';
                  } else {
                     port = "561";
                  }

                  if (output->ArgusBindAddrs || output->ArgusBindPort) {
                     char *ArgusBindAddr = NULL;

                     memset(&hints, 0, sizeof(hints));
                     hints.ai_family   = AF_INET;
                     hints.ai_socktype = SOCK_DGRAM;
                     hints.ai_protocol = IPPROTO_UDP;
                     hints.ai_flags   |= AI_PASSIVE;

                     if (ArgusBindAddr && (!strcmp(ArgusBindAddr, "any")))
                        ArgusBindAddr = NULL;
                     getaddrinfo(ArgusBindAddr, output->ArgusBindPort, NULL, &bhp);
                  }

                  memset(&hints, 0, sizeof(hints));
                  hints.ai_family   = AF_INET;
                  hints.ai_socktype = SOCK_DGRAM;
                  hints.ai_protocol = IPPROTO_UDP;

                  for (ptr = port; *ptr != '\0'; ptr++) {
                     int c = *ptr;
                     if (!isdigit(c))
                        numerichost = 0;
                  }
#if defined(AI_NUMERICHOST)
                  if (numerichost)
                     hints.ai_flags |= AI_NUMERICHOST;
#endif
                  if ((retn = getaddrinfo(baddr, port, &hints, &client->host)) != 0) {
                     switch (retn) {
                        case EAI_AGAIN:
                           ArgusLog(LOG_ERR, "dns server not available");
                           break;
                        case EAI_NONAME:
                           ArgusLog(LOG_ERR, "bind address %s unknown", optarg);
                           break;
#if defined(EAI_ADDRFAMILY)
                        case EAI_ADDRFAMILY:
                           ArgusLog(LOG_ERR, "bind address %s has no IP address", optarg);
                           break;
#endif
                        case EAI_SYSTEM:
                           ArgusLog(LOG_ERR, "bind address %s name server error %s", optarg, strerror(errno));
                           break;
                     }
                  }

                  hp = client->host;

                  do {
                     if ((client->fd = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol)) >= 0) {
                        unsigned char ttl = 128;
                        int ttl_size = sizeof(ttl);

                        if (setsockopt(client->fd, IPPROTO_IP, IP_MULTICAST_TTL, &ttl, ttl_size) < 0)
                           ArgusLog (LOG_INFO, "ArgusInitOutput: setsockopt set multicast TTL: %s", strerror(errno));

                        if (bhp != NULL) {
#if defined(SO_REUSEPORT)
                           int on = 1;
#endif
                           if (bind (client->fd, bhp->ai_addr, sizeof(struct sockaddr_in)) < 0)
                              ArgusLog (LOG_ERR, "ArgusInitOutput: bind %s", strerror(errno));
#if defined(SO_REUSEPORT)
                           if (setsockopt(client->fd, SOL_SOCKET, SO_REUSEPORT, &on, sizeof(on)) < 0)
                              ArgusLog (LOG_INFO, "ArgusInitOutput: setsockopt set reuseport %s", strerror(errno));
#endif
                        }

                     } else
                        ArgusLog (LOG_ERR, "ArgusInitOutput: socket %s: %s", wfile->filename, strerror(errno));
                     hp = hp->ai_next;
                  } while (hp != NULL);
#endif
               } else
                  if ((client->fd = open (wfile->filename, O_WRONLY|O_APPEND|O_CREAT|O_NONBLOCK, 0x1a4)) < 0)
                     ArgusLog (LOG_ERR, "ArgusInitOutput: open %s: %s", wfile->filename, strerror(errno));
            } else {
               client->fd = 1;
               output->ArgusWriteStdOut++;
            }

            if (wfile->filter != NULL) {
               if (ArgusFilterCompile (&client->ArgusNFFcode, wfile->filter, 1) < 0) 
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusFilter syntax error: %s", wfile->filter);
               client->ArgusFilterInitialized++;
#ifdef ARGUSDEBUG
               {
                  char buf[MAXSTRLEN];
                  bzero(buf, MAXSTRLEN);
                  nff_dump(&client->ArgusNFFcode, buf, MAXSTRLEN, 1);
                  ArgusDebug (5, "ArgusInitOutput: ArgusFilterCompile returned: \n%s\n", buf);
               }
#endif
            }

            if ((client->sock = ArgusNewSocket(client->fd)) == NULL)
               ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusNewSocket error %s", strerror(errno));

            if (client->host != NULL) {
               if ((retn = sendto(client->fd, (char *) output->ArgusInitMar, len, 0, client->host->ai_addr, client->host->ai_addrlen)) < 0)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: sendto(): retn %d %s", retn, strerror(errno));

            } else {
               while ((retn = write (client->fd, (char *) output->ArgusInitMar, len)) != len) {
                  if (!output->ArgusWriteStdOut) {
                     close (client->fd);
                     unlink (wfile->filename);
                  }
                  ArgusLog (LOG_ERR, "ArgusInitOutput: write(): retn %d %s", retn, strerror(errno));
               }
            }

            if (strcmp(wfile->filename, "/dev/null"))
               client->sock->filename = strdup(wfile->filename);

            ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK);

            client->ArgusClientStart++;
            ArgusPushBackList (output->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_LOCK);
         }
      } while (output->ArgusWfileList->start->obj != sfile);

      ArgusDeleteList(output->ArgusWfileList, ARGUS_WFILE_LIST);
      output->ArgusWfileList = NULL;
   }

   if (new_gid > 0)
      if (setegid(ArgusGid) < 0)
         ArgusLog (LOG_ERR, "ArgusInitOutput: setgid error %s", strerror(errno));

   if (new_uid > 0) 
      if (seteuid(ArgusUid) < 0)
         ArgusLog (LOG_ERR, "ArgusInitOutput: setuid error %s", strerror(errno));

#ifdef ARGUS_SASL
   if ((retn = sasl_server_init(argus_cb, ArgusProgramName)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitOutput() sasl_server_init failed %d\n", retn);
#endif /* ARGUS_SASL */

#if defined(ARGUS_THREADS)
   if ((pthread_create(&output->thread, ArgusAttr, ArgusOutputProcess, (void *) output)) != 0)
      ArgusLog (LOG_ERR, "ArgusInitOutput() pthread_create error %s\n", strerror(errno));

#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusInitOutput() done");
#endif
}


void
ArgusCloseOutput(struct ArgusOutputStruct *output)
{
#if defined(ARGUS_THREADS)
   void *retn = NULL;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCloseOutput(%p) scheduling closure after %d records\n", output, output->ArgusInputList->count);
#endif
   if ((output != NULL) && (output->thread != 0)) {
      output->status |= ARGUS_SHUTDOWN;
      if (output->thread)
         pthread_join(output->thread, &retn);
   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (4, "ArgusCloseOutput(%p) no output or output->thread available\n", output);
#endif
   }
#else
   if (output != NULL) {
      output->status |= ARGUS_SHUTDOWN;
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusCloseOutput(%p) scheduling closure after writing records\n", output);
#endif
      ArgusOutputProcess(output);
   }
#endif /* ARGUS_THREADS */

   ArgusDeleteList(output->ArgusInputList, ARGUS_OUTPUT_LIST);
   ArgusDeleteList(output->ArgusOutputList, ARGUS_OUTPUT_LIST);

   ArgusDeleteQueue(output->ArgusClients);

   if (output->ArgusInitMar != NULL)
      ArgusFree (output->ArgusInitMar);

   if (ArgusParser != NULL) {
      ArgusCloseParser(ArgusParser);
      ArgusFree(ArgusParser);
      ArgusParser = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCloseOutput(%p) done\n", output);
#endif
}


void ArgusCheckClientStatus (struct ArgusOutputStruct *, int);
int ArgusCheckClientMessage (struct ArgusOutputStruct *, struct ArgusClientData *);
int ArgusCongested = 0;

int ArgusOutputStatusTime(struct ArgusOutputStruct *);

int
ArgusOutputStatusTime(struct ArgusOutputStruct *output)
{
   int retn = 0;


   if ((output->ArgusReportTime.tv_sec  < output->ArgusGlobalTime.tv_sec) ||
      ((output->ArgusReportTime.tv_sec == output->ArgusGlobalTime.tv_sec) &&
       (output->ArgusReportTime.tv_usec < output->ArgusGlobalTime.tv_usec))) {

      long long dtime = ArgusTimeDiff(&output->ArgusGlobalTime, &output->ArgusReportTime);

      if (dtime > 1000000)
         output->ArgusReportTime  = output->ArgusGlobalTime;

      output->ArgusReportTime.tv_sec  += getArgusMarReportInterval(output)->tv_sec;
      output->ArgusReportTime.tv_usec += getArgusMarReportInterval(output)->tv_usec;

      if (output->ArgusReportTime.tv_usec > ARGUS_FRACTION_TIME) {
         output->ArgusReportTime.tv_sec++;
         output->ArgusReportTime.tv_usec -= ARGUS_FRACTION_TIME;
      }

      retn++;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (7, "ArgusOutputStatusTime(%p) done", output);
#endif
   return (retn);
}



void *
ArgusOutputProcess(void *arg)
{
   struct ArgusOutputStruct *output = (struct ArgusOutputStruct *) arg;
   struct timeval ArgusUpDate = {0, 500000}, ArgusNextUpdate = {0,0};
   struct ArgusListStruct *list = NULL;
   int val, count;
   void *retn = NULL;

#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
#if defined(ARGUS_THREADS)
   ArgusDebug (1, "ArgusOutputProcess(%p) starting\n", output);
#else
   ArgusDebug (6, "ArgusOutputProcess(%p) starting\n", output);
#endif
#endif

#if defined(ARGUS_TILERA)
   bind_proc(ArgusFirstTile + 1);
#endif

#if defined(ARGUS_THREADS)
   sigfillset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);

#if defined(HAVE_SOLARIS)
   sigignore(SIGPIPE);
#else
   (void) signal (SIGPIPE, SIG_IGN);
#endif

   while ((list = output->ArgusInputList) == NULL) {
      struct timespec tsbuf = {0, 10000000}, *ts = &tsbuf;
#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusOutputProcess(%p) waiting for ArgusOutputList\n", output);
#endif
      nanosleep (ts, NULL);
   }

   while (!(output->status & ARGUS_SHUTDOWN) || ((output->status & ARGUS_SHUTDOWN) && !ArgusListEmpty(list))) {
#else
      if ((list = output->ArgusInputList) != NULL) {
#endif
         struct ArgusRecordStruct *rec = NULL;

         gettimeofday (&output->ArgusGlobalTime, 0L);
#if defined(ARGUS_NANOSECONDS)
         output->ArgusGlobalTime.tv_usec *= 1000;
#endif
#ifdef ARGUSDEBUG
         ArgusDebug (6, "ArgusOutputProcess() looping\n");
#endif

    /* check to see if there are any new clients */
         
         if ((output->ArgusPortNum != 0) &&
            ((output->ArgusGlobalTime.tv_sec >  ArgusNextUpdate.tv_sec) ||
            ((output->ArgusGlobalTime.tv_sec == ArgusNextUpdate.tv_sec) &&
             (output->ArgusGlobalTime.tv_usec > ArgusNextUpdate.tv_usec)))) {
         
            if (output->ArgusListens) {
               struct timeval wait = {0, 0}; 
               fd_set readmask;
               int i, width = 0;

               FD_ZERO(&readmask);

               for (i = 0; i < output->ArgusListens; i++) {
                  if (output->ArgusLfd[i] != -1) {
                     FD_SET(output->ArgusLfd[i], &readmask);
                     width = (output->ArgusLfd[i] > width) ? output->ArgusLfd[i] : width;
                  }
               }

               if (output->ArgusClients) {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusOutputProcess() checking for remotes\n");
#endif
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;

                     do {
                        if (client->sock && !(client->sock->filename)) {
                           FD_SET(client->fd, &readmask);
                           width = (client->fd > width) ? client->fd : width;
                        }
                        client = (void *) client->qhdr.nxt;
                     } while (client != (void *)output->ArgusClients->start);
                  }

                  if ((val = select (width + 1, &readmask, NULL, NULL, &wait)) >= 0) {
                     if (val > 0) {
                        struct ArgusClientData *client = (void *)output->ArgusClients->start;
                        int done = 0;
#ifdef ARGUSDEBUG
                        ArgusDebug (6, "ArgusOutputProcess() select returned with tasks\n");
#endif
                        for (i = 0; (i < output->ArgusListens) && (!done); i++) {
                           if (FD_ISSET(output->ArgusLfd[i], &readmask))
                              ArgusCheckClientStatus(output, output->ArgusLfd[i]);

                           if (client != NULL) {
                              do {
                                 if (client->fd != -1) {
                                    if (FD_ISSET(client->fd, &readmask)) {
                                       if (ArgusCheckClientMessage(output, client) < 0) {
                                          ArgusDeleteSocket(output, client);
                                       } else {
                                          done++;
                                          break;
                                       }
                                    }
                                 }
                                 client = (void *) client->qhdr.nxt;
                              } while (client != (void *)output->ArgusClients->start);
                           }
                        }
                     }
                  }

#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusOutputProcess() done checking for remotes\n");
#endif
               }

               ArgusNextUpdate.tv_usec += ArgusUpDate.tv_usec;
               ArgusNextUpdate.tv_sec  += ArgusUpDate.tv_sec;

               if (ArgusNextUpdate.tv_usec > ARGUS_FRACTION_TIME) {
                  ArgusNextUpdate.tv_sec++;
                  ArgusNextUpdate.tv_usec -= ARGUS_FRACTION_TIME;
               }
            }
         }

#if defined(ARGUS_THREADS)
         if (ArgusListEmpty(list)) {
            struct timeval tvp;
            struct timespec tsbuf, *ts = &tsbuf;
            gettimeofday (&tvp, 0L);
            ts->tv_sec = tvp.tv_sec + 0;
            ts->tv_nsec = tvp.tv_usec * 1000;
            ts->tv_nsec += 100000000;
            while (ts->tv_nsec > 1000000000) {
               ts->tv_sec++; 
               ts->tv_nsec -= 1000000000;
            }
#ifdef ARGUSDEBUG
            ArgusDebug (6, "ArgusOutputProcess() waiting for input list\n");
#endif
            if (pthread_mutex_lock(&list->lock)) {
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusOutputProcess() pthread_mutex_lock error %s\n", strerror(errno));
#endif
            }

            if (pthread_cond_timedwait(&list->cond, &list->lock, ts) == EINVAL) {
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusOutputProcess() pthread_cond_timedwait error bad value\n");
#endif
            }

            if (pthread_mutex_unlock(&list->lock)) {
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusOutputProcess() pthread_mutex_lock error %s\n", strerror(errno));
#endif
            }
         }
#endif

         if (ArgusOutputStatusTime(output)) {
            if ((rec = ArgusGenerateStatusMarRecord(output, ARGUS_STATUS)) != NULL) {
               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     do {
                        if ((client->fd != -1) && (client->sock != NULL) && client->ArgusClientStart) {
                           if (ArgusWriteSocket (output, client, rec) < 0) {
                              ArgusDeleteSocket(output, client);
                           }
                        }
                        client = (void *) client->qhdr.nxt;
                     } while (client != (void *)output->ArgusClients->start);
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               }
               ArgusFreeListRecord (rec);
               output->ArgusLastMarUpdateTime   = output->ArgusGlobalTime;
            }
         }

         if (output->ArgusOutputList && !(ArgusListEmpty(list))) {
            int done = 0;
            ArgusLoadList(list, output->ArgusOutputList);

            while (!done && ((rec = (struct ArgusRecordStruct *) ArgusPopFrontList(output->ArgusOutputList, ARGUS_LOCK)) != NULL)) {
               output->ArgusTotalRecords++;
               output->ArgusOutputSequence = rec->canon.trans.seqnum;
               count = 0;
#ifdef ARGUSDEBUG
               ArgusDebug (6, "ArgusOutputProcess() received rec %p totals %lld seq %d\n", rec, output->ArgusTotalRecords, output->ArgusOutputSequence);
#endif
               if (((rec->hdr.type & 0xF0) == ARGUS_MAR) && ((rec->hdr.cause & 0xF0) == ARGUS_STOP)) {
                  done++;
                  output->status |= ARGUS_SHUTDOWN;
                  ArgusFreeListRecord(rec);
                  if ((rec = ArgusGenerateStatusMarRecord(output, ARGUS_STOP)) == NULL) {
                  }
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusOutputProcess(%p) rec %d received as stop record \n", output, output->ArgusTotalRecords);
#endif
               }

               if (output->ArgusClients) {
#if defined(ARGUS_THREADS)
                  pthread_mutex_lock(&output->ArgusClients->lock);
#endif
                  if (output->ArgusClients->count) {
                     struct ArgusClientData *client = (void *)output->ArgusClients->start;
                     int i, ArgusWriteRecord = 0;
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusOutputProcess() %d client(s) for record %p\n", output->ArgusClients->count, rec);
#endif
                     for (i = 0; i < output->ArgusClients->count; i++) {
                        if ((client->fd != -1) && (client->sock != NULL) && client->ArgusClientStart) {
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusOutputProcess() client %p ready fd %d sock %p start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           ArgusWriteRecord = 1;
                           if (client->ArgusFilterInitialized) {
                              bcopy(&rec->hdr, &rec->canon.hdr, sizeof(rec->hdr));
                              if (!(ArgusFilterRecord ((struct nff_insn *)client->ArgusNFFcode.bf_insns, rec)))
                                 ArgusWriteRecord = 0;
                           }

                           if (ArgusWriteRecord) {
                              if (ArgusWriteSocket (output, client, rec) < 0) {
                                 ArgusDeleteSocket(output, client);
                              } else {
                                 if (ArgusWriteOutSocket (output, client) < 0) {
                                    ArgusDeleteSocket(output, client);
                                 }
                              }
                           } else {
#ifdef ARGUSDEBUG
                              ArgusDebug (5, "ArgusOutputProcess() client %p filter blocks fd %d sock %p start %d", client, client->fd, client->sock, client->ArgusClientStart);
#endif
                           }

                        } else {
                           struct timeval tvbuf, *tvp = &tvbuf;
#ifdef ARGUSDEBUG
                           ArgusDebug (5, "ArgusOutputProcess() %d client(s) not ready fd %d sock 0x%x start %d", output->ArgusClients->count, client->fd, client->sock, client->ArgusClientStart);
#endif
                           RaDiffTime (&output->ArgusGlobalTime, &client->startime, tvp);
                           if (tvp->tv_sec >= ARGUS_CLIENT_STARTUP_TIMEOUT) {
                              if (client->sock != NULL) {
                                 ArgusDeleteSocket(output, client);
                                 ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: client %s never started: timed out", 
                                    (client->hostname != NULL) ? client->hostname : "noname");
                              }
                              client->ArgusClientStart = 1;
                           }
                        }
                        client = (void *) client->qhdr.nxt;
                     }
                  }
#if defined(ARGUS_THREADS)
                  pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (5, "ArgusOutputProcess() no client for record %p\n", rec);
#endif
               }
               ArgusFreeListRecord(rec);
            }

            if (output->ArgusWriteStdOut)
               fflush (stdout);
         }
#ifdef ARGUSDEBUG
         ArgusDebug (6, "ArgusOutputProcess() checking out clients\n");
#endif
#if defined(ARGUS_THREADS)
         pthread_mutex_lock(&output->ArgusClients->lock);
#endif
         if ((output->ArgusPortNum != 0) && (output->ArgusClients->count)) {
            struct ArgusClientData *client = (void *)output->ArgusClients->start;
            int i;

            for (i = 0; i < output->ArgusClients->count; i++) {
               if ((client->fd != -1) && (client->sock != NULL)) {
                  if (output->status & ARGUS_SHUTDOWN) {
                     ArgusWriteOutSocket (output, client);
                     ArgusDeleteSocket(output, client);
                  } else {
                     if (ArgusWriteOutSocket (output, client) < 0) {
                        ArgusDeleteSocket(output, client);
                     }
                  }
               }
               client = (void *) client->qhdr.nxt;
            }

            for (i = 0, count = output->ArgusClients->count; (i < count) && output->ArgusClients->count; i++) {
               if ((client->fd == -1) && (client->sock == NULL) && client->ArgusClientStart) {
                  if (ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK) != NULL)
                     ArgusFree(client);
                  i = 0; count = output->ArgusClients->count;
                  client = (void *)output->ArgusClients->start;
               } else
                  client = (void *)client->qhdr.nxt;
            }
         }

#if defined(ARGUS_THREADS)
         pthread_mutex_unlock(&output->ArgusClients->lock);
#endif
#ifdef ARGUSDEBUG
         ArgusDebug (6, "ArgusOutputProcess() done with clients\n");
#endif

#if !defined(ARGUS_THREADS)
      }
#else
   }
#endif /* ARGUS_THREADS */

#ifdef ARGUSDEBUG
#if defined(ARGUS_THREADS)
   ArgusDebug (6, "ArgusOutputProcess(%p) shuting down %d\n", output, output->ArgusInputList->count);
#else
   ArgusDebug (6, "ArgusOutputProcess(%p) done count %d\n", output, output->ArgusInputList->count);
#endif /* ARGUS_THREADS */
#endif

#if defined(ARGUS_THREADS)
   {
      struct ArgusClientData *client;
      while ((client = (void *) output->ArgusClients->start) != NULL) {
         if ((client->fd != -1) && (client->sock != NULL))
            ArgusWriteOutSocket (output, client);

         ArgusDeleteSocket(output, client);
         if (ArgusRemoveFromQueue(output->ArgusClients, &client->qhdr, ARGUS_LOCK) != NULL)
            ArgusFree(client);
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusOutputProcess(%p) exiting\n", output);
#endif
   pthread_exit(retn);
#endif /* ARGUS_THREADS */

   return (retn);
}


#include <netdb.h>

int
ArgusEstablishListen (struct ArgusOutputStruct *output, char *errbuf)
{
   int port = output->ArgusPortNum;
   struct ArgusBindAddrStruct *ArgusBindAddrs = NULL;
   char *baddr = NULL;
   int s = -1;

   if (port > 0) {
      if (output->ArgusListens > 0) {
         int i = output->ArgusListens;
         for (i = 0; i < output->ArgusListens; i++) {
            close(output->ArgusLfd[i]);
            output->ArgusLfd[i] = -1;
         }
      }
      output->ArgusListens = 0;

      if (output->ArgusBindAddrs != NULL) {
         ArgusBindAddrs = (struct ArgusBindAddrStruct *)output->ArgusBindAddrs->start;
         baddr = ArgusBindAddrs->addr;
      }

      do {
#if defined(HAVE_GETADDRINFO)
         {
            struct addrinfo hints, *host, *hp;
            char portbuf[32];
            int retn = 0;

            memset(&hints, 0, sizeof(hints));
            if (output->ArgusAddrInfo.ai_socktype || output->ArgusAddrInfo.ai_protocol) {
               hints.ai_family   = output->ArgusAddrInfo.ai_family;
               hints.ai_socktype = output->ArgusAddrInfo.ai_socktype;
               hints.ai_protocol = output->ArgusAddrInfo.ai_protocol;
            } else {
               hints.ai_family   = PF_UNSPEC;
               hints.ai_socktype = SOCK_STREAM;
               hints.ai_protocol = IPPROTO_TCP;
               hints.ai_flags    = AI_PASSIVE;
            }

            snprintf(portbuf, 32, "%d", port);

            if ((retn = getaddrinfo(baddr, portbuf, &hints, &host)) != 0) {
               switch (retn) {
                  case EAI_AGAIN:
                     ArgusLog(LOG_ERR, "dns server not available");
                     break;
                  case EAI_NONAME:
                     ArgusLog(LOG_ERR, "bind address %s unknown", optarg);
                     break;
#if defined(EAI_ADDRFAMILY)
                  case EAI_ADDRFAMILY:
                     ArgusLog(LOG_ERR, "bind address %s has no IP address", optarg);
                     break;
#endif
                  case EAI_SYSTEM:
                     ArgusLog(LOG_ERR, "bind address %s name server error %s", optarg, strerror(errno));
                     break;
               }
            }

            hp = host;

            do {
               retn = -1;
               if ((s = socket (hp->ai_family, hp->ai_socktype, hp->ai_protocol)) >= 0) {
                  int flags = fcntl (s, F_GETFL, 0L);
                  if ((fcntl (s, F_SETFL, flags | O_NDELAY)) >= 0) {
                     int on = 1;
                     if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
                        ArgusLog (LOG_INFO, "ArgusInitOutput: setsockopt set reuseaddr %s", strerror(errno));
#ifdef ARGUSDEBUG
                     if (baddr)
                        ArgusDebug (1, "ArgusEstablishListen(%p, %p) binding: %s:%d family: %d\n", output, errbuf, baddr, port, hp->ai_family);
                     else {
#if defined(__OpenBSD__)
                        switch (hp->ai_family) {
                           case AF_INET6: ((struct sockaddr_in6 *)hp->ai_addr)->sin6_addr = in6addr_any; break;
                        }
#endif
                        ArgusDebug (1, "ArgusEstablishListen(%d, %p) binding: any:%d family: %d\n", port, errbuf, port, hp->ai_family);
                     }
#endif

                     if (!(bind (s, hp->ai_addr, hp->ai_addrlen))) {
                        switch (hp->ai_socktype) {
                           case SOCK_STREAM:
                              if ((retn = listen (s, ARGUS_MAXLISTEN)) >= 0) {
                                 output->ArgusLfd[output->ArgusListens++] = s;
                              } else {
                                 snprintf(errbuf, 1024, "%s: ArgusEstablishListen: listen() failure", ArgusProgramName);
                              }
                              break;

                           case SOCK_DGRAM:
                              retn = 0;
                              break;
                        }
                     } else {
                        snprintf(errbuf, 256, "%s: ArgusEstablishListen: bind() error", ArgusProgramName);
                     }
                  } else
                     snprintf(errbuf, 256, "%s: ArgusEstablishListen: fcntl() error", ArgusProgramName);

                  if (retn == -1) {
                     close (s);
                     s = -1;
                  }

               } else
                  snprintf(errbuf, 256, "%s: ArgusEstablishListen: socket() error", ArgusProgramName);

               hp = hp->ai_next;

            } while ((hp != NULL) && (retn == -1));

            freeaddrinfo(host);
         }
#else
         struct sockaddr_in sin;
         struct hostent *host;

         sin.sin_addr.s_addr = INADDR_ANY;
         if (baddr) {
#ifdef ARGUSDEBUG
            ArgusDebug (1, "ArgusEstablishListen(%d, %s, %p)\n", port, baddr, errbuf);
#endif
            if ((host = gethostbyname (baddr)) != NULL) {
               if ((host->h_addrtype == AF_INET) && (host->h_length == 4)) {
                  bcopy ((char *) *host->h_addr_list, (char *)&sin.sin_addr.s_addr, host->h_length);
               } else
                  ArgusLog (LOG_ERR, "ArgusEstablishListen() unsupported bind address %s", baddr);
            } else
               ArgusLog (LOG_ERR, "ArgusEstablishListen() bind address %s error %s", baddr, strerror(errno));
         }

         sin.sin_port = htons((u_short) port);
         sin.sin_family = AF_INET;

#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusEstablishListen(%p, %p) binding: %d:%d\n", output, errbuf, sin.sin_addr.s_addr, port);
#endif

         if ((s = socket (AF_INET, SOCK_STREAM, 0)) != -1) {
            int flags = fcntl (s, F_GETFL, 0L);
            if ((fcntl (s, F_SETFL, flags | O_NDELAY)) >= 0) {
               int on = 1;
               if (setsockopt(s, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0)
                  ArgusLog (LOG_INFO, "ArgusInitOutput: setsockopt set reuseaddr %s", strerror(errno));

               if (!(bind (s, (struct sockaddr *)&sin, sizeof(sin)))) {
                  if ((listen (s, ARGUS_MAXLISTEN)) >= 0) {
                     output->ArgusLfd[output->ArgusListens++] = s;
                  } else {
                     close (s);
                     s = -1;
                     snprintf(errbuf, 1024, "%s: ArgusEstablishListen: listen() failure", ArgusProgramName);
                  }
               } else {
                  close (s);
                  s = -1;
                  snprintf(errbuf, 256, "%s: ArgusEstablishListen: bind() error", ArgusProgramName);
               }
            } else
               snprintf(errbuf, 256, "%s: ArgusEstablishListen: fcntl() error", ArgusProgramName);
         } else
            snprintf(errbuf, 256, "%s: ArgusEstablishListen: socket() error", ArgusProgramName);
#endif
         if (ArgusBindAddrs) {
            if ((ArgusBindAddrs = (struct ArgusBindAddrStruct *)ArgusBindAddrs->nxt) != NULL) {
               baddr = ArgusBindAddrs->addr;
            } else
               baddr = NULL;
         }
            
      } while (baddr != NULL);
   }
     
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusEstablishListen(%p, %p) returning %d\n", output, errbuf, s);
#endif

   return (s);
}


int ArgusAuthenticateClient (struct ArgusClientData *);
#ifdef ARGUS_SASL
static sasl_ssf_t extprops_ssf = 0;
static char clienthost[NI_MAXHOST*2+1] = "[local]";

sasl_security_properties_t *mysasl_secprops(int);
#endif


void
ArgusCheckClientStatus (struct ArgusOutputStruct *output, int s)
{
   struct sockaddr from;
   int len = sizeof (from), bytes;
   int fd;

#ifdef ARGUS_SASL
#define SASL_SEC_MASK   0x0fff
   struct sockaddr_storage localaddr, remoteaddr;
   int retn, argus_have_addr = 0;
   char localhostname[1024];
   sasl_conn_t *conn = NULL;

   socklen_t salen;
   sasl_security_properties_t *secprops = NULL;
   char localip[60], remoteip[60];
#endif

   if ((fd = accept (s, (struct sockaddr *)&from, (socklen_t *)&len)) > 0) {
      int flags = fcntl (fd, F_GETFL, 0L);

      if ((fcntl (fd, F_SETFL, flags | O_NONBLOCK)) >= 0) {
         if (ArgusTcpWrapper (fd, &from) >= 0) {

            if (output->ArgusClients && (output->ArgusClients->count < ARGUS_MAXLISTEN)) {
               struct ArgusClientData *client = (void *) ArgusCalloc (1, sizeof(struct ArgusClientData));

               if (client == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusCalloc %s", strerror(errno));

               client->fd = fd;
               client->startime = output->ArgusGlobalTime;
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCheckClientStatus() new client\n");
#endif
               if ((client->sock = ArgusNewSocket(fd)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusInitOutput: ArgusNewSocket error %s", strerror(errno));

               if (output->ArgusInitMar != NULL)
                  ArgusFree(output->ArgusInitMar);

               if ((output->ArgusInitMar = ArgusGenerateInitialMar(output)) == NULL)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: ArgusGenerateInitialMar error %s", strerror(errno));

#ifdef ARGUS_SASL
#ifdef ARGUSDEBUG
               ArgusDebug (2, "ArgusCheckClientStatus: SASL enabled\n");
#endif
               {
               char hbuf[NI_MAXHOST];
               int niflags;
               salen = sizeof(remoteaddr);

               bzero(hbuf, sizeof(hbuf));

               if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) == 0 &&
                   (remoteaddr.ss_family == AF_INET || remoteaddr.ss_family == AF_INET6)) {
                   if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, NI_NAMEREQD) == 0) {
                       strncpy(clienthost, hbuf, sizeof(hbuf));
                   } else {
                       clienthost[0] = '\0';
                   }
                   niflags = NI_NUMERICHOST;
#ifdef NI_WITHSCOPEID
                   if (((struct sockaddr *)&remoteaddr)->sa_family == AF_INET6)
                       niflags |= NI_WITHSCOPEID;
#endif
                   if (getnameinfo((struct sockaddr *)&remoteaddr, salen, hbuf, sizeof(hbuf), NULL, 0, niflags) != 0)
                       strncpy(hbuf, "unknown", sizeof(hbuf));

                   sprintf(&clienthost[strlen(clienthost)], "[%s]", hbuf);

                   salen = sizeof(localaddr);
                   if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) == 0) {
                       if(iptostring((struct sockaddr *)&remoteaddr, salen,
                                     remoteip, sizeof(remoteip)) == 0
                          && iptostring((struct sockaddr *)&localaddr, salen,
                                        localip, sizeof(localip)) == 0) {
                          argus_have_addr = 1;
                       }
                   }
               }
               }

               gethostname(localhostname, 1024);
               if (!strchr (localhostname, '.')) {
                  char domainname[256];
                  strcat (localhostname, ".");
                  if (getdomainname (domainname, 256)) {
                     snprintf (&localhostname[strlen(localhostname)], 1024 - strlen(localhostname), "%s", domainname);
                  }
               }

               if ((retn = sasl_server_new("argus", NULL, NULL, localip, remoteip, NULL, 0,
                               &client->sasl_conn)) != SASL_OK)
                  ArgusLog (LOG_ERR, "ArgusCheckClientStatus: sasl_server_new failed %d", retn);

               conn = client->sasl_conn;

              /* set required security properties here */

               if (extprops_ssf)
                  sasl_setprop(conn, SASL_SSF_EXTERNAL, &extprops_ssf);

               secprops = mysasl_secprops(0);
               sasl_setprop(conn, SASL_SEC_PROPS, secprops);


              /* set ip addresses */
               if (argus_have_addr) {
                  sasl_setprop(conn, SASL_IPREMOTEPORT, remoteip);
                  if (client->saslprops.ipremoteport != NULL)
                     free(client->saslprops.ipremoteport);
                  client->saslprops.ipremoteport = strdup(remoteip);

                  sasl_setprop(conn, SASL_IPLOCALPORT, localip);
                  if (client->saslprops.iplocalport != NULL)
                     free(client->saslprops.iplocalport);
                  client->saslprops.iplocalport = strdup(localip);
               }

               output->ArgusInitMar->argus_mar.status |= htonl(ARGUS_SASL_AUTHENTICATE);
#endif
               len = ntohs(output->ArgusInitMar->hdr.len) * 4;

               if ((bytes = write (client->fd, (char *) output->ArgusInitMar, len)) != len) {
                  close (client->fd);
                  ArgusLog (LOG_ALERT, "ArgusInitOutput: write(): %s", strerror(errno));
               } else {
#ifdef ARGUSDEBUG
                  ArgusDebug (2, "ArgusCheckClientStatus: wrote %d bytes to client\n", bytes);
#endif
               }

#ifdef ARGUS_SASL
               if (ArgusMaxSsf > 0) {
                  int flags = fcntl (fd, F_GETFL, 0);

                  fcntl (fd, F_SETFL, flags & ~O_NONBLOCK);
                  if (ArgusAuthenticateClient (client)) {
                     ArgusDeleteSocket(output, client);
                     ArgusLog (LOG_ALERT, "ArgusCheckClientStatus: ArgusAuthenticateClient failed\n");
                  } else {
                     ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
                     fcntl (fd, F_SETFL, flags);
                  }

               } else {
               }
#else
               ArgusAddToQueue(output->ArgusClients, &client->qhdr, ARGUS_NOLOCK);
#endif
            } else {
               char buf[256];
               struct ArgusRecord *argus = (struct ArgusRecord *) &buf;
               if ((argus = ArgusGenerateRecord (output->ArgusModel, NULL, ARGUS_ERROR, (struct ArgusRecord *) &buf)) != NULL) {
                  len = argus->hdr.len * 4;
                  argus->hdr.len = ntohs(argus->hdr.len);
                  argus->hdr.cause |= ARGUS_MAXLISTENEXCD;
                  if (write (fd, (char *) argus, len) != len) {
                     ArgusLog (LOG_ERR, "ArgusInitOutput: write(): %s", strerror(errno));
                  } else {
#ifdef ARGUSDEBUG
                     ArgusDebug (2, "ArgusCheckClientStatus: wrote %d bytes to client fd %d\n", len, fd);
#endif
                  }
                  close(fd);
               }
            }

         } else {
            ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: ArgusTcpWrapper rejects");
            close (fd);
         }
         
      } else {
         ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: fcntl: %s", strerror(errno));
         close (fd);
      }

   } else 
      ArgusLog (LOG_WARNING, "ArgusCheckClientStatus: accept: %s", strerror(errno));
     
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCheckClientStatus() returning\n");
#endif
}


 
#define ARGUSMAXCLIENTCOMMANDS           6
#define RADIUM_START                    0
#define RADIUM_DONE                     1
#define RADIUM_FILTER                   2
#define RADIUM_MODEL                    3
#define RADIUM_PROJECT                  4
#define RADIUM_FILE                     5
 
char *ArgusClientCommands[ARGUSMAXCLIENTCOMMANDS] =
{
   "START: ",
   "DONE: ",
   "FILTER: ",
   "MODEL: ",
   "PROJECT: ",
   "FILE: ",
};


int
ArgusCheckClientMessage (struct ArgusOutputStruct *output, struct ArgusClientData *client)
{
   int retn = 0, cnt = 0, i, found, fd = client->fd;
   char buf[MAXSTRLEN], *ptr = buf;
   unsigned int value = 0;
    
#ifdef ARGUS_SASL
   const char *outputbuf = NULL;
   unsigned int outputlen = 0;
#endif /* ARGUS_SASL */

   bzero(buf, MAXSTRLEN);

   if (value == 0)
      value = MAXSTRLEN;

   if ((cnt = recv (fd, buf, value, 0)) <= 0) {
      if (cnt < 0) {
#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusCheckClientMessage (%p, %p) recv(%d) returned error %s\n", output, client, fd, strerror(errno));
#endif
         return (-1);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (5, "ArgusCheckClientMessage (%p, %p) recv(%d) returned %d bytes\n", output, client, fd, cnt);
#endif
         return(-3);
      }

   } else {
#ifdef ARGUSDEBUG
      ArgusDebug (6, "ArgusCheckClientMessage (%p, %p) recv(%d) returned %d bytes\n", output, client, fd, cnt);
#endif
   }

#ifdef ARGUS_SASL
   if ((client->sasl_conn)) {
      const int *ssfp;
      int result;

      if ((result = sasl_getprop(client->sasl_conn, SASL_SSF, (const void **) &ssfp)) != SASL_OK)
         ArgusLog (LOG_ERR, "sasl_getprop: error %s\n", sasl_errdetail(client->sasl_conn));

      if (ssfp && (*ssfp > 0)) {
         if (sasl_decode (client->sasl_conn, buf, cnt, &outputbuf, &outputlen) != SASL_OK) {
            ArgusLog (LOG_WARNING, "ArgusCheckClientMessage(%p, %d) sasl_decode (%p, %p, %d, %p, %d) failed",
                       client, fd, client->sasl_conn, buf, cnt, &outputbuf, outputlen);
            return(-1);
         } else {
#ifdef ARGUSDEBUG
            ArgusDebug (6, "ArgusCheckClientMessage (%p, %p) sasl_decode(%d) returned %d bytes\n", output, client, fd, outputlen);
#endif
         }
         if (outputlen > 0) {
            if (outputlen < MAXSTRLEN) {
               bzero (buf, MAXSTRLEN);
               bcopy (outputbuf, buf, outputlen);
               cnt = outputlen;
            } else
               ArgusLog (LOG_ERR, "ArgusCheckClientMessage(%p, %d) sasl_decode returned %d bytes\n", client, fd, outputlen);
        
         } else {
            return (0);
         }
      }
   }
#endif /* ARGUS_SASL */

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCheckClientMessage (%p, %p) read '%s' from remote\n", output, client, ptr);
#endif

   for (i = 0, found = 0; i < ARGUSMAXCLIENTCOMMANDS; i++) {
      if (!(strncmp (ptr, ArgusClientCommands[i], strlen(ArgusClientCommands[i])))) {
         found++;
         switch (i) {
            case RADIUM_START: client->ArgusClientStart++; retn = 0; break;
            case RADIUM_DONE:  retn = -4; break; 
            case RADIUM_FILTER: {
               char *reply = NULL;
               reply = ArgusFilterCompile (&client->ArgusNFFcode, &ptr[7], 1);
               if (reply == NULL) {
                  retn = -2;
                  if ((cnt = send (fd, "ER", 2, 0)) != 2) {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusCheckClientMessage: send error %s\n", strerror(errno));
#endif
                  } 
#ifdef ARGUSDEBUG
                  ArgusDebug (3, "ArgusCheckClientMessage: ArgusFilter filter error: %s\n", &ptr[7]);
#endif
               } else 
               if (strcmp(reply, "OK")) {
                  retn = -3;
                  if ((cnt = send (fd, reply, 2, 0)) != 2)  {
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusCheckClientMessage: send error %s\n", strerror(errno));
#endif
                  }
               } else {

#ifdef ARGUSDEBUG
                  char buf[MAXSTRLEN];
                  bzero(buf, MAXSTRLEN);
                  nff_dump(&client->ArgusNFFcode, buf, MAXSTRLEN, 1);
                  ArgusDebug (3, "ArgusInitOutput: ArgusFilterCompile returned: \n%s\n", buf);
#endif
                  client->ArgusFilterInitialized++;
                  if ((cnt = send (fd, "OK", 2, 0)) != 2) {
                     retn = -3;
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusCheckClientMessage: send error %s\n", strerror(errno));
#endif
                  } else {
                     retn = 0;
#ifdef ARGUSDEBUG
                     ArgusDebug (4, "ArgusCheckClientMessage: ArgusFilter %s initialized.\n", &ptr[7]);
#endif
                  }
               }
               break;
            }

            case RADIUM_PROJECT: 
            case RADIUM_MODEL: 
               break;

            case RADIUM_FILE: {
#ifdef ARGUSDEBUG
                  ArgusDebug (6, "ArgusCheckClientMessage: ArgusFile %s initialized.\n", &ptr[6]);
#endif
                  retn = 0;
               }
               break;

            default:
               ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: received %s",  ptr);
               break;
         }

         break;
      }
   }

   if (!found)
      ArgusLog (LOG_WARNING, "ArgusCheckClientMessage: received %s",  ptr);

#ifdef ARGUSDEBUG
   ArgusDebug (5, "ArgusCheckClientMessage: returning %d\n", retn);
#endif

   return (retn);
}


struct ArgusRecord *
ArgusGenerateInitialMar (struct ArgusOutputStruct *output)
{
   struct ArgusSourceStruct *ArgusSrc, *aSrc;
   struct ArgusRecord *retn;
   struct timeval now;
   int x, done;

   if ((retn = (struct ArgusRecord *) ArgusCalloc (1, sizeof(struct ArgusRecord))) == NULL)
     ArgusLog (LOG_ERR, "ArgusGenerateInitialMar(%p) ArgusCalloc error %s\n", output, strerror(errno));
   
   retn->hdr.type  = ARGUS_MAR | ARGUS_VERSION;
   retn->hdr.cause = ARGUS_START;
   retn->hdr.len   = sizeof(struct ArgusRecord) / 4;

   retn->argus_mar.argusid = ARGUS_COOKIE;
   retn->argus_mar.thisid  = getArgusID(ArgusSourceTask);

   switch (getArgusIDType(ArgusSourceTask)) {
      case ARGUS_TYPE_STRING: retn->argus_mar.status |= ARGUS_IDIS_STRING; break;
      case ARGUS_TYPE_INT:    retn->argus_mar.status |= ARGUS_IDIS_INT; break;
      case ARGUS_TYPE_IPV4:   retn->argus_mar.status |= ARGUS_IDIS_IPV4; break;
   }

   retn->argus_mar.startime.tv_sec  = output->ArgusStartTime.tv_sec;
   retn->argus_mar.startime.tv_usec = output->ArgusStartTime.tv_usec;

   gettimeofday (&now, 0L);

   retn->argus_mar.now.tv_sec  = now.tv_sec;
   retn->argus_mar.now.tv_usec = now.tv_usec;

   retn->argus_mar.major_version = VERSION_MAJOR;
   retn->argus_mar.minor_version = VERSION_MINOR;
   retn->argus_mar.reportInterval = getArgusFarReportInterval(output->ArgusModel)->tv_sec;
   retn->argus_mar.argusMrInterval = getArgusMarReportInterval(output)->tv_sec;

   if ((ArgusSrc = output->ArgusSrc) != NULL) {
      for (x = 0, done = 0; x < ARGUS_MAXINTERFACE && !done; x++) {
         if ((aSrc = ArgusSrc->srcs[x]) != NULL) {
            if (aSrc->ArgusInterface[0].ArgusLocalNet != 0) {
               retn->argus_mar.localnet = aSrc->ArgusInterface[0].ArgusLocalNet;
               retn->argus_mar.netmask  = aSrc->ArgusInterface[0].ArgusNetMask;
               done = 1;
            }
         }
      }
   }
  
   retn->argus_mar.nextMrSequenceNum = output->ArgusOutputSequence;
   retn->argus_mar.record_len = -1;

#if defined(_LITTLE_ENDIAN)
   ArgusHtoN(retn);
#endif

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateInitialMar() returning\n");
#endif

   return (retn);
}

// The supplemental mar record is designed to extend the descriptions of the sensors, their inputs,
// providing interfaces, names, interface types, extended argus identifiers (> 4 bytes), 
// and stats, if appropriate,
//
// This will be the way we provide long argus id's, IPv6, ethernet, and long strings.
// 
// Minimally it should provide the argusid, used in all records, and the list of input descriptions,
// as well as the extended argus id itself.


struct ArgusRecordStruct *
ArgusGenerateSupplementalMarRecord (struct ArgusOutputStruct *output, unsigned char status)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusRecord *rec = NULL;

   while ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (sizeof(*retn))) == NULL) {
      if (output && output->ArgusInputList) {
         if ((retn = (struct ArgusRecordStruct *) ArgusPopFrontList(output->ArgusInputList, ARGUS_LOCK)) != NULL) {
            ArgusFreeListRecord (retn);
         } else
            break;
      } else
         break;
   }

   if (retn) {
      struct ArgusSourceStruct *ArgusSrc = NULL, *aSrc = NULL;
      struct timeval now;

      memset(retn, 0, sizeof(*retn));
      
      retn->hdr.type    = ARGUS_MAR | ARGUS_VERSION;
      retn->hdr.cause   = ARGUS_SUPPLEMENTAL;
      retn->hdr.len     = (sizeof(struct ArgusMarSupStruct)/4) + 1;  // have size for one interface, and add as you go

      rec = (struct ArgusRecord *) &retn->canon;
      rec->hdr = retn->hdr;

      rec->argus_sup.argusid = getArgusID(ArgusSourceTask);

      switch (getArgusIDType(ArgusSourceTask)) {
         case ARGUS_TYPE_STRING: rec->argus_sup.status |= ARGUS_IDIS_STRING; break;
         case ARGUS_TYPE_INT:    rec->argus_sup.status |= ARGUS_IDIS_INT; break;
         case ARGUS_TYPE_IPV4:   rec->argus_sup.status |= ARGUS_IDIS_IPV4; break;
      }

      gettimeofday (&now, 0L);

      rec->argus_sup.startime.tv_sec  = output->ArgusLastMarUpdateTime.tv_sec;
      rec->argus_sup.startime.tv_usec = output->ArgusLastMarUpdateTime.tv_usec;

      rec->argus_sup.now.tv_sec  = now.tv_sec;
      rec->argus_sup.now.tv_usec = now.tv_usec;

      if ((ArgusSrc = output->ArgusSrc) != NULL) {
         int x;
         for (x = 0; x < ARGUS_MAXINTERFACE; x++) {
            if ((aSrc = ArgusSrc->srcs[x]) != NULL) {
               if (aSrc->ArgusInterface[0].ArgusPd != NULL) {
                  int i;
                  rec->argus_mar.interfaceType = pcap_datalink(aSrc->ArgusInterface[0].ArgusPd);
                  rec->argus_mar.interfaceStatus = getArgusInterfaceStatus(aSrc);

                  rec->argus_mar.pktsRcvd  = 0;
                  rec->argus_mar.bytesRcvd = 0;
                  rec->argus_mar.dropped   = 0;

                  for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
                     rec->argus_mar.pktsRcvd  += aSrc->ArgusInterface[i].ArgusTotalPkts - 
                                                 aSrc->ArgusInterface[i].ArgusLastPkts;
                     rec->argus_mar.bytesRcvd += aSrc->ArgusInterface[i].ArgusTotalBytes -
                                                 aSrc->ArgusInterface[i].ArgusLastBytes;
                     rec->argus_mar.dropped   += aSrc->ArgusInterface[i].ArgusStat.ps_drop - 
                                                 aSrc->ArgusInterface[i].ArgusLastDrop;

                     aSrc->ArgusInterface[i].ArgusLastPkts  = aSrc->ArgusInterface[i].ArgusTotalPkts;
                     aSrc->ArgusInterface[i].ArgusLastDrop  = aSrc->ArgusInterface[i].ArgusStat.ps_drop;
                     aSrc->ArgusInterface[i].ArgusLastBytes = aSrc->ArgusInterface[i].ArgusTotalBytes;
                  }
               }
            }
         }
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateStatusMar(%p, %d) returning 0x%x", output, status, retn);
#endif

   return (retn);
}


struct ArgusRecordStruct *
ArgusGenerateStatusMarRecord (struct ArgusOutputStruct *output, unsigned char status)
{
   struct ArgusRecordStruct *retn = NULL;
   struct ArgusRecord *rec = NULL;

   while ((retn = (struct ArgusRecordStruct *) ArgusMallocListRecord (sizeof(*retn))) == NULL) {
      if (output && output->ArgusInputList) {
         if ((retn = (struct ArgusRecordStruct *) ArgusPopFrontList(output->ArgusInputList, ARGUS_LOCK)) != NULL) {
            ArgusFreeListRecord (retn);
         } else
            break;
      } else
         break;
   }

   if (retn) {
      extern int ArgusAllocTotal, ArgusFreeTotal, ArgusAllocBytes;
      struct ArgusSourceStruct *ArgusSrc = NULL, *aSrc = NULL;
      struct timeval now;

      memset(retn, 0, sizeof(*retn));
      
      retn->hdr.type    = ARGUS_MAR | ARGUS_VERSION;
      retn->hdr.cause   = status;
      retn->hdr.len     = (sizeof(struct ArgusMarStruct)/4) + 1;

      rec = (struct ArgusRecord *) &retn->canon;

      rec->hdr = retn->hdr;
      rec->argus_mar.argusid = getArgusID(ArgusSourceTask);
      switch (getArgusIDType(ArgusSourceTask)) {
         case ARGUS_TYPE_STRING: rec->argus_mar.status |= ARGUS_IDIS_STRING; break;
         case ARGUS_TYPE_INT:    rec->argus_mar.status |= ARGUS_IDIS_INT; break;
         case ARGUS_TYPE_IPV4:   rec->argus_mar.status |= ARGUS_IDIS_IPV4; break;
      }

      gettimeofday (&now, 0L);

      rec->argus_mar.startime.tv_sec  = output->ArgusLastMarUpdateTime.tv_sec;
      rec->argus_mar.startime.tv_usec = output->ArgusLastMarUpdateTime.tv_usec;

      rec->argus_mar.now.tv_sec  = now.tv_sec;
      rec->argus_mar.now.tv_usec = now.tv_usec;

      rec->argus_mar.major_version = VERSION_MAJOR;
      rec->argus_mar.minor_version = VERSION_MINOR;
      rec->argus_mar.reportInterval = getArgusFarReportInterval(output->ArgusModel)->tv_sec;
      rec->argus_mar.argusMrInterval = getArgusMarReportInterval(ArgusOutputTask)->tv_sec;

      rec->argus_mar.localnet = output->ArgusSrc->ArgusInterface[0].ArgusLocalNet;
      rec->argus_mar.netmask = output->ArgusSrc->ArgusInterface[0].ArgusNetMask;
    
      rec->argus_mar.nextMrSequenceNum = output->ArgusOutputSequence;
      rec->argus_mar.record_len = -1;

      if ((ArgusSrc = output->ArgusSrc) != NULL) {
         int x;
         for (x = 0; x < ARGUS_MAXINTERFACE; x++) {
            if ((aSrc = ArgusSrc->srcs[x]) != NULL) {
               if (aSrc->ArgusInterface[0].ArgusPd != NULL) {
                  int i;
                  rec->argus_mar.interfaceType = pcap_datalink(aSrc->ArgusInterface[0].ArgusPd);
                  rec->argus_mar.interfaceStatus = getArgusInterfaceStatus(aSrc);

                  rec->argus_mar.pktsRcvd  = 0;
                  rec->argus_mar.bytesRcvd = 0;
                  rec->argus_mar.dropped   = 0;

                  for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
                     rec->argus_mar.pktsRcvd  += aSrc->ArgusInterface[i].ArgusTotalPkts - 
                                                 aSrc->ArgusInterface[i].ArgusLastPkts;
                     rec->argus_mar.bytesRcvd += aSrc->ArgusInterface[i].ArgusTotalBytes -
                                                 aSrc->ArgusInterface[i].ArgusLastBytes;
                     rec->argus_mar.dropped   += aSrc->ArgusInterface[i].ArgusStat.ps_drop - 
                                                 aSrc->ArgusInterface[i].ArgusLastDrop;

                     aSrc->ArgusInterface[i].ArgusLastPkts  = aSrc->ArgusInterface[i].ArgusTotalPkts;
                     aSrc->ArgusInterface[i].ArgusLastDrop  = aSrc->ArgusInterface[i].ArgusStat.ps_drop;
                     aSrc->ArgusInterface[i].ArgusLastBytes = aSrc->ArgusInterface[i].ArgusTotalBytes;
                  }
               }
            }
         }
      }

      rec->argus_mar.records = output->ArgusTotalRecords - output->ArgusLastRecords;
      output->ArgusLastRecords = output->ArgusTotalRecords;

      rec->argus_mar.flows = output->ArgusModel->ArgusTotalNewFlows - output->ArgusModel->ArgusLastNewFlows;
      output->ArgusModel->ArgusLastNewFlows = output->ArgusModel->ArgusTotalNewFlows;

      if (output->ArgusModel && output->ArgusModel->ArgusStatusQueue)
         rec->argus_mar.queue   = output->ArgusModel->ArgusStatusQueue->count;
      else
         rec->argus_mar.queue   = 0;

      if (output->ArgusOutputList)
         rec->argus_mar.output  = output->ArgusOutputList->count;
      else
         rec->argus_mar.output  = 0;

      rec->argus_mar.clients = output->ArgusClients->count;

      rec->argus_mar.bufs     = ArgusAllocTotal - ArgusFreeTotal;
      rec->argus_mar.bytes    = ArgusAllocBytes;
      rec->argus_mar.suserlen = getArgusUserDataLen(ArgusModel);
      rec->argus_mar.duserlen = getArgusUserDataLen(ArgusModel);

   }

#ifdef ARGUSDEBUG
   ArgusDebug (4, "ArgusGenerateStatusMarRecord(%p, %d) returning 0x%x", output, status, retn);
#endif

   return (retn);
}


struct timeval *
getArgusMarReportInterval(struct ArgusOutputStruct *output) {
   return (&output->ArgusMarReportInterval);
}


#include <ctype.h>
#include <math.h>

void
setArgusMarReportInterval(struct ArgusOutputStruct *output, char *value)
{
   struct timeval *tvp = getArgusMarReportInterval(output);

   struct timeval ovalue, now;
   double thisvalue = 0.0, iptr, fptr;
   int ivalue = 0;
   char *ptr = NULL;;

   if (tvp != NULL) {
      ovalue = *tvp;
      tvp->tv_sec  = 0;
      tvp->tv_usec = 0;
   } else {
      ovalue.tv_sec  = 0;
      ovalue.tv_usec = 0;
   }

   if (((ptr = strchr (value, '.')) != NULL) || isdigit((int)*value)) {
      if (ptr != NULL) {
         thisvalue = atof(value);
      } else {
         if (isdigit((int)*value)) {
            ivalue = atoi(value);
            thisvalue = ivalue * 1.0;
         }
      }

      fptr =  modf(thisvalue, &iptr);

      tvp->tv_sec = iptr;
      tvp->tv_usec =  fptr * ARGUS_FRACTION_TIME;

      gettimeofday(&now, 0L);
#if defined(ARGUS_NANOSECONDS)
      now.tv_usec *= 1000;
#endif
      output->ArgusReportTime.tv_sec  = now.tv_sec + tvp->tv_sec;
      output->ArgusReportTime.tv_usec = tvp->tv_usec;

   } else
      *tvp = ovalue;

#ifdef ARGUSDEBUG
   ArgusDebug (4, "setArgusMarReportInterval(%s) returning\n", value);
#endif
}


#if defined HAVE_TCP_WRAPPER

#if defined(HAVE_SYSLOG_H)
#include <syslog.h>
#endif 

#include <tcpd.h>

#if !defined(MAXPATHNAMELEN)
#define MAXPATHNAMELEN   BUFSIZ
#endif

#define PARANOID		1
#define KILL_IP_OPTIONS		1
#define HOSTS_ACCESS		1

int allow_severity = LOG_INFO;     /* run-time adjustable */
int deny_severity  = LOG_WARNING;   /* ditto */

void fix_options(struct request_info *);

#endif

int
ArgusTcpWrapper (int fd, struct sockaddr *from)
{
#if defined(HAVE_TCP_WRAPPER)
   int retn = 0;
   struct request_info request;

   /*
    * Find out the endpoint addresses of this conversation. Host name
    * lookups and double checks will be done on demand.
    */
 
   request_init(&request, RQ_DAEMON, ArgusProgramName, RQ_FILE, STDIN_FILENO, 0);
   request.fd = fd;
   fromhost(&request);

   /*
    * Optionally look up and double check the remote host name. Sites
    * concerned with security may choose to refuse connections from hosts
    * that pretend to have someone elses host name.
    */
 
#ifdef PARANOID
   if (STR_EQ(eval_hostname(request.client), paranoid)) {
      ArgusLog (deny_severity, "refused connect from %s", eval_client(&request)); 
      if (request.sink)
         request.sink(request.fd);
      return -1;
   }
#endif

    /*
     * The BSD rlogin and rsh daemons that came out after 4.3 BSD disallow
     * socket options at the IP level. They do so for a good reason.
     * Unfortunately, we cannot use this with SunOS 4.1.x because the
     * getsockopt() system call can panic the system.
     */  

#if defined(KILL_IP_OPTIONS)
   fix_options(&request);
#endif /* KILL_IP_OPTIONS */

    /*
     * Find out and verify the remote host name. Sites concerned with
     * security may choose to refuse connections from hosts that pretend to
     * have someone elses host name.
     */  

#ifdef HOSTS_ACCESS
   if (!hosts_access(&request)) {
      ArgusLog  (deny_severity, "refused connect from %s", eval_client(&request));
      if (request.sink)
         request.sink(request.fd);
      return -1;
   } else
#endif

    /* Report remote client */
   ArgusLog  (allow_severity, "connect from %s", eval_client(&request));
   return (retn);

#else
   return (1);
#endif /* HAVE_TCP_WRAPPER */
}


#if defined(ARGUS_SASL)
/* This creates a structure that defines the allowable
 *   security properties 
 */
#define PROT_BUFSIZE 4096
sasl_security_properties_t *
mysasl_secprops(int flags)
{
    static sasl_security_properties_t ret;

    bzero((char *)&ret, sizeof(ret));

    ret.maxbufsize = PROT_BUFSIZE;
    ret.min_ssf = ArgusMinSsf; /* minimum allowable security strength */
    ret.max_ssf = ArgusMaxSsf; /* maximum allowable security strength */

    ret.security_flags = flags;
    
    ret.property_names = NULL;
    ret.property_values = NULL;

    return &ret;
}

int
iptostring(const struct sockaddr *addr, socklen_t addrlen, char *out, unsigned outlen)
{
    char hbuf[NI_MAXHOST], pbuf[NI_MAXSERV];
    int niflags;

    if(!addr || !out) {
        errno = EINVAL;
        return -1;
    }

    niflags = NI_NUMERICHOST | NI_NUMERICSERV;
#ifdef NI_WITHSCOPEID
    if (addr->sa_family == AF_INET6)
        niflags |= NI_WITHSCOPEID;
#endif
    if (getnameinfo(addr, addrlen, hbuf, sizeof(hbuf), pbuf, sizeof(pbuf),
                    niflags) != 0) {
        errno = EINVAL;
        return -1;
    }
    
    if(outlen < strlen(hbuf) + strlen(pbuf) + 2) {
        errno = ENOMEM;
        return -1;
    }
    
    snprintf(out, outlen, "%s;%s", hbuf, pbuf);
    
    return 0;
}
#endif
