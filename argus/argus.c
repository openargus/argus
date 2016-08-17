/*
 * Argus Software.  Argus files - main argus processing
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
 * $Id: //depot/argus/argus/argus/argus.c#101 $
 * $DateTime: 2015/07/02 10:42:46 $
 * $Change: 3030 $
 */

/*
 * argus - Audit Record Generation and Utilization System
 *
 * written by Carter Bullard
 * QoSient LLC
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(Argus)
#define Argus
#endif

#define _GNU_SOURCE

#include <stdlib.h>
#include <syslog.h>
#include <stdarg.h>

#if defined(HAVE_SYS_TYPES_H)
#include <sys/types.h>
#endif

#if defined(HAVE_SYS_WAIT_H)
#include <sys/wait.h>
#endif

#include <argus.h>

#if defined(ARGUS_TILERA)
#include <pass.h>
#include <pthread.h>
#include <sched.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/netio.h>

void bind_proc(int);
#endif

void ArgusParseResourceFile (struct ArgusModelerStruct *, char *);

char *ArgusPidFile = NULL;
pid_t ArgusSessionId = 0;
struct timeval ArgusNowTime;
char *ArgusPidPath = NULL;
int ArgusDaemon = 0;

#if defined(ARGUS_THREADS)
pthread_attr_t attrbuf, *ArgusAttr = &attrbuf;
#endif


void
usage(void)
{
   extern char version[];

   fprintf (stdout, "Argus Version %s\n", version);
   fprintf (stdout, "usage: %s [options] [-i interface] [filter-expression] \n", ArgusProgramName);
   fprintf (stdout, "usage: %s [options]  -r packetfile [filter-expression] \n\n", ArgusProgramName);

   fprintf (stdout, "options: -A                      Generate application byte metrics.\n");
   fprintf (stdout, "         -b                      dump filter compiler output.\n");
   fprintf (stdout, "         -B <addr[,addr]>        specify bind interface address(s).\n");
   fprintf (stdout, "         -c <dir>                daemon chroot directory.\n");
   fprintf (stdout, "         -C                      run in control plane monitoring mode.\n");
   fprintf (stdout, "         -d                      run Argus in daemon mode.\n");

#if defined(ARGUSDEBUG)
   fprintf (stdout, "         -D <level>              set debug reporting <level>.\n");
#endif

   fprintf (stdout, "         -e <value>              specify Argus Identifier <value>.\n");
   fprintf (stdout, "         -f                      don't stop when EOF is seen, but wait for more\n");
   fprintf (stdout, "                                 packets to arrive in packet capture file.\n");
   fprintf (stdout, "         -F <conffile>           read configuration from <conffile>.\n");
   fprintf (stdout, "         -h                      print help.\n");
   fprintf (stdout, "         -i <interface>          specify interface to use as a packet source.\n");
   fprintf (stdout, "             Supported formats:                                              \n");
   fprintf (stdout, "                -i ind:all                    open all as independent sources.\n");
   fprintf (stdout, "                -i dup:en0,en1/srcid          use two as duplex sources.     \n");
   fprintf (stdout, "                -i bond:en0,en1/srcid         use two as bonded interfaces.  \n");
   fprintf (stdout, "                -i dup:[bond:en0,en1],en2     complex specification.          \n");
   fprintf (stdout, "                -i en0/srcid -i en1/srcid     equivalent to '-i ind:en0/..'   \n");
   fprintf (stdout, "                -i en0 en1                     equivalent '-i bond:en0,en1')  \n");
   fprintf (stdout, "         -J                      generate packet performance data.\n");
   fprintf (stdout, "         -M <secs>               set MAR Status Report Time Interval (300s).\n");
   fprintf (stdout, "         -m                      turn on MAC Layer Reporting.\n");
   fprintf (stdout, "         -O                      turn off filter optimizer.\n");
   fprintf (stdout, "         -p                      don't go into promiscuous mode.\n");
   fprintf (stdout, "         -P <portnum>            enable remote access on <portnum> (561).\n");
   fprintf (stdout, "         -r <file file ...>      use packet file as data source.\n");
   fprintf (stdout, "             Supported formats:                                              \n");
   fprintf (stdout, "                -r file file     open files as, discover packet formats\n");
   fprintf (stdout, "                -r cisco:file    open files and look for netflow records in packet payload\n");

   fprintf (stdout, "         -R                      generate response time data.\n");
   fprintf (stdout, "         -s <bytes>              set the packet snaplen size.\n");
   fprintf (stdout, "         -S <secs>               set FAR Status Report Time Interval (60s).\n");
   fprintf (stdout, "         -t                      indicate that packetfile is MOAT Tsh format. \n");
   fprintf (stdout, "         -u <userid>             specify user id for daemon.\n");
   fprintf (stdout, "         -g <groupid>            specify group id for daemon.\n");
   fprintf (stdout, "         -U <bytes>              specify the number of user bytes to capture.\n");
   fprintf (stdout, "         -w <file [\"filter\"]>    write output to <file>, or '-', for stdout,\n");
   fprintf (stdout, "                                 against optional filter expression.\n");
   fprintf (stdout, "         -w <stream [\"filter\"]>  write output to URL based stream.\n");
   fprintf (stdout, "             Supported formats:                                              \n");
   fprintf (stdout, "                -w argus-udp://hostname[:port]    default port is 561.       \n");
   fprintf (stdout, "                -w udp://hostname[:port]          \n");
   fprintf (stdout, "                -w -                              write to stdout \n");
   fprintf (stdout, "         -X                      reset argus configuration.\n");
   fprintf (stdout, "         -Z                      generate packet size data.\n");
   fflush (stdout);
   exit (-1);
}


/*
 *  Argus main routine 
 *
 *  Argus main will:
 *       simply instantiate the source, modeler, and output tasks,
 *       parse out the command line options,
 *       initalize the tasks and then loop.
 *       Afterwards, it will delete all the tasks and exit();
 *
 */

#define ArgusEnvItems      2

char *ArgusResourceEnvStr [] = {
   "ARGUSHOME",
   "HOME",
};


#include <netdb.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <ctype.h>


static char ArgusPidFileName[MAXPATHNAMELEN];
char * ArgusCreatePIDFile (struct ArgusSourceStruct *, char *, char *);
void setArgusEventDataRecord (char *);
extern void setArgusPcapBufSize (struct ArgusSourceStruct *, int);

#define ARGUS_MAX_INSTANCES	5


char *
ArgusCreatePIDFile (struct ArgusSourceStruct *src, char *pidpath, char *appname)
{
   FILE *fd;
   char pidstrbuf[128], *pidstr = pidstrbuf;
   char *retn = NULL, *dev = NULL, *devstr = NULL;
   int i, pid;
   struct stat statbuf;

   if (pidpath == NULL)
      if (stat ("/var/run", &statbuf) == 0)
         pidpath = "/var/run";

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) pidpath is %s\n", pidpath, appname, pidpath);
#endif 

   if ((appname != NULL) && ((dev = getArgusDevice(src)) != NULL) && (pidpath != NULL)) {
      if ((devstr = strrchr(dev, (int)'/')) != NULL)
         devstr++;
      else
         devstr = dev;

      for (i = 0; i < ARGUS_MAX_INSTANCES; i++) {
         snprintf (ArgusPidFileName, MAXPATHNAMELEN - 1, "%s/%s.%s.%d.pid", pidpath, appname, devstr, i);
         retn = ArgusPidFileName;

         if ((stat (retn, &statbuf)) == 0) {
            if ((fd = fopen (ArgusPidFileName, "r")) != NULL) {
               if ((pidstr = fgets (pidstrbuf, 128, fd)) != NULL) {
                  if ((pid = strtol(pidstr, (char **)NULL, 10)) > 0) {
                     if (pid < 100000000) {
                        if ((kill (pid, 0)) == 0) {
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) pid %d is running\n", pidpath, appname, pid);
#endif 
                           retn = NULL;
                        } else {
                           switch (errno) {
                              case ESRCH: break;
                              default: ArgusLog (LOG_ERR, "kill returned error: %s\n", strerror(errno));
                           }
                        }
                     }
                  }
               }

               fclose (fd);
            } else {
#ifdef ARGUSDEBUG
               ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) fopen error %s:%s\n", pidpath, appname, ArgusPidFileName, strerror(errno));
#endif 
            }
         }
 
         if (retn != NULL)
            break;
      }

      if (retn && ((fd = fopen (retn, "w+")) != NULL)) {
         pid = getpid();
         fprintf (fd, "%d\n", pid);
         fclose (fd);
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) fopen error %s\n", pidpath, appname, strerror(errno));
#endif 
         retn = NULL;
      }

   } else {
#ifdef ARGUSDEBUG
      if (dev == NULL)
         ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) dev is null\n", pidpath, appname);
#endif 
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusCreatePIDFile(%s, %s) returning %s\n", pidpath, appname, retn);
#endif 

   return (retn);
}


int
main (int argc, char *argv[])
{
   int commandlinew = 0, doconf = 0;
   static char path[MAXPATHNAMELEN];
   int dodebug = 0, i, pid = 0;
   char *tmparg, *filter;
   extern char *optarg;
   struct stat statbuf;
   extern int optind, opterr;
   int op, commandlinei = 0;
#if defined(ARGUS_THREADS)
   sigset_t blocked_signals;

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN) && !defined(OpenBSD)
   int thread_policy;
   struct sched_param thread_param;
#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   int rr_min_priority, rr_max_priority;
#endif
#endif
   int status;
#endif

   ArgusUid = getuid();
   ArgusGid = getgid();
   
   gettimeofday(&ArgusNowTime, 0L);

   uflag = 0;
   pflag = 6;

   
   if (strchr (argv[0], '/')) {
#if defined(HAVE_STRLCPY)
      strlcpy(path, argv[0], MAXPATHNAMELEN - 1);
#else
      bzero(path, MAXPATHNAMELEN);
      strncpy(path, argv[0], MAXPATHNAMELEN - 1);
#endif
      argv[0] = strrchr(argv[0], '/') + 1;
   }

   ArgusProgramName = argv[0];

#ifdef HAVE_SYSLOG
#ifndef LOG_PERROR
#define LOG_PERROR      LOG_CONS
#endif

   openlog (ArgusProgramName, LOG_PID | LOG_PERROR, LOG_DAEMON);
#endif

   for (i = 1; (i < argc); i++) {
      char *ptr = argv[i]; 
      if (ptr != NULL) {
         if (*ptr == '-') {
            ptr++;
            if ((*ptr == 0) || (isspace((int)*ptr)))
               break;
            do {
               switch (*ptr) {
                  case 'D': 
                     if (isdigit((int)*++ptr)) {
                        setArgusdflag (ArgusModel, atoi (ptr));
                     } else {
                        if (isdigit((int)*argv[i + 1]))
                           setArgusdflag (ArgusModel, atoi (argv[++i]));
                        else
                           break;
                     }
                     break;

                  case 'X': 
                  case 'F': 
                     doconf++; 
                     break; 
                   
                  default: {
                     if (dodebug) {
                        if (isdigit((int)*ptr)) {
                           setArgusdflag (ArgusModel, atoi (ptr));
                           dodebug = 0;
                        }
                     }
                  }
               }

            } while (isalpha((int)*++ptr));
         }
      }
   }

   if ((ArgusModel = ArgusNewModeler()) == NULL)
      ArgusLog (LOG_ERR, "Error Creating Modeler: Exiting.\n");

   if ((ArgusSourceTask = ArgusNewSource(ArgusModel)) == NULL)
      ArgusLog (LOG_ERR, "Error Creating Source Task: Exiting.\n");

   if ((ArgusOutputTask = ArgusNewOutput(ArgusSourceTask, ArgusModel)) == NULL)
      ArgusLog (LOG_ERR, "Error Creating Output Thread: Exiting.\n");

   ArgusModel->ArgusSrc = ArgusSourceTask;

   setArgusFarReportInterval (ArgusModel, ARGUS_FARSTATUSTIMER);
   setArgusMarReportInterval (ArgusOutputTask,ARGUS_MARSTATUSTIMER);

   if (!doconf) {
      snprintf (path, MAXPATHNAMELEN - 1, "/etc/argus.conf");
      if (stat (path, &statbuf) == 0) {
         ArgusParseResourceFile (ArgusModel, path);
      }
   }

   optind = 1, opterr = 0;

   while ((op = getopt (argc, argv, "AbB:c:CdD:e:fF:g:i:JmM:N:OP:pRr:S:s:tT:u:U:w:XZh")) != EOF) {
      switch (op) {
         case 'A': setArgusAflag(ArgusModel, 1); break;
         case 'b': setArgusbpflag (ArgusSourceTask, 1); break;
         case 'B': setArgusBindAddr (ArgusOutputTask, optarg); break;
         case 'c': 
            if ((chroot_dir = strdup(optarg)) == NULL)
                ArgusLog (LOG_ERR, "strdup %s", strerror(errno));
            break;
         case 'C': {
            setArgusCaptureFlag(ArgusSourceTask, 1);
            setArgusControlMonitor(ArgusModel);
            setArgusSnapLen(ArgusSourceTask, ARGUS_MAXSNAPLEN);
            break;
         }
         case 'd': ArgusDaemon = ArgusDaemon ? 0 : 1; break;
         case 'D': setArgusdflag (ArgusModel, atoi (optarg)); break;
         case 'e': ArgusParseSourceID(ArgusSourceTask, optarg); break;
         case 'f': setArgusfflag (ArgusSourceTask, 1); break;
         case 'F': ArgusParseResourceFile (ArgusModel, optarg); break;

         case 'g': {
            struct group *gr;
            if ((gr = getgrnam(optarg)) == NULL)
                ArgusLog (LOG_ERR, "unknown group \"%s\"\n", optarg);
            new_gid = gr->gr_gid;
            endgrent();
            break;
         }

         case 'i': {
            char Istr[1024], *Iptr = Istr;

            if (!commandlinei++)
               clearArgusDevice(ArgusSourceTask);

            do {
               memset(Istr, 0, sizeof(Istr));
               if (*optarg == '"') {
                  if (Iptr[1] != '\0')
                     snprintf (Istr, 1024, "%s ", (&Iptr[1]));

                  while ((Iptr = strchr (Istr, '"')) == NULL) {
                     if ((optarg = argv[optind]) != NULL) {
                        snprintf (&Istr[strlen(Istr)], (1024 - strlen(Istr)), "%s ", optarg);
                        optind++;
                     } else
                        break;
                  }
                  optarg = Istr;

               } else
                  snprintf (&Istr[strlen(Istr)], (1024 - strlen(Istr)), "%s ", optarg);

               if ((optarg = argv[optind]) != NULL)
                  if (*optarg != '-')
                     optind++;

            } while (optarg && (*optarg != '-'));

            setArgusDevice (ArgusSourceTask, Istr, ARGUS_LIVE_DEVICE, 0);
            break;
         }

         case 'J': setArgusGenerateTime  (ArgusModel, 1); break;
         case 'm': setArgusmflag (ArgusModel, 1); break;
         case 'M': setArgusMarReportInterval (ArgusOutputTask, optarg); break;
         case 'N': {
            char *ptr = NULL;

            if ((ptr = strchr (optarg, '-')) != NULL) {
               char *eptr = ptr + 1;
               ArgusSourceTask->sNflag = strtol(optarg, (char **)&ptr, 10);
               if (ptr == optarg)
                  usage ();
               ArgusSourceTask->eNflag = strtol(eptr, (char **)&ptr, 10);
               if (ptr == eptr)
                  usage ();

            } else {
               ArgusSourceTask->sNflag = 0;
               ArgusSourceTask->eNflag = strtol(optarg, (char **)&ptr, 10);
               if (ptr == optarg)
                  usage ();
            }
            break;
         }

         case 'O': setArgusOflag  (ArgusSourceTask, 0); break;
         case 'P': setArgusPortNum(ArgusOutputTask, atoi(optarg)); break;
         case 'p': setArguspflag (ArgusSourceTask, 1); break;
         case 'R': setArgusResponseStatus (ArgusModel, 1); break;
         case 'r': {
            char Rstr[1024], *Rptr = Rstr;
            do {
               if (*optarg == '"') {
                  if (Rptr[1] != '\0')
                     snprintf (Rstr, 1024, "%s ", (&Rptr[1]));

                  while ((Rptr = strchr (Rstr, '"')) == NULL) {
                     if ((optarg = argv[optind]) != NULL) {
                        snprintf (&Rstr[strlen(Rstr)], (1024 - strlen(Rstr)), "%s ", optarg);
                        optind++;
                     } else
                        break;
                  }
                  optarg = Rstr;
               }
               setArgusrfile  (ArgusSourceTask, optarg);
               if ((optarg = argv[optind]) != NULL)
                  if (*optarg != '-')
                     optind++;
            } while (optarg && (*optarg != '-'));
            break;
         }

         case 'S': setArgusFarReportInterval (ArgusModel, optarg); break;
         case 's': setArgusSnapLen (ArgusSourceTask, atoi(optarg)); break;
         case 't': setArgusMoatTshFile (ArgusSourceTask, 1); break;
         case 'T': {
            float value;
            char *nptr = optarg, *endptr;
            
            value = strtod(nptr, &endptr);
            if (nptr != endptr)
               setArgusRealTime (ArgusSourceTask, value);
            else
               usage ();
            break;
         }
         case 'u': {
            struct passwd *pw;
            if ((pw = getpwnam(optarg)) == NULL)
               ArgusLog (LOG_ERR, "unknown user \"%s\"\n", optarg);
            new_uid = pw->pw_uid;
            endpwent();
            break;
         }
         case 'U': 
            setArgusUserDataLen (ArgusModel, atoi (optarg));
            if (getArgusSnapLen(ArgusSourceTask) != ARGUS_MAXSNAPLEN)
               setArgusSnapLen (ArgusSourceTask, atoi(optarg) + ARGUS_MINSNAPLEN);
            break;
         case 'w':
            if (!commandlinew++)
               clearArgusWfile();

            if ((tmparg = optarg) != NULL) {
               if ((*tmparg != '-') || ((*tmparg == '-') &&
                                       (!(strcmp (tmparg, "-"))))) {
                  if (argc == optind)
                     filter = NULL;
                  else {
                     filter = argv[optind];
                     if (*filter == '-') {
                        filter = NULL;
                     } else
                        optind++;
                     }
                  setArgusWfile (tmparg, filter);
                  break;
               }
            }
         case 'X': clearArgusConfiguration (ArgusModel); break;
         case 'Z': setArgusGeneratePacketSize(ArgusModel, 1); break;

         case 'h':
         default:
            usage ();
      }
   }

   setArgusArgv   (ArgusSourceTask, argv);
   setArgusOptind (ArgusSourceTask, optind);
   setArgusCmdBuf (ArgusSourceTask);
   if (ArgusSourceTask->ArgusCmdBuf != NULL)
      ArgusSourceTask->ArgusInputFilter = strdup(ArgusSourceTask->ArgusCmdBuf);

   if (getArgusrfile(ArgusSourceTask) != NULL) {
      if (!(getArgusRealTime(ArgusSourceTask))) {
         ArgusDaemon = 0;
         setArgusBindAddr(ArgusOutputTask, NULL);
         ArgusSourceTask->ArgusReadingOffLine++;
         if (getArgusfflag (ArgusSourceTask) == 0) {
            setArgusPortNum(ArgusOutputTask, 0);
         }
      }
   }

   setArgusInterfaceStatus(ArgusSourceTask, 1);

   if ((daemonflag = ArgusDaemon) != 0) {
      if ((pid = fork ()) < 0) {
         ArgusLog (LOG_ERR, "Can't fork daemon %s", strerror(errno));
      } else {
         if (pid) {
            struct timespec ts = {0, 500000000};
            int status;

            nanosleep(&ts, NULL);
            waitpid(pid, &status, WNOHANG);
            if (kill(pid, 0) < 0) {
               exit (1);
            } else
               exit (0);

         } else {
            ArgusSessionId = setsid();

            ArgusLog(LOG_WARNING, "started");

            if ((freopen ("/dev/null", "w", stdout)) == NULL)
               ArgusLog (LOG_ERR, "Cannot map stdout to /dev/null");

            if ((freopen ("/dev/null", "w", stderr)) == NULL)
               ArgusLog (LOG_ERR, "Cannot map stderr to /dev/null");

#ifdef HAVE_SYSLOG
            closelog ();
            openlog (ArgusProgramName, LOG_PID, LOG_DAEMON);
#endif
         }
      }
   }

#if defined(ARGUS_THREADS)
   pthread_mutex_init(&ArgusMainLock, NULL);
   if ((status = pthread_attr_init(ArgusAttr)) != 0)
      ArgusLog (LOG_ERR, "pthreads init error");

#if defined(_POSIX_THREAD_PRIORITY_SCHEDULING) && !defined(sun) && !defined(CYGWIN) && !defined(OpenBSD)
   if ((pthread_attr_getschedpolicy(ArgusAttr, &thread_policy)) != 0)
      ArgusLog (LOG_ERR, "pthreads get policy error");
   if ((pthread_attr_getschedparam(ArgusAttr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads get sched params error");
   if ((pthread_attr_setschedpolicy(ArgusAttr, SCHED_RR)) != 0)
      ArgusLog (LOG_ERR, "pthreads set SCHED_RR error");

#if defined(HAVE_SCHED_GET_PRIORITY_MIN)
   if ((rr_min_priority = sched_get_priority_min(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority min error");
   if ((rr_max_priority = sched_get_priority_max(SCHED_RR)) == -1)
      ArgusLog (LOG_ERR, "pthreads get priority max error");

   thread_param.sched_priority = (rr_max_priority + rr_min_priority)/2 + 1;

   if (thread_param.sched_priority > rr_max_priority)
      thread_param.sched_priority = rr_max_priority;
   if (thread_param.sched_priority < (rr_max_priority - 8))
      thread_param.sched_priority = rr_max_priority - 8;

   if ((pthread_attr_setschedparam(ArgusAttr, &thread_param)) != 0)
      ArgusLog (LOG_ERR, "pthreads set sched param error");
#endif
#else
#if defined(__sun__)
   pthread_attr_setschedpolicy(ArgusAttr, SCHED_RR);
#endif
#endif

   pthread_attr_setdetachstate(ArgusAttr, PTHREAD_CREATE_JOINABLE);
#endif

   ArgusInitOutput (ArgusOutputTask);

   if (getArgusrfile(ArgusSourceTask) != NULL) {
      if (getArgusRealTime(ArgusSourceTask)) {
         ArgusInitEvents (ArgusEventsTask);
      }

   } else {
      ArgusInitEvents (ArgusEventsTask);
   }

#if defined(ARGUS_THREADS)
   sigemptyset(&blocked_signals);
   pthread_sigmask(SIG_BLOCK, &blocked_signals, NULL);
#endif

#if defined(HAVE_SOLARIS)
   sigignore(SIGPIPE);
#else
   (void) signal (SIGPIPE, SIG_IGN);
#endif
 
   (void) signal (SIGHUP,  (void (*)(int)) ArgusScheduleShutDown);
   (void) signal (SIGINT,  (void (*)(int)) ArgusScheduleShutDown);
   (void) signal (SIGTERM, (void (*)(int)) ArgusScheduleShutDown);
   (void) signal (SIGUSR1, (void (*)(int)) ArgusUsr1Sig);
   (void) signal (SIGUSR2, (void (*)(int)) ArgusUsr2Sig);

   ArgusSourceProcess(ArgusSourceTask);

#ifdef ARGUSDEBUG
   ArgusDebug (1, "main() ArgusSourceProcess returned: shuting down");
#endif

   ArgusShutDown(0);

#ifdef HAVE_SYSLOG
   closelog();
#endif
   exit(0);
}


void
ArgusComplete ()
{

#define ARGUSPERFMETRICS		1

#if defined(ARGUSPERFMETRICS)
   long long ArgusTotalPkts = 0, ArgusTotalIPPkts = 0;
   long long ArgusTotalNonIPPkts = 0;
   struct timeval timediff;
   double totaltime;
   int i, len;
   char buf[256];

   long long ArgusTotalNewFlows;
   long long ArgusTotalClosedFlows;
   long long ArgusTotalSends;
   long long ArgusTotalBadSends;
   long long ArgusTotalUpdates;
   long long ArgusTotalCacheHits;

   char *ArgusIntStr[ARGUS_MAXINTERFACE];

   bzero(ArgusIntStr, sizeof(ArgusIntStr));
#endif

#if defined(ARGUSPERFMETRICS)
   for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
      if (ArgusSourceTask->ArgusInterface[i].ArgusDevice != NULL) {
         ArgusTotalPkts      += ArgusSourceTask->ArgusInterface[i].ArgusTotalPkts;
         ArgusTotalIPPkts    += ArgusSourceTask->ArgusInterface[i].ArgusTotalIPPkts;
         ArgusTotalNonIPPkts += ArgusSourceTask->ArgusInterface[i].ArgusTotalNonIPPkts;
      }
   }
   if (ArgusSourceTask->ArgusEndTime.tv_sec == 0)
      gettimeofday (&ArgusSourceTask->ArgusEndTime, 0L);

   if (ArgusSourceTask->ArgusStartTime.tv_sec == 0)
      ArgusSourceTask->ArgusStartTime = ArgusSourceTask->ArgusEndTime;

   bzero(buf, sizeof(buf));

   timediff.tv_sec  = ArgusSourceTask->ArgusEndTime.tv_sec  - ArgusSourceTask->ArgusStartTime.tv_sec;
   timediff.tv_usec = ArgusSourceTask->ArgusEndTime.tv_usec - ArgusSourceTask->ArgusStartTime.tv_usec;
 
   if (timediff.tv_usec < 0) {
      timediff.tv_usec += 1000000;
      timediff.tv_sec--;
   }
 
   totaltime = (double) timediff.tv_sec + (((double) timediff.tv_usec)/1000000.0);

   for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
      char sbuf[MAXSTRLEN];
      if (ArgusSourceTask->ArgusInterface[i].ArgusDevice != NULL) {
         sprintf (sbuf, "%s\n    Total Pkts %8lld  Rate %f\n",
                     ArgusSourceTask->ArgusInterface[i].ArgusDevice->name, ArgusSourceTask->ArgusInterface[i].ArgusTotalPkts,
                     ArgusSourceTask->ArgusInterface[i].ArgusTotalPkts/totaltime);
         ArgusIntStr[i] = strdup(sbuf);
      }
   }

#endif

   ArgusCloseSource (ArgusSourceTask);
   ArgusCloseEvents (ArgusEventsTask);
   ArgusCloseModeler (ArgusModel);
   ArgusCloseOutput (ArgusOutputTask);

#if defined(ARGUSPERFMETRICS)
   ArgusTotalNewFlows    = ArgusModel->ArgusTotalNewFlows;
   ArgusTotalClosedFlows = ArgusModel->ArgusTotalClosedFlows;
   ArgusTotalSends       = ArgusModel->ArgusTotalSends;
   ArgusTotalBadSends    = ArgusModel->ArgusTotalBadSends;
   ArgusTotalUpdates     = ArgusModel->ArgusTotalUpdates;
   ArgusTotalCacheHits   = ArgusModel->ArgusTotalCacheHits;
#endif

   ArgusFree(ArgusOutputTask);
   ArgusFree(ArgusModel);

   ArgusDeleteSource(ArgusSourceTask);

#if defined(ARGUSPERFMETRICS)
   len = strlen(ArgusProgramName);
   for (i = 0; i < len; i++)
      buf[i] = ' ';

   if (ArgusTotalNewFlows > 0) {
      extern int ArgusAllocTotal, ArgusFreeTotal, ArgusAllocMax;

      fprintf (stderr, "%s: Time %d.%06d Flows %-8lld  Closed %-8lld  Sends %-8lld  BSends %-8lld\n",
                         ArgusProgramName, (int)timediff.tv_sec, (int)timediff.tv_usec,
                         ArgusTotalNewFlows,  ArgusTotalClosedFlows,
                         ArgusTotalSends, ArgusTotalBadSends);
      fprintf (stderr, "%*s  Updates %-8lld Cache %-8lld\n", (int)strlen(ArgusProgramName), " ",
                         ArgusTotalUpdates, ArgusTotalCacheHits);
      fprintf (stderr, "%*s  Total Memory %-8d Free %-8d MaxBytes %d\n", (int)strlen(ArgusProgramName), " ",
                         ArgusAllocTotal, ArgusFreeTotal, ArgusAllocMax);
   }
   for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
      if (ArgusIntStr[i] != NULL) {
         fprintf (stderr, "Source: %s\n", ArgusIntStr[i]);
         free(ArgusIntStr[i]);
      }
   }

#endif
}


char *ArgusSignalTable [] = { "Normal Shutdown",
"SIGHUP", "SIGINT", "SIGQUIT", "SIGILL", "SIGTRAP",
"SIGABRT", "SIGBUS", "SIGFPE", "SIGKILL", "SIGUSR1",
"SIGSEGV", "SIGUSR2", "SIGPIPE", "SIGALRM", "SIGTERM",
"SIGSTKFLT", "SIGCHLD", "SIGCONT", "SIGSTOP", "SIGTSTP",
"SIGTTIN", "SIGTTOU", "SIGURG", "SIGXCPU", "SIGXFSZ",
"SIGVTALRM", "SIGPROF", "SIGWINCH", "SIGIO",
};

int ArgusShutDownFlag = 0;

#if defined(HAVE_BACKTRACE)
#include <execinfo.h>
#endif

void
ArgusScheduleShutDown (int sig)
{
   ArgusShutDownFlag++;

#ifdef ARGUSDEBUG
#if defined(HAVE_BACKTRACE)
   if (Argusdflag > 1) {
      void* callstack[128];
      int i, frames = backtrace(callstack, 128);
      char** strs = backtrace_symbols(callstack, frames);

      ArgusLog(LOG_WARNING, "ArgusScheduleShutDown(%d)", sig);

      for (i = 0; i < frames; ++i) {
         ArgusLog(LOG_WARNING, "%s", strs[i]);
      }
      free(strs);
   }
#endif

   ArgusDebug (1, "ArgusScheduleShutDown(%d)\n", sig);
#endif 
}

void
ArgusShutDown (int sig)
{
   ArgusShutDownFlag++;

#if defined(ARGUSDEBUG)
#if defined(HAVE_BACKTRACE)
   if (Argusdflag > 1) {
      void* callstack[128];
      int i, frames = backtrace(callstack, 128);
      char** strs = backtrace_symbols(callstack, frames);

      ArgusLog(LOG_WARNING, "ArgusShutDown(%d)", sig);

      for (i = 0; i < frames; ++i) {
         ArgusLog(LOG_WARNING, "%s", strs[i]);
      }
      free(strs);
   }
#endif
#endif


   if (sig < 0) {
#ifdef ARGUSDEBUG
      ArgusDebug (1, "ArgusShutDown(ArgusError)\n");
#endif 
      exit(0);
   }

#ifdef ARGUSDEBUG
   if (Argusdflag >= 1)
      fprintf(stderr, "\n");

   ArgusDebug (1, "ArgusShutDown(%s)\n\n", ArgusSignalTable[sig]);
#endif 

   if (!(ArgusShutDownStarted++)) {
      ArgusComplete ();

   } else {
#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusShutDown() returning\n");
#endif 
      return;
   }

   if (ArgusPidFile)
      unlink (ArgusPidFile);

   if (ArgusPidPath)
      free (ArgusPidPath);

   ArgusDeleteMallocList();

   if (daemonflag)
      ArgusLog(LOG_WARNING, "stopped");

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusShutDown()\n");
#endif 

   exit(0);
}


void
setArgusBindAddr (struct ArgusOutputStruct *output, char *value)
{
   if (value) {
      if (output->ArgusBindAddrs == NULL)
         output->ArgusBindAddrs = ArgusNewList();

      struct ArgusBindAddrStruct *baddr;
      char *tok, *ptr = value;

      while ((tok = strtok (ptr, ", \t")) != NULL) {

         if ((baddr = (struct ArgusBindAddrStruct *) ArgusCalloc(1, sizeof(*baddr))) == NULL)
            ArgusLog (LOG_ERR, "setArgusBindAddr ArgusCalloc %s\n", strerror(errno));

         baddr->addr = strdup(tok);
         ArgusPushBackList(output->ArgusBindAddrs, (struct ArgusListRecord *) baddr, ARGUS_LOCK);
         ptr = NULL;
      }

   } else {
      if (output->ArgusBindAddrs != NULL) {
         ArgusDeleteList(output->ArgusBindAddrs, ARGUS_BIND_ADDR_LIST);
         output->ArgusBindAddrs = NULL;
      }
   }
}


char *
getArgusBindAddr (struct ArgusOutputStruct *output)
{
   char *retn = NULL;

   if (output->ArgusBindAddrs != NULL) {
      if (output->ArgusBindAddrs->start) { 
         struct ArgusBindAddrStruct *baddr = (void *) output->ArgusBindAddrs->start;

         retn = baddr->addr;
      }
   }

   return(retn);
}

void
setArguspidflag (int value)
{
   pidflag = value;
}

int
getArguspidflag ()
{
   return (pidflag);
}

#define ARGUS_RCITEMS				51

#define ARGUS_DAEMON				0
#define ARGUS_MONITOR_ID			1
#define ARGUS_ACCESS_PORT			2
#define ARGUS_INTERFACE				3
#define ARGUS_OUTPUT_FILE			4
#define ARGUS_SET_PID 				5
#define ARGUS_PID_PATH				6
#define ARGUS_GO_PROMISCUOUS			7
#define ARGUS_FLOW_STATUS_INTERVAL		8
#define ARGUS_MAR_STATUS_INTERVAL		9
#define ARGUS_CAPTURE_DATA_LEN			10
#define ARGUS_GENERATE_START_RECORDS		11
#define ARGUS_GENERATE_RESPONSE_TIME_DATA	12
#define ARGUS_GENERATE_JITTER_DATA		13
#define ARGUS_GENERATE_MAC_DATA			14
#define ARGUS_DEBUG_LEVEL			15
#define ARGUS_FILTER_OPTIMIZER			16
#define ARGUS_FILTER				17
#define ARGUS_PACKET_CAPTURE_FILE		18
#define ARGUS_PACKET_CAPTURE_ON_ERROR		19
#define ARGUS_BIND_IP				20
#define ARGUS_MIN_SSF				21
#define ARGUS_MAX_SSF				22
#define ARGUS_COLLECTOR				23
#define ARGUS_FLOW_TYPE				24
#define ARGUS_FLOW_KEY				25
#define ARGUS_GENERATE_APPBYTE_METRIC		26
#define ARGUS_CHROOT_DIR			27
#define ARGUS_SETUSER_ID			28
#define ARGUS_SETGROUP_ID			29
#define ARGUS_GENERATE_TCP_PERF_METRIC		30
#define ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS 31
#define ARGUS_GENERATE_PACKET_SIZE		32
#define ARGUS_ENV				33
#define ARGUS_CAPTURE_FULL_CONTROL_DATA         34
#define ARGUS_SELF_SYNCHRONIZE                  35
#define ARGUS_EVENT_DATA                        36
#define ARGUS_JITTER_HISTOGRAM                  37
#define ARGUS_OUTPUT_STREAM                     38
#define ARGUS_KEYSTROKE				39
#define ARGUS_KEYSTROKE_CONF			40
#define ARGUS_TUNNEL_DISCOVERY			41
#define ARGUS_IP_TIMEOUT			42
#define ARGUS_TCP_TIMEOUT			43
#define ARGUS_ICMP_TIMEOUT			44
#define ARGUS_IGMP_TIMEOUT			45
#define ARGUS_FRAG_TIMEOUT			46
#define ARGUS_ARP_TIMEOUT			47
#define ARGUS_OTHER_TIMEOUT			48
#define ARGUS_TRACK_DUPLICATES			49
#define ARGUS_PCAP_BUF_SIZE			50


char *ArgusResourceFileStr [ARGUS_RCITEMS] = {
   "ARGUS_DAEMON=",
   "ARGUS_MONITOR_ID=",
   "ARGUS_ACCESS_PORT=",
   "ARGUS_INTERFACE=",
   "ARGUS_OUTPUT_FILE=",
   "ARGUS_SET_PID=",
   "ARGUS_PID_PATH=",
   "ARGUS_GO_PROMISCUOUS=",
   "ARGUS_FLOW_STATUS_INTERVAL=",
   "ARGUS_MAR_STATUS_INTERVAL=",
   "ARGUS_CAPTURE_DATA_LEN=",
   "ARGUS_GENERATE_START_RECORDS=",
   "ARGUS_GENERATE_RESPONSE_TIME_DATA=",
   "ARGUS_GENERATE_JITTER_DATA=",
   "ARGUS_GENERATE_MAC_DATA=",
   "ARGUS_DEBUG_LEVEL=",
   "ARGUS_FILTER_OPTIMIZER=",
   "ARGUS_FILTER=",
   "ARGUS_PACKET_CAPTURE_FILE=",
   "ARGUS_PACKET_CAPTURE_ON_ERROR=",
   "ARGUS_BIND_IP=",
   "ARGUS_MIN_SSF=",
   "ARGUS_MAX_SSF=",
   "ARGUS_COLLECTOR=",
   "ARGUS_FLOW_TYPE=",
   "ARGUS_FLOW_KEY=",
   "ARGUS_GENERATE_APPBYTE_METRIC=",
   "ARGUS_CHROOT_DIR=",
   "ARGUS_SETUSER_ID=",
   "ARGUS_SETGROUP_ID=",
   "ARGUS_GENERATE_TCP_PERF_METRIC=",
   "ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS=",
   "ARGUS_GENERATE_PACKET_SIZE=",
   "ARGUS_ENV=",
   "ARGUS_CAPTURE_FULL_CONTROL_DATA=",
   "ARGUS_SELF_SYNCHRONIZE=",
   "ARGUS_EVENT_DATA=",
   "ARGUS_JITTER_HISTOGRAM=",
   "ARGUS_OUTPUT_STREAM=",
   "ARGUS_KEYSTROKE=",
   "ARGUS_KEYSTROKE_CONF=",
   "ARGUS_TUNNEL_DISCOVERY=",
   "ARGUS_IP_TIMEOUT=",
   "ARGUS_TCP_TIMEOUT=",
   "ARGUS_ICMP_TIMEOUT=",
   "ARGUS_IGMP_TIMEOUT=",
   "ARGUS_FRAG_TIMEOUT=",
   "ARGUS_ARP_TIMEOUT=",
   "ARGUS_OTHER_TIMEOUT=",
   "ARGUS_TRACK_DUPLICATES=",
   "ARGUS_PCAP_BUF_SIZE=",
};



extern pcap_dumper_t *ArgusPcapOutFile;
extern char *ArgusWriteOutPacketFile;

void
ArgusParseResourceFile (struct ArgusModelerStruct *model, char *file)
{
   FILE *fd;
   char strbuf[MAXSTRLEN], *str = strbuf, *optarg;
   char result[MAXSTRLEN], *qptr = NULL;
   int i, len, done = 0, linenum = 0;
   int interfaces = 0, outputfiles = 0;

   if (file) {
      if ((fd = fopen (file, "r")) != NULL) {
         while ((fgets(str, MAXSTRLEN, fd)) != NULL)  {
            done = 0;
            linenum++;
            while (*str && isspace((int)*str))
                str++;
 
            if (*str && (*str != '#') && (*str != '\n') && (*str != '!')) {

               for (i = 0; i < ARGUS_RCITEMS && !done; i++) {
                  len = strlen(ArgusResourceFileStr[i]);
                  if (!(strncmp (str, ArgusResourceFileStr[i], len))) {
                     int quoted = 0;
                     optarg = &str[len];

                     if (*optarg == '\"') {
                        optarg++; 
                        if ((qptr = strchr(optarg, '"')) != NULL)
                           *qptr++ = '\0';
                        else
                           ArgusLog (LOG_ERR, "ArgusParseResourceFile(%s) string unterminated at line %d\n", file, linenum);
                        quoted = 1; 
                     }

// deal with potential embedded comments
                     if (!quoted) {
                        if (((qptr = strstr(optarg, " //")) != NULL) ||
                            ((qptr = strstr(optarg, "\t//")) != NULL))
                           *qptr++ = '\0';
                     }

                     while (optarg[strlen(optarg) - 1] == '\n')
                        optarg[strlen(optarg) - 1] = '\0';

                     switch (i) {
                        case ARGUS_DAEMON: 
                           if (!(strncasecmp(optarg, "yes", 3)))
                              ArgusDaemon = 1;
                           else
                              ArgusDaemon = 0;
                           break;

                        case ARGUS_MONITOR_ID: 
                           if (optarg && quoted) {   // Argus ID is a string.  Limit to date is 4 characters.
                              int slen = strlen(optarg);
                              if (slen > 4) optarg[4] = '\0';
                              setArgusID (ArgusSourceTask, optarg, ARGUS_TYPE_STRING);

                           } else {
                           if (optarg && (*optarg == '`')) {
                              char *ptr = NULL;
                              char *tptr = strchr((optarg + 1), '`');

                              if (tptr != NULL) {
                                 FILE *fd;

                                 optarg++;
                                 *tptr = '\0';
                                 if (!(strcmp (optarg, "hostname"))) {
                                    if ((fd = popen("hostname", "r")) != NULL) {
                                       ptr = NULL;
                                       clearerr(fd);
                                       while ((ptr == NULL) && !(feof(fd)))
                                          ptr = fgets(result, MAXSTRLEN, fd);

                                       if (ptr == NULL)
                                          ArgusLog (LOG_ERR, "ArgusParseResourceFile(%s) `hostname` failed %s.\n", file, strerror(errno));

                                       optarg = ptr;
                                       optarg[strlen(optarg) - 1] = '\0';
                                       pclose(fd);

                                       if ((ptr = strstr(optarg, ".local")) != NULL) {
                                          if (strlen(ptr) == strlen(".local"))
                                             *ptr = '\0';
                                       }

                                    } else
                                       ArgusLog (LOG_ERR, "ArgusParseResourceFile(%s) System error: popen() %s\n", file, strerror(errno));
                                 } else
                                    ArgusLog (LOG_ERR, "ArgusParseResourceFile(%s) unsupported command `%s` at line %d.\n", file, optarg, linenum);
                              } else
                                 ArgusLog (LOG_ERR, "ArgusParseResourceFile(%s) syntax error line %d\n", file, linenum);
                           }
                           ArgusParseSourceID(ArgusSourceTask, optarg);
                           }

                           break;
                           
                        case ARGUS_ACCESS_PORT:
                           setArgusPortNum(ArgusOutputTask, atoi(optarg));
                           break;

                        case ARGUS_OUTPUT_FILE:
                        case ARGUS_OUTPUT_STREAM: {
                           char *ptr = NULL;
                           if ((ptr = strchr (optarg, '"')) != NULL)
                              *ptr = '\0';

                           if ((ptr = strchr (optarg, ' ')) != NULL) {
                              *ptr++ = '\0';
                           }
                   
                           if (!outputfiles++)
                              clearArgusWfile();
                           setArgusWfile (optarg, ptr);
                           break;
                        }

                        case ARGUS_INTERFACE:
                           if (!interfaces++)
                              clearArgusDevice(ArgusSourceTask);
                           setArgusDevice (ArgusSourceTask, optarg, ARGUS_LIVE_DEVICE, 0);
                           break;

                        case ARGUS_SET_PID:
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArguspidflag  (1);
                           else
                              setArguspidflag  (0);
                           break;

                        case ARGUS_PID_PATH: {
                           ArgusPidPath = strdup(optarg);
                           break;
                        }

                        case ARGUS_GO_PROMISCUOUS:
                           if ((strncasecmp(optarg, "yes", 3)))
                              setArguspflag  (ArgusSourceTask, 1);
                           else
                              setArguspflag  (ArgusSourceTask, 0);
                           break;

                        case ARGUS_FLOW_STATUS_INTERVAL:
                           setArgusFarReportInterval (model, optarg);
                           break;

                        case ARGUS_MAR_STATUS_INTERVAL:
                           setArgusMarReportInterval (ArgusOutputTask, optarg);
                           break;

                        case ARGUS_CAPTURE_DATA_LEN:
                           setArgusUserDataLen (model, atoi(optarg));
                           if (getArgusSnapLen(ArgusSourceTask) != ARGUS_MAXSNAPLEN)
                              setArgusSnapLen (ArgusSourceTask, atoi(optarg) + ARGUS_MINSNAPLEN);
                           break;

                        case ARGUS_GENERATE_START_RECORDS: {
                           extern int ArgusGenerateStartRecords;

                           if ((!strncasecmp(optarg, "yes", 3)))
                              ArgusGenerateStartRecords++;
                           else
                              ArgusGenerateStartRecords = 0;
                           break;
                        }

                        case ARGUS_GENERATE_RESPONSE_TIME_DATA:
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusResponseStatus  (model, 1);
                           else
                              setArgusResponseStatus  (model, 0);
                           break;

                        case ARGUS_GENERATE_JITTER_DATA:
                           if (!(strncasecmp(optarg, "yes", 3))) {
#if !defined(HAVE_XDR)
                           ArgusLog (LOG_ERR, "Jitter data generation not supported\n");
#endif
                              setArgusGenerateTime  (model, 1);
                           } else
                              setArgusGenerateTime  (model, 0);
                           break;

                        case ARGUS_GENERATE_MAC_DATA:
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusmflag (model, 1);
                           else
                              setArgusmflag (model, 0);
                           break;

                        case ARGUS_DEBUG_LEVEL:
                           setArgusdflag (model, atoi(optarg));
                           break;
                        
                        case ARGUS_FILTER_OPTIMIZER:
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusOflag  (ArgusSourceTask, 1);
                           else
                              setArgusOflag  (ArgusSourceTask, 0);
                           break;

                        case ARGUS_FILTER:
                           if ((ArgusSourceTask->ArgusInputFilter = ArgusCalloc (1, MAXSTRLEN)) != NULL) {
                              char *ptr = ArgusSourceTask->ArgusInputFilter;
                              str = optarg;
                              while (*str) {
                                 if ((*str == '\\') && (str[1] == '\n')) {
                                    if (fgets(str, MAXSTRLEN, fd) != NULL)
                                       while (*str && (isspace((int)*str) && (str[1] && isspace((int)str[1]))))
                                          str++;
                                 }
                                 
                                 if ((*str != '\n') && (*str != '"'))
                                    *ptr++ = *str++;
                                 else
                                    str++;
                              }
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusParseResourceFile: ArgusFilter \"%s\" \n", ArgusSourceTask->ArgusInputFilter);
#endif 
                           }
                           break;

                        case ARGUS_PACKET_CAPTURE_FILE:
                           if (*optarg != '\0') {
                              setArgusWriteOutPacketFile (ArgusSourceTask, optarg);
                              ArgusSourceTask->ArgusDumpPacket = 1;
                           }
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusParseResourceFile: ArgusPacketCaptureFile \"%s\" \n", ArgusSourceTask->ArgusWriteOutPacketFile);
#endif 
                           break;

                        case ARGUS_PACKET_CAPTURE_ON_ERROR:
                           if (!(strncasecmp(optarg, "yes", 3))) {
                              ArgusSourceTask->ArgusDumpPacketOnError = 1;
                              ArgusSourceTask->ArgusDumpPacket = 0;
                           } else {
                              ArgusSourceTask->ArgusDumpPacketOnError = 0;
                           }
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusParseResourceFile: ArgusPacketCaptureOnError \"%s\" \n", optarg);
#endif
                           break;


                        case ARGUS_BIND_IP:
                           if (*optarg != '\0')
                              setArgusBindAddr (ArgusOutputTask, optarg);
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusParseResourceFile: ArgusBindAddr \"%s\" \n", ArgusBindAddr);
#endif 
                           break;

                        case ARGUS_MIN_SSF:
                           if (*optarg != '\0') {
#ifdef ARGUS_SASL
                              ArgusMinSsf = atoi(optarg);
#ifdef ARGUSDEBUG
                           ArgusDebug (1, "ArgusParseResourceFile: ArgusMinSsf \"%d\" \n", ArgusMinSsf);
#endif 
#endif 
                           }
                           break;

                        case ARGUS_MAX_SSF:
                           if (*optarg != '\0') {
#ifdef ARGUS_SASL
                              ArgusMaxSsf = atoi(optarg);
#ifdef ARGUSDEBUG
                              ArgusDebug (1, "ArgusParseResourceFile: ArgusMaxSsf \"%d\" \n", ArgusMaxSsf);
#endif 
#endif 
                           }
                           break;

                        case ARGUS_SELF_SYNCHRONIZE:
                           if (!(strncasecmp(optarg, "yes", 3))) {
                              setArgusSynchronize (ArgusModel, 1);
                           } else {
                              setArgusSynchronize (ArgusModel, 0);
                           }
                           break;

                        case ARGUS_EVENT_DATA: {
                           setArgusEventDataRecord (optarg);
                           break;
                        }

                        case ARGUS_COLLECTOR:
                           break;

                        case ARGUS_FLOW_TYPE:
                           if (!(strncasecmp(optarg, "Uni", 3)))
                              setArgusFlowType (model, ARGUS_UNIDIRECTIONAL);
                           else
                           if (!(strncasecmp(optarg, "Bi", 2)))
                              setArgusFlowType (model, ARGUS_BIDIRECTIONAL);
                           break;

                        case ARGUS_FLOW_KEY: {
                           char *tok = NULL;

                           while ((tok = strtok(optarg, " +\t")) != NULL) {
                              if (!(strncasecmp(tok, "CLASSIC_5_TUPLE", 14)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_CLASSIC5TUPLE);
                              else
                              if (!(strncasecmp(tok, "LAYER_2", 10)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_LAYER_2);
                              else
                              if (!(strncasecmp(tok, "LOCAL_MPLS", 10)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_LOCAL_MPLS);
                              else
                              if (!(strncasecmp(tok, "COMPLETE_MPLS", 10)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_COMPLETE_MPLS);
                              else
                              if (!(strncasecmp(tok, "VLAN", 4)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_VLAN);
                              else
                              if (!(strncasecmp(tok, "LAYER_2_MATRIX", 14)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_LAYER_2_MATRIX);
                              else
                              if (!(strncasecmp(tok, "LAYER_3_MATRIX", 14)))
                                 setArgusFlowKey (model, ARGUS_FLOW_KEY_LAYER_3_MATRIX);

                              optarg = NULL;
                           }
                           break;
                        }

                        case ARGUS_CAPTURE_FULL_CONTROL_DATA:
                           if (!(strncasecmp(optarg, "yes", 3))) {
                              setArgusCaptureFlag(ArgusSourceTask, 1);
                              setArgusControlMonitor(ArgusModel);
                              setArgusSnapLen(ArgusSourceTask, ARGUS_MAXSNAPLEN);
                           } else {
                              setArgusCaptureFlag (ArgusSourceTask, 0);
                           }
                           break;

                        case ARGUS_GENERATE_TCP_PERF_METRIC: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusTCPflag(model, 1);
                           else
                              setArgusTCPflag(model, 0);
                           break;
                        }

                        case ARGUS_GENERATE_BIDIRECTIONAL_TIMESTAMPS: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusTimeReport(model, 1);
                           else
                              setArgusTimeReport(model, 0);
                           break;
                        }

                        case ARGUS_GENERATE_APPBYTE_METRIC: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusAflag(model, 1);
                           else
                              setArgusAflag(model, 0);
                           break;
                        }

                        case ARGUS_GENERATE_PACKET_SIZE: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusGeneratePacketSize(model, 1);
                           else
                              setArgusGeneratePacketSize(model, 0);
                           break;
                        }

                        case ARGUS_CHROOT_DIR: {
                           if (chroot_dir != NULL)
                              free(chroot_dir);
                           chroot_dir = strdup(optarg);
                           break;
                        }
                        case ARGUS_SETUSER_ID: {
                           struct passwd *pw;
                           if ((pw = getpwnam(optarg)) == NULL)
                              ArgusLog (LOG_ERR, "unknown user \"%s\"\n", optarg);
                           new_uid = pw->pw_uid;
                           endpwent();
                           break;
                        }
                        case ARGUS_SETGROUP_ID: {
                           struct group *gr;
                           if ((gr = getgrnam(optarg)) == NULL)
                               ArgusLog (LOG_ERR, "unknown group \"%s\"\n", optarg);
                           new_gid = gr->gr_gid;
                           endgrent();
                           break;
                        }
                        case ARGUS_ENV: {
                           if (putenv(optarg))
                              ArgusLog (LOG_ERR, "Argus set env \"%s\" error %s\n", optarg, strerror(errno));
                           break;
                        }
                        case ARGUS_KEYSTROKE: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusKeystroke(model, ARGUS_TCP_KEYSTROKE);
                           else 
                           if (!(strncasecmp(optarg, "tcp", 3)))
                              setArgusKeystroke(model, ARGUS_TCP_KEYSTROKE);
                           else 
                           if (!(strncasecmp(optarg, "ssh", 3)))
                              setArgusKeystroke(model, ARGUS_SSH_KEYSTROKE);
                           else 
                              setArgusKeystroke(model, 0);

                           if (getArgusKeystroke(model)) {
                              model->ArgusKeyStroke.n_min   = 23;
                              model->ArgusKeyStroke.dc_min  = 48;
                              model->ArgusKeyStroke.dc_max  = 128; 
                              model->ArgusKeyStroke.gs_max  = 3;
                              model->ArgusKeyStroke.ds_min  = 24; 
                              model->ArgusKeyStroke.ds_max  = 256; 
                              model->ArgusKeyStroke.gpc_max = 3;
                              model->ArgusKeyStroke.ic_min  = 50000; 
                              model->ArgusKeyStroke.lcs_max = 50000;
                              model->ArgusKeyStroke.icr_min = 0.892; 
                              model->ArgusKeyStroke.icr_max = 1.122;
                           }  
                           break;
                        }

                        case ARGUS_KEYSTROKE_CONF: {
                           char tokbuf[MAXSTRLEN], *ksptr = tokbuf, *kstok, *brkt;

#if defined(HAVE_STRLCPY)
                           strlcpy(tokbuf, optarg, MAXSTRLEN - 1);
#else
                           strncpy(tokbuf, optarg, MAXSTRLEN - 1);
#endif
                           while ((kstok = strtok_r(ksptr, ";", &brkt)) != NULL) {
                              setArgusKeystrokeVariable(model, kstok);
                              ksptr = NULL;
                           }
                           break;
                        }

                        case ARGUS_TUNNEL_DISCOVERY: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusTunnelDiscovery(model, 1);
                           else
                              setArgusTunnelDiscovery(model, 0);
                           break;
                        }
                        case ARGUS_TRACK_DUPLICATES: {
                           if (!(strncasecmp(optarg, "yes", 3)))
                              setArgusTrackDuplicates(model, 1);
                           else
                              setArgusTrackDuplicates(model, 0);
                           break;
                        }
                        case ARGUS_IP_TIMEOUT: {
                           setArgusIpTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_TCP_TIMEOUT: {
                           setArgusTcpTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_ICMP_TIMEOUT: {
                           setArgusIcmpTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_IGMP_TIMEOUT: {
                           setArgusIgmpTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_FRAG_TIMEOUT: {
                           setArgusFragTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_ARP_TIMEOUT: {
                           setArgusArpTimeout (model, atoi(optarg));
                           break;
                        }
                        case ARGUS_OTHER_TIMEOUT: {
                           setArgusOtherTimeout (model, atoi(optarg));
                           break;
                        }

                        case ARGUS_PCAP_BUF_SIZE: {
                           int size = atoi(optarg);
                           if (size > 0) {
                              if (strchr(optarg, 'K')) size *= 1000;
                              if (strchr(optarg, 'M')) size *= 1000000;
                              if (strchr(optarg, 'G')) size *= 1000000000;

                              setArgusPcapBufSize (ArgusSourceTask, size);
                           }
                           break;
                        }
                     }

                     done = 1;
                     break;
                  }
               }
            }
         }

         fclose (fd);

      } else {
#ifdef ARGUSDEBUG
         ArgusDebug (1, "ArgusParseResourceFile: open %s %s\n", file, strerror(errno));
#endif 
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusParseResourceFile (%s) returning\n", file);
#endif 

}

void
clearArgusConfiguration (struct ArgusModelerStruct *model)
{
   daemonflag = 0;
   setArgusID (ArgusSourceTask, 0, 0);
   clearArgusWfile ();
   clearArgusDevice (ArgusSourceTask);
   setArgusPortNum(ArgusOutputTask, 0);
   setArgusBindAddr (ArgusOutputTask, NULL);
   setArguspidflag  (0);
   setArguspflag  (ArgusSourceTask, 0);
   setArgusFarReportInterval (model, ARGUS_FARSTATUSTIMER);
   setArgusMarReportInterval (ArgusOutputTask, ARGUS_MARSTATUSTIMER);
   setArgusUserDataLen (model, 0);
   setArgusSnapLen (ArgusSourceTask, ARGUS_MINSNAPLEN);
   setArgusResponseStatus (model, 0);
   setArgusGenerateTime (model, 0);
   setArgusmflag (model, 0);
   setArgusOflag (ArgusSourceTask, 1);
   setArgusCaptureFlag (ArgusSourceTask, 0);
   setArgusAflag(model, 0);
   setArgusTimeReport(model, 0);

   if (ArgusSourceTask->ArgusWriteOutPacketFile) {
      if (ArgusSourceTask->ArgusPcapOutFile != NULL) {
         pcap_dump_close(ArgusSourceTask->ArgusPcapOutFile);
         ArgusSourceTask->ArgusPcapOutFile = NULL;
      }
      ArgusSourceTask->ArgusWriteOutPacketFile = NULL;
   }

   if (ArgusSourceTask->ArgusInputFilter) {
      ArgusFree(ArgusSourceTask->ArgusInputFilter);
      ArgusSourceTask->ArgusInputFilter = NULL;
   }

#ifdef ARGUSDEBUG
   ArgusDebug (1, "clearArgusConfiguration () returning\n");
#endif 
}

int
getArgusPortNum(struct ArgusOutputStruct *output)
{
   return(output->ArgusPortNum);
}
 
void
setArgusPortNum(struct ArgusOutputStruct *output, int value)
{
   output->ArgusPortNum = value;

#ifdef ARGUSDEBUG
   ArgusDebug (2, "setArgusPortNum(%d) returning\n", value);
#endif
}


void
clearArgusWfile(void)
{
   ArgusDeleteList (ArgusOutputTask->ArgusWfileList, ARGUS_WFILE_LIST);
   ArgusOutputTask->ArgusWfileList = NULL;
}

void
setArgusWfile(char *file, char *filter)
{
   struct ArgusWfileStruct *wfile = NULL;

   if (ArgusOutputTask->ArgusWfileList == NULL)
      ArgusOutputTask->ArgusWfileList = ArgusNewList();

   if (file) {
      if ((wfile = (struct ArgusWfileStruct *) ArgusCalloc (1, sizeof (*wfile))) != NULL) {
         wfile->filename = strdup(file);
         if (filter)
            wfile->filter = strdup(filter);
         ArgusPushFrontList(ArgusOutputTask->ArgusWfileList, (struct ArgusListRecord *) wfile, ARGUS_LOCK);

      } else
         ArgusLog (LOG_ERR, "setArgusWfile, ArgusCalloc %s\n", strerror(errno));
   } else
      ArgusLog (LOG_ERR, "setArgusWfile, file is null\n");
}

 
void
ArgusUsr1Sig (int sig)
{
#ifdef ARGUSDEBUG
   int value = 0, i;
   Argusdflag = (Argusdflag++ > 30) ? 30 : Argusdflag;
 
   if (Argusdflag == 1) {
      struct ArgusSourceStruct *src;
      
      for (i = 0; i < ARGUS_MAXINTERFACE; i++) {
         if ((src = ArgusSourceTask->srcs[i]) != NULL) {
            struct ArgusModelerStruct *model = src->ArgusModel;
            if ((value = getArgusKeystroke(model)) > 0) {
               ArgusDebug (0, "ArgusKeyStroke model[%d] %s: DC_MIN=%d, DC_MAX=%d, GS_MAX=%d, DS_MIN=%d, DS_MAX=%d, IC_MIN=%d, LCS_MAX=%d, GPC_MAX=%d, ICR_MIN=%f, ICR_MAX=%f\n", 
                  i, (value == ARGUS_TCP_KEYSTROKE) ? "\"tcp\"" : ((value == ARGUS_SSH_KEYSTROKE) ? "\"ssh\"" : "\"unknown\""),
                  model->ArgusKeyStroke.dc_min,
                  model->ArgusKeyStroke.dc_max,
                  model->ArgusKeyStroke.gs_max,
                  model->ArgusKeyStroke.ds_min,
                  model->ArgusKeyStroke.ds_max,
                  model->ArgusKeyStroke.ic_min,
                  model->ArgusKeyStroke.lcs_max,
                  model->ArgusKeyStroke.gpc_max,
                  model->ArgusKeyStroke.icr_min,
                  model->ArgusKeyStroke.icr_max);
            }
         }
      }
   }

   ArgusDebug (0, "ArgusUsr1Sig: debug %d enabled\n", Argusdflag);
#endif
}
 
void
ArgusUsr2Sig (int sig)
{
#ifdef ARGUSDEBUG
   Argusdflag = 0;
 
   ArgusDebug (0, "ArgusUsr2Sig: debug disabled\n");
#endif
}
 
int
getArgusControlMonitor (struct ArgusModelerStruct *model)
{
   return (model->ArgusControlMonitor);
}

void
setArgusControlMonitor (struct ArgusModelerStruct *model)
{
   model->ArgusControlMonitor++;
}


void
clearArgusEventRecord(void)
{
   ArgusDeleteList (ArgusEventsTask->ArgusEventsList, ARGUS_EVENT_LIST);
   ArgusEventsTask->ArgusEventsList = NULL;
}


/* 
   Syntax is:  "method:pathname:interval:postprocessor"
       Where:  method = [ "file" | "prog" ]
             pathname = %s
             interval = %d
             postproc = [ "compress" | "encrypt" | "none" ]
*/


void
setArgusEventDataRecord (char *ptr)
{
   struct ArgusEventRecordStruct *event = NULL;
   char *sptr, *method = NULL, *file = NULL;
   char *tok = NULL, *pp = NULL, *tptr = NULL;
   int ind = 0, interval, elem = 0;

   if (ArgusEventsTask == NULL)
      ArgusEventsTask = ArgusNewEvents();

   if (ArgusEventsTask->ArgusEventsList == NULL)
      ArgusEventsTask->ArgusEventsList = ArgusNewList();

   if (ptr) {
      int i;
      sptr = strdup(ptr);
      while ((tok = strtok(sptr, ":")) != NULL) {
         switch (ind++) {
            case 0:   
               method = tok;
               if (!((strncmp(method, "file", 4) == 0) || (strncmp(method, "prog", 4) == 0)))
                  ArgusLog (LOG_ERR, "setArgusEventDataRecord, syntax error %s\n", ptr);
               elem++;
               break;
            case 1:
               file = tok; elem++;
               break;
            case 2:
               interval = strtol(tok, (char **)&tptr, 10);
               if (tptr == tok)
                  ArgusLog (LOG_ERR, "setArgusEventDataRecord, syntax error %s\n", ptr);
               i = *tptr;
               if (strlen(tptr) && (isalpha(i))) {
                  switch (*tptr) {
                     case 's': break;
                     case 'm': interval *= 60; break;
                     case 'h': interval *= 60 * 60; break;
                     case 'd': interval *= 60 * 60 * 24; break;
                     case 'w': interval *= 60 * 60 * 24 * 7; break;
                     case 'M': interval *= 60 * 60 * 24 * 30; break;
                     case 'y': interval *= 60 * 60 * 24 * 365; break;
                  }
               }
               elem++;
               break;
            case 3:
               pp = tok;
               if (!((strncmp(pp, "compress", 8) == 0) || (strncmp(pp, "compress2", 9) == 0)))
                  ArgusLog (LOG_ERR, "setArgusEventDataRecord, syntax error %s\n", ptr);
               elem++;
               break;
            default:
               ArgusLog (LOG_ERR, "setArgusEventDataRecord, syntax error %s\n", ptr);
               break;
         }
         sptr = NULL;
      }

      if (elem < 3)
         ArgusLog (LOG_ERR, "setArgusEventDataRecord, syntax error %s\n", ptr);

      free (sptr);
      
      if ((event = (struct ArgusEventRecordStruct *) ArgusCalloc (1, sizeof (*event))) != NULL) {
         event->entry    = strdup(ptr);
         event->method   = strdup(method);
         event->filename = strdup(file);
         event->interval = interval;
         if (pp != NULL) {
            if (!(strncmp(pp, "compress", 8)))
               event->status |= ARGUS_ZLIB_COMPRESS;
            if (!(strncmp(pp, "compress2", 9)))
               event->status |= ARGUS_ZLIB_COMPRESS2;
         }
  
         ArgusPushFrontList(ArgusEventsTask->ArgusEventsList, (struct ArgusListRecord *) event, ARGUS_LOCK);

      } else
         ArgusLog (LOG_ERR, "setArgusEventDataRecord, ArgusCalloc %s\n", strerror(errno));
   } else
      ArgusLog (LOG_ERR, "setArgusEventDataRecord, event is null\n");

#ifdef ARGUSDEBUG
   ArgusDebug (2, "setArgusEventDataRecord(%s)\n", ptr);
#endif
}

void
setArgusArgv(struct ArgusSourceStruct *src, char **value)
{
   src->ArgusArgv = value;
}

void
setArgusOptind (struct ArgusSourceStruct *src, int value)
{
   src->ArgusOptind = value;
}

void
setArgusCmdBuf (struct ArgusSourceStruct *src)
{
   ArgusSourceTask->ArgusCmdBuf = ArgusCopyArgv(&src->ArgusArgv[src->ArgusOptind]);
}

char *
ArgusCopyArgv (char **argv)
{
   char **p;
   int len = 0;
   char *buf = NULL, *src, *dst;

   p = argv;
   if (*p == 0) return 0;

   while (*p) len += (int) strlen (*p++) + 1;

   if ((buf = (char *) malloc (len)) != NULL) {
      p = argv;
      dst = buf;
      while ((src = *p++) != NULL) {
         if (*src != '-') {
            while ((*dst++ = *src++) != '\0') ;
            dst[-1] = ' ';
         }
      }

      dst[-1] = '\0';
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusCopyArgv(%p) returning %p\n", argv, buf);
#endif

   return buf;
}

