/*
 * Gargoyle Software.  Argus files - main argus includes
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
 * $Id: //depot/gargoyle/argus/argus/argus.h#6 $
 * $DateTime: 2016/10/03 10:48:03 $
 * $Change: 3210 $
 */


/*  argus.h */

#include <sys/types.h>
#include <pwd.h>
#include <grp.h>

#ifndef Argus_h
#define Argus_h

#include <argus_compat.h>
#include <argus_def.h>
#include <ArgusModeler.h>
#include <ArgusUtil.h>
#include <ArgusEvents.h>
#include <ArgusOutput.h>
#include <ArgusSource.h>

#if defined(ARGUS_NANOSECONDS)
#define ARGUS_FRACTION_TIME      1000000000
#else
#define ARGUS_FRACTION_TIME      1000000
#endif


#define MINOR_VERSION_0    0
#define MINOR_VERSION_1    1
#define MINOR_VERSION_2    2
#define MINOR_VERSION_3    3
#define MINOR_VERSION_4    4
#define MINOR_VERSION_5    5
#define MINOR_VERSION_6    6
#define MINOR_VERSION_7    7
#define MINOR_VERSION_8    8
#define MINOR_VERSION_9    9

#define MAJOR_VERSION_1    1
#define MAJOR_VERSION_2    2
#define MAJOR_VERSION_3    3
#define MAJOR_VERSION_4    4
#define MAJOR_VERSION_5    5
#define MAJOR_VERSION_6    6

#define VERSION_MAJOR      MAJOR_VERSION_5
#define VERSION_MINOR      MINOR_VERSION_0


#if defined(Argus)

#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/time.h>

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN		BUFSIZ
#endif

#if defined(ARGUS_THREADS)
pthread_mutex_t ArgusMainLock;
#endif

char *RaTimeFormat = "%d %b %y %T";
char RaFieldDelimiter = '.';
int nflag = 1, Nflag = -1, uflag = 1, gflag = 0;
int Uflag = 6, XMLflag = 0, pflag = 0, pidflag = 0;

int Dflag = 0, daemonflag = 0;

uid_t new_uid = 0;
gid_t new_gid = 0;

char *chroot_dir = NULL;

int Argusdflag = 0;
int ArgusUid = 0;
int ArgusGid = 0;
int ArgusShutDownStarted = 0;

int ArgusPortNum = 0;

void ArgusUsr1Sig (int);
void ArgusUsr2Sig (int);

#if defined(ARGUS_SASL)
int ArgusMaxSsf = 0;
int ArgusMinSsf = 0;
#endif

char *ArgusProgramName = NULL;
void ArgusLoop (void);
void ArgusShutDown (int);
void ArgusScheduleShutDown (int);

void usage(void);
void ArgusLog (int, char *, ...);
void ArgusComplete (void);

void setArguspidflag (int);
int getArguspidflag (void);

void setArgusArgv(struct ArgusSourceStruct *, char **);
void setArgusOptind(struct ArgusSourceStruct *, int);
void setArgusCmdBuf(struct ArgusSourceStruct *);
char *ArgusCopyArgv (char **);

void  clearArgusWfile(void);
void clearArgusEventRecord(void);


char *ArgusBindAddr = NULL;
struct ArgusListStruct *ArgusWfileList = NULL;


#else /* defined(Argus) */

#if defined(ARGUS_THREADS)
extern pthread_mutex_t ArgusMainLock;
#endif

extern int Argusdflag;

extern char *ArgusProgramName;
extern void ArgusLoop (void);
extern void ArgusShutDown (int);
extern void ArgusScheduleShutDown (int);

extern int nflag, Nflag, uflag, gflag;

extern int daemonflag;

extern int ArgusUid;
extern int ArgusGid;
extern int ArgusShutDownStarted;

extern char *ArgusBindAddr;

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern struct ArgusListStruct *ArgusWfileList;

#if defined(ARGUS_SASL)
extern int ArgusMaxSsf;
extern int ArgusMinSsf;
#endif

extern void usage(void);
extern void ArgusLog (int, char *, ...);
extern void ArgusComplete (void);

#endif /* defined(Argus) */
#endif /* Argus_h */
