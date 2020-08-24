/*
 * Argus-5.0 Software.  Argus files - main argus includes
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
 * $Id: //depot/gargoyle/argus/argus/argus.h#7 $
 * $DateTime: 2016/10/04 10:36:36 $
 * $Change: 3213 $
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

int ArgusPortNum = 0;

void ArgusUsr1Sig (int);
void ArgusUsr2Sig (int);

#if defined(ARGUS_SASL)
int ArgusMaxSsf = 0;
int ArgusMinSsf = 0;
#endif

void ArgusBacktrace (void);

char *ArgusProgramName = NULL;
void ArgusLoop (void);
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
extern void ArgusScheduleShutDown (int);

extern int nflag, Nflag, uflag, gflag;

extern int daemonflag;

extern int ArgusUid;
extern int ArgusGid;

extern char *ArgusBindAddr;

extern void ArgusUsr1Sig (int);
extern void ArgusUsr2Sig (int);

extern struct ArgusListStruct *ArgusWfileList;

#if defined(ARGUS_SASL)
extern int ArgusMaxSsf;
extern int ArgusMinSsf;
#endif

extern void ArgusBacktrace (void);

extern void usage(void);
extern void ArgusLog (int, char *, ...);
extern void ArgusComplete (void);

#endif /* defined(Argus) */
#endif /* Argus_h */
