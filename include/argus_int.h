/*
 * Argus Software.  Common include files - interface
 * Copyright (C) 2000-2020 QoSient, LLC.
 * All Rights Reserved
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/gargoyle/argus/include/argus_int.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#if !defined(Argus_int_h)
#define Argus_int_h

#if !defined(__STDC__)
#define const
#endif

#include <argus_os.h>		/* os dependent stuff */

#if !defined(SIGRET)
#define SIGRET void             /* default */
#endif

struct ArgusTokenStruct {
   int v;                  /* value */
   char *s;                /* string */
};
 

#define MIN_SNAPLEN 128

#if defined(ARGUS)

double update_interval = 1.0, update_time = 0.0;
int updatecounter = 0;
 
extern pcap_handler lookup_pcap_callback (void);
 
int lfd = -1;
int snaplen = MIN_SNAPLEN;

fd_set readmask, writemask, exceptmask;

pcap_t *pd = NULL;

#define ARGUS_PORT      561

#else

extern int Cflag;		/* print each ICMP packet */
extern int Rflag;		/* print each ICMP record on response for RTT */
extern int dflag;		/* print interval code */
extern int wflag;		/* write tcp connection data */
extern int nflag;		/* leave addresses as numbers*/
extern int debugflag;		/* set debug level */
extern int Nflag;               /* remove domains from printed host names */

extern double update_interval;
extern int updatecounter;

extern char *wfile;
extern char *program_name;

extern int lfd;
extern int snaplen;

extern fd_set readmask, writemask, exceptmask;
#endif

#if !defined(min)
#define min(a,b) ((a)>(b)?(b):(a))
#define max(a,b) ((b)>(a)?(b):(a))
#endif

extern char timestamp_fmt[];
extern long timestamp_scale;
extern void timestampinit(void);

extern int fn_print(const u_char *, const u_char *);
extern int fn_printn(const u_char *, u_int, const u_char *);
extern char *dnaddr_string(u_short);
extern char *savestr(const char *);

extern char *llcsap_string(u_char);
extern char *protoid_string(const u_char *);
extern char *dnname_string(u_short);
extern char *dnnum_string(u_short);

#endif /* Argus_out_h */

