/*
 * Argus Software
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
 * Copyright (c) 1990, 1991, 1992, 1993, 1994
 *   The Regents of the University of California.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that: (1) source code distributions
 * retain the above copyright notice and this paragraph in its entirety, (2)
 * distributions including binary code include the above copyright notice and
 * this paragraph in its entirety in the documentation or other materials
 * provided with the distribution, and (3) all advertising materials mentioning
 * features or use of this software display the following acknowledgement:
 * ``This product includes software developed by the University of California,
 * Lawrence Berkeley Laboratory and its contributors.'' Neither the name of
 * the University nor the names of its contributors may be used to endorse
 * or promote products derived from this software without specific prior
 * written permission.
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND WITHOUT ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, WITHOUT LIMITATION, THE IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE.
 */

/* 
 * $Id: //depot/argus/argus/common/argus_code.c#41 $
 * $DateTime: 2015/04/14 18:22:14 $
 * $Change: 3006 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif
#include <argus_compat.h>

#if defined(HAVE_SOLARIS) || (__FreeBSD__) || (__NetBSD__) || (__OpenBSD__)
#include <sys/types.h>
#include <sys/socket.h>
#endif

#include <unistd.h>
#include <stdio.h>

#include <sys/time.h>
#include <netinet/in.h>
#include <net/if.h>

#include <setjmp.h>
#include <stdarg.h>
#include <stdlib.h>
#include <syslog.h>

#include <argus_def.h>
#include <argus_out.h>
#include <argus_util.h>

#include <argus_parser.h>
#include <argus_filter.h>
#include <argus_dscodepoints.h>
#include <argus_encapsulations.h>
#include <argus_ethertype.h>

#include <signal.h>
#include <sys/wait.h>
/*
static u_int ArgusNetMask;
*/
static int fsnaplen;

#ifndef __GNUC__
#define inline
#endif


#ifndef AF_INET6
#define AF_INET6	23
#endif

#ifndef IPPROTO_IGRP
#define IPPROTO_IGRP    9
#endif

#define JMP(c) ((c)|NFF_JMP|NFF_K)

#define ARGUSFORKFILTER   1

static u_int off_nl = 0;

static int alloc_reg(void);
static void free_reg(int);

static struct ablock *root;


#define NCHUNKS 16
#define CHUNK0SIZE 1024

struct chunk {
   u_int n_left;
   void *m;
};

static struct chunk chunks[NCHUNKS];
static int cur_chunk;

static void *newchunk(u_int);
static void freechunks(void);
static struct ablock *new_block(int);
static struct slist *new_stmt(int);
static struct ablock *Argusgen_retblk(int);
static void syntax(void);

#if defined(ARGUSFORKFILTER)
static void deadman(pid_t);
#endif

static void backpatch(struct ablock *, struct ablock *);
static void merge(struct ablock *, struct ablock *);
static struct ablock *Argusgen_cmp(int, u_int, u_int, u_int, u_int, int);
static struct ablock *Argusgen_mcmp(int, u_int, u_int, u_int, u_int, u_int, int);
static struct ablock *Argusgen_bcmp(int, u_int, u_int, u_char *, int);
static struct ablock *Argusgen_prototype(u_int, u_int);
static struct ablock *Argusgen_hostop(u_int *, u_int *, int, int, u_int);
static struct ablock *Argusgen_ehostop(u_char *, int);
static struct ablock *Argusgen_host(u_int *, u_int *, int, int, int);
static struct ablock *Argusgen_srcid(u_int, u_int, int);
static struct ablock *Argusgen_inode(u_int, u_int, int);
static struct ablock *Argusgen_gateway(u_char *, u_int *, int, int, int);
static struct ablock *Argusgen_portatom(int, long, int);
struct ablock *Argusgen_portop(int, int, int, u_int);
static struct ablock *Argusgen_port(int, u_int, int, u_int);
static int Arguslookup_proto(char *, int);
static struct ablock *Argusgen_flow(int);
static struct ablock *Argusgen_proto(int, int, int);
static struct ablock *Argusgen_ipid(int, int, u_int);
static struct ablock *Argusgen_ttl(int, int, u_int);
static struct ablock *Argusgen_tos(int, int, u_int);
static struct ablock *Argusgen_vid(int, int, u_int);
static struct ablock *Argusgen_vpri(int, int, u_int);
static struct ablock *Argusgen_mid(int, int, u_int);
static struct ablock *Argusgen_byte(int, int, u_int);
static struct ablock *Argusgen_pkt(int, int, u_int);
static struct ablock *Argusgen_nstroke(int, int, u_int);
static struct ablock *Argusgen_seq(int, int, u_int);
//static struct ablock *Argusgen_dup(int, int, u_int);
static struct ablock *Argusgen_tcpbase(int, int, u_int);
static struct ablock *Argusgen_trans(int, int, u_int);
static struct ablock *Argusgen_deltadur(int, int, u_int);
static struct ablock *Argusgen_deltastart(int, int, u_int);
static struct ablock *Argusgen_deltalast(int, int, u_int);
static struct ablock *Argusgen_rate(float, int, u_int);
static struct ablock *Argusgen_load(float, int, u_int);
static struct ablock *Argusgen_inter(float, int, int, u_int);
static struct ablock *Argusgen_jitter(float, int, int, u_int);
static struct ablock *Argusgen_dur(float, int, u_int);
static struct ablock *Argusgen_mean(float, int, u_int);
static struct ablock *Argusgen_encaps(int, int, u_int);
static u_int net_mask(u_int *);
static struct slist *xfer_to_x(struct arth *);
static struct slist *xfer_to_a(struct arth *);
static struct ablock *Argusgen_len(int, int);
static struct ablock *Argusgen_linktype(unsigned int);

extern void ArgusLog (int, char *, ...);
extern float RaDeltaFloatTime (struct timeval *, struct timeval *);

static void *
newchunk(n)
u_int n;
{
   struct chunk *cp;
   int k, size;

   /* XXX Round up to nearest long long. */
   n = (n + sizeof(long long) - 1) & ~(sizeof(long long) - 1);

   cp = &chunks[cur_chunk];
   if (n > cp->n_left) {
      ++cp, k = ++cur_chunk;
      if (k >= NCHUNKS)
         ArgusLog(LOG_ERR, "out of memory");
      size = CHUNK0SIZE << k;
      cp->m = (void *)calloc(1, size);
      memset((char *)cp->m, 0, size);
      cp->n_left = size;
      if (n > size)
         ArgusLog(LOG_ERR, "out of memory");
   }
   cp->n_left -= n;
#if defined(ARGUSDEBUG)
   ArgusDebug (9, "newchunk (%d) returning 0x%x\n", n, (char *)cp->m + cp->n_left);
#endif
   return (void *)((char *)cp->m + cp->n_left);
}

static void
freechunks()
{
   int i;

   for (i = 0; i < NCHUNKS; ++i)
      if (chunks[i].m)
         free(chunks[i].m);
#if defined(ARGUSDEBUG)
   ArgusDebug (9, "freechunks () returning\n");
#endif
}

/*
 * A strdup whose allocations are freed after code generation is over.
 */

char *
Argussdup(s)
char *s;
{
   int n = strlen(s) + 1;
   char *cp = newchunk(n);
   strncpy(cp, s, (n - 1));
#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argussdup (%s) returning 0x%x\n", s, cp);
#endif
   return (cp);
}

static struct ablock *
new_block(code)
int code;
{
   struct ablock *p;

   p = (struct ablock *)newchunk(sizeof(*p));
   p->s.code = code;
   p->head = p;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "new_block (%d) returning 0x%x\n", code, p);
#endif
   return p;
}

static struct slist *
new_stmt(code)
int code;
{
   struct slist *p;

   p = (struct slist *)newchunk(sizeof(*p));
   p->s.code = code;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "new_stmt (%d) returning 0x%x\n", code, p);
#endif
   return p;
}

static struct ablock *
Argusgen_retblk(int v)
{
   struct ablock *b = new_block(NFF_RET|NFF_K);

   b->s.data.k = v;
#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_retblk (%d) returning 0x%x\n", v, b);
#endif
   return b;
}


#if defined(ARGUSFORKFILTER)

static void
deadman(pid_t pid)
{
// extern struct ArgusParserStruct *ArgusParser;
   char *errormsg = "ERROR: compiler timed out";

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile deadman() %s\n", errormsg);
#endif
   kill(pid, SIGTERM);

/*
   if (ArgusParser->ArgusFilterFiledes[1] != -1) {
      if ((len = write (ArgusParser->ArgusFilterFiledes[1], errormsg, strlen(errormsg))) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: write retn %s\n", strerror(errno));
      if ((len = read (ArgusParser->ArgusControlFiledes[0], &response, 1)) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: read retn %s\n", strerror(errno));
   } else
*/
   ArgusLog (LOG_INFO, errormsg);
}

#endif

static void
syntax()
{
   extern struct ArgusParserStruct *ArgusParser;
   char response, *errormsg = "SYNTAX ERROR: filter expression";
   int len;

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile syntax() %s\n", errormsg);
#endif

   if (ArgusParser->ArgusFilterFiledes[1] != -1) {
      if ((len = write (ArgusParser->ArgusFilterFiledes[1], errormsg, 4)) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: write retn %s\n", strerror(errno));

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () syntax error routine wrote %d bytes of error message\n", len);
#endif

      if ((len = read (ArgusParser->ArgusControlFiledes[0], &response, 1)) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: read retn %s\n", strerror(errno));

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () syntax error routine read %d bytes of response\n", len);
#endif

   } else
      ArgusLog (LOG_ERR, errormsg);

   exit (1);
}


char *
ArgusFilterCompile(struct nff_program *program, char *buf, int optimize)
{
   extern int argus_n_errors;
   char *retn = NULL;
   int len;

#if defined(ARGUSFORKFILTER)
   extern struct ArgusParserStruct *ArgusParser;
   int width, status = 0;
   char response;
   pid_t pid;

   if ((pipe (ArgusParser->ArgusFilterFiledes)) < 0)
      ArgusLog (LOG_ERR, "pipe %s", strerror(errno));
   if ((pipe (ArgusParser->ArgusControlFiledes)) < 0)
      ArgusLog (LOG_ERR, "pipe %s", strerror(errno));

   if ((pid = fork()) == 0) {
#endif
      fsnaplen = 96;

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () calling argus_lex_init(%s)\n", buf);
#endif
      argus_lex_init(buf ? buf : "");

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () calling argus_parse()\n");
#endif
      argus_parse();

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () argus_parse() done\n");
#endif
      if (argus_n_errors) {
         retn = "SYNTAX ERROR: in filter expression";
         len = strlen(retn);

#if defined(ARGUSDEBUG)
         ArgusDebug (4, "ArgusFilterCompile syntax() %s\n", retn);
#endif  
       } else {
         if (root == NULL)
            root = Argusgen_retblk(fsnaplen);

         if (optimize)
            Argusnff_optimize(&root);

         if (!(root == NULL || (root->s.code == (NFF_RET|NFF_K) && root->s.data.k == 0))) {
            program->bf_insns = Argusicode_to_fcode(root, &len);
            program->bf_len = len;
            freechunks();

            retn = (char *)&program->bf_len;

         } else {
            ArgusLog (LOG_ALERT, "ArgusFilterCompile: expression rejects all records");
            retn = NULL;
            len = 0;
         }
      }

#if defined(ARGUSFORKFILTER)
         if ((len = write (ArgusParser->ArgusFilterFiledes[1], retn, sizeof(program->bf_len))) < 0)
            ArgusLog (LOG_ERR, "ArgusFilterCompile: write retn %s\n", strerror(errno));
#if defined(ARGUSDEBUG)
         ArgusDebug (4, "ArgusFilterCompile () wrote %d bytes of program header", len);
#endif
      if (!(argus_n_errors)) {
         if (program->bf_len > 0) {
            if ((len = write (ArgusParser->ArgusFilterFiledes[1], program->bf_insns, program->bf_len * sizeof(*program->bf_insns))) < 0)
               ArgusLog (LOG_ERR, "ArgusFilterCompile: write filter retn %s", strerror(errno));
#if defined(ARGUSDEBUG)
            ArgusDebug (4, "ArgusFilterCompile () wrote %d bytes of program body", len);
#endif
         }
      }

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () waiting for response from requestor");
#endif
      if ((len = read (ArgusParser->ArgusControlFiledes[0], &response, 1)) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: read retn %s\n", strerror(errno));

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () received response");
#endif
      _exit(EXIT_SUCCESS);

   } else {
      struct timeval wait, now, then;
      float deltatime = 0.0;
      fd_set readmask;

      gettimeofday(&now, NULL);
      then = now;

      wait.tv_sec  = 0;
      wait.tv_usec = 500000;

      FD_ZERO (&readmask);
      FD_SET (ArgusParser->ArgusFilterFiledes[0], &readmask);
      width = ArgusParser->ArgusFilterFiledes[0] + 1;

#if defined(ARGUSDEBUG)
      ArgusDebug (4, "ArgusFilterCompile () waiting for filter process %d on pipe %d\n", pid, ArgusParser->ArgusFilterFiledes[0]);
#endif

#define ARGUS_COMPILER_TIMEOUT  1.5

      while (((deltatime = RaDeltaFloatTime(&now, &then)) <= ARGUS_COMPILER_TIMEOUT) && (select (width, &readmask, NULL, NULL, &wait) >= 0)) {
         if (deltatime >= ARGUS_COMPILER_TIMEOUT) {
            deadman(pid);
            retn = "TI";

         } else {
            if (FD_ISSET (ArgusParser->ArgusFilterFiledes[0], &readmask)) {
               if ((len = read (ArgusParser->ArgusFilterFiledes[0], &program->bf_len, sizeof(program->bf_len))) > 0) {
                  if ((!(strstr ((char *)&program->bf_len, "ERR"))) && (!(strstr ((char *)&program->bf_len, "SYN")))) {
#if defined(ARGUSDEBUG)
                     ArgusDebug (4, "ArgusFilterCompile () read filter length %d\n", program->bf_len);
#endif
                     if (program->bf_len > 0) {
                        if ((program->bf_insns = (void *) calloc (program->bf_len, sizeof(*program->bf_insns))) != NULL) {
                           if ((len = read (ArgusParser->ArgusFilterFiledes[0], program->bf_insns, (program->bf_len * sizeof(*program->bf_insns)))) > 0) {
#if defined(ARGUSDEBUG)
                              ArgusDebug (4, "ArgusFilterCompile () read filter body %d\n", len);
#endif
                              retn = 0;
                              status++;
                           }
                        } else
                           ArgusLog(LOG_ERR, "ArgusFilterCompile: calloc error %s\n", strerror(errno));
                     } else {
                        status++;
#if defined(ARGUSDEBUG)
                        ArgusDebug (4, "ArgusFilterCompile () no filter body %d\n", len);
#endif
                     }

                  } else {
                     if ((strstr ((char *)&program->bf_len, "SYN")))
                       retn = "SY";
                     else
                       retn = "ER";
#if defined(ARGUSDEBUG)
                     ArgusDebug (4, "ArgusFilterCompile () received Error from compiler\n");
#endif
                  }
               }
            }
         }

         if (status || (retn != NULL))
            break;

         FD_SET (ArgusParser->ArgusFilterFiledes[0], &readmask);
         width = ArgusParser->ArgusFilterFiledes[0] + 1; 

         wait.tv_sec  = 0; 
         wait.tv_usec = 200000;

         gettimeofday(&now, NULL);
      }

      if (!status) {
         len = waitpid(pid, &status, WNOHANG);
         if ((len == pid)  || (len == -1)) {
#if defined(ARGUSDEBUG)
            ArgusDebug (4, "ArgusFilterCompile () filter process %d terminated\n", pid);

            if (WIFEXITED(status)) {
               ArgusDebug (4, "ArgusFilterCompile () child %d exited %d\n", pid, WEXITSTATUS(status));
            } else 
            if (WIFSIGNALED(status)) {
               ArgusDebug (4, "ArgusFilterCompile () child %d signaled %d\n", pid, WTERMSIG(status));
            } else {
               ArgusDebug (4, "ArgusFilterCompile () filter process %d terminated\n", pid);
               return (NULL);
            }
#endif
            if (len == -1)
               return (NULL);
         }

      } else {
         if (retn == NULL)
            retn = "OK";
      }

      if ((len = write (ArgusParser->ArgusControlFiledes[1], retn, 2)) < 0)
         ArgusLog (LOG_ERR, "ArgusFilterCompile: write retn %s\n", strerror(errno));

// now block and wait for the child to be done
      len = waitpid(pid, &status, 0);
   }

   close(ArgusParser->ArgusFilterFiledes[0]);
   close(ArgusParser->ArgusFilterFiledes[1]);
   close(ArgusParser->ArgusControlFiledes[0]);
   close(ArgusParser->ArgusControlFiledes[1]);
   ArgusParser->ArgusFilterFiledes[0] = 0;
   ArgusParser->ArgusFilterFiledes[1] = 0;
   ArgusParser->ArgusControlFiledes[0] = 0;
   ArgusParser->ArgusControlFiledes[1] = 0;
#endif /* ARGUSFORKFILTER */

#if defined(ARGUSDEBUG)
   ArgusDebug (2, "ArgusFilterCompile () done %d\n", retn);
#endif

   return (retn);
}

/*
 * Backpatch the blocks in 'list' to 'target'.  The 'sense' field indicates
 * which of the jt and jf fields has been resolved and which is a pointer
 * back to another unresolved block (or nil).  At least one of the fields
 * in each block is already resolved.
 */

static void
backpatch(list, target)
struct ablock *list, *target;
{
   struct ablock *next;

   while (list) {
      if (!list->sense) {
         next = JT(list);
         JT(list) = target;
      } else {
         next = JF(list);
         JF(list) = target;
      }
      list = next;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "backpatch (0x%x, 0x%x) returning 0x%x\n", list, target);
#endif
}

/*
 * Merge the lists in b0 and b1, using the 'sense' field to indicate
 * which of jt and jf is the link.
 */

static void
merge( struct ablock *b0, struct ablock *b1)
{
   register struct ablock **p = &b0;

   /* Find end of list. */
   while (*p)
      p = !((*p)->sense) ? &JT(*p) : &JF(*p);

   /* Concatenate the lists. */
   *p = b1;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "merge (0x%x, 0x%x)\n", b0, b1);
#endif
}

void
Argusfinish_parse(struct ablock *p)
{
   if (p != NULL) {
      backpatch(p, Argusgen_retblk(fsnaplen));
      p->sense = !p->sense;
      backpatch(p, Argusgen_retblk(0));
      root = p->head;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (3, "Argusfinish_parse (0x%x)\n", p);
#endif
}

void
Argusgen_and(b0, b1)
struct ablock *b0, *b1;
{
   if (b0 != b1) {
      backpatch(b0, b1->head);
      b0->sense = !b0->sense;
      b1->sense = !b1->sense;
      merge(b1, b0);
      b1->sense = !b1->sense;
      b1->head = b0->head;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_and (0x%x, 0x%x)\n", b0, b1);
#endif
}

void
Argusgen_or(b0, b1)
struct ablock *b0, *b1;
{
   if (b0 != b1) {
      b0->sense = !b0->sense;
      backpatch(b0, b1->head);
      b0->sense = !b0->sense;
      merge(b1, b0);
      b1->head = b0->head;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_or (0x%x, 0x%x)\n", b0, b1);
#endif
}

void
Argusgen_not(b)
struct ablock *b;
{
   b->sense = !b->sense;

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_not (0x%x, 0x%x)\n", b);
#endif
}

static struct ablock *
Argusgen_cmp(int dsr, u_int offset, u_int size, u_int v, u_int op, int type)
{
   struct slist *s;
   struct ablock *b;

   s = new_stmt(NFF_LD|NFF_DSR|size);
   s->s.dsr = dsr;
   s->s.data.k = offset;

   switch (op) {
      case Q_EQUAL:   b = new_block(JMP(NFF_JEQ)); break;
      case Q_LESS:    b = new_block(JMP(NFF_JGE)); b->sense = !b->sense; break;
      case Q_GREATER: b = new_block(JMP(NFF_JGT)); break;
      case Q_GEQ:     b = new_block(JMP(NFF_JGE)); break;
      case Q_LEQ:     b = new_block(JMP(NFF_JGT)); b->sense = !b->sense; break;
   }
   b->stmts = s;
   b->s.data.k = v;
   b->s.type = type;

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_cmp (%d, %d, %d, %d, %d, %d) returns %p\n", dsr, offset, size, v, op, type, b);
#endif

   return b;
}

static struct ablock *
Argusgen_fcmp(int dsr, u_int offset, u_int size, float v, u_int op, int type)
{
   struct slist *s;
   struct ablock *b;

   s = new_stmt(NFF_LD|NFF_DSR|size);
   s->s.dsr = dsr;
   s->s.data.k = offset;

   switch (op) {
      case Q_EQUAL:   b = new_block(JMP(NFF_JEQ|NFF_F)); break;
      case Q_LESS:    b = new_block(JMP(NFF_JGE|NFF_F)); b->sense = !b->sense; break;
      case Q_GREATER: b = new_block(JMP(NFF_JGT|NFF_F)); break;
      case Q_GEQ:     b = new_block(JMP(NFF_JGE|NFF_F)); break;
      case Q_LEQ:     b = new_block(JMP(NFF_JGT|NFF_F)); b->sense = !b->sense; break;
   }

   b->stmts = s;
   b->s.data.f = v;

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_fcmp (%d, %d, %f, %d, %d) returns %p\n", offset, size, v, op, type, b);
#endif

   return b;
}

static struct ablock *
Argusgen_mcmp(int dsr, u_int offset, u_int size, u_int v, u_int mask, u_int op, int type)
{
   struct ablock *b = Argusgen_cmp(dsr, offset, size, (v & mask), op, type);
   struct slist *s;

   if (mask != 0xffffffff) {
      s = new_stmt(NFF_ALU|NFF_AND|NFF_K);
      s->s.data.k = mask;
      b->stmts->next = s;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_mcmp (%d, %d, %d, %d, 0x%x, %d) returns %p\n", dsr, offset, size, v, mask, op, b);
#endif

   return b;
}


static struct ablock *
Argusgen_bcmp(int dsr, u_int offset, u_int size, u_char *v, int type)
{
   struct ablock *b, *tmp;

   b = NULL;
   while (size >= 4) {
      u_char *p = &v[size - 4];
      u_int w;
#if defined(_LITTLE_ENDIAN)
      w = (p[3] << 24) | (p[2] << 16) | (p[1] << 8) | p[0];
#else
      w = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3];
#endif

      tmp = Argusgen_cmp(dsr, offset + size - 4, NFF_W, w, Q_EQUAL, type);
      if (b != NULL)
         Argusgen_and(b, tmp);
      b = tmp;
      size -= 4;
   }
   while (size >= 2) {
      u_char *p = &v[size - 2];
      u_int w;

#if defined(_LITTLE_ENDIAN)
      w = (p[1] << 8) | p[0];
#else
      w = (p[0] << 8) | p[1];
#endif
      tmp = Argusgen_cmp(dsr, offset + size - 2, NFF_H, w, Q_EQUAL, type);
      if (b != NULL)
         Argusgen_and(b, tmp);
      b = tmp;
      size -= 2;
   }
   if (size > 0) {
      tmp = Argusgen_cmp(dsr, offset, NFF_B, (u_int)v[0], Q_EQUAL, type);
      if (b != NULL)
         Argusgen_and(b, tmp);
      b = tmp;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argusgen_bcmp (%d, %d, %d) returns %p\n", offset, size, v, b);
#endif

   return b;
}

struct ablock *
Argusgen_dns(int v, int value, int dir)
{
   struct ablock *b1 = NULL, *b2 = NULL;
   struct ArgusRecordStruct argus;
/*
   struct ArgusDnsQueryStruct *sdns = &argus.srcappdata;
   struct ArgusDnsQueryStruct *ddns = &argus.dstappdata;
*/
   struct ArgusDnsQueryStruct *sdns = (struct ArgusDnsQueryStruct *) &argus.srate;
   struct ArgusDnsQueryStruct *ddns = (struct ArgusDnsQueryStruct *) &argus.drate;

   int soffset = ((char *)&sdns - (char *)&argus);
   int doffset = ((char *)&ddns - (char *)&argus);

   switch (dir) {
      case Q_SRC: {
         b1 = Argusgen_mcmp(-1, soffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         break;
      }

      case Q_DST: {
         b1 = Argusgen_mcmp(-1, doffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         break;
      }

      case Q_OR:
      case Q_DEFAULT:
         b1 = Argusgen_mcmp(-1, doffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         b2 = Argusgen_mcmp(-1, soffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b2);
         Argusgen_or(b2, b1);
         break;

      case Q_AND:
         b1 = Argusgen_mcmp(-1, doffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         b2 = Argusgen_mcmp(-1, soffset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b2);
         Argusgen_and(b2, b1);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dnsauth () returns %p\n", b1);
#endif
   return (b1);
}


static struct ablock *
Argusgen_espstatustype(unsigned int proto)
{
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusNetworkStruct net;
   int offset = ((char *)&net.net_union.esp.status - (char *)&net);

   b1 = Argusgen_prototype(IPPROTO_ESP, Q_DEFAULT);

   switch (proto) {
      case ARGUS_SRC_PKTS_DROP:
         b0 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, offset, NFF_W, ARGUS_SRC_PKTS_DROP, ARGUS_SRC_PKTS_DROP, Q_EQUAL, Q_DEFAULT);
         break;
      case ARGUS_DST_PKTS_DROP:
         b0 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, offset, NFF_W, ARGUS_DST_PKTS_DROP, ARGUS_DST_PKTS_DROP, Q_EQUAL, Q_DEFAULT);
         break;
   }

   if (b0)
      Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_espstatustype () returns %p\n", b1);
#endif
   return (b1);
}

static struct ablock *
Argusgen_ipstatustype(unsigned int proto)
{
   struct ablock *b1 = NULL;
   switch (proto) {
      case ARGUS_CON_ESTABLISHED: {
         struct ablock *b2, *b3;
         b1 = Argusgen_linktype(ETHERTYPE_IP);
         b2 = Argusgen_pkt(0, Q_SRC, Q_GREATER);
         b3 = Argusgen_pkt(0, Q_DST, Q_GREATER);

         Argusgen_and(b2, b3);
         Argusgen_and(b3, b1);
         break;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpstatustype () returns %p\n", b1);
#endif
   return (b1);
}


static struct ablock *
Argusgen_tcpstatustype(unsigned int proto)
{
   struct ablock *b0, *b1;
   unsigned int value = proto;
   struct ArgusNetworkStruct net;
   int offset = ((char *)&net.net_union.tcp.status - (char *)&net);

   b0 = Argusgen_prototype(IPPROTO_TCP, Q_DEFAULT);

   switch (proto) {
      case ARGUS_SRC_CONGESTED:
      case ARGUS_DST_CONGESTED:
      case ARGUS_SRC_RESET:
      case ARGUS_DST_RESET:
      case ARGUS_SRC_WINDOW_SHUT:
      case ARGUS_DST_WINDOW_SHUT:
      case ARGUS_NORMAL_CLOSE:
      case ARGUS_SAW_SYN:
      case ARGUS_SAW_SYN_SENT:
      case ARGUS_CON_ESTABLISHED:
      case ARGUS_CLOSE_WAITING:
      case ARGUS_SRC_PKTS_RETRANS:
      case ARGUS_DST_PKTS_RETRANS:
      case ARGUS_SRC_OUTOFORDER:
      case ARGUS_DST_OUTOFORDER:
      default:
         b1 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, offset, NFF_W, value, value, Q_EQUAL, Q_DEFAULT);
         break;
   }

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpstatustype () returns %p\n", b1);
#endif
   return (b1);
}

static struct ablock *
Argusgen_ipattrstatustype(unsigned int status)
{
   struct ablock *b1;
   struct ArgusIPAttrStruct ipattr;
   int offset = ((char *)&ipattr.hdr.argus_dsrvl8.qual - (char *)&ipattr);

   b1 = Argusgen_mcmp(ARGUS_IPATTR_INDEX, offset, NFF_B, status, status, Q_EQUAL, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ipattrstatustype (%d) returns %p\n", status, b1);
#endif
   return (b1);
}

static struct ablock *
Argusgen_causetype(unsigned int cause)
{
   struct ablock *b0 = NULL;
   struct ArgusCanonRecord canon;
   int offset = ((char *)&canon.hdr.cause - (char *)&canon);

   switch (cause) {
      case ARGUS_START:
      case ARGUS_STATUS:
      case ARGUS_STOP:
      case ARGUS_TIMEOUT:
      case ARGUS_SHUTDOWN:
         b0 = Argusgen_mcmp(-1, offset, NFF_B, (u_int) cause, cause, Q_EQUAL, Q_DEFAULT);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_causetype () returns %p\n", b0);
#endif

   return (b0);
}

static struct ablock *
Argusgen_recordtype(unsigned int type)
{
   struct ablock *b0 = NULL;
   struct ArgusCanonRecord canon;
   int offset = ((char *)&canon.hdr.type - (char *)&canon);

   switch (type) {
      case ARGUS_MAR:
      case ARGUS_FAR:
      case ARGUS_EVENT:
      case ARGUS_INDEX:
      case ARGUS_DATASUP:
         b0 = Argusgen_mcmp(-1, offset, NFF_B, (u_int) type, type, Q_EQUAL, Q_DEFAULT);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_recordtype () returns %p\n", b0);
#endif

   return (b0);
}

static struct ablock *
Argusgen_mpls(unsigned int proto)
{
   struct ablock *b1 = NULL;
   struct ArgusMplsStruct mpls;
   int offset = ((char *)&mpls.hdr.type - (char *)&mpls);
   b1 = Argusgen_cmp(ARGUS_MPLS_INDEX, offset, NFF_B, (u_int) ARGUS_MPLS_DSR, Q_EQUAL, Q_DEFAULT);

   return(b1);
}
 
static struct ablock *
Argusgen_vlan(unsigned int proto)
{
   struct ablock *b1 = NULL;
   struct ArgusVlanStruct vlan;
   int offset = ((char *)&vlan.hdr.type - (char *)&vlan);
   b1 = Argusgen_cmp(ARGUS_VLAN_INDEX, offset, NFF_B, (u_int) ARGUS_VLAN_DSR, Q_EQUAL, Q_DEFAULT);

   return(b1);
}
 

static struct ablock *
Argusgen_linktype(unsigned int proto)
{
   struct ablock *b1 = NULL;
   struct ArgusFlow flow;
   int offset = ((char *)&flow.hdr.argus_dsrvl8.qual - (char *)&flow);
 
   switch (proto) {
      default:
         switch (proto) {
            case ETHERTYPE_REVARP:
               b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_ARP, 0x1F, Q_EQUAL, Q_DEFAULT);
               break;
            case ETHERTYPE_ARP:
               b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_ARP, 0x1F, Q_EQUAL, Q_DEFAULT);
               break;
            case ETHERTYPE_IP:
               b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_IPV4, 0x1F, Q_EQUAL, Q_DEFAULT);
               break;
            case ETHERTYPE_IPV6:
               b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_IPV6, 0x1F, Q_EQUAL, Q_DEFAULT);
               break;
            case ETHERTYPE_ISIS:
               b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_ISIS, 0x1F, Q_EQUAL, Q_DEFAULT);
               break;
            default: {
               struct ablock *b0 = NULL;
               b0 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) ARGUS_TYPE_ETHER, 0x1F, Q_EQUAL, Q_DEFAULT);

               offset =  ((char *)&flow.mac_flow.ehdr.ether_type - (char *)&flow);

               b1 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_H, (u_int) proto, Q_EQUAL, Q_DEFAULT);
               Argusgen_and(b0, b1);
               break;
            }
         }
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_linktype (0x%x) returns %p\n", proto, b1);
#endif

   return (b1);
}


static struct ablock *
Argusgen_prototype(unsigned int v, unsigned int proto)
{
   struct ArgusFlow flow;
   struct ArgusNetworkStruct net;
   struct ablock *b0, *b1;
   int offset;

   switch (v) {
      default:
         switch (proto) {
            case Q_IPV4:
               offset = ((char *)&flow.ip_flow.ip_p - (char *)&flow);
               b0 = Argusgen_linktype(ETHERTYPE_IP);
               b1 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, v, Q_EQUAL, Q_DEFAULT);
               Argusgen_and(b0, b1);
               return b1;

            case Q_IPV6:
#if defined(_LITTLE_ENDIAN)
               offset = ((char *)&flow.ipv6_flow - (char *)&flow) + 35;
#else
               offset = ((char *)&flow.ipv6_flow - (char *)&flow) + 32;
#endif
               b0 = Argusgen_linktype(ETHERTYPE_IPV6);
               b1 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, v, Q_EQUAL, Q_DEFAULT);
               Argusgen_and(b0, b1);
               return b1;

            case Q_IP:
            case Q_DEFAULT:
               b0 = Argusgen_prototype(v, Q_IPV4);
               b1 = Argusgen_prototype(v, Q_IPV6);
               Argusgen_or(b0, b1);
               return b1;
         }
         break;

      case IPPROTO_UDT: {
         offset = ((char *)&net.hdr.subtype - (char *)&net);
         b1 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int) ARGUS_UDT_FLOW, Q_EQUAL, Q_DEFAULT);
         break;
      }

      case IPPROTO_RTP: {
         offset = ((char *)&flow.ip_flow.ip_p - (char *)&flow);
         b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) IPPROTO_UDP, Q_EQUAL, Q_DEFAULT);
         offset = ((char *)&net.hdr.subtype - (char *)&net);
         b1 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int) ARGUS_RTP_FLOW, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
      }

      case IPPROTO_RTCP: {
         offset = ((char *)&flow.ip_flow.ip_p - (char *)&flow);
         b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) IPPROTO_UDP, Q_EQUAL, Q_DEFAULT);
         offset = ((char *)&net.hdr.subtype - (char *)&net);
         b1 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int) ARGUS_RTCP_FLOW, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_prototype (0x%x) returns %p\n", proto, b1);
#endif

   return b1;
}


static struct ablock *
Argusgen_hostop(unsigned int *addr, unsigned int *mask, int type, int dir, unsigned int proto)
{
   int offset, src_off = 0, dst_off = 0, len = 0;
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusFlow flow;

   switch (proto) {
      case ETHERTYPE_IP:
         src_off = ((char *)&flow.ip_flow.ip_src - (char *)&flow);
         dst_off = ((char *)&flow.ip_flow.ip_dst - (char *)&flow);
         len = sizeof(flow.ip_flow.ip_src);
         break;

      case ETHERTYPE_IPV6:
         src_off = ((char *)&flow.ipv6_flow.ip_src - (char *)&flow);
         dst_off = ((char *)&flow.ipv6_flow.ip_dst - (char *)&flow);
         len = sizeof(flow.ipv6_flow.ip_src);
         break;

      case ETHERTYPE_ARP:
         src_off = ((char *)&flow.arp_flow.arp_spa - (char *)&flow);
         dst_off = ((char *)&flow.arp_flow.arp_tpa - (char *)&flow);
         len = sizeof(flow.arp_flow.arp_spa);
         break;

      case ETHERTYPE_REVARP:
         break;
   }

   switch (dir) {
      case Q_SRC:
         offset = src_off;
         break;

      case Q_DST:
         offset = dst_off;
         break;

      case Q_AND:
         b0 = Argusgen_hostop(addr, mask, type, Q_SRC, proto);
         b1 = Argusgen_hostop(addr, mask, type, Q_DST, proto);
         Argusgen_and(b0, b1);
         return b1;

      case Q_OR:
      case Q_DEFAULT:
         b0 = Argusgen_hostop(addr, mask, type, Q_SRC, proto);
         b1 = Argusgen_hostop(addr, mask, type, Q_DST, proto);
         Argusgen_or(b0, b1);
         return b1;

      default:
         abort();
   }

   switch (len) {
      case 0: break;
      case 1: b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int)*addr, (u_int)*mask, Q_EQUAL, Q_DEFAULT); break;
      case 2: b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset, NFF_H, (u_int)*addr, (u_int)*mask, Q_EQUAL, Q_DEFAULT); break;

      case 4:
      case 8: 
      case 16: {
         int i;
         for (i = 0; i < len/4; i++) {
            if (mask[i] != 0) {
               if (b1 == NULL) {
                  b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset + i*4, NFF_W, (u_int)addr[i], (u_int)mask[i], Q_EQUAL, Q_DEFAULT);
               } else {
                  b0 = Argusgen_mcmp(ARGUS_FLOW_INDEX, offset + i*4, NFF_W, (u_int)addr[i], (u_int)mask[i], Q_EQUAL, Q_DEFAULT);
                  Argusgen_and(b0, b1);
               }
            }
         }
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_hostop (0x%x, 0x%x, %d, %d, 0x%x) returns %p\n",
                    addr, mask, type, dir, proto, b1);
#endif
   return b1;
}


static struct ablock *
Argusgen_ehostop( u_char *eaddr, int dir)
{
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusMacStruct mac;
   int offset;

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ehostop (0x%x, %d)\n", eaddr, dir);
#endif

   switch (dir) {
      case Q_SRC: {
         offset = ((char *)&mac.mac.mac_union.ether.ehdr.ether_shost - (char *)&mac);
         
         return Argusgen_bcmp (ARGUS_MAC_INDEX, offset, 6, eaddr, Q_DEFAULT);
      }

      case Q_DST: {
         offset = ((char *)&mac.mac.mac_union.ether.ehdr.ether_dhost - (char *)&mac);
         return Argusgen_bcmp (ARGUS_MAC_INDEX, offset, 6, eaddr, Q_DEFAULT);
      }

      case Q_AND: {
         b0 = Argusgen_ehostop(eaddr, Q_SRC);
         b1 = Argusgen_ehostop(eaddr, Q_DST);
         Argusgen_and(b0, b1);
         return b1;
      }

      case Q_DEFAULT:
      case Q_OR: {
         b0 = Argusgen_ehostop(eaddr, Q_SRC);
         b1 = Argusgen_ehostop(eaddr, Q_DST);
         Argusgen_or(b0, b1);
         return b1;
      }
   }
   abort();
   /* NOTREACHED */
}


extern struct ArgusParserStruct *ArgusParser;

static struct ablock *
Argusgen_host(u_int *addr, u_int *mask, int type, int proto, int dir)
{
   struct ablock *b0 = NULL, *b1 = NULL;

   switch (proto) {
      case Q_DEFAULT: {
         struct ablock *b2 = NULL;

         b0 = Argusgen_linktype(ETHERTYPE_ARP);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_ARP);
            Argusgen_and(b0, b1);
         } else
            b1 = b0;

         if (!type || (type == Q_IPV4)) {
            b0 = Argusgen_linktype(ETHERTYPE_IP);
            if (*mask > 0) {
               b2 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IP);
               Argusgen_and(b0, b2);
               Argusgen_or(b2, b1);
            } else
               Argusgen_or(b0, b1);
         }
 
         if (!type || (type == Q_IPV6)) {
            b0 = Argusgen_linktype(ETHERTYPE_IPV6);
            if (*mask > 0) {
               b2 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IPV6);
               Argusgen_and(b0, b2);
               Argusgen_or(b2, b1);
            } else
               Argusgen_or(b0, b1);
         }
         break;
      }

      case Q_IP: {
         struct ablock *b2 = NULL;

         if (!type || (type == Q_IPV4)) {
            b0 = Argusgen_linktype(ETHERTYPE_IP);
            if (*mask > 0) {
               b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IP);
               Argusgen_and(b0, b1);
            } else
               b1 = b0;
         }
  
         if (!type || (type == Q_IPV6)) {
            b0 = Argusgen_linktype(ETHERTYPE_IPV6);
            if (*mask > 0) {
               b2 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IPV6);
               Argusgen_and(b0, b2);
               Argusgen_or(b2, b1);
            } else
               Argusgen_or(b0, b1);
         }
         break;
      }

      case Q_IPV6: {
         b0 = Argusgen_linktype(ETHERTYPE_IPV6);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IPV6);
            Argusgen_and(b0, b1);
         }
         break;
      }

      case Q_IPV4: {
         b0 = Argusgen_linktype(ETHERTYPE_IP);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IP);
            Argusgen_and(b0, b1);
         } else
            b1 = b0;
         break;
      }

      case Q_ARP: {
         b0 = Argusgen_flow(ARGUS_FLOW_ARP);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_ARP);
            Argusgen_and(b0, b1);
         } else
            b1 = b0;
         break;
      }

      case Q_RARP: {
         b0 = Argusgen_linktype(ETHERTYPE_REVARP);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_REVARP);
            Argusgen_and(b0, b1);
         } else
            b1 = b0;
         break;
      }

      case Q_TCP:
         ArgusLog(LOG_ERR, "'tcp' modifier applied to host");

      case Q_UDP:
         ArgusLog(LOG_ERR, "'udp' modifier applied to host");

      case Q_RTP:
         ArgusLog(LOG_ERR, "'rtp' modifier applied to host");

      case Q_RTCP:
         ArgusLog(LOG_ERR, "'rtcp' modifier applied to host");

      case Q_UDT:
         ArgusLog(LOG_ERR, "'udt' modifier applied to host");

      case Q_ICMP:
         b0 = Argusgen_linktype(ETHERTYPE_IP);
         if (*mask > 0) {
            b1 = Argusgen_hostop(addr, mask, type, dir, ETHERTYPE_IP);
            Argusgen_and(b0, b1);
         } else
            b1 = b0;
         break;

      case Q_ISIS:
         ArgusLog(LOG_ERR, "'isis' modifier applied to host");

      case Q_RSVP:
         ArgusLog(LOG_ERR, "'rsvp' modifier applied to host");

      default:
         abort();
      }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_host (0x%x, 0x%x, %d, 0x%x, %d) returns %p\n", addr, mask, type, proto, dir, b1);
#endif

   return (b1);
}


static struct ablock *
Argusgen_srcid(u_int addr, u_int mask, int type)
{
   struct ablock *b1 = NULL, *b0 = NULL, *tmp;
   struct ArgusTransportStruct trans;
   struct ArgusRecord mar;

   int offset = ((char *)&mar.argus_mar.argusid - (char *)&mar);

   tmp = Argusgen_recordtype(ARGUS_MAR);
   b1 = Argusgen_mcmp(ARGUS_MAR_INDEX, offset, NFF_W, (u_int)addr, mask, Q_EQUAL, type);
   Argusgen_and(tmp, b1);

   offset = ((char *)&trans.srcid - (char *)&trans);

   tmp = Argusgen_recordtype(ARGUS_FAR);
   b0  = Argusgen_recordtype(ARGUS_EVENT);
   Argusgen_or(b0, tmp);

   b0 = Argusgen_mcmp(ARGUS_TRANSPORT_INDEX, offset, NFF_W, (u_int)addr, mask, Q_EQUAL, type);
   Argusgen_and(tmp, b0);

   Argusgen_or(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_srcid (0x%x, 0x%x) returns %p\n", addr, mask, b1);
#endif

   return (b1);
}

static struct ablock *
Argusgen_inode(u_int addr, u_int mask, int type)
{
   struct ablock *b1 = NULL, *tmp;
   struct ArgusIcmpStruct icmp;

   int offset = ((char *)&icmp.osrcaddr - (char *)&icmp);

   tmp = Argusgen_recordtype(ARGUS_FAR);
   b1 = Argusgen_mcmp(ARGUS_ICMP_INDEX, offset, NFF_W, (u_int)addr, mask, Q_EQUAL, type);
   Argusgen_and(tmp, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_inode (0x%x, 0x%x) returns %p\n", addr, mask, b1);
#endif

   return (b1);
}


static struct ablock *
Argusgen_gateway( u_char *eaddr, u_int *alist, int type, int proto, int dir)
{
   struct ablock *b0, *b1 = NULL;
   u_int maskbuf[4], *mask = maskbuf;

   if (dir != 0)
      ArgusLog(LOG_ERR, "direction applied to 'gateway'");

   switch (proto) {
      case Q_DEFAULT:
      case Q_IP:
      case Q_IPV4:
      case Q_ARP:
      case Q_RARP:
         *mask = 0xffffffffL;
         b0 = Argusgen_ehostop(eaddr, Q_OR);
         b1 = Argusgen_host(alist, mask, type, proto, Q_OR);
         Argusgen_not(b1);
         Argusgen_and(b0, b1);
         break;

      case Q_IPV6:
       default:
         ArgusLog(LOG_ERR, "illegal modifier of 'gateway'");
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_gateway (0x%x, 0x%x, %d, 0x%x, %d) returns %p\n", eaddr, alist, type, proto, dir, b1);
#endif

   return b1;
}

#include <netinet/igmp.h>

struct ablock *
Argusgen_proto_abbrev(proto)
int proto;
{
   struct ablock *b0, *b1 = NULL;

   switch (proto) {
      case Q_TCP:
         b1 = Argusgen_prototype(IPPROTO_TCP, Q_DEFAULT);
         break;

      case Q_ESP:
         b1 = Argusgen_prototype(IPPROTO_ESP, Q_DEFAULT);
         break;

      case Q_RTP:
         b1 = Argusgen_prototype(IPPROTO_RTP, Q_DEFAULT);
         break;

      case Q_RTCP:
         b1 = Argusgen_prototype(IPPROTO_RTCP, Q_DEFAULT);
         break;

      case Q_UDT:
         b1 = Argusgen_prototype(IPPROTO_UDT, Q_DEFAULT);
         break;

      case Q_UDP:
         b1 = Argusgen_prototype(IPPROTO_UDP, Q_DEFAULT);
         break;

      case Q_ICMP:
         b1 = Argusgen_prototype(IPPROTO_ICMP, Q_DEFAULT);
         break;

      case Q_IGMP:
         b1 = Argusgen_prototype(IPPROTO_IGMP, Q_DEFAULT);
         break;

      case Q_IGRP:
         b1 = Argusgen_prototype(IPPROTO_IGRP, Q_DEFAULT);
         break;

      case Q_ARP:
         b1 =  Argusgen_flow(ARGUS_FLOW_ARP);
         break;

      case Q_MPLS:
         b1 = Argusgen_mpls(Q_DEFAULT);
         break;

      case Q_VLAN:
         b1 = Argusgen_vlan(Q_DEFAULT);
         break;

      case Q_RARP:
         b1 =  Argusgen_linktype(ETHERTYPE_REVARP);
         break;

      case Q_IPV6:
         b1 =  Argusgen_linktype(ETHERTYPE_IPV6);
         break;

      case Q_IPV4:
         b1 =  Argusgen_linktype(ETHERTYPE_IP);
         break;

      case Q_IP:
         b0 =  Argusgen_linktype(ETHERTYPE_IPV6);
         b1 =  Argusgen_linktype(ETHERTYPE_IP);
         Argusgen_or(b0, b1);
         break;

      case Q_ISIS:
         b1 =  Argusgen_linktype(ETHERTYPE_ISIS);
         break;

      case Q_MAN:
         b1 =  Argusgen_recordtype(ARGUS_MAR);
         break;

      case Q_FAR:
         b1 =  Argusgen_recordtype(ARGUS_FAR);
         break;

      case Q_EVENT:
         b1 =  Argusgen_recordtype(ARGUS_EVENT);
         break;

      case Q_INDEX:
         b1 =  Argusgen_recordtype(ARGUS_INDEX);
         break;

      case Q_CONNECTED:
      case Q_ESTABLISHED:
         b0 = Argusgen_ipstatustype(ARGUS_CON_ESTABLISHED);
         b1 = Argusgen_tcpstatustype(ARGUS_CON_ESTABLISHED);
         Argusgen_or(b0, b1);
         break;

      case Q_MERGED:
      case Q_ANON:
         break;

      case Q_ICMPMAP: {
         struct ArgusIcmpStruct icmp;
         int offset = ((char *)&icmp.hdr.argus_dsrvl8.qual - (char *)&icmp);
         b1 = Argusgen_mcmp(ARGUS_ICMP_INDEX, offset, NFF_B, 0, 0x07, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         break;
      }

      case Q_ECHO: {
         struct ArgusNetworkStruct net;
         int offset = ((char *)&net.net_union.icmp.icmp_type - (char *)&net);
         b0 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int)  0x08, Q_EQUAL, Q_DEFAULT);
         b1 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int)  0x00, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         b0 = Argusgen_prototype(IPPROTO_ICMP, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_UNREACH: {
         struct ArgusNetworkStruct net;
         struct ArgusIcmpStruct icmp;
         int offset = ((char *)&net.net_union.icmp.icmp_type - (char *)&net);

         b1 = Argusgen_prototype(IPPROTO_ICMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int)  0x03, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);

         offset = ((char *)&icmp.hdr.argus_dsrvl8.qual - (char *)&icmp);
         b0 = Argusgen_cmp(ARGUS_ICMP_INDEX, offset, NFF_B, ARGUS_ICMPUNREACH_MAPPED, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;
      }

      case Q_REDIRECT: {
         struct ArgusIcmpStruct icmp;
         int offset = ((char *)&icmp.icmp_type - (char *)&icmp);

         b1 = Argusgen_prototype(IPPROTO_ICMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_ICMP_INDEX, offset, NFF_B, (u_int)  0x05, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);

         offset = ((char *)&icmp.hdr.argus_dsrvl8.qual - (char *)&icmp);
         b0 = Argusgen_cmp(ARGUS_ICMP_INDEX, offset, NFF_B, ARGUS_ICMPREDIREC_MAPPED, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;
      }

      case Q_TIMEXED: {
         struct ArgusNetworkStruct net;
         struct ArgusIcmpStruct icmp;

         int offset = ((char *)&net.net_union.icmp.icmp_type - (char *)&net);

         b1 = Argusgen_prototype(IPPROTO_ICMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_NETWORK_INDEX, offset, NFF_B, (u_int)  0x0B, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);

         offset = ((char *)&icmp.hdr.argus_dsrvl8.qual - (char *)&icmp);
         b0 = Argusgen_cmp(ARGUS_ICMP_INDEX, offset, NFF_B, ARGUS_ICMPTIMXCED_MAPPED, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;
      }

      case Q_START:
         b1 = Argusgen_causetype(ARGUS_START);
         break;

      case Q_STOP:
         b1 = Argusgen_causetype(ARGUS_STOP);
         break;

      case Q_STATUS:
         b1 = Argusgen_causetype(ARGUS_STATUS);
         break;

      case Q_SHUTDOWN:
         b1 = Argusgen_causetype(ARGUS_SHUTDOWN);
         break;

      case Q_ERROR:
         b1 = Argusgen_causetype(ARGUS_ERROR);
         break;

      case Q_TIMEDOUT:
         b1 = Argusgen_causetype(ARGUS_TIMEOUT);
         break;

      case Q_RETRANS:
         b0 = Argusgen_espstatustype(ARGUS_SRC_PKTS_DROP);
         b1 = Argusgen_tcpstatustype(ARGUS_SRC_PKTS_RETRANS);
         Argusgen_or(b0, b1);
         b0 = Argusgen_espstatustype(ARGUS_DST_PKTS_DROP);
         Argusgen_or(b0, b1);
         b0 = Argusgen_tcpstatustype(ARGUS_DST_PKTS_RETRANS);
         Argusgen_or(b0, b1);
         break;

      case Q_SRCRETRANS:
         b0 = Argusgen_espstatustype(ARGUS_SRC_PKTS_DROP);
         b1 = Argusgen_tcpstatustype(ARGUS_SRC_PKTS_RETRANS);
         Argusgen_or(b0, b1);
         break;

      case Q_DSTRETRANS:
         b0 = Argusgen_espstatustype(ARGUS_DST_PKTS_DROP);
         b1 = Argusgen_tcpstatustype(ARGUS_DST_PKTS_RETRANS);
         Argusgen_or(b0, b1);
         break;

      case Q_FRAG:
         b0 = Argusgen_ipattrstatustype(ARGUS_IPATTR_SRC_FRAGMENTS);
         b1 = Argusgen_ipattrstatustype(ARGUS_IPATTR_DST_FRAGMENTS);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_IP);
         Argusgen_and(b0, b1);
         break;

      case Q_SRCFRAG:
         b0 =  Argusgen_linktype(ETHERTYPE_IP);
         b1 = Argusgen_ipattrstatustype(ARGUS_IPATTR_SRC_FRAGMENTS);
         Argusgen_and(b0, b1);
         break;

      case Q_DSTFRAG:
         b0 =  Argusgen_linktype(ETHERTYPE_IP);
         b1 = Argusgen_ipattrstatustype(ARGUS_IPATTR_DST_FRAGMENTS);
         Argusgen_and(b0, b1);
         break;

      case Q_OUTOFORDER:
         b1 = Argusgen_tcpstatustype(ARGUS_SRC_OUTOFORDER);
         b0 = Argusgen_tcpstatustype(ARGUS_DST_OUTOFORDER);
         Argusgen_or(b0, b1);
         break;

      case Q_SRCOUTOFORDER:
         b1 = Argusgen_tcpstatustype(ARGUS_SRC_OUTOFORDER);
         break;

      case Q_DSTOUTOFORDER:
         b1 = Argusgen_tcpstatustype(ARGUS_DST_OUTOFORDER);
         break;

      case Q_SYN:
         b1 = Argusgen_tcpstatustype(ARGUS_SAW_SYN);
         break;

      case Q_SYNACK:
         b1 = Argusgen_tcpstatustype(ARGUS_SAW_SYN_SENT);
         break;

      case Q_FIN:
         b1 = Argusgen_tcpstatustype(ARGUS_FIN);
         break;

      case Q_FINACK:
         b1 = Argusgen_tcpstatustype(ARGUS_FIN_ACK);
         break;

      case Q_WAIT:
         b1 = Argusgen_tcpstatustype(ARGUS_CLOSE_WAITING);
         break;

      case Q_NORMAL:
         b1 = Argusgen_tcpstatustype(ARGUS_NORMAL_CLOSE);
         break;

      case Q_RTR: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.igmp_flow.type - (char *)&flow);

         b1 = Argusgen_prototype(IPPROTO_IGMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int)  IGMP_HOST_MEMBERSHIP_QUERY, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_LVG: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.igmp_flow.type - (char *)&flow);

         b1 = Argusgen_prototype(IPPROTO_IGMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int) IGMP_HOST_LEAVE_MESSAGE, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_MBR: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.igmp_flow.type - (char *)&flow);
 
         b1 = Argusgen_prototype(IPPROTO_IGMP, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, offset, NFF_B, (u_int)  IGMP_HOST_MEMBERSHIP_QUERY, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b0);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_COCODE: {
         struct ArgusCountryCodeStruct cocode;
         int offset = ((char *)&cocode.src - (char *)&cocode);
         b1 = Argusgen_cmp(ARGUS_COCODE_INDEX, offset, NFF_H, 0, Q_EQUAL, Q_DEFAULT);
         Argusgen_not(b1);
         break;
      }

      case Q_LINK:
         ArgusLog(LOG_ERR, "link layer applied in wrong context");

      default:
         abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_proto_abbrev (%d) returns 0x%x\n", proto, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_tcpoptatom(int off, u_int v)
{
   struct ablock *b0;

   b0 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, off, NFF_W, (u_int)v, (u_int)v, Q_EQUAL, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpoptatom (%d, %d) returns %p\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_ipidatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_IPATTR_INDEX, off, NFF_H, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ipidatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_ttlatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_IPATTR_INDEX, off, NFF_B, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ttlatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_tosatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 =  Argusgen_cmp(ARGUS_IPATTR_INDEX, off, NFF_B, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tosatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_dsbatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   v = (v << 2);
   b0 =  Argusgen_mcmp(ARGUS_IPATTR_INDEX, off, NFF_B, v, 0xFC, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dsbatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}


static struct ablock *
Argusgen_vidatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 = Argusgen_mcmp(ARGUS_VLAN_INDEX, off, NFF_H, v, 0x0FFF, Q_EQUAL, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_vidatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_vpriatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 = Argusgen_mcmp(ARGUS_VLAN_INDEX, off, NFF_H, (v << 12), 0xF000, Q_EQUAL, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_vpriatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_midatom(int off, u_int v, u_int op)
{
   struct ablock *b0;
   unsigned int mask = 0xFFFFF000;
   unsigned int label = v << 12;

   b0 = Argusgen_mcmp(ARGUS_MPLS_INDEX, off, NFF_W, label, mask, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_midatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_encapsatom(int off, u_int v, u_int op)
{
   struct ablock *b0;

   b0 =  Argusgen_mcmp(ARGUS_ENCAPS_INDEX, off, NFF_W, v, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_encapsatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_portatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, off, NFF_H, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_portatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_pktatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_METRIC_INDEX, off, NFF_L, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_pktatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_byteatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_METRIC_INDEX, off, NFF_L, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_byteatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_nstrokeatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_BEHAVIOR_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_nstrokeatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

/*
static struct ablock *
Argusgen_dupatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_NETWORK_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dupatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}
*/

static struct ablock *
Argusgen_tcpbaseatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_NETWORK_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpbaseatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_transatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_AGR_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_transatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_rateatom( int off, float v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_fcmp(-1, off, NFF_F, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_rateatom (%d, %f, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_loadatom( int off, float v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_fcmp(-1, off, NFF_F, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_loadatom (%d, %f, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_plossatom( int off, float v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_fcmp(-1, off, NFF_F, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_plossatom (%d, %f, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_pcratom( int off, float v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_fcmp(-1, off, NFF_F, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_pcratom (%d, %f, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_duratom( int off, float v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_fcmp(-1, off, NFF_F, v, op, Q_DEFAULT);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_duratom (%d, %f, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_meanatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(-1, off, NFF_L, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_meanatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_deltaduratom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_W, (u_int)v*1000, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltaduratom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_deltastartatom( int off, long v, int op)
{
   struct ablock *b0;
 
   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_W, (u_int)v*1000, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltastartatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_deltalastatom( int off, long v, int op)
{
   struct ablock *b0;
 
   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_W, (u_int)v*1000, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltalastatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_deltaspktsatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltaspktsatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_deltadpktsatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltadpktsatom (%d, 0x%x, %d) returns 0x%x\n", off, v, op, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_asnatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_ASN_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_asnatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

static struct ablock *
Argusgen_coratom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_COR_INDEX, off, NFF_B, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_coratom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}



static struct ablock *
Argusgen_spiatom( int off, long v, int op)
{
   struct ablock *b0;

   b0 = Argusgen_cmp(ARGUS_FLOW_INDEX, off, NFF_W, (u_int)v, op, Q_DEFAULT);
#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_spiatom (%d, 0x%x) returns 0x%x\n", off, v, b0);
#endif
   return b0;
}

struct ablock *
Argusgen_portop(int port, int proto, int dir, u_int op)
{
   struct ArgusFlow flow;
   struct ablock *b0 = NULL, *b1 = NULL, *b2 = NULL;

   /* ip proto 'proto' */

   switch (dir) {
      case Q_SRC: {
         int ip4offset = ((char *)&flow.ip_flow.sport   - (char *)&flow);
         int ip6offset = ((char *)&flow.ipv6_flow.sport - (char *)&flow);

         b1 = Argusgen_prototype(proto, Q_IPV4);
         b0 = Argusgen_portatom(ip4offset, port, op);
         Argusgen_and(b0, b1);
         b2 = Argusgen_prototype(proto, Q_IPV6);
         b0 = Argusgen_portatom(ip6offset, port, op);
         Argusgen_and(b0, b2);
         Argusgen_or(b2, b1);
         break;
      }

      case Q_DST: {
         int ip4offset = ((char *)&flow.ip_flow.dport   - (char *)&flow);
         int ip6offset = ((char *)&flow.ipv6_flow.dport - (char *)&flow);

         b1 = Argusgen_prototype(proto, Q_IPV4);
         b0 = Argusgen_portatom(ip4offset, port, op);
         Argusgen_and(b0, b1);
         b2 = Argusgen_prototype(proto, Q_IPV6);
         b0 = Argusgen_portatom(ip6offset, port, op);
         Argusgen_and(b0, b2);
         Argusgen_or(b2, b1);
         break;
      }

      case Q_OR:
      case Q_DEFAULT:
         b0 = Argusgen_portop(port, proto, Q_SRC, op);
         b1 = Argusgen_portop(port, proto, Q_DST, op);
         Argusgen_or(b0, b1);
         break;

      case Q_AND:
         b0 = Argusgen_portop(port, proto, Q_SRC, op);
         b1 = Argusgen_portop(port, proto, Q_DST, op);
         Argusgen_and(b0, b1);
         break;

      default:
         abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_portop (0x%x, 0x%x, %d) returns 0x%x\n", port, proto, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_port( int port, u_int ip_proto, int dir, u_int op)
{
   struct ablock *b1, *b0;

   switch (ip_proto) {
      case IPPROTO_TCP:
         b1 = Argusgen_portop(port, IPPROTO_TCP, dir, op);
         break;

      case IPPROTO_UDP:
         b1 = Argusgen_portop(port, IPPROTO_UDP, dir, op);
         break;

      case IPPROTO_UDT:
         b1 = Argusgen_portop(port, IPPROTO_UDT, dir, op);
         break;

      case IPPROTO_RTP:
         b0 = Argusgen_portop(port, IPPROTO_UDP, dir, op);
         b1  = Argusgen_portop(port, IPPROTO_RTP, dir, op);
         Argusgen_and(b0, b1);
         break;

      case IPPROTO_RTCP:
         b0 = Argusgen_portop(port, IPPROTO_UDP, dir, op);
         b1  = Argusgen_portop(port, IPPROTO_RTCP, dir, op);
         Argusgen_and(b0, b1);
         break;

      case PROTO_UNDEF:
         b0 = Argusgen_portop(port, IPPROTO_TCP, dir, op);
         b1 = Argusgen_portop(port, IPPROTO_UDP, dir, op);
         Argusgen_or(b0, b1);
         break;

      default:
         abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_port (0x%x, 0x%x, %d) returns 0x%x\n", port, ip_proto, dir, b1);
#endif
   return b1;
}

static int
Arguslookup_proto( char *name, int proto)
{
   int v = 0;

   switch (proto) {
      case Q_DEFAULT:
      case Q_IP:
      case Q_IPV6:
      case Q_IPV4:
         v = argus_nametoproto(name);
         if (v == PROTO_UNDEF)
            ArgusLog(LOG_ERR, "unknown proto '%s'", name);
         break;

      case Q_LINK:
         /* XXX should look up h/w protocol type based on linktype */
         v = argus_nametoeproto(name);
         if (v == PROTO_UNDEF)
            ArgusLog(LOG_ERR, "unknown ether proto '%s'", name);
         break;

      case Q_MAN:
         ArgusLog (LOG_ERR, "man proto called '%s'", name);
         break;

      default:
         v = PROTO_UNDEF;
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Arguslookup_proto (%s, 0x%x) returns 0x%x\n", name, proto, v);
#endif
 
   return v;
}

static struct ablock *
Argusgen_proto( int v, int proto, int dir)
{
   struct ablock *b1;

   if (dir != Q_DEFAULT)
      ArgusLog(LOG_ERR, "direction applied to 'proto'");

   switch (proto) {
      case Q_DEFAULT:
      case Q_IP:
      case Q_IPV6:
      case Q_IPV4:
         b1 = Argusgen_prototype(v, proto);
         break;

      case Q_ARP:
         b1 = Argusgen_linktype(ETHERTYPE_ARP);
         break;

      case Q_RARP:
         ArgusLog(LOG_ERR, "rarp does not encapsulate another protocol");
         /* NOTREACHED */

      case Q_MAN:
         b1 = Argusgen_recordtype(ARGUS_MAR);
         break;

      case Q_FAR:
         b1 =  Argusgen_recordtype(ARGUS_FAR);
         break;

      case Q_EVENT:
         b1 =  Argusgen_recordtype(ARGUS_EVENT);
         break;

      case Q_INDEX:
         b1 =  Argusgen_recordtype(ARGUS_INDEX);
         break;

      case Q_LINK:
         b1 = Argusgen_linktype(v);
         break;

      case Q_UDP:
         ArgusLog(LOG_ERR, "'udp proto' is bogus");
         /* NOTREACHED */

      case Q_RTP:
         ArgusLog(LOG_ERR, "'rtp proto' is bogus");
         /* NOTREACHED */

      case Q_RTCP:
         ArgusLog(LOG_ERR, "'rtcp proto' is bogus");
         /* NOTREACHED */

      case Q_TCP:
         ArgusLog(LOG_ERR, "'tcp proto' is bogus");
         /* NOTREACHED */

      case Q_ICMP:
         ArgusLog(LOG_ERR, "'icmp proto' is bogus");
         /* NOTREACHED */

      case Q_IGMP:
         ArgusLog(LOG_ERR, "'igmp proto' is bogus");
         /* NOTREACHED */

      default:
         abort();
         /* NOTREACHED */
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_proto (0x%x, 0x%x, %d) returns 0x%x\n", v, proto, dir, b1);
#endif
 
   return b1;
}

static struct ablock *
Argusgen_flow(int tflow)
{
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusFlow flow;
   int soffset = ((char *)&flow.hdr.subtype - (char *)&flow);

   b0 = Argusgen_recordtype(ARGUS_FAR);
   b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, soffset, NFF_B, tflow, tflow, Q_EQUAL, Q_DEFAULT);
   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_flow (%d) returns 0x%x\n", tflow, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_tcpopt(int v)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusNetworkStruct net;
   unsigned int opt = 0;
   int offset = ((char *)&net.net_union.tcp.options - (char *)&net);

   b0 =  Argusgen_linktype(ETHERTYPE_IP);

   switch (v) {
      case Q_TCPOPT: opt = ARGUS_TCP_OPTIONS; break;
      case Q_MSS: opt = ARGUS_TCP_MAXSEG; break;
      case Q_WSCALE: opt = ARGUS_TCP_WSCALE; break;
      case Q_SELECTIVEACKOK: opt = ARGUS_TCP_SACKOK; break;
      case Q_SELECTIVEACK: opt = ARGUS_TCP_SACK; break;
      case Q_TCPECHO: opt = ARGUS_TCP_ECHO; break;
      case Q_TCPECHOREPLY: opt = ARGUS_TCP_ECHOREPLY; break;
      case Q_TCPTIMESTAMP: opt = ARGUS_TCP_TIMESTAMP; break;
      case Q_TCPCC: opt = ARGUS_TCP_CC; break;
      case Q_TCPCCNEW: opt = ARGUS_TCP_CCNEW; break;
      case Q_TCPCCECHO: opt = ARGUS_TCP_CCECHO; break;
      case Q_SECN: opt = ARGUS_TCP_SRC_ECN; break;
      case Q_DECN: opt = ARGUS_TCP_DST_ECN; break;
   }

   b1 = Argusgen_tcpoptatom(offset, opt);
   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpopt (%d) returns %p\n", v, b1);
#endif
 
   return b1;
}

static struct ablock *
Argusgen_ipid(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL, *tmp;
   struct ArgusIPAttrStruct attr;
   int soffset = ((char *)&attr.src.ip_id - (char *)&attr);
   int doffset = ((char *)&attr.dst.ip_id - (char *)&attr);
 
   b0 = Argusgen_prototype(IPPROTO_TCP, Q_DEFAULT);

   switch (dir) {
   case Q_SRC:
      b1 = Argusgen_ipidatom(soffset, (u_int)v, op);
      break;

   case Q_DST:
      b1 = Argusgen_ipidatom(doffset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      tmp = Argusgen_ipidatom(soffset, (u_int)v, op);
      b1 = Argusgen_ipidatom(doffset, (u_int)v, op);
      Argusgen_or(tmp, b1);
      break;

   case Q_AND:
      tmp = Argusgen_ipidatom(soffset, (u_int)v, op);
      b1 = Argusgen_ipidatom(doffset, (u_int)v, op);
      Argusgen_and(tmp, b1);
      break;

   default:
      abort();
   }

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ipid (0x%x, %d) returns %p\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_ttl(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL, *tmp;
   struct ArgusIPAttrStruct attr;
   int soffset = ((char *)&attr.src.ttl - (char *)&attr);
   int doffset = ((char *)&attr.dst.ttl - (char *)&attr);
 
   b0 =  Argusgen_linktype(ETHERTYPE_IP);

   switch (dir) {
   case Q_SRC: {
      b1 = Argusgen_ttlatom(soffset, (u_int)v, op);
      break;
   }

   case Q_DST: {
      b1 = Argusgen_ttlatom(doffset, (u_int)v, op);
      break;
   }

   case Q_OR:
   case Q_DEFAULT:
      tmp = Argusgen_ttlatom(soffset, (u_int)v, op);
      b1 = Argusgen_ttlatom(doffset, (u_int)v, op);
      Argusgen_or(tmp, b1);
      break;

   case Q_AND:
      tmp = Argusgen_ttlatom(soffset, (u_int)v, op);
      b1 = Argusgen_ttlatom(doffset, (u_int)v, op);
      Argusgen_and(tmp, b1);
      break;

   default:
      abort();
   }

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ttl (0x%x, %d, %d) returns %p\n", v, dir, op, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_tos(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL, *tmp;
   struct ArgusIPAttrStruct attr;
   int soffset = ((char *)&attr.src.tos - (char *)&attr);
   int doffset = ((char *)&attr.dst.tos - (char *)&attr);
 
   b0 =  Argusgen_linktype(ETHERTYPE_IP);

   switch (dir) {
   case Q_SRC:
      b1 = Argusgen_tosatom(soffset, (u_int)v, op);
      break;

   case Q_DST:
      b1 = Argusgen_tosatom(doffset, (u_int)v, op);
      break;

   default:
   case Q_OR:
   case Q_DEFAULT:
      tmp = Argusgen_tosatom(soffset, (u_int)v, op);
      b1 = Argusgen_tosatom(doffset, (u_int)v, op);
      Argusgen_or(tmp, b1);
      break;

   case Q_AND:
      tmp = Argusgen_tosatom(soffset, (u_int)v, op);
      b1 = Argusgen_tosatom(doffset, (u_int)v, op);
      Argusgen_and(tmp, b1);
      break;

   }

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tos (0x%x, %d) returns %p\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_dsb(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL, *tmp;
   struct ArgusIPAttrStruct attr;
   int soffset = ((char *)&attr.src.tos - (char *)&attr);
   int doffset = ((char *)&attr.dst.tos - (char *)&attr);
 
   b0 =  Argusgen_linktype(ETHERTYPE_IP);

   switch (dir) {
   case Q_SRC:
      b1 = Argusgen_dsbatom(soffset, (u_int)v, op);
      break;

   case Q_DST:
      b1 = Argusgen_dsbatom(doffset, (u_int)v, op);
      break;

   default:
   case Q_OR:
   case Q_DEFAULT:
      tmp = Argusgen_dsbatom(soffset, (u_int)v, op);
      b1 = Argusgen_dsbatom(doffset, (u_int)v, op);
      Argusgen_or(tmp, b1);
      break;

   case Q_AND:
      tmp = Argusgen_dsbatom(soffset, (u_int)v, op);
      b1 = Argusgen_dsbatom(doffset, (u_int)v, op);
      Argusgen_and(tmp, b1);
      break;
   }

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dsb (0x%x, %d) returns %p\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_cocode(char *v, int dir, u_int op)
{
   extern struct ArgusParserStruct *ArgusParser;
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusCountryCodeStruct cocode;
   unsigned short val;

   int soffset = ((char *)&cocode.src - (char *)&cocode);
   int doffset = ((char *)&cocode.dst - (char *)&cocode);

   bcopy(v, (char *)&val, sizeof(val));

   switch (dir) {
      case Q_SRC:
         b1 = Argusgen_cmp(ARGUS_COCODE_INDEX, soffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         break;

      case Q_DST:
         b1 = Argusgen_cmp(ARGUS_COCODE_INDEX, doffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         break;

      default:
      case Q_OR:
      case Q_DEFAULT:
         b1 = Argusgen_cmp(ARGUS_COCODE_INDEX, doffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_COCODE_INDEX, soffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;

      case Q_AND:
         b1 = Argusgen_cmp(ARGUS_COCODE_INDEX, doffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         b0 = Argusgen_cmp(ARGUS_COCODE_INDEX, soffset, NFF_H, val, Q_EQUAL, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_cocode (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_vid(int v, int dir, u_int op)
{
   struct ArgusVlanStruct vlan;
   struct ablock *b0, *b1 = NULL;
   int offset = 0;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b1 = Argusgen_vidatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vidatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b0 = Argusgen_vidatom(offset, (u_int)v, op);

      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vidatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b0 = Argusgen_vidatom(offset, (u_int)v, op);

      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vidatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_vid (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}

static struct ablock *
Argusgen_vpri(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusVlanStruct vlan;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b1 = Argusgen_vpriatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vpriatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b0 = Argusgen_vpriatom(offset, (u_int)v, op);
      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vpriatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&vlan.sid - (char *)&vlan);
      b0 = Argusgen_vpriatom(offset, (u_int)v, op);
      offset = ((char *)&vlan.did - (char *)&vlan);
      b1 = Argusgen_vpriatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_vpri (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_mid(int v, int dir, u_int op)
{
   struct ablock *retn = NULL, *b0, *b1 = NULL;
   struct ArgusMplsStruct mpls;
   int offset;
 
      switch (dir) {
         case Q_SRC:
            offset = ((char *)&mpls.slabel - (char *)&mpls);
            b1 = Argusgen_midatom(offset, (u_int)v, op);
            break;

         case Q_DST:
            offset = ((char *)&mpls.dlabel - (char *)&mpls);
            b1 = Argusgen_midatom(offset, (u_int)v, op);
            break;

         case Q_OR:
         case Q_DEFAULT:
            offset = ((char *)&mpls.slabel - (char *)&mpls);
            b0 = Argusgen_midatom(offset, (u_int)v, op);
            offset = ((char *)&mpls.dlabel - (char *)&mpls);
            b1 = Argusgen_midatom(offset, (u_int)v, op);
            Argusgen_or(b0, b1);
            break;

         case Q_AND:
            offset = ((char *)&mpls.slabel - (char *)&mpls);
            b0 = Argusgen_midatom(offset, (u_int)v, op);
            offset = ((char *)&mpls.dlabel - (char *)&mpls);
            b1 = Argusgen_midatom(offset, (u_int)v, op);
            Argusgen_and(b0, b1);
            break;

         default:
            abort();
      }

      if (retn != NULL) {
         Argusgen_or(b1, retn);
      } else 
         retn = b1;

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_mid (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return retn;
}


static struct ablock *
Argusgen_encaps(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL, *tmp;
   struct ArgusEncapsStruct encaps;
   int soffset = ((char *)&encaps.src - (char *)&encaps);
   int doffset = ((char *)&encaps.dst - (char *)&encaps);
 
   switch (dir) {
   case Q_SRC:
      b1 = Argusgen_encapsatom(soffset, (u_int)v, op);
      break;

   case Q_DST:
      b1 = Argusgen_encapsatom(doffset, (u_int)v, op);
      break;

   default:
   case Q_OR:
   case Q_DEFAULT:
      tmp = Argusgen_encapsatom(soffset, (u_int)v, op);
      b1 = Argusgen_encapsatom(doffset, (u_int)v, op);
      Argusgen_or(tmp, b1);
      break;

   case Q_AND:
      tmp = Argusgen_encapsatom(soffset, (u_int)v, op);
      b1 = Argusgen_encapsatom(doffset, (u_int)v, op);
      Argusgen_and(tmp, b1);
      break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_encaps (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_trans(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusAgrStruct agr;
   int offset;
 
   offset = ((char *)&agr.count - (char *)&agr);
   b1 = Argusgen_transatom(offset, (u_int)v, op);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_trans (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}

static struct ablock *
Argusgen_rate(float v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&argus.srate - (char *)&argus.hdr);
      b1 = Argusgen_rateatom(offset, v, op);
      break;

   case Q_DST:
      offset = ((char *)&argus.drate - (char *)&argus.hdr);
      b1 = Argusgen_rateatom(offset, v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&argus.srate - (char *)&argus.hdr);
      b0 = Argusgen_rateatom(offset, v, op);
      offset = ((char *)&argus.drate - (char *)&argus.hdr);
      b1 = Argusgen_rateatom(offset, v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&argus.srate - (char *)&argus.hdr);
      b0 = Argusgen_rateatom(offset, v, op);
      offset = ((char *)&argus.drate - (char *)&argus.hdr);
      b1 = Argusgen_rateatom(offset, v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_rate (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_load(float v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&argus.sload - (char *)&argus.hdr);
      b1 = Argusgen_loadatom(offset, v, op);
      break;

   case Q_DST:
      offset = ((char *)&argus.dload - (char *)&argus.hdr);
      b1 = Argusgen_loadatom(offset, v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&argus.sload - (char *)&argus.hdr);
      b0 = Argusgen_loadatom(offset, v, op);
      offset = ((char *)&argus.dload - (char *)&argus.hdr);
      b1 = Argusgen_loadatom(offset, v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&argus.sload - (char *)&argus.hdr);
      b0 = Argusgen_loadatom(offset, v, op);
      offset = ((char *)&argus.dload - (char *)&argus.hdr);
      b1 = Argusgen_loadatom(offset, v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_load (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}

/*
static struct ablock *
Argusgen_loss(float v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&argus.sloss - (char *)&argus.hdr);
      b1 = Argusgen_lossatom(offset, v, op);
      break;

   case Q_DST:
      offset = ((char *)&argus.dloss - (char *)&argus.hdr);
      b1 = Argusgen_lossatom(offset, v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&argus.sloss - (char *)&argus.hdr);
      b0 = Argusgen_lossatom(offset, v, op);
      offset = ((char *)&argus.dloss - (char *)&argus.hdr);
      b1 = Argusgen_lossatom(offset, v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&argus.sloss - (char *)&argus.hdr);
      b0 = Argusgen_lossatom(offset, v, op);
      offset = ((char *)&argus.dloss - (char *)&argus.hdr);
      b1 = Argusgen_lossatom(offset, v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_loss (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}
*/

static struct ablock *
Argusgen_ploss(float v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&argus.sploss - (char *)&argus.hdr);
      b1 = Argusgen_plossatom(offset, v, op);
      break;

   case Q_DST:
      offset = ((char *)&argus.dploss - (char *)&argus.hdr);
      b1 = Argusgen_plossatom(offset, v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&argus.sploss - (char *)&argus.hdr);
      b0 = Argusgen_plossatom(offset, v, op);
      offset = ((char *)&argus.dploss - (char *)&argus.hdr);
      b1 = Argusgen_plossatom(offset, v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&argus.sploss - (char *)&argus.hdr);
      b0 = Argusgen_plossatom(offset, v, op);
      offset = ((char *)&argus.dploss - (char *)&argus.hdr);
      b1 = Argusgen_plossatom(offset, v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ploss (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}




static struct ablock *
Argusgen_pcr(float v, int dir, u_int op)
{
   struct ArgusRecordStruct argus;
   struct ablock *b1 = NULL, *b0 = NULL;
   int offset = ((char *)&argus.pcr - (char *)&argus.hdr);

   b0 = Argusgen_recordtype(ARGUS_FAR);
   b1 = Argusgen_pcratom(offset, v, op);
   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_pcr (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_inter(float v, int dir, int type, u_int op)
{
   struct ablock *b1 = NULL, *b0 = NULL;
   struct ArgusJitterStruct jitter;
   float value = v * 1000.0;
   int offset;

   switch (dir) {
      case Q_SRC:
         switch (type) {
            case Q_INTER:       offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERACTIVE: offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERIDLE:   offset = (char *)&jitter.idle.src.meanval - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         break;

      case Q_DST:
         switch (type) {
            case Q_INTER:       offset = (char *)&jitter.act.dst.meanval - (char *)&jitter; break;
            case Q_INTERACTIVE: offset = (char *)&jitter.act.dst.meanval - (char *)&jitter; break;
            case Q_INTERIDLE:   offset = (char *)&jitter.idle.dst.meanval - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         break;

      case Q_OR:
         switch (type) {
            case Q_INTER:       offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERACTIVE: offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERIDLE:   offset = (char *)&jitter.idle.src.meanval - (char *)&jitter; break;
         }
         b0 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);

         offset = (char *)&jitter.act.dst.meanval - (char *)&jitter;
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;

      case Q_DEFAULT:
      case Q_AND:
         switch (type) {
            case Q_INTER:       offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERACTIVE: offset = (char *)&jitter.act.src.meanval - (char *)&jitter; break;
            case Q_INTERIDLE:   offset = (char *)&jitter.idle.src.meanval - (char *)&jitter; break;
         }
         b0 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);

         switch (type) {
            case Q_INTER:       offset = (char *)&jitter.act.dst.meanval - (char *)&jitter; break;
            case Q_INTERACTIVE: offset = (char *)&jitter.act.dst.meanval - (char *)&jitter; break;
            case Q_INTERIDLE:   offset = (char *)&jitter.idle.dst.meanval - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_inter (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_jitter(float v, int dir, int type, u_int op)
{
   struct ablock *b1 = NULL, *b0 = NULL;
   struct ArgusJitterStruct jitter;
   float value = v * 1000.0;
   int offset;

   switch (dir) {
      case Q_SRC:
         switch (type) {
            case Q_JITTER:       offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERACTIVE: offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERIDLE:   offset = (char *)&jitter.idle.src.stdev - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         break;

      case Q_DST:
         switch (type) {
            case Q_JITTER:       offset = (char *)&jitter.act.dst.stdev - (char *)&jitter; break;
            case Q_JITTERACTIVE: offset = (char *)&jitter.act.dst.stdev - (char *)&jitter; break;
            case Q_JITTERIDLE:   offset = (char *)&jitter.idle.dst.stdev - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         break;

      case Q_OR:
         switch (type) {
            case Q_JITTER:       offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERACTIVE: offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERIDLE:   offset = (char *)&jitter.idle.src.stdev - (char *)&jitter; break;
         }
         b0 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);

         offset = (char *)&jitter.act.dst.stdev - (char *)&jitter;
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         Argusgen_or(b0, b1);
         break;

      case Q_DEFAULT:
      case Q_AND:
         switch (type) {
            case Q_JITTER:       offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERACTIVE: offset = (char *)&jitter.act.src.stdev - (char *)&jitter; break;
            case Q_JITTERIDLE:   offset = (char *)&jitter.idle.src.stdev - (char *)&jitter; break;
         }
         b0 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);

         switch (type) {
            case Q_JITTER:       offset = (char *)&jitter.act.dst.stdev - (char *)&jitter; break;
            case Q_JITTERACTIVE: offset = (char *)&jitter.act.dst.stdev - (char *)&jitter; break;
            case Q_JITTERIDLE:   offset = (char *)&jitter.idle.dst.stdev - (char *)&jitter; break;
         }
         b1 = Argusgen_fcmp(ARGUS_JITTER_INDEX, offset, NFF_F, value, op, Q_DEFAULT);
         Argusgen_and(b0, b1);
         break;
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_jitter (%f, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_dur(float v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;
 
   switch (dir) {
      case Q_SRC:
      case Q_DST:
      case Q_OR:
      case Q_DEFAULT:
      case Q_AND:
         offset = ((char *)&argus.dur - (char *)&argus.hdr);
         b1 = Argusgen_duratom(offset, v, op);
         break;

      default:
         abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dur (%f, %d, %d) returns 0x%x\n", v, dir, op, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_mean(float v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusRecordStruct argus;
   int offset;

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      offset = ((char *)&argus.mean - (char *)&argus.hdr);
      b1 = Argusgen_meanatom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_mean (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_deltadur(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;
   int offset = ((char *)&cor.metrics.deltaDur - (char *)&cor);

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      b1 = Argusgen_deltaduratom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltadur (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_deltastart(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;
   int offset = ((char *)&cor.metrics.deltaStart - (char *)&cor);

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      b1 = Argusgen_deltastartatom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltastart (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_deltalast(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;
   int offset = ((char *)&cor.metrics.deltaLast - (char *)&cor);

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      b1 = Argusgen_deltalastatom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltalast (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}


static struct ablock *
Argusgen_deltasrcpkts(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;
   int offset = ((char *)&cor.metrics.deltaSrcPkts - (char *)&cor);

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      b1 = Argusgen_deltaspktsatom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltasrcpkts (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_deltadstpkts(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;
   int offset = ((char *)&cor.metrics.deltaDstPkts - (char *)&cor);

   switch (dir) {
   case Q_SRC:
   case Q_DST:
   case Q_OR:
   case Q_DEFAULT:
   case Q_AND:
      b1 = Argusgen_deltadpktsatom(offset, v, op);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_deltadstpkts (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}


static struct ablock *
Argusgen_asn(u_int v, int dir, u_int op)
{
   struct ablock *b1 = NULL, *b0 = NULL;
   struct ArgusAsnStruct asn;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&asn.src_as - (char *)&asn);
      b1 = Argusgen_asnatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&asn.dst_as - (char *)&asn);
      b1 = Argusgen_asnatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&asn.src_as - (char *)&asn);
      b0 = Argusgen_asnatom(offset, (u_int)v, op);
      offset = ((char *)&asn.dst_as - (char *)&asn);
      b1 = Argusgen_asnatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&asn.src_as - (char *)&asn);
      b0 = Argusgen_asnatom(offset, (u_int)v, op);
      offset = ((char *)&asn.dst_as - (char *)&asn);
      b1 = Argusgen_asnatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_asn (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}


static struct ablock *
Argusgen_cor(u_int v, int dir, u_int op)
{
   struct ablock *b1 = NULL;
   struct ArgusCorrelateStruct cor;

   int offset = ((char *)&cor.hdr.argus_dsrvl8.len - (char *)&cor);
   int value = (v * ((sizeof(struct ArgusCorMetrics) + 3 )/ 4)) + 1;
   if (value == 1) value = 0;

   b1 = Argusgen_coratom(offset, (u_int)value, op);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_cor (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}

static struct ablock *
Argusgen_spi(u_int v, int dir, u_int op)
{
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusFlow flow;
   int offset = ((char *)&flow.flow_un.esp.spi - (char *)&flow);

   b1 = Argusgen_prototype(IPPROTO_ESP, Q_DEFAULT);
   b0 = Argusgen_spiatom(offset, v, op);

   if (b0)
      Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_spi (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}


/*
static struct ablock *
Argusgen_dup(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusNetworkStruct net;
   int offset;

   switch (dir) {
   case Q_SRC:
      offset = ((char *)&net.net_union.tcp.sdups - (char *)&net);
      b1 = Argusgen_dupatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&net.net_union.tcp.ddups - (char *)&net);
      b1 = Argusgen_dupatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&net.net_union.tcp.sdups - (char *)&net);
      b0 = Argusgen_dupatom(offset, (u_int)v, op);
      offset = ((char *)&net.net_union.tcp.ddups - (char *)&net);
      b1 = Argusgen_dupatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&net.net_union.tcp.sdups - (char *)&net);
      b0 = Argusgen_dupatom(offset, (u_int)v, op);
      offset = ((char *)&net.net_union.tcp.ddups - (char *)&net);
      b1 = Argusgen_dupatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_dup (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif

   return b1;
}
*/


static struct ablock *
Argusgen_tcpbase(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusNetworkStruct net;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&net.net_union.tcp.src.seqbase - (char *)&net);
      b1 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&net.net_union.tcp.dst.seqbase - (char *)&net);
      b1 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&net.net_union.tcp.src.seqbase - (char *)&net);
      b0 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      offset = ((char *)&net.net_union.tcp.dst.seqbase - (char *)&net);
      b1 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&net.net_union.tcp.src.seqbase - (char *)&net);
      b0 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      offset = ((char *)&net.net_union.tcp.dst.seqbase - (char *)&net);
      b1 = Argusgen_tcpbaseatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcpbase (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_pkt(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusMetricStruct metric;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&metric.src.pkts - (char *)&metric);
      b1 = Argusgen_pktatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&metric.dst.pkts - (char *)&metric);
      b1 = Argusgen_pktatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&metric.src.pkts - (char *)&metric);
      b0 = Argusgen_pktatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.pkts - (char *)&metric);
      b1 = Argusgen_pktatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&metric.src.pkts - (char *)&metric);
      b0 = Argusgen_pktatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.pkts - (char *)&metric);
      b1 = Argusgen_pktatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_pkt (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}


static struct ablock *
Argusgen_byte(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusMetricStruct metric;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&metric.src.bytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&metric.dst.bytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&metric.src.bytes - (char *)&metric);
      b0 = Argusgen_byteatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.bytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&metric.src.bytes - (char *)&metric);
      b0 = Argusgen_byteatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.bytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_byte (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}

struct ablock *
Argusgen_appbytes(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusMetricStruct metric;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&metric.src.appbytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&metric.dst.appbytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&metric.src.appbytes - (char *)&metric);
      b0 = Argusgen_byteatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.appbytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&metric.src.appbytes - (char *)&metric);
      b0 = Argusgen_byteatom(offset, (u_int)v, op);
      offset = ((char *)&metric.dst.appbytes - (char *)&metric);
      b1 = Argusgen_byteatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_appbytes (0x%x, %d) returns 0x%x\n", v, dir, b1);
#endif
 
   return b1;
}

struct ablock *
Argusgen_seq(int v, int dir, u_int op)
{
   struct ablock *b1 = NULL, *b0 = NULL;
   struct ArgusTransportStruct trans;
   int offset;

   offset = ((char *)&trans.seqnum - (char *)&trans);

   b1 = Argusgen_recordtype(ARGUS_FAR);
   b0 = Argusgen_cmp(ARGUS_TRANSPORT_INDEX, offset, NFF_W, (u_int)v, op, Q_DEFAULT);

   Argusgen_and(b0, b1);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_seq (0x%x, %d, 0x%x) returns %p\n", v, dir, op ,b1);
#endif

   return (b1);
}

static struct ablock *
Argusgen_nstroke(int v, int dir, u_int op)
{
   struct ablock *b0, *b1 = NULL;
   struct ArgusBehaviorStruct actor;
   int offset;
 
   switch (dir) {
   case Q_SRC:
      offset = ((char *)&actor.keyStroke.src.n_strokes - (char *)&actor);
      b1 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      break;

   case Q_DST:
      offset = ((char *)&actor.keyStroke.dst.n_strokes - (char *)&actor);
      b1 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      break;

   case Q_OR:
   case Q_DEFAULT:
      offset = ((char *)&actor.keyStroke.src.n_strokes - (char *)&actor);
      b0 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      offset = ((char *)&actor.keyStroke.dst.n_strokes - (char *)&actor);
      b1 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      Argusgen_or(b0, b1);
      break;

   case Q_AND:
      offset = ((char *)&actor.keyStroke.src.n_strokes - (char *)&actor);
      b0 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      offset = ((char *)&actor.keyStroke.dst.n_strokes - (char *)&actor);
      b1 = Argusgen_nstrokeatom(offset, (u_int)v, op);
      Argusgen_and(b0, b1);
      break;

   default:
      abort();
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_nstroke (0x%x, %d, 0x%x) returns %p\n", v, dir, op, b1);
#endif
 
   return b1;
}


/*
 * Left justify 'addr' and return its resulting network mask.
 */

#if !defined(TH_ECE)
#define TH_ECE  0x40
#endif
#if !defined(TH_CWR)  
#define TH_CWR  0x80
#endif


static u_int
net_mask(addr)
u_int *addr;
{
   register u_int m = 0xffffffff;

   if (*addr)
      while ((*addr & 0xff000000) == 0)
         *addr <<= 8, m <<= 8;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "net_mask (0x%x) returns 0x%x\n", addr, m);
#endif
 
   return m;
}


#include <netinet/tcp.h>

struct ablock *
Argusgen_ocode(int name, struct qual q)
{
   struct ablock *b1 = NULL;

   b1 = Argusgen_tcpopt(name);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ocode (0x%x, 0x%x) returns %p\n", name, q, b1);
#endif

   return b1;
}


struct ablock *
Argusgen_tcode(int name, struct qual q)
{
   int dir = q.dir;
   struct ablock *b0 = NULL, *b1 = NULL;

   switch (name) {
      case Q_OUTOFORDER: {
         switch (dir) {
            case Q_SRC: b1 = Argusgen_proto_abbrev(Q_SRCOUTOFORDER); break;
            case Q_DST: b1 = Argusgen_proto_abbrev(Q_DSTOUTOFORDER); break;
   
            case Q_AND:
               b0 = Argusgen_proto_abbrev(Q_SRCOUTOFORDER);
               b1 = Argusgen_proto_abbrev(Q_DSTOUTOFORDER);
               Argusgen_and(b0, b1);
               break;
   
            default:
            case Q_OR:  b1 = Argusgen_proto_abbrev(Q_OUTOFORDER); break;
         }
         break;
      }

      case Q_RETRANS: {
         switch (dir) {
            case Q_SRC: b1 = Argusgen_proto_abbrev(Q_SRCRETRANS); break;
            case Q_DST: b1 = Argusgen_proto_abbrev(Q_DSTRETRANS); break;

            case Q_AND:
               b0 = Argusgen_proto_abbrev(Q_SRCRETRANS);
               b1 = Argusgen_proto_abbrev(Q_DSTRETRANS);
               Argusgen_and(b0, b1);
               break;

            default:
            case Q_OR:  b1 = Argusgen_proto_abbrev(Q_RETRANS); break;
         }
         break;
      }

      case Q_FRAG: {
         switch (dir) {
            case Q_SRC: b1 = Argusgen_proto_abbrev(Q_SRCFRAG); break;
            case Q_DST: b1 = Argusgen_proto_abbrev(Q_DSTFRAG); break;

            default:
            case Q_OR:  b1 = Argusgen_proto_abbrev(Q_FRAG); break;
         }
         break;
      }

      case Q_FRAG_ONLY: {
         break;
      }

      case Q_WINSHUT: {
         switch (dir) {
            case Q_SRC: b1 = Argusgen_tcpstatustype(ARGUS_SRC_WINDOW_SHUT); break;
            case Q_DST: b1 = Argusgen_tcpstatustype(ARGUS_DST_WINDOW_SHUT); break;

            case Q_AND:
               b0 = Argusgen_tcpstatustype(ARGUS_SRC_WINDOW_SHUT);
               b1 = Argusgen_tcpstatustype(ARGUS_DST_WINDOW_SHUT);
               Argusgen_and(b0, b1);
               break;

            default:
            case Q_OR:
               b0 = Argusgen_tcpstatustype(ARGUS_SRC_WINDOW_SHUT);
               b1 = Argusgen_tcpstatustype(ARGUS_DST_WINDOW_SHUT);
               Argusgen_or(b0, b1);
               break;
         }
         break;
      }

      case Q_ECN: {
         switch (dir) {
            case Q_SRC: b1 = Argusgen_tcpstatustype(ARGUS_SRC_CONGESTED); break;
            case Q_DST: b1 = Argusgen_tcpstatustype(ARGUS_DST_CONGESTED); break;
 
            case Q_AND:
               b0 = Argusgen_tcpstatustype(ARGUS_SRC_CONGESTED);
               b1 = Argusgen_tcpstatustype(ARGUS_DST_CONGESTED);
               Argusgen_and(b0, b1);
               break;
 
            default:
            case Q_OR:
               b0 = Argusgen_tcpstatustype(ARGUS_SRC_CONGESTED);
               b1 = Argusgen_tcpstatustype(ARGUS_DST_CONGESTED);
               Argusgen_or(b0, b1);
               break;
         }
         break;
      }

      case Q_SYN: 
      case Q_ACK:
      case Q_PUSH:
      case Q_URGENT:
      case Q_RESET:
      case Q_ECE:
      case Q_CWR:
      case Q_FIN: {
         struct ArgusNetworkStruct net;
         int soffset = ((char *)&net.net_union.tcp.src.flags - (char *)&net);
         int doffset = ((char *)&net.net_union.tcp.dst.flags - (char *)&net);
         int value = 0;

         switch (name) {
            case Q_SYN:    value = TH_SYN; break;
            case Q_ACK:    value = TH_ACK; break;
            case Q_PUSH:   value = TH_PUSH; break;
            case Q_URGENT: value = TH_URG; break;
            case Q_FIN:    value = TH_FIN; break;
            case Q_RESET:  value = TH_RST; break;
            case Q_ECE:    value = TH_ECE; break;
            case Q_CWR:    value = TH_CWR; break;
         }

         switch (dir) {
            case Q_SRC: 
               b1 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, soffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               break;
            case Q_DST:
               b1 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, doffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               break;
 
            case Q_AND:
               b0 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, doffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               b1 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, soffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               Argusgen_and(b0, b1);
               break;
 
            default:
            case Q_OR:
               b0 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, soffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               b1 = Argusgen_mcmp(ARGUS_NETWORK_INDEX, doffset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               Argusgen_or(b0, b1);
               break;
         }

         b0 = Argusgen_prototype(IPPROTO_TCP, Q_DEFAULT);
         Argusgen_and(b0, b1);

         break;
      }

      case Q_MULTIPATH: {
         struct ArgusMacStruct mac;
         int offset = ((char *)&mac.hdr.argus_dsrvl8.qual - (char *)&mac);
         int value = 0;

         switch (dir) {
            case Q_SRC: {
               value = ARGUS_SRC_MULTIPATH;
               b1 = Argusgen_mcmp(ARGUS_MAC_INDEX, offset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               break;
            }
            case Q_DST: {
               value = ARGUS_DST_MULTIPATH;
               b1 = Argusgen_mcmp(ARGUS_MAC_INDEX, offset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               break;
            }
            case Q_AND: {
               value = ARGUS_MULTIPATH;
               b1 = Argusgen_mcmp(ARGUS_MAC_INDEX, offset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               break;
            }

            default:
            case Q_OR: {
               value = ARGUS_SRC_MULTIPATH;
               b0 = Argusgen_mcmp(ARGUS_MAC_INDEX, offset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);

               value = ARGUS_DST_MULTIPATH;
               b1 = Argusgen_mcmp(ARGUS_MAC_INDEX, offset, NFF_B, value, value, Q_EQUAL, Q_DEFAULT);
               Argusgen_or(b0, b1);
               break;
            }
         }
         break;
      }

      case Q_PSNP: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.isis_flow.pdu_type - (char *)&flow);
         int value = 0;

         value = L1_PSNP;
         b0 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         value = L2_PSNP;
         b1 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_ISIS);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_CSNP: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.isis_flow.pdu_type - (char *)&flow);
         int value = 0;

         value = L1_CSNP;
         b0 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         value = L2_CSNP;
         b1 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_ISIS);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_HELLO: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.isis_flow.pdu_type - (char *)&flow);
         int value = 0;

         value = L1_LAN_IIH;
         b0 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         value = L2_LAN_IIH;
         b1 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_ISIS);
         Argusgen_and(b0, b1);
         break;
      }

      case Q_LSP: {
         struct ArgusFlow flow;
         int offset = ((char *)&flow.isis_flow.pdu_type - (char *)&flow);
         int value = 0;

         value = L1_LSP;
         b0 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         value = L2_LSP;
         b1 = Argusgen_cmp (ARGUS_FLOW_INDEX, offset, NFF_W, value, Q_EQUAL, Q_DEFAULT);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_ISIS);
         Argusgen_and(b0, b1);
         break;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_tcode (0x%x, 0x%x) returns %p\n", name, q, b1);
#endif

   return b1;
}


#include <netdb.h>

struct ablock *
Argusgen_scode(char *name, struct qual q)
{
   int port, real_proto = -1, slen = 0, i;
   int type = q.type, proto = q.proto, dir = q.dir;
   u_int maskbuf[4], *mask = maskbuf;

   struct ablock *b = NULL, *tmp;
#if HAVE_GETADDRINFO
   struct addrinfo *host = NULL;
   int retn;
#else
   struct hostent *host = NULL;
   u_int **alist;
#endif
   u_char *eaddr;

   slen = strlen(name);

   if ((name[0] == '\"') && (name[strlen(name) - 1] == '\"')) {
      name++;
      name[strlen(name) - 1] = '\0';
      slen -= 2;
   }

   switch (q.addr) {
      case Q_NET: {
#if defined(CYGWIN)
         ArgusLog(LOG_ERR, "cygwin does not support net");
#else
         u_int addr = 0;
         struct netent *np;
         if ((np = getnetbyname(name)) != NULL)
            if ((addr = np->n_net) == 0)
               ArgusLog(LOG_ERR, "unknown network '%s'", name);

         *mask = net_mask(&addr);
         b = Argusgen_host(&addr, mask, type, proto, dir);
#endif
         break;
      }

      case Q_DEFAULT:
      case Q_HOST:
         switch (proto) {
            case Q_LINK: {
               eaddr = argus_ether_hostton(name);
               if (eaddr == NULL)
                  ArgusLog(LOG_ERR, "unknown ether host '%s'", name);
               b = Argusgen_ehostop(eaddr, dir);
               break;
            }
            case Q_DECNET: {
               unsigned short dn_addr = __argus_nametodnaddr(name);
               b = (Argusgen_host((u_int *)&dn_addr, 0, type, proto, dir));
               break;
            }

            case Q_DEFAULT:
            case Q_IPV6:
            case Q_IP:
            case Q_IPV4: {
#if HAVE_GETADDRINFO
               if ((retn = getaddrinfo(name, NULL, NULL, &host)) == 0) {
                  struct addrinfo *hptr = host;
                  while (host) {
                     struct sockaddr_in *sa = (struct sockaddr_in *)host->ai_addr;
                     unsigned int addr[128];
                     bcopy ((char *)&sa->sin_addr, (char *)&addr, host->ai_addrlen);

                     switch (host->ai_family) {
                        case AF_INET:  {
                           proto = Q_IPV4;
                           *mask = 0xffffffff;
                           addr[0] = ntohl(addr[0]);
                           tmp = Argusgen_host(&addr[0], mask, type, proto, dir);
                           if (b != NULL)
                              Argusgen_or(b, tmp);
                           b = tmp;
                           break;
                        }
                        case AF_INET6: {
                           proto = Q_IPV6;
                           for (i = 0; i < 4; i++) {
                              mask[i] = 0xffffffff;
                              addr[i] = ntohl(addr[i]);
                           }
                           tmp = Argusgen_host(addr, mask, type, proto, dir);
                           if (b != NULL)
                              Argusgen_or(b, tmp);
                           b = tmp;
                           break;
                        }
                     }
                     host = host->ai_next;
                  }
                  freeaddrinfo(hptr);

               } else {
                  switch (retn) {
                     case EAI_AGAIN:
                        ArgusLog(LOG_ERR, "dns server not available");
                        break;
                     case EAI_NONAME:
                        ArgusLog(LOG_ERR, "host %s unknown", name);
                        break;
#if defined(EAI_ADDRFAMILY)
                     case EAI_ADDRFAMILY:
                        ArgusLog(LOG_ERR, "host %s has no IP address", name);
                        break;
#endif
                     case EAI_SYSTEM:
                        ArgusLog(LOG_ERR, "host %s name server error %s", name, strerror(errno));
                        break;
                  }
               }
#else
               if ((host = gethostbyname(name)) != NULL) {
                  alist = (unsigned int **) host->h_addr_list;
                  while (*alist) {
                     **alist = htonl(**alist);
                     *alist++;
                  }
                  alist = (unsigned int **) host->h_addr_list;
               }

               if (alist == NULL || *alist == NULL)
                  ArgusLog(LOG_ERR, "unknown host '%s'", name);

               switch (host->h_addrtype) {
                  case AF_INET:
                     proto = Q_IPV4;
                     *mask = 0xffffffff;
                     break;
                  case AF_INET6:
                     proto = Q_IPV6;
                     for (i = 0; i < 4; i++) mask[i] = 0xffffffff;
                     break;
               }

               b = Argusgen_host(*alist++, mask, type, proto, dir);
               while (*alist) {
                  tmp = Argusgen_host(*alist++, mask, type, proto, dir);
                  Argusgen_or(b, tmp);
                  b = tmp;
               }
#endif
               break;
            }
         }
         break;

      case Q_INODE: 
      case Q_SRCID: {
         if (type == Q_STRING) {
            *mask = 0xffffffff;
            unsigned int addr = 0;

            if (slen > 4) slen = 4;
            bcopy(name, (char *)&addr, slen);

            switch (q.addr) {
               case Q_INODE:
                  b = Argusgen_inode(addr, *mask, type);
                  break;

               case Q_SRCID:
                  b = Argusgen_srcid(addr, *mask, type);
                  break;
            }
            break;

         } else {
#if HAVE_GETADDRINFO
         struct addrinfo hints;
         bzero(&hints, sizeof(hints));
         hints.ai_family = PF_INET;
         if ((retn = getaddrinfo(name, NULL, &hints, &host)) == 0) {
            struct addrinfo *hptr = host;

            while (host) {
               struct sockaddr_in *sa = (struct sockaddr_in *)host->ai_addr;
               unsigned int addr[4];
               bcopy ((char *)&sa->sin_addr, (char *)&addr, host->ai_addrlen);

               switch (host->ai_family) {
                  case AF_INET:  {
                     proto = Q_IPV4;
                     *mask = 0xffffffff;
                     addr[0] = ntohl(addr[0]);

                     switch (q.addr) {
                        case Q_INODE: 
                           tmp = Argusgen_inode(addr[0], *mask, type);
                           break;

                        case Q_SRCID: 
                           tmp = Argusgen_srcid(addr[0], *mask, type);
                           break;
                     }

                     if (b != NULL)
                        Argusgen_or(b, tmp);
                     b = tmp;
                     break;
                  }
               }
               host = host->ai_next;
            }

            freeaddrinfo(hptr);

         } else {
            switch (retn) {
               case EAI_AGAIN:
                  ArgusLog(LOG_ERR, "dns server not available");
                  break;
               case EAI_NONAME:
                  ArgusLog(LOG_ERR, "srcid %s unknown", name);
                  break;
#if defined(EAI_ADDRFAMILY)
               case EAI_ADDRFAMILY:
                  ArgusLog(LOG_ERR, "srcid %s has no IP address", name);
                  break;
#endif
               case EAI_SYSTEM:
                  ArgusLog(LOG_ERR, "srcid %s name server error %s", name, strerror(errno));
                  break;
            }
         }
#else
         if ((host = gethostbyname(name)) != NULL) {
            alist = (unsigned int **) host->h_addr_list;
            while (*alist) {
               **alist = htonl(**alist);
               *alist++;
            }
            alist = (unsigned int **) host->h_addr_list;
         }

         if (alist == NULL || *alist == NULL)
            ArgusLog(LOG_ERR, "unknown srcid '%s'", name);

         switch (q.addr) {
            case Q_INODE: {
               b = Argusgen_inode(**alist++, 0xffffffffL);
               while (*alist) {
                  tmp = Argusgen_inode(**alist++, 0xffffffffL);
                  Argusgen_or(b, tmp);
                  b = tmp;
               }
            }
            case Q_SRCID: {
               b = Argusgen_srcid(**alist++, 0xffffffffL, type);
               while (*alist) {
                  tmp = Argusgen_srcid(**alist++, 0xffffffffL, type);
                  Argusgen_or(b, tmp);
                  b = tmp;
               }
            }
         }
#endif
         }
         break;
      }

      case Q_PORT: {
         char *ptr = NULL;

         if ((proto != Q_DEFAULT) && (proto != Q_UDP) && (proto != Q_TCP) && (proto != Q_UDT)
                                  && (proto != Q_RTP) && (proto != Q_RTCP))
            ArgusLog(LOG_ERR, "illegal qualifier of 'port'");

         if ((ptr = strchr(name, '-')) != NULL) {
            char *endptr;
            int port;
            *ptr++ = '\0';
            
            port = strtol(name, (char **)&endptr, 10);
            if (endptr == name)
               break;

            b = Argusgen_ncode (ptr, port, q, Q_GEQ);

            port = strtol(ptr, (char **)&endptr, 10);
            if (endptr == ptr)
               break;

            tmp = Argusgen_ncode (ptr, port, q, Q_LEQ);
            Argusgen_and(tmp, b);

         } else {
            if (argus_nametoport(name, &port, &real_proto) == 0)
               ArgusLog(LOG_ERR, "unknown port '%s'", name);

            if ((proto == Q_UDP) || (proto == Q_RTP) || (proto == Q_RTCP) || (proto == Q_UDT)) {
               if (real_proto == IPPROTO_TCP)
                  ArgusLog(LOG_ERR, "port '%s' is tcp", name);
               else {
                  /* override PROTO_UNDEF */
                  real_proto = IPPROTO_UDP;
               }
            }
            if (proto == Q_TCP) {
               if (real_proto == IPPROTO_UDP)
                  ArgusLog(LOG_ERR, "port '%s' is udp", name);
               else
                  /* override PROTO_UNDEF */
                  real_proto = IPPROTO_TCP;
            }

            b = Argusgen_port(port, real_proto, dir, Q_EQUAL);

            if (ptr != NULL) {
               if (argus_nametoport(ptr, &port, &real_proto) == 0)
                  ArgusLog(LOG_ERR, "unknown port '%s'", name);

               tmp = Argusgen_port(port, real_proto, dir, Q_EQUAL);
               ptr[-1] = '-';
            }
         }

         break;
      }

      case Q_GATEWAY:
         eaddr = argus_ether_hostton(name);
         if (eaddr == NULL)
            ArgusLog(LOG_ERR, "unknown ether host: %s", name);

#if HAVE_GETADDRINFO
         if ((retn = getaddrinfo(name, NULL, NULL, &host)) == 0) {
            struct addrinfo *hptr = host;

            while (host) {
               struct sockaddr_in *sa = (struct sockaddr_in *)host->ai_addr;
               unsigned int addr[4];
               bcopy ((char *)&sa->sin_addr, (char *)&addr, host->ai_addrlen);

               switch (host->ai_family) {
                  case AF_INET:  {
                     proto = Q_IPV4;
                     *mask = 0xffffffff;
                     addr[0] = ntohl(addr[0]);
                     tmp = Argusgen_gateway(eaddr, &addr[0], type, proto, dir);
                     if (b != NULL)
                        Argusgen_or(b, tmp);
                     b = tmp;
                     break;
                  }
                  case AF_INET6: {
                     proto = Q_IPV6;
                     for (i = 0; i < 4; i++) {
                        mask[i] = 0xffffffff;
                        addr[i] = ntohl(addr[i]);
                     }
                     tmp = Argusgen_gateway(eaddr, addr, type, proto, dir);
                     if (b != NULL)
                        Argusgen_or(b, tmp);
                     b = tmp;
                     break;
                  }
               }
               host = host->ai_next;
            }
            freeaddrinfo(hptr);

         } else {
            switch (retn) {
               case EAI_AGAIN:
                  ArgusLog(LOG_ERR, "dns server not available");
                  break;
               case EAI_NONAME:
                  ArgusLog(LOG_ERR, "srcid %s unknown", name);
                  break;
#if defined(EAI_ADDRFAMILY)
               case EAI_ADDRFAMILY:
                  ArgusLog(LOG_ERR, "srcid %s has no IP address", name);
                  break;
#endif
               case EAI_SYSTEM:
                  ArgusLog(LOG_ERR, "srcid %s name server error %s", name, strerror(errno));
                  break;
            }
         }
#else
         if ((host = gethostbyname(name)) != NULL)
            alist = (unsigned int **) host->h_addr_list;
         if (alist == NULL || *alist == NULL)
            ArgusLog(LOG_ERR, "unknown host '%s'", name);
         b = Argusgen_gateway(eaddr, *alist, type, proto, dir);

#endif
         break;

      case Q_PROTO:
         real_proto = Arguslookup_proto(name, proto);
         if (real_proto >= 0)
            b = Argusgen_proto(real_proto, proto, dir);
         else
            ArgusLog(LOG_ERR, "unknown protocol: %s", name);
         break;

      case Q_DSB: {
         struct ArgusDSCodePointStruct *dsctable = ArgusSelectDSCodesTable(ArgusParser);
         struct ArgusDSCodePointStruct *dscode = NULL;
         int i = 0, val = -1;

         if (dsctable && (dscode = &dsctable[i])) {
            while (dscode->label != NULL) {
               if (!(strncasecmp(dscode->label, name, strlen(dscode->label)))) {
                  val = dscode->code;
                  break;
               }
               dscode = &dsctable[++i];
            }
         }

         if (val >= 0)
            b = Argusgen_dsb(val, dir, Q_EQUAL);
         break;
      }

      case Q_CO: {
         b = Argusgen_cocode(name, dir, Q_EQUAL);
         break;
      }

      case Q_ENCAPS: {
         int i = 0, val = -1;

         struct ArgusEncapsulationStruct *encaps = &argus_encapsulations[i];
         while (encaps->label != NULL) {
            if (!(strncasecmp(encaps->label, name, strlen(encaps->label)))) {
               val = encaps->code;
               break;
            }
            encaps = &argus_encapsulations[++i];
         }

         if (val >= 0)
            b = Argusgen_encaps(val, dir, Q_EQUAL);
         break;
      }

      case Q_UNDEF:
         syntax();
         /* NOTREACHED */
   }

   if (b == NULL)
      ArgusLog(LOG_ERR, "Argusgen_scode error");

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_scode (%s, 0x%x) returns %p\n", name, q, b);
#endif

   return b;
}

struct ablock *
Argusgen_mcode(char *s1, char *s2, int masklen, struct qual q)
{
   struct ArgusCIDRAddr cidrbuf, *cidr = &cidrbuf, *cidraddr = NULL;
   struct ablock *b0 = NULL;
   char buf[128];

   if (s1 != NULL) {
      if (snprintf (buf, 128, "%s/%d", s1, masklen) >= 128)
         ArgusLog(LOG_ERR, "Argusgen_mcode: addressmlength must be < 128 bytes");

      if ((cidraddr = RaParseCIDRAddr (ArgusParser, buf)) == NULL)
         ArgusLog(LOG_ERR, "Argusgen_mcode: CIDR address format error");

      bcopy ((char *)cidraddr, (char *)cidr, sizeof(*cidr));

      if (s2 != NULL) {
         if (snprintf (buf, 128, "%s/%d", s2, masklen) >= 128)
            ArgusLog(LOG_ERR, "Argusgen_mcode: addressmlength must be < 128 bytes");

         if ((cidraddr = RaParseCIDRAddr (ArgusParser, buf)) == NULL)
            ArgusLog(LOG_ERR, "Argusgen_mcode: CIDR address format error");
         bcopy ((char *)&cidraddr->addr, (char *)&cidr->mask, sizeof(cidr->mask));
      }

      switch (q.addr) {
         case Q_NET:
            b0 = Argusgen_host(cidr->addr, cidr->mask, q.type, q.proto, q.dir);
            break;

         default:
            ArgusLog(LOG_ERR, "Mask syntax for networks only");
            /* NOTREACHED */
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_mcode (%s, %s, %d, 0x%x) returns %p\n", s1, s2, masklen, q, b0);
#endif

   return b0;
}


struct ablock *
Argusgen_ncode(char *s, int v, struct qual q, u_int op)
{
   int dir = q.dir, vlen, proto = q.proto, type = q.type;
   u_int *addr = NULL, maskbuf[4], *mask = maskbuf;
   struct ablock *b;

   bzero(mask, sizeof(maskbuf));
   switch (type) {
      case Q_IPV6: {
         vlen = 128;
         break;
      }

      case Q_IPV4: {
         if (s == NULL)
            vlen = 32;
         else
            vlen = __argus_atoin(s, (unsigned int *)&v);
         break;
      }
   }

   switch (q.addr) {
      case Q_DEFAULT:
      case Q_HOST:
      case Q_NET:
         switch (type) {
            case Q_LINK:
               ArgusLog(LOG_ERR, "illegal link layer address");
               break;

            case Q_IPV6: {
               struct ArgusCIDRAddr *cidraddr = RaParseCIDRAddr (ArgusParser, s);
               int i, len;
               memset((char *)mask, 0, sizeof(maskbuf));
               for (i = 0, len = cidraddr->masklen; i < len; i++)
                  mask[i/32] |= (1 << (31 - (i % 32)));
               for (i = 0; i < 4; i++)
                  mask[i] = ntohl(mask[i]);

               addr = (u_int*)&cidraddr->addr;
               break;
            }

            case Q_IP:
            case Q_IPV4: {
               *mask = 0xffffffff;
               if ((s == NULL) && (q.addr == Q_NET)) {
                  /* Promote short net number */
                  while (v && (v & 0xff000000) == 0) {
                     v <<= 8;
                     *mask <<= 8;
                  }
               } else {
                  /* Promote short ipaddr */
                  v <<= 32 - vlen;
                  *mask <<= 32 - vlen;
               }
               addr = (u_int *)&v;
               break;
            }
         }

         b = Argusgen_host(addr, mask, type, proto, dir);
         break;

      case Q_SRCID:
         *mask = 0xffffffff;
         b = Argusgen_srcid(v, *mask, type);
         break;

      case Q_INODE:
         *mask = 0xffffffff;
         b = Argusgen_inode(v, *mask, type);
         break;

      case Q_PORT: {
         switch (proto) {
            case Q_UDP:     proto = IPPROTO_UDP; break;
            case Q_UDT:     proto = IPPROTO_UDT; break;
            case Q_RTP:     proto = IPPROTO_RTP; break;
            case Q_RTCP:    proto = IPPROTO_RTCP; break;
            case Q_TCP:     proto = IPPROTO_TCP; break;
            case Q_DEFAULT: proto = PROTO_UNDEF; break;
            default: ArgusLog(LOG_ERR, "illegal qualifier of 'port'");
         }

         b = Argusgen_port((int)v, proto, dir, op);
         break;
      }

      case Q_GATEWAY:
         ArgusLog(LOG_ERR, "'gateway' requires a name");
         /* NOTREACHED */

      case Q_PROTO:
         b = Argusgen_proto((int)v, proto, dir);
         break;

      case Q_IPID:
         b = Argusgen_ipid((int)v, dir, op);
         break;

      case Q_TTL:
         b = Argusgen_ttl((int)v, dir, op);
         break;

      case Q_TOS:
         b = Argusgen_tos((int)v, dir, op);
         break;

      case Q_DSB: {
         b = Argusgen_dsb((int)v, dir, op);
         break;
      }

      case Q_VID:
         b = Argusgen_vid((int)v, dir, op);
         break;

      case Q_VPRI:
         b = Argusgen_vpri((int)v, dir, op);
         break;

      case Q_MPLSID:
         b = Argusgen_mid((int)v, dir, op);
         break;

      case Q_BYTE:
         b = Argusgen_byte((int)v, dir, op);
         break;

      case Q_PKT:
         b = Argusgen_pkt((int)v, dir, op);
         break;

      case Q_NSTROKE:
         b = Argusgen_nstroke((int)v, dir, op);
         break;

      case Q_SEQ:
         b = Argusgen_seq((int)v, dir, op);
         break;

      case Q_APPBYTE:
         b = Argusgen_appbytes((int)v, dir, op);
         break;

      case Q_TCPBASE:
         b = Argusgen_tcpbase((int)v, dir, op);
         break;

      case Q_TRANS:
         b = Argusgen_trans((int)v, dir, op);
         break;

      case Q_LOAD:
         b = Argusgen_load(v, dir, op);
         break;

      case Q_RATE:
         b = Argusgen_rate(v, dir, op);
         break;
/*
      case Q_LOSS:
         b = Argusgen_loss(v, dir, op);
         break;
*/
      case Q_PLOSS:
         b = Argusgen_ploss(v, dir, op);
         break;

/*
      case Q_GAP:
         b = Argusgen_gap(v, dir, op);
         break;

      case Q_DUP:
         b = Argusgen_dup(v, dir, op);
         break;
*/

      case Q_PCR:
         b = Argusgen_pcr(v, dir, op);
         break;

      case Q_INTER:
      case Q_INTERACTIVE:
      case Q_INTERIDLE:
         b = Argusgen_inter((int)v, dir, type, op);
         break;

      case Q_JITTER:
      case Q_JITTERACTIVE:
      case Q_JITTERIDLE:
         b = Argusgen_jitter(v, dir, type, op);
         break;

      case Q_DUR:
         b = Argusgen_dur(v, dir, op);
         break;

      case Q_AVGDUR:
         b = Argusgen_mean(v, dir, op);
         break;

      case Q_DELTADUR:
         b = Argusgen_deltadur(v, dir, op);
         break;

      case Q_DELTASTART:
         b = Argusgen_deltastart(v, dir, op);
         break;

      case Q_DELTALAST:
         b = Argusgen_deltalast(v, dir, op);
         break;

      case Q_DELTASPKTS:
         b = Argusgen_deltasrcpkts(v, dir, op);
         break;

      case Q_DELTADPKTS:
         b = Argusgen_deltadstpkts(v, dir, op);
         break;

      case Q_SPI:
         b = Argusgen_spi(v, dir, op);
         break;

      case Q_ASN:
         b = Argusgen_asn((int)v, dir, op);
         break;

      case Q_CORRELATED: 
         b = Argusgen_cor((int)v, dir, op);
         break;

      case Q_UNDEF:
         syntax();
         /* NOTREACHED */

      default:
         abort();
         /* NOTREACHED */
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ncode (%s, 0x%x, 0x%x, 0x%x) returns %p\n", s, v, &q, op, b);
#endif

   return b;
}

struct ablock *
Argusgen_fcode(char *s, float v, struct qual q, u_int op)
{
   int dir = q.dir;
   struct ablock *b;

   switch (q.addr) {
      case Q_LOAD:
         b = Argusgen_load(v, dir, op);
         break;

      case Q_RATE:
         b = Argusgen_rate(v, dir, op);
         break;

      case Q_INTER:
      case Q_INTERACTIVE:
      case Q_INTERIDLE:
         b = Argusgen_inter(v, dir, q.addr, op);
         break;

      case Q_JITTER:
      case Q_JITTERACTIVE:
      case Q_JITTERIDLE:
         b = Argusgen_jitter(v, dir, q.addr, op);
         break;

      case Q_DUR:
         b = Argusgen_dur(v, dir, op);
         break;

      case Q_AVGDUR:
         b = Argusgen_mean(v, dir, op);
         break;

      case Q_PLOSS:
         b = Argusgen_ploss(v, dir, op);
         break;

      case Q_PCR:
         b = Argusgen_pcr(v, dir, op);
         break;

      case Q_UNDEF:
         syntax();
         /* NOTREACHED */

      default:
         abort();
         /* NOTREACHED */
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_fcode (%s, %f, 0x%x, 0x%x) returns %p\n", s, v, &q, op, b);
#endif

   return b;
}

struct ablock *
Argusgen_ecode( u_char *eaddr, struct qual q)
{
   struct ablock *b0 = NULL, *b1 = NULL;
   struct ArgusFlow flow;
   int offset, len;

   switch (q.proto) {
      case Q_LINK:
      case Q_ETHER:
         if (q.addr == Q_HOST || q.addr == Q_DEFAULT)
            b0 = Argusgen_ehostop(eaddr, (int)q.dir);
         break;

      case Q_ARP:
         if (q.addr == Q_HOST) {
            b1 =  Argusgen_linktype(ETHERTYPE_ARP);
            offset = ((char *)&flow.arp_flow.haddr.h_un.ethernet - (char *)&flow);
            len = sizeof(flow.arp_flow.haddr.h_un.ethernet);
            b0 = Argusgen_bcmp (ARGUS_FLOW_INDEX, offset, len, eaddr, Q_DEFAULT);
            Argusgen_and(b1, b0);
         }
         break;

      default:
         ArgusLog(LOG_ERR, "ethernet address used in non-ether expression");
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_ecode (0x%x, 0x%x) returns %p\n", eaddr, q, b0);
#endif

   return b0;
}

void
Argussappend(s0, s1)
struct slist *s0, *s1;
{
   /*
    * This is definitely not the best way to do this, but the
    * lists will rarely get long.
    */
   while (s0->next)
      s0 = s0->next;
   s0->next = s1;

#if defined(ARGUSDEBUG)
   ArgusDebug (7, "Argussappend (0x%x, 0x%x)\n", s0, s1);
#endif
}

static struct slist *
xfer_to_x(a)
struct arth *a;
{
   struct slist *s;

   s = new_stmt(NFF_LDX|NFF_MEM);
   s->s.data.k = a->regno;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "xfer_to_x (0x%x) returns %p\n", a, s);
#endif

   return s;
}

static struct slist *
xfer_to_a(a)
struct arth *a;
{
   struct slist *s;

   s = new_stmt(NFF_LD|NFF_MEM);
   s->s.data.k = a->regno;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "xfer_to_a (0x%x) returns %p\n", a, s);
#endif

   return s;
}

struct arth *
ArgusLoad(proto, index, size)
int proto;
struct arth *index;
int size;
{
   struct slist *s, *tmp;
   struct ablock *b;
   int regno = alloc_reg();

   free_reg(index->regno);
   switch (size) {

   default:
      ArgusLog(LOG_ERR, "data size must be 1, 2, or 4");

   case 1:
      size = NFF_B;
      break;

   case 2:
      size = NFF_H;
      break;

   case 4:
      size = NFF_W;
      break;

   case 8:
      size = NFF_L;
      break;
   }

   switch (proto) {
   default:
      ArgusLog(LOG_ERR, "unsupported index operation");

   case Q_LINK:
      s = xfer_to_x(index);
      tmp = new_stmt(NFF_LD|NFF_IND|size);
      Argussappend(s, tmp);
      Argussappend(index->s, s);
      break;

   case Q_IP:
   case Q_IPV4:
   case Q_IPV6:
   case Q_ARP:
   case Q_RARP:
      s = xfer_to_x(index);
      tmp = new_stmt(NFF_LD|NFF_IND|size);
      tmp->s.data.k = off_nl;
      Argussappend(s, tmp);
      Argussappend(index->s, s);

      b = Argusgen_proto_abbrev(proto);
      if (index->b)
         Argusgen_and(index->b, b);
      index->b = b;
      break;

   case Q_TCP:
   case Q_RTP:
   case Q_RTCP:
   case Q_UDT:
   case Q_UDP:
   case Q_ICMP:
   case Q_IGMP:
   case Q_IGRP:
      s = new_stmt(NFF_LDX|NFF_MSH|NFF_B);
      s->s.data.k = off_nl;
      Argussappend(s, xfer_to_a(index));
      Argussappend(s, new_stmt(NFF_ALU|NFF_ADD|NFF_X));
      Argussappend(s, new_stmt(NFF_MISC|NFF_TAX));
      Argussappend(s, tmp = new_stmt(NFF_LD|NFF_IND|size));
      tmp->s.data.k = off_nl;
      Argussappend(index->s, s);

      b = Argusgen_proto_abbrev(proto);
      if (index->b)
         Argusgen_and(index->b, b);
      index->b = b;
      break;
   }
   index->regno = regno;
   s = new_stmt(NFF_ST);
   s->s.data.k = regno;
   Argussappend(index->s, s);

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusLoad (0x%x, 0x%x, 0x%x) returns %p\n", proto, index, size, index);
#endif

   return index;
}

struct ablock *
Argusgen_relation(code, a0, a1, reversed)
int code;
struct arth *a0, *a1;
int reversed;
{
   struct slist *s0, *s1, *s2;
   struct ablock *b, *tmp;

   s0 = xfer_to_x(a1);
   s1 = xfer_to_a(a0);
   s2 = new_stmt(NFF_ALU|NFF_SUB|NFF_X);
   b = new_block(JMP(code));
   if (reversed)
      Argusgen_not(b);

   Argussappend(s1, s2);
   Argussappend(s0, s1);
   Argussappend(a1->s, s0);
   Argussappend(a0->s, a1->s);

   b->stmts = a0->s;

   free_reg(a0->regno);
   free_reg(a1->regno);

   /* 'and' together protocol checks */
   if (a0->b) {
      if (a1->b) {
         Argusgen_and(a0->b, tmp = a1->b);
      }
      else
         tmp = a0->b;
   } else
      tmp = a1->b;

   if (tmp)
      Argusgen_and(tmp, b);

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "Argusgen_relation (0x%x, 0x%x, 0x%x, %d) returns %p\n", code, a0, a1, reversed, b);
#endif

   return b;
}

struct arth *
ArgusLoadLen()
{
   int regno = alloc_reg();
   struct arth *a = (struct arth *)newchunk(sizeof(*a));
   struct slist *s;

   s = new_stmt(NFF_LD|NFF_LEN);
   s->next = new_stmt(NFF_ST);
   s->next->s.data.k = regno;
   a->s = s;
   a->regno = regno;

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusLoadLen () returns %p\n", a);
#endif

   return a;
}

struct arth *
ArgusLoadI(val)
int val;
{
   struct arth *a;
   struct slist *s;
   int reg;

   a = (struct arth *)newchunk(sizeof(*a));

   reg = alloc_reg();

   s = new_stmt(NFF_LD|NFF_IMM);
   s->s.data.k = val;
   s->next = new_stmt(NFF_ST);
   s->next->s.data.k = reg;
   a->s = s;
   a->regno = reg;

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "ArgusLoadI (0x%x) returns %p\n", val, a);
#endif

   return a;
}

struct arth *
ArgusNeg(a)
struct arth *a;
{
   struct slist *s;

   s = xfer_to_a(a);
   Argussappend(a->s, s);
   s = new_stmt(NFF_ALU|NFF_NEG);
   s->s.data.k = 0;
   Argussappend(a->s, s);
   s = new_stmt(NFF_ST);
   s->s.data.k = a->regno;
   Argussappend(a->s, s);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "ArgusNeg (0x%x) returns %p\n", a, a);
#endif

   return a;
}

struct arth *
ArgusArth( int code, struct arth *a0, struct arth *a1)
{
   struct slist *s0, *s1, *s2;

   s0 = xfer_to_x(a1);
   s1 = xfer_to_a(a0);
   s2 = new_stmt(NFF_ALU|NFF_X|code);

   Argussappend(s1, s2);
   Argussappend(s0, s1);
   Argussappend(a1->s, s0);
   Argussappend(a0->s, a1->s);

   free_reg(a1->regno);

   s0 = new_stmt(NFF_ST);
   a0->regno = s0->s.data.k = alloc_reg();
   Argussappend(a0->s, s0);

#if defined(ARGUSDEBUG)
   ArgusDebug (5, "Argusgen_arth (0x%x, 0x%x, 0x%x) returns %p\n", code, a0, a1, a0);
#endif

   return a0;
}

/*
 * Here we handle simple allocation of the scratch registers.
 * If too many registers are alloc'd, the allocator punts.
 */
static int regused[NFF_MEMWORDS];
static int curreg;

/*
 * Return the next free register.
 */
static int
alloc_reg()
{
   int retn = -1;
   int n = NFF_MEMWORDS;

   while (--n >= 0) {
      if (regused[curreg])
         curreg = (curreg + 1) % NFF_MEMWORDS;
      else {
         regused[curreg] = 1;
         retn = curreg;
         break;
      }
   }

   if (retn == -1)
      ArgusLog(LOG_ERR, "too many registers needed to evaluate expression");

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "alloc_reg () returns %p\n", retn);
#endif

   return (retn);
}

/*
 * Return a register to the table so it can
 * be used later.
 */

static void
free_reg(n)
int n;
{
   regused[n] = 0;

#if defined(ARGUSDEBUG)
   ArgusDebug (9, "free_reg (%d)\n", n);
#endif
}

static struct ablock *
Argusgen_len(jmp, n)
int jmp, n;
{
   struct slist *s;
   struct ablock *b;

   s = new_stmt(NFF_LD|NFF_LEN);
   s->next = new_stmt(NFF_ALU|NFF_SUB|NFF_K);
   s->next->s.data.k = n;
   b = new_block(JMP(jmp));
   b->stmts = s;

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "Argusgen_len (%d, %d) return %p\n", jmp, n, b);
#endif

   return b;
}

struct ablock *
Argusgen_greater(n)
int n;
{
   struct ablock *b;

   b = Argusgen_len(NFF_JGE, n);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "Argusgen_greater (%d) return %p\n", n, b);
#endif

   return b;
}

struct ablock *
Argusgen_less(n)
int n;
{
   struct ablock *b;

   b = Argusgen_len(NFF_JGT, n);
   Argusgen_not(b);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "Argusgen_less (%d) return %p\n", n, b);
#endif

   return b;
}

struct ablock *
Argusgen_byteop(op, idx, val)
int op, idx, val;
{
   struct ablock *b;
   struct slist *s;

   switch (op) {
   default:
      abort();

   case '=':
      return Argusgen_cmp(-1, (u_int)idx, NFF_B, (u_int)val, Q_EQUAL, Q_DEFAULT);

   case '<':
      b = Argusgen_cmp(-1, (u_int)idx, NFF_B, (u_int)val, Q_EQUAL, Q_DEFAULT);
      b->s.code = JMP(NFF_JGE);
      Argusgen_not(b);
      return b;

   case '>':
      b = Argusgen_cmp(-1, (u_int)idx, NFF_B, (u_int)val, Q_EQUAL, Q_DEFAULT);
      b->s.code = JMP(NFF_JGT);
      return b;

   case '|':
      s = new_stmt(NFF_ALU|NFF_OR|NFF_K);
      break;

   case '&':
      s = new_stmt(NFF_ALU|NFF_AND|NFF_K);
      break;
   }
   s->s.data.k = val;
   b = new_block(JMP(NFF_JEQ));
   b->stmts = s;
   Argusgen_not(b);

#if defined(ARGUSDEBUG)
   ArgusDebug (6, "Argusgen_byteop (0x%x, 0x%x, 0x%x) return %p\n", op, idx, val, b);
#endif

   return b;
}

struct ablock *
Argusgen_broadcast(proto)
int proto;
{
   struct ablock *b0 = NULL, *b1 = NULL;
   static u_char ebroadcast[] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
   u_int netaddr = 0xffffffffL, mask;
/*
   u_int classmask = 0xffffffffL;
*/

   switch (proto) {
      case Q_LINK:
         b0 = Argusgen_ehostop(ebroadcast, Q_OR);
         break;

      case Q_IP:
         mask = 0xffffffffL;
/*
         if (ArgusParser->ArgusCurrentInput) {
            netaddr = ArgusParser->ArgusLocalNet & ArgusParser->ArgusNetMask;
            classmask = ipaddrtonetmask(ArgusParser->ArgusLocalNet);
            b1 = Argusgen_host((u_int *)&netaddr, &mask, Q_IPV4, proto, Q_OR);
            netaddr |= ~(~0 & ArgusNetMask);
            b0 = Argusgen_host((u_int *)&netaddr, &mask, Q_IPV4, proto, Q_OR);
            Argusgen_or(b1, b0);
            if (classmask != ArgusNetMask) {
               netaddr = ArgusParser->ArgusLocalNet & classmask;
               b1 = Argusgen_host((u_int *)&netaddr, &mask, Q_IPV4, proto, Q_OR);
               Argusgen_or(b1, b0);
            }
         }
*/
         netaddr = ~0;
         b1 = Argusgen_host( (u_int *)&netaddr, &mask, Q_IPV4, proto, Q_OR);
         if (b0 != NULL)
            Argusgen_or(b1, b0);
         else
            b0 = b1;
         break;

      case Q_DEFAULT:
         ArgusLog(LOG_ERR, "only ether/ip broadcast filters supported");
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_broadcast (0x%x) returns %p\n", proto, b0);
#endif

   return b0;
}

struct ablock *
Argusgen_multicast(proto)
int proto;
{
   register struct ablock *b0 = NULL, *b1 = NULL;
   register struct slist *s;

   switch (proto) {
      case Q_LINK:
         s = new_stmt(NFF_LD|NFF_B|NFF_ABS);
         s->s.data.k = 92;
         b0 = new_block(JMP(NFF_JSET));
         b0->s.data.k = 1;
         b0->stmts = s;

         s = new_stmt(NFF_LD|NFF_B|NFF_ABS);
         s->s.data.k = 98;
         b1 = new_block(JMP(NFF_JSET));
         b1->s.data.k = 1;
         b1->stmts = s;
   
         Argusgen_or(b0, b1);
         break;

      case Q_IP:
      case Q_DEFAULT: {
         struct ArgusFlow flow;
         int src_off = 0, dst_off = 0;

         src_off = ((char *)&flow.ip_flow.ip_src - (char *)&flow);
         dst_off = ((char *)&flow.ip_flow.ip_dst - (char *)&flow);

         b1 = Argusgen_mcmp(ARGUS_FLOW_INDEX, src_off, NFF_W, 0xe0000000, 0xf0000000, Q_EQUAL, Q_DEFAULT);
         b1->s.code = JMP(NFF_JGE);
         b0 = Argusgen_mcmp(ARGUS_FLOW_INDEX, dst_off, NFF_W, 0xe0000000, 0xf0000000, Q_EQUAL, Q_DEFAULT);
         b0->s.code = JMP(NFF_JGE);
         Argusgen_or(b0, b1);
         b0 =  Argusgen_linktype(ETHERTYPE_IP);
         Argusgen_and(b0, b1);
         break;
      }
   }

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_multicast (0x%x) returns %p\n", proto, b1);
#endif

   return b1;
}

/*
 * generate command for inbound/outbound.  It's here so we can
 * make it link-type specific.  'dir' = 0 implies "inbound",
 * = 1 implies "outbound".
 */

struct ablock *
Argusgen_inbound(dir)
int dir;
{
   register struct ablock *b0;

   b0 = Argusgen_relation(NFF_JEQ,
           ArgusLoad(Q_LINK, ArgusLoadI(0), 1),
           ArgusLoadI(0),
           dir);

#if defined(ARGUSDEBUG)
   ArgusDebug (4, "Argusgen_multicast (0x%x) returns %p\n", dir, b0);
#endif

   return (b0);
}
