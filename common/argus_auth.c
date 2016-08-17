/*
 * Argus Software.  Common library routines - Authentication
 * Copyright (c) 2000-2015 QoSient, LLC
 * All rights reserved.
 *
 * QoSIENT, LLC DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS
 * SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL QoSIENT, LLC BE LIABLE FOR ANY
 * SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION,
 * ARISING OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF
 * THIS SOFTWARE.
 *
 */

/*
 * $Id: //depot/argus/argus/common/argus_auth.c#13 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

/*
 * Copyright (c) 2000 Carnegie Mellon University.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. The name "Carnegie Mellon University" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For permission or any other legal
 *    details, please contact
 *      Office of Technology Transfer
 *      Carnegie Mellon University
 *      5000 Forbes Avenue
 *      Pittsburgh, PA  15213-3890
 *      (412) 268-4387, fax: (412) 268-7395
 *      tech-transfer@andrew.cmu.edu
 *
 * 4. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Computing Services
 *     at Carnegie Mellon University (http://www.cmu.edu/computing/)."
 *
 * CARNEGIE MELLON UNIVERSITY DISCLAIMS ALL WARRANTIES WITH REGARD TO
 * THIS SOFTWARE, INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
 * AND FITNESS, IN NO EVENT SHALL CARNEGIE MELLON UNIVERSITY BE LIABLE
 * FOR ANY SPECIAL, INDIRECT OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN
 * AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

/*
 * Written/Maintained/Modified by Carter Bullard
 * QoSient, LLC
 *
 */

/* 
 * $Id: //depot/argus/argus/common/argus_auth.c#13 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusAuth
#define ArgusAuth
#endif

#include <stdlib.h>
#include <unistd.h>

#include <errno.h>
#include <netinet/in.h>
#include <string.h>

#ifdef ARGUS_SASL

#include <ctype.h>
#include <assert.h>
#include <sasl.h>

#endif /* ARGUS_SASL */

#include <compat.h>
#include <pcap.h>

#include <interface.h>

#include <argus_parse.h>
#include <argus_util.h>
#include <argus_out.h>
#include <argus_filter.h>


extern void ArgusLog (int, char *, ...);

int ArgusInitializeAuthentication (struct ARGUS_INPUT *);
int ArgusAuthenticate (struct ARGUS_INPUT *);

#ifdef ARGUS_SASL

static int RaGetRealm(void *context, int, const char **, const char **);
static int RaSimple(void *context, int, const char **, unsigned *);
static int RaGetSecret(sasl_conn_t *, void *context, int, sasl_secret_t **);

int RaSaslNegotiate(FILE *, FILE *, sasl_conn_t *);
int RaGetSaslString (FILE *, char *, int);
int RaSendSaslString (FILE *, const char *, int);

/* RaCallBacks we support */

static sasl_callback_t RaCallBacks[] = {
  { SASL_CB_GETREALM, &RaGetRealm,  NULL },
  { SASL_CB_USER,     &RaSimple,    NULL },
  { SASL_CB_AUTHNAME, &RaSimple,    NULL },
  { SASL_CB_PASS,     &RaGetSecret, NULL },
  { SASL_CB_LIST_END, NULL, NULL }
};

char *RaSaslMech = NULL;

#endif 


int
ArgusInitializeAuthentication (struct ARGUS_INPUT *input)
{
   int retn = 1;

#ifdef ARGUS_SASL
   struct sockaddr_in localaddr, remoteaddr;
   int salen, fd = input->fd;
   char *localhostname = NULL;

   if ((retn = sasl_client_init(RaCallBacks)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() sasl_client_init %d", retn);

   localhostname = ArgusCalloc (1, 1024);
   gethostname(localhostname, 1024);
   if (!strchr (localhostname, '.')) {
      strcat (localhostname, ".");
      getdomainname (&localhostname[strlen(localhostname)], 1024 - strlen(localhostname));
   }

   if ((retn = sasl_client_new("argus", localhostname, NULL, SASL_SECURITY_LAYER, &input->sasl_conn)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() sasl_client_new %d", retn);
   
   /* set external properties here
   sasl_setprop(input->sasl_conn, SASL_SSF_EXTERNAL, &extprops); */
   
   /* set required security properties here
   sasl_setprop(input->sasl_conn, SASL_SEC_PROPS, &secprops); */
   
   /* set ip addresses */
   salen = sizeof(localaddr);
   if (getsockname(fd, (struct sockaddr *)&localaddr, &salen) < 0)
      perror("getsockname");

   salen = sizeof(remoteaddr); 
   if (getpeername(fd, (struct sockaddr *)&remoteaddr, &salen) < 0)
      perror("getpeername");

   if ((retn = sasl_setprop(input->sasl_conn, SASL_IP_LOCAL, &localaddr)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() error setting localaddr %d", retn);

   if ((retn = sasl_setprop(input->sasl_conn, SASL_IP_REMOTE, &remoteaddr)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusInitializeAuthentication() error setting remoteaddr %d", retn);

   retn = 1;
#endif 

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusInitializeAuthentication () returning %d\n", retn);
#endif 

   return (retn);
}


int
ArgusAuthenticate (struct ARGUS_INPUT *input)
{
   int retn = 0;

   if (ArgusInitializeAuthentication(input)) {
#ifdef ARGUS_SASL
      int fd = input->fd;

      if ((input->in = fdopen(fd, "r")) == NULL)
         ArgusLog (LOG_ERR, "ArgusAuthenticate(0x%x) fdopen in failed %s", strerror(errno));

      if ((input->out = fdopen(fd, "w")) == NULL)
         ArgusLog (LOG_ERR, "ArgusAuthenticate(0x%x) fdopen out failed %s", strerror(errno));

      if ((retn = RaSaslNegotiate(input->in, input->out, input->sasl_conn)) == SASL_OK)
         retn = 1;
      else
         retn = 0;
#endif 
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusAuthenticate (0x%x) returning %d\n", input, retn);
#endif 

   return (retn);
}


#ifdef ARGUS_SASL

static void RaChop (char *s)          /* remove \r\n at end of the line */
{
   char *p;

   assert(s);

   p = s + strlen(s) - 1;
   if (p[0] == '\n')
      *p-- = '\0';

   if (p >= s && p[0] == '\r')
      *p-- = '\0';
}

static int
RaGetRealm(void *context __attribute__((unused)), int id,
           const char **availrealms, const char **result)
{
   static char buf[1024];

   if (id != SASL_CB_GETREALM)
      return SASL_BADPARAM;

   if (!result)
      return SASL_BADPARAM;

   printf("please choose a realm (available:");
   while (*availrealms) {
      printf(" %s", *availrealms);
      availrealms++;
   }
   printf("): ");

   fgets(buf, sizeof buf, stdin);
   RaChop(buf);
   *result = buf;
  
   return SASL_OK;
}

static char RaSimpleBuf[1024];

static int
RaSimple(void *context __attribute__((unused)), int id,
         const char **result, unsigned *len)
{
   char *ptr = NULL;

   if (! result)
      return SASL_BADPARAM;

   switch (id) {
      case SASL_CB_USER:
         if (ustr == NULL) {
            printf("please enter an authorization id: ");
            fgets(RaSimpleBuf, sizeof(RaSimpleBuf), stdin);

         } else {
            if ((ptr = strchr(ustr, '/')) != NULL)
                *ptr = '\0';
          
            snprintf (RaSimpleBuf, sizeof(RaSimpleBuf), "%s", ustr);
            if (ptr)
               *ptr = '/';
         }

         break;

      case SASL_CB_AUTHNAME:
         if (ustr != NULL)
            if ((ptr = strchr(ustr, '/')) != NULL)
               ptr++;

         if (ptr == NULL) {
            printf("please enter an authentication id: ");
            fgets(RaSimpleBuf, sizeof RaSimpleBuf, stdin);
         } else 
            snprintf (RaSimpleBuf, sizeof(RaSimpleBuf), "%s", ptr);

         break;

      default:
         return SASL_BADPARAM;
   }

   RaChop(RaSimpleBuf);
   *result = RaSimpleBuf;

   if (len)
      *len = strlen(RaSimpleBuf);
  
   return SASL_OK;
}

#ifndef HAVE_GETPASSPHRASE
static char *
getpassphrase(const char *prompt)
{
  return getpass(prompt);
}
#endif

static int
RaGetSecret(sasl_conn_t *conn, void *context __attribute__((unused)),
            int id, sasl_secret_t **psecret)
{
   char *password;
   size_t len;
   static sasl_secret_t *x;

   if (! conn || ! psecret || id != SASL_CB_PASS)
      return SASL_BADPARAM;

   if (pstr !=  NULL)
      password = pstr;
   else
      password = getpassphrase("Password: ");

   if (! password)
      return SASL_FAIL;

   len = strlen(password);

   x = (sasl_secret_t *) realloc(x, sizeof(sasl_secret_t) + len);
  
   if (!x) {
      memset(password, 0, len);
      return SASL_NOMEM;
   }

   x->len = len;
#if defined(HAVE_STRLCPY)
   strlcpy(x->data, password, len);
#else
   memset(x->data, 0, len);
   strncpy(x->data, password, len);
#endif
   memset(password, 0, len);
   
   *psecret = x;
   return SASL_OK;
}


int
RaSaslNegotiate(FILE *in, FILE *out, sasl_conn_t *conn)
{
   int retn = 0;
   char buf[8192];
   char *data;
   const char *chosenmech;
   int len, c;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSaslNegotiate(0x%x, 0x%x, 0x%x) receiving capability list... ", in, out, conn);
#endif

   if ((len = RaGetSaslString(in, buf, sizeof(buf))) <= 0)
      ArgusLog (LOG_ERR, "RaSaslNegotiate: RaGetSaslString(0x%x, 0x%x, %d) error %s\n", in, buf, sizeof(buf), strerror(errno));

   if (RaSaslMech) {
   /* make sure that 'RaSaslMech' appears in 'buf' */
      if (!strstr(buf, RaSaslMech)) {
         printf("server doesn't offer mandatory mech '%s'\n", RaSaslMech);
         return 0;
      }
   } else
      RaSaslMech = buf;

#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSaslNegotiate(0x%x, 0x%x, 0x%x) calling sasl_client_start()", in, out, conn);
#endif 

   retn = sasl_client_start(conn, RaSaslMech, NULL, NULL, &data, &len, &chosenmech);

   if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
      fputc ('N', out);
      fflush(out);
      ArgusLog (LOG_ERR, "RaSaslNegotiate: error starting SASL negotiation");
   }

   if (retn == SASL_INTERACT)
      ArgusLog (LOG_ERR, "RaSaslNegotiate: returned SASL_INTERACT\n");
   
#ifdef ARGUSDEBUG
   ArgusDebug (1, "RaSaslNegotiate: using mechanism %s\n", chosenmech);
#endif 

   /* we send two strings; the mechanism chosen and the initial response */

   RaSendSaslString(out, chosenmech, strlen(chosenmech));
   RaSendSaslString(out, data, len);

   for (;;) {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "waiting for server reply...\n");
#endif 

      switch (c = fgetc(in)) {
         case 'O':
            goto done_ok;

         case 'N':
            goto done_no;

         case 'C': /* continue authentication */
            break;

         default:
            printf("bad protocol from server (%c %x)\n", c, c);
            return 0;
         }

      if ((len = RaGetSaslString(in, buf, sizeof(buf))) <= 0)
         ArgusLog (LOG_ERR, "RaSaslNegotiate: RaGetSaslString(0x%x, 0x%x, %d) returned %d\n", in, buf, sizeof(buf), len);

      retn = sasl_client_step(conn, buf, len, NULL, &data, &len);

      if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
         fputc ('N', out);
         fflush(out);
         ArgusLog (LOG_ERR, "RaSaslNegotiate: error performing SASL negotiation");
      }

      if (data) {

#ifdef ARGUSDEBUG
         ArgusDebug (2, "sending response length %d...\n", len);
#endif 

         RaSendSaslString(out, data, len);
         free(data);
      } else {

#ifdef ARGUSDEBUG
         ArgusDebug (2, "sending null response...\n");
#endif 

         RaSendSaslString(out, "", 0);
      }
   }

 done_ok:
#ifdef ARGUSDEBUG
   ArgusDebug (1, "successful authentication");
#endif 
   return SASL_OK;

 done_no:
#ifdef ARGUSDEBUG
   ArgusDebug (1, "authentication failed");
#endif 
   return -1;
}


/* send/recv library for IMAP4 style literals. */

int
RaSendSaslString (FILE *f, const char *s, int l)
{
   char saslbuf[MAXSTRLEN];
   int len, al = 0;

   bzero (saslbuf, MAXSTRLEN);
   
   snprintf(saslbuf, MAXSTRLEN, "{%d}\r\n", l);
   len = strlen(saslbuf);

   bcopy (s, &saslbuf[len], l);
   len += l;

   al = fwrite(saslbuf, 1, len, f);
   fflush(f);

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusSendSaslString(0x%x, 0x%x, %d)\n", f, s, l);
   s = saslbuf;
   if (3 <= Argusdflag) {
      while (len--) {
         if (isprint((int)((unsigned char) *s))) {
            printf("%c ", *s);
         } else {
            printf("%x ", (unsigned char) *s);
         }
         s++;
      }
      printf("\n");
   }
#endif 

   return al;
}

int
RaGetSaslString (FILE *f, char *buf, int buflen)
{
   int c, len, l;
   char *s;
   
   if ((c = fgetc(f)) != '{')
      return -1;

   /* read length */
   len = 0;
   c = fgetc(f);
   while (isdigit(c)) {
      len = len * 10 + (c - '0');
      c = fgetc(f);
   }
   if (c != '}')
      return -1;

   if ((c = fgetc(f)) != '\r')
      return -1;

   if ((c = fgetc(f)) != '\n')
      return -1;

   /* read string */
   if (buflen <= len) {
      fread(buf, buflen - 1, 1, f);
      buf[buflen - 1] = '\0';
      /* discard oversized string */
      len -= buflen - 1;
      while (len--)
         (void)fgetc(f);
      len = buflen - 1;
   } else {
      fread(buf, len, 1, f);
      buf[len] = '\0';
   }

   l = len;
   s = buf;

#ifdef ARGUSDEBUG
   ArgusDebug (3, "ArgusGetSaslString(0x%x, 0x%x, %d)\n", f, s, l);
   if (3 <= Argusdflag) {
      while (l--) {
         if (isprint((int)((unsigned char) *s))) {
            printf("%c ", *s);
         } else {
            printf("%X ", (unsigned char) *s);
         }
         s++;
      }
      printf("\n");
   }
#endif 

   return len;
}

#endif 
