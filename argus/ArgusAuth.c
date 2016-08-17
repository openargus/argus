/*
 * Argus Software.  Argus files - Authentication
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
 */

/* 
 * $Id: //depot/argus/argus/argus/ArgusAuth.c#18 $
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
 *
 * modified by Carter Bullard
 * QoSient, LLC
 *
 */

#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusSasl)
#define ArgusSasl
#endif
 
#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusOutput.h>
#include <ArgusSource.h>


int ArgusAuthenticateClient (struct ArgusClientData *);
int ArgusGetSaslString(FILE *, char *, int);
int ArgusSendSaslString(FILE *, const char *, int, int);

int
ArgusAuthenticateClient (struct ArgusClientData *client)
{
   int retn = 1;

#ifdef ARGUS_SASL
   unsigned int rlen = 0;
   int len, mechnum = 0;
   char buf[8192], chosenmech[512];
   const char *data;
   sasl_conn_t *conn = NULL;

// int SASLOpts = (SASL_SEC_NOPLAINTEXT | SASL_SEC_NOANONYMOUS);
   FILE *in, *out;

   conn = client->sasl_conn;

   if ((retn = sasl_listmech(conn, NULL, "{", ", ", "}", &data, &rlen, &mechnum)) != SASL_OK)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: Error generating mechanism list");

   if ((in  = fdopen (client->fd, "r")) < 0)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: fdopen() error %s", strerror(errno));

   if ((out = fdopen (client->fd, "w")) < 0)
      ArgusLog (LOG_ERR, "ArgusAuthenticateClient: fdopen() error %s", strerror(errno));

   ArgusSendSaslString (out, data, rlen, SASL_OK);

   if ((len = ArgusGetSaslString (in, chosenmech, sizeof(chosenmech))) <= 0)  {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
      return 0;
   }

   if ((len = ArgusGetSaslString (in, buf, sizeof(buf))) <= 0)  {
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
      return 0;
   }

   if (*buf == 'Y') {
      if ((len = ArgusGetSaslString (in, buf, sizeof(buf))) <= 0)  {
#ifdef ARGUSDEBUG
         ArgusDebug (2, "ArgusAuthenticateClient: Error ArgusGetSaslString returned %d\n", len);
#endif
         return 0;
      }
      retn = sasl_server_start(conn, chosenmech, buf, len, &data, &rlen);

   } else {
      retn = sasl_server_start(conn, chosenmech, NULL, 0, &data, &rlen);
   }

   if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
      sprintf (buf, "%s", sasl_errstring(retn, NULL, NULL));
#ifdef ARGUSDEBUG
      ArgusDebug (2, "ArgusAuthenticateClient: Error starting SASL negotiation");
#endif
      ArgusSendSaslString(out, buf, strlen(buf), retn);
      return 0;
   }

   while (retn == SASL_CONTINUE) {
      if (data) {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "sending response length %d...\n", rlen);
#endif
         ArgusSendSaslString(out, data, rlen, retn);
      } else {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "no data to send? ...\n");
#endif
      }

#ifdef ARGUSDEBUG
      ArgusDebug(2, "waiting for client reply...\n");
#endif
      len = ArgusGetSaslString(in, buf, sizeof(buf));

      if (len < 0) {
#ifdef ARGUSDEBUG
         ArgusDebug(2, "client disconnected ...\n");
#endif
         return 0;
      }

      retn = sasl_server_step(conn, buf, len, &data, &rlen);
      if ((retn != SASL_OK) && (retn != SASL_CONTINUE)) {
         sprintf (buf, "%s", sasl_errstring(retn, NULL, NULL));
#ifdef ARGUSDEBUG
         ArgusDebug(2, "Authentication failed %s\n", sasl_errstring(retn, NULL, NULL));
#endif
         ArgusSendSaslString(out, buf, strlen(buf), retn);
         return 0;
      }
   }

   if (retn == SASL_OK)
      ArgusSendSaslString(out, NULL, 0, SASL_OK);

#endif
#ifdef ARGUSDEBUG
   ArgusDebug (1, "ArgusAuthenticateClient() returning %d\n", retn);
#endif

   return (retn);
}


#ifdef ARGUS_SASL

#include <stdio.h>
#include <ctype.h>
#include <stdarg.h>
#include <sysexits.h>

#include <sasl/sasl.h>
#include <sasl/saslutil.h>

/* send/recv library for IMAP4 style literals. */

int
ArgusSendSaslString(FILE *f, const char *s, int l, int mode)
{
   char *buf = NULL, *ptr = NULL, error[128];
   unsigned int al, len;
   int result, size, tsize;

   switch (mode) {
      case SASL_OK: {
         if ((s == NULL) || (l == 0)) {
            ptr = "D: ";
            tsize = 3;
            break;
         }
      }
      case SASL_CONTINUE: {
         ptr = "S: ";
         tsize = 3;
         break;
      }
      default: {
         sprintf (error, "E: [%d]", mode);
         ptr = error;
         tsize = strlen(error);
         break;
      }
   }

   if (ferror(f))
      clearerr(f);

   while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
      if (size >= 0) {
         tsize -= size;
         ptr += size;
      } else {
         if (ferror(f))
            ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
      }
   }

   if (l > 0) {
      al = (((l / 3) + 1) * 4) + 1;

      if ((buf = malloc(al)) == NULL)
         ArgusLog (LOG_ERR, "malloc: error %s", strerror(errno));

      if ((ptr = buf) != NULL) {
         result = sasl_encode64(s, l, buf, al, &len);

         if (result == SASL_OK) {
            tsize = len;
            while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
               if (size >= 0) {
                  tsize -= size;
                  ptr += size;
               } else {
                  if (ferror(f))
                     ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
               }
            }
         }
      }

      free(buf);
   }

   ptr = "\n";
   tsize = 1;
   while ((size = fwrite(ptr, 1, tsize, f)) != tsize) {
      if (size >= 0) {
         tsize -= size;
         ptr += size;
      } else {
         if (ferror(f))
            ArgusLog (LOG_ERR, "ArgusSendSaslString: error %d", ferror(f));
      }
   }

   fflush(f);

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusSendSaslString(0x%x, 0x%x, %d) %s", f, s, l, s);
#endif
   return len;
}

int
ArgusGetSaslString(FILE *f, char *buf, int buflen)
{
   unsigned int len = -1;
   char *s = NULL;
   int result;

   if (ferror(f))
      clearerr(f);

   if ((s = fgets(buf, buflen, f)) != NULL) {
      switch (*buf) {
         case 'C': {
            if (!(strncmp(buf, "C: ", 3))) {
               buf[strlen(buf) - 1] = '\0';

               result = sasl_decode64(buf + 3, (unsigned) strlen(buf + 3), buf, buflen, &len);

               if (result != SASL_OK)
                  ArgusLog (LOG_ERR, "ArgusGetSaslString: sasl_decode64 error");

               buf[len] = '\0';
            } else
               ArgusLog (LOG_ERR, "ArgusGetSaslString: error %s", strerror(errno));

            break;
         }

         default:
         case 'N': 
            len = -1;
            break;
      }
   }

#ifdef ARGUSDEBUG
   ArgusDebug (2, "ArgusGetSaslString(0x%x, 0x%x, %d) %s", f, buf, buflen, buf);
#endif 
   return len;
}

#endif 
