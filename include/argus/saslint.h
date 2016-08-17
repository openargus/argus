/* saslint.h - internal SASL library definitions
 * Tim Martin
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
 * $Id: //depot/argus/argus/include/argus/saslint.h#2 $
 * $DateTime: 2011/01/26 17:16:43 $
 * $Change: 2088 $
 */

#if !defined(Saslint_h)
#define Saslint_h


#include <sasl.h>

typedef struct {
  const sasl_callback_t *callbacks;
  const char *appname;
} sasl_global_callbacks_t;

typedef struct sasl_mech_secret {
    unsigned long len;
    unsigned long mechoffset;   /* 0 if plain mechanism */
    unsigned long useroffset;
    char buf[1];
} sasl_mech_secret_t;

typedef struct sasl_credentials sasl_credentials_t;

typedef struct sasl_out_params {
    int doneflag;               /* exchange complete */
    sasl_ssf_t mech_ssf;        /* security layer strength factor of mech */
    unsigned maxoutbuf;         /* max plain output to security layer */

    /* mic functions differs from encode in that the output is intended to be
     * appended to the input rather than an encapsulated variant of it.
     * a plugin which supports getmic()/verifymic() but not
     * encode()/decode() should be exportable.  Ditto for framework.
     * datalen param of verifymic returns length of data in buffer
     */
    void *encode_context;
    int (*encode)(void *context, const char *input, unsigned inputlen,
                  char **output, unsigned *outputlen);
    int (*getmic)(void *context, const char *input, unsigned inputlen,
                  char **output, unsigned *outputlen);
    void *decode_context;
    int (*decode)(void *context, const char *input, unsigned inputlen,
                  char **output, unsigned *outputlen);
    int (*verifymic)(void *context, const char *input, unsigned inputlen,
                     unsigned *datalen);

    char *user;                 /* canonicalized user name */
    char *authid;               /* canonicalized authentication id */
    char *realm;                /* security realm */

    /* set to 0 initially, this allows a plugin with extended parameters
     * to work with an older framework by updating version as parameters
     * are added.
     */
    int param_version;

    /* Credentials passed by clients.  NOTE: this should ONLY
     * be set by server plugins. */
    sasl_credentials_t *credentials;
} sasl_out_params_t;

struct sasl_conn {
  void (*destroy_conn)(sasl_conn_t *); /* destroy function */

  int open; /* connection open or not */
  char *service;

  int secflags;  /* security layer flags passed to sasl_*_new */
  int got_ip_local, got_ip_remote;
  struct sockaddr_in ip_local, ip_remote;
  sasl_external_properties_t external;

  void *context;
  sasl_out_params_t oparams;

  sasl_security_properties_t props;

  sasl_secret_t *secret;

  int uses_sec_layer;   /* if need to encrypt/decrpt all transmissions */

  void *mutex;

  int (*idle_hook)(sasl_conn_t *conn);
  const sasl_callback_t *callbacks;
  const sasl_global_callbacks_t *global_callbacks; /* global callbacks
						    * for this
						    * connection */
  char *serverFQDN;
};

#endif /* SASLINT_H */
