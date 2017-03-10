/* Derived from Flexera sample code.  Original Copyright notice: */

/**************************************************************************************************
* NOTICE OF COPYRIGHT AND OWNERSHIP OF SOFTWARE:
*
* Copyright (c) 1997-2016 Flexera Software LLC. All Rights Reserved.
*
**************************************************************************************************/
/*
 *
 *	Description:	This is a sample application program, to illustrate
 *			the use of the Flexible License Manager.
 *
 */

/*
 * Gargoyle Software.  Argus files - Main argus processing
 * Copyright (c) 2017 QoSient, LLC
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
 * Written by Eric Kinzie
 * QoSient, LLC
 *
 */

#ifdef HAVE_CONFIG_H
# include "argus_config.h"
#endif

#include "lmclient.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include "lm_attr.h"
#include "lm_redir_std.h"

#ifdef PC
#define LICPATH "@localhost"
#else
#define LICPATH "@localhost:license.dat:."
#endif /* PC */

#define ARGUS_LICENSE_FEATURE "arguspro_sensor"
#define ARGUS_LICENSE_VERSION ARGUSPRO_VERSION_STRING
static void init(struct flexinit_property_handle **);
static void cleanup(struct flexinit_property_handle *);

struct argus_license {
   LM_HANDLE *lm_job;
   struct flexinit_property_handle *handle;
   VENDORCODE code;
   struct timeval borrow_expire;
};

static LM_HANDLE *
ArgusFlexLMInit(VENDORCODE *code, struct flexinit_property_handle **handle,
                struct timeval *borrow_expire)
{
   LM_HANDLE *tmp;

   init(handle);

   if (lc_new_job(0, lc_new_job_arg2, code, &tmp)) {
      lc_perror(tmp, "ArgusPro license initialization failed");
      cleanup(*handle);
      exit(lc_get_errno(tmp));
   }

   (void)lc_set_attr(tmp, LM_A_LICENSE_DEFAULT, (LM_A_VAL_TYPE)LICPATH);

   if (borrow_expire && borrow_expire->tv_sec > 0) {
      char datestr[18];
      struct tm when;

      localtime_r(&borrow_expire->tv_sec, &when);
      if (strftime(&datestr[0], sizeof(datestr), "%d-%b-%Y:%H:%M", &when))
         (void)lc_set_attr(tmp, LM_A_BORROW_EXPIRE, (LM_A_VAL_TYPE)datestr);
   }

   return tmp;
}

static void
ArgusFlexLMCheckout(LM_HANDLE *lm_job, VENDORCODE *code,
                    struct flexinit_property_handle *handle)
{
   if(lc_checkout(lm_job, ARGUS_LICENSE_FEATURE, ARGUS_LICENSE_VERSION,
                  1, LM_CO_NOWAIT, code, LM_DUP_NONE)) {
      lc_perror(lm_job, "ArgusPro license checkout failed");
      cleanup(handle);
      exit (lc_get_errno(lm_job));
   }
}

static void
ArgusFlexLMCheckin(LM_HANDLE *lm_job)
{
   lc_checkin(lm_job, ARGUS_LICENSE_FEATURE, 0);
}

static void
ArgusFlexLMCleanup(LM_HANDLE *lm_job, VENDORCODE *code,
                   struct flexinit_property_handle *handle)
{
   lc_free_job(lm_job);
   cleanup(handle);
}

static void init(struct flexinit_property_handle **handle)
{
#ifndef NO_ACTIVATION_SUPPORT
	struct flexinit_property_handle *ourHandle;
	int stat;

	if ((stat = lc_flexinit_property_handle_create(&ourHandle)))
	{
		fprintf(lm_flex_stderr(), "lc_flexinit_property_handle_create() failed: %d\n", stat);
		exit(1);
	}
	if ((stat = lc_flexinit_property_handle_set(ourHandle,
			(FLEXINIT_PROPERTY_TYPE)FLEXINIT_PROPERTY_USE_TRUSTED_STORAGE,
			(FLEXINIT_VALUE_TYPE)1)))
	{
		fprintf(lm_flex_stderr(), "lc_flexinit_property_handle_set failed: %d\n", stat);
	    exit(1);
	}
	if ((stat = lc_flexinit(ourHandle)))
	{
		fprintf(lm_flex_stderr(), "lc_flexinit failed: %d\n", stat);
	    exit(1);
	}
	*handle = ourHandle;
#endif /* NO_ACTIVATION_SUPPORT */
}

static void cleanup(struct flexinit_property_handle *initHandle)
{
#ifndef NO_ACTIVATION_SUPPORT
	int stat;

	if ((stat = lc_flexinit_cleanup(initHandle)))
	{
		fprintf(lm_flex_stderr(), "lc_flexinit_cleanup failed: %d\n", stat);
	}
	if ((stat = lc_flexinit_property_handle_free(initHandle)))
	{
		fprintf(lm_flex_stderr(), "lc_flexinit_property_handle_free failed: %d\n", stat);
	}
#endif /* NO_ACTIVATION_SUPPORT */
}

/* A non-null borrow_expire pointer indicates that we will borrow
 * a license.  The expiration is an absolute time in the local
 * timezone.
 */
void *
ArgusLicenseInit(struct timeval *borrow_expire)
{
   struct argus_license *lic = malloc(sizeof *lic);

   if (lic == NULL) {
      fprintf(lm_flex_stderr(), "Unable to allocate memory for license\n");
      exit(1);
   }

   memset(lic, 0, sizeof(*lic));
   if (borrow_expire)
      lic->borrow_expire = *borrow_expire;
   lic->lm_job = ArgusFlexLMInit(&lic->code, &lic->handle, borrow_expire);
   return (void *)lic;
}

void
ArgusLicenseCheckout(void *vlic)
{
   struct argus_license *lic = vlic;

   ArgusFlexLMCheckout(lic->lm_job, &lic->code, lic->handle);
}

void
ArgusLicenseCheckin(void *vlic)
{
   struct argus_license *lic = vlic;

   ArgusFlexLMCheckin(lic->lm_job);
}

void
ArgusLicenseCleanup(void *vlic)
{
   struct argus_license *lic = vlic;

   ArgusFlexLMCleanup(lic->lm_job, &lic->code, lic->handle);
}
