/*
 * Argus Software.  Argus files - Layer 2 processing
 * Copyright (c) 2000-2020 QoSient, LLC
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
 * Written by Carter Bullard
 * QoSient, LLC
 *
 */


#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#if !defined(ArgusMac)
#define ArgusMac
#endif

#include <argus_compat.h>
#include <ArgusModeler.h>
#include <ArgusOutput.h>
#include <ArgusSource.h>
#include <ArgusUtil.h>

#include <argus_out.h>

void
ArgusMacFlowRecord (struct ArgusFlowStruct *flowstr, struct ArgusRecord *argus, unsigned char state)
{
   int length = 0;
   struct ArgusMacStruct *mac = (struct ArgusMacStruct *) flowstr->MacDSRBuffer;
      
   if (mac && ((length = argus->ahdr.length) > 0)) {
      bcopy ((char *)mac, &((char *)argus)[argus->ahdr.length], sizeof(*mac));
      argus->ahdr.length += sizeof(*mac);
   }
}
