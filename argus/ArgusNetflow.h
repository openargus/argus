/*
 * Gargoyle Software.  Argus files - Netflow processing includes
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
 * $Id: //depot/argus/argus/argus/ArgusNetflow.h#1 $
 * $DateTime: 2011/01/26 17:21:20 $
 * $Change: 2089 $
 */


#define CISCO_VERSION_1         1
#define CISCO_VERSION_5         5
#define CISCO_VERSION_6         6
#define CISCO_VERSION_7         7
#define CISCO_VERSION_8         8
#define CISCO_VERSION_9         9


#ifndef ArgusNetflow_h
#define ArgusNetflow_h

#include <ArgusModeler.h>

void ArgusParseCiscoRecord (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV1 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV7 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV8 (struct ArgusModelerStruct *, void *);
void ArgusParseCiscoRecordV9 (struct ArgusModelerStruct *, void *);

#else
extern void ArgusParseCiscoRecord (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV1 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV5 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV6 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV7 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV8 (struct ArgusModelerStruct *, void *);
extern void ArgusParseCiscoRecordV9 (struct ArgusModelerStruct *, void *);
#endif
