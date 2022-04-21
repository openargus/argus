/*
 * --------------------------------------------------------------------------------
 * 
 * 2019-2021 CounterFlow AI, Inc.
 * Proprietary & Confidential. All Rights Reserved.
 * 
 * This software is a proprietary fork of Argus, commercially licensed from
 * QoSient, LLC by CounterFlow AI in 2019.
 * 
 * Refactored and enhanced with numerous features and functions.
 *
 * ArgusVxLan support written by 
 * Carter Bullard
 *
 * 
 */
#ifdef HAVE_CONFIG_H
#include "argus_config.h"
#endif

#ifndef ArgusVxLan_h
#define ArgusVxLan_h

#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <argus_compat.h>
#include <ArgusModeler.h>

#include <argus/bootp.h>

unsigned short ArgusParseVxLan (struct ArgusModelerStruct *, void *);
#endif
