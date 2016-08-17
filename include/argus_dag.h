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
 * Data structures required to define struct Dag Record.
 * Derived from Dag source code tree ./include/dagapi.h
 *
 * $Id: //depot/argus/argus/include/argus_dag.h#7 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */

#define TYPE_LEGACY             0
#define TYPE_HDLC_POS           1
#define TYPE_ETH                2
#define TYPE_ATM                3
#define TYPE_AAL5               4
#define TYPE_MC_HDLC            5
#define TYPE_MC_RAW             6
#define TYPE_MC_ATM             7
#define TYPE_MC_RAW_CHANNEL     8
#define TYPE_MC_AAL5            9
#define TYPE_COLOR_HDLC_POS     10
#define TYPE_COLOR_ETH          11
#define TYPE_MC_AAL2            12
#define TYPE_IP_COUNTER         13
#define TYPE_TCP_FLOW_COUNTER   14
#define TYPE_DSM_COLOR_HDLC_POS 15
#define TYPE_DSM_COLOR_ETH      16
#define TYPE_COLOR_MC_HDLC_POS  17
#define TYPE_AAL2               18
#define TYPE_COLOR_HASH_POS     19
#define TYPE_COLOR_HASH_ETH     20
#define TYPE_INFINIBAND         21
#define TYPE_RAW_LINK           24
#define TYPE_PAD                48
#define TYPE_MIN  1   /* sanity checking */
#define TYPE_MAX  48  /* sanity checking */


#define dag_record_size   16

typedef struct flags {
   uint8_t iface:2;
   uint8_t vlen:1;
   uint8_t trunc:1;
   uint8_t rxerror:1;
   uint8_t dserror:1;
   uint8_t reserved:1;
   uint8_t direction:1;
} flags_t;

typedef struct dag_record {
   uint64_t      ts;
   uint8_t       type;
   flags_t       flags;
   uint16_t      rlen;
   uint16_t      lctr;
   uint16_t      wlen;
} dag_record_t;

