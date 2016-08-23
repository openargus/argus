/*
 * Argus Software
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

 /*
 * Data structures required to define struct Dag Record.
 * Derived from Dag source code tree ./include/dagapi.h
 *
 * $Id: //depot/gargoyle/argus/include/argus_dag.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
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

