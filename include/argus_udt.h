/*
 * Argus Software.  Common include files - UDT processing
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
 * $Id: //depot/gargoyle/argus/include/argus_udt.h#5 $
 * $DateTime: 2015/04/13 00:39:28 $
 * $Change: 2980 $
 */

#ifndef ArgusUdt_h
#define ArgusUdt_h

#define UDT_SEQNUMBER_MASK	0xEFFFFFFF
#define UDT_MSGNUMBER_MASK	0x1FFFFFFF

#define UDT_PACKET_MASK		0x8000
#define UDT_CONTROL_PACKET      0x8000
#define UDT_DATA_PACKET         0x0000

#define UDTOECONTROLPAD		48


#define UDT_CONTROL_TYPE_MASK	0x7FFF

#define UDT_CONTROL_HANDSHAKE	0x0000
#define UDT_CONTROL_KEEPALIVE	0x0001
#define UDT_CONTROL_ACK		0x0002
#define UDT_CONTROL_NAK		0x0003
#define UDT_CONTROL_CONGEST	0x0004
#define UDT_CONTROL_SHUTDOWN	0x0005
#define UDT_CONTROL_ACKACK	0x0006
#define UDT_CONTROL_DROPREQ	0x0007

#define UDTOE_PACKET_MASK         0x80
#define UDTOE_CONTROL_PACKET      0x80
#define UDTOE_DATA_PACKET         0x00

#define UDTOE_CONTROL_TYPE_MASK   0x7F

#define UDTOE_CONTROL_HANDSHAKE   0x00
#define UDTOE_CONTROL_KEEPALIVE   0x01
#define UDTOE_CONTROL_ACK         0x02
#define UDTOE_CONTROL_NAK         0x03
#define UDTOE_CONTROL_CONGEST     0x04
#define UDTOE_CONTROL_SHUTDOWN    0x05
#define UDTOE_CONTROL_ACKACK      0x06
#define UDTOE_CONTROL_DROPREQ     0x07

struct udtoe_control_hdr {
   unsigned char type, resv;
   unsigned short ackseq;
   unsigned int info;
   unsigned int tstamp;
   unsigned int sockid;
};

struct udt_control_hdr {
   unsigned short type, resv;
   unsigned int info;
   unsigned int tstamp;
   unsigned int sockid;
};

struct udt_control_handshake {
   unsigned int version;
   unsigned int socktype;
   unsigned int initseq;
   unsigned int psize;
   unsigned int wsize;
   unsigned int conntype;
   unsigned int sockid;
};

struct udt_control_ack {
   unsigned int ackseqnum;
   unsigned int rtt;
   unsigned int var;
   unsigned int bsize;
   unsigned int rate;
   unsigned int lcap;
};

struct udt_control_nak {
   unsigned int seqnum;
};

struct udt_control_dropreq {
   unsigned int firstseqnum;
   unsigned int lastseqnum;
};

struct udt_data_hdr {
   unsigned int seqnum;
   unsigned int msgnum;
   unsigned int tstamp;
   unsigned int sockid;
};


struct udtoe_header {
   union {
      struct udtoe_control_hdr cntl;
      struct udt_data_hdr      data;
   } un_udt;
};

struct udt_header {
   union {
      struct udt_control_hdr cntl;
      struct udt_data_hdr    data;
   } un_udt;
};
 
#define udt_control    un_udt.cntl
#define udt_data       un_udt.data

#endif /* ArgusUdt_h */

