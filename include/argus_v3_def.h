/*
 * Argus Software.  Common include files - Version 3 definitions
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
 * $Id: //depot/argus/argus/include/argus_v3_def.h#12 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


/* Argus_def.h */
 */


#if !defined(Argus_def_h)
#define Argus_def_h

/*
   Argus Record Format
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                                                               |
   |                     Argus Record Header                       |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                          Argus Data                           |
   |                               .                               |
   |                               .                               |
   |                               .                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



/*
   Argus Record Header Format
                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Cause     |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |     Option    |           Qualifier           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Record Start Time                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Record Last Time                     |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
   Argus Record Header Type Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Version Record Field
          Note that one tick mark represents one bit position.
*/

/* Argus Record Type */
 
#define ARGUS_V3_FAR 		0x01    /* Normal Argus Data Record */
#define ARGUS_V3_MAR		0x80    /* Normal Argus Management Record */
 
 
/* Argus Derivative Types */
 
#define ARGUS_V1_WRITESTRUCT  	0x10    /* Argus 1.x Write Struct Conversion */
#define ARGUS_V2_RECORD  	0x20    /* Argus 2.x Argus Record Conversion */
#define ARGUS_V3_CISCO_NETFLOW	0x30    /* Argus CISCO Netflow Support */


/*
   Argus Record Header Type Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |     Cause     |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Cause Record Field
          Note that one tick mark represents one bit position.
*/


/* Argus Record Cause */
 
#define ARGUS_V3_START		0x01   /* Initial Record */
#define ARGUS_V3_STATUS		0x02   /* Qualifier Record*/
#define ARGUS_V3_STOP		0x11   /* Closed/Terminating Record */
#define ARGUS_V3_TIMEOUT	0x12   /* Record Timed Out */
#define ARGUS_V3_SHUTDOWN	0x13   /* Administrative Shutdown */
#define ARGUS_V3_ERROR		0x14   /* Error - Major Problem */

/*
   Argus Record Header Length Field
      Number of 32-bit longwords, including the header.
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |               |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Length Record Field
          Note that one tick mark represents one bit position.
*/


/*
   Argus Record Header Version Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Version Record Field
          Note that one tick mark represents one bit position.
*/

/* Record Version (Ver) */

#define ARGUS_VERSION_1		0x01		/* Version 1 */
#define ARGUS_VERSION_2		0x02		/* Version 2 */
#define ARGUS_VERSION_3		0x03		/* Version 3 */

#define ARGUS_VERSION		ARGUS_VERSION_3	/* Version 3 */


/*
   Argus Record Header Option Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |    Option     |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Option Record Field
          Note that one tick mark represents one bit position.
*/


/* Record Options (Opt)*/
 
#define ARGUS_V3_SASL_NEGOTIATION	0x80

/*
   Argus Record Header Qualifier Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |           Qualifier           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Qualifier Record
          Note that one tick mark represents one bit position.
*/


/* Argus Record Qualifier */

#define ARGUSV3__CONNECTED	0x0001
#define ARGUS_V3_COROLATED	0x0002

#define ARGUS_V3_ANON		0x0010
#define ARGUS_V3_MERGED		0x0020
#define ARGUS_V3_RMON  		0x0040


/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Seconds                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Fractional Seconds (usec)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                   Argus Start/Last Time Record Field
          Note that one tick mark represents one bit position.
*/




/* Argus Data 
      Argus Data is a collection of Argus Data Specific Records (DSRs)

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                  Argus Data Specific Records                  |
   |                               .                               |
   |                               .                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/* Argus Data Specific Record (DSR) Formats
      All Argus DSRs are 32-bit aligned.  In order to be size
      conservative, there are two DSR types, one being a Type Value
      (TV) record with an explicit length of 4 bytes, and a Type
      Length Value (TLV) record, that provides support for variable
      length records.  The fixed length record does not support a
      length field.  These DSR types are distinquished from the
      most significant bit in the DSR.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|    Type     |    SubType    |         Argus DSR Data        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|    Type     |     Length    |     SubType   |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                        Argus DSR Data                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Argus Data Specific Record (DSR) Field
          Note that one tick mark represents one bit position.
*/


/*
   Argus Record Data Type Field
      The DSR Type Field specifies the format of the DSR.  The
      most significant bit indicates if the DSR is a TV or TLV
      type.  The other bits specify highest level semantics for
      the DSR. 

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/* Argus Record Data Specific Record (DSR) Types */

#define ARGUS_SOURCE_DSR		0x01
#define ARGUS_FLOW_DSR			0x02
#define ARGUS_PROTO_DSR			0x03
#define ARGUS_PROTO_IP_DSR		0x04

#define ARGUS_METER_DSR			0x10

#define ARGUS_DSR_AGR			0x22
#define ARGUS_DSR_TIME			0x23
#define ARGUS_DSR_SRCUSERDATA		0x24
#define ARGUS_DSR_DSTUSERDATA		0x25
#define ARGUS_DSR_SRCTIME		0x26
#define ARGUS_DSR_DSTTIME		0x27
#define ARGUS_DSR_COROLATE		0x28


/*
   Argus Record Data Length Field
      Number of 32-bit longwords, including the header.
      Data records that have a 0 as the most significant
      bit support variable length records, and as a result
      have a length field.  Records with a 1 as the most
      significant bit are fixed length 4 byte records,
      and thus do not require a length field.
     
    0                   1                   2                   3  
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|             |    Length   |                                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

      The Length field can equal 1.
*/


/*
   Argus Record Data SubType Field
      Data Records that have a 0 as the most significant bit
      support variable length records. The Length field displaces
      the SubType field in these headers by 8 bits.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|                             |    SubType    |               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|             |    SubType    |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/*
   Argus Record Data Qualifier Field
      TLV Data Records support an 8-bit  Qualifier field, which is
      used to convey additional semantics for the DSR format and
      contents.  In some situations, the qualifier may be used to
      further specify the actual DSR data format, in others it may
      provide addition semantics, or it can be used to provide the
      actual 8-bit data.

      How the Qualifier is parsed and used is specific to the
      DSR Type and SubType.
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|                                             |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
*/



/* Argus Source DSR

      The 

#define ARGUS_SOURCE_ID_DSR		0x01
#define ARGUS_SOURCE_TRANS_DSR		0x02

#define ARGUS_ID_IS_IPV4ADDR		0x01
#define ARGUS_ID_IS_IPV6ADDR		0x02

#define ARGUS_COOKIE			0xE5617ACB

/*
       The Argus Source Record Identifier is an optional DSR that
       helps to identify a specific record.  Many applications
       require the ability to discriminate the source of a specific
       record, and some have further requirements for the source
       to provide a unique sequence number for transactional
       processing and to assist in reliable transport.

    ARGUS_SOURCE_ID_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x10      |      0x02     |      0x01     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Source Identifier                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_SOURCE_TRANS_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x10      |      0x04     |      0x02     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Source Identifier                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Transaction Identifier                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                   Argus Source Identifier Record Field
          Note that one tick mark represents one bit position.
*/
 


#define ARGUS_FLOW_DSR			0x01
#define ARGUS_FLOW_IPV4_DSR		0x01
#define ARGUS_FLOW_IPV6_DSR		0x02
#define ARGUS_FLOW_ARP_DSR		0x03
#define ARGUS_FLOW_RARP_DSR		0x04
#define ARGUS_FLOW_IP_FRG_DSR		0x05

/*
       The Argus Source Record Identifier is an optional DSR that
       helps to identify a specific record.  Many applications
       require the ability to discriminate the source of a specific
       record, and some have further requirements for the source
       to provide a unique sequence number for transactional
       processing and to assist in reliable transport.

    ARGUS_FLOW_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |    Length     |     SubType   |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Argus Flow Specific Data                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_FLOW_IPV4_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x03     |      0x01     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_FLOW_IPV6_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x0B     |      0x02     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Priority   |                 Flow  Label                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                       Source IPv6 Address                     |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                    Destination IPv6 Address                   |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_FLOW_ARP_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x05     |      0x03     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP SPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP TPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +        Ethernet Address       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_FLOW_RARP_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x05     |      0x04     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP TPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +   Source  Ethernet Address    +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Target Ethernet Address     +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+



    ARGUS_FLOW_IP_FRG_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x05     |      0x05     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Fragment Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Fragment Identifier                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             IpId              |          Total Length         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-|-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |         Current Length        |      Maximum Frag Length      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/



#define ARGUS_PROTO_DSR				0x04

/*
    ARGUS_PROTO_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x84      |   ProtoType   |         Protocol Data         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |    Length     |   Proto Type  |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                 Argus Protocol Specific Data                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


#define ARGUS_PROTO_DLT_DSR		0x01

#define ARGUS_PROTO_SNAP_DSR            0x02 
#define ARGUS_PROTO_MPLS_DSR		0x04
#define ARGUS_PROTO_802_1Q_DSR		0x03
#define ARGUS_PROTO_ISL_DSR		0x06 
#define ARGUS_PROTO_PPPOE		0x07


#define ARGUS_PROTO_IP_DSR		0x10
#define ARGUS_PROTO_IP_EXT_ATTR_DSR	0x11
#define ARGUS_PROTO_IP_EXT_OPTIONS_DSR	0x12


/*
    ARGUS_PROTO_IP_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x84      |      0x10     |   Proto Num   |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |     Length    |      0x10     |   Proto Num   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


/*
    ARGUS_PROTO_IP_DSR	TCP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |      0x03     |      0x10     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           TCP State           |           TCP Options         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	UDP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x02      |      0x02     |      0x10     |      0x11     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_PROTO_IP_DSR	ICMP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x02      |      0x02     |      0x10     |      0x01     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ICMP Type   |   ICMP Code   |            ICMP ID            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_PROTO_IP_DSR	ESP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x02      |      0x02     |      0x10     |      0x32     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               ESP Security Payload Identifiier                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_PROTO_IP_DSR	IGMP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x02      |      0x02     |      0x10     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   IGMP Type   |   IGMP Code   |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*
   ARGUS_PROTO_IP_EXT_ATTR_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |      0x02     |      0x11     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             IP ID             |      TTL      |      TOS      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
 
   ARGUS_PROTO_IP_EXT_OPTIONS_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |      0x02     |      0x12     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IP Options Indicator                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


#define ARGUS_PROTO_MPLS_DSR		0x01
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |    Length     |      0x01     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Argus MPLS Label Data                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Argus MPLS Label Data                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define ARGUS_PROTO_802_1Q_DSR		0x02
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x04      |      0x08     |      0x02     |1 1|           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Src 802.1Q Tag         |        Dst 802.1Q Tag         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x84      |     0x04      |          802.1Q Tag           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define ARGUS_PROTO_SNAP_DSR		0x01
#define ARGUS_PROTO_VLAN_802_1Q_DSR	0x02
#define ARGUS_PROTO_VLAN_ISL_DSR	0x03
#define ARGUS_PROTO_PPPOE			11

#define ARGUS_DSR_AGR			12
#define ARGUS_DSR_TIME			13
#define ARGUS_DSR_SRCUSERDATA		14
#define ARGUS_DSR_DSTUSERDATA		15
#define ARGUS_DSR_SRCTIME		16
#define ARGUS_DSR_DSTTIME		17
#define ARGUS_DSR_COROLATE		18


#define ARGUS_METER_DSR			0x20
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    Length     |    SubType    |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Argus Meter Specific Data                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


#define ARGUS_METER_LOAD_DSR		0x01
#define ARGUS_METER_LOAD_BYTE_DSR	0x1
#define ARGUS_METER_LOAD_SHORT_DSR	0x2
#define ARGUS_METER_LOAD_LONG_DSR	0x3
#define ARGUS_METER_LOAD_LONGLONG_DSR	0x4
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |      0x08     |      0x01     | D |   |  0x1  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    packets    |     bytes     |     packets   |     bytes     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    Length     |      0x01     | D |   |  0x2  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           packets             |             bytes             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    Length     |      0x01     | D |   |  0x3  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            packets                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             bytes                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    Length     |      0x01     | D |   |  0x4  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                            packets                            +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   +                             bytes                             +
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define ARGUS_METER_TCP_STATUS_DSR	0x02
#define ARGUS_METER_TCP_PERF_DSR	0x03
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |      0x10     |      0x02     |   Qualifier   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          TCPQualifier                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              TCP Syn ACK uSec Response Timer                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              TCP ACK DATA uSec Response Timer                 |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    Length     |      0x03     | D | Qualifier |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      TCP Sequence Base                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     TCP Acknowledged Bytes                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          TCP Total Bytes                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   TCP Retransmitted Packets                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    TCP Last Reported Window   |   TCP Flags   |     Pad       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define ARGUS_METER_IGMP_PERF_DSR	0x04
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |      0x18     |      0x04     | D | Qualifier |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                          IGMP Group                           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   IGMP Join Delay (Timeval)                   |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  IGMP Leave Delay (Timeval)                   |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

#define ARGUS_METER_ESP_PERF_DSR	0x05
/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |      0x0C     |      0x05     | D | Qualifier |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       ESP Last Sequence                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    ESP Lost Sequence Number                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/



#define ARGUS_SRC_VLAN		0x0001
#define ARGUS_DST_VLAN		0x0002

#define ARGUS_SRC_MPLS		0x0001
#define ARGUS_DST_MPLS		0x0002

#define ARGUS_SRC_CHANGED	0x0010
#define ARGUS_DST_CHANGED	0x0020


/* Argus Error Messages go into the status field when
   the Record Cause is ARGUS_ERROR.
*/

#define ARGUS_ACCESSDENIED	0x000010
#define ARGUS_MAXLISTENEXCD	0x000020


/*  Link Types  */

#define ARGUS_ETHERNET		0x01000000
#define ARGUS_ATM		0x02000000
#define ARGUS_FDDI		0x03000000
#define ARGUS_TOKENRING		0x04000000
#define ARGUS_SLIP		0x05000000
#define ARGUS_PPP		0x06000000
#define ARGUS_ESP		0x07000000
#define ARGUS_RAW		0x08000000
#define ARGUS_NULL		0x09000000


#define ARGUS_SEND_FRAG_COMPLETE	0x10000000

/*
                  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 |                               |
                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                       Argus FAR Qualifier Field
        Note that one tick mark represents one bit position.
*/


/* ICMP Mapped Indicator */
/*  argus_far.status indicator */

#define ARGUS_ICMP_MAPPED		0x0007
#define ARGUS_ICMPUNREACH_MAPPED	0x0001
#define ARGUS_ICMPREDIREC_MAPPED	0x0002
#define ARGUS_ICMPTIMXCED_MAPPED	0x0004

#define ARGUS_FRAGMENTS			0x0008
#define ARGUS_FRAGOVERLAP		0x0010

#define ARGUS_TOS_MODIFIED		0x0020
#define ARGUS_TTL_MODIFIED		0x0040
#define ARGUS_OPTION_MODIFIED		0x0080

/* IP Option Indicators */

#define ARGUS_IPOPTIONS			0x3F00
#define ARGUS_TIMESTAMP			0x0100
#define ARGUS_SECURITY			0x0200
#define ARGUS_LSRCROUTE			0x0400
#define ARGUS_RECORDROUTE		0x0800
#define ARGUS_SSRCROUTE			0x1000
#define ARGUS_RTRALERT			0x2000
 
#define ARGUS_MULTIADDR			0x4000


/* Type:  DSR    Cause:  ANY  */

#define ARGUS_DSR_TYPES			19
#define ARGUS_DSR_MAC			0
#define ARGUS_DSR_TCP			1
#define ARGUS_DSR_ICMP			2
#define ARGUS_DSR_RTP			3
#define ARGUS_DSR_RTCP			4
#define ARGUS_DSR_IGMP			5
#define ARGUS_DSR_ARP			6
#define ARGUS_DSR_FRG			7
#define ARGUS_DSR_ESP			8
#define ARGUS_DSR_MPLS			9
#define ARGUS_DSR_VLAN			10
#define ARGUS_DSR_PPPOE			11
#define ARGUS_DSR_AGR			12
#define ARGUS_DSR_TIME			13
#define ARGUS_DSR_SRCUSERDATA		14
#define ARGUS_DSR_DSTUSERDATA		15
#define ARGUS_DSR_SRCTIME		16
#define ARGUS_DSR_DSTTIME		17
#define ARGUS_DSR_COROLATE		18
 
#define ARGUS_MAC_DSR			0x08
 
#define ARGUS_TCP_DSR			0x11
#define ARGUS_ICMP_DSR			0x12
#define ARGUS_RTP_DSR			0x14
#define ARGUS_RTCP_DSR			0x15
#define ARGUS_IGMP_DSR			0x18

#define ARGUS_ARP_DSR			0x20
#define ARGUS_FRG_DSR			0x21
#define ARGUS_ESP_DSR			0x22

#define ARGUS_MPLS_DSR			0x28
#define ARGUS_VLAN_DSR			0x2a
#define ARGUS_PPPOE_DSR			0x2b
 
#define ARGUS_AGR_DSR			0x30
 
#define ARGUS_TIME_DSR			0x40
#define ARGUS_SRCUSRDATA_DSR		0x42
#define ARGUS_DSTUSRDATA_DSR		0x43

#define ARGUS_COROLATE_DSR		0x50

#define ARGUS_SRC_TIME_DSR		0x01
#define ARGUS_DST_TIME_DSR		0x02


/* IP Sec AH Header Qualifier Bits */

#define ARGUS_AH_HDR                  0x00000010
#define ARGUS_AH_REPLAY               0x00000008


/* RTP State Constants and Reporting Values */

#define ARGUS_RTP_SRCSILENCE		0x01
#define ARGUS_RTP_DSTSILENCE		0x02

#define ARGUS_RTCP_TAG			0x2000
#define ARGUS_RTP_TAG			0x4000

#define ARGUS_HTTP_FLOWTAG		0x01
#define ARGUS_RTCP_FLOWTAG		0x10
#define ARGUS_RTP_FLOWTAG		0x20
#define ARGUS_FRAG_FLOWTAG		0xCB


/* TCP State Constants and Reporting Values */

#define ARGUS_SAW_SYN			0x00000001
#define ARGUS_SAW_SYN_SENT		0x00000002
#define ARGUS_CON_ESTABLISHED		0x00000004
#define ARGUS_FIN			0x00000008
#define ARGUS_FIN_ACK			0x00000010

#define ARGUS_NORMAL_CLOSE		0x00000020
#define ARGUS_CLOSE_WAITING		0x00000040

#define ARGUS_PKTS_RETRANS		0x00000300  /* SRC_PKTS_RETRANS | DST_PK*/
#define ARGUS_SRC_PKTS_RETRANS		0x00000100
#define ARGUS_DST_PKTS_RETRANS		0x00000200

#define ARGUS_WINDOW_SHUT             	0x00000C00  /* SRC_WINDOW_SHUT | DST_WIN*/
#define ARGUS_SRC_WINDOW_SHUT         	0x00000400
#define ARGUS_DST_WINDOW_SHUT         	0x00000800
#define ARGUS_RESET                   	0x00003000  /* SRC_RESET | DST_RESET */
#define ARGUS_SRC_RESET               	0x00001000
#define ARGUS_DST_RESET               	0x00002000
#define ARGUS_ECN_CONGESTED           	0x0000C000  /* SRC_CONGESTED | DST_CONGESTED */
#define ARGUS_SRC_CONGESTED           	0x00004000
#define ARGUS_DST_CONGESTED           	0x00008000


#define ARGUS_OUTOFORDER		0x00030000
#define ARGUS_SRC_OUTOFORDER    	0x00010000
#define ARGUS_DST_OUTOFORDER    	0x00020000

#define ARGUS_TCP_OPTIONS	0xFFF00000
#define ARGUS_TCP_MAXSEG	0x00100000
#define ARGUS_TCP_WSCALE	0x00200000
#define ARGUS_TCP_SACKOK	0x00400000
#define ARGUS_TCP_SACK		0x00800000
#define ARGUS_TCP_ECHO		0x01000000
#define ARGUS_TCP_ECHOREPLY	0x02000000
#define ARGUS_TCP_TIMESTAMP	0x04000000
#define ARGUS_TCP_CC		0x08000000
#define ARGUS_TCP_CCNEW		0x10000000
#define ARGUS_TCP_CCECHO	0x20000000

#define ARGUS_TCP_SRC_ECN	0x40000000
#define ARGUS_TCP_DST_ECN	0x80000000


/* Fragment State Constants and Reporting Values */

#define ARGUS_FRAG_INIT			0x0001
#define ARGUS_FRAG_OUT_OF_ORDER		0x0002
#define ARGUS_TCPFRAGOFFSETERROR	0x0004

/* User Data Qualifier Values */

#define ARGUS_FAR_DSR_STATUS		0x00000001
#define ARGUS_MAC_DSR_STATUS		0x00000010
#define ARGUS_VLAN_DSR_STATUS		0x00000020
#define ARGUS_MPLS_DSR_STATUS		0x00000040
#define ARGUS_PPPOE_DSR_STATUS		0x00000080

#define ARGUS_TCP_DSR_STATUS		0x00000100
#define ARGUS_ICMP_DSR_STATUS		0x00000200
#define ARGUS_RTP_DSR_STATUS		0x00000400
#define ARGUS_RCTP_DSR_STATUS		0x00000800
#define ARGUS_IGMP_DSR_STATUS		0x00001000
#define ARGUS_ARP_DSR_STATUS		0x00002000
#define ARGUS_FRG_DSR_STATUS		0x00004000
 
#define ARGUS_TIME_DSR_STATUS		0x00100000
#define ARGUS_SRCUSRDATA_DSR_STATUS	0x00200000
#define ARGUS_DSTUSRDATA_DSR_STATUS	0x00400000
#define ARGUS_ESP_DSR_STATUS		0x00800000

#define ARGUS_SRCTIME_DSR_STATUS	0x01000000
#define ARGUS_DSTTIME_DSR_STATUS	0x02000000

#define ARGUS_COROLATE_DSR_STATUS	0x04000000

#define ARGUS_AGR_DSR_STATUS		0x80000000
 
#define ARGUS_FAR_DSR_INDEX		0
   
#define ARGUS_MAC_DSR_INDEX		4
#define ARGUS_VLAN_DSR_INDEX		5
#define ARGUS_MPLS_DSR_INDEX		6
#define ARGUS_PPPOE_DSR_INDEX		7
#define ARGUS_TCP_DSR_INDEX		8
#define ARGUS_ICMP_DSR_INDEX		9
#define ARGUS_RTP_DSR_INDEX		10
#define ARGUS_RTCP_DSR_INDEX		11
#define ARGUS_IGMP_DSR_INDEX		12
#define ARGUS_ARP_DSR_INDEX		13
#define ARGUS_FRG_DSR_INDEX		14
  
#define ARGUS_TIME_DSR_INDEX		20
#define ARGUS_SRCUSRDATA_DSR_INDEX	21
#define ARGUS_DSTUSRDATA_DSR_INDEX	22
#define ARGUS_ESP_DSR_INDEX		23
#define ARGUS_SRCTIME_DSR_INDEX		24
#define ARGUS_DSTTIME_DSR_INDEX		25
#define ARGUS_COROLATE_DSR_INDEX	26

#define ARGUS_AGR_DSR_INDEX		31

#define ARGUS_AGR_USECACTTIME		0x0010
#define ARGUS_AGR_USECIDLETIME		0x0020

#define ARGUS_AGR_MSECACTTIME		0x0040
#define ARGUS_AGR_MSECIDLETIME		0x0080

#define ARGUS_AGR_NORMALIZED  		0x0100

#endif /*  Argus_def_h */
