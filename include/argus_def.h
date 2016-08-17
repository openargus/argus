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
 * $Id: //depot/argus/argus/include/argus_def.h#49 $
 * $DateTime: 2015/07/02 09:02:44 $
 * $Change: 3029 $
 */

/* Argus_def.h */
/* 
 * Argus_def.h is a reimplementation of the version 2 argus_def.h
 * for version 3.  The new record structure and data types
 * are designed to provide flexible and efficient data 
 * representation and transport; motivated to suport IPv6. 
 * While the intent is to provide a clean room style reworking
 * of the complete argus architecture and data model, there is
 * continuity and compatibility with version 2 Argus data.
 *
 * The basic properties retained are a common fixed size
 * initial MAR *.  The prinicpal difference is a 4 byte
 * ArgusRecord header with most data integrated into the
 * Data Supplement Records (DSR), support for 8, 16, 32 and
 * 64 bit counters, and new flow descriptor strategies.
 *
 */

#ifndef Argus_def_h
#define Argus_def_h

#ifdef __cplusplus
extern "C" {
#endif
/* 
   argus constants 
*/

#define MINOR_VERSION_0    0
#define MINOR_VERSION_1    1
#define MINOR_VERSION_2    2
#define MINOR_VERSION_3    3
#define MINOR_VERSION_4    4
#define MINOR_VERSION_5    5
#define MINOR_VERSION_6    6
#define MINOR_VERSION_7    7
#define MINOR_VERSION_8    8
#define MINOR_VERSION_9    9
#define MAJOR_VERSION_1    1
#define MAJOR_VERSION_2    2
#define MAJOR_VERSION_3    3
#define MAJOR_VERSION_4    4
#define MAJOR_VERSION_5    5
#define VERSION_MAJOR      MAJOR_VERSION_3
#define VERSION_MINOR      MINOR_VERSION_0

#ifndef MAXPATHNAMELEN
#define MAXPATHNAMELEN          BUFSIZ
#endif

/*
   Argus Record Format
      The Argus has a short 32-bit header and then a collection
      of Data Specific Records, which have a TLV structure.
      This allows for a lot of options in representing data.
      The goal is to support explicit data alignment, extended
      key and non-key attributes, removeable transport identifiers,
      efficently reporting unidirectional flows, and supporting
      multi-length counters in the metrics.
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Argus Record Header                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Record Transport                     | O
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ p
   |                                                               | t
   |                     Argus Record Flow Key                     | i
   |                                                               | o
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ n
   |                   Argus Record Flow Non-Key                   | a  
   |                          Attributes                           | l  
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               | D
   |                          Argus Metrics                        | S
   |                               .                               | R
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ s

*/

/*
   Argus Record Header Format
     The argus record is a 32-bit header that specifies the
     type of record, MAR or FAR, the standard cause indicator,
     a shorter version number, starting with 3, and a Options
     field.  The Length field, which is the number of 4-byte
     integers in the record,  supports 64K size argus records.
                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type |  Vers | Cause |  Opt  |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define ARGUS_MAXRECORDSIZE			0x40000

/*
   Argus  Record Header Type Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type |                                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Version Record Field
          Note that one tick mark represents one bit position.
*/

/* Argus  Record Type */

#define ARGUS_MAR				0x80   /* Normal Argus Management Record */
 
#define ARGUS_FAR 				0x10   /* Normal Argus Data Record */

#define ARGUS_INDEX   				0x20   /* New Argus Index Record */
#define ARGUS_NETFLOW  				0x30   /* Argus Cisco Netflow Originated Record */
#define ARGUS_EVENT				0x40   /* New Argus Event/Message Record */
#define ARGUS_DATASUP				0x50   /* New Supplemental Argus Data Record */
#define ARGUS_ARCHIVAL				0x60   /* New Archival Argus Data Record */


/*
 
   Argus Record Header Version Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       |  Vers |                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                      Argus Version Record Field
          Note that one tick mark represents one bit position.
*/


/* Record Version (Ver) */
 
#define ARGUS_VERSION_1				0x01	/* Version 1 */
#define ARGUS_VERSION_2				0x02	/* Version 2 */
#define ARGUS_VERSION_3				0x03	/* Version 3 */
#define ARGUS_VERSION_4				0x04	/* Version 4 */
 
#define ARGUS_VERSION				ARGUS_VERSION_3	/* Version 3 */


/*
   Argus Record Header Version Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               | Cause |                                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                         Argus Version Record Field
          Note that one tick mark represents one bit position.
*/


/* Argus Record Cause */
  
#define ARGUS_START				0x10   /* Initial Record */
#define ARGUS_STATUS				0x20   /* Continuation Record*/
#define ARGUS_STOP				0x30   /* Closed/Terminating Record */
#define ARGUS_TIMEOUT				0x40   /* Record Timed Out */
#define ARGUS_FLUSH				0x50   /* System Record Flush */
#define ARGUS_SHUTDOWN				0x60   /* Administrative Shutdown */
#define ARGUS_CLOSED				0x70   /* Argus Initiates Shutdown */

#define ARGUS_ERROR				0x80   /* Error - Major Problem */
#define ARGUS_SUPPLEMENTAL			0x90   /* Argus Supplemental Record */

/*
   Argus  Record Header Option Field

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       |  Opt  |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                        Argus Option Record Field
          Note that one tick mark represents one bit position.

   The values in the Argus Option Field are specific to each cause.
*/

/*
   Argus Start Option Messages
*/
/*
   Argus Status Option Messages
*/
/*
   Argus Supplemental Option Messages
*/
/*
   Argus Stop Option Messages
*/
/*
   Argus Timeout Option Messages
*/
/*
   Argus Flush Option Messages
*/
/*
   Argus Shutdown Option Messages
*/
/*
   Argus Error Option Messages
*/
 
#define ARGUS_ACCESSDENIED			0x01
#define ARGUS_MAXLISTENEXCD			0x02


/*
   Argus  Record Header Length Field
      Number of 32-bit longwords, including the header.
      Unsigned 16 bit integer.
  
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
  
                        Argus Length Record Field
          Note that one tick mark represents one bit position.
*/


#define MAXARGUSRECORD           		0x40000
#define MAXSTRLEN               		4096


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

                        Argus Data Record Field
          Note that one tick mark represents one bit position.
*/


/* Argus MAR Record Specific Defines */
 
#define ARGUS_COOKIE				0xE5712DCB
#define ARGUS_V3_COOKIE				ARGUS_COOKIE
#define ARGUS_V2_COOKIE				0xE5617ACB
#define ARGUS_SASL_AUTHENTICATE			0x00001000

#define ARGUS_IDIS_STRING			0x00200000
#define ARGUS_IDIS_INT				0x00400000
#define ARGUS_IDIS_IPV4				0x00800000
 
 
/* Argus Record Data Specific Record (DSR) Types */

#define ARGUSMAXDSRTYPE				21

/* Argus Data Specific Record (DSR) Formats
      There are two types of DSR, 1) a Type Value (TV) record
      with an explicit length of 4 bytes, and 2) a Type 
      Length Value (TLV) record, that is longer than 4 bytes
      and supports variable length records.

      The fixed length record is distinquished from the variable
      length record with the most significant bit of the Type
      Field set to 1 (>= 0x80).

      All Argus DSRs are 32-bit aligned.  

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|    Type     |    SubType    |   Qualifier   |     Length    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                         Argus DSR Data                         |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|    Type     |    SubType    |          Argus DSR Data        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                 Argus Data Specific Record (DSR) Field
          Note that one tick mark represents one bit position.
*/

/*
   Argus Record Data Type Field
      The DSR Type Field specifies the type and format of the
      DSR.  The most significant bit indicates if the DSR is a
      TV or TLV type.  A TV structure has a specific length of
      4 bytes, which a TLV has a variable length indicator.
      The other bits specify highest level semantics for the DSR. 

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |x|   Type      |                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define ARGUS_IMMEDIATE_DATA			0x80

#define ARGUS_TRANSPORT_DSR			0x01
#define ARGUS_FLOW_DSR				0x02
#define ARGUS_TIME_DSR				0x03

#define ARGUS_METER_DSR				0x10
#define ARGUS_PSIZE_DSR                         0x12

#define ARGUS_ENCAPS_DSR			0x20
#define ARGUS_NETWORK_DSR			0x30
#define ARGUS_ICMP_DSR				0x34

#define ARGUS_IB_DSR                            0x35
#define ARGUS_ISIS_DSR                          0x36
#define ARGUS_RSVP_DSR                          0x37
#define ARGUS_ESP_DSR                           0x38
#define ARGUS_LCP_DSR                           0x39

#define ARGUS_DATA_DSR				0x50
#define ARGUS_AGR_DSR				0x60
#define ARGUS_COR_DSR				0x62
#define ARGUS_COCODE_DSR			0x64
#define ARGUS_LABEL_DSR				0x66



/*
   Argus Record Data SubType Field

      The DSR SubType Field indicates the specific types for
      this DSR, and is specific for the DSR Type.  The most
      significant bit of the subtype field indicates the width
      of the length, when it is present.
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|             |x|  SubType    |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|             |0|  SubType    |                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

#define ARGUS_LEN_16BITS                         0x80
#define ARGUS_TIMEADJUST                         0x01
   
/*    
   Argus Record Data Qualifier Field
      TLV Data Records that have an 8 bit length field support an
      8-bit  Qualifier field, which is used to convey additional semantics
      for the DSR format and contents.  In some situations, the qualifier
      may be used to further specify the actual DSR data format, in others
      it may provide addition semantics, or it can be used to provide the
      actual 8-bit data.
    
      How the Qualifier is parsed and used is specific to the 
      DSR Type and SubType.
   
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   |0|             |0|             |   Qualifier   |               | 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+ 
   
*/ 


/* Argus DSR Qualifier */
   
#define ARGUS_SRC				0x01
#define ARGUS_DST				0x02
#define ARGUS_SRC_CHANGED                       0x04 
#define ARGUS_DST_CHANGED                       0x08
#define ARGUS_SRC_INT_CHANGED                   0x10
#define ARGUS_DST_INT_CHANGED                   0x20

#define ARGUS_TYPE_IPV4                         0x01
#define ARGUS_TYPE_IPV6                         0x02
#define ARGUS_TYPE_ETHER                        0x03
#define ARGUS_TYPE_ARP                          0x04
#define ARGUS_TYPE_RARP                         0x05
#define ARGUS_TYPE_MPLS                         0x06
#define ARGUS_TYPE_VLAN                         0x07
#define ARGUS_TYPE_WLAN                         0x08
#define ARGUS_TYPE_LCP                          0x09
#define ARGUS_TYPE_ISIS                         0x0A
#define ARGUS_TYPE_IB_LOCAL                     0x0B
#define ARGUS_TYPE_IB_GLOBAL                    0x0C

#define ARGUS_TYPE_UDT                          0x0D
 
#define ARGUS_TYPE_INT				0x20
#define ARGUS_TYPE_STRING			0x21


/* Flow Descriptor Option Qualifiers */
#define ARGUS_ANON				0x20

/* Record Descriptor Qualifiers */
#define ARGUS_MERGED				0x40


/*
   Argus Record Data Length Field
      Number of 32-bit longwords, including the header.
      Data records that have a 0 as the most significant
      bit support variable length records, and as a result
      have a length field.  Records with a 1 as the most
      significant bit are fixed length 4 byte records,
      and thus do not have a length field.
     
    0                   1                   2                   3  
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|                                             |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
      The Length field can equal 1.
*/

#define ARGUS_MAXDSRLEN				0xFF


/*
   Argus Data Transport DSR 
      The Transport DSR provides source probe identification
      and optionally a probe transport specific sequence number.
      The probe identifier can be a number of types including
      an IPv4, IPv6 address, an ethernet address, a unsigned
      32-bit integer, and/or an arbitrary string, such as a URL.

      The probe identifier should be unique throughout the
      monitoring domain.
*/

#define ARGUS_MAR_INDEX				0
#define ARGUS_EVENT_INDEX			0

/* Argus Transport DSR Type */
#define ARGUS_TRANSPORT_INDEX			0

/* Argus Transport DSR SubType */
#define ARGUS_SRCID				0x01
#define ARGUS_SEQ				0x02

/* Argus Transport DSR Qualifier */
/*
   ARGUS_TYPE_IPV4
   ARGUS_TYPE_IPV6
   TAM_TYPE_ETHER
   ARGUS_TYPE_INT
   ARGUS_TYPE_STRING

    ARGUS_SRCID  (with IPV4ADDR as the ID)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x01     |      0x01     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Source Identifier                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_SRCID  (with IPV6ADDR as the ID)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x01     |      0x02     |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                    Argus Source Identifier                     |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_SRCID | ARGUS_SEQ (with 32-bin unsigned int as ID)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x03     |      0x03     |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Source Identifier                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_SRCID | ARGUS_SEQ  (with STRING as ID)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x03     |      0x11     |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Argus Source Identifier                     |
   |                                                               |
   |                               +---+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |              PAD              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Argus Transport Record Field
          Note that one tick mark represents one bit position.
*/


/*
   Argus Time Descriptor DSR 
       The Argus Time Descriptor is an optional DSR that specifies
       time for packet related events.  These can represent time
       ranges, single timestamps, or relative timestamps.  If
       relative timestamps are used in an Argus record, there must
       be only one absolute timestamp to act as the unambiguous
       reference, and this should be the first timestamp in the
       record.  This absolute reference can stand alone or be
       included in a composite structure that also contains
       relative time references.  The scale must match, or there
       is an error.

       Unsigned 32-bit uSec relative time references can handle
       up to 71.58278 minutes, and nSec relative time refereces
       can handle up to 4.294967296 seconds, however there are
       many network events that can exceed these time ranges,
       and so when needed, absolute time ranges will be used.

       Flows are bounded in time with single packet events having
       a single reference, and multiple packet flows having
       additional time boundary references.

       In the case of uni-directional multi-packet flows, a
       time range indicates the time for the occurence of the
       first and last measured event for that flow.  In bi-directional
       flows, the strategy is to represent the metrics as two uni-
       directional flows bound together by the flow descriptors,
       and some state.  This strategy impacts how time will be
       reported.

       Each uni-directional flow can be composed of a single packet
       event or a multi-packet event, so there is a requirement
       to support up to 4 timestamps in a given record.
       
*/


/* Argus Time Descriptor DSR Types */
#define ARGUS_TIME_INDEX				2


/* Argus Time Descriptor DSR SubTypes */
#define ARGUS_TIME_ABSOLUTE_TIMESTAMP		0x01
#define ARGUS_TIME_ABSOLUTE_RANGE		0x02
#define ARGUS_TIME_ABSOLUTE_RELATIVE_RANGE	0x03
#define ARGUS_TIME_RELATIVE_TIMESTAMP		0x04
#define ARGUS_TIME_RELATIVE_RANGE		0x05

#define ARGUS_TIME_SRC_START                    0x08
#define ARGUS_TIME_SRC_END                      0x10
#define ARGUS_TIME_DST_START                    0x20
#define ARGUS_TIME_DST_END                      0x40

#define ARGUS_TIME_MASK (ARGUS_TIME_SRC_START | ARGUS_TIME_DST_START | ARGUS_TIME_SRC_END | ARGUS_TIME_DST_END)


/* Argus Flow Descriptor DSR Qualifiers */
 
#define ARGUS_TYPE_UTC_MICROSECONDS		0x18
#define ARGUS_TYPE_UTC_NANOSECONDS		0x19
#define ARGUS_TYPE_MICROSECONDS			0x1A
#define ARGUS_TYPE_NANOSECONDS			0x1B

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x03      |      0x01     |      0x18     |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Seconds                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Fractional Seconds (usec)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x03      |      0x02     |      0x18     |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Argus Record Start Time (UTC)                 |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Argus Record Last Time  (UTC)                 |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x03      |      0x03     |      0x19     |      0x04     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            Seconds                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Fractional Seconds (nsec)                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Delta Fractional Seconds (nsec)                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x03      |      0x04     |      0x1A     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                Delta Fractional Seconds (usec)                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x03      |      0x05     |      0x1B     |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             Start Delta Fractional Seconds (nsec)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Last Delta Fractional Seconds (nsec)             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                        Argus Time Record Field
           Note that one tick mark represents one bit position.
*/


/*
   Argus Time Adjustment Descriptor DSR 
       The Argus Time Adjustment Descriptor is an optional DSR that
       specifies a time adjustment that is assigned/imposed by
       the NTAIS system.  Generally added by either an intermediate
       RADIUM node or in the receiving NTAIS, this value is a
       single time adjustment value to bring the timestamps into
       synchronization in the system.  

       The DSR is a composite DSR, and is composed of a mandatory
       Source Identifier, and a Timestamp, as specified above.

       The minimum record length is 24 bytes long (6 * 4).
*/


/* Argus Time Descriptor DSR Types */
#define ARGUS_TIME_ADJ_INDEX			16

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x09      |      0x00     |      0x00     |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     Argus Transport Record                     |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Argus Time Record                        |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                     Argus Time Adjustment Record Field
           Note that one tick mark represents one bit position.
*/
 
/*
   Argus Flow Descriptor DSR 
       The Argus Flow Descriptor is an optional DSR that
       specifies the key and non-key attributes that apply
       to the flow record.  Key attributes indicate the
       attributes that were used by the probe or aggregator
       to formulate the flow.  This may involve any combination
       of identifiers that were contained in the packets
       themselves.

       A flow description is a collection of identifiers
       that were used to classify packets.  All packets that
       contain the identifiers are considered a part of the
       same flow model.  The Argus supports both uni and bi-
       directional flow modeling.  Because flow descriptors
       can be directionally sensitive, a direction bit is
       included in the flow descriptor qualifier.

       The Argus supports a number of pre-defined complex
       flow descriptor groupings as specific data types,
       in order to be efficient.  It also supports arbitrary
       flow descriptions,

       While most flows will be Type-P1 5-tuple Layer 3/4
       flows, many applications will want to support Layer 2,
       unidirectional Layer 2.5 (MPLS), Layer 3 address,
       and Layer 3 CIDR address based flows.
   
       Aggregation experiments indicate that non-key attributes
       can be persistent during the life of some flows, and the
       ability to report these attributes is important for
       many analytical methods.  So, indicating persistent and
       non-persistent/last attribute values is extremely
       important. 

       It is important to propagte throught the life of the
       flow record, an indication that the RMON style of
       data, where only one set of the bi-directional flow
       key objects, are retained and being used as a key.

       Attributes that are used as keys are indicated in the
       most significant bit of the DSR.
*/


/* Argus Flow Descriptor DSR Types */
#define ARGUS_FLOW_INDEX			1


/* Argus Flow Descriptor DSR SubTypes */
#define ARGUS_FLOW_KEY_ATTRIBUTE		0x80
 
#define ARGUS_FLOW_CLASSIC5TUPLE                0x01
#define ARGUS_FLOW_LAYER_2_MATRIX               0x02
#define ARGUS_FLOW_LAYER_3_MATRIX               0x03
#define ARGUS_FLOW_MPLS                         0x04
#define ARGUS_FLOW_VLAN                         0x05
#define ARGUS_FLOW_ARP                          0x06
#define ARGUS_FLOW_LAYER_2                      0x07

#define ARGUS_FLOW_KEYS                         0x00000007
#define ARGUS_FLOW_KEY_CLASSIC5TUPLE            0x00000001
#define ARGUS_FLOW_KEY_LAYER_2_MATRIX           0x00000002
#define ARGUS_FLOW_KEY_LAYER_3_MATRIX           0x00000004
#define ARGUS_FLOW_KEY_LOCAL_MPLS               0x00000008
#define ARGUS_FLOW_KEY_COMPLETE_MPLS            0x00000010
#define ARGUS_FLOW_KEY_VLAN                     0x00000020
#define ARGUS_FLOW_KEY_LAYER_2                  0x00000040


#define ARGUS_FLOW_COMPOSITE                    0x08
#define ARGUS_FLOW_DLT_IANA			0x10  /* this is the layer 2 ifType */
#define ARGUS_FLOW_ETH_IANA			0x11  /* this is the layer 3 protocol ids */
#define ARGUS_FLOW_IP_IANA			0x12  /* this is the layer 4 protocol/nexthop number */

#define ARGUS_FLOW_RMON				0x40  /* this has been created usig RMON options */

/* Argus Flow Descriptor DSR Qualifiers */
#define ARGUS_SYSTEM_FLOW			0x20
#define ARGUS_REVERSE				0x40

#define ARGUS_UNIDIRECTIONAL			0x10
#define ARGUS_BIDIRECTIONAL			0x20
#define ARGUS_MASKLEN				0x40
#define ARGUS_FRAGMENT				0x80

/*

    ARGUS_FLOW_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|D|  SubType  |   Qualifier   |     Length    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                   Argus Flow Specific Data                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=ARGUS_FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_IPV4
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|  0x01     |     0x01      |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  IP Proto     |  Trans Proto  |          Source Port          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination Port        |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=ARGUS_FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_IPV6
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|    0x01   |      0x02     |      0x0B     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                       Source IPv4 Address                     |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                    Destination IPv4 Address                   |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  IP Proto     |  Trans Proto  |          Source Port          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination Port        |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_ETHER
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|    0x01   |      0x03     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Source                                                    |
   |     Ethernet                  +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Address                   |           Destination         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+           Ethernet            |
   |                                           Address             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Ethernet Type           |      dsap     |      ssap     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=ARGUS_FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_IPV4
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|    0x01   |      0x01     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     ICMP      |  Trans Proto  |     Type      |     Code      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Identifier         |         IP Identifier         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    TYPE=ARGUS_FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_IPV4
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|   0x01    |      0x01     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     IGMP      |  Trans Proto  |     Type      |     Code      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |              Pad              |         IP Identifier         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=ARGUS_FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_IPV4
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|    0x01   |      0x01     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |      ESP      |  Trans Proto  |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                  Security Payload Identifier                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_ARP
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|0|    0x01   |      0x07     |      0x06     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP SPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP TPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |        Ethernet Address       +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                               |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
    ARGUS_FLOW_CLASSIC5TUPLE
    TYPE=FLOW   SubType=ARGUS_CLASSIC5TUPLE    Qual=ARGUS_TYPE_ARP (reverse)
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|1|    0x01   |      0x07     |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            ARP TPA                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Source                                                 |
   |        Ethernet               +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        Address                |            Target             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+            Ethernet           |
   |                                            Address            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


*/

/*
   ARGUS_FLOW_COMPOSITE

   Composite argus flow descriptors allow for arbitrary identifiers
   to be used as flow key elements.  The trick is to effeciently
   encode the flow descriptor so that clients can keep up.

   The concept is that anything in the packet should be fair game
   fair game, as they are observable identifiers.  Practically
   there are limits, as some fields are arbitrary, or can be
   modified in the network.

   Composite flow keys are indicated using the ARGUS_FLOW_COMPOSITE
   DSR identifier, which is a header preceeding a set of IANA based
   packet content identifiers.  The values of many of the constants
   are defined in other include files, and so if you see a value
   you are not familiar with, grep for in the set of include files
   provided.

   First the composite methods should be capable of representing
   the stanard flow defintiions efficiently.

   This is an example of how to indicate the classic
   IPv4 5-tuple flow spec for UDP traffic, using Composite Flow DSRs.

    Type=COMPOSITE  
       SubType=IANA_LAYER3  Qual=IPv4
       SubType=IANA_LAYER4  IANA        Qual=UDP
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x08     |      0x01     |      0x06     |  Composite
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x01     |      0x01     |      0x03     |  IPv4 Matrix
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x10     |      0x11     |      0x02     |  UDP Matrix
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


   This is an example of how to indicate a modified  IPv4
   flow spec for UDP traffic, using Composite Flow DSRs. This
   flow spec has src and dst address data and just the protocol
   field.

    Type=COMPOSITE  
       SubType=IANA_LAYER3  Qual=IPv4
       SubType=IANA_LAYER4  IANA        Qual=UDP
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x08     |      0x01     |      0x06     |  Composite
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x01     |      0x01     |      0x03     |  IPv4 Matrix
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x10     |             0x11              |  UDP Protocol
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    Type=FLOW     SubType=LAYER3  Qual=IPv4
    Type=LAYER4   SubType=IANA    Qual=TCP
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x01     |      0x01     |      0x07     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |1|D|  0x01     |     0x01      |      0x05     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  IP Proto     |  Trans Proto  |          Source Port          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |       Destination Port        |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x10     |          Source ToS           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_FLOW_IPV6_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x02     |   Qualifier   |      0x0A     |
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
   |0|   0x02      |K|    0x10     |      0x06     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*

#define ARGUS_PROTO_DSR				0x04

    ARGUS_PROTO_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x04      |K| ProtoType   |         Protocol Data         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x04      |K| Proto Type  |   Qualifier   |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                 Argus Protocol Specific Data                  |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*
#define ARGUS_PROTO_DLT_DSR			0x04
#define ARGUS_PROTO_DLT_BPF			0x01
#define ARGUS_PROTO_DLT_IANA			0x02
 

    ARGUS_PROTO_DLT_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x04      |K| DLT Value   |      Data Link Type Data      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x04      |K| DLT Value   |   Qualifier   |     Length    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 

 
    ARGUS_PROTO_DLT_802_1Q_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x04      |K|     71      |          802.1Q Tag           |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

/*
    ARGUS_PROTO_ETHER_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x04      |K|   ETH_IANA  |     Ethernet Protocol Value   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/
 


/*
#define ARGUS_PROTO_IP_DSR			0x10
#define ARGUS_PROTO_IP_ATTR_DSR			0x04
#define ARGUS_PROTO_IP_OPTIONS_DSR		0x05
*/

/* ARGUS_PROTO_IP_DSR IP Qualifiers */

#define ARGUS_IP_V4				0x01
#define ARGUS_IP_V6				0x02
#define ARGUS_IP_OPTIONS			0x03

/* ARGUS_PROTO_IP_ATTR_DSR Status */
/*
#define ARGUS_IP_TOS_MODIFIED			0x00001000
#define ARGUS_IP_TTL_MODIFIED			0x00002000
#define ARGUS_IP_OPTIONS_MODIFIED		0x00004000
*/

#define ARGUS_ICMP_MAPPED			0x07
#define ARGUS_ICMPUNREACH_MAPPED		0x01
#define ARGUS_ICMPREDIREC_MAPPED		0x02
#define ARGUS_ICMPTIMXCED_MAPPED		0x04

/* IP Header Field Identifiers */

#define ARGUS_IP_SRC				0x01
#define ARGUS_IP_DST				0x02
#define ARGUS_IP_PROTO				0x04
#define ARGUS_IP_TOS				0x08
#define ARGUS_IP_TTL				0x10
#define ARGUS_IP_ID 				0x20

/* IP Option Indicators */

#define ARGUS_RECORDROUTE			0x01
#define ARGUS_TIMESTAMP				0x02
#define ARGUS_SECURITY				0x04
#define ARGUS_LSRCROUTE				0x08
#define ARGUS_SATID				0x10
#define ARGUS_SSRCROUTE				0x20
#define ARGUS_RTRALERT				0x40

/*
    ARGUS_PROTO_IP_ATTR_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x10      |K|    0x04     |   Qualifier   |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |             IP ID             |      TTL      |      TOS      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |            Status             |    Options    |    Reserved   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
*/


/* 
    ARGUS_PROTO_IP_OPTIONS_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x10      |K|    0x05     |   Qualifier   |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       IP Options Indicator                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

 
/*

#define ARGUS_PROTO_IP_PROTO_DSR			0x12

    ARGUS_PROTO_IP_PROTO_DSR
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x12      |K|    0x10     |   Qualifier   |   Proto Num   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |   Proto Num   |     Length    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                           DSR Data                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	TCP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x06     |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           TCP State           |           TCP Options         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	UDP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x11     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	ICMP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x01     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   ICMP Type   |   ICMP Code   |            ICMP ID            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	ESP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x32     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               ESP Security Payload Identifiier                |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


    ARGUS_PROTO_IP_DSR	IGMP Specific
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |1|   0x12      |1|    0x10     |      0x02     |      0x02     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   IGMP Type   |   IGMP Code   |              Pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x20      |    SubType    |   Qualifier   |    Length     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Argus Meter Specific Data                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


/* Argus Meter DSR Type */
#define ARGUS_METRIC_INDEX			3

/* Argus Meter DSR Subtype */
#define ARGUS_METER_PKTS_BYTES			0x01
#define ARGUS_METER_PKTS_BYTES_APP		0x04

 
/* Argus Meter DSR Qual */
#define ARGUS_SRCDST_BYTE			0x01
#define ARGUS_SRCDST_SHORT			0x02
#define ARGUS_SRCDST_INT				0x03
#define ARGUS_SRCDST_LONGLONG			0x04
#define ARGUS_SRC_BYTE				0x05
#define ARGUS_SRC_SHORT				0x06
#define ARGUS_SRC_INT				0x07
#define ARGUS_SRC_LONGLONG			0x08
#define ARGUS_DST_BYTE				0x09
#define ARGUS_DST_SHORT				0x0A
#define ARGUS_DST_INT				0x0B
#define ARGUS_DST_LONGLONG			0x0C

/*
#define ARGUS_METER_PKTS_BYTES			0x01

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |      0x01     |       2       |     0x02      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |           packets             |             bytes             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |      0x01     |       3       |     0x03      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                            packets                            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             bytes                             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |      0x01     |       4       |     0x05      |
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


/* Argus Packet Size DSR Type */
#define ARGUS_PSIZE_INDEX                       10

/* Argus Packet Size DSR Subtype */
#define ARGUS_PSIZE_SRC_MAX_MIN                 0x01
#define ARGUS_PSIZE_DST_MAX_MIN                 0x02
#define ARGUS_PSIZE_HISTO                   	0x04

/* Argus Packet Size DSR Qual (same as Metric above) */
/*
#define ARGUS_SRCDST_SHORT                      0x02
#define ARGUS_SRCDST_INT                        0x03
#define ARGUS_SRC_SHORT                         0x06
#define ARGUS_SRC_INT                           0x07
#define ARGUS_DST_SHORT                         0x0A
#define ARGUS_DST_INT                           0x0B
*/

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |      0x01     |      0x06     |     0x03      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        src min size           |         src max size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |        dst min size           |         dst max size          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    Standard Source and Destination max and min packet size report.
*/



#define ARGUS_DIRECTION          		0x0000020 

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x04     |   Qualifier   |      0x04     |
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
   |0|   0x20      |K|    0x05     | D | Qualifier |    Length     |
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



/*
#define ARGUS_METER_IGMP_PERF		0x06

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x06     | D | Qualifier |      0x06     |
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

/*
#define ARGUS_METER_ESP_PERF		0x07
*/

/* IP Sec AH Header Qualifier Bits */
 

/*
#define ARGUS_AH_HDR                  0x10
#define ARGUS_AH_REPLAY               0x08

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x07     |   Qualifier   |      0x03     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       ESP Last Sequence                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    ESP Lost Sequence Number                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/


#define ARGUS_AGR_INDEX				4

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x22      |     0x01      |   Qualifier   |     0x02      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         record  count                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x22      |     0x02      |   Qualifier   |     0x07      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         record  count                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                     lastStartTime Seconds                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    lastStartTime  uSeconds                    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        lastTime Seconds                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                       lastTime  uSeconds                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/* Argus Encapsulation DSR Type */
#define ARGUS_ENCAPS_INDEX                      15

/* Argus Encapsulation DSR Qualifier */
#define ARGUS_ENCAPS_CHANGED                    0x80

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |     0x00      |   Qualifier   |     0x03      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Src Encapsulation Mask                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                   Dst Encapsulation Mask                      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/


/* Argus Fragment DSR Type */
#define ARGUS_FRAG_INDEX				5

#define ARGUS_FRAGMENTS				0x01
#define ARGUS_FRAGOVERLAP			0x02

/* Fragment State Constants and Reporting Values */

#define ARGUS_FRAG_INIT				0x10
#define ARGUS_FRAG_OUT_OF_ORDER			0x20
#define ARGUS_TCPFRAGOFFSETERROR		0x40


/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x25      |     0x01      |   Qualifier   |     0x02      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                         fragment number                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      fragment identification                  |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Total Fragment Length     |    Current Fragment Length    |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |   Maxiumum Fragment Length    |              pad              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/

 
/*
   Argus Network DSR 
      The Network DSR provides additional information regarding
      transport layer information.
*/
 
/* Argus Transport DSR Type */
#define ARGUS_NETWORK_INDEX		5 


/* Argus Transport DSR Subtype */
#define ARGUS_TCP_INIT			0x03
#define ARGUS_TCP_STATUS		0x04
#define ARGUS_TCP_PERF			0x05
#define ARGUS_NETWORK_SUBTYPE_ARP	0x10
#define ARGUS_NETWORK_SUBTYPE_FRAG	0x45

/* RTP State Constants and Reporting Values */
#define ARGUS_RTP_SRCSILENCE		0x01
#define ARGUS_RTP_DSTSILENCE		0x02

#define ARGUS_HTTP_FLOWTAG		0x01

#define ARGUS_RTCP_FLOW			0x09
#define ARGUS_RTP_FLOW			0x0A

/* UDT State Constants and Reporting Values */
#define ARGUS_UDT_FLOW                  0x0D


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


#define ARGUS_PKTS_DROP                 0x30
#define ARGUS_SRC_PKTS_DROP             0x10
#define ARGUS_DST_PKTS_DROP             0x20

#define ARGUS_OUTOFORDER		0x00030000
#define ARGUS_SRC_OUTOFORDER    	0x00010000
#define ARGUS_DST_OUTOFORDER    	0x00020000

#define ARGUS_DUPLICATES		0x000C0000
#define ARGUS_SRC_DUPLICATES    	0x00040000
#define ARGUS_DST_DUPLICATES    	0x00080000

#define ARGUS_TCP_OPTIONS		0xFFF00000
#define ARGUS_TCP_MAXSEG		0x00100000
#define ARGUS_TCP_WSCALE		0x00200000
#define ARGUS_TCP_SACKOK		0x00400000
#define ARGUS_TCP_SACK			0x00800000
#define ARGUS_TCP_ECHO			0x01000000
#define ARGUS_TCP_ECHOREPLY		0x02000000
#define ARGUS_TCP_TIMESTAMP		0x04000000
#define ARGUS_TCP_CC			0x08000000
#define ARGUS_TCP_CCNEW			0x10000000
#define ARGUS_TCP_CCECHO		0x20000000
#define ARGUS_TCP_SRC_ECN		0x40000000
#define ARGUS_TCP_DST_ECN		0x80000000

#define ARGUS_UDT_OPTIONS		0xFFF00000
#define ARGUS_UDT_BADVERSION		0x00100000
#define ARGUS_UDT_FIRSTDROPZERO		0x01000000

/* ESP State Constatans and Reporting Values */
#define ARGUS_ESP_ROLLOVER              0x1000
#define ARGUS_ESP_SEQFAILURE            0x2000
 
/* Vlan Transport DSR Type */
#define ARGUS_VLAN_DSR                   0x40
#define ARGUS_VLAN_INDEX                 6 

#define ARGUS_SRC_VLAN                   0x01
#define ARGUS_DST_VLAN                   0x02

 
/* Mpls Transport DSR Type */
#define ARGUS_MPLS_DSR                   0x44
#define ARGUS_MPLS_INDEX                 7

/* Argus MPLS DSR SubType */
#define ARGUS_MPLS_SRC_LABEL		0x01
#define ARGUS_MPLS_DST_LABEL		0x02

/* Argus MPLS DSR Qualifier */
#define ARGUS_MPLS_SRC_LABEL_CHANGED	0x10
#define ARGUS_MPLS_DST_LABEL_CHANGED	0x20

/* Mac Layer Header DSR Type */
#define ARGUS_MAC_DSR                    0x42
#define ARGUS_MAC_INDEX                  13 

/* Argus Mac Layer DSR Qualifier */
#define ARGUS_MULTIPATH                  0x03
#define ARGUS_SRC_MULTIPATH              0x01
#define ARGUS_DST_MULTIPATH              0x02

/* Jitter Transport DSR Type */
#define ARGUS_JITTER_DSR                 0x46
#define ARGUS_JITTER_INDEX               8

/* Argus Jitter DSR Qualifier */
#define ARGUS_SRC_ACTIVE_JITTER		0x01
#define ARGUS_SRC_IDLE_JITTER		0x02
#define ARGUS_DST_ACTIVE_JITTER		0x04
#define ARGUS_DST_IDLE_JITTER		0x08


/* Argus Histogram DSR Type */
#define ARGUS_HISTO_DSR                 0x47
#define ARGUS_HISTO_INDEX               18

/* Argus Histogram DSR Subtype */
#define ARGUS_HISTO_EXP                 0x01
#define ARGUS_HISTO_LINEAR              0x02

/*
   ARGUS_HISTO_LINEAR       size:bins:start
   ARGUS_HISTO_EXPONENTIAL  size:bins:start:base
   ARGUS_HISTO_SCALED
   ARGUS_HISTO_OUTLAYER_LOWER
   ARGUS_HISTO_OUTLAYER_UPPER

*/


/* Argus IP Attribute DSR Type */
#define ARGUS_IPATTR_DSR                 0x48
#define ARGUS_IPATTR_INDEX               9

/* Argus IP Attribute DSR Qualifier */
#define ARGUS_IPATTR_SRC                 0x01
#define ARGUS_IPATTR_DST                 0x02
#define ARGUS_IPATTR_SRC_OPTIONS         0x04
#define ARGUS_IPATTR_DST_OPTIONS         0x08
#define ARGUS_IPATTR_SRC_FRAGMENTS       0x10 
#define ARGUS_IPATTR_DST_FRAGMENTS       0x20

/* Argus Data DSR Type */
#define ARGUS_DATA_DSR			0x50
#define ARGUS_SRCUSERDATA_INDEX		11
#define ARGUS_DSTUSERDATA_INDEX		12

/* Argus Data DSR SubTypes */
#define ARGUS_TOTAL_PACKET		0x01
#define ARGUS_PACKET_HDR		0x02
#define ARGUS_USER_DATA			0x03
#define ARGUS_DATA_COMPRESS		0x08

#define ARGUS_SRC_DATA			0x10
#define ARGUS_DST_DATA			0x20


/* Argus ICMP DSR Type */
#define ARGUS_ICMP_DSR			0x34
#define ARGUS_ICMP_INDEX		14

/* Argus Behavior DSR Type */
#define ARGUS_BEHAVIOR_DSR               0x54
#define ARGUS_BEHAVIOR_INDEX             17

/* Argus Behavior DSR SubTypes */
#define ARGUS_TCP_KEYSTROKE             0x01
#define ARGUS_SSH_KEYSTROKE             0x02

/* Argus Correlation DSR Type */
#define ARGUS_COR_INDEX			17

/* Argus Country Code DSR */
#define ARGUS_COCODE_INDEX		18

/* Argus Label DSR */
#define ARGUS_LABEL_INDEX               19

/* Argus Label SubTypes */
#define ARGUS_SVC_LABEL                 0x01

/* Argus ASN DSR */
#define ARGUS_ASN_DSR                   0x32
#define ARGUS_ASN_INDEX                 20

/* Argus ASN SubTypes */
#define ARGUS_ASN_ORIGIN                0x01
#define ARGUS_ASN_PEER                  0x02

#define ARGUS_SRC_ADDR			0x01
#define ARGUS_DST_ADDR			0x02
#define ARGUS_INODE_ADDR		0x04

#define ARGUS_ADDR_MASK         	0x07

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x50      |     0x01      |   Qualifier   |     0x24      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                                                               |
   |                     Total Packet Contents                     |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                      Argus Packet Contents Field
          Note that one tick mark represents one bit position.

    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x50      |     0x02      |   Qualifier   |     0x08      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                     Packet Header Contents                    |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                  Argus Packet Header Contents Field
          Note that one tick mark represents one bit position.


    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x50      |     0x03      |   Qualifier   |     0x80      |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               |
   |                                                               |
   |                    Flow User Data Contents                    |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   |                                                               |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                  Argus Packet Header Contents Field
          Note that one tick mark represents one bit position.
*/

/*
   Argus Record Examples
      Simple TCP 5-Tuple UDP flow record with transport
      identifier and sequence numbers with unidirectional
      Packet and Byte Load Metrics.
 
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Type | Cause |  Vers |  Opt  |             Length            |   Header
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     0x01      |      0x02     |      0x03     |      0x03     |   Transport
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Identifier
   |                     Argus Source Identifier                    |   and 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   sequence num
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x01     |      0x01     |      0x03     |   Flow Key
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   IPv4 Addrs
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x11     |      0x02     |   Flow Key
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   UDP and Ports
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x01     |   Qualifier   |     0x02      |   Src Load Metrics
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   16-bit counters
   |           packets             |             bytes             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+


      Simple TCP 5-Tuple TCP flow record with TCP state and
      status indicators, with bidirectional Packet and Byte Metrics.
 
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  0x1  |  0x2  |  0x03 |  0x0  |            0x000C             |   Header
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x02      |K|    0x01     |      0x01     |      0x03     |   Flow Key
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   IPv4 Addrs
   |                       Source IPv4 Address                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                    Destination IPv4 Address                   |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x12      |K|    0x10     |      0x06     |      0x02     |   Flow Key
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   TCP and Ports
   |          Source Port          |       Destination Port        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x16      |K|    0x10     |      0x06     |      0x02     |   TCP State and Options
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   Attributes
   |           TCP State           |           TCP Options         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x01     |   SRC Qual    |     0x02      |   Src Load Metrics
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   16-bit counters
   |           packets             |             bytes             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |0|   0x20      |K|    0x01     |   DST Qual    |     0x02      |   Dst Load Metrics
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+   16-bit counters
   |           packets             |             bytes             |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

*/



/*
    argus_def_v2.h
    Legacy Argus Record Header Format
                                    
    0                   1                   2                   3   
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |     Type      |     Cause     |             Length            |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Ver  |  Opt  |                    Status                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Argus Identifier                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                        Sequence Number                        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                             data                              |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
*/

/*
    0                   1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |               |                  Status                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+

                          Argus Status Record
          Note that one tick mark represents one bit position.
*/



/* Argus Record Type */

#define ARGUS_V2_MAR		0x80    /* Normal Argus Management Record */
#define ARGUS_V2_INDEX   	0xA0    /* New Argus Index Record */
#define ARGUS_V2_EVENT		0xC0    /* New Argus Event/Message Record */
#define ARGUS_V2_CISCO_NETFLOW	0x10    /* Argus CISCO Netflow Support */
#define ARGUS_V2_WRITESTRUCT  	0x20    /* Argus 1.x Write Struct Conversion */
#define ARGUS_V2_RMON		0x40    /* New RMON style FAR Record Format */

#define ARGUS_V2_FAR 		0x01    /* Normal Argus Data Record */
#define ARGUS_V2_DATASUP		0x02    /* New Supplemental Argus Data Record */
#define ARGUS_V2_ARCHIVE		0x03    /* New Archival Argus Data Record */


/* Argus Record Cause */

#define ARGUS_V2_START		0x01   /* INIT */
#define ARGUS_V2_STATUS		0x04   /* STATUS */
#define ARGUS_V2_STOP		0x08   /* CLOSE */
#define ARGUS_V2_SHUTDOWN	0x10   /* Administrative shutdown */
#define ARGUS_V2_TIMEOUT		0x20   /* TIMEOUT */
#define ARGUS_V2_ERROR		0x40   /* MAJOR PROBLEM */

/* Record Version (Ver) */

#define ARGUS_V2_VERSION		0x20000000    /* Version 2 */

/* Record Options (Opt)*/

#define ARGUS_V2_ANON		0x01000000
#define ARGUS_V2_MERGED		0x02000000
#define ARGUS_V2_TOPN		0x04000000
#define ARGUS_V2_MATRIX		0x08000000


/* Argus MAR Record Status */

#define ARGUS_V2_SASL_AUTHENTICATE	0x00001000



/*
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |  Status Conditions    | Proto |        EtherType Field        |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                     Argus Record Status Field
          Note that one tick mark represents one bit position.
*/


#define ARGUS_V2_ETHERTYPE		0x00FFFF

#define ARGUS_V2_MPLS		0x00010000
#define ARGUS_V2_VLAN		0x00020000
#define ARGUS_V2_PPPoE 		0x00040000
#define ARGUS_V2_SNAPENCAPS	0x00080000

#define ARGUS_V2_CONNECTED	0x00100000
#define ARGUS_V2_ID_IS_IPADDR	0x00800000


#define ARGUS_V2_SRC_VLAN		0x0001
#define ARGUS_V2_DST_VLAN		0x0002

#define ARGUS_V2_SRC_MPLS		0x0001
#define ARGUS_V2_DST_MPLS		0x0002

#define ARGUS_V2_SRC_CHANGED	0x0010
#define ARGUS_V2_DST_CHANGED	0x0020


/* Argus Error Messages go into the status field when
   the Record Cause is ARGUS_V2_ERROR.
*/

#define ARGUS_V2_ACCESSDENIED	0x000010
#define ARGUS_V2_MAXLISTENEXCD	0x000020


/*  Link Types  */

#define ARGUS_V2_ETHERNET			0x01000000
#define ARGUS_V2_ATM			0x02000000
#define ARGUS_V2_FDDI			0x03000000
#define ARGUS_V2_TOKENRING			0x04000000
#define ARGUS_V2_SLIP			0x05000000
#define ARGUS_V2_PPP			0x06000000
#define ARGUS_V2_ESP			0x07000000
#define ARGUS_V2_RAW			0x08000000
#define ARGUS_V2_NULL			0x09000000


#define ARGUS_V2_SEND_FRAG_COMPLETE	0x10000000

/*
                  0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 
                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
                 |                               |
                 +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
 
                       Argus FAR Status Field
        Note that one tick mark represents one bit position.
*/


/* ICMP Mapped Indicator */
/* argus_far.status indicator */

#define ARGUS_V2_ICMP_MAPPED		0x0007
#define ARGUS_V2_ICMPUNREACH_MAPPED	0x0001
#define ARGUS_V2_ICMPREDIREC_MAPPED	0x0002
#define ARGUS_V2_ICMPTIMXCED_MAPPED	0x0004

#define ARGUS_V2_FRAGMENTS		0x0008
#define ARGUS_V2_FRAGOVERLAP		0x0010

#define ARGUS_V2_TOS_MODIFIED		0x0020
#define ARGUS_V2_TTL_MODIFIED		0x0040
#define ARGUS_V2_OPTION_MODIFIED	0x0080

/* IP Option Indicators */

#define ARGUS_V2_IPOPTIONS		0x3F00
#define ARGUS_V2_TIMESTAMP		0x0100
#define ARGUS_V2_SECURITY		0x0200
#define ARGUS_V2_LSRCROUTE		0x0400
#define ARGUS_V2_RECORDROUTE		0x0800
#define ARGUS_V2_SSRCROUTE		0x1000
#define ARGUS_V2_SATNETID		0x2000
 
#define ARGUS_V2_MULTIADDR		0x4000

 
/* Type:  DSR    Cause:  ANY  */
 
#define ARGUS_V2_DSR_TYPES                 20
#define ARGUS_V2_DSR_MAC                   0
#define ARGUS_V2_DSR_TCP                   1
#define ARGUS_V2_DSR_ICMP                  2
#define ARGUS_V2_DSR_RTP                   3
#define ARGUS_V2_DSR_RTCP                  4
#define ARGUS_V2_DSR_IGMP                  5
#define ARGUS_V2_DSR_ARP                   6
#define ARGUS_V2_DSR_FRG                   7
#define ARGUS_V2_DSR_ESP                   8
#define ARGUS_V2_DSR_MPLS                  9
#define ARGUS_V2_DSR_VLAN                  10
#define ARGUS_V2_DSR_PPPOE                 11
#define ARGUS_V2_DSR_AGR                   12
#define ARGUS_V2_DSR_TIME                  13
#define ARGUS_V2_DSR_SRCUSERDATA           14
#define ARGUS_V2_DSR_DSTUSERDATA           15
#define ARGUS_V2_DSR_SRCTIME               16
#define ARGUS_V2_DSR_DSTTIME               17
 
#define ARGUS_V2_MAC_DSR                   0x08
 
#define ARGUS_V2_TCP_DSR                   0x11
#define ARGUS_V2_ICMP_DSR                  0x12
#define ARGUS_V2_RTP_DSR                   0x14
#define ARGUS_V2_RTCP_DSR                  0x15
#define ARGUS_V2_IGMP_DSR                  0x18
 
#define ARGUS_V2_ARP_DSR                   0x20
#define ARGUS_V2_FRG_DSR                   0x21
#define ARGUS_V2_ESP_DSR                   0x22
 
#define ARGUS_V2_MPLS_DSR                  0x28
#define ARGUS_V2_VLAN_DSR                  0x2a
#define ARGUS_V2_PPPOE_DSR                 0x2b
 
#define ARGUS_V2_AGR_DSR                   0x30
 
#define ARGUS_V2_TIME_DSR                  0x40
#define ARGUS_V2_SRCUSRDATA_DSR            0x42
#define ARGUS_V2_DSTUSRDATA_DSR            0x43
 
#define ARGUS_V2_SRC_TIME_DSR              0x01
#define ARGUS_V2_DST_TIME_DSR              0x02


/* IP Sec AH Header Status Bits */

#define ARGUS_V2_AH_HDR                  0x00000010
#define ARGUS_V2_AH_REPLAY               0x00000008


/* RTP State Constants and Reporting Values */

#define ARGUS_V2_RTP_SRCSILENCE		0x01
#define ARGUS_V2_RTP_DSTSILENCE		0x02

#define ARGUS_V2_RTCP_TAG			0x2000
#define ARGUS_V2_RTP_TAG			0x4000

#define ARGUS_V2_HTTP_FLOWTAG		0x01
#define ARGUS_V2_RTCP_FLOWTAG		0x10
#define ARGUS_V2_RTP_FLOWTAG		0x20
#define ARGUS_V2_FRAG_FLOWTAG		0xCB


/* TCP State Constants and Reporting Values */

#define ARGUS_V2_SAW_SYN			0x00000001
#define ARGUS_V2_SAW_SYN_SENT		0x00000002
#define ARGUS_V2_CON_ESTABLISHED		0x00000004
#define ARGUS_V2_FIN			0x00000008
#define ARGUS_V2_FIN_ACK			0x00000010

#define ARGUS_V2_NORMAL_CLOSE		0x00000020
#define ARGUS_V2_CLOSE_WAITING		0x00000040

#define ARGUS_V2_PKTS_RETRANS		0x00000300  /* SRC_PKTS_RETRANS | DST_PK*/
#define ARGUS_V2_SRC_PKTS_RETRANS		0x00000100
#define ARGUS_V2_DST_PKTS_RETRANS		0x00000200

#define ARGUS_V2_WINDOW_SHUT             	0x00000C00  /* SRC_WINDOW_SHUT | DST_WIN*/
#define ARGUS_V2_SRC_WINDOW_SHUT         	0x00000400
#define ARGUS_V2_DST_WINDOW_SHUT         	0x00000800
#define ARGUS_V2_RESET                   	0x00003000  /* SRC_RESET | DST_RESET */
#define ARGUS_V2_SRC_RESET               	0x00001000
#define ARGUS_V2_DST_RESET               	0x00002000
#define ARGUS_V2_ECN_CONGESTED           	0x0000C000  /* SRC_CONGESTED | DST_CONGESTED */
#define ARGUS_V2_SRC_CONGESTED           	0x00004000
#define ARGUS_V2_DST_CONGESTED           	0x00008000


#define ARGUS_V2_TCP_OUTOFORDER    	0x00030000
#define ARGUS_V2_SRC_OUTOFORDER    	0x00010000
#define ARGUS_V2_DST_OUTOFORDER    	0x00020000

#define ARGUS_V2_TCP_OPTIONS	0xFFF00000
#define ARGUS_V2_TCP_MAXSEG	0x00100000
#define ARGUS_V2_TCP_WSCALE	0x00200000
#define ARGUS_V2_TCP_SACKOK	0x00400000
#define ARGUS_V2_TCP_SACK		0x00800000
#define ARGUS_V2_TCP_ECHO		0x01000000
#define ARGUS_V2_TCP_ECHOREPLY	0x02000000
#define ARGUS_V2_TCP_TIMESTAMP	0x04000000
#define ARGUS_V2_TCP_CC		0x08000000
#define ARGUS_V2_TCP_CCNEW		0x10000000
#define ARGUS_V2_TCP_CCECHO	0x20000000

#define ARGUS_V2_TCP_SRC_ECN	0x40000000
#define ARGUS_V2_TCP_DST_ECN	0x80000000


/* Fragment State Constants and Reporting Values */

#define ARGUS_V2_FRAG_INIT			0x0001
#define ARGUS_V2_FRAG_OUT_OF_ORDER		0x0002
#define ARGUS_V2_TCPFRAGOFFSETERROR	0x0004

/* User Data Status Values */
 
#define ARGUS_V2_FAR_DSR_STATUS            0x00000001
#define ARGUS_V2_MAC_DSR_STATUS            0x00000010
#define ARGUS_V2_VLAN_DSR_STATUS           0x00000020
#define ARGUS_V2_MPLS_DSR_STATUS           0x00000040
#define ARGUS_V2_PPPOE_DSR_STATUS          0x00000080
 
#define ARGUS_V2_TCP_DSR_STATUS            0x00000100
#define ARGUS_V2_ICMP_DSR_STATUS           0x00000200
#define ARGUS_V2_RTP_DSR_STATUS            0x00000400
#define ARGUS_V2_RTCP_DSR_STATUS           0x00000800
#define ARGUS_V2_IGMP_DSR_STATUS           0x00001000
#define ARGUS_V2_ARP_DSR_STATUS            0x00002000
#define ARGUS_V2_FRG_DSR_STATUS            0x00004000
 
#define ARGUS_V2_TIME_DSR_STATUS           0x00100000
#define ARGUS_V2_SRCUSRDATA_DSR_STATUS     0x00200000
#define ARGUS_V2_DSTUSRDATA_DSR_STATUS     0x00400000
#define ARGUS_V2_ESP_DSR_STATUS            0x00800000
 
#define ARGUS_V2_SRCTIME_DSR_STATUS        0x01000000
#define ARGUS_V2_DSTTIME_DSR_STATUS        0x02000000
 
#define ARGUS_V2_AGR_DSR_STATUS            0x80000000

#define ARGUS_V2_MAX_DSR_INDEX             32

#define ARGUS_V2_FAR_DSR_INDEX             0
 
#define ARGUS_V2_MAC_DSR_INDEX             4
#define ARGUS_V2_VLAN_DSR_INDEX            5
#define ARGUS_V2_MPLS_DSR_INDEX            6
#define ARGUS_V2_PPPOE_DSR_INDEX           7
#define ARGUS_V2_TCP_DSR_INDEX             8
#define ARGUS_V2_ICMP_DSR_INDEX            9
#define ARGUS_V2_RTP_DSR_INDEX             10
#define ARGUS_V2_RTCP_DSR_INDEX            11
#define ARGUS_V2_IGMP_DSR_INDEX            12
#define ARGUS_V2_ARP_DSR_INDEX             13
#define ARGUS_V2_FRG_DSR_INDEX             14

#define ARGUS_V2_TIME_DSR_INDEX		20
#define ARGUS_V2_SRCUSRDATA_DSR_INDEX	21
#define ARGUS_V2_DSTUSRDATA_DSR_INDEX	22
#define ARGUS_V2_ESP_DSR_INDEX		23
#define ARGUS_V2_SRCTIME_DSR_INDEX		24
#define ARGUS_V2_DSTTIME_DSR_INDEX		25

#define ARGUS_V2_AGR_DSR_INDEX		31

#define ARGUS_V2_AGR_USECACTTIME		0x0010
#define ARGUS_V2_AGR_USECIDLETIME		0x0020

#define ARGUS_V2_AGR_MSECACTTIME		0x0040
#define ARGUS_V2_AGR_MSECIDLETIME		0x0080

#define ARGUS_V2_AGR_NORMALIZED  		0x0100

#define IANA_IFT_OTHER				1
#define IANA_IFT_REGULAR1822			2
#define IANA_IFT_HDH1822			3
#define IANA_IFT_DDNX25				4
#define IANA_IFT_RFC877X25			5
#define IANA_IFT_ETHERNETCSMACD			6
#define IANA_IFT_ISO88023CSMACD			7
#define IANA_IFT_ISO88024TOKENBUS		8
#define IANA_IFT_ISO88025TOKENRING		9
#define IANA_IFT_ISO88026MAN			10
#define IANA_IFT_STARLAN			11
#define IANA_IFT_PROTEON10MBIT			12
#define IANA_IFT_PROTEON80MBIT			13
#define IANA_IFT_HYPERCHANNEL			14
#define IANA_IFT_FDDI				15
#define IANA_IFT_LAPB				16
#define IANA_IFT_SDLC				17
#define IANA_IFT_DS1				18
#define IANA_IFT_E1				19
#define IANA_IFT_BASICISDN			20
#define IANA_IFT_PRIMARYISDN			21
#define IANA_IFT_PROPPOINTTOPOINTSERIAL		22
#define IANA_IFT_PPP				23
#define IANA_IFT_SOFTWARELOOPBACK		24
#define IANA_IFT_EON				25
#define IANA_IFT_ETHERNET3MBIT			26
#define IANA_IFT_NSIP				27
#define IANA_IFT_SLIP				28
#define IANA_IFT_ULTRA				29
#define IANA_IFT_DS3				30
#define IANA_IFT_SIP				31
#define IANA_IFT_FRAMERELAY			32
#define IANA_IFT_RS232				33
#define IANA_IFT_PARA				34
#define IANA_IFT_ARCNET				35
#define IANA_IFT_ARCNETPLUS			36
#define IANA_IFT_ATM				37
#define IANA_IFT_MIOX25				38
#define IANA_IFT_SONET				39
#define IANA_IFT_X25PLE				40
#define IANA_IFT_ISO88022LLC			41
#define IANA_IFT_LOCALTALK			42
#define IANA_IFT_SMDSDXI			43
#define IANA_IFT_FRAMERELAYSERVICE		44
#define IANA_IFT_V35				45
#define IANA_IFT_HSSI				46
#define IANA_IFT_HIPPI				47
#define IANA_IFT_MODEM				48
#define IANA_IFT_AAL5				49
#define IANA_IFT_SONETPATH			50
#define IANA_IFT_SONETVT			51
#define IANA_IFT_SMDSICIP			52
#define IANA_IFT_PROPVIRTUAL			53
#define IANA_IFT_PROPMULTIPLEXOR		54
#define IANA_IFT_IEEE80212			55
#define IANA_IFT_FIBRECHANNEL			56
#define IANA_IFT_HIPPIINTERFACE			57
#define IANA_IFT_FRAMERELAYINTERCONNECT		58
#define IANA_IFT_AFLANE8023			59
#define IANA_IFT_AFLANE8025			60
#define IANA_IFT_CCTEMUL			61
#define IANA_IFT_FASTETHER			62
#define IANA_IFT_ISDN				63
#define IANA_IFT_V11				64
#define IANA_IFT_V36				65
#define IANA_IFT_G703AT64K			66
#define IANA_IFT_G703AT2MB			67
#define IANA_IFT_QLLC				68
#define IANA_IFT_FASTETHERFX			69
#define IANA_IFT_CHANNEL			70
#define IANA_IFT_IEEE80211			71
#define IANA_IFT_IBM370PARCHAN			72
#define IANA_IFT_ESCON				73
#define IANA_IFT_DLSW				74
#define IANA_IFT_ISDNS				75
#define IANA_IFT_ISDNU				76
#define IANA_IFT_LAPD				77
#define IANA_IFT_IPSWITCH			78
#define IANA_IFT_RSRB				79
#define IANA_IFT_ATMLOGICAL			80
#define IANA_IFT_DS0				81
#define IANA_IFT_DS0BUNDLE			82
#define IANA_IFT_BSC				83
#define IANA_IFT_ASYNC				84
#define IANA_IFT_CNR				85
#define IANA_IFT_ISO88025DTR			86
#define IANA_IFT_EPLRS				87
#define IANA_IFT_ARAP				88
#define IANA_IFT_PROPCNLS			89
#define IANA_IFT_HOSTPAD			90
#define IANA_IFT_TERMPAD			91
#define IANA_IFT_FRAMERELAYMPI			92
#define IANA_IFT_X213				93
#define IANA_IFT_ADSL				94
#define IANA_IFT_RADSL				95
#define IANA_IFT_SDSL				96
#define IANA_IFT_VDSL				97
#define IANA_IFT_ISO88025CRFPINT		98
#define IANA_IFT_MYRINET			99
#define IANA_IFT_VOICEEM			100
#define IANA_IFT_VOICEFXO			101
#define IANA_IFT_VOICEFXS			102
#define IANA_IFT_VOICEENCAP			103
#define IANA_IFT_VOICEOVERIP			104
#define IANA_IFT_ATMDXI				105
#define IANA_IFT_ATMFUNI			106
#define IANA_IFT_ATMIMA				107
#define IANA_IFT_PPPMULTILINKBUNDLE		108
#define IANA_IFT_IPOVERCDLC			109
#define IANA_IFT_IPOVERCLAW			110
#define IANA_IFT_STACKTOSTACK			111
#define IANA_IFT_VIRTUALIPADDRESS		112
#define IANA_IFT_MPC				113
#define IANA_IFT_IPOVERATM			114
#define IANA_IFT_ISO88025FIBER			115
#define IANA_IFT_TDLC				116
#define IANA_IFT_GIGABITETHERNET		117
#define IANA_IFT_HDLC				118
#define IANA_IFT_LAPF				119
#define IANA_IFT_V37				120
#define IANA_IFT_X25MLP				121
#define IANA_IFT_X25HUNTGROUP			122
#define IANA_IFT_TRASNPHDLC			123
#define IANA_IFT_INTERLEAVE			124
#define IANA_IFT_FAST				125
#define IANA_IFT_IP				126
#define IANA_IFT_DOCSCABLEMACLAYER		127
#define IANA_IFT_DOCSCABLEDOWNSTREAM		128
#define IANA_IFT_DOCSCABLEUPSTREAM		129
#define IANA_IFT_A12MPPSWITCH			130
#define IANA_IFT_TUNNEL				131
#define IANA_IFT_COFFEE				132
#define IANA_IFT_CES				133
#define IANA_IFT_ATMSUBINTERFACE		134
#define IANA_IFT_L2VLAN				135
#define IANA_IFT_L3IPVLAN			136
#define IANA_IFT_L3IPXVLAN			137
#define IANA_IFT_DIGITALPOWERLINE		138
#define IANA_IFT_MEDIAMAILOVERIP		139
#define IANA_IFT_DTM				140
#define IANA_IFT_DCN				141
#define IANA_IFT_IPFORWARD			142
#define IANA_IFT_MSDSL				143
#define IANA_IFT_IEEE1394			144
#define IANA_IFT_IF_GSN				145
#define IANA_IFT_DVBRCCMACLAYER			146
#define IANA_IFT_DVBRCCDOWNSTREAM		147
#define IANA_IFT_DVBRCCUPSTREAM			148
#define IANA_IFT_ATMVIRTUAL			149
#define IANA_IFT_MPLSTUNNEL			150
#define IANA_IFT_SRP				151
#define IANA_IFT_VOICEOVERATM			152
#define IANA_IFT_VOICEOVERFRAMERELAY		153
#define IANA_IFT_IDSL				154
#define IANA_IFT_COMPOSITELINK			155
#define IANA_IFT_SS7SIGLINK			156
#define IANA_IFT_PROPWIRELESSP2P		157
#define IANA_IFT_FRFORWARD			158
#define IANA_IFT_RFC1483			159
#define IANA_IFT_USB				160
#define IANA_IFT_IEEE8023ADLAG			161
#define IANA_IFT_BGPPOLICYACCOUNTING		162
#define IANA_IFT_FRF16MFRBUNDLE			163
#define IANA_IFT_H323GATEKEEPER			164
#define IANA_IFT_H323PROXY			165
#define IANA_IFT_MPLS				166
#define IANA_IFT_MFSIGLINK			167
#define IANA_IFT_HDSL2				168
#define IANA_IFT_SHDSL				169
#define IANA_IFT_DS1FDL				170
#define IANA_IFT_POS				171
#define IANA_IFT_DVBASIIN			172
#define IANA_IFT_DVBASIOUT			173
#define IANA_IFT_PLC				174
#define IANA_IFT_NFAS				175
#define IANA_IFT_TR008				176
#define IANA_IFT_GR303RDT			177
#define IANA_IFT_GR303IDT			178
#define IANA_IFT_ISUP				179
#define IANA_IFT_PROPDOCSWIRELESSMACLAYER	180
#define IANA_IFT_PROPDOCSWIRELESSDOWNSTREAM	181
#define IANA_IFT_PROPDOCSWIRELESSUPSTREAM	182
#define IANA_IFT_HIPERLAN2			183
#define IANA_IFT_PROPBWAP2MP			184
#define IANA_IFT_SONETOVERHEADCHANNEL		185
#define IANA_IFT_DIGITALWRAPPEROVERHEADCHANNEL	186
#define IANA_IFT_AAL2				187
#define IANA_IFT_RADIOMAC			188
#define IANA_IFT_ATMRADIO			189
#define IANA_IFT_IMT				190
#define IANA_IFT_MVL				191
#define IANA_IFT_REACHDSL			192
#define IANA_IFT_FRDLCIENDPT			193
#define IANA_IFT_ATMVCIENDPT			194
#define IANA_IFT_OPTICALCHANNEL			195
#define IANA_IFT_OPTICALTRANSPORT		196
#define IANA_IFT_PROPATM			197
#define IANA_IFT_VOICEOVERCABLE			198
#define IANA_IFT_INFINIBAND			199
#define IANA_IFT_TELINK				200
#define IANA_IFT_Q2931				201
#define IANA_IFT_VIRTUALTG			202
#define IANA_IFT_SIPTG				203
#define IANA_IFT_SIPSIG				204
#define IANA_IFT_DOCSCABLEUPSTREAMCHANNEL	205
#define IANA_IFT_ECONET				206
#define IANA_IFT_PON155				207
#define IANA_IFT_PON622				208
#define IANA_IFT_BRIDGE				209
#define IANA_IFT_LINEGROUP			210
#define IANA_IFT_VOICEEMFGD			211
#define IANA_IFT_VOICEFGDEANA			212
#define IANA_IFT_VOICEDID			213
#define IANA_IFT_MPEGTRANSPORT			214
#define IANA_IFT_SIXTOFOUR			215
#define IANA_IFT_GTP				216
#define IANA_IFT_PDNETHERLOOP1			217
#define IANA_IFT_PDNETHERLOOP2			218
#define IANA_IFT_OPTICALCHANNELGROUP		219

#ifdef __cplusplus
}
#endif
#endif/*Argus_def_h*/

