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
 * $Id: //depot/argus/argus/include/argus_ethernames.h#7 $
 * $DateTime: 2015/04/06 10:38:44 $
 * $Change: 2973 $
 */


/* prepared from IANA Ether Types definitions Wed Aug 16 11:45:21 EDT 2000 */


#ifndef  Argus_Ethernames_h
#define Argus_Ethernames_h

#ifdef __cplusplus
extern "C" {
#endif

struct ArgusEtherTypeStruct {
   char *range, *tag, *description;
};

#ifdef  ArgusAddrtoName

struct ArgusEtherTypeStruct argus_ethertype_names [] = {
/* { "0000-1500", "802.3", "IEEE802.3 Length Field" },  */

/* Argus Pseudo Ethertypes */
   { "0",    "llc", "Argus Pseudo LLC Ethertype"},
   { "0100", "ipx", "Argus Pseudo Ethertype"},

   { "0129", "clns", "Spanning Tree Protocol" },
   { "0130", "esis", "Spanning Tree Protocol" },
   { "0131", "isis", "Intermediate System IS Protocol" },
   { "0132", "nullns", "Spanning Tree Protocol" },

   { "0257", "exp", "Experimental" }, 
   { "0258", "drip", "Cisco SNAP ethertype for DRiP" }, 
   { "0259-511", "exp", "Experimental" }, 
   { "0512", "pup", "XEROX PUP (see 0A00)" }, 
   { "0513", "pupat", "PUP Addr Trans (see 0A01)" }, 

   { "1024", "nix", "Nixdorf" }, 
   { "1536", "idp", "XEROX NS IDP" }, 
   { "1632", "dlog", "DLOG" }, 
   { "1633", "dlog", "DLOG" }, 
   { "2048", "ip", "Internet IP (IPv4)" }, 
   { "2049", "x75", "X.75 Internet" }, 
   { "2050", "nbs", "NBS Internet" }, 
   { "2051", "ecma", "ECMA Internet" }, 
   { "2052", "chaos", "Chaosnet" }, 
   { "2053", "x25", "X.25 Level 3" }, 
   { "2054", "arp", "ARP" }, 
   { "2055", "xnscp", "XNS Compatability" }, 
   { "2056", "frarp", "Frame Relay ARP" }, 
   { "2076", "symbl", "Symbolics Private" }, 
   { "2184-2186", "xyplx", "Xyplex" }, 
   { "2304", "ubdeb", "Ungermann-Bass net debugr" }, 
   { "2560", "pup.3", "Xerox IEEE802.3 PUP" }, 
   { "2561", "pupat", "PUP Addr Trans" }, 
   { "2989", "vines", "Banyan VINES" }, 
   { "2990", "vinlb", "VINES Loopback" }, 
   { "2991", "vinec", "VINES Echo" }, 
   { "4096", "brktn", "Berkeley Trailer nego" }, 
   { "4097-4111", "brkte", "Berkeley Trailer encap/IP" }, 
   { "5632", "valid", "Valid Systems" }, 

   { "6532", "train", "MS Train" }, 

   { "8192", "cdp", "Cisco Discovery Protocol" }, 
   { "8193", "cgmp", "Cisco Group Management Protocol" }, 
   { "8195", "vtp", "Cisco VLAN Trunk Protocol" }, 

   { "9298", "cent", "Intel Centrino" }, 

   { "15367", "nbp", "3Com NBP Datagram" }, 

   { "16962", "pcs", "PCS Basic Block Protocol" }, 
   { "21000", "bbn", "BBN Simnet" }, 
   { "24576", "decun", "DEC Unassigned (Exp.)" }, 
   { "24577", "decdl", "DEC MOP Dump/Load" }, 
   { "24578", "decrc", "DEC MOP Remote Console" }, 
   { "24579", "decro", "DEC DECNET Phase IV Route" }, 
   { "24580", "lat", "DEC LAT" }, 
   { "24581", "decdp", "DEC Diagnostic Protocol" }, 
   { "24582", "deccp", "DEC Customer Protocol" }, 
   { "24583", "lavc", "DEC LAVC,  SCA" }, 
   { "24584-24585", "decun", "DEC Unassigned" }, 
   { "24586-24596", "3com", "3Com Corporation" }, 
   { "25944", "trans", "Trans Ether Bridging" }, 
   { "25945", "rawfr", "Raw Frame Relay" }, 
   { "28672", "dbdwn", "Ungermann-Bass download" }, 
   { "28674", "ubdia", "Ungermann-Bass dia/loop" }, 
   { "28704-28713", "lrt", "LRT" }, 
   { "28720", "prote", "Proteon" }, 
   { "28724", "cable", "Cabletron" }, 
   { "32771", "cronv", "Cronus VLN" }, 
   { "32772", "crond", "Cronus Direct" }, 
   { "32773", "hppro", "HP Probe" }, 
   { "32774", "nesta", "Nestar" }, 
   { "32776", "att", "AT&T" }, 
   { "32784", "excel", "Excelan" }, 
   { "32787", "sgid", "SGI diagnostics" }, 
   { "32788", "sging", "SGI network games" }, 
   { "32789", "sgres", "SGI reserved" }, 
   { "32790", "sgibs", "SGI bounce server" }, 
   { "32793", "apld", "Apollo Domain" }, 
   { "32815", "tym", "Tymshare" }, 
   { "32816", "tigan", "Tigan,  Inc." }, 
   { "32821", "rarp", "Reverse ARP" }, 
   { "32822", "aeon", "Aeonic Systems" }, 
   { "32824", "declb", "DEC LANBridge" }, 
   { "32825-32828", "decun", "DEC Unassigned" }, 
   { "32829", "decee", "DEC Ethernet Encryption" }, 
   { "32830", "decun", "DEC Unassigned" }, 
   { "32831", "dectm", "DEC LAN Traffic Monitor" }, 
   { "32832-32834", "decun", "DEC Unassigned" }, 
   { "32836", "plan", "Planning Research Corp." }, 
   { "32838", "att", "AT&T" }, 
   { "32839", "att", "AT&T" }, 
   { "32841", "expd", "ExperData" }, 
   { "32859", "Vexp", "Stanford V Kernel exp." }, 
   { "32860", "Vprod", "Stanford V Kernel prod." }, 
   { "32861", "es", "Evans & Sutherland" }, 
   { "32864", "ltlm", "Little Machines" }, 
   { "32866", "count", "Counterpoint Computers" }, 
   { "32869", "um", "Univ. of Mass. @ Amherst" }, 
   { "32870", "um", "Univ. of Mass. @ Amherst" }, 
   { "32871", "veeco", "Veeco Integrated Auto." }, 
   { "32872", "gd", "General Dynamics" }, 
   { "32873", "att", "AT&T" }, 
   { "32874", "autop", "Autophon" }, 
   { "32876", "comd", "ComDesign" }, 
   { "32877", "comgr", "Computgraphic Corp." }, 
   { "32878-32887", "land", "Landmark Graphics Corp." }, 
   { "32890", "matra", "Matra" }, 
   { "32891", "dansk", "Dansk Data Elektronik" }, 
   { "32892", "merit", "Merit Internodal" }, 
   { "32893-32895", "vtlnk", "Vitalink Communications" }, 
   { "32896", "vtlnk", "Vitalink TransLAN III" }, 
   { "32897-32899", "count", "Counterpoint Computers" }, 
   { "32923", "atalk", "Appletalk" }, 
   { "32924-32926", "data", "Datability" }, 
   { "32927", "spidr", "Spider Systems Ltd." }, 
   { "32931", "nix", "Nixdorf Computers" }, 
   { "32932-32947", "siem", "Siemens Gammasonics Inc." }, 
   { "32960-32963", "dcaex", "DCA Data Exchange Cluster" }, 
   { "32964", "ban", "Banyan Systems" }, 
   { "32965", "ban", "Banyan Systems" }, 
   { "32966", "pacer", "Pacer Software" }, 
   { "32967", "appli", "Applitek Corporation" }, 
   { "32968-32972", "intrg", "Intergraph Corporation" }, 
   { "32973-32974", "haris", "Harris Corporation" }, 
   { "32975-32978", "taylr", "Taylor Instrument" }, 
   { "32979-32980", "rose", "Rosemount Corporation" }, 
   { "32981", "sna", "IBM SNA Service on Ether" }, 
   { "32989", "varin", "Varian Associates" }, 
   { "32990-32991", "trfs", "Integrated Solutions TRFS" }, 
   { "32992-32995", "allen", "Allen-Bradley" }, 
   { "32996-33008", "data", "Datability" }, 
   { "33010", "retix", "Retix" }, 
   { "33011", "aarp", "AppleTalk AARP (Kinetics)" }, 
   { "33012-33013", "kinet", "Kinetics" }, 
   { "33015", "aplo", "Apollo Computer" }, 
   { "33023", "wcp", "Wellfleet Compression Protocol" }, 
   { "33024-33027", "well", "Wellfleet Communications" }, 
   { "33031-33033", "symbl", "Symbolics Private" }, 
   { "33072", "hayes", "Hayes Microcomputers" }, 
   { "33073", "vglab", "VG Laboratory Systems" }, 
   { "33074-33078", "brdg", "Bridge Communications" }, 
   { "33079-33080", "ipx/spx", "Novell,  Inc." }, 
   { "33081-33085", "kti", "KTI" }, 
   { "33096", "logic", "Logicraft" }, 
   { "33097", "ncd", "Network Computing Devices" }, 
   { "33098", "alpha", "Alpha Micro" }, 
   { "33100", "snmp", "SNMP" }, 
   { "33101", "biin", "BIIN" }, 
   { "33104", "biin", "BIIN" }, 
   { "33103", "elite", "Technically Elite Concept" }, 
   { "33104", "ratnl", "Rational Corp" }, 
   { "33105-33107", "qual", "Qualcomm" }, 
   { "33108-33110", "cprot", "Computer Protocol Pty Ltd" }, 
   { "33124-33126", "crd", "Charles River Data System" }, 
   { "33149", "xtp", "XTP" }, 
   { "33150", "sgitw", "SGI/Time Warner prop." }, 
   { "33152", "hippi", "HIPPI-FP encapsulation" }, 
   { "33153", "stp", "STP,  HIPPI-ST" }, 
   { "33154", "h6400", "Reserved for HIPPI-6400" }, 
   { "33155", "h6400", "Reserved for HIPPI-6400" }, 
   { "33156-33164", "sgi", "Silicon Graphics prop." }, 
   { "33165", "mot", "Motorola Computer" }, 
   { "33178-33187", "qual", "Qualcomm" }, 
   { "33188", "arai", "ARAI Bunkichi" }, 
   { "33189-33198", "rad", "RAD Network Devices" }, 
   { "33207-33209", "xyplx", "Xyplex" }, 
   { "33228-33237", "apri", "Apricot Computers" }, 
   { "33238-33245", "arti", "Artisoft" }, 
   { "33254-33263", "poly", "Polygon" }, 
   { "33264-33266", "comst", "Comsat Labs" }, 
   { "33267-33269", "saic", "SAIC" }, 
   { "33270-33272", "vg", "VG Analytical" }, 
   { "33277", "ismp", "Cabeltron Interswitch Message Protocol" }, 
   { "33283-33285", "quant", "Quantum Software" }, 
   { "33313-33314", "ascom", "Ascom Banking Systems" }, 
   { "33342-33344", "aes", "Advanced Encryption System" }, 
   { "33407-33410", "athen", "Athena Programming" }, 
   { "33379-33386", "crd", "Charles River Data System" }, 
   { "33434-33435", "iiit", "Inst Ind Info Tech" }, 
   { "33436-33451", "tarus", "Taurus Controls" }, 
   { "33452-34451", "wrq", "Walker Richer & Quinn" }, 
   { "34452-34461", "ideac", "Idea Courier" }, 
   { "34462-34465", "cnt", "Computer Network Tech" }, 
   { "34467-34476", "gtway", "Gateway Communications" }, 
   { "34523", "sectr", "SECTRA" }, 
   { "34526", "delta", "Delta Controls" }, 
   { "34525", "ipv6", "IPv6" }, 
   { "34527", "atom", "ATOMIC" }, 
   { "34528-34543", "lgp", "Landis & Gyr Powers" }, 
   { "34560-34576", "mot", "Motorola" }, 
   { "34605", "cwl", "Cisco Wireless (Aironet)" }, 
   { "34667", "compr", "TCP/IP Compression" }, 
   { "34668", "ipas", "IP Autonomous Systems" }, 
   { "34669", "sdata", "Secure Data" }, 
   { "34824", "mac", "MAC Control" }, 
   { "34825", "slow", "SLOW Protocols" }, 
   { "34827", "ppp", "PPP" }, 
   { "34887", "mplsu", "MPLS Unicast" }, 
   { "34888", "mplsm", "MPLS Multicast" }, 
   { "34915", "pppoe", "PPP Over Ethernet" }, 
   { "34916", "pppoe", "PPP Over Ethernet" }, 
   { "34925", "ans", "Intel ANS (NIC teaming)" }, 
   { "34927", "nlb", "MS Network Load Balancing" }, 
   { "34945", "cdma", "CDMA2000(R) Based Wireless" }, 
   { "34958", "eapol", "802.1x Authentication" }, 
   { "34962", "prof", "PROFInet protocol" }, 
   { "34970", "hscsi", "HyperSCSI protocol" }, 
   { "34971", "csm", "Mindseed Technologies" }, 
   { "34978", "aoe", "ATA Over Ethernet" }, 
   { "34990", "brd", "MS Boardwalk" }, 
   { "34999", "oui", "IEEE 802a OUI Extended" }, 
   { "35000-35002", "gse", "IEC 61850" }, 
   { "35015", "rsn", "802.11i Pre-Authentication" }, 
   { "35018", "tipc", "Transparent InterProcess Communication" }, 
   { "35020", "lldp", "IEEE 802.1 Link Layer Discovery Protocol" }, 
   { "35026", "3gpp", "CDMA2000(R) Access Network" }, 
   { "35478-35479", "invis", "Invisible Software" }, 
   { "36864", "loop", "Loopback" }, 
   { "36865", "xnssm", "3Com(Bridge) XNS Sys Mgmt" }, 
   { "36866", "3coms", "3Com(Bridge) TCP-IP Sys" }, 
   { "36867", "3coml", "3Com(Bridge) loop detect" }, 
   { "36897", "rtmac", "Real-Time Media Access Control" }, 
   { "36898", "rtcfg", "Real-Time Configuration Protocol" }, 
   { "48879", "nrludt", "NRL (Eric Kinzie) UDT Protocol" }, 
   { "64764", "fcft", "Cisco MDS Transport" }, 
   { "65280-65295", "ramo", "ISC Bunker Ramo" }, 
   { "65535", "*",  "Merged" }, 
   { (char *) 0, (char *) 0, (char *) 0 }, 
};

#else

extern struct ArgusEtherTypeStruct argus_ethertype_names [];

#endif
#ifdef __cplusplus
}
#endif
#endif
