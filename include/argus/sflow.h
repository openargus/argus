/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

/////////////////////////////////////////////////////////////////////////////////
/////////////////////// sFlow Sampling Packet Data Types ////////////////////////
/////////////////////////////////////////////////////////////////////////////////

#ifndef SFLOW_H
#define SFLOW_H 1

#if defined(__cplusplus)
extern "C" {
#endif

typedef struct {
    uint32_t addr;
} SFLIPv4;

typedef struct {
    u_char addr[16];
} SFLIPv6;

typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
} SFLAddress_value;

enum SFLAddress_type {
  SFLADDRESSTYPE_UNDEFINED = 0,
  SFLADDRESSTYPE_IP_V4 = 1,
  SFLADDRESSTYPE_IP_V6 = 2
};

typedef struct _SFLAddress {
  uint32_t type;           /* enum SFLAddress_type */
  SFLAddress_value address;
} SFLAddress;

/* Packet header data */

#define SFL_DEFAULT_HEADER_SIZE 128
#define SFL_DEFAULT_COLLECTOR_PORT 6343
#define SFL_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum SFLHeader_protocol {
  SFLHEADER_ETHERNET_ISO8023     = 1,
  SFLHEADER_ISO88024_TOKENBUS    = 2,
  SFLHEADER_ISO88025_TOKENRING   = 3,
  SFLHEADER_FDDI                 = 4,
  SFLHEADER_FRAME_RELAY          = 5,
  SFLHEADER_X25                  = 6,
  SFLHEADER_PPP                  = 7,
  SFLHEADER_SMDS                 = 8,
  SFLHEADER_AAL5                 = 9,
  SFLHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  SFLHEADER_IPv4                 = 11,
  SFLHEADER_IPv6                 = 12,
  SFLHEADER_MPLS                 = 13,
  SFLHEADER_POS                  = 14,
  SFLHEADER_IEEE80211MAC         = 15,
  SFLHEADER_IEEE80211_AMPDU      = 16,
  SFLHEADER_IEEE80211_AMSDU_SUBFRAME = 17
};

/* raw sampled header */

typedef struct _SFLSampled_header {
  uint32_t header_protocol;            /* (enum SFLHeader_protocol) */
  uint32_t frame_length;               /* Original length of packet before sampling */
  uint32_t stripped;                   /* header/trailer bytes stripped by sender */
  uint32_t header_length;              /* length of sampled header bytes to follow */
  uint8_t *header_bytes;               /* Header bytes */
} SFLSampled_header;

/* decoded ethernet header */

typedef struct _SFLSampled_ethernet {
  uint32_t eth_len;       /* The length of the MAC packet excluding 
                             lower layer encapsulations */
  uint8_t src_mac[8];    /* 6 bytes + 2 pad */
  uint8_t dst_mac[8];
  uint32_t eth_type;
} SFLSampled_ethernet;

/* decoded IP version 4 header */

typedef struct _SFLSampled_ipv4 {
  uint32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  uint32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip; /* Source IP Address */
  SFLIPv4 dst_ip; /* Destination IP Address */
  uint32_t src_port;    /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;   /* TCP flags */
  uint32_t tos;         /* IP type of service */
} SFLSampled_ipv4;

/* decoded IP version 6 data */

typedef struct _SFLSampled_ipv6 {
  uint32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  uint32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip; /* Source IP Address */
  SFLIPv6 dst_ip; /* Destination IP Address */
  uint32_t src_port;     /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;    /* TCP flags */
  uint32_t priority;     /* IP priority */
} SFLSampled_ipv6;

/* Extended data types */

/* Extended switch data */

typedef struct _SFLExtended_switch {
  uint32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  uint32_t src_priority;   /* The 802.1p priority */
  uint32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  uint32_t dst_priority;   /* The 802.1p priority */
} SFLExtended_switch;

/* Extended router data */

typedef struct _SFLExtended_router {
  SFLAddress nexthop;               /* IP address of next hop router */
  uint32_t src_mask;               /* Source address prefix mask bits */
  uint32_t dst_mask;               /* Destination address prefix mask bits */
} SFLExtended_router;

/* Extended gateway data */
enum SFLExtended_as_path_segment_type {
  SFLEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  SFLEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _SFLExtended_as_path_segment {
  uint32_t type;   /* enum SFLExtended_as_path_segment_type */
  uint32_t length; /* number of AS numbers in set/sequence */
  union {
    uint32_t *set;
    uint32_t *seq;
  } as;
} SFLExtended_as_path_segment;

typedef struct _SFLExtended_gateway {
  SFLAddress nexthop;                       /* Address of the border router that should
                                               be used for the destination network */
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_segments;           /* number of segments in path */
  SFLExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  uint32_t communities_length;             /* number of communities */
  uint32_t *communities;                   /* set of communities */
  uint32_t localpref;                      /* LocalPref associated with this route */
} SFLExtended_gateway;

typedef struct _SFLString {
  uint32_t len;
  char *str;
} SFLString;

/* Extended user data */

typedef struct _SFLExtended_user {
  uint32_t src_charset;  /* MIBEnum value of character set used to encode a string - See RFC 2978
			     Where possible UTF-8 encoding (MIBEnum=106) should be used. A value
			     of zero indicates an unknown encoding. */
  SFLString src_user;
  uint32_t dst_charset;
  SFLString dst_user;
} SFLExtended_user;

/* Extended URL data */

enum SFLExtended_url_direction {
  SFLEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  SFLEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _SFLExtended_url {
  uint32_t direction;   /* enum SFLExtended_url_direction */
  SFLString url;         /* URL associated with the packet flow.
			    Must be URL encoded */
  SFLString host;        /* The host field from the HTTP header */
} SFLExtended_url;

/* Extended MPLS data */

typedef struct _SFLLabelStack {
  uint32_t depth;
  uint32_t *stack; /* first entry is top of stack - see RFC 3032 for encoding */
} SFLLabelStack;

typedef struct _SFLExtended_mpls {
  SFLAddress nextHop;        /* Address of the next hop */ 
  SFLLabelStack in_stack;
  SFLLabelStack out_stack;
} SFLExtended_mpls;

  /* Extended NAT data
     Packet header records report addresses as seen at the sFlowDataSource.
     The extended_nat structure reports on translated source and/or destination
     addesses for this packet. If an address was not translated it should 
     be equal to that reported for the header. */

typedef struct _SFLExtended_nat {
  SFLAddress src;    /* Source address */
  SFLAddress dst;    /* Destination address */
} SFLExtended_nat;

  /* additional Extended MPLS stucts */

typedef struct _SFLExtended_mpls_tunnel {
   SFLString tunnel_lsp_name;  /* Tunnel name */
   uint32_t tunnel_id;        /* Tunnel ID */
   uint32_t tunnel_cos;       /* Tunnel COS value */
} SFLExtended_mpls_tunnel;

typedef struct _SFLExtended_mpls_vc {
   SFLString vc_instance_name; /* VC instance name */
   uint32_t vll_vc_id;        /* VLL/VC instance ID */
   uint32_t vc_label_cos;     /* VC Label COS value */
} SFLExtended_mpls_vc;

/* Extended MPLS FEC
    - Definitions from MPLS-FTN-STD-MIB mplsFTNTable */

typedef struct _SFLExtended_mpls_FTN {
   SFLString mplsFTNDescr;
   uint32_t mplsFTNMask;
} SFLExtended_mpls_FTN;

/* Extended MPLS LVP FEC
    - Definition from MPLS-LDP-STD-MIB mplsFecTable
    Note: mplsFecAddrType, mplsFecAddr information available
          from packet header */

typedef struct _SFLExtended_mpls_LDP_FEC {
   uint32_t mplsFecAddrPrefixLength;
} SFLExtended_mpls_LDP_FEC;

/* Extended VLAN tunnel information 
   Record outer VLAN encapsulations that have 
   been stripped. extended_vlantunnel information 
   should only be reported if all the following conditions are satisfied: 
     1. The packet has nested vlan tags, AND 
     2. The reporting device is VLAN aware, AND 
     3. One or more VLAN tags have been stripped, either 
        because they represent proprietary encapsulations, or 
        because switch hardware automatically strips the outer VLAN 
        encapsulation. 
   Reporting extended_vlantunnel information is not a substitute for 
   reporting extended_switch information. extended_switch data must 
   always be reported to describe the ingress/egress VLAN information 
   for the packet. The extended_vlantunnel information only applies to 
   nested VLAN tags, and then only when one or more tags has been 
   stripped. */ 

typedef SFLLabelStack SFLVlanStack;
typedef struct _SFLExtended_vlan_tunnel { 
  SFLVlanStack stack;  /* List of stripped 802.1Q TPID/TCI layers. Each 
			  TPID,TCI pair is represented as a single 32 bit 
			  integer. Layers listed from outermost to 
			  innermost. */ 
} SFLExtended_vlan_tunnel;

  ////////////////// IEEE 802.11 Extension structs ////////////////////

/* The 4-byte cipher_suite identifier follows the format of the cipher suite
   selector value from the 802.11i (TKIP/CCMP amendment to 802.11i)
   The most significant three bytes contain the OUI and the least significant
   byte contains the Suite Type.

   The currently assigned values are:

   OUI        |Suite type  |Meaning
   ----------------------------------------------------
   00-0F-AC   | 0          | Use group cipher suite
   00-0F-AC   | 1          | WEP-40
   00-0F-AC   | 2          | TKIP
   00-0F-AC   | 3          | Reserved
   00-0F-AC   | 4          | CCMP
   00-0F-AC   | 5          | WEP-104
   00-0F-AC   | 6-255      | Reserved
   Vendor OUI | Other      | Vendor specific
   Other      | Any        | Reserved
   ----------------------------------------------------
*/

typedef uint32_t SFLCipherSuite;

/* Extended wifi Payload
   Used to provide unencrypted version of 802.11 MAC data. If the
   MAC data is not encrypted then the agent must not include an
   extended_wifi_payload structure.
   If 802.11 MAC data is encrypted then the sampled_header structure
   should only contain the MAC header (since encrypted data cannot
   be decoded by the sFlow receiver). If the sFlow agent has access to
   the unencrypted payload, it should add an extended_wifi_payload
   structure containing the unencrypted data bytes from the sampled
   packet header, starting at the beginning of the 802.2 LLC and not
   including any trailing encryption footers.  */
/* opaque = flow_data; enterprise = 0; format = 1013 */

typedef struct _SFLExtended_wifi_payload {
  SFLCipherSuite cipherSuite;
  SFLSampled_header header;
} SFLExtended_wifi_payload;

typedef enum  {
  IEEE80211_A=1,
  IEEE80211_B=2,
  IEEE80211_G=3,
  IEEE80211_N=4,
} SFL_IEEE80211_version;

/* opaque = flow_data; enterprise = 0; format = 1014 */

#define SFL_MAX_SSID_LEN 256

typedef struct _SFLExtended_wifi_rx {
  uint32_t ssid_len;
  char *ssid;
  char bssid[6];    /* BSSID */
  SFL_IEEE80211_version version;  /* version */
  uint32_t channel;       /* channel number */
  uint64_t speed;
  uint32_t rsni;          /* received signal to noise ratio, see dot11FrameRprtRSNI */
  uint32_t rcpi;          /* received channel power, see dot11FrameRprtLastRCPI */
  uint32_t packet_duration_us; /* amount of time that the successfully received pkt occupied RF medium.*/
} SFLExtended_wifi_rx;

/* opaque = flow_data; enterprise = 0; format = 1015 */

typedef struct _SFLExtended_wifi_tx {
  uint32_t ssid_len;
  char *ssid;              /* SSID string */
  char  bssid[6];             /* BSSID */
  SFL_IEEE80211_version version;    /* version */
  uint32_t transmissions;   /* number of transmissions for sampled
				packet.
				0 = unkown
				1 = packet was successfully transmitted
				on first attempt
				n > 1 = n - 1 retransmissions */
  uint32_t packet_duration_us;  /* amount of time that the successfully
                                    transmitted packet occupied the
                                    RF medium */
  uint32_t retrans_duration_us; /* amount of time that failed transmission
                                    attempts occupied the RF medium */
  uint32_t channel;         /* channel number */
  uint64_t speed;
  uint32_t power_mw;           /* transmit power in mW. */
} SFLExtended_wifi_tx;

/* Extended 802.11 Aggregation Data */
/* A flow_sample of an aggregated frame would consist of a packet
   header for the whole frame + any other extended structures that
   apply (e.g. 80211_tx/rx etc.) + an extended_wifi_aggregation
   structure which would contain an array of pdu structures (one
   for each PDU in the aggregate). A pdu is simply an array of
   flow records, in the simplest case a packet header for each PDU,
   but extended structures could be included as well. */

/* opaque = flow_data; enterprise = 0; format = 1016 */

struct _SFLFlow_Pdu; // forward decl

typedef struct _SFLExtended_aggregation {
  uint32_t num_pdus;
  struct _SFFlow_Pdu *pdus;
} SFLExtended_aggregation;

/* Extended socket information,
   Must be filled in for all application transactions associated with a network socket
   Omit if transaction associated with non-network IPC  */

/* IPv4 Socket */
/* opaque = flow_data; enterprise = 0; format = 2100 */
typedef struct _SFLExtended_socket_ipv4 {
   uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
   SFLIPv4 local_ip;      /* local IP address */
   SFLIPv4 remote_ip;     /* remote IP address */
   uint32_t local_port;   /* TCP/UDP local port number or equivalent */
   uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv4;

#define XDRSIZ_SFLEXTENDED_SOCKET4 20

/* IPv6 Socket */
/* opaque = flow_data; enterprise = 0; format = 2101 */
typedef struct _SFLExtended_socket_ipv6 {
  uint32_t protocol;     /* IP Protocol (e.g. TCP = 6, UDP = 17) */
  SFLIPv6 local_ip;      /* local IP address */
  SFLIPv6 remote_ip;     /* remote IP address */
  uint32_t local_port;   /* TCP/UDP local port number or equivalent */
  uint32_t remote_port;  /* TCP/UDP remote port number of equivalent */
} SFLExtended_socket_ipv6;

#define XDRSIZ_SFLEXTENDED_SOCKET6 44

typedef enum  {
  MEMCACHE_PROT_OTHER   = 0,
  MEMCACHE_PROT_ASCII   = 1,
  MEMCACHE_PROT_BINARY  = 2,
} SFLMemcache_prot;

typedef enum  {
  MEMCACHE_CMD_OTHER    = 0,
  MEMCACHE_CMD_SET      = 1,
  MEMCACHE_CMD_ADD      = 2,
  MEMCACHE_CMD_REPLACE  = 3,
  MEMCACHE_CMD_APPEND   = 4,
  MEMCACHE_CMD_PREPEND  = 5,
  MEMCACHE_CMD_CAS      = 6,
  MEMCACHE_CMD_GET      = 7,
  MEMCACHE_CMD_GETS     = 8,
} SFLMemcache_cmd;

enum SFLMemcache_operation_status {
  MEMCACHE_OP_UNKNOWN      = 0,
  MEMCACHE_OP_OK           = 1,
  MEMCACHE_OP_ERROR        = 2,
  MEMCACHE_OP_CLIENT_ERROR = 3,
  MEMCACHE_OP_SERVER_ERROR = 4,
  MEMCACHE_OP_STORED       = 5,
  MEMCACHE_OP_NOT_STORED   = 6,
  MEMCACHE_OP_EXISTS       = 7,
  MEMCACHE_OP_NOT_FOUND    = 8,
  MEMCACHE_OP_DELETED      = 9,
};

#define SFL_MAX_MEMCACHE_KEY 255
 
typedef struct _SFLSampled_memcache {
  uint32_t protocol;    /* SFLMemcache_prot */
  uint32_t command;     /* SFLMemcache_cmd */
  SFLString key;        /* up to 255 chars */
  uint32_t nkeys;
  uint32_t value_bytes;
  uint32_t duration_uS;
  uint32_t status;      /* SFLMemcache_operation_status */
} SFLSampled_memcache;

typedef enum {
  SFHTTP_OTHER    = 0,
  SFHTTP_OPTIONS  = 1,
  SFHTTP_GET      = 2,
  SFHTTP_HEAD     = 3,
  SFHTTP_POST     = 4,
  SFHTTP_PUT      = 5,
  SFHTTP_DELETE   = 6,
  SFHTTP_TRACE    = 7,
  SFHTTP_CONNECT  = 8,
} SFLHTTP_method;

#define SFL_MAX_HTTP_URI 255
#define SFL_MAX_HTTP_HOST 32
#define SFL_MAX_HTTP_REFERRER 255
#define SFL_MAX_HTTP_USERAGENT 64
#define SFL_MAX_HTTP_AUTHUSER 32
#define SFL_MAX_HTTP_MIMETYPE 32

typedef struct _SFLSampled_http {
  SFLHTTP_method method;
  uint32_t protocol;      /* 1.1=1001 */
  SFLString uri;           /* URI exactly as it came from the client (up to 255 bytes) */
  SFLString host;          /* Host value from request header (<= 32 bytes) */
  SFLString referrer;      /* Referer value from request header (<=255 bytes) */
  SFLString useragent;     /* User-Agent value from request header (<= 64 bytes)*/
  SFLString authuser;      /* RFC 1413 identity of user (<=32 bytes)*/
  SFLString mimetype;      /* Mime-Type (<=32 bytes) */
  uint64_t bytes;          /* Content-Length of document transferred */
  uint32_t uS;             /* duration of the operation (microseconds) */
  uint32_t status;         /* HTTP status code */
} SFLSampled_http;


typedef enum {
  SFLOW_CAL_TRANSACTION_OTHER=0,
  SFLOW_CAL_TRANSACTION_START,
  SFLOW_CAL_TRANSACTION_END,
  SFLOW_CAL_TRANSACTION_ATOMIC,
  SFLOW_CAL_TRANSACTION_EVENT,
  SFLOW_CAL_NUM_TRANSACTION_TYPES
}  EnumSFLCALTransaction;

//static const char *CALTransactionNames[] = {"OTHER", "START", "END","ATOMIC", "EVENT" };

typedef struct _SFLSampled_CAL {
  EnumSFLCALTransaction type;
  uint32_t depth;
  SFLString pool;
  SFLString transaction;
  SFLString operation;
  SFLString status;
  uint64_t duration_uS;
} SFLSampled_CAL;

#define SFLCAL_MAX_POOL_LEN 32
#define SFLCAL_MAX_TRANSACTION_LEN 128
#define SFLCAL_MAX_OPERATION_LEN 128
#define SFLCAL_MAX_STATUS_LEN 64

enum SFLFlow_type_tag { 
  /* enterprise = 0, format = ... */
  SFLFLOW_HEADER    = 1,      /* Packet headers are sampled */
  SFLFLOW_ETHERNET  = 2,      /* MAC layer information */
  SFLFLOW_IPV4      = 3,      /* IP version 4 data */
  SFLFLOW_IPV6      = 4,      /* IP version 6 data */
  SFLFLOW_EX_SWITCH    = 1001,      /* Extended switch information */
  SFLFLOW_EX_ROUTER    = 1002,      /* Extended router information */
  SFLFLOW_EX_GATEWAY   = 1003,      /* Extended gateway router information */
  SFLFLOW_EX_USER      = 1004,      /* Extended TACAS/RADIUS user information */
  SFLFLOW_EX_URL       = 1005,      /* Extended URL information */
  SFLFLOW_EX_MPLS      = 1006,      /* Extended MPLS information */
  SFLFLOW_EX_NAT       = 1007,      /* Extended NAT information */
  SFLFLOW_EX_MPLS_TUNNEL  = 1008,   /* additional MPLS information */
  SFLFLOW_EX_MPLS_VC      = 1009,
  SFLFLOW_EX_MPLS_FTN     = 1010,
  SFLFLOW_EX_MPLS_LDP_FEC = 1011,
  SFLFLOW_EX_VLAN_TUNNEL  = 1012,   /* VLAN stack */
  SFLFLOW_EX_80211_PAYLOAD = 1013,
  SFLFLOW_EX_80211_RX      = 1014,
  SFLFLOW_EX_80211_TX      = 1015,
  SFLFLOW_EX_AGGREGATION   = 1016,
  SFLFLOW_EX_SOCKET4       = 2100,
  SFLFLOW_EX_SOCKET6       = 2101,
  SFLFLOW_MEMCACHE         = 2200,
  SFLFLOW_HTTP             = 2201,
  SFLFLOW_CAL             = (4300 << 12) + 5,  /* 4300 is InMon enterprise no. */
};

typedef union _SFLFlow_type {
  SFLSampled_header header;
  SFLSampled_ethernet ethernet;
  SFLSampled_ipv4 ipv4;
  SFLSampled_ipv6 ipv6;
  SFLSampled_memcache memcache;
  SFLSampled_http http;
  SFLSampled_CAL cal;
  SFLExtended_switch sw;
  SFLExtended_router router;
  SFLExtended_gateway gateway;
  SFLExtended_user user;
  SFLExtended_url url;
  SFLExtended_mpls mpls;
  SFLExtended_nat nat;
  SFLExtended_mpls_tunnel mpls_tunnel;
  SFLExtended_mpls_vc mpls_vc;
  SFLExtended_mpls_FTN mpls_ftn;
  SFLExtended_mpls_LDP_FEC mpls_ldp_fec;
  SFLExtended_vlan_tunnel vlan_tunnel;
  SFLExtended_wifi_payload wifi_payload;
  SFLExtended_wifi_rx wifi_rx;
  SFLExtended_wifi_tx wifi_tx;
  SFLExtended_aggregation aggregation;
  SFLExtended_socket_ipv4 socket4;
  SFLExtended_socket_ipv6 socket6;
} SFLFlow_type;

typedef struct _SFLFlow_sample_element {
  struct _SFLFlow_sample_element *nxt;
  uint32_t tag;  /* SFLFlow_type_tag */
  uint32_t length;
  SFLFlow_type flowType;
} SFLFlow_sample_element;

enum SFL_sample_tag {
  SFLFLOW_SAMPLE = 1,              /* enterprise = 0 : format = 1 */
  SFLCOUNTERS_SAMPLE = 2,          /* enterprise = 0 : format = 2 */
  SFLFLOW_SAMPLE_EXPANDED = 3,     /* enterprise = 0 : format = 3 */
  SFLCOUNTERS_SAMPLE_EXPANDED = 4  /* enterprise = 0 : format = 4 */
};

typedef struct _SFLFlow_Pdu {
  struct _SFLFlow_Pdu *nxt;
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_Pdu;

  
/* Format of a single flow sample */

typedef struct _SFLFlow_sample {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t source_id;            /* fsSourceId */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample;

  /* same thing, but the expanded version (for full 32-bit ifIndex numbers) */

typedef struct _SFLFlow_sample_expanded {
  /* uint32_t tag;    */         /* SFL_sample_tag -- enterprise = 0 : format = 1 */
  /* uint32_t length; */
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t ds_class;             /* EXPANDED */
  uint32_t ds_index;             /* EXPANDED */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t inputFormat;          /* EXPANDED */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t outputFormat;         /* EXPANDED */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known. */
  uint32_t num_elements;
  SFLFlow_sample_element *elements;
} SFLFlow_sample_expanded;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _SFLIf_counters {
  uint32_t ifIndex;
  uint32_t ifType;
  uint64_t ifSpeed;
  uint32_t ifDirection;        /* Derived from MAU MIB (RFC 2668)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  uint32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  uint64_t ifInOctets;
  uint32_t ifInUcastPkts;
  uint32_t ifInMulticastPkts;
  uint32_t ifInBroadcastPkts;
  uint32_t ifInDiscards;
  uint32_t ifInErrors;
  uint32_t ifInUnknownProtos;
  uint64_t ifOutOctets;
  uint32_t ifOutUcastPkts;
  uint32_t ifOutMulticastPkts;
  uint32_t ifOutBroadcastPkts;
  uint32_t ifOutDiscards;
  uint32_t ifOutErrors;
  uint32_t ifPromiscuousMode;
} SFLIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _SFLEthernet_counters {
  uint32_t dot3StatsAlignmentErrors;
  uint32_t dot3StatsFCSErrors;
  uint32_t dot3StatsSingleCollisionFrames;
  uint32_t dot3StatsMultipleCollisionFrames;
  uint32_t dot3StatsSQETestErrors;
  uint32_t dot3StatsDeferredTransmissions;
  uint32_t dot3StatsLateCollisions;
  uint32_t dot3StatsExcessiveCollisions;
  uint32_t dot3StatsInternalMacTransmitErrors;
  uint32_t dot3StatsCarrierSenseErrors;
  uint32_t dot3StatsFrameTooLongs;
  uint32_t dot3StatsInternalMacReceiveErrors;
  uint32_t dot3StatsSymbolErrors;
} SFLEthernet_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _SFLTokenring_counters {
  uint32_t dot5StatsLineErrors;
  uint32_t dot5StatsBurstErrors;
  uint32_t dot5StatsACErrors;
  uint32_t dot5StatsAbortTransErrors;
  uint32_t dot5StatsInternalErrors;
  uint32_t dot5StatsLostFrameErrors;
  uint32_t dot5StatsReceiveCongestions;
  uint32_t dot5StatsFrameCopiedErrors;
  uint32_t dot5StatsTokenErrors;
  uint32_t dot5StatsSoftErrors;
  uint32_t dot5StatsHardErrors;
  uint32_t dot5StatsSignalLoss;
  uint32_t dot5StatsTransmitBeacons;
  uint32_t dot5StatsRecoverys;
  uint32_t dot5StatsLobeWires;
  uint32_t dot5StatsRemoves;
  uint32_t dot5StatsSingles;
  uint32_t dot5StatsFreqErrors;
} SFLTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _SFLVg_counters {
  uint32_t dot12InHighPriorityFrames;
  uint64_t dot12InHighPriorityOctets;
  uint32_t dot12InNormPriorityFrames;
  uint64_t dot12InNormPriorityOctets;
  uint32_t dot12InIPMErrors;
  uint32_t dot12InOversizeFrameErrors;
  uint32_t dot12InDataErrors;
  uint32_t dot12InNullAddressedFrames;
  uint32_t dot12OutHighPriorityFrames;
  uint64_t dot12OutHighPriorityOctets;
  uint32_t dot12TransitionIntoTrainings;
  uint64_t dot12HCInHighPriorityOctets;
  uint64_t dot12HCInNormPriorityOctets;
  uint64_t dot12HCOutHighPriorityOctets;
} SFLVg_counters;

typedef struct _SFLVlan_counters {
  uint32_t vlan_id;
  uint64_t octets;
  uint32_t ucastPkts;
  uint32_t multicastPkts;
  uint32_t broadcastPkts;
  uint32_t discards;
} SFLVlan_counters;

typedef struct _SFLWifi_counters {
  uint32_t dot11TransmittedFragmentCount;
  uint32_t dot11MulticastTransmittedFrameCount;
  uint32_t dot11FailedCount;
  uint32_t dot11RetryCount;
  uint32_t dot11MultipleRetryCount;
  uint32_t dot11FrameDuplicateCount;
  uint32_t dot11RTSSuccessCount;
  uint32_t dot11RTSFailureCount;
  uint32_t dot11ACKFailureCount;
  uint32_t dot11ReceivedFragmentCount;
  uint32_t dot11MulticastReceivedFrameCount;
  uint32_t dot11FCSErrorCount;
  uint32_t dot11TransmittedFrameCount;
  uint32_t dot11WEPUndecryptableCount;
  uint32_t dot11QoSDiscardedFragmentCount;
  uint32_t dot11AssociatedStationCount;
  uint32_t dot11QoSCFPollsReceivedCount;
  uint32_t dot11QoSCFPollsUnusedCount;
  uint32_t dot11QoSCFPollsUnusableCount;
  uint32_t dot11QoSCFPollsLostCount;
} SFLWifi_counters;

/* Processor Information */
/* opaque = counter_data; enterprise = 0; format = 1001 */

typedef struct _SFLProcessor_counters {
   uint32_t five_sec_cpu;  /* 5 second average CPU utilization */
   uint32_t one_min_cpu;   /* 1 minute average CPU utilization */
   uint32_t five_min_cpu;  /* 5 minute average CPU utilization */
   uint64_t total_memory;  /* total memory (in bytes) */
   uint64_t free_memory;   /* free memory (in bytes) */
} SFLProcessor_counters;
  
typedef struct _SFLRadio_counters {
  uint32_t elapsed_time;         /* elapsed time in ms */
  uint32_t on_channel_time;      /* time in ms spent on channel */
  uint32_t on_channel_busy_time; /* time in ms spent on channel and busy */
} SFLRadio_counters;

  /* host sflow */

enum SFLMachine_type {
  SFLMT_unknown = 0,
  SFLMT_other   = 1,
  SFLMT_x86     = 2,
  SFLMT_x86_64  = 3,
  SFLMT_ia64    = 4,
  SFLMT_sparc   = 5,
  SFLMT_alpha   = 6,
  SFLMT_powerpc = 7,
  SFLMT_m68k    = 8,
  SFLMT_mips    = 9,
  SFLMT_arm     = 10,
  SFLMT_hppa    = 11,
  SFLMT_s390    = 12
};

enum SFLOS_name {
  SFLOS_unknown   = 0,
  SFLOS_other     = 1,
  SFLOS_linux     = 2,
  SFLOS_windows   = 3,
  SFLOS_darwin    = 4,
  SFLOS_hpux      = 5,
  SFLOS_aix       = 6,
  SFLOS_dragonfly = 7,
  SFLOS_freebsd   = 8,
  SFLOS_netbsd    = 9,
  SFLOS_openbsd   = 10,
  SFLOS_osf       = 11,
  SFLOS_solaris   = 12
};

typedef struct _SFLMacAddress {
  uint8_t mac[8];
} SFLMacAddress;

typedef struct _SFLAdaptor {
  uint32_t ifIndex;
  uint32_t num_macs;
  SFLMacAddress macs[1];
} SFLAdaptor;

typedef struct _SFLAdaptorList {
  uint32_t capacity;
  uint32_t num_adaptors;
  SFLAdaptor **adaptors;
} SFLAdaptorList;

typedef struct _SFLHost_parent {
  uint32_t dsClass;       /* sFlowDataSource class */
  uint32_t dsIndex;       /* sFlowDataSource index */
} SFLHost_parent;


#define SFL_MAX_HOSTNAME_LEN 64
#define SFL_MAX_OSRELEASE_LEN 32

typedef struct _SFLHostId {
  SFLString hostname;
  u_char uuid[16];
  uint32_t machine_type; /* enum SFLMachine_type */
  uint32_t os_name;      /* enum SFLOS_name */
  SFLString os_release;  /* max len 32 bytes */
} SFLHostId;

typedef struct _SFLHost_nio_counters {
  uint64_t bytes_in;
  uint32_t pkts_in;
  uint32_t errs_in;
  uint32_t drops_in;
  uint64_t bytes_out;
  uint32_t pkts_out;
  uint32_t errs_out;
  uint32_t drops_out;
} SFLHost_nio_counters;

typedef struct _SFLHost_cpu_counters {
  float load_one;      /* 1 minute load avg. */
  float load_five;     /* 5 minute load avg. */
  float load_fifteen;  /* 15 minute load avg. */
  uint32_t proc_run;   /* running threads */
  uint32_t proc_total; /* total threads */
  uint32_t cpu_num;    /* # CPU cores */
  uint32_t cpu_speed;  /* speed in MHz of CPU */
  uint32_t uptime;     /* seconds since last reboot */
  uint32_t cpu_user;   /* time executing in user mode processes (ms) */
  uint32_t cpu_nice;   /* time executing niced processs (ms) */
  uint32_t cpu_system; /* time executing kernel mode processes (ms) */
  uint32_t cpu_idle;   /* idle time (ms) */
  uint32_t cpu_wio;    /* time waiting for I/O to complete (ms) */
  uint32_t cpu_intr;   /* time servicing interrupts (ms) */
  uint32_t cpu_sintr;  /* time servicing softirqs (ms) */
  uint32_t interrupts; /* interrupt count */
  uint32_t contexts;   /* context switch count */
} SFLHost_cpu_counters;

typedef struct _SFLHost_mem_counters {
  uint64_t mem_total;    /* total bytes */
  uint64_t mem_free;     /* free bytes */
  uint64_t mem_shared;   /* shared bytes */
  uint64_t mem_buffers;  /* buffers bytes */
  uint64_t mem_cached;   /* cached bytes */
  uint64_t swap_total;   /* swap total bytes */
  uint64_t swap_free;    /* swap free bytes */
  uint32_t page_in;      /* page in count */
  uint32_t page_out;     /* page out count */
  uint32_t swap_in;      /* swap in count */
  uint32_t swap_out;     /* swap out count */
} SFLHost_mem_counters;

typedef struct _SFLHost_dsk_counters {
  uint64_t disk_total;
  uint64_t disk_free;
  uint32_t part_max_used;   /* as percent * 100, so 100==1% */
  uint32_t reads;           /* reads issued */
  uint64_t bytes_read;      /* bytes read */
  uint32_t read_time;       /* read time (ms) */
  uint32_t writes;          /* writes completed */
  uint64_t bytes_written;   /* bytes written */
  uint32_t write_time;      /* write time (ms) */
} SFLHost_dsk_counters;

/* Virtual Node Statistics */
/* opaque = counter_data; enterprise = 0; format = 2100 */

typedef struct _SFLHost_vrt_node_counters {
   uint32_t mhz;           /* expected CPU frequency */
   uint32_t cpus;          /* the number of active CPUs */
   uint64_t memory;        /* memory size in bytes */
   uint64_t memory_free;   /* unassigned memory in bytes */
   uint32_t num_domains;   /* number of active domains */
} SFLHost_vrt_node_counters;

/* Virtual Domain Statistics */
/* opaque = counter_data; enterprise = 0; format = 2101 */

/* virDomainState imported from libvirt.h */
enum SFLVirDomainState {
     SFL_VIR_DOMAIN_NOSTATE = 0, /* no state */
     SFL_VIR_DOMAIN_RUNNING = 1, /* the domain is running */
     SFL_VIR_DOMAIN_BLOCKED = 2, /* the domain is blocked on resource */
     SFL_VIR_DOMAIN_PAUSED  = 3, /* the domain is paused by user */
     SFL_VIR_DOMAIN_SHUTDOWN= 4, /* the domain is being shut down */
     SFL_VIR_DOMAIN_SHUTOFF = 5, /* the domain is shut off */
     SFL_VIR_DOMAIN_CRASHED = 6  /* the domain is crashed */
};

typedef struct _SFLHost_vrt_cpu_counters {
   uint32_t state;       /* virtDomainState */
   uint32_t cpuTime;     /* the CPU time used in mS */
   uint32_t cpuCount;    /* number of virtual CPUs for the domain */
} SFLHost_vrt_cpu_counters;

/* Virtual Domain Memory statistics */
/* opaque = counter_data; enterprise = 0; format = 2102 */

typedef struct _SFLHost_vrt_mem_counters {
  uint64_t memory;      /* memory in bytes used by domain */
  uint64_t maxMemory;   /* memory in bytes allowed */
} SFLHost_vrt_mem_counters;

/* Virtual Domain Disk statistics */
/* opaque = counter_data; enterprise = 0; format = 2103 */

typedef struct _SFLHost_vrt_dsk_counters {
  uint64_t capacity;   /* logical size in bytes */
  uint64_t allocation; /* current allocation in bytes */
  uint64_t available;  /* remaining free bytes */
  uint32_t rd_req;     /* number of read requests */
  uint64_t rd_bytes;   /* number of read bytes */
  uint32_t wr_req;     /* number of write requests */
  uint64_t wr_bytes;   /* number of  written bytes */
  uint32_t errs;        /* read/write errors */
} SFLHost_vrt_dsk_counters;

/* Virtual Domain Network statistics */
/* opaque = counter_data; enterprise = 0; format = 2104 */

typedef struct _SFLHost_vrt_nio_counters {
  uint64_t bytes_in;
  uint32_t pkts_in;
  uint32_t errs_in;
  uint32_t drops_in;
  uint64_t bytes_out;
  uint32_t pkts_out;
  uint32_t errs_out;
  uint32_t drops_out;
} SFLHost_vrt_nio_counters;

typedef struct _SFLMemcache_counters {
   uint32_t uptime;     /* Number of seconds this server has been running */
   uint32_t rusage_user;    /* Accumulated user time for this process (ms)*/
   uint32_t rusage_system;  /* Accumulated system time for this process (ms)*/
   uint32_t curr_connections; /* Number of open connections */
   uint32_t total_connections; /* Total number of connections opened since
                                      the server started running */
   uint32_t connection_structures; /* Number of connection structures
                                          allocated by the server */
   uint32_t cmd_get;        /* Cumulative number of retrieval requests */
   uint32_t cmd_set;        /* Cumulative number of storage requests */
   uint32_t cmd_flush;      /* */
   uint32_t get_hits;       /* Number of keys that have been requested and
                                     found present */
   uint32_t get_misses;     /* Number of items that have been requested
                                     and not found */
   uint32_t delete_misses;
   uint32_t delete_hits;
   uint32_t incr_misses;
   uint32_t incr_hits;
   uint32_t decr_misses;
   uint32_t decr_hits;
   uint32_t cas_misses;
   uint32_t cas_hits;
   uint32_t cas_badval;
   uint32_t auth_cmds;
   uint32_t auth_errors;
   uint64_t bytes_read;
   uint64_t bytes_written;
   uint32_t limit_maxbytes;
   uint32_t accepting_conns;
   uint32_t listen_disabled_num;
   uint32_t threads;
   uint32_t conn_yields;
   uint64_t bytes;
   uint32_t curr_items;
   uint32_t total_items;
   uint32_t evictions;
} SFLMemcache_counters;

typedef struct _SFLHTTP_counters {
  uint32_t method_option_count;
  uint32_t method_get_count;
  uint32_t method_head_count;
  uint32_t method_post_count;
  uint32_t method_put_count;
  uint32_t method_delete_count;
  uint32_t method_trace_count;
  uint32_t methd_connect_count;
  uint32_t method_other_count;
  uint32_t status_1XX_count;
  uint32_t status_2XX_count;
  uint32_t status_3XX_count;
  uint32_t status_4XX_count;
  uint32_t status_5XX_count;
  uint32_t status_other_count;
} SFLHTTP_counters;


typedef struct _SFLCAL_counters {
  uint32_t transactions;
  uint32_t errors;
  uint64_t duration_uS;
} SFLCAL_counters;

/* Counters data */

enum SFLCounters_type_tag {
  /* enterprise = 0, format = ... */
  SFLCOUNTERS_GENERIC      = 1,
  SFLCOUNTERS_ETHERNET     = 2,
  SFLCOUNTERS_TOKENRING    = 3,
  SFLCOUNTERS_VG           = 4,
  SFLCOUNTERS_VLAN         = 5,
  SFLCOUNTERS_80211        = 6,
  SFLCOUNTERS_PROCESSOR    = 1001,
  SFLCOUNTERS_RADIO        = 1002,
  SFLCOUNTERS_HOST_HID     = 2000, /* host id */
  SFLCOUNTERS_ADAPTORS     = 2001, /* host adaptors */
  SFLCOUNTERS_HOST_PAR     = 2002, /* host parent */
  SFLCOUNTERS_HOST_CPU     = 2003, /* host cpu  */
  SFLCOUNTERS_HOST_MEM     = 2004, /* host memory  */
  SFLCOUNTERS_HOST_DSK     = 2005, /* host storage I/O  */
  SFLCOUNTERS_HOST_NIO     = 2006, /* host network I/O */
  SFLCOUNTERS_HOST_VRT_NODE = 2100, /* host virt node */
  SFLCOUNTERS_HOST_VRT_CPU  = 2101, /* host virt cpu */
  SFLCOUNTERS_HOST_VRT_MEM  = 2102, /* host virt mem */
  SFLCOUNTERS_HOST_VRT_DSK  = 2103, /* host virt storage */
  SFLCOUNTERS_HOST_VRT_NIO  = 2104, /* host virt network I/O */
  SFLCOUNTERS_MEMCACHE      = 2200, /* memcached */
  SFLCOUNTERS_HTTP          = 2201, /* http */
  SFLCOUNTERS_CAL          = (4300 << 12) + 5,
};

typedef union _SFLCounters_type {
  SFLIf_counters generic;
  SFLEthernet_counters ethernet;
  SFLTokenring_counters tokenring;
  SFLVg_counters vg;
  SFLVlan_counters vlan;
  SFLWifi_counters wifi;
  SFLProcessor_counters processor;
  SFLRadio_counters radio;
  SFLHostId hostId;
  SFLAdaptorList *adaptors;
  SFLHost_parent host_par;
  SFLHost_cpu_counters host_cpu;
  SFLHost_mem_counters host_mem;
  SFLHost_dsk_counters host_dsk;
  SFLHost_nio_counters host_nio;
  SFLHost_vrt_node_counters host_vrt_node;
  SFLHost_vrt_cpu_counters host_vrt_cpu;
  SFLHost_vrt_mem_counters host_vrt_mem;
  SFLHost_vrt_dsk_counters host_vrt_dsk;
  SFLHost_vrt_nio_counters host_vrt_nio;
  SFLMemcache_counters memcache;
  SFLHTTP_counters http;
  SFLCAL_counters cal;
} SFLCounters_type;

typedef struct _SFLCounters_sample_element {
  struct _SFLCounters_sample_element *nxt; /* linked list */
  uint32_t tag; /* SFLCounters_type_tag */
  uint32_t length;
  SFLCounters_type counterBlock;
} SFLCounters_sample_element;

typedef struct _SFLCounters_sample {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample;

/* same thing, but the expanded version, so ds_index can be a full 32 bits */
typedef struct _SFLCounters_sample_expanded {
  /* uint32_t tag;    */       /* SFL_sample_tag -- enterprise = 0 : format = 2 */
  /* uint32_t length; */
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t ds_class;           /* EXPANDED */
  uint32_t ds_index;           /* EXPANDED */
  uint32_t num_elements;
  SFLCounters_sample_element *elements;
} SFLCounters_sample_expanded;

#define SFLADD_ELEMENT(_sm, _el) do { (_el)->nxt = (_sm)->elements; (_sm)->elements = (_el); } while(0)

/* Format of a sample datagram */

enum SFLDatagram_version {
  SFLDATAGRAM_VERSION2 = 2,
  SFLDATAGRAM_VERSION4 = 4,
  SFLDATAGRAM_VERSION5 = 5
};

typedef struct _SFLSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum SFLDatagram_version) = VERSION5 = 5 */
  SFLAddress agent_address;        /* IP address of sampling agent */
  uint32_t sub_agent_id;          /* Used to distinguishing between datagram
                                      streams from separate agent sub entities
                                      within an device. */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  uint32_t num_records;           /* Number of tag-len-val flow/counter records to follow */
} SFLSample_datagram_hdr;

#define SFL_MAX_DATAGRAM_SIZE 1500
#define SFL_MIN_DATAGRAM_SIZE 200
#define SFL_DEFAULT_DATAGRAM_SIZE 1400

#define SFL_DATA_PAD 400

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOW_H */


/* Copyright (c) 2002-2011 InMon Corp. Licensed under the terms of the InMon sFlow licence: */
/* http://www.inmon.com/technology/sflowlicense.txt */

#ifndef SFLOWTOOL_H
#define SFLOWTOOL_H 1

#if defined(__cplusplus)
extern "C" {
#endif

enum INMAddress_type {
  INMADDRESSTYPE_IP_V4 = 1,
  INMADDRESSTYPE_IP_V6 = 2
};

typedef union _INMAddress_value {
  SFLIPv4 ip_v4;
  SFLIPv6 ip_v6;
} INMAddress_value;

typedef struct _INMAddress {
  uint32_t type;           /* enum INMAddress_type */
  INMAddress_value address;
} INMAddress;

/* Packet header data */

#define INM_MAX_HEADER_SIZE 256   /* The maximum sampled header size. */
#define INM_DEFAULT_HEADER_SIZE 128
#define INM_DEFAULT_COLLECTOR_PORT 6343
#define INM_DEFAULT_SAMPLING_RATE 400

/* The header protocol describes the format of the sampled header */
enum INMHeader_protocol {
  INMHEADER_ETHERNET_ISO8023     = 1,
  INMHEADER_ISO88024_TOKENBUS    = 2,
  INMHEADER_ISO88025_TOKENRING   = 3,
  INMHEADER_FDDI                 = 4,
  INMHEADER_FRAME_RELAY          = 5,
  INMHEADER_X25                  = 6,
  INMHEADER_PPP                  = 7,
  INMHEADER_SMDS                 = 8,
  INMHEADER_AAL5                 = 9,
  INMHEADER_AAL5_IP              = 10, /* e.g. Cisco AAL5 mux */
  INMHEADER_IPv4                 = 11,
  INMHEADER_IPv6                 = 12
};

typedef struct _INMSampled_header {
  uint32_t header_protocol;            /* (enum INMHeader_protocol) */
  uint32_t frame_length;               /* Original length of packet before sampling */
  uint32_t header_length;              /* length of sampled header bytes to follow */
  uint8_t header[INM_MAX_HEADER_SIZE]; /* Header bytes */
} INMSampled_header;

/* Packet IP version 4 data */

typedef struct _INMSampled_ipv4 {
  uint32_t length;      /* The length of the IP packet
			    excluding lower layer encapsulations */
  uint32_t protocol;    /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv4 src_ip; /* Source IP Address */
  SFLIPv4 dst_ip; /* Destination IP Address */
  uint32_t src_port;    /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;    /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;   /* TCP flags */
  uint32_t tos;         /* IP type of service */
} INMSampled_ipv4;

/* Packet IP version 6 data */

typedef struct _INMSampled_ipv6 {
  uint32_t length;       /* The length of the IP packet
			     excluding lower layer encapsulations */
  uint32_t protocol;     /* IP Protocol type (for example, TCP = 6, UDP = 17) */
  SFLIPv6 src_ip; /* Source IP Address */
  SFLIPv6 dst_ip; /* Destination IP Address */
  uint32_t src_port;     /* TCP/UDP source port number or equivalent */
  uint32_t dst_port;     /* TCP/UDP destination port number or equivalent */
  uint32_t tcp_flags;    /* TCP flags */
  uint32_t tos;          /* IP type of service */
} INMSampled_ipv6;


/* Packet data */

enum INMPacket_information_type {
  INMPACKETTYPE_HEADER  = 1,      /* Packet headers are sampled */
  INMPACKETTYPE_IPV4    = 2,      /* IP version 4 data */
  INMPACKETTYPE_IPV6    = 3       /* IP version 4 data */
};

typedef union _INMPacket_data_type {
  INMSampled_header header;
  INMSampled_ipv4 ipv4;
  INMSampled_ipv6 ipv6;
} INMPacket_data_type;

/* Extended data types */

/* Extended switch data */

typedef struct _INMExtended_switch {
  uint32_t src_vlan;       /* The 802.1Q VLAN id of incomming frame */
  uint32_t src_priority;   /* The 802.1p priority */
  uint32_t dst_vlan;       /* The 802.1Q VLAN id of outgoing frame */
  uint32_t dst_priority;   /* The 802.1p priority */
} INMExtended_switch;

/* Extended router data */

typedef struct _INMExtended_router {
  INMAddress nexthop;               /* IP address of next hop router */
  uint32_t src_mask;               /* Source address prefix mask bits */
  uint32_t dst_mask;               /* Destination address prefix mask bits */
} INMExtended_router;

/* Extended gateway data */

enum INMExtended_as_path_segment_type {
  INMEXTENDED_AS_SET = 1,      /* Unordered set of ASs */
  INMEXTENDED_AS_SEQUENCE = 2  /* Ordered sequence of ASs */
};
  
typedef struct _INMExtended_as_path_segment {
  uint32_t type;   /* enum INMExtended_as_path_segment_type */
  uint32_t length; /* number of AS numbers in set/sequence */
  union {
    uint32_t *set;
    uint32_t *seq;
  } as;
} INMExtended_as_path_segment;

/* note: the INMExtended_gateway structure has changed between v2 and v4.
   Here is the old version first... */

typedef struct _INMExtended_gateway_v2 {
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_length;             /* number of AS numbers in path */
  uint32_t *dst_as_path;
} INMExtended_gateway_v2;

/* now here is the new version... */

typedef struct _INMExtended_gateway_v4 {
  uint32_t as;                             /* AS number for this gateway */
  uint32_t src_as;                         /* AS number of source (origin) */
  uint32_t src_peer_as;                    /* AS number of source peer */
  uint32_t dst_as_path_segments;           /* number of segments in path */
  INMExtended_as_path_segment *dst_as_path; /* list of seqs or sets */
  uint32_t communities_length;             /* number of communities */
  uint32_t *communities;                   /* set of communities */
  uint32_t localpref;                      /* LocalPref associated with this route */
} INMExtended_gateway_v4;

/* Extended user data */
typedef struct _INMExtended_user {
  uint32_t src_user_len;
  char *src_user;
  uint32_t dst_user_len;
  char *dst_user;
} INMExtended_user;
enum INMExtended_url_direction {
  INMEXTENDED_URL_SRC = 1, /* URL is associated with source address */
  INMEXTENDED_URL_DST = 2  /* URL is associated with destination address */
};

typedef struct _INMExtended_url {
  uint32_t direction; /* enum INMExtended_url_direction */
  uint32_t url_len;
  char *url;
} INMExtended_url;

/* Extended data */

enum INMExtended_information_type {
  INMEXTENDED_SWITCH    = 1,      /* Extended switch information */
  INMEXTENDED_ROUTER    = 2,      /* Extended router information */
  INMEXTENDED_GATEWAY   = 3,      /* Extended gateway router information */
  INMEXTENDED_USER      = 4,      /* Extended TACAS/RADIUS user information */
  INMEXTENDED_URL       = 5       /* Extended URL information */
};

/* Format of a single sample */

typedef struct _INMFlow_sample {
  uint32_t sequence_number;      /* Incremented with each flow sample
				     generated */
  uint32_t source_id;            /* fsSourceId */
  uint32_t sampling_rate;        /* fsPacketSamplingRate */
  uint32_t sample_pool;          /* Total number of packets that could have been
				     sampled (i.e. packets skipped by sampling
				     process + total number of samples) */
  uint32_t drops;                /* Number of times a packet was dropped due to
				     lack of resources */
  uint32_t input;                /* SNMP ifIndex of input interface.
				     0 if interface is not known. */
  uint32_t output;               /* SNMP ifIndex of output interface,
				     0 if interface is not known.
				     Set most significant bit to indicate
				     multiple destination interfaces
				     (i.e. in case of broadcast or multicast)
				     and set lower order bits to indicate
				     number of destination interfaces.
				     Examples:
				     0x00000002  indicates ifIndex = 2
				     0x00000000  ifIndex unknown.
				     0x80000007  indicates a packet sent
				     to 7 interfaces.
				     0x80000000  indicates a packet sent to
				     an unknown number of
				     interfaces greater than 1.*/
  uint32_t packet_data_tag;       /* enum INMPacket_information_type */
  INMPacket_data_type packet_data; /* Information about sampled packet */

  /* in the sFlow packet spec the next field is the number of extended objects
     followed by the data for each one (tagged with the type).  Here we just
     provide space for each one, and flags to enable them.  The correct format
     is then put together by the serialization code */
  int gotSwitch;
  INMExtended_switch switchDevice;
  int gotRouter;
  INMExtended_router router;
  int gotGateway;
  union {
    INMExtended_gateway_v2 v2;  /* make the version explicit so that there is */
    INMExtended_gateway_v4 v4;  /* less danger of mistakes when upgrading code */
  } gateway;
  int gotUser;
  INMExtended_user user;
  int gotUrl;
  INMExtended_url url;
} INMFlow_sample;

/* Counter types */

/* Generic interface counters - see RFC 1573, 2233 */

typedef struct _INMIf_counters {
  uint32_t ifIndex;
  uint32_t ifType;
  uint64_t ifSpeed;
  uint32_t ifDirection;        /* Derived from MAU MIB (RFC 2239)
				   0 = unknown, 1 = full-duplex,
				   2 = half-duplex, 3 = in, 4 = out */
  uint32_t ifStatus;           /* bit field with the following bits assigned:
				   bit 0 = ifAdminStatus (0 = down, 1 = up)
				   bit 1 = ifOperStatus (0 = down, 1 = up) */
  uint64_t ifInOctets;
  uint32_t ifInUcastPkts;
  uint32_t ifInMulticastPkts;
  uint32_t ifInBroadcastPkts;
  uint32_t ifInDiscards;
  uint32_t ifInErrors;
  uint32_t ifInUnknownProtos;
  uint64_t ifOutOctets;
  uint32_t ifOutUcastPkts;
  uint32_t ifOutMulticastPkts;
  uint32_t ifOutBroadcastPkts;
  uint32_t ifOutDiscards;
  uint32_t ifOutErrors;
  uint32_t ifPromiscuousMode;
} INMIf_counters;

/* Ethernet interface counters - see RFC 2358 */
typedef struct _INMEthernet_specific_counters {
  uint32_t dot3StatsAlignmentErrors;
  uint32_t dot3StatsFCSErrors;
  uint32_t dot3StatsSingleCollisionFrames;
  uint32_t dot3StatsMultipleCollisionFrames;
  uint32_t dot3StatsSQETestErrors;
  uint32_t dot3StatsDeferredTransmissions;
  uint32_t dot3StatsLateCollisions;
  uint32_t dot3StatsExcessiveCollisions;
  uint32_t dot3StatsInternalMacTransmitErrors;
  uint32_t dot3StatsCarrierSenseErrors;
  uint32_t dot3StatsFrameTooLongs;
  uint32_t dot3StatsInternalMacReceiveErrors;
  uint32_t dot3StatsSymbolErrors;
} INMEthernet_specific_counters;

typedef struct _INMEthernet_counters {
  INMIf_counters generic;
  INMEthernet_specific_counters ethernet;
} INMEthernet_counters;

/* FDDI interface counters - see RFC 1512 */
typedef struct _INMFddi_counters {
  INMIf_counters generic;
} INMFddi_counters;

/* Token ring counters - see RFC 1748 */

typedef struct _INMTokenring_specific_counters {
  uint32_t dot5StatsLineErrors;
  uint32_t dot5StatsBurstErrors;
  uint32_t dot5StatsACErrors;
  uint32_t dot5StatsAbortTransErrors;
  uint32_t dot5StatsInternalErrors;
  uint32_t dot5StatsLostFrameErrors;
  uint32_t dot5StatsReceiveCongestions;
  uint32_t dot5StatsFrameCopiedErrors;
  uint32_t dot5StatsTokenErrors;
  uint32_t dot5StatsSoftErrors;
  uint32_t dot5StatsHardErrors;
  uint32_t dot5StatsSignalLoss;
  uint32_t dot5StatsTransmitBeacons;
  uint32_t dot5StatsRecoverys;
  uint32_t dot5StatsLobeWires;
  uint32_t dot5StatsRemoves;
  uint32_t dot5StatsSingles;
  uint32_t dot5StatsFreqErrors;
} INMTokenring_specific_counters;

typedef struct _INMTokenring_counters {
  INMIf_counters generic;
  INMTokenring_specific_counters tokenring;
} INMTokenring_counters;

/* 100 BaseVG interface counters - see RFC 2020 */

typedef struct _INMVg_specific_counters {
  uint32_t dot12InHighPriorityFrames;
  uint64_t dot12InHighPriorityOctets;
  uint32_t dot12InNormPriorityFrames;
  uint64_t dot12InNormPriorityOctets;
  uint32_t dot12InIPMErrors;
  uint32_t dot12InOversizeFrameErrors;
  uint32_t dot12InDataErrors;
  uint32_t dot12InNullAddressedFrames;
  uint32_t dot12OutHighPriorityFrames;
  uint64_t dot12OutHighPriorityOctets;
  uint32_t dot12TransitionIntoTrainings;
  uint64_t dot12HCInHighPriorityOctets;
  uint64_t dot12HCInNormPriorityOctets;
  uint64_t dot12HCOutHighPriorityOctets;
} INMVg_specific_counters;

typedef struct _INMVg_counters {
  INMIf_counters generic;
  INMVg_specific_counters vg;
} INMVg_counters;

/* WAN counters */

typedef struct _INMWan_counters {
  INMIf_counters generic;
} INMWan_counters;

typedef struct _INMVlan_counters {
  uint32_t vlan_id;
  uint64_t octets;
  uint32_t ucastPkts;
  uint32_t multicastPkts;
  uint32_t broadcastPkts;
  uint32_t discards;
} INMVlan_counters;

/* Counters data */

enum INMCounters_version {
  INMCOUNTERSVERSION_GENERIC      = 1,
  INMCOUNTERSVERSION_ETHERNET     = 2,
  INMCOUNTERSVERSION_TOKENRING    = 3,
  INMCOUNTERSVERSION_FDDI         = 4,
  INMCOUNTERSVERSION_VG           = 5,
  INMCOUNTERSVERSION_WAN          = 6,
  INMCOUNTERSVERSION_VLAN         = 7
};

typedef union _INMCounters_type {
  INMIf_counters generic;
  INMEthernet_counters ethernet;
  INMTokenring_counters tokenring;
  INMFddi_counters fddi;
  INMVg_counters vg;
  INMWan_counters wan;
  INMVlan_counters vlan;
} INMCounters_type;

typedef struct _INMCounters_sample_hdr {
  uint32_t sequence_number;    /* Incremented with each counters sample
				   generated by this source_id */
  uint32_t source_id;          /* fsSourceId */
  uint32_t sampling_interval;  /* fsCounterSamplingInterval */
} INMCounters_sample_hdr;

typedef struct _INMCounters_sample {
  INMCounters_sample_hdr hdr;
  uint32_t counters_type_tag;  /* Enum INMCounters_version */
  INMCounters_type counters;    /* Counter set for this interface type */
} INMCounters_sample;

/* when I turn on optimisation with the Microsoft compiler it seems to change
   the values of these enumerated types and break the program - not sure why */
enum INMSample_types {
   FLOWSAMPLE  = 1,
   COUNTERSSAMPLE = 2
};

typedef union _INMSample_type {
  INMFlow_sample flowsample;
  INMCounters_sample counterssample;
} INMSample_type;

/* Format of a sample datagram */

enum INMDatagram_version {
  INMDATAGRAM_VERSION2 = 2,
  INMDATAGRAM_VERSION4 = 4
};

typedef struct _INMSample_datagram_hdr {
  uint32_t datagram_version;      /* (enum INMDatagram_version) = VERSION4 */
  INMAddress agent_address;        /* IP address of sampling agent */
  uint32_t sequence_number;       /* Incremented with each sample datagram
				      generated */
  uint32_t uptime;                /* Current time (in milliseconds since device
				      last booted). Should be set as close to
				      datagram transmission time as possible.*/
  uint32_t num_samples;           /* Number of flow and counters samples to follow */
} INMSample_datagram_hdr;

#define INM_MAX_DATAGRAM_SIZE 1500
#define INM_MIN_DATAGRAM_SIZE 200
#define INM_DEFAULT_DATAGRAM_SIZE 1400

#define INM_DATA_PAD 400

#if defined(__cplusplus)
}  /* extern "C" */
#endif

#endif /* SFLOWTOOL_H */


typedef struct _SFSample {
  struct in_addr sourceIP;
  SFLAddress agent_addr;
  uint32_t agentSubId;

  /* the raw pdu */
  u_char *rawSample;
  uint32_t rawSampleLen;
  u_char *endp;
  time_t pcapTimestamp;

  /* decode cursor */
  uint32_t *datap;

  uint32_t datagramVersion;
  uint32_t sampleType;
  uint32_t ds_class;
  uint32_t ds_index;

  /* generic interface counter sample */
  SFLIf_counters ifCounters;

  /* sample stream info */
  uint32_t sysUpTime;
  uint32_t sequenceNo;
  uint32_t sampledPacketSize;
  uint32_t samplesGenerated;
  uint32_t meanSkipCount;
  uint32_t samplePool;
  uint32_t dropEvents;

  /* the sampled header */
  uint32_t packet_data_tag;
  uint32_t headerProtocol;
  u_char *header;
  int headerLen;
  uint32_t stripped;

  /* header decode */
  int gotIPV4;
  int gotIPV4Struct;
  int offsetToIPV4;
  int gotIPV6;
  int gotIPV6Struct;
  int offsetToIPV6;
  int offsetToPayload;
  SFLAddress ipsrc;
  SFLAddress ipdst;
  uint32_t dcd_ipProtocol;
  uint32_t dcd_ipTos;
  uint32_t dcd_ipTTL;
  uint32_t dcd_sport;
  uint32_t dcd_dport;
  uint32_t dcd_tcpFlags;
  uint32_t ip_fragmentOffset;
  uint32_t udp_pduLen;

  /* ports */
  uint32_t inputPortFormat;
  uint32_t outputPortFormat;
  uint32_t inputPort;
  uint32_t outputPort;

  /* ethernet */
  uint32_t eth_type;
  uint32_t eth_len;
  u_char eth_src[8];
  u_char eth_dst[8];

  /* vlan */
  uint32_t in_vlan;
  uint32_t in_priority;
  uint32_t internalPriority;
  uint32_t out_vlan;
  uint32_t out_priority;
  int vlanFilterReject;

  /* extended data fields */
  uint32_t num_extended;
  uint32_t extended_data_tag;
#define SASAMPLE_EXTENDED_DATA_SWITCH 1
#define SASAMPLE_EXTENDED_DATA_ROUTER 4
#define SASAMPLE_EXTENDED_DATA_GATEWAY 8
#define SASAMPLE_EXTENDED_DATA_USER 16
#define SASAMPLE_EXTENDED_DATA_URL 32
#define SASAMPLE_EXTENDED_DATA_MPLS 64
#define SASAMPLE_EXTENDED_DATA_NAT 128
#define SASAMPLE_EXTENDED_DATA_MPLS_TUNNEL 256
#define SASAMPLE_EXTENDED_DATA_MPLS_VC 512
#define SASAMPLE_EXTENDED_DATA_MPLS_FTN 1024
#define SASAMPLE_EXTENDED_DATA_MPLS_LDP_FEC 2048
#define SASAMPLE_EXTENDED_DATA_VLAN_TUNNEL 4096

  /* IP forwarding info */
  SFLAddress nextHop;
  uint32_t srcMask;
  uint32_t dstMask;

  /* BGP info */
  SFLAddress bgp_nextHop;
  uint32_t my_as;
  uint32_t src_as;
  uint32_t src_peer_as;
  uint32_t dst_as_path_len;
  uint32_t *dst_as_path;
  /* note: version 4 dst as path segments just get printed, not stored here, however
   * the dst_peer and dst_as are filled in, since those are used for netflow encoding
   */
  uint32_t dst_peer_as;
  uint32_t dst_as;
  
  uint32_t communities_len;
  uint32_t *communities;
  uint32_t localpref;

  /* user id */
#define SA_MAX_EXTENDED_USER_LEN 200
  uint32_t src_user_charset;
  uint32_t src_user_len;
  char src_user[SA_MAX_EXTENDED_USER_LEN+1];
  uint32_t dst_user_charset;
  uint32_t dst_user_len;
  char dst_user[SA_MAX_EXTENDED_USER_LEN+1];

  /* url */
#define SA_MAX_EXTENDED_URL_LEN 200
#define SA_MAX_EXTENDED_HOST_LEN 200
  uint32_t url_direction;
  uint32_t url_len;
  char url[SA_MAX_EXTENDED_URL_LEN+1];
  uint32_t host_len;
  char host[SA_MAX_EXTENDED_HOST_LEN+1];

  /* mpls */
  SFLAddress mpls_nextHop;

  /* nat */
  SFLAddress nat_src;
  SFLAddress nat_dst;

  /* counter blocks */
  uint32_t statsSamplingInterval;
  uint32_t counterBlockVersion;

# define SFABORT(s, r) abort()

} SFSample;

static uint32_t SFGetData32_nobswap(SFSample *sample) {
  uint32_t ans = *(sample->datap)++;

  if((u_char *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
  return ans;
}

static uint32_t SFGetData32(SFSample *sample) {
  return ntohl(SFGetData32_nobswap(sample));
}

static float SFGetFloat(SFSample *sample) {
  float fl;
  uint32_t reg = SFGetData32(sample);
  memcpy(&fl, &reg, 4);
  return fl;
}

static uint64_t SFGetData64(SFSample *sample) {
  uint64_t tmpLo, tmpHi;
  tmpHi = SFGetData32(sample);
  tmpLo = SFGetData32(sample);
  return (tmpHi << 32) + tmpLo;
}

static void SFSkipBytes(SFSample *sample, uint32_t skip) {
  int quads = (skip + 3) / 4;
  sample->datap += quads;
  if(skip > sample->rawSampleLen || (u_char *)sample->datap > sample->endp) {
    SFABORT(sample, SF_ABORT_EOS);
  }
}

static uint32_t SFGetString(SFSample *sample, char *buf, uint32_t bufLen) {
  uint32_t len, read_len;
  len = SFGetData32(sample);
  // truncate if too long
  read_len = (len >= bufLen) ? (bufLen - 1) : len;
  memcpy(buf, sample->datap, read_len);
  buf[read_len] = '\0';   // null terminate
  SFSkipBytes(sample, len);
  return len;
}


static uint32_t SFGetAddress(SFSample *sample, SFLAddress *address) {
  address->type = SFGetData32(sample);
  if(address->type == SFLADDRESSTYPE_IP_V4)
    address->address.ip_v4.addr = SFGetData32_nobswap(sample);
  else {
    memcpy(&address->address.ip_v6.addr, sample->datap, 16);
    SFSkipBytes(sample, 16);
  }
  return address->type;
}
