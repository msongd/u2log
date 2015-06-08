package main
import (
	"io"
//        "bufio"
)

const OP_MODE_SINGLE = 0
const OP_MODE_SPOOL  = 1


const UNIFIED2_EVENT = 1

//CURRENT
const UNIFIED2_PACKET = 2
const UNIFIED2_IDS_EVENT = 7
const UNIFIED2_IDS_EVENT_IPV6 = 72
const UNIFIED2_IDS_EVENT_MPLS = 99
const UNIFIED2_IDS_EVENT_IPV6_MPLS = 100
const UNIFIED2_IDS_EVENT_VLAN = 104
const UNIFIED2_IDS_EVENT_IPV6_VLAN = 105
const UNIFIED2_EXTRA_DATA = 110

const UNIFIED2_IDS_EVENT_APPID = 111
const UNIFIED2_IDS_EVENT_APPID_IPV6 = 112

const UNIFIED2_IDS_EVENT_APPSTAT = 113

const MAX_EVENT_APPNAME_LEN = 16

type Serial_Unified2_Header struct {
        Type   uint32
        Length uint32
}

type Unified2_Packet struct {
        Type   uint32
        Length uint32
        Data   []byte
}

//UNIFIED2_IDS_EVENT_VLAN = type 104
//comes from SFDC to EStreamer archive in serialized form with the extended header
type Unified2IDSEvent struct {
        Sensor_id          uint32
        Event_id           uint32
        Event_second       uint32
        Event_microsecond  uint32
        Signature_id       uint32
        Generator_id       uint32
        Signature_revision uint32
        Classification_id  uint32
        Priority_id        uint32
        Ip_source          [4]byte
        Ip_destination     [4]byte
        Sport_itype        uint16
        Dport_icode        uint16
        Protocol           uint8
        Impact_flag        uint8 //overloads packet_action
        Impact             uint8
        Blocked            uint8
        Mpls_label         uint32
        VlanId             uint16
        Pad2               uint16 //Policy ID
}
//UNIFIED2_IDS_EVENT_APPID = type 111
type Unified2IDSEventAppId struct {
        Unified2IDSEvent
        App_name           [MAX_EVENT_APPNAME_LEN]byte
}

//UNIFIED2_IDS_EVENT_IPV6_VLAN = type 105
type Unified2IDSEventIPv6 struct {
        Sensor_id          uint32
        Event_id           uint32
        Event_second       uint32
        Event_microsecond  uint32
        Signature_id       uint32
        Generator_id       uint32
        Signature_revision uint32
        Classification_id  uint32
        Priority_id        uint32
        Ip_source          [16]byte
        Ip_destination     [16]byte
        Sport_itype        uint16
        Dport_icode        uint16
        Protocol           uint8
        Impact_flag        uint8
        Impact             uint8
        Blocked            uint8
        Mpls_label         uint32
        VlanId             uint16
        Pad2               uint16 /*could be IPS Policy local id to support local sensor alerts*/
}
//UNIFIED2_IDS_EVENT_IPV6_APPID = type 112
type Unified2IDSEventIPv6AppId struct {
        Unified2IDSEventIPv6
        App_name           [MAX_EVENT_APPNAME_LEN]byte
}

//UNIFIED2_PACKET = type 2
type Serial_Unified2Packet struct {
        Sensor_id          uint32
        Event_id           uint32
        Event_second       uint32
        Packet_second      uint32
        Packet_microsecond uint32
        Linktype           uint32
        Packet_length      uint32
//        Packet_data        [4]byte
}

type Unified2ExtraDataHdr struct {
        Event_type   uint32
        Event_length uint32
}

//UNIFIED2_EXTRA_DATA - type 110
type SerialUnified2ExtraData struct {
        Sensor_id    uint32
        Event_id     uint32
        Event_second uint32
        Type         uint32 /* EventInfo */
        Data_type    uint32 /*EventDataType */
        Blob_length  uint32 /* Length of the data + sizeof(blob_length) + sizeof(data_type)*/
}

type Data_Blob struct {
        Length uint32
        Data   []byte
}

//UNIFIED2_EXTRA_DATA - type 110
type Serial_Unified2ExtraData struct {
        Sensor_id    uint32
        Event_id     uint32
        Event_second uint32
        Type         uint32
        data         Data_Blob
}

const (
        EVENT_INFO_XFF_IPV4        = 1
        EVENT_INFO_XFF_IPV6        = 2
        EVENT_INFO_REVIEWED_BY     = 3
        EVENT_INFO_GZIP_DATA       = 4
        EVENT_INFO_SMTP_FILENAME   = 5
        EVENT_INFO_SMTP_MAILFROM   = 6
        EVENT_INFO_SMTP_RCPTTO     = 7
        EVENT_INFO_SMTP_EMAIL_HDRS = 8
        EVENT_INFO_HTTP_URI        = 9
        EVENT_INFO_HTTP_HOSTNAME   = 10
        EVENT_INFO_IPV6_SRC        = 11
        EVENT_INFO_IPV6_DST        = 12
        EVENT_INFO_JSNORM_DATA     = 13
)

const (
        EVENT_DATA_TYPE_BLOB = 1
        EVENT_DATA_TYPE_MAX  = 2
)

const EVENT_TYPE_EXTRA_DATA = 4

const ETH_HEADER_SIZE = 14
type EthHeader struct {
  SrcMac [6]byte
  DstMac [6]byte
  EthType uint16
}

const IP4_HEADER_SIZE_BASIC = 20
type Ipv4Header struct {
  Byte1 byte
  Byte2 byte
  PacketLen uint16
  ID    uint16
  Byte3 byte
  Byte4 byte
  TTL   byte
  Proto byte
  Chksum uint16
  SrcIP [4]byte
  DstIP [4]byte
}

var U2ExtraTypeMap = map[uint32] string { 
 EVENT_INFO_XFF_IPV4 :       "Original Client IPv4" ,
 EVENT_INFO_XFF_IPV6 :       "Original Client IPv6",
 EVENT_INFO_REVIEWED_BY   :       "UNUSED",
 EVENT_INFO_GZIP_DATA     :       "GZIP Decompressed Data",
 EVENT_INFO_SMTP_FILENAME :  "SMTP Filename",
 EVENT_INFO_SMTP_MAILFROM   :    "SMTP Mail From",
 EVENT_INFO_SMTP_RCPTTO      :   "SMTP RCPT To",
 EVENT_INFO_SMTP_EMAIL_HDRS  :  "SMTP Email Headers",
 EVENT_INFO_HTTP_URI      :  "HTTP URI",
 EVENT_INFO_HTTP_HOSTNAME     :  "HTTP Hostname",
 EVENT_INFO_IPV6_SRC       :  "IPv6 Source Address",
 EVENT_INFO_IPV6_DST       :  "IPv6 Destination Address",
 EVENT_INFO_JSNORM_DATA       :  "Normalized Javascript Data",
}

type RawPacket struct {
  Serial_Unified2Packet
  EthHeader
  Ipv4Header
  Data []byte
}

//UNIFIED2_IDS_EVENT_IPV6_VLAN = type 200
type Serial_Unified2AppStat struct {
        Event_second uint32
        AppCnt       uint32
}

type Unified2FormatParser struct {
     Reader   *io.Reader
}

type Unified2ExtraData struct {
  Unified2ExtraDataHdr
  SerialUnified2ExtraData
  Data []byte
}

type SnortEventIpv4AppId struct {
  Unified2IDSEventAppId
  Packets []RawPacket
  ExtraData []Unified2ExtraData
}

type PrettyUnified2ExtraData struct {
        Sensor_id    uint32
        Event_id     uint32
        Second uint32
        Type         uint32 /* EventInfo */
        Data_type    uint32 /*EventDataType */
  		Data string
}

type PrettySnortEventIpv4AppId struct {
        Sensor_id          uint32
        Event_id           uint32
        Second       uint32
        Microsecond  uint32
        Sig_id       uint32
        Gen_id       uint32
        Sig_rev uint32
        Cls_id  uint32
        Pri_id        uint32
        Ip_src     string
        Ip_dst     string
        Sport        uint16
        Dport        uint16
        Proto           uint8
        Impact_flag        uint8 //overloads packet_action
        Impact             uint8
        Blocked            uint8
        Mpls_label         uint32
        VlanId             uint16
        Pad2               uint16 //Policy ID
        App           string
  Packets []RawPacket
  ExtraData []PrettyUnified2ExtraData
}

type SnortEventIpv6AppId struct {
}

type Waldo struct {
  Filename string
  Location int64
}

type U2FileConsumer func(io.Reader, io.Writer, string) error

