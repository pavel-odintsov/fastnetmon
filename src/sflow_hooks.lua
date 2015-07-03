local json = require("json")

-- We have this library bundled only in luajit:
-- g++ lua_integration.cpp -lluajit-5.1

-- Before production use, please call your code with luajit CLI
local ffi = require("ffi")

-- Load declaration from the inside separate header file
-- This code should be in sync with https://github.com/FastVPSEestiOu/fastnetmon/blob/master/src/sflow_plugin/sflow_data.h
-- We have changed all defines to actual values
ffi.cdef([[
typedef unsigned char u_char;
typedef long time_t;

typedef struct _SFLIf_counters {
    uint32_t ifIndex;
    uint32_t ifType;
    uint64_t ifSpeed;
    uint32_t ifDirection; /* Derived from MAU MIB (RFC 2668)
              0 = unknown, 1 = full-duplex,
              2 = half-duplex, 3 = in, 4 = out */
    uint32_t ifStatus; /* bit field with the following bits assigned:
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

typedef struct { uint32_t addr; } SFLIPv4;

typedef struct { u_char addr[16]; } SFLIPv6;

typedef union _SFLAddress_value {
    SFLIPv4 ip_v4;
    SFLIPv6 ip_v6;
} SFLAddress_value;

typedef struct _SFLAddress {
    uint32_t type; /* enum SFLAddress_type */
    SFLAddress_value address;
} SFLAddress;
typedef struct _SFSample {
    SFLAddress sourceIP;
    SFLAddress agent_addr;
    uint32_t agentSubId;

    /* the raw pdu */
    uint8_t* rawSample;
    uint32_t rawSampleLen;
    uint8_t* endp;
    time_t pcapTimestamp;

    /* decode cursor */
    uint32_t* datap;

    uint32_t datagramVersion;
    uint32_t sampleType;
    uint32_t elementType;
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
    uint8_t* header;
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
    uint8_t eth_src[8];
    uint8_t eth_dst[8];

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
    uint32_t* dst_as_path;
    /* note: version 4 dst as path segments just get printed, not stored here, however
    * the dst_peer and dst_as are filled in, since those are used for netflow encoding
    */
    uint32_t dst_peer_as;
    uint32_t dst_as;

    uint32_t communities_len;
    uint32_t* communities;
    uint32_t localpref;

/* user id */
    uint32_t src_user_charset;
    uint32_t src_user_len;
    char src_user[200 + 1];
    uint32_t dst_user_charset;
    uint32_t dst_user_len;
    char dst_user[200 + 1];

/* url */
    uint32_t url_direction;
    uint32_t url_len;
    char url[200 + 1];
    uint32_t host_len;
    char host[200 + 1];

    /* mpls */
    SFLAddress mpls_nextHop;

    /* nat */
    SFLAddress nat_src;
    SFLAddress nat_dst;

    /* counter blocks */
    uint32_t statsSamplingInterval;
    uint32_t counterBlockVersion;

    /* exception handler context */
    //jmp_buf env;
} SFSample;
]])

-- Load json file once
local json_file = io.open("/usr/src/fastnetmon/src/tests/netflow_exclude.json", "r")
local decoded = json.decode(json_file:read("*all"))


function process_sflow(flow_agent_ip, flow)
    local sflow_t = ffi.typeof('SFSample*')
    local lua_sflow = ffi.cast(sflow_t, flow)

    --print ("We got this packets from: ", flow_agent_ip)
    -- TODO: PLEASE BE AWARE! Thid code will read json file for every packet
    --print ("Flow packets and bytes: ", lua_flow.flow_packets, lua_flow.flow_octets)
    print ("Agent IP", flow_agent_ip," in interface :", lua_sflow.inputPort, " out interface: ", lua_sflow.outputPort)

    for agent_ip, ports_table in pairs(decoded) do
        if agent_ip == flow_agent_ip then
            for port_number, port_description in pairs(ports_table) do
                if lua_sflow.outputPort == port_number then
                    -- We found this port in ignore list
                    return false
                end 
            end
        end
    end

    --for k,v in pairs(decoded) do 
    --    for kk, vv in pairs(v) do
    --        --print(k, kk, vv)
    --    end
    --end

    return true
end
