package.path = package.path .. ";/usr/share/lua/5.1/?.lua"

local json = require("json")

-- We have this library bundled only in luajit:
-- g++ lua_integration.cpp -lluajit-5.1

-- Before production use, please call your code with luajit CLI
local ffi = require("ffi")

-- Load declaration from the inside separate header file
-- This code should be in sync with https://github.com/FastVPSEestiOu/fastnetmon/blob/master/src/netflow_plugin/netflow.h
-- And we use uintXX_t instead u_intXX_t here
ffi.cdef([[typedef struct __attribute__((packed)) NF5_FLOW {
    uint32_t src_ip, dest_ip, nexthop_ip;
    uint16_t if_index_in, if_index_out;
    uint32_t flow_packets, flow_octets;
    uint32_t flow_start, flow_finish;
    uint16_t src_port, dest_port;
    uint8_t pad1;
    uint8_t tcp_flags, protocol, tos;
    uint16_t src_as, dest_as;
    uint8_t src_mask, dst_mask;
    uint16_t pad2;
} NF5_FLOW_t;]])

-- Load json file once
local json_file = io.open("/usr/src/fastnetmon/src/tests/netflow_exclude.json", "r")
local decoded = json.decode(json_file:read("*all"))

--for k, v in pairs(decoded) do  
--    for kk, vv in pairs(v) do
--        print(k, kk, vv) 
--    end 
--end 

function process_netflow(flow_agent_ip, flow)
    local netlflow5_t = ffi.typeof('NF5_FLOW_t*')
    local lua_flow = ffi.cast(netlflow5_t, flow)

    --print ("We got this packets from: ", flow_agent_ip)
    -- TODO: PLEASE BE AWARE! Thid code will read json file for every netflow packet
    --print ("Flow packets and bytes: ", lua_flow.flow_packets, lua_flow.flow_octets)
    --print ("In interface :", lua_flow.if_index_in, " out interface: ", lua_flow.if_index_out)

    for agent_ip, ports_table in pairs(decoded) do
        if agent_ip == flow_agent_ip then
            for port_number, port_description in pairs(ports_table) do
                if lua_flow.if_index_in == port_number then
                    -- We found this port in ignore list
                    return false
                end 
            end
        end
    end

    return true
end
