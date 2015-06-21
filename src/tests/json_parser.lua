local json = require("json")

-- We have this library bundled only in luajit:
-- g++ lua_integration.cpp -lluajit-5.1
local ffi = require("ffi")

-- Load declaration from the inside separate header file
ffi.cdef("typedef struct netflow_struct { int packets; int bytes; } netflow_t;")

function process_netflow(flow)
    local netlflow_t = ffi.typeof('netflow_t*')
    local lua_flow = ffi.cast(netlflow_t, flow)

    print ("Function param: ", lua_flow.packets, lua_flow.bytes)
    local json_file = io.open("netflow_exclude.json", "r")
    
    local decoded = json.decode(json_file:read("*all"))

    for k,v in pairs(decoded) do 
        for kk, vv in pairs(v) do
            --print(k, kk, vv)
        end
    end

    return true
end

-- process_netflow("test")
