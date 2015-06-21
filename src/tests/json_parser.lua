-- apt-get install -y lua5.2 lua-json liblua5.2-dev 

function process_netflow(flow)  
    local json = require("json")

    local json_file = io.open("netflow_exclude.json", "r")
    
    local decoded = json.decode(json_file:read("*all"))

    for k,v in pairs(decoded) do 
        for kk, vv in pairs(v) do
            print(k, kk, vv)
        end
    end
end

process_netflow("test")
