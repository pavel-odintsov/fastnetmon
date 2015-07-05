if #main.parameters ~= 2 then
   print([[Usage: capture2c <pciaddress> <my.so>

Capture network traffic from an Intel 82599 NIC at <pciaddress> and
pass each packet to a callback function defined in the shared library
<my.so>.

The callback function signature is:

  void packet(char *data, int length);]])
      os.exit(1)
end

local pciaddr, sofile = unpack(main.parameters)

-- Load shared object
print("Loading shared object: "..sofile)
local ffi = require("ffi")
local so = ffi.load(sofile)
ffi.cdef("void packet(char *data, int length);")
ffi.cdef("void run_speed_printer();");

-- Initialize a device driver
print("Initializing NIC: "..pciaddr)
local intel10g = require("apps.intel.intel10g")
-- Maximum buffers to avoid packet drops
intel10g.num_descriptors = 32*1024
local nic = intel10g.new_sf({pciaddr=pciaddr})
nic:open()

print("Run speed printer from C code")
so.run_speed_printer()

-- Process traffic in infinite loop
print("Processing traffic...")
while true do
   -- Fill up the NIC with receive buffers
   while nic:can_add_receive_buffer() do
      nic:add_receive_buffer(packet.allocate())
   end

   -- Process packets via callback.
   while nic:can_receive() do
      local p = nic:receive()
      so.packet(p.data, p.length)
      packet.free(p)
   end
   -- Update hardware ring
   nic:sync_receive()
end
