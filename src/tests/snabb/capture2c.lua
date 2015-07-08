if #main.parameters ~= 2 and #main.parameters ~= 3 then
   print([[Usage: capture2c <pciaddress>[,<pciaddress>...] <callback.so> [npackets]

Capture network traffic from one or more Intel 82599 NICs
(comma-separated "pciaddress" list) and pass each packet to a callback
function defined in a shared library "callback.so".

The optional "npackets" parameter sets the number of packets in the
hardware receive queue. This may (or my not) be interesting for
performance tuning.
]])
      os.exit(1)
end

local pciaddresses, sofile, npackets = unpack(main.parameters)
npackets = tonumber(npackets) or 32*1024

-- Load shared object
print("Loading shared object: "..sofile)
local ffi = require("ffi")
local so = ffi.load(sofile)
ffi.cdef[[
int process_packets(char **packets, void *rxring, int ring_size, int index, int max);
void run_speed_printer();
]]

-- Array where we store a function for each NIC that will process the traffic.
local run_functions = {}

for pciaddr in pciaddresses:gmatch("[0-9:.]+") do

   -- Initialize a device driver
   print("Initializing NIC: "..pciaddr)

   local pci = require("lib.hardware.pci")
   pci.unbind_device_from_linux(pciaddr) -- make kernel/ixgbe release this device

   local intel10g = require("apps.intel.intel10g")
   -- Maximum buffers to avoid packet drops
   intel10g.num_descriptors = npackets
   local nic = intel10g.new_sf({pciaddr=pciaddr})
   nic:open()

   -- Traffic processing
   --
   -- We are using a special-purpose receive method designed for fast
   -- packet capture:
   --
   --   Statically allocate all packet buffers.
   --
   --   Statically initialize the hardware RX descriptor ring to point to
   --   the preallocated packets.
   --
   --   Have the C callback loop directly over the RX ring to process the
   --   packets that are ready.
   --
   -- This means that no work is done to allocate and free buffers or to
   -- write new descriptors to the RX ring. This is expected to have
   -- extremely low overhead to recieve each packet.

   -- Set NIC to "legacy" descriptor format. In this mode the NIC "write
   -- back" does not overwrite the address stored in the descriptor and
   -- so this can be reused. See 82599 datasheet section 7.1.5.
   nic.r.SRRCTL(10 + bit.lshift(1, 28))
   -- Array of packet data buffers. This will be passed to C.
   local packets = ffi.new("char*[?]", npackets)
   for i = 0, npackets-1 do
      -- Statically allocate a packet and put the address in the array
      local p = packet.allocate()
      packets[i] = p.data
      -- Statically allocate the matching hardware receive descriptor
      nic.rxdesc[i].data.address = memory.virtual_to_physical(p.data)
      nic.rxdesc[i].data.dd = 0
   end
   nic.r.RDT(npackets-1)

   local index = 0                 -- ring index of next packet
   local rxring = nic.rxdesc._ptr
   local ring_size = npackets
   local run = function ()
      local npackets = bit.band(npackets + nic.r.RDH() - nic.r.RDT())
      if npackets > 0 then
         -- Performance note: it is helpful that we pass 'npackets' to
         -- tell the C callback how many packets to process before it
         -- stops. If the callback does not have this limit then it can
         -- slow down the NIC by processing packets too quickly. (I think
         -- the issue is write/write conflicts when the CPU and the NIC
         -- are both updating receive descriptors that are too close
         -- together i.e. on the same cache line. -lukego)
         index = so.process_packets(packets, rxring, ring_size, index, npackets)
         nic.r.RDT(index==0 and npackets or index-1)
      end
   end
   table.insert(run_functions, run)
end

print("Run speed printer from C code")
so.run_speed_printer()

-- Process traffic in infinite loop
print("Processing traffic...")

while true do
   for i = 1, #run_functions do
      -- Run the traffic processing function for each NIC.
      run_functions[i]()
   end
end

