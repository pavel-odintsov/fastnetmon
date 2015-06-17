### This article will describe everything about sFLOW from hardware side

Please be aware! Extreme XOS operating system before 15.4 release lack of support for ingress sflow, only for egress ([source](http://extrcdn.extremenetworks.com/wp-content/uploads/2014/01/EXOS_Command_Reference_Guide_15_4.pdf)). Please use 15.4 version or more recent.

Example of sFLOW configuration for Extreme XOS:
```bash
configure sflow collector 10.0.2.33 port 6343 vr "VR-Default" # add collector
configure sflow agent 10.0.2.15 # agent address
configure sflow poll-interval 1 # send data to collector once per second 
configure sflow sample-rate 1024 # sampling rate
enable sflow ports 1:39,1:40,2:39 both # add ports to sFLOW monitoring for egress and ingress traffic.
enable sflow #  enable sflow globally
```

Check configuration for correctness:
```bash
show sflow
 
SFLOW Global Configuration
Global Status: enabled
Polling interval: 1
Sampling rate: 2048
Maximum cpu sample limit: 2000
SFLOW Configured Agent IP: 10.0.2.15 Operational Agent IP: 10.0.2.15
Collectors
Collector IP 10.0.2.33, Port 6343, VR "VR-Default"
SFLOW Port Configuration
Port      Status           Sample-rate         Subsampling
                       Config   /  Actual      factor     
1:39      enabled     1024      /  1024         1             
1:40      enabled     1024      /  1024         1             
2:39      enabled     1024      /  1024         1
```
