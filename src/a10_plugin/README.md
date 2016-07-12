Fastnetmon Plugin:  A10 Networks TPS AXAPIv3 integration for FastNetMon  

This script connect to A10 TPS device to create Protected Object and announce BGP route toward upstream router upon FastNetMon ban detection. 

1. Place both Python files at a directory that is reachable by FastNetMon
2. Make sure both scripts are executable, i.e. "chmod +x a10.py fastnetmon_a10_v0.2.py"
3. Modify fastnetmon.conf for notification, i.e. notify_script_path = <path>/fastnetmon_a10_v0.2.py

Please modify the following: 

1. A10 mitigator IP
2. BGP Autonomous System Number
3. Username and Password for your A10 Device. Note that you can use your own password vault or protection schema

For more information about A10 Networks AXAPIv3: 
https://www.a10networks.com/resources/glossary/axapi-custom-management


v0.2 - Jul 7th, 2016 - initial commit

Author: Eric Chou ericc@a10networks.com

Feedback and Feature Requests are Welcomed. 

Example Usage: 

- Ban action: 

```
a10-ubuntu3:~/fastnetmon/src/a10_plugin$ sudo python fastnetmon_a10_v0.2.py "10.10.10.10" "outgoing" "111111" "ban"

TH4435-1#show ddos dst zone all-entries
Legend (Rate/Limit): 'U'nlimited, 'E'xceeded, '-' Not applicable
Legend (State)     : 'W'hitelisted, 'B'lacklisted, 'P'ermitted, black'H'oled, 'I'dle, 'L'earning, 'M'onitoring, '-' Regular mode
Zone Name / Zone Service Info               | [State]| Curr Conn| Conn Rate| Pkt Rate | kBit Rate|Frag Pkt R|Sources # |Age |LockU
                                            |        |     Limit|     Limit|     Limit|     Limit|     Limit|     Limit|#min| Time
-----------------------------------------------------------------------------------------------------------------------------------
10.10.10.10_zone                                  [M]         U          U          U          U          U               1S     0
                                                    -         U          U          U          U          U
Displayed Entries:  1
Displayed Services: 0

TH4435-1#sh run router bgp
!Section configuration: 221 bytes
!
router bgp 64513
  <skip>
  network 10.10.10.10/32
  <skip>
!
TH4435-1#
TH4435-1#sh run router bgp | i 10.10.10.10
  network 10.10.10.10/32
TH4435-1#
```

- Unban action: 

a10-ubuntu3:~/fastnetmon/src/a10_plugin$ sudo python fastnetmon_a10_v0.2.py "10.10.10.10" "outgoing" "111111" "unban"

```
TH4435-1#sh run router bgp | i 10.10.10.10
TH4435-1#
```




