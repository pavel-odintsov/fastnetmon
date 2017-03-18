#A10 Networks Thunder TPS Appliance AXAPIv3 integration for FastNetMon  

##Prerequisites: 

  1. A10 Thunder TPS with AXAPIv3. More information on AXAPIv3: https://www.a10networks.com/resources/glossary/axapi-custom-management.
  2. Network topology is Asymmetric Reactive with BGP as the routing Protocol. A10 Thunder TPS peers with the upstream router. 
  3. TPS contains base config under /fastnetmon/src/a10_plugin/configs/tps_base_config_vX.txt for base glid, zone-template, and ddos protection rate-interval, etc. 

##Overview:
 
  1. This script connect to A10 Thunder TPS Appliance via AXAPIv3 to create Protected Object.
  2. The traffic is onramped via announce BGP route toward upstream router upon FastNetMon ban detection. 
  3. The BGP route is withdrawn upon unban instruction from FastNetMon.
  4. [Important] Please note that the script works in conjection with the tps_base_config_v[xx].txt and tps_zone_config_v[xx].txt files. For example, the script assumes the 'bgp advertised' command is configured under 'ddos dst zone' to advertise the BGP route. Please consult with www.a10networks.com for the latest commands and configuration guides.   
  4.1 As a matter of reference, the tps_base_config and tps_zone_config configuration files were provided in .txt format under configs/ folder as well as in JSon format under json_configs/ folder. But the assumption is they were pre-configured prior to FastNetMon ban/unban actions.  
  5. Log of the script is keep under /var/log/fastnetmon-notify.log. 

##Configuration Steps: 

  0. If this is a brand new TPS with no prior 'ddos dst zone' config, do a quick dummy zone config and remove it: 
```
TH3030S-1(config)#ddos dst zone dummy
TH3030S-1(config-ddos zone)#exit
TH3030S-1(config)#no ddos dst zone dummy
TH3030S-1(config)#end
TH3030S-1#
```
  1. Configure the fastnetmon_a10_xx.py script as the executed script under /etc/fastnetmon.conf, i.e. notify_script_path=<path>/fastnetmon_a10_v0.3.py.
  2. Please note that we have various versions of ban actions depending on your topology, such as integration of aGalaxy. 
  3. Alternatively place all files in a directory that is reachable by FastNetMon and indicate it as the executed script in /etc/fastnetmon.conf.
  4. Make sure both Python scripts are executable, i.e. "chmod +x a10.py fastnetmon_a10_v0.3.py"

##Please modify the following in the fastnetmon_a10_v[xx].py script 

  1. A10 Thunder TPS mitigator IP.
  2. Username and Password for your A10 Device. Please follow your own password vault or other security schema.

Author: Eric Chou ericc@a10networks.com, Rich Groves rgroves@a10networks.com

Feedback and Feature Requests are Appreciated and Welcomed. 

Example Usage: 

- Ban action: 

```
a10-ubuntu3:~/fastnetmon/src/a10_plugin$ sudo python fastnetmon_a10_v0.3.py "10.10.10.10" "outgoing" "111111" "ban"

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


TH4435#sh ip bgp neighbors <upstream router IP> advertised-routes

```

- Unban action: 

a10-ubuntu3:~/fastnetmon/src/a10_plugin$ sudo python fastnetmon_a10_v0.3.py "10.10.10.10" "outgoing" "111111" "unban"

```
TH4435-1#sh ip bgp neighbors <upstream router IP> advertised-routes
TH4435-1#
```

## Notes

  1. In a10.py, SSL ssl._create_unverified_context() was used. Please see PEP476 for details.
 



