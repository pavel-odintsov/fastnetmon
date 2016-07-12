#!/usr/bin/python

#
# v0.2 created [ban | unban] [on ramp | off ramp action] for A10 TPS 
# Eric Chou (ericc@a10networks.com)
#

import sys
from sys import stdin
import optparse
import logging, json
from a10 import axapi_auth, axapi_action
from json_config.logoff import logoff_path
from json_config.write_memory import write_mem_path

LOG_FILE = "/var/log/fastnetmon-notify.log"


logger = logging.getLogger("DaemonLog")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(formatter)
logger.addHandler(handler)



client_ip_as_string=sys.argv[1]
data_direction=sys.argv[2]
pps_as_string=int(sys.argv[3])
action=sys.argv[4]

logger.info(" - " . join(sys.argv))


# A10 Mitigator Information
mitigator_ip = "192.168.199.152"
zone_name = client_ip_as_string + "_zone"
ip_addr = client_ip_as_string
asn="64513"
mitigator_base_url, signature = axapi_auth(mitigator_ip, "admin", "a10")


if action == "unban":
    try: 
        r = axapi_action(mitigator_base_url+'/axapi/v3/router/bgp/'+asn+'/network/ip-cidr/'+ip_addr+'%2F32', method="DELETE", signature=signature)
    except Exception as e: 
        logger.info("route not removed in unban, returned: " + str(e))

    # Commit config
    axapi_action(mitigator_base_url+write_mem_path, signature=signature)
    # Logoff
    axapi_action(mitigator_base_url+logoff_path, signature=signature)
 
    sys.exit(0)

elif action == "ban":
    
    r = axapi_action(mitigator_base_url+'/axapi/v3/ddos/dst/zone/', method='GET', signature=signature)
    if zone_name in [i['zone-name'] for i in json.loads(r)['zone-list']]:
        r = axapi_action(mitigator_base_url+'/axapi/v3/ddos/dst/zone/'+zone_name, method="DELETE", signature=signature)
        logger.info(str(r))

    # A10 Mitigation On Ramp 
    zone_name = client_ip_as_string + "_zone"
    ip_addr = client_ip_as_string
    port_num = 53
    port_protocol = 'udp'
    ddos_violation_action_payload = {
      "zone-list": [
        {
          "zone-name":zone_name,
          "ip": [
            {
              "ip-addr":ip_addr
            }
          ],
          "operational-mode":"monitor",
          "port": {
            "zone-service-list": [
              {
                "port-num":port_num,
                "protocol":port_protocol,
                "level-list": [
                  {
                    "level-num":"0",
                    "zone-escalation-score":1,
                    "indicator-list": [
                      {
                        "type":"pkt-rate",
                        "score":50,
                        "zone-threshold-num":1,
                      }
                    ],
                  },
                  {
                    "level-num":"1",
                  }
                ],
              }
            ],
          },
        }
      ]
    }   
    try:
        r = axapi_action(mitigator_base_url+'/axapi/v3/ddos/dst/zone', signature=signature, payload=ddos_violation_action_payload)
    except Exception as e:
        logger("zone not created: " + str(e))

    route_advertisement = {
      "bgp":
        {
          "network": {
            "ip-cidr-list": [
              {
                "network-ipv4-cidr":ip_addr+"/32",
              }
            ]
          },
        }
    }
    try: 
        r = axapi_action(mitigator_base_url+'/axapi/v3/router/bgp/'+asn, payload=route_advertisement, signature=signature)
    except Exception as e:
        logger("route not added: " + str(e))

    # Commit changes
    axapi_action(mitigator_base_url+write_mem_path, signature=signature)
    # Log off
    axapi_action(mitigator_base_url+logoff_path, signature=signature)
    
    sys.exit(0)

elif action == "attack_details":
    
    sys.exit(0)


else:
    sys.exit(0)




