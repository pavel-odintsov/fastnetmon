#!/usr/bin/python

#
# v0.2 created [ban | unban] [on ramp | off ramp action] for A10 TPS 
# v0.3 offload URI path and json_body into separate json_config files
# Eric Chou (ericc@a10networks.com)
#

import sys
from sys import stdin
import optparse
import logging, json
from a10 import axapi_auth, axapi_action
from json_config.logoff import logoff_path
from json_config.write_memory import write_mem_path
from json_config.ddos_dst_zone import ddos_dst_zone_path, ddos_dst_zone
from json_config.bgp import bgp_advertisement_path, bgp_advertisement

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
        r = axapi_action(mitigator_base_url+bgp_advertisement+asn+'/network/ip-cidr/'+ip_addr+'%2F32', method="DELETE", signature=signature)
    except Exception as e: 
        logger.info("route not removed in unban, returned: " + str(e))

    # Commit config
    axapi_action(mitigator_base_url+write_mem_path, signature=signature)
    # Logoff
    axapi_action(mitigator_base_url+logoff_path, signature=signature)
 
    sys.exit(0)

elif action == "ban":
    
    r = axapi_action(mitigator_base_url+ddos_dst_zone_path, method='GET', signature=signature)
    if zone_name in [i['zone-name'] for i in json.loads(r)['zone-list']]:
        r = axapi_action(mitigator_base_url+ddos_dst_zone_path+zone_name, method="DELETE", signature=signature)
        logger.info(str(r))

    # A10 Mitigation On Ramp 
    zone_name = client_ip_as_string + "_zone"
    ip_addr = client_ip_as_string
    returned_body = ddos_dst_zone(zone_name, ip_addr)
    try:
        r = axapi_action(mitigator_base_url+ddos_dst_zone_path, signature=signature, payload=returned_body)
    except Exception as e:
        logger("zone not created: " + str(e))

    route_advertisement = bgp_advertisement(ip_addr) 
    try: 
        r = axapi_action(mitigator_base_url+bgp_advertisement_path+asn, payload=route_advertisement, signature=signature)
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




