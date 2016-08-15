
ddos_dst_zone_path = '/axapi/v3/ddos/dst/zone/'

def ddos_dst_zone(zone_name, ip_addr):
    port_num = 53
    port_protocol = 'udp'
    ddos_dst_zone_payload = {
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
    return ddos_dst_zone_payload 
