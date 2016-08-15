
ddos_dst_zone_path = '/axapi/v3/ddos/dst/zone/'

def ddos_dst_zone(zone_name, ip_addr):
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
          "advertised-enable":1,
          "zone-template": {
            "logging":"cef-logger"
          },
          "log-enable":1,
          "log-periodic":1,
          "ip-proto": {
            "proto-tcp-udp-list": [
              {
                "protocol":"tcp",
                "drop-frag-pkt":1,
              },
              {
                "protocol":"udp",
                "drop-frag-pkt":1,
              }
            ],
            "proto-name-list": [
              {
                "protocol":"icmp-v4",
                "deny":1,
                "detection-enable":1,
              },
              {
                "protocol":"icmp-v6",
                "deny":1,
                "detection-enable":1,
              }
            ]
          },
          "port": {
            "zone-service-other-list": [
              {
                "port-other":"other",
                "protocol":"tcp",
                "detection-enable":1,
                "level-list": [
                  {
                    "level-num":"0",
                    "zone-escalation-score":10,
                    "indicator-list": [
                      {
                        "type":"pkt-rate",
                        "score":20,
                        "zone-threshold-num":1,
                      }
                    ]
                  },
                  {
                    "level-num":"1",
                    "zone-template": {
                      "tcp":"tcp-protect1"
                    },
                  }
                ]
              },
              {
                "port-other":"other",
                "protocol":"udp",
                "detection-enable":1,
                "level-list": [
                  {
                    "level-num":"0",
                    "zone-escalation-score":10,
                    "indicator-list": [
                      {
                        "type":"pkt-rate",
                        "score":20,
                        "zone-threshold-num":1,
                      }
                    ]
                  },
                  {
                    "level-num":"1",
                    "zone-template": {
                      "udp":"udp-protect1"
                    },
                  }
                ]
              }
            ]
          }
        }
      ]
    }

    return ddos_dst_zone_payload 
