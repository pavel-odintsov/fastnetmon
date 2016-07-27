bgp_advertisement_path = '/axapi/v3/router/bgp/'

def bgp_advertisement(ip_addr):
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
    return route_advertisement
