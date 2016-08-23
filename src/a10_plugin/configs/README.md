#A10 Networks Thunder TPS Appliance Configs

##Base Config v1 Functionality

  1.  Assumes TPS receives inbound traffic only (from the Internet to the protected service)
  2.  Rate Limiters (GLID) for 10gbps, 1gbps, and 100mbps provided for use
  3.  Basic TCP and UDP templates provided (syn-auth, UDP-auth, and low src port filter)
  4.  BGP configuration for auto mitigation announcements (ddos-advertise route map)
  5.  Base sFlow export configuration
  6.  All events logged in CEF format

##Basic Zone Config v1 Functionality
  1. Filters L2, L3, L4 packet anomalies (consult A10 documentation for specifics
  2. Drops ICMPv4, ICMPv6, and all fragments
  3. Performs TCP SYN Auth for TCP dest ports 21,22,25,53,80,110,143,443,587,993,995,5060,5061
  4. Filters well-known UDP SRC ports
  5. Performs UDP Auth for UDP dest port 53
  6. blocks all other traffic
  7. Creates a "incident" in the TPS GUI when seeing any packets to these dest ports.

## These are just examples. Current plugin does not receive rate info from FNM. Future revisions will
Author: Eric Chou ericc@a10networks.com, Rich Groves rgroves@a10networks.com

Feedback and Feature Requests are Appreciated and Welcomed. 
