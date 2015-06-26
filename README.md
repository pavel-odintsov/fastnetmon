FastNetMon
===========
[![Build Status](https://travis-ci.org/FastVPSEestiOu/fastnetmon.svg?branch=master)](https://travis-ci.org/FastVPSEestiOu/fastnetmon) [![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/FastVPSEestiOu/fastnetmon?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) [![Stories in Progress](https://badge.waffle.io/FastVPSEestiOu/fastnetmon.svg?label=ready&title=Progress)](http://waffle.io/FastVPSEestiOu/fastnetmon)

Chat: #fastnetmon at irc.freenode.net [web client](https://webchat.freenode.net/)

FastNetMon - A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, netmap, PF_RING, PCAP).

[Please fill survey, we need your voice!](https://docs.google.com/forms/d/1YoXQImMeEjBH-JPz3KYtcDwknHs8xrI538ObwSy9uZo/viewform)

* Author: [Pavel Odintsov](http://ru.linkedin.com/in/podintsov/) pavel.odintsov at gmail.com [Follow my Twitter](https://twitter.com/odintsov_pavel)
* License: GPLv2
* Join to [maillist](https://groups.google.com/forum/#!forum/fastnetmon)
* Look at [road map](docs/ROADMAP.md)

What can we do? We can detect hosts in our own network with a large amount of packets per second/bytes per second or flow per second incoming or outgoing from certain hosts. And we can call an external script which can notify you, switch off a server or blackhole the client.

- [VyOS based iso image with bundled FastNetMon](docs/VYOS_BINARY_ISO_IMAGE.md)
- [Binary rpm packages for CentOS 6/7 and Fedora 21](docs/INSTALL_RPM_PACKAGES.md)
- [Automatic install script for Debian/Ubuntu/CentOS/Fedora](docs/INSTALL.md)
- [Manual install on FreeBSD and Dragonfly BSD](docs/FreeBSD_INSTALL.md)
- [Manual install on Mac OS X](docs/MAC_OS_INSTALL.md)
- [Manual install on Slackware](docs/SLACKWARE_INSTALL.md)
- [Manual install for VyOS](docs/VyOS_INSTALL.md)

#### Supported packet capture engines:

- NetFlow v5, v9
- IPFIX
- ![sFLOW](http://sflow.org/images/sflowlogo.gif) v4 (dev branch only), v5
- Port mirror/SPAN capture with PF_RING (with ZC/DNA mode support [need license](http://www.ntop.org/products/pf_ring/)), NETMAP and PCAP

You could look [comparison table](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/CAPTURE_BACKENDS.md) for all available packet capture engines.

#### Features:

- Can process incoming and outgoing traffic
- Can trigger block script if certain IP loads network with a large amount of packets/bytes/flows per second
- Could [announce blocked IPs](docs/EXABGP_INTEGRATION.md) to BGP router with [ExaBGP](https://github.com/Exa-Networks/exabgp)
- Have integration with [Graphite](docs/GRAPHITE_INTEGRATION.md)
- netmap support (open source; wire speed processing; only Intel hardware NICs or any hypervisor VM type)
- Supports L2TP decapsulation, VLAN untagging and MPLS processing in mirror mode 
- Can work on server/soft-router
- Can detect DoS/DDoS in 1-2 seconds
- [Tested](https://github.com/FastVPSEestiOu/fastnetmon/blob/master/docs/PERFORMANCE_TESTS.md) up to 10GE with 12 Mpps on Intel i7 3820 with Intel NIC 82599
- Complete plugin support
- Have [complete support](docs/DETECTED_ATTACK_TYPES.md) for most popular attack types

#### Supported platforms:

- Linux (Debian 6/7/8, CentOS 6/7, Ubuntu 12+)
- FreeBSD 9, 10, 11
- Mac OS X Yosemite

#### Supported architectures:

- x86 64 bit (recommended)
- x86 32 bit

What is "flow" in FastNetMon terms? It's one or multiple udp, tcp, icmp connections with unique src IP, dst IP, src port, dst port and protocol.

#### Main program screen image:

![Main screen image](docs/images/fastnetmon_screen.png)

#### Example for cpu load on Intel i7 2600 with Intel X540/82599 NIC on 400 kpps load:
![Cpu consumption](docs/images/fastnetmon_stats.png)

#### Example deployment scheme:
![Network diagramm](docs/images/network_map.png)

Example of [notification email](docs/ATTACK_REPORT_EXAMPLE.md) about detected attack.

To enable sFLOW simply specify IP of server with installed FastNetMon and specify port 6343.  
To enable netflow simply specify IP of server with installed FastNetMon and specify port 2055.  

Why did we write this? Because we can't find any software for solving this problem in the open source world! 

#### How I can help project?

- We are looking for maintainer for Debian and Fedora/EPEL packages
- Test it! 
- Share your experience
- Share your use cases
- Share your improvements
- Test it with different equipment
- Create feature requests
