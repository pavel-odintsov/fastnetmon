FastNetMon
===========
FastNetMon - A high performance DoS/DDoS load analyzer built on top of multiple packet capture engines (NetFlow, IPFIX, sFLOW, SnabbSwitch, netmap, PF_RING, PCAP).

What can we do? We can detect hosts in our networks sending or receiving large volumes of packets/bytes/flows per second. We can call an external script to notify you, switch off a server, or blackhole the client.

To enable sFLOW, simply specify IP of the server running FastNetMon and specify (configurable) port 6343
To enable netflow, simply specify IP of the server running FastNetMon and specify (configurable) port 2055

Why did we write this? Because we can't find any software for solving this problem in the open source world! 

What is a "flow" in FastNetMon terms?  It's one or multiple UDP, TCP, or ICMP connections with unique src IP, dst IP, src port, dst port, and protocol.

License: GPLv2

[![Gitter](https://badges.gitter.im/Join%20Chat.svg)](https://gitter.im/FastVPSEestiOu/fastnetmon?utm_source=badge&utm_medium=badge&utm_campaign=pr-badge) 



Project 
-------
- [Mailing list](https://groups.google.com/forum/#!forum/fastnetmon)
- [Roadmap](docs/ROADMAP.md)
- [Release Notes](docs/RELEASENOTES.md)
- Chat: #fastnetmon at irc.freenode.net [web client](https://webchat.freenode.net/)
- [Please fill out the survey, we need your voice!](https://docs.google.com/forms/d/1YoXQImMeEjBH-JPz3KYtcDwknHs8xrI538ObwSy9uZo/viewform)
- Detailed reference in Russian: [link](docs/FastNetMon_Reference_Russian.pdf)

Supported packet capture engines
--------------------------------
- NetFlow v5, v9
- IPFIX
- ![sFLOW](http://sflow.org/images/sflowlogo.gif) v4 (dev branch only), v5
- Port mirror/SPAN capture with PF_RING (with ZC/DNA mode support [need license](http://www.ntop.org/products/pf_ring/)), SnabbSwitch, NETMAP and PCAP

You can check out the [comparison table](docs/CAPTURE_BACKENDS.md) for all available packet capture engines.

Features
--------
- Complete [BGP Flow Spec support](docs/BGP_FLOW_SPEC.md), RFC 5575
- Process and distinguish incoming and/or outgoing traffic
- Trigger block/notify script if an IP exceeds defined thresholds for packets/bytes/flows per second
- Thresholds can be configured per-subnet with the hostgroups feature
- [Announce blocked IPs](docs/EXABGP_INTEGRATION.md) via BGP to routers with [ExaBGP](https://github.com/Exa-Networks/exabgp)
- GoBGP [integration](docs/GOBGP.md) for unicast IPv4 announcements
- Full integration with [Graphite](docs/GRAPHITE_INTEGRATION.md) and [InfluxDB](docs/INFLUXDB_INTEGRATION.md)
- API
- Redis integration
- MongoDB integration
- Deep packet inspection for attack traffic
- netmap support (open source; wire speed processing; only Intel hardware NICs or any hypervisor VM type)
- SnabbSwitch support (open source, very flexible, LUA driven, very-very-very fast)
- Filter NetFlow v5 flows or sFLOW packets with LUA scripts (useful for excluding particular ports)
- Supports L2TP decapsulation, VLAN untagging and MPLS processing in mirror mode 
- Works on server/soft-router
- Detects DoS/DDoS in as little as 1-2 seconds
- [Tested](docs/PERFORMANCE_TESTS.md) up to 10Gb with 12 Mpps on Intel i7 3820 with Intel NIC 82599
- Complete plugin support
- Captures attack fingerprints in PCAP format
- [Complete support](docs/DETECTED_ATTACK_TYPES.md) for most popular attack types

Running Fastnetmon
------------------
### Supported platforms
- Linux (Debian 6/7/8, CentOS 6/7, Ubuntu 12+)
- FreeBSD 9, 10, 11
- Mac OS X Yosemite

### Supported architectures
- x86 64 bit (recommended)
- x86 32 bit

### Router integration instructions
- [Juniper MX Routers](docs/JUNOS_INTEGRATION.md)

### Distributions supported
- We are part of the [CloudRouter](https://cloudrouter.org/cloudrouter/2015/07/09/fastnetmon.html) distribution
- We are part in the [official FreeBSD ports collection](https://freshports.org/net-mgmt/fastnetmon/), [manual install](docs/FreeBSD_INSTALL.md)
- [Amazon AMI image](docs/AMAZON.md)
- [VyOS based ISO image with bundled FastNetMon](docs/VYOS_BINARY_ISO_IMAGE.md)
- [Docker image](docs/DOCKER_INSTALL.md)
- [Automatic install script for Debian/Ubuntu/CentOS/Fedora/Gentoo](docs/INSTALL.md)
- [Automatic install script for Mac OS X](docs/MAC_OS_INSTALL.md)
- [Manual install on Slackware](docs/SLACKWARE_INSTALL.md)
- [Manual install for VyOS](docs/VyOS_INSTALL.md)

Screenshoots
------------

Main program screenshot:

![Main screen image](docs/images/fastnetmon_screen.png)

Example CPU load on Intel i7 2600 with Intel X540/82599 NIC at 400 kpps load:
![Cpu consumption](docs/images/fastnetmon_stats.png)

Example deployment scheme:
![Network diagramm](docs/images/network_map.png)

Example of [notification email](docs/ATTACK_REPORT_EXAMPLE.md) about detected attack.


How I can help project?
-----------------------
- We are looking for a maintainer for the Debian and Fedora/EPEL packages
- Test it! 
- Share your experience
- Share your use cases
- Share your improvements
- Test it with different equipment
- Create feature requests

Author: [Pavel Odintsov](http://ru.linkedin.com/in/podintsov/) pavel.odintsov at gmail.com [Follow my Twitter](https://twitter.com/odintsov_pavel)
