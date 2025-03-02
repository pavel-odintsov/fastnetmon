![logo](https://fastnetmon.com/wp-content/uploads/2018/01/cropped-new_logo_3var-e1515443553507-1-300x146.png)

Community Edition
===========
FastNetMon - A high-performance DDoS detector/sensor built on top of multiple packet capture engines: NetFlow, IPFIX, sFlow, AF_PACKET (port mirror).

What do we do?
--------------
We detect hosts in the deployed network sending or receiving large volumes of traffic, packets/bytes/flows per second and
perform a configurable action to handle that event. These configurable actions include notifying you, calling script or making BGP announcements. 

Project 
-------
🌏️ [Official site](https://fastnetmon.com)  
⭐️ [FastNetMon Advanced, Commercial Edition](https://fastnetmon.com/product-overview/)  
🌟️ [FastNetMon Advanced, free one-month trial](https://fastnetmon.com/trial/)  
📜️ [FastNetMon Advanced and Community difference table](https://fastnetmon.com/compare-community-and-advanced/)  
📘️ [Detailed reference](https://fastnetmon.com/wp-content/uploads/2023/07/fastnetmon_community_book_20_jul_2023.pdf)  

Legal
--------------

By installing or using this software, you confirm that you have read and agree to the FastNetMon Community Edition T&Cs and Privacy Notice, which will apply to your installation and use of the software

### Installation
- [Linux install instructions](https://fastnetmon.com/install/)
- [macOS install instructions](https://formulae.brew.sh/formula/fastnetmon)
- [FreeBSD port](https://www.freshports.org/net-mgmt/fastnetmon/)
- [VyOS bundled support](https://fastnetmon.com/fastnetmon-community-on-vyos-rolling-1-3/)

Supported packet capture engines
--------------------------------
- NetFlow v5, v9, v9 Lite
- IPFIX
- ![sFlow](http://sflow.org/images/sflowlogo.gif) v5
- PCAP
- AF_PACKET (recommended)
- AF_XDP (XDP based capture)
- Netmap (deprecated, still supported only for FreeBSD)
- PF_RING / PF_RING ZC (deprecated, available only for CentOS 6 in 1.2.0)

You can check out the [comparison table](https://fastnetmon.com/docs/capture_backends/) for all available packet capture engines.

Features
--------
- Detects DoS/DDoS in as little as 1-2 seconds
- Scales up to terabits on single server (sFlow, Netflow, IPFIX) or to 40G + in mirror mode
- Trigger block/notify script if an IP exceeds defined thresholds for packets/bytes/flows per second
- Thresholds can be configured per-subnet basis with the hostgroups feature
- [Email notifications](https://fastnetmon.com/docs/attack_report_example/) about detected attack
- Complete IPv6 support
- Prometheus support: system metrics and total traffic counters
- Flow and packet export to Kafka in JSON and Protobuf format
- Announce blocked IPs via BGP to routers with [ExaBGP](https://fastnetmon.com/docs/exabgp_integration/) or [GoBGP](https://fastnetmon.com/docs/gobgp-integration/) (recommended)
- Full integration with [Clickhouse](https://github.com/pavel-odintsov/fastnetmon/blob/7f0ad9c6cd2db3856607aeed04b5e8125fad3124/src/fastnetmon.conf#L287) [InfluxDB](https://fastnetmon.com/docs/influxdb_integration/) and [Graphite](https://fastnetmon.com/docs/graphite_integration/)
- [API](https://fastnetmon.com/docs/fastnetmon-community-api/)
- [Redis](https://fastnetmon.com/docs/redis/) integration
- MongoDB protocol support compatible with native [MongoDB](https://fastnetmon.com/docs/mongodb/) and [FerretDB](https://github.com/FerretDB/FerretDB)
- VLAN untagging in mirror and sFlow modes
- Capture attack fingerprints in PCAP format

We track [multiple](https://fastnetmon.com/docs-fnm-advanced/fastnetmon-usage-analytics/) platform and environment-specific metrics to understand ways how our product is being used and prioritise development accordingly. 

Official support groups:
-------
- [Mailing list](https://groups.google.com/g/fastnetmon)
- [Slack](https://slack.fastnetmon.com)
- IRC: #fastnetmon at irc.libera.chat:6697 (TLS) [web client](https://web.libera.chat/?channels=#fastnetmon)
- Telegram: [fastnetmon](https://t.me/fastnetmon)
- Discord: [fastnetmon](https://discord.fastnetmon.com)

Follow us at social media:
-------
- [Twitter](https://twitter.com/fastnetmon)
- [LinkedIn](https://www.linkedin.com/company/fastnetmon/)
- [Facebook](https://www.facebook.com/fastnetmon/)

### Router integration instructions
- [Juniper MX Routers](https://fastnetmon.com/docs/junos_integration/)

Complete integration with the following vendors
--------------------------------
- [Juniper integration](src/juniper_plugin)
- [A10 Networks Thunder TPS Appliance integration](src/a10_plugin)
- [MikroTik RouterOS](src/mikrotik_plugin)


Screenshots
------------
Command line interface
![Main screen image](docs/images/fastnetmon_screen.png)

------------
Standard Grafana dashboard
![Grafana total traffic](docs/images/grafana_total.png)

Example deployment scheme
--------------

![Network diagramm](docs/images/deploy.png)


CI build status
--------------
[![CircleCI](https://circleci.com/gh/pavel-odintsov/fastnetmon/tree/master.svg?style=svg)](https://circleci.com/gh/pavel-odintsov/fastnetmon/tree/master)

Upstream versions in different distributions
--------------

[![FastNetMon upstream distro packaging status](https://repology.org/badge/vertical-allrepos/fastnetmon.svg)](https://repology.org/project/fastnetmon/versions) 
