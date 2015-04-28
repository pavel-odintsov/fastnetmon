|Name | Capture speed |Installation | CPU load | Platforms | Cost |
|-----|:-------------:|:-------:|:--:|:--:|:------:|
|netmap | Up to wire speed (10GE, 14 MPPS) | Need kernel module and NIC driver patch [ixgbe provided](https://github.com/pavel-odintsov/ixgbe-linux-netmap)  |Normal |Linux, FreeBSD | BSD |
|PF_RING | Up to 2-3 MPPS, 2-3 GE |Need kernel module install |Very big| Linux  only | GPLv2 |
|PF_RING ZC | Up to wire speed (10GE, 14 MPPS) | Need kernel module + patched drivers (provided in package)|Normal| Linux only | Commercial ~200 euro |
| pcap | very slow, 10-100 mbps | Simple | huge | FreeBSD, Linux | GPL
| sFLOW | Up to 40-100GE | Very simple | Small | Linux, FreeBSD, MacOS | Free | 
| NetFlow | Up to 40-100GE | Very simple | Small | Linux, FreeBSD, MacOS | Free | 
| AF_PACKET (not implemented yet) | Up to 5-10 MPPS/5-10GE | Very simple | Normal-huge | Linux (since 3.6 kernel) | GPLv2 |
