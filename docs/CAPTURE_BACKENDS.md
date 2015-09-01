|Name | Capture speed |Installation | CPU load | Platforms | Cost | Accuracy of attack detection | Speed of attack detection 
|-----|:-------------:|:-------:|:--:|:--:|:------:|:----:|:---:|
|netmap | Up to wire speed (10GE, 14 MPPS) | Need kernel module and NIC driver patch [ixgbe provided](https://github.com/pavel-odintsov/ixgbe-linux-netmap). For FreeBSD could need kernel rebuild but patches are included to kernel |Normal |Linux, FreeBSD | BSD | Very accurate | Very fast|
|PF_RING | Up to 2-3 MPPS, 2-3 GE |Need kernel module install |Very big| Linux  only | GPLv2 | Enough accurate | Very fast|
|PF_RING ZC | Up to wire speed (10GE, 14 MPPS) | Need kernel module + patched drivers (provided in package)|Normal| Linux only | Commercial ~200 euro | Very accurate | Very fast|
| pcap | very slow, 10-100 mbps | Simple | huge | FreeBSD, Linux | GPL | Not so accurate | Very fast|
| sFLOW | Up to 40-100GE | Very simple | Small | Linux, FreeBSD, MacOS | Free |  Accurate but depends on sampling rate (1-128 sampling rate recommended but significantly depends on traffic in network) | Very fast|
| NetFlow | Up to 40-100GE | Very simple | Small for FastNetMon but could be huge for network equpment if implemented in software way | Linux, FreeBSD, MacOS | Free but could require additional licenses or hardware from network equipment vendor | Not so accurate | So slow, up to multiple minutes depends on flow timeout configuration  on routers|
| AF_PACKET | Up to 2 MPPS/5-10GE | Very simple | Normal-huge | Linux (since 3.6 kernel) | GPLv2 | Very accurate | Very fast|
