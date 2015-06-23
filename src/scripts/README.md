### Here you could find nice scripts for subnet's collection from the BGP router server

- Clone ExaBGP master's repository: ```bash
cd /usr/src
https://github.com/Exa-Networks/exabgp.git
```
- Put exabgp_network_collector.conf to /etc
- Put bgp_network_collector.py to /usr/local/bin
- Run ExaBGP: ```bash
env exabgp.log.level=DEBUG  exabgp.daemon.user=root exabgp.tcp.bind="0.0.0.0" exabgp.tcp.port=179 exabgp.daemon.daemonize=false exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log sbin/exabgp exabgp_network_collector.conf
```
