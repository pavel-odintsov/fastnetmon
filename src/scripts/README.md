### Here you can find some nice scripts for subnet's collection from the BGP route server

- Clone ExaBGP master's repository:
```bash
# yum/apt-get install -y python-pip
pip install exabgp
```
- Download configs and scripts:
```bash
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/scripts/exabgp_network_collector.conf -O/etc/exabgp_network_collector.conf
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/scripts/bgp_network_retriever.py -O/usr/local/bin/bgp_network_retriever.py

wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/scripts/bgp_network_collector.py -O/usr/local/bin/bgp_network_collector.py

chmod +x /usr/local/bin/bgp_network_retriever.py /usr/local/bin/bgp_network_collector.py
```
- Run ExaBGP:
```bash
cd /usr/src/exabgp
env exabgp.log.level=DEBUG exabgp.daemon.user=root exabgp.tcp.bind="0.0.0.0" exabgp.tcp.port=179 exabgp.daemon.daemonize=false exabgp.daemon.pid=/var/run/exabgp.pid exabgp.log.destination=/var/log/exabgp.log exabgp /etc/exabgp_network_collector.conf
```
- Wait a few minutes while all route announcements are received (depends on router server size)
- Retrieve learned networks from database (/var/lib/bgp_network_collector.db): ```python /usr/local/bin/bgp_network_retriever.py```
