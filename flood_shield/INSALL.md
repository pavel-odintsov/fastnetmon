# Flood Shield is a very fast http flood blocker

We sniff and parse all incoming http requests. If any IP made more than XX requests per second we will trigger ipset ban immediately. 

Install FastNetMon (it will build and install all required libs):
```bash
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/fastnetmon_install.pl
perl fastnetmon_install.pl
```

Install dependency of Flood Shield:
```bash
apt-get install -y ipset libipset-dev libipset2
```

Build Flood Shield:
```
cd /usr/src
git clone https://github.com/FastVPSEestiOu/fastnetmon.git
cd flood_shield
./build_shield.sh
```

Create ipset and iptables rules:
```bash
ipset --create blacklist iphash --hashsize 4096
iptables -I INPUT -m set --match-set blacklist src -p TCP --destination-port 80 -j DROP
```

Run it:
```bash
./shield
```

By default we will ban any IP which exceed 20 requests per second. If you want to change it, please fix in code and recompile. We sniff only 80 port by default.
