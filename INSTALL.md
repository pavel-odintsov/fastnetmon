For Debian 6, 7 and CentOS 6 and 7 you should use automati installer:
```bash
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/fastnetmon_install.pl
perl fastnetmon_install.pl
```

It's REQUIRED to add all your networks in CIDR form (11.22.33.44/24) to file /etc/networks_list if form when one subnet on one line. When you running this software in OpenVZ node you may did not specify networks explicitly, we can read it from file /proc/vz/veip.

You can add whitelist subnets in similar form to /etc/networks_whitelist (CIDR masks too).

Start it:
```bash
./opt/fastnetmon/fastnetmon 
```

Enable programm start on server startup, please add to /etc/rc.local this lines:
```bash
screen -S fastnetmon -d -m /root/fastnetmon/fastnetmon
```
If something goes wrong, please check logs:
```bash
tail -f /var/logfastnetmon.log
```

When incoming or outgoing attack arrives programm call bash script (when it exists): /usr/local/bin/notify_about_attack.sh two times. First time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit what did happens.

Guide for manual install (for unsupported platforms): [link](MANUAL_INSTALL.md)
