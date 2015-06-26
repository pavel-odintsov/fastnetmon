For Debian 6, 7, 8 and CentOS 6 and 7 you should use the automatic installer:
```bash
wget https://raw.githubusercontent.com/FastVPSEestiOu/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl
sudo perl fastnetmon_install.pl
```
If you want to use netmap module, please install it: [netmap install](NETMAP_INSTALL.md)

It's REQUIRED to add all of your networks in CIDR notation (11.22.33.0/24) to the file /etc/networks_list in the form of one prefix per line. If you are running this software on an OpenVZ node, you may not need to specify networks explicitly, as we can read them from /proc/vz/veip.

You can whitelist prefixes by adding them to /etc/networks_whitelist (CIDR notation too).

Start main process:
```bash
/opt/fastnetmon/fastnetmon
```

Start the client process in another console:
```bash
/opt/fastnetmon/fastnetmon_client
```

To enable fastnetmon to start on server startup, please add the following line to /etc/rc.local:
```bash
/opt/fastnetmon/fastnetmon --daemonize
```
If something goes wrong, please check logs:
```bash
tail -f /var/log/fastnetmon.log
```

When an incoming or outgoing attack occurs, the program calls a bash script twice (if it exists):
```bash
/usr/local/bin/notify_fastnetmon_attack.sh
```
The first time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit of what happened.

A sample script is provided and can be installed as follows:
```bash
cp /usr/src/fastnetmon/src/notify_fastnetmon_attack.sh /usr/local/bin/notify_fastnetmon_attack.sh
chmod 755 /usr/local/bin/notify_fastnetmon_attack.sh
```
After copying the file, you need to open it and configure the 'email_notify' option as required.

Guide for manual install (for unsupported platforms): [link](MANUAL_INSTALL.md)
