For Debian 6, 7, 8 and CentOS 6, 7 and Fedora and Gentoo you should use the automatic installer:
```bash
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
```

Please keep in mind! We track some information about your machine (os type and distro version). If you do not want to share this information, please add flag --do-not-track-me to intsall script call. But in this case we can't improve FastNetMon for your distribution.

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
/usr/local/bin/notify_about_attack.sh
```

The first time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit of what happened.

A sample script is provided and can be installed as follows:
```bash
cp /usr/src/fastnetmon/src/notify_about_attack.sh /usr/local/bin/notify_about_attack.sh
chmod 755 /usr/local/bin/notify_about_attack.sh
```
After copying the file, you need to open it and configure the 'email_notify' option as required.

You can use an alternative python script: /usr/src/fastnetmon/src/scripts/fastnetmon_notify.py


Guide for manual install (for unsupported platforms): [link](MANUAL_INSTALL.md)

If you want unstable development branch, please use this syntax:
```bash
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master
```
