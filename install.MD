Install

For Debian 6, 7, 8, 9 and CentOS 6, 7 and Ubuntu 14.04 and Fedora and Gentoo you should use the automatic installer:
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
1
2
	
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl

Please keep in mind! We track some information about your machine (os type and distro version). If you do not want to share this information, please add flag
--do-not-track-me
1
	
--do-not-track-me

To intstall script call. But in this case we can’t improve FastNetMon for your distribution.

It’s REQUIRED to add all of your networks in CIDR notation (11.22.33.0/24) to the file /etc/networks_list in the form of one prefix per line. If you are running this software on an OpenVZ node, you may not need to specify networks explicitly, as we can read them from /proc/vz/veip.

You can whitelist prefixes by adding them to /etc/networks_whitelist (CIDR notation too).

Start main process:
/opt/fastnetmon/fastnetmon
1
	
/opt/fastnetmon/fastnetmon

Start the client process in another console:
/opt/fastnetmon/fastnetmon_client
1
	
/opt/fastnetmon/fastnetmon_client

To enable fastnetmon to start on server startup, please add the following line to /etc/rc.local:
/opt/fastnetmon/fastnetmon --daemonize
1
	
/opt/fastnetmon/fastnetmon --daemonize

If something goes wrong, please check logs:
tail -f /var/log/fastnetmon.log
1
	
tail -f /var/log/fastnetmon.log

When an incoming or outgoing attack occurs, the program calls a bash script twice (if it exists):
/usr/local/bin/notify_about_attack.sh
1
	
/usr/local/bin/notify_about_attack.sh

The first time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit of what happened.

A sample script is provided and can be installed as follows:
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/notify_about_attack.sh -O/usr/local/bin/notify_about_attack.sh
chmod 755 /usr/local/bin/notify_about_attack.sh
1
2
	
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/notify_about_attack.sh -O/usr/local/bin/notify_about_attack.sh
chmod 755 /usr/local/bin/notify_about_attack.sh

After downloading the file, you need to open it and configure the ’email_notify’ option as required.

You can use an alternative python script from here.

If you want to use unstable development branch, please use this syntax:
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master
1
2
	
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master

That’s great to have nice video about FastNetMon install from Eric Chou! Thank you!
