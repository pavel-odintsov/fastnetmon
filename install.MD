## Install ##

For Debian 6, 7, 8, 9 and CentOS 6, 7 and Ubuntu 14.04 and Fedora and Gentoo you should use the automatic installer:
<pre>
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
</pre>

Please keep in mind! We track some information about your machine (os type and distro version). If you do not want to share this information, please add flag
<pre>
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl
</pre>
Please keep in mind! We track some information about your machine (os type and distro version). If you do not want to share this information, please add flag
<pre>
--do-not-track-me
</pre>

To intstall script call. But in this case we can’t improve FastNetMon for your distribution.

It’s REQUIRED to add all of your networks in CIDR notation (11.22.33.0/24) to the file /etc/networks_list in the form of one prefix per line. If you are running this software on an OpenVZ node, you may not need to specify networks explicitly, as we can read them from /proc/vz/veip.

You can whitelist prefixes by adding them to /etc/networks_whitelist (CIDR notation too).

Start main process:
<pre>
/opt/fastnetmon/fastnetmon
</pre>

Start the client process in another console:
<pre>
/opt/fastnetmon/fastnetmon_client
</pre>

To enable fastnetmon to start on server startup, please add the following line to /etc/rc.local:
<pre>
/opt/fastnetmon/fastnetmon --daemonize
</pre>

If something goes wrong, please check logs:
<pre>
tail -f /var/log/fastnetmon.log
</pre>

When an incoming or outgoing attack occurs, the program calls a bash script twice (if it exists):
<pre>
/usr/local/bin/notify_about_attack.sh
</pre>

The first time when threshold exceed (at this step we know IP, direction and power of attack). Second when we collect 100 packets for detailed audit of what happened.

A sample script is provided and can be installed as follows:
<pre>
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/notify_about_attack.sh -O/usr/local/bin/notify_about_attack.sh
chmod 755 /usr/local/bin/notify_about_attack.sh
</pre>

After downloading the file, you need to open it and configure the ’email_notify’ option as required.

You can use an alternative python script from here.

If you want to use unstable development branch, please use this syntax:
<pre>
wget https://raw.githubusercontent.com/pavel-odintsov/fastnetmon/master/src/fastnetmon_install.pl -Ofastnetmon_install.pl 
sudo perl fastnetmon_install.pl --use-git-master
</pre>
 
That’s great to have nice video about FastNetMon install from Eric Chou! Thank you!
