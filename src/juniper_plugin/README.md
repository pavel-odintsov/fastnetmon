Juniper FastNetMon plug-in
===========

Overview
--------
Connects to a Juniper router and adds or removes a blackhole rule for an attack by IP address.

The actions can be modified such as adding a firewall rule.

This script uses the Juniper NETCONF PHP API. More information about this can be found at the following URL:
 * https://github.com/Juniper/netconf-php

Installation
------------

#### Prerequisite
You must have a user and netconf enabled on your Juniper

to enable netconf go to your cli and type:
```
user@host> configure
user@host# set netconf ssh
```
if you wish to change netconf port instead of
```
user@host# set netconf ssh
```
use
```
user@host# set netconf ssh port <number>
``` 

Install php to your server:
```
sudo apt-get install php-cli php
```

#### Process
1.  Configure the router in the ```fastnetmon_juniper.php``` file
```
$cfg['hostname'] = "10.0.0.1"; // Juniper IP
$cfg['port'] = 880; //NETCONF Port 
$cfg['username'] = "user"; //user
$cfg['password'] = "password"; //pass
```
2. Change the ```notify_about_attack.sh``` with the new to run the PHP script

This is the first buggy version, you are welcome to add more features.

3. Set executable bit ```sudo chmod +x /etc/fastnetmon/scripts/notify_about_attack.sh```

4. For FastNetMon Advanced, please disable details:

```
sudo fcli set main notify_script_pass_details disable
sudo fcli commit
```

Changelog
---------
v1.0 - 5 Dec 18 - Initial version

Author: Christian David <davidchristia@gmail.com>

Based on Mikrotik Plugin by Maximiliano Dobladez <info@mkesolutions.net>