MikroTik FastNetMon plug-in
===========

Overview
--------
Connects to a MikroTik router and adds or removes a blackhole rule for an attack by IP address.

The actions can be modified such as adding a firewall rule.

This script uses the MikroTik PHP API. More information about this can be found at the following URLs:
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class

Installation
------------

#### Prerequisite
You must have a user with API access on the router

Install php to your server:
```
sudo apt-get install php-cli php
```

#### Process
1.  Configure the router in the ```fastnetmon_mikrotik.php``` file
```
$cfg[ ip_mikrotik ] = "192.168.10.1"; // MikroTik Router IP
$cfg[ api_user ]    = "api"; // username
$cfg[ api_pass ]    = "api123"; // password
```
2. Change the ```notify_about_attack.sh``` with the new to run the PHP script

This is the first buggy version, you are welcome to add more features.

Changelog
---------
v1.0 - 4 Jul 16 - Initial version

Author: Maximiliano Dobladez info@mkesolutions.net

http://maxid.com.ar | http://www.mkesolutions.net  
