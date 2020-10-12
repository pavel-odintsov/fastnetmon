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

This is the first version, you are welcome to add more features.

3. Set executable bit ```sudo chmod +x /etc/fastnetmon/scripts/notify_about_attack.sh```

4. For FastNetMon Advanced, specify this script as callback: 

```
sudo fcli set main notify_script_enabled enable
sudo fcli set main notify_script_path /etc/fastnetmon/scripts/notify_about_attack.sh
sudo fcli set main notify_script_format text
sudo fcli commit
```
And disable passing details to this script:
```
sudo fcli set main notify_script_pass_details disable
sudo fcli commit
```

Changelog
---------
v1.1 - 12 Oct 2020 - fix RouterOS API-ssl to support post MikroTik 6.45.1

v1.0 - 4 Jul 16 - Initial version

Author: Maximiliano Dobladez info@mkesolutions.net

http://maxid.com.ar | http://www.mkesolutions.net  
