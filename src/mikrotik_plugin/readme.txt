Fastnetmon Plugin:  MikroTik RouterOS PHP API integration for FastNetMon  


This script connect to router MikroTik and add or remove a blackhole's rule for the IP attack.

You can modify the action, ex add a firewall rule, etc.

This script use PHP API for MikroTik:
 * http://www.mikrotik.com
 * http://wiki.mikrotik.com/wiki/API_PHP_class


v1.0 - 4 Jul 16 - initial version

Author: Maximiliano Dobladez info@mkesolutions.net

http://maxid.com.ar | http://www.mkesolutions.net  

** instalation

* You must to have an user with API access on the router MikroTik. 

* Set the router's config on fastnetmon_mikrotik.php file

$cfg[ ip_mikrotik ] = "192.168.10.1"; // IP Mikrotik Router 
$cfg[ api_user ]    = "api"; //user
$cfg[ api_pass ]    = "api123"; //pass

* Change the notify_about_attack.sh file with the new to run the php script

** 

This is the first buggy version, you are welcome to add more feature.

