#!/usr/bin/env bash
#
#  Fastnetmon: Juniper plugin  
#  
#  Author: - info@mkesolutions.net - http://maxid.com.ar  
#  Modified by Christian David <davidchristia@gmail.com> for juniper implementation
#
# This script will get following params:
#  $1 client_ip_as_string
#  $2 data_direction
#  $3 pps_as_string
#  $4 action (ban or unban)
  
 
php -f /opt/fastnetmon/fastnetmon_juniper.php $1 $2 $3 $4
exit 0
 