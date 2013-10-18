#!/bin/bash

#$1 client_ip_as_string
#$2 data_direction
#$3 pps_as_string

email_notify="odintsov@fastvps.ru,hohryakov@fastvps.ru,ziltsov@fastvps.ee"
echo "Subject, please execute all related tasks :)" | mail -s "Myflower Guard: IP $1 blocked bacause $2 attack with power $3 pps" $email_notify


