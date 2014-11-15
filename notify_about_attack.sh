#!/bin/bash

# $1 client_ip_as_string
# $2 data_direction
# $3 pps_as_string
# $4 action (ban or unban)

email_notify="root,please_fix_this_email@domain.ru"

# Далее возможны два варианта:
# это первый запуск, при котором нужно банить IP (на stdin пусто)
# это второй запуск, когда скрипт уже собрал (если смог) детали об атаке (на stdin даные об атаке)

if [ "$4" = "unban" ]; then
    # Unban actions if used
    exit 0
fi

cat | mail -s "FastNetMon Guard: IP $1 blocked because $2 attack with power $3 pps" $email_notify;
# You can add ban code here!
# iptables -A INPUT -s $1 -j DROP
# iptables -A INPUT -d $1 -j DROP
