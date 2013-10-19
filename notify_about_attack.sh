#!/bin/bash

#$1 client_ip_as_string
#$2 data_direction
#$3 pps_as_string

email_notify="odintsov@fastvps.ru,hohryakov@fastvps.ru,ziltsov@fastvps.ee"

# Далее возможны два варианта:
# это первый запуск, при котором нужно банить IP (на stdin пусто)
# это второй запуск, когда скрипт уже собрал (если смог) детали об атаке (на stdin даные об атаке)

# check stdin type
if [ -t 0 ]; then
    echo "Subject, please execute all related tasks :) You may (not always) got atack details in next letter" | mail -s "Myflower Guard: IP $1 blocked because $2 attack with power $3 pps" $email_notify;
else
    cat | mail -s "Myflower Guard: IP $1 blocked because $2 attack with power $3 pps" $email_notify;
fi
