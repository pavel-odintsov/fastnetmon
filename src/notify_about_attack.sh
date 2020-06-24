#!/usr/bin/env bash

#
# Hello, lovely FastNetMon customer! I'm really happy to see you here!
#  Pavel Odintsov, author
#

# This script will get following params:
#  $1 client_ip_as_string
#  $2 data_direction
#  $3 pps_as_string
#  $4 action (ban or unban)

email_notify="root,please_fix_this_email@domain.ru"

#
# Please be careful ! You should not remove cat >
#

if [ "$4" = "unban" ]; then
    # No details arrived to stdin here

    # Unban actions if used
    exit 0
fi

#
# For ban and attack_details actions we will receive attack details to stdin
# if option notify_script_pass_details enabled in FastNetMon's configuration file
#
# If you do not need this details, please set option notify_script_pass_details to "no".
#
# Please do not remove "cat" command if you have notify_script_pass_details enabled, because
# FastNetMon will crash in this case (it expect read of data from script side).
#

if [ "$4" = "ban" ]; then
    cat | mail -s "FastNetMon Guard: IP $1 blocked because $2 attack with power $3 pps" $email_notify;
    # You can add ban code here!
    exit 0
fi

if [ "$4" == "attack_details" ]; then
    cat | mail -s "FastNetMon Guard: IP $1 blocked because $2 attack with power $3 pps" $email_notify;

    exit 0
fi
