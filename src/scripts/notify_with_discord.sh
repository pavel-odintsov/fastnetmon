#!/usr/bin/env bash

# Instructions:
#
# Copy this script to /usr/local/bin/
# Edit /etc/fastnetmon.conf and set:
# notify_script_path = /usr/local/bin/notify_with_discord.sh
#
# Add your Discord incoming webhook to discord_url.
# discord_url="https://discord.com/api/webhooks/XXXXXXXXXXXXXXXXXXXXXXXXXXXX"
#
# Notes:
# hostname lookup requires the dig command.
# Debian: apt install dnsutils
# Redhat: dnf install bind-utils

#
# For ban and attack_details actions we will receive attack details to stdin
# if option notify_script_pass_details enabled in FastNetMon's configuration file
#
# If you do not need this details, please set option notify_script_pass_details to "no".
#
# Please do not remove the following command if you have notify_script_pass_details enabled, because
# FastNetMon will crash in this case (it expect read of data from script side).
#

if [ "$4" = "ban" ] || [ "$4" = "attack_details" ]; then
    fastnetmon_output=$(</dev/stdin)
fi

fastnetmon_ip="$1"
fastnetmon_direction="$2"
fastnetmon_pps="$3"
fastnetmon_action="$4"
target_hostname=`dig -x $fastnetmon_ip +short`

webhook_url=""
message_username="FastNetMon"
message_title="FastNetMon Alert - $fastnetmon_direction Attack"
message_content=""

if [ "$fastnetmon_action" = "ban" ]; then
    color="14425373"
elif [ "$fastnetmon_action" = "attack_details" ]; then
    color="16765184"
elif [ "$fastnetmon_action" = "unban" ]; then
    color="3857437"
else
    color="1957075"
fi

if [ ! -z "$fastnetmon_output" ]; then
    message_content="\```$fastnetmon_output\```"
fi

discord_payload="{\"username\": \"$message_username\", \"content\": \"$message_content\", \"embeds\": [ { \"title\": \"$message_title\", \"color\": \"$color\", \"fields\": [ {\"name\": \"IP\", \"value\": \"$fastnetmon_ip\n$target_hostname\", \"inline\": true}, {\"name\": \"PPS\", \"value\": \"$fastnetmon_pps\", \"inline\": true}, {\"name\": \"Action Taken\", \"value\": \"$fastnetmon_action\"} ] } ] }"
curl --connect-timeout 30 --max-time 60 -s -S -X POST -H 'Content-type: application/json' --data "$discord_payload" "$webhook_url"
