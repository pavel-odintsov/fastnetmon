#!/usr/bin/env bash

# Instructions:
#
# - Copy this script to /usr/local/bin/
# - Edit /etc/fastnetmon.conf and set:
#   notify_script_path = /usr/local/bin/notify_with_discord.sh
# - Add your Discord channel webhook to discord_url.
#
# Notes:
# Hostname lookup requires the dig command.
#   Debian: apt install dnsutils
#   Redhat: dnf install bind-utils

fastnetmon_ip="$1"
fastnetmon_direction="$2"
fastnetmon_pps="$3"
fastnetmon_action="$4"
target_hostname=`dig -x $fastnetmon_ip +short`

webhook_url=""
message_username="FastNetMon"
message_title="FastNetMon Alert - $fastnetmon_direction Attack"

if [ -z "$fastnetmon_ip" ] || [ -z "$webhook_url" ]; then
    echo "Webhook URL / IP not set" 
    exit 1
fi

if [ "$fastnetmon_action" = "ban" ]; then
    # Read data from stdin
    cat > /dev/null
    color="14425373"
elif [ "$fastnetmon_action" = "unban" ]; then
    color="3857437"
else
    color="1957075"
fi

discord_payload="{\"username\": \"$message_username\", \"embeds\": [ { \"title\": \"$message_title\", \"color\": \"$color\", \"fields\": [ {\"name\": \"IP\", \"value\": \"$fastnetmon_ip\n$target_hostname\", \"inline\": true}, {\"name\": \"PPS\", \"value\": \"$fastnetmon_pps\", \"inline\": true}, {\"name\": \"Action Taken\", \"value\": \"$fastnetmon_action\"} ] } ] }"
curl --connect-timeout 30 --max-time 60 -s -S -X POST -H 'Content-type: application/json' --data "$discord_payload" "$webhook_url"
