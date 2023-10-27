#!/usr/bin/env bash

#
# For FastNetMon Advanced you can use native integration: https://fastnetmon.com/docs-fnm-advanced/fastnetmon-advanced-and-slack-integration/
#
#
# Instructions:
#
# Copy this script to /usr/local/bin/
# Edit /etc/fastnetmon.conf and set:
# notify_script_path = /usr/local/bin/notify_with_slack.sh
#
# Add your email address to email_notify.
#
# Add your Slack incoming webhook to slack_url.
# slack_url="https://hooks.slack.com/services/TXXXXXXXX/BXXXXXXXXX/LXXXXXXXXX"
#
# Notes:
# hostname lookup requires the dig command.
# Debian: apt-get install dnsutils
# Redhat: yum install bind-utils

#
# For ban action we will receive attack details to stdin
# Please do not remove the following command because
# FastNetMon will crash in this case (it expect read of data from script side).
#

if [ "$4" = "ban" ]; then
    fastnetmon_output=$(</dev/stdin)
fi

# This script will get following params:
#  $1 client_ip_as_string
#  $2 data_direction
#  $3 pps_as_string
#  $4 action (ban or unban)

# Target hostname
hostname=`dig -x ${1} +short`

# Email:
email_notify="root,please_fix_this_email@domain.ru"

# Slack:
slack_url=""
slack_title="FastNetMon Alert!"
slack_text="IP: ${1}\nHostname: ${hostname}\nAttack: ${2}\nPPS: ${3}\nAction: ${4}\n\n${fastnetmon_output}"
slack_action=${4}

function slackalert () {
    if [ ! -z $slack_url  ] && [ "$slack_action" = "ban" ]; then
        local slack_color="danger"
    elif [ ! -z $slack_url  ] && [ "$slack_action" = "unban" ]; then
        local slack_color="good"
    else
        return 0
    fi
    local slack_payload="{\"attachments\": [ { \"title\": \"${slack_title}\", \"text\": \"${slack_text}\",  \"color\": \"${slack_color}\" } ] }"
    curl --connect-timeout 30 --max-time 60 -s -S -X POST -H 'Content-type: application/json' --data "${slack_payload}" "${slack_url}"
}

if [ "$4" = "unban" ]; then
    # Slack Alert:
    slackalert
    # Unban actions if used
    exit 0
fi

if [ "$4" = "ban" ]; then
    # Email Alert:
    echo "${fastnetmon_output}" | mail -s "FastNetMon Alert: IP $1 blocked because of $2 attack with power $3 pps" $email_notify;
    # Slack Alert:
    slackalert
    # You can add ban code here!
    # iptables -A INPUT -s $1 -j DROP
    # iptables -A INPUT -d $1 -j DROP
    exit 0
fi
