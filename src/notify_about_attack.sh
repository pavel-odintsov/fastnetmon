#!/bin/sh

#
# This script will get following arguments from FastNetMon:
#
#  $1 IP of host which is under attack (incoming attack) or source of attack (outgoing attack)
#  $2 Attack direction: incoming or outgoing
#  $3 Attack bandwidth in packets per second
#  $4 Attack action: ban or unban
#

email_notify="please_fix_this_email@domain.com"

# For ban action we will receive attack details to stdin
# Please do not remove "cat" command because
# FastNetMon will crash in this case as it expects read of data from script side
#

if [ "$4" = "ban" ]; then
    # This action receives multiple statistics about attack's performance and attack's sample to stdin

    cat | mail -s "FastNetMon Community: IP $1 blocked because $2 attack with power $3 pps" $email_notify;
    
    # Please add actions to run when we ban host
    exit 0
fi

if [ "$4" = "unban" ]; then
    # No details provided to stdin here

    # Please add actions to run when we unban host
    exit 0
fi
