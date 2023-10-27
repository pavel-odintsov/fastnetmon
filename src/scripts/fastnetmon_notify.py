#!/usr/bin/python

import smtplib
import sys
from sys import stdin
import optparse
import sys
import logging

LOG_FILE = "/var/log/fastnetmon-notify.log"
MAIL_HOSTNAME="localhost"
MAIL_FROM="infra@example.com"
MAIL_TO="infra@example.com"


logger = logging.getLogger("DaemonLog")
logger.setLevel(logging.INFO)
formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
handler = logging.FileHandler(LOG_FILE)
handler.setFormatter(formatter)
logger.addHandler(handler)



client_ip_as_string=sys.argv[1]
data_direction=sys.argv[2]
pps_as_string=int(sys.argv[3])
action=sys.argv[4]

logger.info(" - " . join(sys.argv))



def mail(subject, body):
    fromaddr = MAIL_FROM
    toaddrs  = [MAIL_TO]

    # Add the From: and To: headers at the start!
    headers = ("From: %s\r\nTo: %s\r\nSubject: %s\r\n\r\n"
           % (
                fromaddr,
                ", ".join(toaddrs), 
                subject
            )
    )

    msg = headers + body

    server = smtplib.SMTP(MAIL_HOSTNAME)
    #server.set_debuglevel(1)
    server.sendmail(fromaddr, toaddrs, msg)
    server.quit()


if action == "unban":
    subject = "FastNetMon Community: IP %(client_ip_as_string)s unblocked because %(data_direction)s attack with power %(pps_as_string)d pps" % {
        'client_ip_as_string': client_ip_as_string,
        'data_direction': data_direction,
        'pps_as_string' : pps_as_string,
        'action' : action
    }

    mail(subject, "unban")
    sys.exit(0)
elif action == "ban":
    subject = "FastNetMon Community: IP %(client_ip_as_string)s blocked because %(data_direction)s attack with power %(pps_as_string)d pps" % {
        'client_ip_as_string': client_ip_as_string,
        'data_direction': data_direction,
        'pps_as_string' : pps_as_string,
        'action' : action
    }

    body = "".join(sys.stdin.readlines())
    mail(subject, body)

    sys.exit(0)
else:
    sys.exit(0)




