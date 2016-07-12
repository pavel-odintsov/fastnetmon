
Fastnetmon Plugin:  A10 Networks TPS AXAPIv3 integration for FastNetMon  

This script connect to A10 TPS device to create Protected Object and announce BGP route toward upstream router upon FastNetMon ban detection. 

1. Place both Python files at a directory that is reachable by FastNetMon
2. Make sure both scripts are executable, i.e. "chmod +x a10.py fastnetmon_a10_v0.2.py"
3. Modify fastnetmon.conf for notification, i.e. notify_script_path = <path>/fastnetmon_a10_v0.2.py

Please modify the following: 

1. A10 mitigator IP
2. BGP Autonomous System Number
3. Username and Password for your A10 Device. Note that you can use your own password vault or protection schema

For more information about A10 Networks AXAPIv3: 
https://www.a10networks.com/resources/glossary/axapi-custom-management


v0.2 - Jul 7th, 2016 - initial commit

Author: Eric Chou ericc@a10networks.com

Feedback and Feature Requests are Welcomed. 
