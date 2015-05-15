from subprocess import call

def execute_ip_ban(ip):
    print "Will ban IP: " + ip + "\n"
    call(["iptables", "-A", "INPUT", "-s", ip, "-j", "DROP"])
    return True


