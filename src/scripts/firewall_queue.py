from subprocess import call
import pprint
# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

def execute_ip_ban(flow):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(flow)    

    source_ip = flow["source-ipv4"][0]

    print "Will ban IP: " + source_ip + "\n"
    call(["iptables", "-A", "INPUT", "-s", source_ip, "-j", "DROP"])
    return True


