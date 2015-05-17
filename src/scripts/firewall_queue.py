from subprocess import call
import pprint
import multiprocessing

# u'destination-ipv4': [u'10.0.0.2/32'],
# u'destination-port': [u'=3128'],
# u'protocol': [u'=tcp'],
# u'source-ipv4': [u'10.0.0.1/32'],
# u'string': u'flow destination-ipv4 10.0.0.2/32 source-ipv4 10.0.0.1/32 protocol =tcp destination-port =3128'}

# Ban specific protocol:
# ipfw add deny udp from any to 10.10.10.221/32

# Block fragmentation:
# ipfw add deny all from any to 10.10.10.221/32 frag

# Block all traffic:
# ipfw add deny all from any to 10.10.10.221/32

# Black traffic from specific port:
# ipfw add deny udp from any 53 to 10.10.10.221/32 

# Block traffic to specific port:
# ipfw add deny udp from any to 10.10.10.221/32 8080

# action deny/allow
def ipfw_add_rule(action, protocol, source_host, source_port, target_host, target_port, flags):
    allowed_actions = [ 'allow', 'deny' ]
    allowed_protocols = [ 'udp', 'tcp', 'all', 'icmp' ]
    allowed_flags = ['fragmented']

    if not action in allowed_actions:
        print "Bad action"
        return False

    if not protocol in allowed_protocols:
        print "Bad protocol"
        return False 

    if len(flag) > 0 and not flag in allowed_flags:
        print "Bad flags"
        return False

    if not(len (source_port) > 0 and source_port.isdigit()):
        return "Bad source port"
        return False

    if not(len (target_port) > 0 and target_port.isdigit()):
        return "Bad target port"
        return False

    # Add validity check for IP for source and target hosts
    ipfw_command = "ipfw add {} {} from {} {} to {} {} {}".format(action, protocol, source_host, source_port, target_host, target_port, flags)

    # Add skip for multiple spaces to single

    print "We generated this command: " + ipfw_command
    print "We have following number of processors: " + multiprocessing.cpu_count()
    return True 

def execute_ip_ban(flow):
    pp = pprint.PrettyPrinter(indent=4)
    pp.pprint(flow)    

    if not 'destination-ipv4' in flow:
        print "Internal error. I can't process packet without destination IP"
        return False

    # ipfw_add_rule(action, protocol, source_host, source_port, target_host, target_port, flags)
    action = 'drop' 
    protocol = 'all'
    source_port = ''
    source_host = 'any'
    target_port = ''
    target_host = 'any'
    flags = ''   
  
    # We support only one subnet for source and destination 
    if 'source-ipv4' in flow:
        source_host = flow["source-ipv4"][0]

    if 'destination-ipv4' in flow:
        target_host = flow["destination-ipv4"][0]

    if source_host == "any" and target_host == "any":
        print "We can't process this rule because it will drop whole traffic to the network"
        return False
   
    if 'fragment' in flow:
        if 'is-fragment' in flow['fragment']:
            flags = "frag" 
    
    if 'protocol' in flow:
        for current_protocol in flow['protocol']:
            ipfw_add_rule(action, source_host, source_port, target_host, target_port, flags) 

    return True


