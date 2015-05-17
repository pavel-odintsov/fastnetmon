import subprocess
import pprint
import multiprocessing
import logging
import os

logging.basicConfig(filename='/var/log/firewall_queue_worker.log', level=logging.INFO)
logger = logging.getLogger(__name__)

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
        logger.info("Bad action")
        return False

    if not protocol in allowed_protocols:
        logger.info("Bad protocol")
        return False 

    if len(flags) > 0 and not flags in allowed_flags:
        logger.info("Bad flags")
        return False

    if not(len (source_port) > 0 and source_port.isdigit()):
        return "Bad source port"
        return False

    if not(len (target_port) > 0 and target_port.isdigit()):
        return "Bad target port"
        return False

    # Add validity check for IP for source and target hosts
    ipfw_command = "add {} {} from {} {} to {} {} {}".format(action, protocol, source_host, source_port, target_host, target_port, flags)

    # Add skip for multiple spaces to single

    logger.info( "We generated this command: " + ipfw_command )
    logger.info( "We have following number of processors: " + str(multiprocessing.cpu_count()) )

    execute_command_for_all_ipfw_backends(ipfw_command) 

    return True 

def manage_flow(action, peer_ip, flow):
    if action == 'announce':
        pp = pprint.PrettyPrinter(indent=4)
        logger.info(pp.pformat(flow)) 

        # ipfw_add_rule(action, protocol, source_host, source_port, target_host, target_port, flags)
        action = 'deny' 
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
            logger.info( "We can't process this rule because it will drop whole traffic to the network" )
            return False
   
        if 'destination-port' in flow:
            target_port = flow['destination-port'][0].lstrip('=')

        if 'source-port' in flow:
            source_port = flow['source-port'][0].lstrip('=');

        if 'fragment' in flow:
            if '=is-fragment' in flow['fragment']:
                flags = "fragmented" 
    
        if 'protocol' in flow:
            global_result = True

            for current_protocol in flow['protocol']:
                logger.info("Call ipfw_add_rule")
                result = ipfw_add_rule(action, current_protocol.lstrip('='), source_host, source_port, target_host, target_port, flags)

                if result != True:
                    global_result = False

            return global_result 
        else:
            return ipfw_add_rule(action, "all", source_host, source_port, target_host, target_port, flags) 

        return False
    elif action == 'withdrawal':
        logger.info("We will flush all rules from peer " + peer_ip)
        execute_command_for_all_ipfw_backends("-f flush")
        return True
    else:
        logger.info("Unknown action: " + action)
        return False

def execute_command_for_all_ipfw_backends(ipfw_command):
    for cpu_number in range(0, multiprocessing.cpu_count() - 1): 
        port_for_current_cpu = 5550 + cpu_number

        args = [ '/usr/src/netmap-ipfw/ipfw/ipfw' ]
        args.extend( ipfw_command.split() )

        pp = pprint.PrettyPrinter(indent=4)

        new_env = os.environ.copy()
        # Will fail without explicit conversion:
        #  TypeError: execve() arg 3 contains a non-string value 
        new_env['IPFW_PORT'] = str(port_for_current_cpu)

        subprocess.Popen( args, env=new_env)
