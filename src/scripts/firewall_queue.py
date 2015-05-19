import subprocess
import pprint
import multiprocessing
import logging
import os

logging.basicConfig(filename='/var/log/firewall_queue_worker.log', level=logging.INFO)
logger = logging.getLogger(__name__)

firewall_backend = 'netmap_ipfw'

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

class AbstractFirewall:
    pass

class Iptables(AbstractFirewall):
    def __init__(self):
        self_iptables_path = '/sbin/iptables'
        

class Ipfw(AbstractFirewall):
    def __init__(self):
        logger.info( "We have following number of processors: " + str(multiprocessing.cpu_count()) )

        self.number_of_netmap_instances = multiprocessing.cpu_count()
        self.netmap_path = '/usr/src/netmap-ipfw/ipfw/ipfw'

    def execute_command_for_all_ipfw_backends(self, ipfw_command):
        for instance_number in range(0, self.number_of_netmap_instances - 1): 
            port_for_current_instance = 5550 + instance_number

            args = [ self.netmap_path ]
            args.extend( ipfw_command.split() )

            pp = pprint.PrettyPrinter(indent=4)

            new_env = os.environ.copy()
            # Will fail without explicit conversion:
            #  TypeError: execve() arg 3 contains a non-string value 
            new_env['IPFW_PORT'] = str(port_for_current_instance)

            subprocess.Popen( args, env=new_env)
    def flush_rules(self, peer_ip):
        # If we got blank flow we should remove all rules for this peer
        logger.info("We will flush all rules from peer " + peer_ip)
        # TODO: switch to another code parser
        self.execute_command_for_all_ipfw_backends("-f flush") 
    def add_rules(self, pyflow_list):
        allowed_actions = [ 'allow', 'deny' ]
        allowed_protocols = [ 'udp', 'tcp', 'all', 'icmp' ]
        allowed_flags = ['fragmented']

        for pyflow_rule in pyflow_list:
            if not pyflow_rule['action'] in allowed_actions:
                logger.info("Bad action")
                return False

            if not pyflow_rule['protocol'] in allowed_protocols:
                logger.info("Bad protocol")
                return False 

            if len(pyflow_rule['flags']) > 0 and not pyflow_rule['flags'] in allowed_flags:
                logger.info("Bad flags")
                return False

            if len (pyflow_rule['source_port']) > 0 and not pyflow_rule['source_port'].isdigit():
                return "Bad source port"
                return False

            if len (pyflow_rule['target_port']) > 0 and not pyflow_rule['target_port'].isdigit():
                return "Bad target port: " + pyflow_rule['target_port']
                return False

            # Add validity check for IP for source and target hosts
            ipfw_command = "add %(action) %(protocol) from %(source_host) %(source_port) to %(target_host) %(target_port) %(flags)".format(pyflow_rule)
            # Add skip for multiple spaces to single
            logger.info( "We generated this command: " + ipfw_command )

            self.execute_command_for_all_ipfw_backends(ipfw_command) 

        return True 

firewall = Ipfw()

def manage_flow(action, peer_ip, flow):
    allowed_actions = [ 'withdrawal', 'announce' ]

    if action not in allowed_actions:
        logger.warning("Action " + action + " is not allowed")
        return False

    pp = pprint.PrettyPrinter(indent=4)
    logger.info(pp.pformat(flow)) 

    if action == 'withdrawal' and flow == None:
        firewall.flush_rules(peer_ip)
        return True

    py_flow_list = convert_exabgp_to_pyflow(flow)
    logger.info("Call add_rules") 
    return firewall.add_rules(py_flow_list)

def convert_exabgp_to_pyflow(flow):
    # Flow in python format, here
    # We use customer formate because ExaBGP output is not so friendly for firewall generation
    current_flow = {
        'action'      : 'deny', 
        'protocol'    : 'all',
        'source_port' : '',
        'source_host' : 'any',
        'target_port' : '',
        'target_host' : 'any',
        'flags'       : '',
    }
 
    # We support only one subnet for source and destination 
    if 'source-ipv4' in flow:
        current_flow['source_host'] = flow["source-ipv4"][0]

    if 'destination-ipv4' in flow:
        current_flow['target_host'] = flow["destination-ipv4"][0]

    if current_flow['source_host'] == "any" and current_flow['target_host'] == "any":
        logger.info( "We can't process this rule because it will drop whole traffic to the network" )
        return False
   
    if 'destination-port' in flow:
        current_flow['target_port'] = flow['destination-port'][0].lstrip('=')

    if 'source-port' in flow:
        current_flow['source_port'] = flow['source-port'][0].lstrip('=');

    if 'fragment' in flow:
        if '=is-fragment' in flow['fragment']:
            current_flow['flags'] = "fragmented" 
   
    pyflow_list = []
 
    if 'protocol' in flow:
        global_result = True

        for current_protocol in flow['protocol']:
            current_flow['protocol'] = current_protocol.lstrip('=')
            pyflow_list.append(current_flow)
    else:
        current_flow['protocol'] = 'all'
        pyflow_list.append(current_flow)

    return pyflow_list
