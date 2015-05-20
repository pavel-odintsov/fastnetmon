#!/usr/bin/python

import firewall_queue
import unittest
import copy

standard_flow = {
    'action'        : 'deny', 
    'protocol'      : 'all',
    'source_port'   : '',
    'source_host'   : 'any',
    'target_port'   : '',
    'target_host'   : 'any',
    'fragmentation' : False,
    'packet_length' : 'any',
    'tcp_flags'     : [],
}

peer_ip = '10.0.3.4'

class TestIptablesRulesGeneration(unittest.TestCase):
    # Executed before any tests
    def setUp(self):
        self.firewall = firewall_queue.Iptables()
        self.standard_flow = copy.copy(standard_flow)
    def test_standard_block_rule(self):
        self.standard_flow['target_host'] = '10.10.10.10';

        generated_rule = self.firewall.generate_rule(peer_ip, self.standard_flow)
        self.assertMultiLineEqual(' '.join(generated_rule), 
            "-I FORWARD -d 10.10.10.10 -m comment --comment Received from: 10.0.3.4 -j DROP");
    def test_fragmentation_block(self):
        self.standard_flow['fragmentation'] = True
        self.standard_flow['target_host'] = '10.10.10.10';

        generated_rule = self.firewall.generate_rule(peer_ip, self.standard_flow)
        
        self.assertMultiLineEqual(' '.join(generated_rule),  
            "-I FORWARD -d 10.10.10.10 --fragment -m comment --comment Received from: 10.0.3.4 -j DROP")
    def test_udp_block(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'udp';

        generated_rule = self.firewall.generate_rule(peer_ip, self.standard_flow)

        self.assertMultiLineEqual(' '.join(generated_rule),
            "-I FORWARD -p udp -d 10.10.10.10 -m comment --comment Received from: 10.0.3.4 -j DROP")
    def test_tcp_block(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'tcp';

        generated_rule = self.firewall.generate_rule(peer_ip, self.standard_flow)

        self.assertMultiLineEqual(' '.join(generated_rule),
            "-I FORWARD -p tcp -d 10.10.10.10 -m comment --comment Received from: 10.0.3.4 -j DROP")
    def test_tcp_block_with_destination_port(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'tcp';
        self.standard_flow['target_port'] = str(6667);
        
        self.assertMultiLineEqual(' '.join(self.firewall.generate_rule(peer_ip, self.standard_flow)),
            "-I FORWARD -p tcp -d 10.10.10.10 --dport 6667 -m comment --comment Received from: 10.0.3.4 -j DROP")
    def test_udp_block_with_destination_port(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'udp';
        self.standard_flow['target_port'] = str(6667);
    
        self.assertMultiLineEqual(' '.join(self.firewall.generate_rule(peer_ip, self.standard_flow)),
            "-I FORWARD -p udp -d 10.10.10.10 --dport 6667 -m comment --comment Received from: 10.0.3.4 -j DROP")
    def test_udp_block_with_only_source_port(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'udp';
        self.standard_flow['source_port'] = str(65000);
    
        self.assertMultiLineEqual(' '.join(self.firewall.generate_rule(peer_ip, self.standard_flow)),
            "-I FORWARD -p udp -d 10.10.10.10 --sport 65000 -m comment --comment Received from: 10.0.3.4 -j DROP")

    def test_tcp_block_with_only_source_port(self):
        self.standard_flow['target_host'] = '10.10.10.10';
        self.standard_flow['protocol'] = 'tcp';
        self.standard_flow['source_port'] = str(65000);

        self.assertMultiLineEqual(' '.join(self.firewall.generate_rule(peer_ip, self.standard_flow)),
            "-I FORWARD -p tcp -d 10.10.10.10 --sport 65000 -m comment --comment Received from: 10.0.3.4 -j DROP")

if __name__ == '__main__':
    suite = unittest.TestLoader().loadTestsFromTestCase(TestIptablesRulesGeneration)
    unittest.TextTestRunner(verbosity=2).run(suite)

