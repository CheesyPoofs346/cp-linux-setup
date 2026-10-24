import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'lib'))
import firewall_policy as policy

class LocalServiceFirewallTests(unittest.TestCase):
    def test_loopback_backend_does_not_block_known_service_ports(self):
        rules=policy.plan({'critical_services':['ssh','nginx','research-api']},local_only={'research-api'})
        self.assertIn('80/tcp',rules)
        self.assertNotIn('8081/tcp',rules)

    def test_unverified_custom_service_still_requires_review(self):
        with self.assertRaises(ValueError): policy.plan({'critical_services':['ssh','unknown']})

    def test_wildcard_socket_prevents_local_only_classification(self):
        text='tcp LISTEN 0 5 127.0.0.1:8081 0.0.0.0:* users:(("python",pid=17,fd=3))\n'
        self.assertTrue(policy.loopback_only(17,text))
        self.assertFalse(policy.loopback_only(18,text))
        self.assertFalse(policy.loopback_only(17,text.replace('127.0.0.1:8081','0.0.0.0:8081')))

if __name__=='__main__': unittest.main()
