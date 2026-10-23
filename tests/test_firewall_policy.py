import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import firewall_policy


class FirewallPolicyTests(unittest.TestCase):
    def shell(self, script, services):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'ufw.log'
            prelude = '''source "$1"
ufw() { printf '%s\\n' "$*" >> "$COMMAND_LOG"; return 0; }
'''
            p = subprocess.run(['bash', '-c', prelude + script, 'test', str(ROOT / 'modules/defensive_countermeasures.sh')],
                               env=dict(os.environ, README_DATA=json.dumps({'critical_services': services}), COMMAND_LOG=str(log)), capture_output=True)
            return p, log.read_text() if log.exists() else ''

    def test_required_postgres_dns_mail_and_printing_ports_are_allowed(self):
        p, log = self.shell('allow_critical_services_ports', ['postgresql', 'bind9', 'postfix', 'cups'])
        self.assertEqual(p.returncode, 0, p.stderr)
        for port in ('5432/tcp', '53/tcp', '53/udp', '25/tcp', '631/tcp'):
            self.assertIn('allow ' + port + '\n', log)

    def test_unknown_service_stops_before_firewall_mutation(self):
        p, log = self.shell('run_defensive_countermeasures', ['custom-database'])
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(log, '')

    def test_failed_allow_does_not_report_success(self):
        p, _ = self.shell('ufw() { return 1; }; allow_critical_services_ports', ['postgresql'])
        self.assertNotEqual(p.returncode, 0)

    def test_required_port_does_not_get_a_later_deny_rule(self):
        script = 'command_exists() { return 1; }; allow_critical_services_ports; deny_unnecessary_ports'
        p, log = self.shell(script, ['postfix'])
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertNotIn('deny 25/tcp\n', log)

    def test_nondefault_ssh_and_desktop_programs(self):
        self.assertEqual(firewall_policy.plan({'critical_services': ['sshd.service', 'chromium']}, 2222), ['2222/tcp'])

    def test_invalid_or_dynamic_requirements_are_rejected(self):
        for data in ({}, {'critical_services': [None]}, {'critical_services': ['nfs-server']}):
            with self.subTest(data=data), self.assertRaises(ValueError):
                firewall_policy.plan(data)

    def test_existing_global_denies_and_ranges_stop_for_review(self):
        for rule in ('ufw deny 5432/tcp', 'ufw reject in proto tcp to any port 5432', 'ufw deny 5400:5500/tcp'):
            with self.subTest(rule=rule), self.assertRaises(ValueError):
                firewall_policy.check_existing(rule, ['5432/tcp'])
        firewall_policy.check_existing('ufw deny 25/udp', ['25/tcp'])
        firewall_policy.check_existing('ufw deny from 192.0.2.1 to any port 25', ['25/tcp'])

    def test_operator_ssh_is_preserved_or_requires_review(self):
        connection = '192.0.2.1 40000 192.0.2.2 2222'
        self.assertEqual(firewall_policy.plan({'critical_services': ['ssh']}, 22, connection), ['22/tcp', '2222/tcp'])
        with self.assertRaises(ValueError):
            firewall_policy.plan({'critical_services': []}, 22, connection)

    def test_existing_deny_stops_before_allow_commands(self):
        script = '''ufw() {
  if [[ "$*" == 'show added' ]]; then echo 'ufw deny 5432/tcp'; return 0; fi
  printf '%s\\n' "$*" >> "$COMMAND_LOG"
}
allow_critical_services_ports
'''
        p, log = self.shell(script, ['postgresql'])
        self.assertEqual(p.returncode, 2, p.stderr)
        self.assertEqual(log, '')

    def test_ipv6_setting_is_appended_when_missing(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'ufw-default'
            path.write_text('# site configuration\nDEFAULT_INPUT_POLICY="DROP"\n')
            script = 'source "$1"; backup_file() { :; }; configure_ipv6_parity "$2"'
            p = subprocess.run(['bash', '-c', script, 'test', str(ROOT / 'modules/defensive_countermeasures.sh'), str(path)], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn('\nIPV6=yes\n', path.read_text())
