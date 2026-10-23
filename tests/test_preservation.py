import os
from pathlib import Path
import subprocess
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]


class PreservationTests(unittest.TestCase):
    def test_hosts_retains_internal_names_and_is_idempotent(self):
        with tempfile.TemporaryDirectory() as directory:
            hosts = Path(directory) / 'hosts'
            original = '10.20.30.4 database.internal report.internal\n# required virtual host\n2001:db8::4 portal.internal\n'
            hosts.write_text(original)
            script = '''source "$1"
backup_file() { :; }
hostname() { echo fixturehost; }
body=$(declare -f sanitize_hosts_file)
body=${body//\\/etc\\/hosts/$HOST_FIXTURE}
eval "$body"
sanitize_hosts_file
cp "$HOST_FIXTURE" "$HOST_FIXTURE.first"
sanitize_hosts_file
cmp "$HOST_FIXTURE" "$HOST_FIXTURE.first"
'''
            p = subprocess.run(['bash', '-c', script, 'test', str(ROOT / 'modules/os_settings.sh')],
                               env=dict(os.environ, HOST_FIXTURE=str(hosts)), capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertIn(original, hosts.read_text())
            self.assertIn('127.0.0.1', hosts.read_text())
            self.assertIn('::1', hosts.read_text())

    def test_log_root_remains_traversable_by_service_accounts(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory)
            path.chmod(0o750)
            p = subprocess.run(['bash', '-c', 'source "$1"; chown() { return 0; }; fix_log_root_directory "$2"',
                                'test', str(ROOT / 'modules/os_settings.sh'), directory], capture_output=True)
            self.assertEqual(p.returncode, 0, p.stderr)
            self.assertTrue(path.stat().st_mode & 0o001)
            self.assertFalse(path.stat().st_mode & 0o022)

    def test_both_kernel_modules_propagate_baseline_failure(self):
        for module, function in [('security_policy.sh', 'apply_hardened_sysctl'), ('extra_hardening.sh', 'extra_sysctl_extra')]:
            with self.subTest(module=module):
                script = 'source "$1"; python3() { return 19; }; backup_sysctl_conf() { return 0; }; "$2"'
                # Redirect legacy fixed paths in an isolated copy before executing anything.
                with tempfile.TemporaryDirectory() as directory:
                    source = (ROOT / 'modules' / module).read_text().replace('source "$SCRIPT_DIR/../lib/utils.sh"', 'source "' + str(ROOT / 'lib/utils.sh') + '"')
                    source = source.replace('/etc/', directory + '/etc/').replace('/var/backups/', directory + '/var/backups/')
                    (Path(directory) / 'etc/sysctl.d').mkdir(parents=True)
                    copy = Path(directory) / 'module.sh'
                    copy.write_text(source)
                    p = subprocess.run(['bash', '-c', script, 'test', str(copy), function], capture_output=True)
                    self.assertNotEqual(p.returncode, 0, p.stdout)
