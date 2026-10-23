import importlib.util
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location('kernel_policy', Path(__file__).resolve().parents[1] / 'lib/kernel_policy.py')
policy = importlib.util.module_from_spec(spec)
spec.loader.exec_module(policy)


class KernelPolicyTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for key in policy.SETTINGS:
            p = self.root / 'proc/sys' / key.replace('.', '/')
            p.parent.mkdir(parents=True, exist_ok=True)
            p.write_text('0')
        (self.root / 'etc/sysctl.d').mkdir(parents=True)

    def command(self, args, **kwargs):
        return subprocess.CompletedProcess(args, 0, str(policy.SETTINGS[args[2]]) if args[1] == '-n' else '')

    def test_preserves_unrelated_role_settings_and_repairs_owned_profile(self):
        original = b'# local config\nnet.ipv6.conf.all.disable_ipv6 = 0\nnet.ipv4.ip_forward = 1\ncustom.site = 17\nkernel.randomize_va_space = 0\n'
        source = self.root / 'etc/sysctl.conf'
        source.write_bytes(original)
        owned = self.root / 'etc/sysctl.d/99-cp-hardening.conf'
        owned.write_text('kernel.randomize_va_space = 0\n')
        policy.apply(self.root, self.command)
        self.assertIn(b'custom.site = 17', source.read_bytes())
        self.assertIn(b'net.ipv4.ip_forward = 1', source.read_bytes())
        self.assertIn(b'net.ipv6.conf.all.disable_ipv6 = 0', source.read_bytes())
        self.assertNotIn(b'\nkernel.randomize_va_space = 0', source.read_bytes())
        self.assertIn('kernel.randomize_va_space = 2', owned.read_text())
        self.assertNotIn('unprivileged_userns_clone', owned.read_text())
        self.assertNotIn('disable_ipv6', owned.read_text())
        self.assertNotIn('ptrace_scope', owned.read_text())
        self.assertEqual(next((self.root / 'var/backups').rglob('sysctl.conf')).read_bytes(), original)
        before = source.read_bytes(), owned.read_bytes()
        policy.apply(self.root, self.command)
        self.assertEqual(before, (source.read_bytes(), owned.read_bytes()))

    def test_failed_kernel_write_is_not_success(self):
        with self.assertRaisesRegex(ValueError, 'Could not apply'):
            policy.apply(self.root, lambda args, **kw: subprocess.CompletedProcess(args, 1, ''))

    def test_failed_readback_is_not_success(self):
        with self.assertRaisesRegex(ValueError, 'verification failed'):
            policy.apply(self.root, lambda args, **kw: subprocess.CompletedProcess(args, 0, '999'))

    def test_check_does_not_change_files(self):
        policy.apply(self.root, self.command, check=True)
        self.assertEqual(list((self.root / 'etc/sysctl.d').iterdir()), [])

    def test_external_config_symlink_is_not_modified(self):
        with tempfile.TemporaryDirectory() as outside:
            target = Path(outside) / 'external.conf'
            target.write_text('kernel.randomize_va_space = 0\n')
            (self.root / 'etc/sysctl.d/external.conf').symlink_to(target)
            policy.apply(self.root, self.command)
            self.assertEqual(target.read_text(), 'kernel.randomize_va_space = 0\n')

    def test_managed_config_symlink_is_rejected(self):
        target = self.root / 'etc/target'
        target.write_text('original')
        (self.root / 'etc/sysctl.d/99-cp-hardening.conf').symlink_to(target)
        with self.assertRaisesRegex(ValueError, 'symlink'):
            policy.apply(self.root, self.command)
        self.assertEqual(target.read_text(), 'original')
