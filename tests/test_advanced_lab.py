import importlib.util
from pathlib import Path
import unittest
import tempfile
import os
from unittest.mock import patch

PATH = Path(__file__).resolve().parents[1] / 'practice/advanced/score.py'


class AdvancedLabTests(unittest.TestCase):
    def load(self):
        spec = importlib.util.spec_from_file_location('lab_score', PATH)
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        return module

    def test_seed_validation(self):
        mod = self.load()
        for seed in ('../x', 'a;id', '-1', '0', '100000'):
            with self.assertRaises(ValueError):
                mod.scenario(seed)
        self.assertEqual(mod.scenario('17'), mod.scenario('17'))
        self.assertNotEqual(mod.scenario('17'), mod.scenario('29'))

    def test_unique_substantive_checks(self):
        checks = self.load().checks('17')
        self.assertGreaterEqual(len(checks), 60)
        self.assertEqual(len({c['id'] for c in checks}), len(checks))
        self.assertTrue(all(c['command'] for c in checks))
        self.assertTrue(all('grep - ' not in c['command'] for c in checks))

    @unittest.skipUnless(os.name=='posix','Requires bash')
    def test_probe_errors_never_pass(self):
        mod = self.load()
        result = mod.evaluate([{'id':'broken','command':'exit 127','points':2,'penalty':0}])
        self.assertEqual(result['earned'], 0)
        self.assertEqual(result['checks'][0]['status'], 'ERROR')

    @unittest.skipUnless(os.name=='posix','Requires bash')
    def test_failed_negative_probes_do_not_earn_points(self):
        mod=self.load()
        with tempfile.TemporaryDirectory() as directory:
            for name in ('curl','getfacl','sudo','dpkg','find','id','grep'):
                path=Path(directory)/name
                path.write_text('#!/bin/sh\nexit 2\n');path.chmod(0o755)
            wanted={'nginx.hide-version','privilege.shadow-acl','sudo.staff-no-nopasswd',
                    'updates.dpkg-consistent','nginx.webroot-not-world-writable',
                    'accounts.staff-not-admin','pam.no-permit-bypass'}
            with patch.dict(os.environ,{'PATH':directory+':'+os.environ['PATH']}):
                result=mod.evaluate([row for row in mod.checks('17') if row['id'] in wanted])
            self.assertEqual(len(result['checks']),len(wanted))
            self.assertEqual(result['earned'],0,result)

    @unittest.skipUnless(os.name=='posix','Requires bash')
    def test_removed_timer_is_distinct_from_probe_error(self):
        mod=self.load();row=next(row for row in mod.checks('28') if row['id']=='persistence.timer-marker')
        with tempfile.TemporaryDirectory() as directory:
            executable=Path(directory)/'systemctl'
            for output,code,expected in [('not-found',4,'PASS'),('Permission denied',4,'FAIL'),('command missing',127,'FAIL'),('enabled',0,'FAIL')]:
                executable.write_text(f'#!/bin/sh\nprintf "%s\\n" "{output}"\nexit {code}\n');executable.chmod(0o755)
                with patch.dict(os.environ,{'PATH':directory+':'+os.environ['PATH']}):
                    self.assertEqual(mod.evaluate([row])['checks'][0]['status'],expected)

    @unittest.skipUnless(os.name=='posix','Requires bash')
    def test_availability_penalties(self):
        mod = self.load()
        result = mod.evaluate([
            {'id':'secure','command':'true','points':5,'penalty':0},
            {'id':'service','command':'false','points':0,'penalty':10}])
        self.assertEqual(result['penalties'], 10)
        self.assertEqual(result['score'], 90)

    def test_builder_refuses_existing_vm_definition(self):
        spec = importlib.util.spec_from_file_location('vm_builder', PATH.with_name('vmware_lab.py'))
        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lab.vmx').write_text('existing disk chain')
            with self.assertRaises(FileExistsError):
                mod.require_new_vm(root)
            self.assertEqual((root / 'lab.vmx').read_text(), 'existing disk chain')


if __name__ == '__main__':
    unittest.main()
