import copy
import importlib.util
from pathlib import Path
import unittest
import json
import os
import subprocess
import tempfile
import sys
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'lib/validate_readme.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

HTML = '<h2>Authorized Administrators (user:password):</h2><p>operator:secret (YOU)<br></p><h2>Authorized Users:</h2><p>member<br>member2<br></p><h2>Critical Services:</h2><p>SSH (openssh-server)<br></p>'
DATA = {'all_users': [{'name': name, 'account_type': role, 'groups': []} for name, role in [('operator','admin'),('member','standard'),('member2','standard')]], 'recent_hires': [], 'terminated_users': [], 'critical_services': ['ssh'], 'groups_to_create': [], 'system_users_to_restrict': []}


class ValidationTests(unittest.TestCase):
    def test_cli_cannot_bypass_invalid_data_with_auto_remediate(self):
        with tempfile.TemporaryDirectory() as tmp:
            source = Path(tmp) / 'readme.html'
            parsed = Path(tmp) / 'parsed.json'
            source.write_text(HTML)
            parsed.write_text('{}')
            result = subprocess.run([sys.executable, str(Path(guard.__file__)), str(source), str(parsed)],
                                    env=dict(os.environ, AUTO_REMEDIATE='1'), capture_output=True)
            self.assertNotEqual(result.returncode, 0)

    def test_no_ai_accepts_prose_but_rejects_unbacked_actions(self):
        from readme_extract import extract
        html = '<h2>Accounts</h2><pre>Authorized Administrators:\noperator\npassword: secret\nAuthorized Users:\nmember\n</pre><p>OpenSSH is a critical service.</p><p>member is no longer an administrator but should still have an account.</p>'
        data = extract(html)
        with patch.dict(os.environ, {'CP_NO_AI': '1', 'AUTO_REMEDIATE': '1'}):
            self.assertEqual(guard.validate(html, data), 2)
            data['terminated_users'] = ['operator']
            with self.assertRaises(ValueError):
                guard.validate(html, data)

    def test_complete(self):
        self.assertEqual(guard.validate(HTML, DATA), 3)

    def test_omitted_user(self):
        data = copy.deepcopy(DATA)
        data['all_users'].pop()
        with self.assertRaises(ValueError): guard.validate(HTML, data)

    def test_role_change(self):
        data = copy.deepcopy(DATA)
        data['all_users'][0]['account_type'] = 'standard'
        with self.assertRaises(ValueError): guard.validate(HTML, data)

    def test_service_removed(self):
        data = copy.deepcopy(DATA)
        data['critical_services'] = []
        with self.assertRaises(ValueError): guard.validate(HTML, data)

    def test_ambiguous_format(self):
        with self.assertRaises(ValueError): guard.validate('<p>Some users</p>', DATA)

    def test_extra_account_action(self):
        data = copy.deepcopy(DATA)
        data['terminated_users'] = ['member']
        with self.assertRaises(ValueError): guard.validate(HTML, data)

    def test_uppercase_and_bullets(self):
        html = '<h2>Authorized Administrators:</h2><p>- Benjamin:secret (YOU)<br></p><h2>Authorized Users:</h2><p>* Alice<br>1. Bob<br></p><h2>Critical Services:</h2><p>- SSH (openssh-server)<br></p>'
        data = {'all_users': [{'name': 'benjamin', 'account_type': 'admin', 'groups': []}, {'name': 'alice', 'account_type': 'standard', 'groups': []}, {'name': 'bob', 'account_type': 'standard', 'groups': []}], 'recent_hires': [], 'terminated_users': [], 'critical_services': ['ssh'], 'groups_to_create': [], 'system_users_to_restrict': []}
        self.assertEqual(guard.validate(html, data), 3)

    def test_plain_text_readme(self):
        text = """Authorized Administrators:
- Benjamin (YOU)

Authorized Users:
- Alice
- Bob

Critical Services:
SSH
"""
        data = {'all_users': [{'name': 'benjamin', 'account_type': 'admin', 'groups': []}, {'name': 'alice', 'account_type': 'standard', 'groups': []}, {'name': 'bob', 'account_type': 'standard', 'groups': []}], 'recent_hires': [], 'terminated_users': [], 'critical_services': ['ssh'], 'groups_to_create': [], 'system_users_to_restrict': []}
        self.assertEqual(guard.validate(text, data), 3)

    def test_auto_remediate_rejects_unbacked_actions(self):
        import os
        old = os.environ.get('AUTO_REMEDIATE')
        os.environ['AUTO_REMEDIATE'] = '1'
        try:
            data = copy.deepcopy(DATA)
            data['terminated_users'] = ['member']
            with self.assertRaisesRegex(ValueError, 'matching README evidence'):
                guard.validate(HTML, data)
        finally:
            if old is None:
                del os.environ['AUTO_REMEDIATE']
            else:
                os.environ['AUTO_REMEDIATE'] = old


if __name__ == '__main__': unittest.main()
