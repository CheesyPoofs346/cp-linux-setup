"""Synthetic scenarios independent of SH7 names, questions, and score values."""
import base64
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import readme_extract as rx
import validate_readme
import forensics_det as det

BASE = '<h2>Authorized Administrators:</h2><pre>operator\nsecondadmin</pre><h2>Authorized Users:</h2><pre>member</pre>'


class RequirementsVariationTests(unittest.TestCase):
    def validate(self, html):
        data = rx.extract(html)
        with patch.dict(os.environ, {'CP_NO_AI': '1'}):
            validate_readme.validate(html, data)
        return data

    def test_every_explicit_service_is_preserved(self):
        for separator in (', ', '; ', ' and '):
            with self.subTest(separator=separator):
                data = self.validate(BASE + '<h2>Critical Services:</h2><p>' + separator.join(['Apache', 'Samba', 'PostgreSQL']) + '</p>')
                self.assertEqual(set(data['critical_services']), {'apache2', 'smbd', 'postgresql'})

    def test_unknown_html_heading_ends_service_list(self):
        data = self.validate(BASE + '<h2>Critical Services:</h2><p>SSH</p><h2>Other Requirements</h2><p>Remember to preserve the forensic files.</p>')
        self.assertEqual(data['critical_services'], ['ssh'])

    def test_unknown_html_heading_ends_account_list(self):
        data = self.validate(BASE + '<h2>Other Tasks</h2><p>Backups</p>')
        self.assertEqual({u['name'] for u in data['all_users']}, {'operator', 'secondadmin', 'member'})

    def test_conflicting_explicit_roles_are_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<h2>Authorized Users:</h2><p>secondadmin</p>')

    def test_unsupported_role_change_is_not_silently_ignored(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<p>secondadmin must no longer have administrator privileges.</p>')

    def test_all_comma_separated_accounts_are_preserved(self):
        for names in (['cedar', 'birch'], ['alpha', 'beta', 'gamma']):
            with self.subTest(names=names):
                html = '<h2>Authorized Administrators:</h2><p>operator</p><h2>Authorized Users:</h2><p>' + ', '.join(names) + '</p>'
                self.assertEqual({u['name'] for u in self.validate(html)['all_users']}, {'operator', *names})

    def test_unrecognized_account_annotation_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<p>someone else who might have access</p>')

    def test_existing_groups_and_prose_role_changes_remain_supported(self):
        data = self.validate(BASE + '<p>secondadmin is no longer an administrator but should still have an account.</p>')
        self.assertEqual(next(u['account_type'] for u in data['all_users'] if u['name'] == 'secondadmin'), 'standard')

    def test_prose_prefix_does_not_change_the_target_username(self):
        data = self.validate(BASE + '<p>Please remember that secondadmin is no longer an administrator.</p>')
        self.assertEqual(next(u['account_type'] for u in data['all_users'] if u['name'] == 'secondadmin'), 'standard')

    def test_unsupported_negated_admin_instruction_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<p>secondadmin must not be an administrator.</p>')

    def test_negated_admin_hire_is_never_promoted(self):
        html = BASE + '<p>A new employee (delta) has been hired as a standard user, not an administrator.</p>'
        data = self.validate(html)
        self.assertEqual(data['recent_hires'][0]['account_type'], 'standard')

    def test_unknown_role_change_target_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<p>unlisted should be an administrator.</p>')

    def test_explicit_admin_account_creation_retains_role(self):
        data = self.validate(BASE + '<p>Create an admin account for delta.</p>')
        self.assertEqual(data['recent_hires'], [{'name': 'delta', 'account_type': 'admin', 'groups': []}])

    def test_role_changes_apply_to_new_hires(self):
        for first, instruction, expected in (
                ('administrator', 'delta is no longer an administrator.', 'standard'),
                ('standard user', 'delta must be an administrator.', 'admin')):
            with self.subTest(first=first):
                data = self.validate(BASE + '<p>A new employee (delta) has been hired as an ' + first + '.</p><p>' + instruction + '</p>')
                self.assertEqual(data['recent_hires'][0]['account_type'], expected)

    def test_inline_header_lists_are_not_discarded(self):
        html = '<h2>Authorized Administrators (user:password): operator:Example1</h2><h2>Authorized Users: cedar, birch</h2><h2>Critical Services: Apache, Samba</h2>'
        data = self.validate(html)
        self.assertEqual({u['name'] for u in data['all_users']}, {'operator', 'cedar', 'birch'})
        self.assertEqual(set(data['critical_services']), {'apache2', 'smbd'})

    def test_unrecognized_inline_account_heading_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate('<h2>Authorized Administrators:</h2><p>operator</p><h2>Authorized Users are cedar and birch</h2>')

    def test_unrecognized_inline_service_heading_is_rejected(self):
        with self.assertRaises(ValueError):
            self.validate(BASE + '<h2>Required Services - Samba and PostgreSQL</h2>')


class EvidenceVariationTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        for p in ('etc', 'home/ada/Documents', 'var/tmp', 'usr/lib', 'var/lib/dpkg/info'):
            (self.root / p).mkdir(parents=True)
        (self.root / 'etc/passwd').write_text('ada:x:1100:1100::/home/ada:/bin/bash\n')
        self.ev = det.Evidence(self.root)

    def question(self, text):
        return {'content': '-' * 40 + '\n' + text + '\nANSWER: \n', 'number': 17}

    def test_explicit_base64_file_outside_home_is_supported(self):
        (self.root / 'var/tmp/notice.txt').write_bytes(base64.b64encode(b'original evidence'))
        result = det.solve(self.question('Decode the base64 text in /var/tmp/notice.txt.'), self.ev)
        self.assertIsNotNone(result)
        self.assertEqual(result['answers'], ['original evidence'])

    def test_explicit_base64_filename_with_spaces(self):
        (self.root / 'home/ada/Documents/hidden message.txt').write_bytes(base64.b64encode(b'specific evidence'))
        result = det.solve(self.question('Decode the base64 text in "/home/ada/Documents/hidden message.txt".'), self.ev)
        self.assertIsNotNone(result)
        self.assertEqual(result['answers'], ['specific evidence'])

    def test_multiple_backdoors_are_not_high_confidence_guesses(self):
        for name in ('alpha.so', 'omega.so'):
            (self.root / 'usr/lib' / name).write_text("import socket\ns=socket.socket()\ns.connect(('10.4.3.2', 4444))\n")
        result = det.solve(self.question('What is the path of the backdoor file?'), self.ev)
        self.assertEqual(result['confidence'], 'medium')

    def test_explicit_short_base64_value_is_decoded(self):
        (self.root / 'var/tmp/short.txt').write_text('QQ==')
        result = det.solve(self.question('Decode the base64 text in /var/tmp/short.txt.'), self.ev)
        self.assertIsNotNone(result)
        self.assertEqual(result['answers'], ['A'])

    def test_base64_file_symlink_is_not_followed_outside_fixture(self):
        with tempfile.NamedTemporaryFile() as external:
            external.write(base64.b64encode(b'outside evidence'))
            external.flush()
            (self.root / 'home/ada/Documents/link.txt').symlink_to(external.name)
            result = det.solve(self.question('Decode the base64 text in /home/ada/Documents/link.txt.'), self.ev)
            self.assertIsNone(result)

