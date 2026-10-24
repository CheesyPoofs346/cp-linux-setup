import json
import sys
import os
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import readme_extract as rx
import validate_readme

BASE = """<html><body><h1>Image 1</h1><p>Welcome. Create a group called "devs" and add bob, carol and dave.</p>
<h2>Authorized Administrators (user:password):</h2><pre>alice:Secret1 (YOU)
zed</pre>
<h2>Authorized Users:</h2><ul><li>bob</li><li>carol (groups: devs, audio)</li><li>dave</li></ul>
<h2>Critical Services:</h2><ul><li>SSH (openssh-server)</li><li>Apache</li></ul>
<h2>Terminated Employees</h2><ul><li>mallory</li><li>trent</li></ul>
<h2>New Hires</h2><ul><li>erin</li><li>frank (admin)</li></ul></body></html>"""


class ReadmeExtractTests(unittest.TestCase):
    def test_service_list_ends_at_business_prose(self):
        data=rx.extract('Authorized Administrators:\nalice\nAuthorized Users:\nbob\nCritical Services:\nOpenSSH (ssh), nginx, PostgreSQL, Samba (smbd), research-api.\n\nSSH on port 22 and the existing public key must continue working.\nThe web site and its API must return the ledger.\n')
        self.assertEqual(set(data['critical_services']), {'ssh','nginx','postgresql','smbd','research-api'})

    def test_sections_and_validation(self):
        d = rx.extract(BASE)
        self.assertEqual({u['name']: u['account_type'] for u in d['all_users']},
                         {'alice': 'admin', 'zed': 'admin', 'bob': 'standard', 'carol': 'standard', 'dave': 'standard'})
        self.assertEqual(d['critical_services'], ['ssh', 'apache2'])
        self.assertEqual(d['terminated_users'], ['mallory', 'trent'])
        self.assertEqual([(h['name'], h['account_type']) for h in d['recent_hires']], [('erin', 'standard'), ('frank', 'admin')])
        self.assertEqual(d['groups_to_create'], [{'name': 'devs', 'members': ['bob', 'carol', 'dave']}])
        self.assertEqual(next(u for u in d['all_users'] if u['name'] == 'carol')['groups'], ['audio', 'devs'])
        self.assertEqual(d['passwords'], {'alice': 'Secret1'})
        self.assertEqual(d['unparsed_hints'], [])
        with patch.dict(os.environ, {'AUTO_REMEDIATE': '1'}):
            self.assertEqual(validate_readme.validate(BASE, json.loads(json.dumps(d))), 5)

    def test_termination_sentence_is_parsed_without_ai(self):
        html = BASE.replace('<h2>Terminated Employees</h2><ul><li>mallory</li><li>trent</li></ul>',
                            '<p>Mallory was terminated last week.</p>')
        d = rx.extract(html)
        self.assertIn('mallory', d['terminated_users'])
        self.assertNotIn('terminated_users', d['unparsed_hints'])

    def test_cp_style_prose_readme(self):
        html = ('<h2>Policy</h2><p>OpenSSH is a critical service. Chromium is the default web browser and must remain.</p>'
                '<h2>Authorized Administrators and Users</h2><pre>Authorized Administrators:\nbenjamin (you)\n\tpassword: Abc123!xyz\n'
                'dscott\n\tpassword: Pw9#kkkkkkk\nAuthorized Users:\ncmarcus\n</pre>'
                '<p>A new employee, Eliza Darby (edarby), has been hired as an administrator. Please create an account for her.</p>'
                '<p>dscott is no longer an administrator but should still have an account.</p>')
        d = rx.extract(html)
        types = {u['name']: u['account_type'] for u in d['all_users']}
        self.assertEqual(types, {'benjamin': 'admin', 'dscott': 'standard', 'cmarcus': 'standard'})
        self.assertNotIn('password', types)
        self.assertEqual([h['name'] for h in d['recent_hires']], ['edarby'])
        self.assertEqual(d['recent_hires'][0]['account_type'], 'admin')
        self.assertEqual(set(d['critical_services']), {'ssh', 'chromium'})
        self.assertEqual(d['passwords']['benjamin'], 'Abc123!xyz')

    def test_no_sections_means_ai_fallback(self):
        d = rx.extract('<html><body><p>Nothing structured here.</p></body></html>')
        self.assertEqual(d['all_users'], [])


if __name__ == '__main__':
    unittest.main()
