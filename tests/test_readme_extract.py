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

    def test_unstructured_mentions_become_hints(self):
        html = BASE.replace('<h2>Terminated Employees</h2><ul><li>mallory</li><li>trent</li></ul>',
                            '<p>Mallory was terminated last week.</p>')
        self.assertIn('terminated_users', rx.extract(html)['unparsed_hints'])

    def test_no_sections_means_ai_fallback(self):
        d = rx.extract('<html><body><p>Nothing structured here.</p></body></html>')
        self.assertEqual(d['all_users'], [])


if __name__ == '__main__':
    unittest.main()
