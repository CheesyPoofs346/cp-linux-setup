import copy
import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location('guard', Path(__file__).resolve().parents[1] / 'lib/validate_readme.py')
guard = importlib.util.module_from_spec(spec)
spec.loader.exec_module(guard)

HTML = '<h2>Authorized Administrators (user:password):</h2><p>operator:secret (YOU)<br></p><h2>Authorized Users:</h2><p>member<br>member2<br></p><h2>Critical Services:</h2><p>SSH (openssh-server)<br></p>'
DATA = {'all_users': [{'name': name, 'account_type': role, 'groups': []} for name, role in [('operator','admin'),('member','standard'),('member2','standard')]], 'recent_hires': [], 'terminated_users': [], 'critical_services': ['ssh'], 'groups_to_create': [], 'system_users_to_restrict': []}


class ValidationTests(unittest.TestCase):
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

    def test_no_password_in_error(self):
        with self.assertRaises(ValueError) as error: guard.validate(HTML.replace('member2<br>', 'member2 invalid words<br>'), DATA)
        self.assertNotIn('secret', str(error.exception))


if __name__ == '__main__': unittest.main()
