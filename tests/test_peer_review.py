import importlib.util
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

LIB = Path(__file__).resolve().parents[1] / 'lib'
sys.path.insert(0, str(LIB))
import peer_review


class PeerReviewTests(unittest.TestCase):
    def test_different_model_and_bound_input_approval(self):
        def call(messages, model):
            self.assertEqual(model, 'reviewer')
            value = json.loads(messages[1]['content'])
            self.assertEqual(value['material']['readme'], 'full original source')
            return {'approved': True, 'input_sha256': value['input_sha256'], 'reason': 'Checked source'}
        result = peer_review.review({'readme': 'full original source'}, call, 'worker', 'reviewer')
        self.assertTrue(result['approved'])

    def test_same_model_refused(self):
        with self.assertRaises(ValueError): peer_review.review({}, lambda *args: {}, 'same', 'same')

    def test_unbound_approval_refused(self):
        with self.assertRaises(ValueError): peer_review.review({}, lambda *args: {'approved': True, 'input_sha256': 'fake', 'reason': 'okay'}, 'worker', 'reviewer')

    def test_every_section_requires_source_quote(self):
        material = {'sections': [{'id': 's0', 'heading': 'Policy', 'text': 'Preserve SSH'}], 'modules': {'local_policy': 'source'}}
        good = {'sections': [{'id': 's0', 'quote': 'Preserve SSH', 'disposition': 'manual', 'reason': 'SSH remains unchanged'}], 'approved_modules': ['local_policy']}
        self.assertEqual(peer_review.validate_coverage(material, good), ['local_policy'])
        good['sections'][0]['quote'] = 'invented'
        with self.assertRaises(ValueError): peer_review.validate_coverage(material, good)
        good['sections'] = []
        with self.assertRaises(ValueError): peer_review.validate_coverage(material, good)

    def test_unknown_module_refused(self):
        with self.assertRaises(ValueError): peer_review.validate_coverage({'sections': [], 'modules': {}}, {'sections': [], 'approved_modules': ['arbitrary_shell']})

    def test_source_change_after_review_refused(self):
        from unittest.mock import patch
        with tempfile.TemporaryDirectory() as folder:
            engine = Path(folder)
            (engine / 'data').mkdir()
            code = engine / 'module.sh'
            code.write_text('original')
            (engine / 'data/review-source-hashes.json').write_text(json.dumps({'module.sh': hashlib.sha256(code.read_bytes()).hexdigest()}))
            with patch.object(peer_review, '__file__', str(engine / 'lib/peer_review.py')), patch.object(sys, 'argv', ['review', '--check-sources']):
                self.assertEqual(peer_review.main(), 0)
                code.write_text('changed')
                with self.assertRaises(ValueError): peer_review.main()

    @unittest.skipUnless(os.name == 'posix', 'Linux guard')
    def test_guard_refuses_current_mount_namespace(self):
        env = dict(os.environ)
        env.pop('CP_PARENT_MNT_NS', None)
        result = subprocess.run(['bash', str(LIB / 'protect_account.sh'), '--inside', 'local_policy'], env=env, capture_output=True)
        self.assertNotEqual(result.returncode, 0)
        self.assertIn(b'Private mount namespace required', result.stderr)

    @unittest.skipUnless(os.name == 'posix', 'Linux pwd/grp')
    def test_changed_main_identity_stops_guard(self):
        from unittest.mock import patch
        import account_guard
        with tempfile.TemporaryDirectory() as folder:
            path = Path(folder) / 'guard.json'
            path.write_text(json.dumps({'user': 'operator', 'uid': 1000}))
            with patch.object(sys, 'argv', ['guard', 'check', str(path)]), patch.object(account_guard, 'snapshot', return_value={'user': 'operator', 'uid': 1001}):
                with self.assertRaises(ValueError): account_guard.main()


if __name__ == '__main__': unittest.main()
