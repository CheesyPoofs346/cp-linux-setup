import importlib.util
from pathlib import Path
import os
import tempfile
import unittest

def load():
    path=Path(__file__).resolve().parents[1]/'lib/privilege_policy.py'
    spec=importlib.util.spec_from_file_location('privilege_policy',path)
    mod=importlib.util.module_from_spec(spec);spec.loader.exec_module(mod);return mod

@unittest.skipUnless(os.name=='posix','POSIX permissions')
class PrivilegePolicyTests(unittest.TestCase):
    def test_only_explicit_policy_and_matching_binary_copies(self):
        m=load()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory)
            (root/'usr/bin').mkdir(parents=True);(root/'usr/local/bin').mkdir(parents=True)
            reference=root/'usr/bin/find';reference.write_bytes(b'known-reference')
            clone=root/'usr/local/bin/renamed';clone.write_bytes(reference.read_bytes());clone.chmod(0o4755)
            custom=root/'usr/local/bin/business-helper';custom.write_bytes(b'custom');custom.chmod(0o4755)
            self.assertEqual(m.apply_policy(root,False),[])
            self.assertTrue(clone.stat().st_mode & 0o4000)
            result=m.apply_policy(root,True)
            self.assertEqual(len(result),1)
            self.assertFalse(clone.stat().st_mode & 0o4000)
            self.assertTrue(custom.stat().st_mode & 0o4000)
            self.assertEqual(m.apply_policy(root,True),[])

    def test_symlink_outside_local_tree_is_not_followed(self):
        m=load()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'usr/bin').mkdir(parents=True);(root/'usr/local/bin').mkdir(parents=True)
            binary=root/'usr/bin/find';binary.write_bytes(b'reference');binary.chmod(0o4755)
            (root/'usr/local/bin/link').symlink_to(binary)
            self.assertEqual(m.apply_policy(root,True),[])
            self.assertTrue(binary.stat().st_mode & 0o4000)

    def test_hardlink_to_package_binary_is_preserved(self):
        m=load()
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'usr/bin').mkdir(parents=True);(root/'usr/local/bin').mkdir(parents=True)
            binary=root/'usr/bin/find';binary.write_bytes(b'reference');binary.chmod(0o4755)
            os.link(binary,root/'usr/local/bin/hardlink')
            self.assertEqual(m.apply_policy(root,True),[])
            self.assertTrue(binary.stat().st_mode & 0o4000)
