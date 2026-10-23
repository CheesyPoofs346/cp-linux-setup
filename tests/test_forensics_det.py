import importlib.util
import os
import tempfile
import unittest
from unittest.mock import patch
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

    def test_music_question_does_not_count_unrelated_documents(self):
        (self.root / 'home/ben/Music/song.mp3').write_bytes(b'x')
        for n in range(4):
            (self.root / f'home/ben/Documents/n{n}.pdf').write_bytes(b'x')
        result = det.solve(question('Which directory contains the music files?'), self.ev())
        self.assertEqual(result['answers'], ['/home/ben/Music'])

    def test_uid_zero_account_is_solved_from_passwd(self):
        with (self.root / 'etc/passwd').open('a') as out:
            out.write('intruder:x:0:0::/root:/bin/bash\n')
        result = det.solve(question('Which unauthorized user has UID 0?'), self.ev())
        self.assertIsNotNone(result)
        self.assertEqual(result['answers'], ['intruder'])
        self.assertEqual(result['confidence'], 'high')

    def test_multiple_uid_zero_candidates_are_not_guessed(self):
        with (self.root / 'etc/passwd').open('a') as out:
            out.write('one:x:0:0::/root:/bin/bash\ntwo:x:0:0::/root:/bin/bash\n')
        self.assertIsNone(det.solve(question('Which unauthorized user has UID 0?'), self.ev()))

    def test_base64_question_uses_named_file(self):
        (self.root / 'home/ben/Documents/target.txt').write_text('c2VjcmV0IG1lc3NhZ2U=')
        (self.root / 'home/ben/Documents/other.txt').write_text('d3JvbmcgbWVzc2FnZQ==')
        result = det.solve(question('Decode the base64 message in /home/ben/Documents/target.txt.'), self.ev())
        self.assertEqual(result['answers'], ['secret message'])
        self.assertEqual(result['confidence'], 'high')

    def test_ambiguous_answer_is_not_written_by_default(self):
        desktop = self.root / 'home/ben/Desktop'
        desktop.mkdir()
        target = desktop / 'Forensics_Question_1.txt'
        original = question('Which directory contains the music?')['content']
        target.write_text(original)
        with patch.object(det, 'solve', return_value={'answers': ['/guess'], 'confidence': 'medium', 'why': 'ambiguous'}):
            result = det.run([desktop], root=str(self.root))
        self.assertEqual(target.read_text(), original)
        self.assertEqual(result[0]['status'], 'unsolved')

    def test_persistent_backups_allow_a_reset_question_to_be_answered_again(self):
        desktop = self.root / 'home/ben/Desktop'
        desktop.mkdir()
        target = desktop / 'Forensics_Question_1.txt'
        original = question('What is the answer?')['content']
        backups = self.root / 'backups'
        with patch.object(det, 'solve', return_value={'answers': ['verified'], 'confidence': 'high', 'why': 'fixture'}):
            for _ in range(2):
                target.write_text(original)
                result = det.run([desktop], root=str(self.root), backup_dir=backups)
                self.assertEqual(result[0]['status'], 'applied')
        self.assertEqual(len(list(backups.rglob('*.original'))), 2)


if __name__ == '__main__':
    unittest.main()
