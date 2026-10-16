import os
from pathlib import Path
import shutil
import stat
import subprocess
import tempfile
import unittest


@unittest.skipUnless(os.name == 'posix', 'Linux script permissions')
class RepositoryPermissionTests(unittest.TestCase):
    def test_engine_help_does_not_chmod_sourced_modules(self):
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            engine = Path(folder)
            shutil.copyfile(root / 'cp-engine.sh', engine / 'cp-engine.sh')
            shutil.copyfile(root / 'config.conf', engine / 'config.conf')
            (engine / 'lib').mkdir()
            for source in (root / 'lib').glob('*.sh'):
                shutil.copyfile(source, engine / 'lib' / source.name)
            (engine / 'modules').mkdir()
            module = engine / 'modules' / 'fixture.sh'
            module.write_text('# sourced fixture\n')
            module.chmod(0o644)
            result = subprocess.run(['bash', str(engine / 'cp-engine.sh'), '--help'], capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr.decode())
            self.assertEqual(stat.S_IMODE(module.stat().st_mode), 0o644)


if __name__ == '__main__': unittest.main()
