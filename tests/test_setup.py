import os
from pathlib import Path
import select
import shutil
import stat
import subprocess
import tempfile
import time
import unittest


@unittest.skipUnless(os.name == 'posix' and os.geteuid() != 0, 'Interactive non-root Linux setup')
class SetupTests(unittest.TestCase):
    def test_hidden_key_private_config_and_no_shell_injection(self):
        import pty
        root = Path(__file__).resolve().parents[1]
        with tempfile.TemporaryDirectory() as folder:
            destination = Path(folder)
            for name in ('setup.sh', 'start.sh', 'config.conf'):
                shutil.copyfile(root / name, destination / name)
            readme = destination / 'README practice.html'
            readme.write_text('<h1>Practice</h1>')
            key = 'dummy-$(touch ' + str(destination / 'injected') + ')'
            # Setup's prerequisite prompt is unrelated to this PTY/config test.
            # Stub absent tools so the test never reaches sudo/package installation.
            tools = destination / 'bin'
            tools.mkdir()
            for tool in ('curl', 'jq', 'python3', 'perl', 'flock', 'timeout', 'unshare', 'mount', 'setpriv'):
                if shutil.which(tool) is None:
                    stub = tools / tool
                    stub.write_text('#!/bin/sh\nexit 0\n')
                    stub.chmod(0o755)
            master, slave = pty.openpty()
            process = subprocess.Popen(['bash', str(destination / 'setup.sh')], stdin=slave, stdout=slave, stderr=slave,
                                       env=dict(os.environ, PATH=str(tools) + os.pathsep + os.environ['PATH']))
            os.close(slave)
            output = b''
            handled = set()
            deadline = time.monotonic() + 15
            prompts = [(b'input hidden', key), (b'Image README HTTPS', str(readme)), (b'Question directory', ''), (b'experimental run', 'y')]
            try:
                while time.monotonic() < deadline:
                    if select.select([master], [], [], 0.1)[0]:
                        try:
                            chunk = os.read(master, 65536)
                        except OSError:
                            break
                        if not chunk:
                            break
                        output += chunk
                        for marker, answer in prompts:
                            if marker in output and marker not in handled:
                                os.write(master, (answer + '\n').encode())
                                handled.add(marker)
                    if process.poll() is not None:
                        break
                process.wait(timeout=2)
                self.assertEqual(process.returncode, 0, output.decode(errors='replace'))
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait()
                os.close(master)
            self.assertNotIn(key.encode(), output)
            self.assertFalse((destination / 'injected').exists())
            for name in ('config.local.conf', 'run.local.conf'):
                self.assertEqual(stat.S_IMODE((destination / name).stat().st_mode), 0o600)
            # Load exactly as the runner does: literal shell characters stay data.
            result = subprocess.run(['bash', '-c', 'source "$1"; printf "%s" "$NVIDIA_API_KEY"', 'test', str(destination / 'config.local.conf')], capture_output=True, check=True)
            self.assertEqual(result.stdout.decode(), key)
            self.assertFalse((destination / 'injected').exists())
            result = subprocess.run(['bash', str(destination / 'start.sh')], capture_output=True)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn(b'sudo bash start.sh', result.stderr)


if __name__ == '__main__': unittest.main()
