import importlib.util
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from mint_update_config import configure
from readme_extract import extract
from validate_readme import validate
from chromium_policy import configure as configure_chromium


class RoundOneTests(unittest.TestCase):
    def test_chromium_policy_requires_readme_and_is_idempotent(self):
        import json
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.assertFalse(configure_chromium(root, 'Chromium is required.'))
            self.assertTrue(configure_chromium(root, 'Configure Chromium to block sites from sending pop-ups and using redirects.'))
            configure_chromium(root, 'Chromium must block pop-ups.')
            policy = root / 'etc/chromium/policies/managed/99-cp-popups.json'
            self.assertEqual(json.loads(policy.read_text())['DefaultPopupsSetting'], 2)

    @unittest.skipUnless(os.name == 'posix', 'Bash execution')
    def test_full_upgrade_failure_is_not_reported_as_success(self):
        import subprocess
        result = subprocess.run(['bash', '-c', '''
source modules/os_updates.sh
log_section() { :; }; log_info() { :; }; log_success() { :; }; log_error() { :; }
apt-get() { return 42; }
perform_full_upgrade
'''], cwd=ROOT, capture_output=True)
        self.assertNotEqual(result.returncode, 0)

    def test_pasted_readme_passwords_and_guidelines(self):
        text = ('Make a new administrator account for “tchalla”.\n'
                'Critical Services:\nsshd\nAuthorized Administrators and Users\n'
                'Authorized Administrators:\npparker (you)\n password: example\n'
                'Authorized Users:\nokoye\nCompetition Guidelines\n'
                'Do not stop the CCS Client service.\n')
        data = extract(text)
        with patch.dict(os.environ, CP_NO_AI='0', AUTO_REMEDIATE='1'):
            self.assertEqual(validate(text, data), 2)
        self.assertEqual(data['recent_hires'][0]['name'], 'tchalla')

    def test_mint_sources_preferences_backup_and_idempotence(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'etc').mkdir()
            (root / 'etc/os-release').write_text('ID=linuxmint\nVERSION_ID="21"\nVERSION_CODENAME=vanessa\n')
            schema = root / 'usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml'
            schema.parent.mkdir(parents=True)
            keys = ('refresh-schedule-enabled refresh-days refresh-hours refresh-minutes '
                    'autorefresh-days autorefresh-hours autorefresh-minutes '
                    'auto-update-flatpaks auto-update-cinnamon-spices').split()
            schema.write_text('<schemalist><schema>' + ''.join(f'<key name="{k}"/>' for k in keys) + '</schema></schemalist>')
            sources = root / 'etc/apt/sources.list.d/official-package-repositories.list'
            sources.parent.mkdir(parents=True)
            sources.write_text('broken base-only sources\n')
            configure(root, True)
            self.assertIn('jammy-security', sources.read_text())
            self.assertIn('vanessa', sources.read_text())
            self.assertIn('Ubuntu:jammy-security', (root / 'etc/apt/apt.conf.d/99-cp-origins').read_text())
            prefs = root / 'etc/dconf/db/local.d/01-mintupdate'
            self.assertIn('refresh-schedule-enabled=true', prefs.read_text())
            self.assertNotIn('\nauto-update=', prefs.read_text())
            configure(root, True)
            self.assertEqual(sources.with_name(sources.name + '.before-round1-fix').read_text(), 'broken base-only sources\n')
            if os.name == 'posix':
                self.assertEqual((root / 'etc/dconf/profile').stat().st_mode & 0o777, 0o755)
                self.assertEqual(prefs.stat().st_mode & 0o777, 0o644)


if __name__ == '__main__':
    unittest.main()
