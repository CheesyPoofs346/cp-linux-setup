import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
import forensics_agent
import sentinel
import score_tracker


class OfflineSafetyTests(unittest.TestCase):
    def test_grub_policy_preserves_passwords_and_does_not_force_unsigned_boot(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);(root/'etc/default').mkdir(parents=True);(root/'etc/grub.d').mkdir()
            default=root/'etc/default/grub';custom=root/'etc/grub.d/40_custom'
            default.write_text('GRUB_TIMEOUT=0\n')
            custom.write_text('#!/bin/sh\nexec tail -n +3 $0\nset superusers="admin"\npassword_pbkdf2 admin existing-policy\n')
            before=(default.read_text(),custom.read_text())
            script='''source "$1"
backup_file() { :; }
update-grub() { :; }
body=$(declare -f enforce_grub_signature_checks)
body=${body//\\/etc\\//$TEST_ROOT/etc/}
eval "$body"
enforce_grub_signature_checks
'''
            result=subprocess.run(['bash','-c',script,'test',str(ROOT/'modules/os_settings.sh')],env={**os.environ,'TEST_ROOT':str(root)},capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            self.assertEqual((default.read_text(),custom.read_text()),before)

    def test_unknown_locked_service_identity_is_preserved(self):
        script='''source "$1"
getent() { printf '%s\\n' 'businessapi:x:992:992::/nonexistent:/usr/sbin/nologin'; }
is_system_account businessapi
'''
        result=subprocess.run(['bash','-c',script,'test',str(ROOT/'modules/user_auditing.sh')],capture_output=True)
        self.assertEqual(result.returncode,0,result.stderr)

    def test_sentinel_package_pause_keeps_update_timers_running(self):
        calls=[]
        with patch.object(sentinel,'_APT_QUIET',[]), patch.object(sentinel.os,'geteuid',return_value=0), patch.object(sentinel,'run',side_effect=lambda args,**kw:calls.append(args)):
            sentinel.quiesce_apt()
        self.assertFalse(any(arg.endswith('.timer') for call in calls for arg in call))

    def test_gdm_configuration_does_not_create_a_stray_file(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'etc/gdm3').mkdir(parents=True)
            config = root / 'etc/gdm3/custom.conf'
            config.write_text('[daemon]\n')
            script = '''source "$1"
detect_display_manager() { echo gdm3; }
backup_file() { :; }
dconf() { :; }
body=$(declare -f disable_user_enumeration)
body=${body//\\/etc\\//$TEST_ROOT/etc/}
eval "$body"
disable_user_enumeration
'''
            result = subprocess.run(['bash', '-c', script, 'test', str(ROOT / 'modules/account_policy.sh')],
                                    cwd=directory, env=dict(os.environ, TEST_ROOT=directory), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('disable-user-list=true', config.read_text())
            self.assertEqual(sorted(p.name for p in root.iterdir()), ['etc'])

    def test_failed_penalty_recovery_is_not_reported_as_restored(self):
        with tempfile.TemporaryDirectory() as directory:
            report = Path(directory) / 'score.html'
            report.write_text('<p>OpenSSH service stopped: -5 pts</p>')
            for installed in (True, False):
                with self.subTest(installed=installed):
                    ctx = SimpleNamespace(root=Path('/'), failed_actions=0)
                    def command(args, **kwargs):
                        return subprocess.CompletedProcess(args, 1, 'install ok installed' if args[0] == 'dpkg' and installed else '')
                    with patch.object(os, 'geteuid', return_value=0), \
                            patch.object(score_tracker, 'find_scoring_report', return_value=report), \
                            patch.object(sentinel, 'quiesce_apt'), \
                            patch.object(sentinel, 'run', side_effect=command), \
                            patch.object(sentinel, 'record_fix') as record:
                        self.assertEqual(sentinel.restore_penalties(ctx, log=lambda _: None), 0)
                        record.assert_not_called()
                        self.assertEqual(ctx.failed_actions, 1)

    def test_failed_service_stop_is_not_reported_as_success(self):
        with patch.object(sentinel, 'run', return_value=subprocess.CompletedProcess([], 1)):
            ok, _ = sentinel.apply(None, sentinel.Finding('service', 'test', ('disable-unit', 'example')))
        self.assertFalse(ok)

    def test_required_services_and_nfs_dependencies_are_not_stopped(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / 'commands'
            script = '''source "$1"
get_critical_services() { printf 'cups\nnfs-server\navahi\nsnmp\n'; }
service_exists() { return 0; }
systemctl() { printf '%s\n' "$*" >> "$MUTATION_LOG"; return 0; }
stop_disable_service cups
stop_disable_service rpcbind
stop_disable_service avahi-daemon
stop_disable_service snmpd.service
'''
            result = subprocess.run(['bash', '-c', script, 'test', str(ROOT / 'modules/service_auditing.sh')],
                                    env=dict(os.environ, MUTATION_LOG=str(log), BACKUP_DIR=directory), capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertFalse(log.exists(), log.read_text() if log.exists() else '')

    def test_updates_do_not_mount_package_configuration_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'lib').mkdir()
            (root / 'data').mkdir()
            guard = root / 'lib/protect_account.sh'
            guard.write_text((ROOT / 'lib/protect_account.sh').read_text())
            bins = root / 'bin'
            bins.mkdir()
            commands = {
                'readlink': 'case "$1" in /proc/self/*) echo child;; *) echo parent;; esac',
                'python3': 'if [ "$1" = -c ]; then echo /; fi',
                'mount': 'echo "$*" >> "$MOUNT_LOG"',
                'bash': 'exit 0',
            }
            for name, body in commands.items():
                p = bins / name
                p.write_text('#!/bin/sh\n' + body + '\n')
                p.chmod(0o755)
            log = root / 'mount.log'
            result = subprocess.run(['/bin/bash', str(guard), '--inside', 'os_updates'],
                                    env=dict(os.environ, CP_PARENT_MNT_NS='parent', AUTO_REMEDIATE='1', MOUNT_LOG=str(log), PATH=str(bins) + ':' + os.environ['PATH']),
                                    capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertNotIn('/etc/security', log.read_text())
            self.assertNotIn('/etc/pam.d', log.read_text())

    def test_shell_api_preflight_blocks_saved_credentials(self):
        result = subprocess.run(['bash', '-c', 'source "$1"; if check_openrouter_config; then exit 99; fi', 'test', str(ROOT / 'lib/openrouter.sh')],
                                env=dict(os.environ, CP_NO_AI='1', OPENROUTER_API_KEY='fake'), capture_output=True)
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_score_observation_never_runs_unscoped_hardening(self):
        with patch.object(score_tracker, 'find_scoring_report', return_value=None), \
                patch.object(score_tracker, 'apply_targeted_hardening') as harden, \
                patch.object(score_tracker, 'restore_scoring_service') as restore, \
                patch.object(score_tracker, 'repair_protected_aging'), \
                patch('atexit.register'), patch.object(sys, 'argv', ['score_tracker.py', '--once']):
            score_tracker.main()
            harden.assert_not_called()
            restore.assert_not_called()

    def test_python_ai_is_blocked_even_with_credentials(self):
        with patch.dict(os.environ, {'CP_NO_AI': '1', 'OPENROUTER_API_KEY': 'fake', 'OPENROUTER_MODEL': 'fake'}):
            with patch.object(forensics_agent, '_post_with_retry', return_value='{\"choices\":[{\"message\":{\"content\":\"{}\"}}]}') as post:
                with self.assertRaisesRegex(ValueError, 'CP_NO_AI'):
                    forensics_agent.call_ai([])
                post.assert_not_called()

    def test_positive_ssh_score_is_not_a_penalty(self):
        self.assertEqual(sentinel.penalty_actions('<p>Disabled SSH root login - 4 pts</p>'), [])
        self.assertEqual(sentinel.penalty_actions('<p>Disabled SSH root login -4 pts</p>'), [])

    def test_real_service_penalty_is_restored(self):
        self.assertEqual(sentinel.penalty_actions('<p>OpenSSH service stopped: -5 pts</p>')[0][:2], ('openssh-server', 'ssh'))

    @unittest.skipUnless(hasattr(os, 'geteuid') and os.geteuid() == 0, 'launcher requires root; run this test as root')
    def test_launcher_reaches_engine_without_setup_or_early_mutation(self):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'start.sh').write_text((ROOT / 'start.sh').read_text())
            (root / 'readme.html').write_text('Authorized Administrators: bob')
            (root / 'cp-engine.sh').write_text('printf "ENGINE:no_ai=%s\\n" "$CP_NO_AI"\n')
            # Fake privileged programs: any preflight mutation is a test failure.
            bins = root / 'bin'
            bins.mkdir()
            for name in ('apt-get', 'dpkg', 'killall', 'pkill', 'passwd', 'chage', 'chpasswd', 'systemctl', 'ufw', 'find', 'rm', 'chmod', 'chown', 'sed', 'mkdir', 'dconf'):
                p = bins / name
                p.write_text('#!/bin/sh\necho "EARLY_MUTATION"\nexit 99\n')
                p.chmod(0o755)
            env = dict(os.environ, PATH=str(bins) + ':' + os.environ['PATH'])
            env.pop('CP_NO_AI', None)
            env.pop('NVIDIA_API_KEY', None)
            result = subprocess.run(['bash', str(root / 'start.sh'), '--readme', str(root / 'readme.html')], env=env, text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
            self.assertNotIn('EARLY_MUTATION', result.stdout)
            self.assertIn('ENGINE:no_ai=1', result.stdout)
