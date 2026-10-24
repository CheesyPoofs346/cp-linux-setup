import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / 'lib'))
from postflight import verify
from privilege_audit import acl_findings, capability_findings, collect, server_config_findings
from ssh_policy import render, install
from mint_update_config import configure as configure_mint


class MintCompatibilityTests(unittest.TestCase):
    def prepare(self, root, version='22', base='noble'):
        (root / 'etc').mkdir()
        (root / 'etc/os-release').write_text(f'ID=linuxmint\nVERSION_ID={version}\nVERSION_CODENAME=wilma\nUBUNTU_CODENAME={base}\n')
        schema = root / 'usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml'
        schema.parent.mkdir(parents=True)
        keys = 'refresh-schedule-enabled refresh-days refresh-hours refresh-minutes autorefresh-days autorefresh-hours autorefresh-minutes auto-update-flatpaks auto-update-cinnamon-spices'.split()
        schema.write_text('<schemalist><schema>' + ''.join(f'<key name="{key}"/>' for key in keys) + '</schema></schemalist>')

    def test_mint22_uses_its_own_base_without_replacing_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare(root)
            configure_mint(root)
            origins = (root / 'etc/apt/apt.conf.d/99-cp-origins').read_text()
            self.assertIn('Ubuntu:noble-security', origins)
            self.assertNotIn('jammy', origins)
            self.assertFalse((root / 'etc/apt/sources.list.d').exists())
            with self.assertRaises(ValueError):
                configure_mint(root, restore_sources=True)

    def test_missing_schema_does_not_mutate_sources(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare(root, version='21', base='jammy')
            (root / 'etc/os-release').write_text('ID=linuxmint\nVERSION_ID=21\nVERSION_CODENAME=vanessa\n')
            (root / 'usr/share/glib-2.0/schemas/com.linuxmint.updates.gschema.xml').unlink()
            with self.assertRaises(ValueError):
                configure_mint(root, restore_sources=True)
            self.assertFalse((root / 'etc/apt').exists())

    def test_postflight_reports_disabled_native_refresh(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            self.prepare(root)
            configure_mint(root)
            (root / 'etc/dconf/db/local').write_bytes(b'compiled fixture')
            def command(args):
                if args[0] == 'gsettings':
                    values = {'refresh-schedule-enabled': 'false', 'refresh-minutes': '10',
                              'autorefresh-hours': '2', 'auto-update-flatpaks': 'true',
                              'auto-update-cinnamon-spices': 'true'}
                    return 0, values[args[-1]], ''
                return 0, '', ''
            report = verify({'critical_services': []}, command=command, root=root)
            self.assertEqual(report['status'], 'FAIL')
            self.assertTrue(any(c['check'] == 'mint-preference:refresh-schedule-enabled' and c['status'] == 'FAIL' for c in report['checks']))


@unittest.skipUnless(os.name == 'posix', 'Linux shell fixtures')
class ModuleResultTests(unittest.TestCase):
    def test_user_auditing_continues_but_preserves_failed_step(self):
        script = '''source "$1"
README_PARSED=1
for name in disable_guest_account fix_root_uid_users remove_unauthorized_users remove_hidden_users handle_system_users manage_admin_privileges create_groups create_missing_users add_users_to_groups fix_null_passwords fix_insecure_passwords rotate_authorized_passwords enforce_password_policies check_password_hashing disable_system_user_logins ensure_system_accounts_nologin ensure_matching_uid_gid verify_user_account_shells; do
    eval "$name() { return 0; }"
done
fix_insecure_passwords() { return 19; }
verify_user_account_shells() { echo FINAL_STEP_REACHED; }
run_user_auditing
'''
        result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'modules/user_auditing.sh')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1, result.stdout + result.stderr)
        self.assertIn('FINAL_STEP_REACHED', result.stdout)

    def test_failed_ssh_reload_cannot_report_success(self):
        script = '''source "$1"
systemctl() { if [[ "$1" == list-unit-files ]]; then echo ssh.service; else return 1; fi; }
command_exists() { return 0; }
ssh_service_reload
'''
        result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'modules/ssh_hardening.sh')], capture_output=True, text=True)
        self.assertEqual(result.returncode, 1)
        self.assertNotIn('service reloaded', result.stdout)

    def test_socket_library_is_not_a_reverse_shell_indicator(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'socket.py').write_text('import socket\ns = socket.socket()\n')
            (root / 'reverse.py').write_text('import socket, os, pty\ns = socket.socket()\nos.dup2(s.fileno(), 0)\npty.spawn("/bin/sh")\n')
            script = '''source "$1"
README_CRITICAL_SERVICES=(ssh)
find() { printf '%s\\0' "$FIXTURE/socket.py" "$FIXTURE/reverse.py"; }
record_finding() { echo "FINDING: $2"; }
scan_service_specific_artifacts
'''
            result = subprocess.run(['bash', '-c', script, 'fixture', str(ROOT / 'modules/malware.sh')],
                env=dict(os.environ, FIXTURE=folder), capture_output=True, text=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn('reverse.py', result.stdout)
            self.assertNotIn('socket.py', result.stdout)


class SSHPolicyTests(unittest.TestCase):
    def test_match_blocks_are_preserved_and_global_prefix_is_idempotent(self):
        original = 'Include /etc/ssh/sshd_config.d/*.conf\nPort 2222\nMatch User backup\n    ForceCommand internal-sftp\n    X11Forwarding yes\n'
        new = render(original, port=2222)
        self.assertTrue(new.endswith(original))
        self.assertLess(new.index('PasswordAuthentication yes'), new.index('Include '))
        self.assertIn('AuthenticationMethods any\n', new)
        self.assertEqual(render(new, port=2222), new)

    def test_only_explicit_key_only_disables_passwords(self):
        self.assertIn('PasswordAuthentication yes\n', render(''))
        self.assertIn('PasswordAuthentication no\n', render('', key_only=True))

    def test_invalid_options_do_not_enter_config(self):
        for options in ({'port': 0}, {'allow_users': 'alice\nPermitRootLogin yes'}, {'banner': '/tmp/x\nX11Forwarding yes'}):
            with self.assertRaises(ValueError):
                render('', **options)

    def test_failed_syntax_restores_main_and_legacy_snippet(self):
        with tempfile.TemporaryDirectory() as folder:
            main, snippet = Path(folder) / 'sshd_config', Path(folder) / '99-cyberpatriot.conf'
            main.write_text('Port 22\n')
            snippet.write_text('AuthenticationMethods publickey\n')
            main.chmod(0o640)
            def reject():
                return subprocess.CompletedProcess([], 1, '', 'bad option')
            with self.assertRaisesRegex(ValueError, 'sshd rejected'):
                install(main, snippet, reject)
            self.assertEqual(main.read_text(), 'Port 22\n')
            self.assertEqual(snippet.read_text(), 'AuthenticationMethods publickey\n')
            if os.name == 'posix':
                self.assertEqual(main.stat().st_mode & 0o777, 0o640)

    def test_success_retires_only_owned_snippet(self):
        with tempfile.TemporaryDirectory() as folder:
            main, snippet = Path(folder) / 'sshd_config', Path(folder) / '99-cyberpatriot.conf'
            main.write_text('Match User backup\n ForceCommand internal-sftp\n')
            snippet.write_text('PasswordAuthentication no\n')
            install(main, snippet, lambda: subprocess.CompletedProcess([], 0, '', ''))
            self.assertIn('PasswordAuthentication yes', main.read_text())
            self.assertNotIn('PasswordAuthentication no', snippet.read_text())


class PrivilegeTests(unittest.TestCase):
    def test_nfs_root_and_wildcard_write_are_reviewed_not_rewritten(self):
        text = '# /example *(rw,no_root_squash)\n/srv/reports 10.0.0.0/24(ro,root_squash)\n/srv/public *(rw,no_root_squash,sync)\n'
        findings = server_config_findings('/etc/exports', text)
        self.assertEqual({f['rule'] for f in findings}, {'nfs-root-identity', 'nfs-world-write'})
        self.assertTrue(all(f['line'] == 3 for f in findings))

    def test_snmp_credentials_are_not_copied_into_findings(self):
        findings = server_config_findings('/etc/snmp/snmpd.conf',
            'rocommunity public default\nrwcommunity very-secret-value 10.0.0.2\ncom2sec local default private\n')
        self.assertEqual(len(findings), 3)
        self.assertNotIn('very-secret-value', json.dumps(findings))
        self.assertEqual(server_config_findings('/etc/snmp/snmpd.conf', '# rwcommunity public\nrouser monitor priv\n'), [])

    def test_capabilities_separate_privilege_bypass_from_ping(self):
        found = capability_findings('/usr/bin/python3.10 cap_setuid,cap_setgid=ep\n/usr/bin/ping cap_net_raw=ep\n')
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]['capabilities'], ['cap_setgid', 'cap_setuid'])

    def test_acl_masks_are_respected(self):
        self.assertEqual(acl_findings('/etc/sudoers', 'user:alice:rwx\nmask::r--\n'), [])
        self.assertEqual(len(acl_findings('/etc/sudoers', 'user:alice:rwx\nmask::rw-\n')), 1)
        self.assertEqual(len(acl_findings('/etc/shadow', 'user:alice:r--\nmask::r--\n')), 1)
        self.assertEqual(acl_findings('/etc/shadow', 'user:root:rw-\nmask::rw-\n'), [])

    def test_disguised_elf_symlinks_and_budget(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            desktop = root / 'home/alice/Desktop'
            desktop.mkdir(parents=True)
            payload = desktop / 'report.pdf'
            payload.write_bytes(b'\x7fELFpayload')
            (desktop / 'real.pdf').write_bytes(b'%PDF-1.7')
            if os.name == 'posix':
                (desktop / 'link.pdf').symlink_to(payload)
            report = collect(root, command=lambda _: '', budget=5)
            self.assertEqual([f['path'] for f in report['findings']], ['/home/alice/Desktop/report.pdf'])
            self.assertEqual(payload.read_bytes(), b'\x7fELFpayload')
            self.assertTrue(collect(root, command=lambda _: '', max_entries=0)['truncated'])

    def test_missing_optional_tools_report_gaps(self):
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'usr/bin').mkdir(parents=True)
            (root / 'etc').mkdir()
            def missing(_):
                raise FileNotFoundError('not installed')
            report = collect(root, command=missing)
            self.assertEqual(len(report['errors']), 2)
            self.assertEqual(report['findings'], [])


class PostflightTests(unittest.TestCase):
    def command(self, args):
        if args[:2] == ['systemctl', 'is-active'] or args[:2] == ['systemctl', 'is-enabled']:
            return (0 if args[-1] == 'ssh' else 1), '', ''
        if args[0] == '/usr/sbin/sshd':
            return 0, 'permitrootlogin no\npermitemptypasswords no\npasswordauthentication yes\nauthenticationmethods any\n', ''
        if args[0] == 'ufw':
            return 0, 'Status: active\n', ''
        if args[:2] == ['getent', 'passwd']:
            return 0, args[-1] + ':x:1000:1000::/home/' + args[-1] + ':/bin/bash\n', ''
        if args[:2] == ['passwd', '-S']:
            return 0, args[-1] + ' P 2026-01-01 0 90 7 -1\n', ''
        return 0, '', ''

    def test_required_ssh_machine_baseline(self):
        data = {'critical_services': ['sshd'], 'all_users': [{'name': 'alice'}]}
        report = verify(data, 'All authorized users must log in using SSH. Use UFW.', self.command)
        self.assertEqual(report['status'], 'PASS', report)

    def test_disabled_required_service_cannot_pass(self):
        report = verify({'critical_services': ['nginx']}, command=self.command)
        self.assertEqual(report['status'], 'FAIL')

    def test_unknown_custom_service_is_review_not_silently_passed(self):
        self.assertEqual(verify({'critical_services': ['reactor-service']}, command=self.command)['status'], 'REVIEW')

    def test_pending_packages_and_reboot_are_visible(self):
        def pending(args):
            if args[0] == 'apt-get':
                return 0, 'Inst linux-generic [old] (new)\n', ''
            return self.command(args)
        with tempfile.TemporaryDirectory() as folder:
            root = Path(folder)
            (root / 'var/run').mkdir(parents=True)
            (root / 'var/run/reboot-required').touch()
            report = verify({'critical_services': []}, command=pending, root=root)
            self.assertEqual(report['status'], 'REVIEW')
            self.assertEqual({c['check'] for c in report['checks'] if c['status'] == 'REVIEW'}, {'reboot', 'pending-updates'})

    def test_match_root_login_and_key_only_requirement_are_detected(self):
        def unsafe(args):
            if args[0] == '/usr/sbin/sshd' and '-T' in args:
                return 0, 'permitrootlogin yes\npermitemptypasswords no\npasswordauthentication no\nauthenticationmethods publickey\n', ''
            return self.command(args)
        data = {'critical_services': ['ssh'], 'all_users': [{'name': 'alice'}]}
        report = verify(data, 'All authorized users must log in using SSH.', unsafe)
        self.assertEqual(report['status'], 'FAIL')
        self.assertTrue(any(c['check'] == 'ssh-access:alice' and c['status'] == 'REVIEW' for c in report['checks']))

    def test_broken_package_state_and_failed_probe_are_failures(self):
        report = verify({'critical_services': []}, command=lambda _: (1, '', 'failed'))
        self.assertEqual(report['status'], 'FAIL')

    def test_locked_required_account_does_not_pass(self):
        def locked(args):
            if args[:2] == ['passwd', '-S']:
                return 0, 'alice L 2026-01-01 0 90 7 -1\n', ''
            return self.command(args)
        report = verify({'critical_services': ['ssh'], 'all_users': [{'name': 'alice'}]}, command=locked)
        self.assertEqual(report['status'], 'FAIL')

    def test_postgres_umbrella_unit_does_not_hide_offline_cluster(self):
        def offline(args):
            if args[0] == 'systemctl':
                return 0, '', ''
            if args[0] == 'pg_lsclusters':
                return 0, '14 main 5432 down postgres /var/lib/postgresql/14/main /var/log/postgresql/log\n', ''
            return self.command(args)
        report = verify({'critical_services': ['postgresql']}, command=offline)
        self.assertEqual(report['status'], 'FAIL')


if __name__ == '__main__':
    unittest.main()
