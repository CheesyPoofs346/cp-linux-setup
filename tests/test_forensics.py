import hashlib
import contextlib
import io
import importlib.util
import json
import os
from pathlib import Path
import stat
import tempfile
import sys
import unittest
import zipfile
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('forensics', Path(__file__).resolve().parents[1] / 'lib/forensics_agent.py')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class ForensicsTests(unittest.TestCase):
    def setUp(self):
        agent._skip_all.clear()
        self.addCleanup(agent._skip_all.clear)
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name).resolve()
        self.desktop = self.root / 'Desktop'
        self.desktop.mkdir()
        self.runner = self.root / 'runner'
        self.runner.mkdir()
        (self.runner / 'data').mkdir()
        (self.runner / 'data' / 'auto-source.html').write_text('<h1>Practice README</h1><p>Preserve evidence.</p>')
        self.tools = agent.EvidenceTools(self.runner, [self.root])
        self.evidence = self.root / 'evidence.log'
        self.evidence.write_text('Evidence: culprit.exe\n', encoding='utf-8')
        self.question = self.desktop / 'Forensics Question 12'
        self.question.write_bytes(b'Identify the file.\r\nANSWER: \r\n')

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_members_are_decompressed_without_extraction(self):
        book = self.root / 'document.xlsm'
        with zipfile.ZipFile(book, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('docProps/core.xml', '<source>192.0.2.14</source>')
            archive.writestr('../outside.txt', 'never extract this')
        self.assertIn('docProps/core.xml', self.tools.run({'tool': 'zip_list', 'path': str(book)}))
        self.assertIn('192.0.2.14', self.tools.run({'tool': 'zip_read_text', 'path': str(book), 'member': 'docProps/core.xml'}))
        self.assertFalse((self.root.parent / 'outside.txt').exists())

    def test_vba_parser_uses_fixed_command_stdin_and_timeout(self):
        executable = self.runner / '.forensics-venv/bin/python'
        executable.parent.mkdir(parents=True)
        executable.touch()
        from subprocess import CompletedProcess
        with patch.object(agent.subprocess, 'run', return_value=CompletedProcess([], 0, b'Sub Test(): End Sub', b'')) as run:
            output = self.tools.run({'tool': 'vba_source', 'path': str(self.evidence)})
            self.assertIn('Sub Test', output)
            self.assertEqual(run.call_args.kwargs['input'], self.evidence.read_bytes())
            self.assertEqual(run.call_args.kwargs['timeout'], 20)
            self.assertNotIn(str(self.evidence), run.call_args.args[0])

    def test_archive_bomb_and_secret_rejected(self):
        book = self.root / 'document.zip'
        with zipfile.ZipFile(book, 'w', compression=zipfile.ZIP_DEFLATED) as archive:
            archive.writestr('bomb', 'A' * 200000)
            archive.writestr('secret', 'nvapi-private-token')
        for member in ('bomb', 'secret'):
            with self.assertRaises(ValueError):
                self.tools.run({'tool': 'zip_read_text', 'path': str(book), 'member': member})

    def test_history_symlink_metadata_without_following(self):
        history = self.root / '.bash_history'
        history.symlink_to('/dev/null')
        result = json.loads(self.tools.run({'tool': 'path_info', 'path': str(history)}))
        self.assertEqual(result['target'], '/dev/null')
        with self.assertRaises(ValueError):
            self.tools.run({'tool': 'read_text', 'path': str(history)})

    def test_duplicate_requests_reuse_evidence_despite_model_ids(self):
        calls = []
        def caller(messages):
            calls.append(messages)
            if len(calls) <= 2:
                return {'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence), 'tool_id': str(len(calls))}]}
            return {'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False}
        question = agent.discover([self.desktop])[0]
        with patch.object(self.tools, 'run', wraps=self.tools.run) as run:
            agent.investigate(question, self.tools, self.runner / 'data', caller=caller)
            self.assertEqual(run.call_count, 1)
        saved = json.loads((self.runner / 'data' / (question['id'] + '-evidence.json')).read_text())
        self.assertEqual(len(saved), 1)

    def test_discovery_multidigit_extensionless_and_nested(self):
        sub = self.desktop / 'Questions'
        sub.mkdir()
        (sub / 'forensics_question_2.TXT').write_text('Q\nANSWER:\n')
        self.assertEqual([q['number'] for q in agent.discover([self.desktop])], [2, 12])

    def test_shell_rejected(self):
        with self.assertRaises(ValueError): self.tools.run({'command': 'touch /tmp/unsafe', 'tool': 'read_text', 'path': str(self.evidence)})
        with self.assertRaises(ValueError): self.tools.run({'tool': 'shell', 'path': str(self.evidence)})

    def test_protected_config_and_outside_roots(self):
        private = self.runner / 'config.conf'
        private.write_text('dummy-key')
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(private)})
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': '/etc/passwd'})

    def test_credential_file_excluded(self):
        private = self.root / 'config.local.conf'
        private.write_text('dummy-key')
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(private)})

    def test_private_key_content_excluded(self):
        self.evidence.write_text('-----BEGIN OPENSSH PRIVATE KEY-----')
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(self.evidence)})

    @unittest.skipUnless(os.name == 'posix', 'Linux file semantics')
    def test_symlink_and_fifo_excluded(self):
        link = self.root / 'linked'
        link.symlink_to(self.evidence)
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(link)})
        fifo = self.root / 'pipe'
        os.mkfifo(fifo)
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(fifo)})

    def test_bounded_read(self):
        self.evidence.write_text('a' * 20000)
        self.assertEqual(len(self.tools.run({'tool': 'read_text', 'path': str(self.evidence)})), agent.LIMIT)
        with self.assertRaises(ValueError): self.tools.run({'tool': 'read_text', 'path': str(self.evidence), 'offset': -1})

    def test_fabricated_citation_or_answer_rejected(self):
        evidence = {'e1': {'ok': True, 'output': 'Evidence: culprit.exe'}}
        result = {'answers': ['culprit.exe'], 'needs_manual_review': False, 'evidence': [{'tool_id': 'e1', 'quote': 'invented'}]}
        # A sloppy quote is dropped, but the answer is still literally present in real evidence.
        self.assertEqual(agent.supported_answers(result, evidence), ['culprit.exe'])
        result['answers'] = ['invented.exe']
        with self.assertRaises(ValueError): agent.supported_answers(result, evidence)
        result['evidence'][0]['quote'] = 'culprit.exe'
        result['answers'] = ['another.exe']
        with self.assertRaises(ValueError): agent.supported_answers(result, evidence)

    def test_multiline_and_whitespace_quotes_from_recon_verify(self):
        recon = {'download_history_and_ips': 'firefox download: http://203.0.113.9/a.xlsm -> file:///home/u/Downloads/a.xlsm' + chr(10) + 'firefox recent URL: "x"'}
        result = {'answers': ['203.0.113.9'], 'needs_manual_review': False,
                  'evidence': [{'tool_id': 'e0', 'quote': 'http://203.0.113.9/a.xlsm  ->  file:///home/u/Downloads/a.xlsm' + chr(10) + 'firefox recent URL: "x"'}]}
        self.assertEqual(agent.supported_answers(result, {}, recon=recon), ['203.0.113.9'])

    def test_fast_path_answers_unique_download_ip_without_model(self):
        q = {'content': 'What is the IP address of the site we were compromised through? EXAMPLE: 13.33.33.37'}
        recon = {'download_history_and_ips': 'a.jpg user.xdg.origin.url = http://203.0.113.9/a.jpg' + chr(10) + 'firefox recent URL: http://example.com/'}
        result = agent.fast_path(q, recon)
        self.assertEqual(result['answers'], ['203.0.113.9'])
        self.assertEqual(agent.supported_answers(dict(result), {}, recon=recon), ['203.0.113.9'])
        recon['download_history_and_ips'] += chr(10) + 'firefox download: http://198.51.100.7/b.exe -> file:///tmp/b'
        self.assertIsNone(agent.fast_path(q, recon))
        self.assertIsNone(agent.fast_path({'content': 'Which user was added?'}, recon))

    def test_shrink_history_trims_old_tool_output_only(self):
        msgs = [{'role': 'system', 'content': 's'}, {'role': 'user', 'content': 'u'},
                {'role': 'user', 'content': json.dumps({'evidence_results': [{'id': 'e1', 'output': 'x' * 5000}]})}]
        agent.shrink_history(msgs, keep=100)
        self.assertLess(len(msgs[2]['content']), 400)
        self.assertEqual(msgs[1]['content'], 'u')

    def test_rate_limit_429_is_retried_then_succeeds(self):
        import urllib.error

        class Body:
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def read(self, n=-1): return json.dumps({'choices': [{'message': {'content': '{"tool_requests": []}'}, 'finish_reason': 'stop'}]}).encode()

        calls = []

        def fake_urlopen(request, timeout=0):
            calls.append(1)
            if len(calls) < 3:
                raise urllib.error.HTTPError('u', 429, 'Too Many Requests', {'Retry-After': '1'}, None)
            return Body()

        env = {'AI_PROVIDER': 'nvidia', 'OPENROUTER_API_KEY': 'k', 'OPENROUTER_MODEL': 'm', 'AI_MIN_INTERVAL': '0'}
        with patch.dict(os.environ, env), patch.object(agent.urllib.request, 'urlopen', fake_urlopen), \
                patch.object(agent.time, 'sleep', lambda s: None), patch.object(agent, 'save_ai_diagnostic', lambda *a: 'd'):
            self.assertEqual(agent.call_ai([{'role': 'user', 'content': 'x'}]), {'tool_requests': []})
        self.assertEqual(len(calls), 3)

    def test_model_confidence_without_evidence_rejected(self):
        with self.assertRaises(ValueError): agent.supported_answers({'answers': ['guess'], 'needs_manual_review': False}, {})

    def test_malformed_citation_rejected(self):
        with self.assertRaises(ValueError): agent.supported_answers({'answers': ['guess'], 'needs_manual_review': False, 'evidence': ['not-a-record']}, {})

    @unittest.skipUnless(os.name == 'posix', 'Linux file semantics')
    def test_investigate_and_fill_preserves_backup_crlf_mode(self):
        self.question.chmod(0o640)
        original = self.question.read_bytes()
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence)}]},
            {'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False},
        ])
        result = agent.investigate(question, self.tools, self.runner, caller=lambda messages: next(responses))
        agent.apply_answers(question, result['answers'], self.runner / 'backups')
        self.assertEqual(self.question.read_bytes(), b'Identify the file.\r\nANSWER: culprit.exe\r\n')
        self.assertEqual(stat.S_IMODE(self.question.stat().st_mode), 0o640)
        self.assertEqual((self.runner / 'backups' / (question['id'] + '.original')).read_bytes(), original)

    def test_missing_placeholders_not_appended(self):
        question = agent.discover([self.desktop])[0]
        original = self.question.read_bytes()
        with self.assertRaises(ValueError): agent.apply_answers(question, ['one', 'two'], self.runner / 'backups')
        self.assertEqual(self.question.read_bytes(), original)

    def test_changed_source_not_overwritten(self):
        question = agent.discover([self.desktop])[0]
        self.question.write_text('User edited this')
        with self.assertRaises(ValueError): agent.apply_answers(question, ['culprit.exe'], self.runner / 'backups')
        self.assertEqual(self.question.read_text(), 'User edited this')

    def test_legacy_shell_request_stops_investigation(self):
        question = agent.discover([self.desktop])[0]
        with self.assertRaises(ValueError): agent.investigate(question, self.tools, self.runner, caller=lambda messages: {'command_requests': [{'command': 'rm -rf /'}]})

    def test_validation_feedback_continues_multistep_investigation(self):
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'answers': ['guess'], 'needs_manual_review': False},
            {'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence)}]},
            {'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False},
        ])
        seen = []
        def caller(messages):
            seen.append(messages[-1]['content'])
            return next(responses)
        result = agent.investigate(question, self.tools, self.runner, caller=caller)
        self.assertEqual(result['answers'], ['culprit.exe'])
        self.assertIn('validation_feedback', seen[1])
        self.assertIn('evidence_results', seen[2])

    def test_supported_answer_with_extra_tool_request_finalizes(self):
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence)}]},
            {'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False, 'tool_requests': [{'tool': 'read_text', 'path': '/not-needed'}]},
        ])
        result = agent.investigate(question, self.tools, self.runner, caller=lambda messages: next(responses))
        self.assertEqual(result['answers'], ['culprit.exe'])
        self.assertEqual(result['tool_requests'], [])

    def test_budget_reserves_final_synthesis_after_last_tool_output(self):
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence)}]},
            {'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False},
        ])
        with patch.dict(os.environ, {'FORENSICS_MAX_ROUNDS': '1'}):
            result = agent.investigate(question, self.tools, self.runner, caller=lambda messages: next(responses))
        self.assertEqual(result['answers'], ['culprit.exe'])

    def test_partial_results_and_real_evidence_paths_survive(self):
        question = agent.discover([self.desktop])[0]
        (self.runner / (question['id'] + '-round12.json')).write_text(json.dumps({'answers': ['uncertain'], 'explanation': 'Possibly the helper, not proven'}))
        (self.runner / (question['id'] + '-evidence.json')).write_text(json.dumps({'e1': {'ok': True, 'request': {'tool': 'read_text', 'path': str(self.evidence)}, 'output': 'Evidence: culprit.exe'}, 'e2': {'ok': False, 'request': {'path': '/invented'}, 'output': 'not found'}}))
        report = agent.investigation_leads(question, self.runner)
        self.assertEqual(report['partial_answers'], ['uncertain'])
        self.assertEqual([lead['path'] for lead in report['leads']], [str(self.evidence)])

    def test_nvidia_payload_and_endpoint(self):
        class Response:
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return json.dumps({'choices': [{'message': {'content': '{"tool_requests":[]}'}}]}).encode()
        with patch.dict(os.environ, {'AI_PROVIDER': 'nvidia', 'OPENROUTER_API_KEY': 'dummy', 'OPENROUTER_MODEL': 'nvidia/test-model'}):
            with patch.object(agent.urllib.request, 'urlopen', return_value=Response()) as request:
                agent.call_ai([{'role': 'user', 'content': 'test'}])
                sent = request.call_args.args[0]
                self.assertEqual(sent.full_url, 'https://integrate.api.nvidia.com/v1/chat/completions')
                self.assertEqual(json.loads(sent.data)['model'], 'nvidia/test-model')

    @unittest.skipUnless(os.name == 'posix', 'Linux runtime')
    def test_main_with_mocked_nvidia_http_fills_and_saves_report(self):
        class Response:
            def __init__(self, result): self.result = result
            def __enter__(self): return self
            def __exit__(self, *args): pass
            def read(self, size): return json.dumps({'choices': [{'message': {'content': json.dumps(self.result)}}]}).encode()
        responses = [Response({'tool_requests': [{'tool': 'read_text', 'path': str(self.evidence)}]}), Response({'answers': ['culprit.exe'], 'evidence': [{'tool_id': 'e1', 'quote': 'Evidence: culprit.exe'}], 'needs_manual_review': False})]
        settings = {'AI_PROVIDER': 'nvidia', 'OPENROUTER_API_KEY': 'dummy', 'OPENROUTER_MODEL': 'nvidia/test-model', 'REVIEWER_MODEL': 'nvidia/reviewer-model', 'FORENSICS_DIR': str(self.desktop), 'FORENSICS_APPLY_ANSWERS': '1', 'README_FILE': ''}
        def http(request, **kwargs):
            payload = json.loads(request.data)
            if payload['model'] == 'nvidia/reviewer-model':
                material = json.loads(payload['messages'][-1]['content'])
                return Response({'input_sha256': material['input_sha256'], 'approved': True, 'reason': 'Answer matches collected evidence and question'})
            self.assertIn('readme_html_full', payload['messages'][1]['content'])
            return responses.pop(0)
        with patch.dict(os.environ, settings), patch.object(agent, '__file__', str(self.runner / 'lib' / 'forensics_agent.py')), patch.object(agent.urllib.request, 'urlopen', side_effect=http), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(), 0)
        reports = list((self.runner / 'data' / 'forensics').glob('*/results.json'))
        self.assertEqual(len(reports), 1)
        self.assertEqual(json.loads(reports[0].read_text())[0]['status'], 'FILLED_UNVERIFIED_SCORE')
        self.assertIn(b'ANSWER: culprit.exe', self.question.read_bytes())

    def test_no_questions_returns_review_status(self):
        self.question.unlink()
        with patch.dict(os.environ, {'FORENSICS_DIR': str(self.desktop)}), patch.object(agent, '__file__', str(self.runner / 'lib' / 'forensics_agent.py')), contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            self.assertEqual(agent.main(), 2)

    def test_reviewer_decline_preserves_original_question(self):
        import peer_review
        original = self.question.read_bytes()
        def investigation(question, tools, directory, **kwargs):
            (directory / (question['id'] + '-evidence.json')).write_text('{}')
            return {'answers': ['culprit.exe'], 'needs_manual_review': False}
        with patch.dict(os.environ, {'FORENSICS_DIR': str(self.desktop), 'README_FILE': '', 'OPENROUTER_MODEL': 'worker'}), patch.object(agent, '__file__', str(self.runner / 'lib/forensics_agent.py')), patch.object(agent, 'investigate', side_effect=investigation), patch.object(peer_review, 'review', side_effect=ValueError('Reviewer declined')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(), 2)
        self.assertEqual(self.question.read_bytes(), original)

    def test_autonomous_commands_investigation_and_fill(self):
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'commands': [f'cat "{self.evidence}"']},
            {'answers': ['culprit.exe'], 'solved': True}
        ])
        result = agent.investigate(question, self.tools, self.runner, caller=lambda messages: next(responses))
        self.assertEqual(result['answers'], ['culprit.exe'])
        agent.apply_answers(question, result['answers'], self.runner / 'backups')
        self.assertIn(b'ANSWER: culprit.exe', self.question.read_bytes())

    def test_sqlite_query_tool(self):
        import sqlite3
        db = self.root / 'history.sqlite'
        with sqlite3.connect(str(db)) as conn:
            conn.execute('CREATE TABLE moz_places (id INTEGER, url TEXT);')
            conn.execute("INSERT INTO moz_places VALUES (1, 'http://13.33.33.37/download.xlsm');")
        res = self.tools.run({'tool': 'sqlite_query', 'path': str(db), 'query': 'SELECT url FROM moz_places;'})
        self.assertIn('13.33.33.37', res)

    def test_usr_prefix_stripped_scoring_allowed(self):
        evidence = {'e1': {'ok': True, 'output': 'Listening process: /usr/bin/nc.traditional'}}
        result = {'answers': ['/bin/nc.traditional'], 'evidence': [{'tool_id': 'e1', 'quote': '/usr/bin/nc.traditional'}]}
        answers = agent.supported_answers(result, evidence)
        self.assertEqual(answers, ['/bin/nc.traditional'])

    def test_initial_recon_fast_solve(self):
        recon = {'download_history_and_ips': 'http://192.9.137.137/malicious.xlsm'}
        result = {'answers': ['192.9.137.137'], 'evidence': [{'tool_id': 'e0', 'quote': '192.9.137.137'}]}
        answers = agent.supported_answers(result, {}, recon=recon)
        self.assertEqual(answers, ['192.9.137.137'])


    def test_already_answered_skips_investigation(self):
        self.question.write_bytes(b'Identify the file.\r\nANSWER: 192.9.137.137\r\n')
        with patch.dict(os.environ, {'FORENSICS_DIR': str(self.desktop), 'README_FILE': ''}), patch.object(agent, '__file__', str(self.runner / 'lib/forensics_agent.py')), contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(agent.main(), 0)

    def test_placeholder_recognition(self):
        self.assertTrue(agent.is_unanswered_placeholder('<Type Answer Here>'))
        self.assertTrue(agent.is_unanswered_placeholder('<Type-Answer-Here>'))
        self.assertTrue(agent.is_unanswered_placeholder('[Type Answer Here]'))
        self.assertTrue(agent.is_unanswered_placeholder('<Type-Answer-Here-Leave-Single-Space-After-Colon>'))
        self.assertTrue(agent.is_unanswered_placeholder(''))
        self.assertTrue(agent.is_unanswered_placeholder('   '))
        self.assertTrue(agent.is_unanswered_placeholder('TODO'))
        self.assertTrue(agent.is_unanswered_placeholder('N/A'))
        self.assertFalse(agent.is_unanswered_placeholder('/home/benjamin/Music'))
        self.assertFalse(agent.is_unanswered_placeholder('192.168.1.50'))
        self.assertFalse(agent.is_unanswered_placeholder('benjamin'))

    def test_clean_answer_value(self):
        self.assertEqual(agent.clean_answer_value('<192.168.1.50>'), '192.168.1.50')
        self.assertEqual(agent.clean_answer_value('[/home/benjamin/Music]'), '/home/benjamin/Music')
        self.assertEqual(agent.clean_answer_value('ANSWER: 192.168.1.50'), '192.168.1.50')
        self.assertEqual(agent.clean_answer_value('<<culprit.exe>>'), 'culprit.exe')

    def test_placeholder_not_skipped_and_clean_answer_written(self):
        self.question.write_bytes(b'Identify the file.\r\nANSWER: <Type-Answer-Here>\r\n')
        question = agent.discover([self.desktop])[0]
        responses = iter([
            {'answers': ['<culprit.exe>'], 'solved': True, 'evidence': [{'tool_id': 'e0', 'quote': 'culprit.exe'}]}
        ])
        with patch.object(agent, 'gather_initial_recon', return_value={'lead': 'culprit.exe'}):
            result = agent.investigate(question, self.tools, self.runner, caller=lambda messages: next(responses))
            self.assertEqual(result['answers'], ['culprit.exe'])
            agent.apply_answers(question, result['answers'], self.runner / 'backups')
            # Verify clean answer without angle brackets written directly into file
            self.assertEqual(self.question.read_bytes(), b'Identify the file.\r\nANSWER: culprit.exe\r\n')

    def test_eof_stdin_is_not_a_skip_but_enter_is(self):
        for payload, expected in ((b"", False), (bytes([10]), True)):
            r, w = os.pipe()
            os.write(w, payload)
            os.close(w)
            with os.fdopen(r) as stream:
                with patch.object(agent, '_tty_stream', None), patch.object(sys, 'stdin', stream), \
                        patch.dict(os.environ, {'SKIP_FORENSICS': ''}):
                    self.assertEqual(agent.check_user_skip(0), expected)


if __name__ == '__main__': unittest.main()
