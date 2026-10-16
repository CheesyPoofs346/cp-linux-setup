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
from unittest.mock import patch

spec = importlib.util.spec_from_file_location('forensics', Path(__file__).resolve().parents[1] / 'lib/forensics_agent.py')
sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
agent = importlib.util.module_from_spec(spec)
spec.loader.exec_module(agent)


class ForensicsTests(unittest.TestCase):
    def setUp(self):
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
        with self.assertRaises(ValueError): agent.supported_answers(result, evidence)
        result['evidence'][0]['quote'] = 'culprit.exe'
        result['answers'] = ['another.exe']
        with self.assertRaises(ValueError): agent.supported_answers(result, evidence)

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


if __name__ == '__main__': unittest.main()
