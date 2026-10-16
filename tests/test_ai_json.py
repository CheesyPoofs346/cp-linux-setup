import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from forensics_agent import decode_model_json


class JsonOutputTests(unittest.TestCase):
    def test_plain_object(self):
        self.assertEqual(decode_model_json('{"answers":[]}'), {'answers': []})

    def test_fence_and_prose(self):
        text = 'Here is the result:\n```json\n{"tool_requests":[]}\n```\nEnd.'
        self.assertEqual(decode_model_json(text), {'tool_requests': []})

    def test_thinking_not_executed(self):
        text = '<think>{"tool_requests":[{"tool":"shell"}]}</think>\n{"answers":[]}'
        self.assertEqual(decode_model_json(text), {'answers': []})

    def test_bom(self):
        self.assertEqual(decode_model_json('\ufeff{"answers":[]}'), {'answers': []})

    def test_ambiguous_objects_rejected(self):
        with self.assertRaises(ValueError): decode_model_json('Example: {"a":1}\nFinal: {"a":2}')

    def test_truncated_outer_object_not_salvaged(self):
        with self.assertRaises(ValueError): decode_model_json('{"nested":{"answers":[]}')

    def test_incomplete_think_rejected(self):
        with self.assertRaises(ValueError): decode_model_json('<think>{"answers":[]}')

    def test_empty_nonjson_or_array_rejected(self):
        for text in ('', 'No response', '[{"answers":[]}]'):
            with self.assertRaises(ValueError): decode_model_json(text)


if __name__ == '__main__': unittest.main()
