import sys
from pathlib import Path
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'lib'))
from score_tracker import parse_scoring_report


class ScoreTrackerTests(unittest.TestCase):
    def test_parse_report_with_date_and_points(self):
        html = """
        <!DOCTYPE html>
        <html>
        <head><title>Scoring Report</title></head>
        <body>
        <div class="header">
            <p>Report Generated At: 2026/10/17 01:09:51 UTC</p>
            <p>Team ID: 19-3460</p>
        </div>
        <div class="score">
            <h2>47 out of 100 points received (8 out of 18 scored checks)</h2>
        </div>
        <ul class="scored-list">
            <li>Forensics Question 1 correct</li>
            <li>Removed unauthorized user tgianopolous</li>
            <li>Removed unauthorized user jquelling</li>
            <li>User dscott is not an administrator</li>
            <li>Created new administrator account for edarby</li>
            <li>User edarby must change password at next login</li>
            <li>Uncomplicated Firewall (UFW) protection enabled</li>
            <li>FTP service disabled/removed</li>
        </ul>
        <div class="penalties">
            <p>Penalties: None</p>
        </div>
        </body>
        </html>
        """
        info = parse_scoring_report(html)
        self.assertEqual(info['score'], 47)
        self.assertEqual(info['max_score'], 100)
        self.assertEqual(info['num_vulns'], 8)
        self.assertEqual(len(info['scored_items']), 8)
        self.assertIn("Forensics Question 1 correct", info['scored_items'])
        self.assertIn("FTP service disabled/removed", info['scored_items'])

    def test_parse_report_alternative_formats(self):
        html1 = "<p>Score: 54 / 100 points</p>"
        info1 = parse_scoring_report(html1)
        self.assertEqual(info1['score'], 54)
        self.assertEqual(info1['max_score'], 100)

        html2 = "<p>Total: 100 out of 100 points received</p>"
        info2 = parse_scoring_report(html2)
        self.assertEqual(info2['score'], 100)
        self.assertEqual(info2['max_score'], 100)

    def test_reject_timestamp_only(self):
        html = "<p>Report Generated At: 2026/10/17 01:09:51 UTC</p>"
        info = parse_scoring_report(html)
        self.assertIsNone(info['score'])
        self.assertIsNone(info['max_score'])


if __name__ == '__main__':
    unittest.main()
