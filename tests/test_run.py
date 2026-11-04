import io
import json
import tempfile
import unittest
from pathlib import Path

from vuln_digest.github import ProviderError
from vuln_digest.report import dump_state
from vuln_digest.run import NOTIFY_FAILED, OK, PROVIDER_FAILED, run

from .test_report import CRIT, OFF


class Run(unittest.TestCase):
    def setUp(self):
        self.dir = Path(tempfile.mkdtemp())
        self.state_in, self.state_out = self.dir / 'in.json', self.dir / 'out.json'
        self.sent, self.out = [], io.StringIO()

    def go(self, findings_fn, send=None):
        return run(self.state_in, self.state_out, findings_fn, send or self.sent.append, out=self.out)

    def test_provider_failure_keeps_state(self):  # AC2, R4
        def fail():
            raise ProviderError('dependabot alerts: HTTP 500')
        self.state_in.write_text(dump_state([CRIT]))
        self.assertEqual(self.go(fail), PROVIDER_FAILED)
        self.assertFalse(self.state_out.exists())
        self.assertEqual(self.sent, [])
        self.assertNotIn('me/', self.out.getvalue())

    def test_first_run_sends_baseline(self):
        self.assertEqual(self.go(lambda: ([CRIT, OFF], 2)), OK)
        self.assertEqual(len(self.sent), 1)
        self.assertEqual(len(json.loads(self.state_out.read_text())['findings']), 2)
        self.assertNotIn('me/', self.out.getvalue())  # AC6

    def test_unchanged_sends_nothing(self):
        self.state_in.write_text(dump_state([CRIT]))
        self.assertEqual(self.go(lambda: ([CRIT], 1)), OK)
        self.assertEqual(self.sent, [])

    def test_refused_alert_is_kept_and_retried(self):  # R7
        def refuse(text):
            raise OSError('telegram down')
        self.state_in.write_text(dump_state([]))
        self.assertEqual(self.go(lambda: ([CRIT], 1), send=refuse), NOTIFY_FAILED)
        self.state_in.write_text(self.state_out.read_text())
        self.assertEqual(self.go(lambda: ([CRIT], 1)), OK)
        self.assertEqual(len(self.sent), 1)
        self.assertIn('GHSA-1', self.sent[0])
        self.assertNotIn('pending_messages', json.loads(self.state_out.read_text()))


if __name__ == '__main__':
    unittest.main()
