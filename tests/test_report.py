import json
import unittest

from vuln_digest.checks import Finding
from vuln_digest.report import MAX_CHARS, diff, dump_state, load_state, message, public_summary

CRIT = Finding('dependabot', 'critical', 'me/api', 'dependabot:me/api#1', 'lib (npm) GHSA-1 fix 1.2.3')
LOW = Finding('dependabot', 'low', 'me/api', 'dependabot:me/api#2', 'tiny (npm) GHSA-2')
OFF = Finding('alerts-disabled', 'medium', 'me/web', 'alerts-disabled:me/web', 'Dependabot alerts are off')


class Diff(unittest.TestCase):
    def test_opened_and_resolved(self):  # AC4
        previous = load_state(dump_state([CRIT, OFF]))
        opened, resolved = diff(previous, [CRIT, LOW])
        self.assertEqual([f.id for f in opened], [LOW.id])
        self.assertEqual([f['id'] for f in resolved], [OFF.id])

    def test_unchanged_is_empty(self):  # AC4
        previous = load_state(dump_state([CRIT]))
        self.assertEqual(diff(previous, [CRIT]), ([], []))


class Message(unittest.TestCase):
    def test_nothing_changed_sends_nothing(self):  # AC4
        self.assertIsNone(message([], [], [CRIT], first_run=False))

    def test_only_low_opened_sends_nothing(self):  # AC4, R3
        self.assertIsNone(message([LOW], [], [CRIT, LOW], first_run=False))

    def test_opened_grouped_by_repo_highest_first(self):  # R3
        text = message([OFF, LOW, CRIT], [], [CRIT, LOW, OFF], first_run=False)
        self.assertIn('me/api', text)
        self.assertLess(text.index('me/api'), text.index('me/web'))
        self.assertIn('GHSA-1', text)
        self.assertNotIn('GHSA-2', text)  # low: counted only
        self.assertIn('1 critical', text)

    def test_resolved_listed(self):
        text = message([], [CRIT.as_dict()], [], first_run=False)
        self.assertIn('Resolved', text)
        self.assertIn('GHSA-1', text)

    def test_baseline_lists_repos_not_every_alert(self):  # R3
        many = [Finding('dependabot', 'high', f'me/r{i % 3}', f'dependabot:me/r{i % 3}#{i}', f'p{i}')
                for i in range(30)]
        text = message(many, [], many, first_run=True)
        self.assertIn('baseline', text)
        self.assertIn('me/r0', text)
        self.assertNotIn('p17', text)

    def test_long_message_is_bounded(self):
        many = [Finding('dependabot', 'critical', f'me/{"x" * 60}{i}', f'dependabot:me/x{i}#1', 'y' * 80)
                for i in range(200)]
        self.assertLessEqual(len(message(many, [], many, first_run=False)), MAX_CHARS)


class Public(unittest.TestCase):
    def test_counts_only(self):  # AC6
        text = public_summary([CRIT, LOW, OFF], opened=1, resolved=0, scanned=12)
        for name in ('me/', 'GHSA', 'lib'):
            self.assertNotIn(name, text)
        self.assertEqual(json.loads(text)['critical'], 1)
        self.assertEqual(json.loads(text)['alerts_disabled'], 1)


if __name__ == '__main__':
    unittest.main()
