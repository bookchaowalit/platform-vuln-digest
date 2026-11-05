import unittest

from vuln_digest.checks import excluded, findings_for, not_installed, sweep
from vuln_digest.github import ProviderError

from .test_github import alert


class Findings(unittest.TestCase):
    def test_one_finding_per_open_alert(self):  # AC1
        got = findings_for('o/r', [alert(3, 'critical'), alert(4, 'low')])
        self.assertEqual([(f.id, f.severity) for f in got],
                         [('dependabot:o/r#3', 'critical'), ('dependabot:o/r#4', 'low')])
        self.assertIn('lib', got[0].subject)
        self.assertIn('fix 1.2.3', got[0].subject)

    def test_disabled_alerts_are_one_medium_finding(self):  # AC2
        [f] = findings_for('o/r', None)
        self.assertEqual((f.id, f.severity), ('alerts-disabled:o/r', 'medium'))


class NotInstalled(unittest.TestCase):
    def test_owner_without_installation_is_a_finding(self):
        [f] = not_installed(['org'])
        self.assertEqual((f.id, f.severity), ('app-not-installed:org', 'medium'))


class Exclusion(unittest.TestCase):
    def test_owner_wildcard_and_exact_repo(self):  # AC3
        patterns = ['client-org/*', 'me/client-web']
        self.assertTrue(excluded('client-org/anything', patterns))
        self.assertTrue(excluded('me/client-web', patterns))
        self.assertTrue(excluded('Me/Client-Web', patterns))
        self.assertFalse(excluded('me/client-web-2', patterns))
        self.assertFalse(excluded('me/own', patterns))


class Sweep(unittest.TestCase):
    def repos(self):
        return [('t', {'full_name': 'me/own', 'archived': False, 'fork': False}),
                ('t', {'full_name': 'me/old', 'archived': True, 'fork': False}),
                ('t', {'full_name': 'me/copy', 'archived': False, 'fork': True}),
                ('t', {'full_name': 'client-org/x', 'archived': False, 'fork': False}),
                ('t2', {'full_name': 'me/own', 'archived': False, 'fork': False})]  # seen by two installations

    def test_skips_archived_forks_and_excluded_and_dedupes(self):  # AC3
        asked = []

        def alerts(token, name):
            asked.append(name)
            return [alert(1)]
        found, scanned = sweep(self.repos(), alerts, ['client-org/*'])
        self.assertEqual(asked, ['me/own'])
        self.assertEqual(scanned, 1)
        self.assertEqual([f.id for f in found], ['dependabot:me/own#1'])

    def test_one_failure_fails_the_sweep(self):  # R4
        def alerts(token, name):
            raise ProviderError('dependabot alerts: HTTP 500')
        with self.assertRaises(ProviderError):
            sweep(self.repos(), alerts, [])


if __name__ == '__main__':
    unittest.main()
