import base64
import json
import subprocess
import tempfile
import unittest
from pathlib import Path

from vuln_digest.github import API, GitHub, ProviderError, app_jwt


class FakeHttp:
    """Answers (method, url) from a table: value = (status, json body, headers)."""

    def __init__(self, table):
        self.table, self.calls = table, []

    def __call__(self, method, url, token, timeout):
        self.calls.append((method, url, token))
        if url not in self.table:
            raise AssertionError(f'unexpected {method} {url}')
        status, body, headers = self.table[url]
        return status, body, headers


def alert(n, severity='high'):
    return {'number': n, 'state': 'open',
            'security_advisory': {'ghsa_id': f'GHSA-{n}', 'severity': severity},
            'security_vulnerability': {'package': {'name': 'lib', 'ecosystem': 'npm'},
                                       'first_patched_version': {'identifier': '1.2.3'}},
            'dependency': {'manifest_path': 'package-lock.json'}}


class Alerts(unittest.TestCase):
    def test_follows_link_next_until_it_ends(self):  # AC5
        first = f'{API}/repos/o/r/dependabot/alerts?state=open&per_page=100'
        second = f'{API}/repositories/1/dependabot/alerts?page=2'
        http = FakeHttp({first: (200, [alert(1)], {'link': f'<{second}>; rel="next", <{first}>; rel="first"'}),
                         second: (200, [alert(2)], {})})
        got = GitHub(http).alerts('tok', 'o/r')
        self.assertEqual([a['number'] for a in got], [1, 2])

    def test_disabled_answer_is_none(self):  # AC2
        url = f'{API}/repos/o/r/dependabot/alerts?state=open&per_page=100'
        http = FakeHttp({url: (403, {'message': 'Dependabot alerts are disabled for this repository.'}, {})})
        self.assertIsNone(GitHub(http).alerts('tok', 'o/r'))

    def test_any_other_error_fails(self):  # AC2, R4
        url = f'{API}/repos/o/r/dependabot/alerts?state=open&per_page=100'
        for status, body in [(403, {'message': 'Resource not accessible by integration'}), (500, {}), (404, {})]:
            http = FakeHttp({url: (status, body, {})})
            with self.assertRaises(ProviderError) as ctx:
                GitHub(http).alerts('tok', 'o/r')
            self.assertNotIn('o/r', str(ctx.exception))  # R2: the error reaches the public log


class AppAuth(unittest.TestCase):
    def test_repositories_of_every_installation(self):
        http = FakeHttp({
            f'{API}/app/installations?per_page=100': (200, [{'id': 7}, {'id': 9}], {}),
            f'{API}/app/installations/7/access_tokens': (201, {'token': 't7'}, {}),
            f'{API}/app/installations/9/access_tokens': (201, {'token': 't9'}, {}),
            f'{API}/installation/repositories?per_page=100': (200, {'repositories': [{'full_name': 'o/a'}]}, {}),
        })
        got = GitHub(http).app_repositories('jwt')
        self.assertEqual([(token, r['full_name']) for token, r in got], [('t7', 'o/a'), ('t9', 'o/a')])
        self.assertEqual(http.calls[0][2], 'jwt')

    def test_jwt_is_rs256_signed_by_openssl(self):
        d = Path(tempfile.mkdtemp())
        key = d / 'k.pem'
        subprocess.run(['openssl', 'genrsa', '-out', str(key), '2048'], check=True, capture_output=True)
        token = app_jwt('123', key.read_text(), now=1_000_000)
        header, claims, sig = token.split('.')
        pad = lambda s: base64.urlsafe_b64decode(s + '=' * (-len(s) % 4))  # noqa: E731
        self.assertEqual(json.loads(pad(header))['alg'], 'RS256')
        self.assertEqual(json.loads(pad(claims)), {'iss': '123', 'iat': 1_000_000 - 60, 'exp': 1_000_000 + 540})
        pub = d / 'p.pem'
        subprocess.run(['openssl', 'rsa', '-in', str(key), '-pubout', '-out', str(pub)], check=True,
                       capture_output=True)
        (d / 'sig').write_bytes(pad(sig))
        ok = subprocess.run(['openssl', 'dgst', '-sha256', '-verify', str(pub), '-signature', str(d / 'sig')],
                            input=f'{header}.{claims}'.encode(), capture_output=True)
        self.assertEqual(ok.returncode, 0)


if __name__ == '__main__':
    unittest.main()
