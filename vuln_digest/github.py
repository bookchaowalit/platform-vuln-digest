"""GitHub REST calls: App JWT, installations, repositories and open Dependabot alerts (SPEC-001 R1, R5, R6).

The App JWT is RS256-signed with the `openssl` binary, so the package keeps no third-party
dependency. Errors carry only the endpoint kind and status, never a repository name, because
they reach the public job log (R2).
"""
import base64
import json
import os
import re
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

API = 'https://api.github.com'
USER_AGENT = 'platform-vuln-digest/1'
TIMEOUT = 20
DISABLED = 'Dependabot alerts are disabled'
_NEXT = re.compile(r'<([^>]+)>;\s*rel="next"')


class ProviderError(Exception):
    pass


def _b64(data):
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()


def app_jwt(app_id, private_key_pem, now=None):
    """A 10-minute App JWT; iat is back-dated 60 s for clock drift, as GitHub recommends."""
    now = int(now if now is not None else time.time())
    header = _b64(json.dumps({'alg': 'RS256', 'typ': 'JWT'}).encode())
    claims = _b64(json.dumps({'iss': str(app_id), 'iat': now - 60, 'exp': now + 540}).encode())
    signing_input = f'{header}.{claims}'
    fd, path = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(private_key_pem)
        sig = subprocess.run(['openssl', 'dgst', '-sha256', '-sign', path], input=signing_input.encode(),
                             capture_output=True, check=True).stdout
    finally:
        os.unlink(path)
    return f'{signing_input}.{_b64(sig)}'


def http(method, url, token, timeout=TIMEOUT):
    """(status, parsed json or None, lower-cased headers); network failures raise ProviderError."""
    scheme = 'Bearer' if token.count('.') == 2 else 'token'  # App JWT vs installation/personal token
    req = urllib.request.Request(url, method=method, data=b'' if method == 'POST' else None, headers={
        'Accept': 'application/vnd.github+json', 'Authorization': f'{scheme} {token}',
        'X-GitHub-Api-Version': '2022-11-28', 'User-Agent': USER_AGENT})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw, headers = resp.status, resp.read(), resp.headers
    except urllib.error.HTTPError as exc:
        status, raw, headers = exc.code, exc.read(), exc.headers
    except (OSError, urllib.error.URLError) as exc:
        raise ProviderError(f'github: {type(exc).__name__}') from None
    try:
        body = json.loads(raw) if raw else None
    except ValueError:
        body = None
    return status, body, {k.lower(): v for k, v in (headers or {}).items()}


class GitHub:
    def __init__(self, fetch=http):
        self.fetch = fetch

    def _pages(self, url, token, kind, key=None):
        while url:
            status, body, headers = self.fetch('GET', url, token, TIMEOUT)
            if status != 200:
                raise ProviderError(f'{kind}: HTTP {status}')
            yield from (body[key] if key else body)
            match = _NEXT.search(headers.get('link', ''))
            url = match.group(1) if match else None

    def app_repositories(self, jwt):
        """(installation token, repository) for every repository of every installation of the App."""
        out = []
        for inst in self._pages(f'{API}/app/installations?per_page=100', jwt, 'installations'):
            status, body, _ = self.fetch('POST', f'{API}/app/installations/{inst["id"]}/access_tokens', jwt, TIMEOUT)
            if status != 201:
                raise ProviderError(f'installation token: HTTP {status}')
            token = body['token']
            out += [(token, r) for r in self._pages(f'{API}/installation/repositories?per_page=100', token,
                                                    'repositories', key='repositories')]
        return out

    def user_repositories(self, token):
        """Local runs with a personal token: the repositories the user owns or reaches through an org."""
        url = f'{API}/user/repos?per_page=100&affiliation=owner,organization_member'
        return [(token, r) for r in self._pages(url, token, 'repositories')]

    def alerts(self, token, full_name):
        """Open Dependabot alerts of one repository, or None when alerts are turned off for it."""
        url = f'{API}/repos/{full_name}/dependabot/alerts?state=open&per_page=100'
        status, body, headers = self.fetch('GET', url, token, TIMEOUT)
        if status == 403 and DISABLED in ((body or {}).get('message') or ''):
            return None
        if status != 200:
            raise ProviderError(f'dependabot alerts: HTTP {status}')
        out = list(body)
        match = _NEXT.search(headers.get('link', ''))
        if match:
            out += self._pages(match.group(1), token, 'dependabot alerts')
        return out
