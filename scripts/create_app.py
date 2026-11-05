"""Create the digest's GitHub App with the manifest flow and store its credentials (owner runs this once).

    python3 scripts/create_app.py

Opens a local page that posts the manifest to GitHub. After you press "Create GitHub App",
GitHub redirects back here; the script converts the code, then writes the App id and private key
to Infisical `/vuln-digest` and to this repository's Actions secrets without printing them, and
prints the install link. Install the App on your account and on each organization listed in the
`VULN_OWNERS` secret, "All repositories".

Permissions: Dependabot alerts read, Metadata read (SPEC-001 R1). No webhook. The App is public
because GitHub lets a private App be installed only on the account that owns it; the digest reads
only installations on `VULN_OWNERS`, so an install anywhere else gives that account nothing.
"""
import http.server
import json
import os
import subprocess
import sys
import tempfile
import threading
import urllib.parse
import urllib.request
import webbrowser

PORT = 8719
REPO = 'bookchaowalit/platform-vuln-digest'
INFISICAL_PATH = '/vuln-digest'
MANIFEST = {
    'name': 'bookchaowalit-vuln-digest',
    'url': f'https://github.com/{REPO}',
    'hook_attributes': {'url': f'https://github.com/{REPO}', 'active': False},
    'redirect_url': f'http://127.0.0.1:{PORT}/callback',
    'public': True,  # installable on the organizations; see the module docstring
    'default_permissions': {'vulnerability_alerts': 'read', 'metadata': 'read'},
    'default_events': [],
}
done = threading.Event()
result = {}


def store(app_id, pem):
    """Actions secrets first (the job needs them); Infisical is the copy and may need a login.

    The manifest code works once, so if GitHub refuses the secrets the key is kept in a 0600 file
    instead of being lost.
    """
    try:
        _actions_secrets(app_id, pem)
    except (subprocess.CalledProcessError, OSError):
        keep = os.path.expanduser('~/vuln-digest-app.pem')
        fd = os.open(keep, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(pem)
        raise RuntimeError(f'gh secret set failed; App {app_id} key kept in {keep}') from None
    _infisical(app_id, pem)


def _actions_secrets(app_id, pem):
    subprocess.run(['gh', 'secret', 'set', 'VULN_GITHUB_APP_ID', '--repo', REPO], input=str(app_id).encode(),
                   check=True, capture_output=True)
    subprocess.run(['gh', 'secret', 'set', 'VULN_GITHUB_APP_PRIVATE_KEY_PEM', '--repo', REPO], input=pem.encode(),
                   check=True, capture_output=True)


def _infisical(app_id, pem):
    project, env = os.environ['INFISICAL_PROJECT_ID'], os.environ.get('INFISICAL_ENVIRONMENT', 'dev')
    fd, path = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(pem)
        # KEY=@file keeps the multi-line key out of argv and out of any .env quoting.
        proc = subprocess.run(['infisical', 'secrets', 'set', f'VULN_GITHUB_APP_ID={app_id}',
                               f'VULN_GITHUB_APP_PRIVATE_KEY_PEM=@{path}', '--path', INFISICAL_PATH,
                               '--projectId', project, '--env', env, '--silent'],
                              capture_output=True, stdin=subprocess.DEVNULL, timeout=60)
        result['infisical'] = proc.returncode == 0
    except subprocess.TimeoutExpired:
        result['infisical'] = False
    finally:
        os.unlink(path)


class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, format, *args):  # noqa: A002  quiet: the callback URL carries the code
        pass

    def reply(self, html):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()
        self.wfile.write(html.encode())

    def do_GET(self):
        url = urllib.parse.urlsplit(self.path)
        if url.path == '/':
            manifest = json.dumps(MANIFEST).replace('"', '&quot;')
            self.reply('<form id=f method=post action="https://github.com/settings/apps/new">'
                       f'<input type=hidden name=manifest value="{manifest}"></form>'
                       '<script>document.getElementById("f").submit()</script>')
        elif url.path == '/callback':
            code = urllib.parse.parse_qs(url.query).get('code', [''])[0]
            req = urllib.request.Request(f'https://api.github.com/app-manifests/{urllib.parse.quote(code)}/conversions',
                                         method='POST', data=b'', headers={'Accept': 'application/vnd.github+json'})
            try:
                with urllib.request.urlopen(req, timeout=30) as resp:
                    app = json.load(resp)
                store(app['id'], app['pem'])
                result['install'] = f'{app["html_url"]}/installations/new'
                self.reply('App created and stored. You can close this tab and return to the terminal.')
            except Exception as exc:  # noqa: BLE001
                # RuntimeError carries our own message (no secret); anything else only its type.
                result['error'] = str(exc) if isinstance(exc, RuntimeError) else type(exc).__name__
                self.reply('Something failed; see the terminal.')
            done.set()


def main():
    if 'INFISICAL_PROJECT_ID' not in os.environ:
        sys.exit('source ~/.config/solo-empire/environment.sh first')
    server = http.server.HTTPServer(('127.0.0.1', PORT), Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    print(f'Open http://127.0.0.1:{PORT}/ and press "Create GitHub App".')
    webbrowser.open(f'http://127.0.0.1:{PORT}/')
    done.wait()
    server.shutdown()
    if 'error' in result:
        sys.exit(f'failed: {result["error"]}')
    print('Stored VULN_GITHUB_APP_ID and VULN_GITHUB_APP_PRIVATE_KEY_PEM in the Actions secrets.')
    if not result.get('infisical'):
        print('Infisical copy NOT written (log in, then copy the secrets to /vuln-digest).')
    print(f'Now install it: {result["install"]}')


if __name__ == '__main__':
    main()
