"""Create the digest's GitHub App with the manifest flow and store its credentials (owner runs this once).

    python3 scripts/create_app.py

Opens a local page that posts the manifest to GitHub. After you press "Create GitHub App",
GitHub redirects back here; the script converts the code, then writes the App id and private key
to Infisical `/vuln-digest` and to this repository's Actions secrets without printing them, and
prints the install link. Install the App on your account and each own organization (not
Happy-Teeth or bookchaowalit-freelance), "All repositories".

Permissions: Dependabot alerts read, Metadata read (SPEC-001 R1). No webhook.
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
    'public': False,
    'default_permissions': {'vulnerability_alerts': 'read', 'metadata': 'read'},
    'default_events': [],
}
done = threading.Event()
result = {}


def store(app_id, pem):
    project, env = os.environ['INFISICAL_PROJECT_ID'], os.environ.get('INFISICAL_ENVIRONMENT', 'dev')
    subprocess.run(['infisical', 'secrets', 'folders', 'create', '--name', INFISICAL_PATH.strip('/'), '--path', '/',
                    '--projectId', project, '--env', env, '--silent'], capture_output=True)
    fd, path = tempfile.mkstemp(suffix='.pem')
    try:
        with os.fdopen(fd, 'w') as f:
            f.write(pem)
        # KEY=@file keeps the multi-line key out of argv and out of any .env quoting.
        subprocess.run(['infisical', 'secrets', 'set', f'VULN_GITHUB_APP_ID={app_id}',
                        f'VULN_GITHUB_APP_PRIVATE_KEY_PEM=@{path}', '--path', INFISICAL_PATH, '--projectId', project,
                        '--env', env, '--silent'], check=True, capture_output=True)
    finally:
        os.unlink(path)
    subprocess.run(['gh', 'secret', 'set', 'VULN_GITHUB_APP_ID', '--repo', REPO], input=str(app_id).encode(),
                   check=True, capture_output=True)
    subprocess.run(['gh', 'secret', 'set', 'VULN_GITHUB_APP_PRIVATE_KEY_PEM', '--repo', REPO], input=pem.encode(),
                   check=True, capture_output=True)


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
                result['error'] = type(exc).__name__
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
    print('Stored VULN_GITHUB_APP_ID and VULN_GITHUB_APP_PRIVATE_KEY_PEM (Infisical /vuln-digest and Actions secrets).')
    print(f'Now install it: {result["install"]}')


if __name__ == '__main__':
    main()
