"""One digest run: sweep, diff, alert, then write state (SPEC-001 R3, R4, R7)."""
import argparse
import json
import os
import sys
import urllib.request
from pathlib import Path

from .checks import sweep
from .github import GitHub, ProviderError, app_jwt
from .report import NOTIFY_MIN, diff, dump_state, load_pending, load_state, message, public_summary

OK, PROVIDER_FAILED, NOTIFY_FAILED = 0, 2, 3


def live_findings(env):
    gh = GitHub()
    if env.get('VULN_GITHUB_APP_ID'):
        repos = gh.app_repositories(app_jwt(env['VULN_GITHUB_APP_ID'], env['VULN_GITHUB_APP_PRIVATE_KEY_PEM']))
    elif env.get('VULN_GITHUB_TOKEN'):  # local runs only
        repos = gh.user_repositories(env['VULN_GITHUB_TOKEN'])
    else:
        raise ProviderError('missing VULN_GITHUB_APP_ID or VULN_GITHUB_TOKEN')
    exclude = [p for p in env.get('VULN_EXCLUDE', '').replace('\n', ',').split(',') if p.strip()]
    return sweep(repos, gh.alerts, exclude)


def telegram(env):
    def send(text):
        data = json.dumps({'chat_id': env['TELEGRAM_CHAT_ID'], 'text': text,
                           'disable_web_page_preview': True}).encode()
        req = urllib.request.Request(f'https://api.telegram.org/bot{env["TELEGRAM_BOT_TOKEN"]}/sendMessage',
                                     data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=20) as resp:
            if not json.load(resp).get('ok'):
                raise OSError('telegram refused the message')
    return send


def run(state_in, state_out, findings_fn, send, out=sys.stdout, notify_min=NOTIFY_MIN):
    """Returns the exit code. A failed sweep writes no state; otherwise unsent alerts are kept in it."""
    try:
        current, scanned = findings_fn()
    except ProviderError as exc:
        print(json.dumps({'status': 'provider_failed', 'error': str(exc)}), file=out)
        return PROVIDER_FAILED
    previous_text = state_in.read_text() if state_in.exists() else ''
    previous = load_state(previous_text)
    opened, resolved = diff(previous or {}, current)

    queue = load_pending(previous_text)
    text = message(opened, resolved, current, first_run=previous is None, notify_min=notify_min)
    if text:
        queue.append(text)
    unsent = []
    for n, item in enumerate(queue):
        try:
            send(item)
        except Exception:  # noqa: BLE001  kept in state, retried next run
            unsent = queue[n:]
            break

    state_out.write_text(dump_state(current, pending_messages=unsent))
    summary = json.loads(public_summary(current, len(opened), len(resolved), scanned))
    if unsent:
        summary['status'], summary['alerts_pending'] = 'notify_failed', len(unsent)
    print(json.dumps(summary), file=out)
    return NOTIFY_FAILED if unsent else OK


def main(argv=None):
    p = argparse.ArgumentParser(prog='vuln_digest')
    p.add_argument('--state-in', type=Path, required=True)
    p.add_argument('--state-out', type=Path, required=True)
    p.add_argument('--no-notify', action='store_true', help='print the alert to stderr instead of Telegram')
    p.add_argument('--notify-min', default=os.environ.get('VULN_NOTIFY_MIN', NOTIFY_MIN),
                   choices=['critical', 'high', 'medium', 'low'])
    args = p.parse_args(argv)
    env = os.environ
    send = (lambda text: print(text, file=sys.stderr)) if args.no_notify else telegram(env)
    return run(args.state_in, args.state_out, lambda: live_findings(env), send, notify_min=args.notify_min)
