"""State diff, the Telegram message and the counts-only public summary (SPEC-001 R2, R3, R7)."""
import json
from collections import defaultdict

from .checks import SEVERITY_ORDER

ICON = {'critical': '🟣', 'high': '🔴', 'medium': '🟠', 'low': '⚪'}
NOTIFY_MIN = 'medium'
MAX_LINES = 45
MAX_CHARS = 4000  # Telegram rejects messages over 4096 characters
MAX_PENDING = 5
BASELINE_TOP = 10


def load_state(text):
    """Previous findings by id, or None when there is no state yet (first run)."""
    if not text.strip():
        return None
    return {f['id']: f for f in json.loads(text)['findings']}


def load_pending(text):
    return [bound(m) for m in json.loads(text).get('pending_messages', [])] if text.strip() else []


def bound(text):
    return text if len(text) <= MAX_CHARS else text[:MAX_CHARS - 12] + '\n… (cut)'


def dump_state(findings, pending_messages=()):
    data = {'version': 1, 'findings': [f.as_dict() for f in findings]}
    pending = [bound(m) for m in pending_messages]
    if len(pending) > MAX_PENDING:
        dropped = len(pending) - (MAX_PENDING - 1)
        pending = [f'Vuln digest: {dropped} older undelivered alerts were dropped.'] + pending[-(MAX_PENDING - 1):]
    if pending:
        data['pending_messages'] = pending
    return json.dumps(data, indent=1) + '\n'


def diff(previous, current):
    current_ids = {f.id for f in current}
    opened = [f for f in current if f.id not in previous]
    resolved = [f for i, f in previous.items() if i not in current_ids]
    return opened, resolved


def _rank(f):
    return SEVERITY_ORDER.get(f['severity'] if isinstance(f, dict) else f.severity, 9)


def _counts(findings):
    counts = {s: 0 for s in SEVERITY_ORDER}
    disabled = 0
    for f in findings:
        if f.rule == 'alerts-disabled':
            disabled += 1
        else:
            counts[f.severity] += 1
    return counts, disabled


def _head(title, current):
    c, disabled = _counts(current)
    off = f', alerts off in {disabled} repos' if disabled else ''
    return f'{title} (open: {c["critical"]} critical, {c["high"]} high, {c["medium"]} medium, {c["low"]} low{off})'


def _grouped(items, icon):
    by_repo = defaultdict(list)
    for f in items:
        f = f if isinstance(f, dict) else f.as_dict()
        by_repo[f['repo']].append(f)
    lines = []
    for repo in sorted(by_repo, key=lambda r: (min(_rank(f) for f in by_repo[r]), r)):
        lines.append(repo)
        lines += [f'  {icon(f)} {f["subject"]}' for f in sorted(by_repo[repo], key=lambda f: (_rank(f), f['id']))]
    return lines


def _finish(lines):
    if len(lines) > MAX_LINES:
        lines = lines[:MAX_LINES] + [f'… and {len(lines) - MAX_LINES} more lines']
    return bound('\n'.join(lines))


def message(opened, resolved, current, first_run, notify_min=NOTIFY_MIN):
    limit = SEVERITY_ORDER[notify_min]
    if first_run:
        worst = defaultdict(lambda: [0, 0])
        for f in current:
            if f.rule == 'dependabot' and f.severity in ('critical', 'high'):
                worst[f.repo][SEVERITY_ORDER[f.severity]] += 1
        lines = [_head('Vuln digest baseline', current)]
        if worst:
            lines.append('\nMost critical/high:')
            top = sorted(worst.items(), key=lambda kv: (-kv[1][0], -kv[1][1], kv[0]))[:BASELINE_TOP]
            lines += [f'{ICON["critical"]}{c} {ICON["high"]}{h} {repo}' for repo, (c, h) in top]
        return _finish(lines)
    opened = [f for f in opened if _rank(f) <= limit]
    resolved = [f for f in resolved if _rank(f) <= limit]
    if not opened and not resolved:
        return None
    lines = [_head('Vuln digest: changes', current)]
    if opened:
        lines.append('\nOpened:')
        lines += _grouped(opened, lambda f: ICON[f['severity']])
    if resolved:
        lines.append('\nResolved:')
        lines += _grouped(resolved, lambda f: '✅')
    return _finish(lines)


def public_summary(current, opened, resolved, scanned):
    counts, disabled = _counts(current)
    return json.dumps({**counts, 'alerts_disabled': disabled, 'opened': opened, 'resolved': resolved,
                       'repos_scanned': scanned})

