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
    """Alert counts per severity, plus the coverage gaps: repos with alerts off, owners without the App."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    gaps = {'alerts-disabled': 0, 'app-not-installed': 0}
    for f in findings:
        if f.rule in gaps:
            gaps[f.rule] += 1
        else:
            counts[f.severity] += 1
    return counts, gaps


def _head(title, current):
    c, gaps = _counts(current)
    off = f', alerts off in {gaps["alerts-disabled"]} repos' if gaps['alerts-disabled'] else ''
    off += f', App missing on {gaps["app-not-installed"]} owners' if gaps['app-not-installed'] else ''
    return f'{title} (open: {c["critical"]} critical, {c["high"]} high, {c["medium"]} medium, {c["low"]} low{off})'


def _grouped(items, icon):
    """Repo, then one line per distinct subject; the same advisory in several manifests shows once with ×n."""
    by_repo = defaultdict(list)
    for f in items:
        f = f if isinstance(f, dict) else f.as_dict()
        by_repo[f['repo']].append(f)
    lines = []
    for repo in sorted(by_repo, key=lambda r: (min(_rank(f) for f in by_repo[r]), r)):
        lines.append(repo)
        seen = {}
        for f in sorted(by_repo[repo], key=lambda f: (_rank(f), f['id'])):
            key = (icon(f), f['subject'])
            seen[key] = seen.get(key, 0) + 1
        lines += [f'  {i} {subject}' + (f' ×{n}' if n > 1 else '') for (i, subject), n in seen.items()]
    return lines


def _resolved_summary(resolved):
    """Fixed alerts need no action: one count line with the most common packages, not every alert.
    Coverage findings are not packages and get their own neutral line: a gap that is gone from this scan may
    have been fixed, or its repo archived or excluded, so it is not reported as fixed."""
    alerts = [f for f in resolved if f.get('rule', 'dependabot') == 'dependabot']
    lines = []
    if alerts:
        repos = {f['repo'] for f in alerts}
        packages = defaultdict(int)
        for f in alerts:
            packages[f['subject'].split(' ', 1)[0]] += 1
        top = sorted(packages.items(), key=lambda kv: (-kv[1], kv[0]))[:4]
        more = f' +{len(packages) - len(top)}' if len(packages) > len(top) else ''
        lines.append(f'✅ ปิดแล้ว {len(alerts)} รายการใน {len(repos)} repo: '
                     + ', '.join(f'{p} ×{n}' for p, n in top) + more)
    on = sorted({f['repo'] for f in resolved if f.get('rule') == 'alerts-disabled'})
    if on:
        lines.append(f'⚪ ไม่พบแล้วในรอบนี้ (alert ปิดอยู่) {len(on)} repo: ' + ', '.join(on[:5]) + (f' +{len(on) - 5}' if len(on) > 5 else ''))
    app = sorted({f['repo'] for f in resolved if f.get('rule') == 'app-not-installed'})
    if app:
        lines.append(f'⚪ ไม่พบแล้วในรอบนี้ (App ยังไม่ติดตั้ง) {len(app)} owner: ' + ', '.join(app[:5]))
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
    c, gaps = _counts(current)
    opened_by = defaultdict(int)
    for f in opened:
        opened_by[f.severity] += 1
    bits = [f'{ICON[sev]} {opened_by[sev]} {sev}' for sev in SEVERITY_ORDER if opened_by[sev]]
    title = '🛡️ Vuln · ' + (' · '.join(bits) + ' เปิดใหม่' if bits else 'ไม่มีรายการใหม่')
    if resolved:
        title += f' · ✅ {len(resolved)} ปิดแล้ว'
    still = f'คงเปิด: {c["critical"]} critical · {c["high"]} high · {c["medium"]} medium · {c["low"]} low'
    if gaps['alerts-disabled']:
        still += f' · ⚠️ alert ปิดอยู่ {gaps["alerts-disabled"]} repo'
    if gaps['app-not-installed']:
        still += f' · ⚠️ App ยังไม่ติดตั้ง {gaps["app-not-installed"]} owner'
    lines = [title, still]
    if opened:
        lines.append('\nเปิดใหม่')
        lines += _grouped(opened, lambda f: ICON[f['severity']])
    if resolved:
        lines += ['', *_resolved_summary([f if isinstance(f, dict) else f.as_dict() for f in resolved])]
    return _finish(lines)


def public_summary(current, opened, resolved, scanned):
    counts, gaps = _counts(current)
    return json.dumps({**counts, 'alerts_disabled': gaps['alerts-disabled'], 'app_not_installed': gaps['app-not-installed'],
                       'opened': opened, 'resolved': resolved, 'repos_scanned': scanned})

