"""Findings from Dependabot alerts, repository exclusion and the parallel sweep (SPEC-001 scope, AC1–AC3)."""
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {'critical': 0, 'high': 1, 'medium': 2, 'low': 3}
WORKERS = 8


@dataclass(frozen=True)
class Finding:
    rule: str
    severity: str
    repo: str
    id: str
    subject: str  # display text only: it may change (a fix version appears) without reopening the finding

    def as_dict(self):
        return asdict(self)


def _severity(alert):
    s = ((alert.get('security_advisory') or {}).get('severity')
         or (alert.get('security_vulnerability') or {}).get('severity') or 'medium').lower()
    return s if s in SEVERITY_ORDER else 'medium'


def findings_for(repo, alerts):
    if alerts is None:
        return [Finding('alerts-disabled', 'medium', repo, f'alerts-disabled:{repo}', 'Dependabot alerts are off')]
    out = []
    for a in alerts:
        vuln = a.get('security_vulnerability') or {}
        pkg = vuln.get('package') or {}
        fix = (vuln.get('first_patched_version') or {}).get('identifier')
        ghsa = (a.get('security_advisory') or {}).get('ghsa_id', '')
        subject = f'{pkg.get("name", "?")} ({pkg.get("ecosystem", "?")}) {ghsa}' + (f' fix {fix}' if fix else ' no fix')
        out.append(Finding('dependabot', _severity(a), repo, f'dependabot:{repo}#{a["number"]}', subject))
    return out


def excluded(full_name, patterns):
    name = full_name.lower()
    owner = name.split('/', 1)[0]
    for p in patterns:
        p = p.strip().lower()
        if p and (p == name or p == f'{owner}/*'):
            return True
    return False


def sweep(repos, alerts_fn, exclude, workers=WORKERS):
    """(findings, scanned repositories). One failing repository fails the whole sweep (R4)."""
    todo = {}
    for token, r in repos:
        name = r['full_name']
        if r.get('archived') or r.get('fork') or excluded(name, exclude) or name in todo:
            continue
        todo[name] = token
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda item: findings_for(item[0], alerts_fn(item[1], item[0])), todo.items()))
    return [f for found in results for f in found], len(todo)
