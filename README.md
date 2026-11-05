# platform-vuln-digest

Daily digest of GitHub **Dependabot alerts** across every own `bookchaowalit` repository. It reads
the open alerts, diffs them with the previous run and sends one Telegram message only when an
alert opens or resolves, or a repository has alerts turned off. Requirements:
[SPEC-001](docs/specs/001-vuln-digest.md).

It complements the shared `security.yml` in
[platform-ci-workflows](https://github.com/bookchaowalit/platform-ci-workflows) (OSV-Scanner and
Trivy on every push and pull request): those catch a vulnerable dependency when code changes;
this catches a new advisory for code that has not changed.

## What it reports

| Finding | Severity | Fires when |
|---|---|---|
| `dependabot` | the advisory's | an open Dependabot alert |
| `alerts-disabled` | medium | Dependabot alerts are turned off for the repository |

Telegram lists opened and resolved findings at `medium` and above (`--notify-min` /
`VULN_NOTIFY_MIN`), grouped by repository; `low` is counted only. The first run sends a baseline
with counts and the repositories with the most critical and high alerts.

## How it runs

- `.github/workflows/digest.yml`, dispatched daily at 01:17 UTC (08:17 Bangkok) by the jobs Worker
  job `vuln-digest` (platform-jobs-worker, ADR-0008). The repository is public, so the log prints
  only counts; state is the private R2 object `vuln-digest/state.json`.
- A failed or missed run alerts through the uptime Worker heartbeat `vuln-digest` (30 h).
- Credentials (Infisical `/vuln-digest`, mirrored to Actions secrets): the GitHub App
  `bookchaowalit-vuln-digest` (Dependabot alerts read, Metadata read), R2 keys for the one bucket,
  `TELEGRAM_*` (book_noti_bot), `HEARTBEAT_TOKEN`, `VULN_OWNERS` (the accounts whose
  installations are read; the App is public so it can be installed on organizations) and
  `VULN_EXCLUDE`, the comma list of `owner/*` or `owner/repo` that are never read (client and
  hands-off repositories). Both are secrets so this public repository names no client.

## Run locally

```bash
VULN_GITHUB_TOKEN="$(gh auth token)" VULN_EXCLUDE="..." python3 -m vuln_digest --no-notify \
  --state-in /tmp/none.json --state-out /tmp/state.json
```

With a personal token it reads the repositories you own or reach through an organization.

## Develop

Standard library only (Python 3.13). Tests: `python -m unittest discover -s tests -t .`;
lint: `ruff check .`.

## Setup (once)

1. `python3 scripts/create_app.py` (owner): creates the App with the manifest flow and stores
   its id and key without printing them.
2. Install the App on each account in `VULN_OWNERS`, "All repositories".
3. Run the workflow once by hand (`gh workflow run digest.yml`); the first run sends the baseline.
