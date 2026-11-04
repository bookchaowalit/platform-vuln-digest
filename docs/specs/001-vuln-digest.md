---
title: "SPEC-001 Dependency vulnerability digest"
status: accepted
created: 2026-11-04
updated: 2026-11-04
description: Daily read-only sweep of GitHub Dependabot alerts across every own repository that alerts only on changes.
---

# SPEC-001 Dependency vulnerability digest

## Problem

The shared `security.yml` (platform-ci-workflows) runs OSV-Scanner and Trivy, but only on a
push or a pull request. Most of the ~340 own repositories are rarely touched, so a CVE
published after their last push is never seen. GitHub Dependabot alerts were off on every
repository checked on 2026-11-04, and Renovate is not installed. Nothing watches the
dependencies of code that is already deployed.

Owner decision 2026-11-04: turn on Dependabot alerts (not security-update PRs) on the own
repositories and build a digest that reports changes, in the posture-monitor pattern.

## Outcome

Once a day a job reads the open Dependabot alerts of every repository the digest's GitHub App
can see, compares them with the previous run and sends one Telegram message only when an
alert opens or resolves, or a repository has alerts turned off. A missed run alerts through
the uptime Worker heartbeat `vuln-digest`.

## Scope (v1)

| Finding | Severity | Fires when |
|---|---|---|
| `dependabot` | the advisory's (`critical`, `high`, `medium`, `low`) | an open Dependabot alert; id `dependabot:<owner>/<repo>#<number>` |
| `alerts-disabled` | medium | the alerts API answers that Dependabot alerts are disabled for the repository |

Repositories that are archived, forks, or match the `VULN_EXCLUDE` list (client and
hands-off repositories; kept in a secret so the public repository names no client) are skipped.

Out of scope for v1: opening or merging fix PRs (Renovate, an owner action), code scanning and
secret scanning alerts, an audit event per change (`security-api`, as posture-monitor does).

## Requirements

- **R1 Read-only.** The GitHub App holds only `Dependabot alerts: read` and `Metadata: read`.
  The job never changes a repository. Its other credentials are R2 object access to one
  bucket (`vuln-digest`), Telegram and the heartbeat token.
- **R2 Public log stays quiet.** The repository is public and many scanned repositories are
  private, so the job log and step summary print only counts per severity and the exit
  status, never a repository, package or advisory. Details go only to Telegram.
- **R3 Alert on change.** The message lists opened findings at or above the notify level
  (`medium` by default; lower ones are counted only), grouped by repository, highest
  severity first, and resolved ones at the same levels. No message when nothing changed. The
  first run (no state) sends one baseline message with counts and the repositories with the
  most critical and high alerts, not every alert.
- **R4 Fail loudly.** If listing installations, repositories or any repository's alerts
  fails (other than the "disabled" answer), the run exits 2, writes no state (a partial
  sweep must not resolve alerts) and the heartbeat reports `ok: false`. A missed run alerts
  after 30 hours.
- **R5 Bounded.** Each API call has a 20 s timeout and alert pages hold 100 alerts; requests
  run in parallel (8 workers). A run finishes within 5 minutes for 400 repositories.
- **R6 No third-party runtime dependencies.** Standard library only; the App JWT is signed
  with the `openssl` binary, as posture-monitor signs its client assertion.
- **R7 Undelivered alerts are kept.** A message Telegram refused stays in the state and is
  sent first next run; the run exits 3.

## Acceptance criteria

- AC1 Given open alerts for a repository, one finding per alert is produced with the
  advisory's severity; a dismissed or fixed alert (not in the open list) produces none.
- AC2 A "Dependabot alerts are disabled" answer produces one `alerts-disabled` finding; any
  other error fails the run (exit 2) and leaves the state untouched.
- AC3 Archived repositories, forks and `VULN_EXCLUDE` matches (`owner/*` or `owner/repo`)
  are never queried.
- AC4 Diffing previous and current findings yields exactly the opened and resolved sets; an
  unchanged set yields no message; opened `low` alerts alone yield no message.
- AC5 Pagination follows the `Link: rel="next"` header until it ends.
- AC6 The public summary contains no repository, package or advisory name.

## Later

- Weekly reminder of critical and high alerts older than 14 days.
- `security-api` audit events per change.
- Renovate (owner installs the app) to open the fix PRs this digest only reports.
