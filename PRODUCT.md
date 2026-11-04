# Product

<!-- impeccable:product-schema 1 -->

## Platform

scheduled job (GitHub Actions, daily, dispatched by the jobs Worker), standard-library Python

## Users

- The owner, who gets a Telegram message only when a Dependabot alert opens or resolves.

## Product Purpose

Keep known-vulnerable dependencies in deployed but untouched repositories from going unnoticed:
read the open Dependabot alerts of every own repository, diff with the previous run and report
only the change. Success: every new critical, high or medium alert reaches Telegram within a day,
and nothing is reported when nothing changed. Requirements: [SPEC-001](docs/specs/001-vuln-digest.md).

## Positioning

The continuous half of dependency scanning. The shared `security.yml` (OSV-Scanner, Trivy) checks
code when it changes; this checks code that has not changed against new advisories. Read-only.

## Operating Context

- `.github/workflows/digest.yml` on a GitHub-hosted runner; public log prints counts only.
- Credentials in Infisical `/vuln-digest`, mirrored to Actions secrets.
- CI: shared `ci-python` and the shared security workflow.

Sentry waiver: a failed or missed run already alerts through the uptime Worker heartbeat `vuln-digest` (30 h) and Telegram; the job is standard-library only and its log is public by design, so it ships no error reporter or extra secret.
