# ADR-0001 Dependabot alerts read through a GitHub App

Status: accepted, 2026-11-04

## Context

OSV-Scanner and Trivy already run in the shared CI on every push and pull request, but most
repositories are rarely pushed. Continuous scanning needs either our own scheduled scanner (clone
~330 repositories daily and run OSV-Scanner) or GitHub's Dependabot alerts, which GitHub
re-evaluates whenever an advisory is published. The repositories span the personal account and
11 organizations; a fine-grained token covers only one owner, and the existing classic tokens
carry far more than read access.

## Decision

Turn on Dependabot alerts (not security-update pull requests) on every own repository, and read
them with a dedicated GitHub App holding only `Dependabot alerts: read` and `Metadata: read`,
installed on each owner. The job is the posture-monitor pattern: diff with R2 state, Telegram on
change, heartbeat.

## Consequences

- No clone or scan cost; detection follows GitHub's advisory database within hours.
- One credential with the narrowest permission, usable across all owners.
- Repositories added later need alerts turned on; the digest reports them as `alerts-disabled`.
- GitHub also emails the owner about new alerts (notification settings).
- Fix pull requests stay out of scope until Renovate is installed (owner).
