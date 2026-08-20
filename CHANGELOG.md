# Changelog — dotmac-deployment-control

All notable changes to the `dotmac-deployment-control` distribution. This package
follows [Semantic Versioning](https://semver.org). Pre-1.0 (`0.x`, incl. this
alpha) the surface is still settling — a `0.MINOR` bump may carry breaking
changes, each called out here.

## 0.1.0a1 — 2026-08-19

First release, under ADR-0033 § 3. **Split provenance**, recorded as
`source_mode = "historical-mixed"`: the receipt half ports the never-merged
Vendor V6 admission design, the plan/rollout half is greenfield with the absence
evidenced.

### Added

- `mod_deploy` — `deployment_targets`, `target_credentials`, `deployment_plans`,
  `rollouts`, `rollout_attempts`, `observation_receipts`, `observation_attempts`
  on the platform plane. Lineage root `dc_0001_deployment_control`, which verifies
  `idempotency_ledger.v1` and `platform_audit_log.v1` before any DDL of its own.
- Versioned desired state, immutable digest-bearing plan snapshots, and
  approval evidence bound to the plan digest (ADR-0026 § 2's binding, applied
  where the blast radius is other people's running systems).
- Rollouts with one in-flight attempt at a time, a provider-neutral
  `DeliveryIntent` return, and the full outcome vocabulary including `TIMED_OUT`
  and `MANUAL_REPAIR` as states distinct from `FAILED` and `CANCELLED`.
- Observation admission: every arrival written as an append-only attempt, only
  valid-and-eligible-and-matching arrivals admitted, replays returning the
  original verdict verbatim, and the proven identity kept in a different column
  from the reported claim under two CHECK constraints.
- Drift computed on demand against the plan that was actually **rolled out** —
  never against the current desired state, which would make every desired-state
  edit look like fleet-wide drift.

### Ported from the V6 reference

- The attempt/receipt pair, and the reasoning for it: a single table keyed on
  `(identity, report_id)` cannot store the second arrival, which is the row worth
  keeping.
- The claim/proof separation, and the two CHECK constraints that make it
  structural rather than conventional.
- The stable-verdict rule: a replay returns the original decision rather than
  recomputing, so an at-least-once transport cannot look like a state change.
- Credential eligibility as a half-open window evaluated against the stored
  timestamps, so a report that arrived while a credential was live stays
  evaluable after it is rotated out.
- Enrollment to `PENDING`, never straight to `ACTIVE`.
- The fingerprint over DECODED key bytes, never the base64 text.

### Deliberately NOT included

- **Any provider client, HTTP library or transport.** The Integrator's
  (ADR-0024, hard rule 28).
- **Any signature verification.** `dotmac_kernel.licensing` owns it (ADR-0007);
  a second verifier could disagree with the first.
- **Any health status.** Ruling A4 keeps health separate from fleet.
- **Any private key or provider credential.** `target_credentials` holds a
  deployment's own PUBLIC verification key and nothing else.
