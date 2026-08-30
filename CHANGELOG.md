# Changelog — dotmac-deployment-control

All notable changes to the `dotmac-deployment-control` distribution. This package
follows [Semantic Versioning](https://semver.org). Pre-1.0 (`0.x`, incl. this
alpha) the surface is still settling — a `0.MINOR` bump may carry breaking
changes, each called out here.

## 0.1.0a4 — RELEASED 2026-08-30, independently verified

Supersedes `0.1.0a3`. No source change from a3: the module's code is identical,
and the bump exists because a3 can never be pinned.

### Changed

- Nothing in the package. `0.1.0a3` was published by a release run cancelled
  during its own verification, so the upload succeeded while the read-back,
  consumer proof and tag never ran. Both a3 artifacts were later confirmed
  byte-correct out of band — the BYTES are sound and the EVIDENCE CHAIN is not.
  An index cannot un-publish, so a3 remains on it permanently, recorded
  UNPROVABLE and never pinnable, and a4 carries the same code with a complete
  chain behind it.

### Released

- Published by release run `33297423568` from peeled commit
  `2c61540f74018b7e19d7c5add893e0653cfcdb17`, and **independently** verified by
  run `33310594187`: both artifacts fetched from the index by name and
  sha256-equal to the release build (wheel
  `ad1aaaa2d20b9a565d0656f64762564f4dfd90eb4c367187aa63fdd54a33c37e`, sdist
  `a5dae85d76e17ab34b1868741def46aab514ffba119110ec750794f5dc1c6e2c`),
  provenance closed on that commit, publisher read-back, read-only consumer
  install, and exactly one wheel and one sdist on the index.

  The tag was written earlier, by a job in the release run that called itself a
  verification and compared the wheel only. That defect is recorded in
  `docs/CONTROL_EXCEPTIONS.md` and structurally removed: a publishing run can no
  longer tag, and only `verify-release.yml` may.

## 0.1.0a3 — PUBLISHED, UNPROVABLE, NEVER PIN

**Published and unusable.** It was declared a3 rather than a2 because the package
source changed after a2 was published, and a version that names two different
contents is the hazard, not the bump. a2's artifact in the index is untouched
and stays the authoritative a2 forever.

### Fixed

- `record_observation` imported `conflict_savepoint` from `dotmac_kernel.db` —
  the reference assembly's CONFIGURED instance, which builds a
  `DatabaseRuntime` at module import time. Every operation in this package
  takes a caller-owned `Session` and opens nothing, so importing the module
  that makes a connection was a boundary violation whether or not the runtime
  was ever used. It now imports the engine-free `dotmac_kernel.transactions`,
  which re-exports the same function and constructs nothing.

  The import was also LAZY, inside the handler, which is how the violation
  stayed invisible: absent from the file's imports, absent when the package was
  imported, and surfacing only as `ArgumentError: Could not parse SQLAlchemy
  URL` deep inside SQLAlchemy when an observation was finally admitted. It is
  now a module-level import, so the boundary is a fact static analysis can
  read.

  A consumer sees one behavioural difference: admitting an observation no
  longer causes the assembly's database runtime to be constructed as a side
  effect.

## 0.1.0a2 — 2026-08-21

Published, installed back from the private index, conformance-checked and
tagged from exact protected-main revision `5c87272a` by release run
`32471956734`. Publication is supply-chain evidence only; it composes no product
and moves no authority.

### Fixed

- A genuinely concurrent first observation now establishes exactly one
  canonical receipt. The receipt insert runs inside a savepoint; the losing
  transaction retains its append-only attempt, points it at the winner, and
  returns the winner's original verdict as a replay or conflict instead of
  leaking the unique-constraint error.
- The PostgreSQL rehearsal now gates both workers after their first production
  receipt lookup has returned empty. This makes the race deterministic and
  covers identical and divergent arrivals rather than relying on thread-start
  timing.
- The README now uses the dossier's authoritative
  `greenfield-after-inventory` source mode. The receipt half has a historical
  tested reference, but it was never production-used and therefore does not
  qualify as product-first extraction under rule 24.

## 0.1.0a1 — 2026-08-19

First release, under ADR-0057 § 3. **Split historical evidence**, recorded as
`source_mode = "greenfield-after-inventory"`: the receipt half ports the
never-merged and never-deployed Vendor V6 admission design as a tested
reference, while the plan/rollout half is greenfield with the absence evidenced.

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
