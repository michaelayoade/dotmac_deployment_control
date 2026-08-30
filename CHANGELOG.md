# Changelog — dotmac-deployment-control

All notable changes to the `dotmac-deployment-control` distribution. This package
follows [Semantic Versioning](https://semver.org). Pre-1.0 (`0.x`, incl. this
alpha) the surface is still settling — a `0.MINOR` bump may carry breaking
changes, each called out here.

## 0.1.0a5 — UNRELEASED

Supersedes `0.1.0a4` for FUNCTIONAL reasons. a4's identity proofs stand and are
not withdrawn: it is immutable, independently verified, and **unadoptable**
(Michael's ruling, 2026-08-30). Platform CP pins a5, never a4.

### Fixed

- **`approve_plan` no longer reports an encoding difference as a plan
  mutation.** This is the defect a5 exists for. `snapshot_digest` returned bare
  hex, `spec_digest` returned the `sha256:`-prefixed form, `propose_plan` stored
  the bare one, and `approve_plan` compared the two as STRINGS — so a caller
  supplying the plan's own digest in the other encoding was refused with *"the
  plan changed after approval, so a new approval is required"*.

  A security refusal standing in for a formatting bug is the worst available
  failure shape: it looks exactly like the system working, and the operator
  re-runs an approval that was never stale.

- **`__version__` is derived from the installed distribution's metadata.** The
  published a4 wheel carries `__version__ = "0.1.0a2"` while declaring
  `0.1.0a4`, so an authorization would have recorded the wrong version of the
  deciding module. Two literals for one fact is the root cause; one is deleted
  rather than a third check added. A source tree with no install reports
  `0.0.0+not-installed`, a shape `release_guard` refuses, rather than guessing.

### Added

- **`dotmac_deployment_control.digests` — Control-owned `PlanDigestV1`.** An
  ALGORITHM and its digest BYTES, not a string. Canonical serialization
  `sha256:<64 lowercase hex>`. Equality is over the bytes, so no encoding can
  change it, and nothing on the authorization path compares digest text —
  `tests/architecture/test_digest_comparison_is_typed.py` parses the package and
  fails the build if it comes back.

  `SpecDigestV1` is a separate type for the observation path. Same algorithm and
  encoding, different subject, and the values compare unequal across types — so
  a spec digest can never satisfy a plan-digest binding by arriving in the right
  shape.

  Malformed, uppercase, wrong-length and unknown-algorithm values are refused,
  each naming what is wrong: those have genuinely different repairs.

- **`DigestEncodingError`, and it is deliberately NOT an
  `ApprovalRefusedError`.** "I cannot read the value you sent" and "the plan you
  approved is not the plan you are approving" are different findings, for
  different readers, with different repairs. Both remain catchable as
  `DeploymentControlError`.

- **a4's bare-hex form is accepted, in ONE named place, inside Control.**
  `PlanDigestV1.parse_a4_bare_hex` / `parse_accepting_a4_bare_hex` — named for
  the version they exist for, so the compatibility carries an expiry
  conversation rather than becoming the format. **Consumers must not normalize
  a Control digest.** A second implementation of this parser will disagree
  eventually, and the disagreement arrives as a false "the plan changed".

- **`scripts/artifact_canaries.py` — seven behavioural canaries that execute the
  INSTALLED wheel**, never a source checkout. Its first canary refuses to
  continue unless the module it imported came out of the environment's
  `site-packages`; without that the rest would be a slower copy of the unit
  tests wearing a stronger claim, which is precisely how a4 shipped a stale
  `__version__`. Run pre-merge in `ci.yml` against a wheel built from the pull
  request, and post-publication in `verify-release.yml` against the wheel the
  registry served.

- **Property 7 of the release verdict: "the installed distribution behaves as
  published".** a4 passed all six identity properties and was unadoptable; the
  seventh is what stops that combination reaching a tag. A failing canary is
  UNPROVABLE and therefore untagged.

### Changed

- `mod_deploy.deployment_plans.plan_digest` widened `VARCHAR(64)` ->
  `VARCHAR(128)` by `dc_0002_canonical_plan_digest`. 64 was exactly the width of
  bare hex, which is a fair summary of why a4 stored bare hex: the column could
  not hold a value that said which algorithm produced it. Metadata-only in
  PostgreSQL; existing rows are deliberately NOT rewritten, because rewriting
  them would be a migration silently restating other people's frozen approval
  bindings.
- `snapshot_digest` now returns the canonical `sha256:`-prefixed form. Its
  bare-hex return is the a4 behaviour and is gone. `spec_digest` is unchanged.
  `plan_digest_of` and `spec_digest_of` are the new typed accessors.
- `0.1.0a4` is recorded `pinnable: false` and refused BY NAME by
  `scripts/release_guard.py`, distinctly from the floor. Its original PASS
  record is untouched and the superseding disposition is APPENDED beside it —
  both facts are true and the pair is the useful evidence.

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
