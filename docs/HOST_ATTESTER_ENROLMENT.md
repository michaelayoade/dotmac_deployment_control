# Host-attester enrolment and rotation

Source of truth: `src/dotmac_deployment_control/host_attester_enrolment.py`.
This document summarizes the design and states what is settled versus what
still needs a decision; the module docstring is the authoritative text.

## What this is, and what it is not

The issuing-side contract for binding a Fleet `host_id` to a host attester's
incarnation, in support of Foundation's trusted-provenance verifier. It is
NOT that verifier and NOT a Platform caller — exactly as `recovery_grant.py`
and `rehearsal_grant.py` are libraries a verifier elsewhere calls, this
module is the same shape for the host-attestation half of the custody
ruling:

- **Candidate signer**: the protected Starter release workflow identity.
- **Host signer**: a separate attester identity per enrolled host
  incarnation.
- **Custody**: separate OpenBao principals and policies; neither key usable
  by the other party. This module stores an approved `bao://` path pointer
  and a public-key fingerprint — never a key, never a secret value.

## What makes an old incarnation unusable

**The event: a host rebuild revokes its old attester key and enrols a new
one for the same `host_id`.** The enforcement is that the incarnation IS the
attester-key fingerprint — there is no separate `incarnation_id` counter for
a rebuild to leave behind unincremented. `evaluate_enrolment` refuses any
fingerprint whose registry status is `REVOKED` or `SUPERSEDED`, permanently
and for any host; no *function* in this module performs or requests that
reversal (a caller's OWN registry can of course still be written to
directly — `FingerprintRecord` is a plain exported dataclass, and nothing
stops a caller from constructing `FingerprintRecord(host, ACTIVE)` in its
own storage; the guarantee is only about what this module's functions do).
See the module docstring's "The incarnation IS the attester-key fingerprint"
and "What makes an old incarnation unusable" sections for the full
reasoning, including the two alternatives considered (a Fleet provisioning
epoch; a host-derived value like machine-id) and why each was set aside.

**Two integrity checks make this hold under adversarial or buggy input, not
just the happy path** (added after independent review found both gaps):
`evaluate_enrolment` judges the PRESENTED fingerprint's own global status
before it judges the target host's local binding, so a revoked or
superseded fingerprint is named precisely (`FINGERPRINT_REVOKED` /
`FINGERPRINT_SUPERSEDED`) even when presented to a host that separately
already has an active attester — see "Evaluation order" in the module
docstring. And a rotation's `supersedes_fingerprint` is independently
cross-checked against `known_fingerprints` (present, `ACTIVE`, and
recorded against the SAME host) rather than trusted from `active_by_host`
alone — otherwise a rotation for host B naming a fingerprint
`active_by_host` (wrongly, or adversarially) claims is B's could retire
host A's real attester permanently. See "The serious one" in the review
history below.

## MEASURED vs INFERRED

MEASURED (read directly from the Fleet registry, 2026-09-08): `host_id` is
canonical, unique across 26 hosts, zero stale/conflicted values; it is a
manually assigned slug (`db-primary`, `control-runner`, `ns1`), not derived
from provider state; the provider reference changes on reprovisioning while
`host_id` does not; there is no incarnation, generation, provisioning epoch
or enrolment instance anywhere in Fleet; `last_verified_at` exists and
nothing records provisioning time.

INFERRED / DESIGN DECISION (this slice, not measured from Fleet): that the
attester-key fingerprint is the right incarnation value. The brief's
reasoning is evaluated and adopted in the module docstring, not merely
accepted — the self-enforcement property and the one-value-not-two argument
are both stated as the reasons, and the rejected alternatives are recorded
so a later reviewer does not re-litigate them without seeing why they were
set aside.

## Does Fleet need a new field?

No, not for this slice to be enforceable. The fingerprint-as-incarnation
design needs nothing from Fleet beyond the existing `host_id` slug. A future
Fleet provisioning epoch, if built, would be a second independent signal —
not a replacement for this binding and not a prerequisite for it.

## What must be decided before the URN grammar can freeze

1. Whether the wire form of an incarnation is the bare fingerprint text
   (`sha256:<hex>`, what this module produces today) or a composite
   `urn:dotmac:host:<host_id>:<fingerprint>`.
2. Whether a future Fleet provisioning epoch becomes a third bound term in
   that grammar or stays Fleet-internal metadata this contract never sees.

These need a decision from whoever holds authority over both the Control and
Foundation repositories; this slice does not resolve them and does not need
to.

**Retired, not open:** whether Fleet's `host_id` slug alphabet is a closed
DNS-label grammar (`require_host_id`'s current behaviour) or an open string
this module should only bound in length. An independent review checked
`require_host_id`'s grammar against all 26 Fleet hosts and every one
matches — the closed grammar is safe to freeze. (It was validated against
only three example slugs when this module was first written; the earlier
version of this document listed this as open on that narrower basis, which
was too little evidence for the claim it was making.)

## No table added here

`evaluate_enrolment` and `host_attester_standing` take the fingerprint
registry (`active_by_host`, `known_fingerprints`) as caller-supplied
mappings — the same shape `recovery_grant.py`'s `revoked_grant_ids` and
`rehearsal_grant.py`'s `consumed_references` use, and for the same reason:
this package performs no I/O. `models.py` and the migration lineage are a
sibling lane's territory for this task. A genuine durable table for "the
currently active fingerprint per host_id" is real, and will eventually be
needed on the same shape as `TargetCredential`'s
`uq_target_credentials_fingerprint` unique constraint — but adding it here
would be schema work racing the sibling lane rather than sequenced with it.
**This is reported rather than silently deferred: persistence for host
attester enrolment is UNMONITORED until a coordinated migration lands.**

## The cut-off rule

Whichever of consumption or revocation commits first wins permanently, and a
later revocation cannot reclaim a spent marker. This module makes that
expressible by keeping the fingerprint status vocabulary monotone
(`ACTIVE -> SUPERSEDED` or `ACTIVE -> REVOKED`, no operation moves a
fingerprint back) — but the actual atomicity of two writers racing against
one durable row is the holder-of-the-store's problem, most likely the Kernel
idempotency ledger for the consumption half. This module does not resolve
that race and says so plainly rather than implying coverage it does not
have.

## What is proven, and how

`tests/unit/test_host_attester_enrolment.py`:

- Non-vacuity: a real initial enrolment and a real rotation are admitted.
- Every refusal path asserts both `HostAttesterEnrolmentRefusedError` (a
  `DeploymentControlError`) and a specific, distinct
  `HostAttesterEnrolmentRefusalCode` — no condition is folded behind another
  condition's code.
- `test_a_superseded_fingerprint_is_refused_for_re_enrolment_and_standing`:
  the rotation property. Proves a legitimate, unrelated use of the
  fingerprint is admitted BEFORE a rotation (near-miss, silent), then proves
  the exact same old fingerprint is refused with `FINGERPRINT_SUPERSEDED`
  AFTER the rotation, both for re-enrolment and for a standing query (plant,
  named) — isolating the cause to that one branch of `evaluate_enrolment`
  rather than an unrelated invariant. (Renamed from an earlier
  "...evidence signed by the old key..." name that overstated what this
  module checks: it has no signature-evidence verification path of its own.)
- `test_two_hosts_cannot_share_an_incarnation` /
  `test_a_superseded_fingerprint_is_also_refused_across_hosts` /
  `test_two_enrolments_of_the_same_host_cannot_share_a_fingerprint`: the
  requested uniqueness proofs, with distinct codes
  (`FINGERPRINT_REUSED_ACROSS_HOSTS` for the cross-host case regardless of
  whether the existing record is `ACTIVE` or `SUPERSEDED`, vs
  `FINGERPRINT_ALREADY_ENROLLED` for the same-host case). The same-host case
  is reachable only because the fingerprint's own status is judged BEFORE
  the host's binding — see "Evaluation order" below.
- `test_a_revoked_fingerprint_is_reported_before_the_host_block`: the
  ordering property directly. A `REVOKED` fingerprint presented to an
  ALREADY-enrolled host reports `FINGERPRINT_REVOKED`, never
  `HOST_ALREADY_ENROLLED` — which would be true but silent about the more
  urgent fact.
- `test_a_rotation_cannot_retire_another_hosts_key`: THE serious property
  from review. `active_by_host` alone is never trusted for the most
  destructive operation this module can request; a rotation whose
  `supersedes_fingerprint` is independently recorded, by
  `known_fingerprints`, as a DIFFERENT host's active attester is refused
  with `SUPERSEDES_FINGERPRINT_WRONG_HOST`, with a same-shape legitimate
  rotation kept silent as the near-miss.
  `test_supersedes_fingerprint_unknown_is_refused` /
  `test_supersedes_fingerprint_not_active_is_refused` cover the same
  cross-check's other two arms, each with its own code.
- `test_a_revoked_fingerprint_is_refused_with_its_own_distinct_code`: proves
  `REVOKED` and `SUPERSEDED` are not merged behind one code.
- `test_revocation_cannot_reclaim_a_spent_marker` /
  `test_registry_disagreement_is_refused_not_trusted` /
  `test_a_fingerprint_active_for_this_host_with_no_active_by_host_entry` /
  `test_wrong_host_is_distinct_from_registry_disagreement`: the finality and
  standing-vocabulary properties — `WRONG_HOST`, `NOT_ACTIVE_FOR_HOST` and
  `REGISTRY_DISAGREEMENT` are three distinct `HostAttesterStanding` members
  for three different operator actions, not one composite condition.

## `evaluate_enrolment` requires a VERIFIED statement, by convention only

`evaluate_enrolment` takes `HostAttesterEnrolmentStatementV1` directly, not
a verified `HostAttesterEnrolmentV1` envelope — unlike
`recovery_grant.verify_recovery_grant` and
`rehearsal_grant.verify_rehearsal_grant`, which authenticate a signature and
apply the caller-supplied revocation/consumption set in the SAME call. That
split means every field `evaluate_enrolment` reads is caller-fabricable
unless the caller itself only ever passes it
`verify_host_attester_enrolment(...).statement`. This is now stated
explicitly in both functions' docstrings; it is a documented caller
obligation, not something the type system enforces.

## Not evaluated in this version: proof of possession

`FingerprintStatus` (`ACTIVE | SUPERSEDED | REVOKED`) is deliberately
smaller than the existing `TargetCredential`'s `CredentialStatus`
(`PENDING | ACTIVE | RETIRED | REVOKED`, `models.py:125-139`) —
`SUPERSEDED` is `RETIRED` renamed for this contract's vocabulary, but there
is no `PENDING`. `service.py:1755-1758` names what `PENDING` protects for
`TargetCredential`: proof of possession before a key is trusted, without
which anyone reaching the enrolment endpoint could enrol a key it does not
hold. This module's registry types carry no such state today. Reconciling
the two status vocabularies — and deciding whether host-attester enrolment
needs its own possession proof before the durable table lands — is left
open for whoever designs that table.

## No expiry window on the statement

`verify_host_attester_enrolment` carries no `at` parameter. An earlier
version accepted one and silently discarded it — worse than no parameter,
since an authority-shaped argument that does nothing reads as a check that
is performed. `HostAttesterEnrolmentStatementV1` has no `not_before`/
`expires_at` (unlike `RecoveryGrantStatementV1`/`RehearsalGrantStatementV1`)
because an attester key's validity is bounded by rotation, not by time; if
that changes, `at` is reintroduced bound to a real window, not restored as
a no-op.

## Not wired into the package's public surface

`src/dotmac_deployment_control/__init__.py` does not re-export this module's
symbols. That file aggregates the whole package's public surface and is not
part of this task's owned scope; wiring the export is left open rather than
guessed at.
