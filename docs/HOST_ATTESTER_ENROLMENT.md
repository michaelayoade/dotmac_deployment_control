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
and for any host; this module exposes no operation that clears either
status. See the module docstring's "The incarnation IS the attester-key
fingerprint" and "What makes an old incarnation unusable" sections for the
full reasoning, including the two alternatives considered (a Fleet
provisioning epoch; a host-derived value like machine-id) and why each was
set aside.

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
2. Whether Fleet's `host_id` slug alphabet (this module currently validates
   a DNS-label shape: lowercase alphanumerics and hyphens, 1-63 characters)
   is a closed grammar Control validates against, or an open string Control
   merely bounds in length.
3. Whether a future Fleet provisioning epoch becomes a third bound term in
   that grammar or stays Fleet-internal metadata this contract never sees.

These need a decision from whoever holds authority over both the Control and
Foundation repositories (and Fleet, if question 2 is answered "closed
grammar"); this slice does not resolve them and does not need to.

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
- `test_evidence_signed_by_the_old_key_is_refused_after_rebuild`: the
  rotation property. Proves the identical statement shape is admitted BEFORE
  a rotation (near-miss, silent), then proves the exact same old fingerprint
  is refused with `FINGERPRINT_SUPERSEDED` AFTER the rotation (plant, named)
  — isolating the cause to the rotation rather than an unrelated invariant.
- `test_two_hosts_cannot_share_an_incarnation` /
  `test_two_enrolments_of_the_same_host_cannot_share_a_fingerprint`: the two
  requested uniqueness proofs, with distinct codes
  (`FINGERPRINT_REUSED_ACROSS_HOSTS` vs `FINGERPRINT_ALREADY_ENROLLED`).
- `test_a_revoked_fingerprint_is_refused_with_its_own_distinct_code`: proves
  `REVOKED` and `SUPERSEDED` are not merged behind one code.
- `test_revocation_cannot_reclaim_a_spent_marker` /
  `test_registry_disagreement_is_refused_not_trusted`: the finality
  properties, including that a registry disagreement is refused rather than
  trusted.

## Not wired into the package's public surface

`src/dotmac_deployment_control/__init__.py` does not re-export this module's
symbols. That file aggregates the whole package's public surface and is not
part of this task's owned scope; wiring the export is left open rather than
guessed at.
