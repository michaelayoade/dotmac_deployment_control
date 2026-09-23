"""Control's real issuance boundary for the rehearsal-issuer authorization
contract (`rehearsal_issuer_authorization.py`, C1) -- DB-backed, following the
exact "forbidden fields, caller cannot supply what's derived inside" pattern
`authorization_v3.issue_authorization_envelope_v3` already establishes, but
with a database behind it the way `service.request_rollout` has one and C1
itself deliberately does not.

## Why this module exists, and why it is not part of `service.py`

A prior CP-side design tried to derive A6.4 authorization values itself and
invented a same-process "harness witness" object -- empirically forgeable
(`dataclasses.replace()` on a legitimate binding produced a second, equally
"valid" witness; the "private" sentinel guarding it was importable from
outside the module that defined it). This module is the correction: Control
owns issuance, revocation, staged consumption and standing for ONE lease's
rehearsal-issuer authority, backed by a durable ledger
(`RehearsalIssuerAuthorizationRecord`, migration `dc_0014`) that is a SIBLING
of `RehearsalGrant` -- same lifecycle shape, different authority. See that
model's own docstring for why the two never share a table.

A SIBLING service module to `service.py`, not a function inside it: the
rehearsal issuer is a different authority than the rollout lifecycle
`service.py` owns, and the two must never share a table, a signer purpose, or
an audit/fact vocabulary entry. `AUDIT_ACTION_REHEARSAL_ISSUER` and
`facts.REHEARSAL_ISSUER_AUTHORIZATION_CHANGED_V1` are consumed here, not in
`service.py` -- the two architecture tests that check every declared
audit action and published fact has a real consumer scan BOTH files.

## Protected composition, not a per-call verifier parameter

`install_rehearsal_issuer_security` follows
`host_admission_coordinator.install_host_admission_security`'s exact
install-once shape: a second call raises, and there is no public function in
this module that accepts a verifier as a per-call parameter. A per-call
verifier would reopen the exact bypass class this whole correction exists to
close -- a caller could pass a permissive stub and the type would never know.

## What this module does NOT establish

No CP-side changes, no production activation, no real key material. No
widening of `AttestationCustodyDomain` (deliberately closed at two members).
Overrides are not supported: every `*_provenance` field this module builds is
`A6ProvenanceKind.DERIVED`.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from threading import Lock
from typing import Any, Final
from uuid import UUID, uuid4

from dotmac_kernel.messaging import process_once_platform
from dotmac_kernel.transactions import conflict_savepoint
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from dotmac_deployment_control import facts
from dotmac_deployment_control.authorization_v3 import _installed_control_version
from dotmac_deployment_control.digests import canonical_json
from dotmac_deployment_control.images import AuthorizedImage
from dotmac_deployment_control.models import (
    DeploymentPlan,
    DeploymentTarget,
    RehearsalIssuerAuthorizationRecord,
    RehearsalIssuerAuthorizationState,
    TargetStatus,
)
from dotmac_deployment_control.ports import DeploymentControlError
from dotmac_deployment_control.rehearsal_harness_evidence import (
    ParsedRehearsalHarnessEvidence,
    RehearsalHarnessEvidenceVerifier,
    parse_signed_rehearsal_harness_evidence,
    verify_rehearsal_harness_evidence_signature,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    _STATEMENT_KEYS as _C1_STATEMENT_KEYS,
)
from dotmac_deployment_control.rehearsal_issuer_authorization import (
    REHEARSAL_ONLY_ENVIRONMENT,
    A6ProvenanceKind,
    RehearsalIssuerAuthorizationRefusedError,
    RehearsalIssuerAuthorizationSigner,
    RehearsalIssuerAuthorizationStandingResult,
    RehearsalIssuerAuthorizationStatementV1,
    RehearsalIssuerAuthorizationSubject,
    RehearsalIssuerAuthorizationV1,
    RehearsalIssuerAuthorizationVerifier,
    issue_rehearsal_issuer_authorization,
    rehearsal_issuer_standing,
    verify_rehearsal_issuer_authorization,
)
from dotmac_deployment_control.service import (
    _audit_and_emit,
    _control_now,
    _load_plan_with_target_for_update,
    _standing_plan_terms,
    _StandingPlanTerms,
)

__all__ = [
    "AUDIT_ACTION_REHEARSAL_ISSUER",
    "REHEARSAL_ISSUER_ISSUANCE_COMMAND_TYPE",
    "RehearsalIssuerConsumptionStaged",
    "RehearsalIssuerIssuanceRefusalCode",
    "RehearsalIssuerIssuanceRefusedError",
    "install_rehearsal_issuer_security",
    "issue_rehearsal_issuer_authorization_for_plan",
    "rehearsal_issuer_standing_for",
    "revoke_rehearsal_issuer_authorization",
    "stage_rehearsal_issuer_consumption",
]

#: Split by subject, matching the manifest's other four -- see manifest.py's
#: "Five audit actions" section.
AUDIT_ACTION_REHEARSAL_ISSUER: Final[str] = "deployment.rehearsal_issuer.changed"
_ENTITY_REHEARSAL_ISSUER_AUTHORIZATION: Final[str] = "rehearsal_issuer_authorization"
REHEARSAL_ISSUER_ISSUANCE_COMMAND_TYPE: Final[str] = (
    "deployment.issue_rehearsal_issuer_authorization"
)

#: Every key C1's own signed statement carries, plus `schema`/`version` (the
#: latter are already members of `_STATEMENT_KEYS`, included again here so
#: this constant reads as complete on its own without requiring a reader to
#: already know that). IMPORTED rather than hand-copied: a hand-copy is
#: exactly the drift risk this correction exists to close, and
#: `test_forbidden_fields_matches_c1_statement_keys` proves the two cannot
#: silently diverge.
_FORBIDDEN_REQUEST_FIELDS: Final[frozenset[str]] = _C1_STATEMENT_KEYS | {
    "schema",
    "version",
}

#: The only keys a caller may supply to `issue_rehearsal_issuer_authorization_for_plan`.
_ALLOWED_REQUEST_FIELDS: Final[frozenset[str]] = frozenset(
    {"command_id", "plan_id", "actor_ref"}
)

_MAX_AUTHORIZATION_TTL: Final[timedelta] = timedelta(hours=24)


class RehearsalIssuerIssuanceRefusalCode(StrEnum):
    """Why this issuance/consumption path refuses, and why."""

    SECURITY_NOT_INSTALLED = "rehearsal_issuer_issuance_security_not_installed"
    MALFORMED = "rehearsal_issuer_issuance_malformed"
    PLAN_UNRESOLVED = "rehearsal_issuer_issuance_plan_unresolved"
    APPROVAL_NOT_STANDING = "rehearsal_issuer_issuance_approval_not_standing"
    #: D6: the resolved target's `environment` is not `REHEARSAL_ONLY_ENVIRONMENT`.
    NOT_A_REHEARSAL_TARGET = "rehearsal_issuer_issuance_not_a_rehearsal_target"
    #: D8: the resolved plan's authorized operation is not `"deploy"`.
    WRONG_AUTHORIZED_OPERATION = "rehearsal_issuer_issuance_wrong_authorized_operation"
    TARGET_MISMATCH = "rehearsal_issuer_issuance_target_mismatch"
    LEASE_ALREADY_AUTHORIZED = "rehearsal_issuer_issuance_lease_already_authorized"
    EVIDENCE_WINDOW_EXCEEDED = "rehearsal_issuer_issuance_evidence_window_exceeded"
    NOT_RECORDED = "rehearsal_issuer_issuance_not_recorded"
    ENVELOPE_MISMATCH = "rehearsal_issuer_issuance_envelope_mismatch"
    #: The freshly minted envelope failed genuine cryptographic
    #: self-verification against the installed `authorization_verifier` --
    #: the same verifier every other caller must satisfy, never a shortcut.
    #: This is NOT a metadata comparison (an earlier version of this check
    #: compared `key_id`/`algorithm`/`public_key_fingerprint` against the
    #: same statement object used to build them, which can never disagree);
    #: it re-derives and checks the signature over the canonical bytes,
    #: exactly as a real consumer of this envelope would.
    SIGNER_IDENTITY_MISMATCH = "rehearsal_issuer_issuance_signer_identity_mismatch"
    #: The presented harness evidence at consumption is the exact evidence
    #: used at issuance (a replay), or predates issuance outright -- neither
    #: can be a later, fresh presentation.
    STALE_HARNESS_EVIDENCE = "rehearsal_issuer_issuance_stale_harness_evidence"
    #: The resolved target is not `TargetStatus.ACTIVE` -- checked at both
    #: issuance and consumption, since a target can be suspended or
    #: decommissioned between the two.
    TARGET_NOT_ACTIVE = "rehearsal_issuer_issuance_target_not_active"
    NOT_REVOCABLE = "rehearsal_issuer_issuance_not_revocable"


class RehearsalIssuerIssuanceRefusedError(DeploymentControlError):
    def __init__(self, code: RehearsalIssuerIssuanceRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(
    code: RehearsalIssuerIssuanceRefusalCode, detail: str
) -> RehearsalIssuerIssuanceRefusedError:
    return RehearsalIssuerIssuanceRefusedError(code, detail)


def _authorized_image_digest_projection(
    images: tuple[AuthorizedImage, ...],
) -> tuple[str, ...]:
    """The ONE place `AuthorizedImage` -> C1's `authorized_image_digests`
    lossy projection happens (it drops `service`/`repository`). `images` is
    already canonically ordered by `authorized_image_set`
    (service, repository, digest), so this preserves that order rather than
    re-sorting."""
    return tuple(image.digest.canonical for image in images)


# ── Protected composition ───────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class _RehearsalIssuerSecurity:
    signer: RehearsalIssuerAuthorizationSigner
    authorization_verifier: RehearsalIssuerAuthorizationVerifier
    harness_verifier: RehearsalHarnessEvidenceVerifier
    authorization_ttl: timedelta


_SECURITY_INSTALL_LOCK = Lock()
_installed_security: _RehearsalIssuerSecurity | None = None


def install_rehearsal_issuer_security(
    *,
    signer: RehearsalIssuerAuthorizationSigner,
    authorization_verifier: RehearsalIssuerAuthorizationVerifier,
    harness_verifier: RehearsalHarnessEvidenceVerifier,
    authorization_ttl: timedelta,
) -> None:
    """Install once, at startup. A second call raises (D5, D3).

    `authorization_ttl` must be strictly positive and at most 24 hours (D5):
    a rehearsal-scoped authorization has no legitimate reason to outlive one
    working day, and refusing an absurd TTL here is cheap insurance against a
    misconfigured assembly.
    """
    if not isinstance(signer, RehearsalIssuerAuthorizationSigner):
        raise TypeError("rehearsal-issuer signer does not satisfy its port")
    if not isinstance(authorization_verifier, RehearsalIssuerAuthorizationVerifier):
        raise TypeError(
            "rehearsal-issuer authorization verifier does not satisfy its port"
        )
    if not isinstance(harness_verifier, RehearsalHarnessEvidenceVerifier):
        raise TypeError("rehearsal-harness-evidence verifier does not satisfy its port")
    if not isinstance(authorization_ttl, timedelta):
        raise TypeError("authorization_ttl must be a timedelta")
    if authorization_ttl <= timedelta(0):
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"authorization_ttl must be strictly positive, got {authorization_ttl}",
        )
    if authorization_ttl > _MAX_AUTHORIZATION_TTL:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"authorization_ttl {authorization_ttl} exceeds the "
            f"{_MAX_AUTHORIZATION_TTL} ceiling; a rehearsal-scoped authorization "
            "has no legitimate reason to outlive one working day",
        )
    global _installed_security
    with _SECURITY_INSTALL_LOCK:
        if _installed_security is not None:
            raise RuntimeError("rehearsal-issuer security is already installed")
        _installed_security = _RehearsalIssuerSecurity(
            signer=signer,
            authorization_verifier=authorization_verifier,
            harness_verifier=harness_verifier,
            authorization_ttl=authorization_ttl,
        )


def _require_installed_security() -> _RehearsalIssuerSecurity:
    security = _installed_security
    if security is None:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.SECURITY_NOT_INSTALLED,
            "rehearsal-issuer security was not installed at startup",
        )
    return security


def _reset_rehearsal_issuer_security_for_tests() -> None:
    """Remove startup composition between tests; never exported to products."""
    global _installed_security
    with _SECURITY_INSTALL_LOCK:
        _installed_security = None


# ── Issuance ─────────────────────────────────────────────────────────────────


def _fresh_harness_evidence(
    document: object,
    *,
    harness_verifier: RehearsalHarnessEvidenceVerifier,
    now: datetime,
) -> ParsedRehearsalHarnessEvidence:
    parsed = parse_signed_rehearsal_harness_evidence(document)
    verify_rehearsal_harness_evidence_signature(
        parsed, verifier=harness_verifier, at=now
    )
    return parsed


def issue_rehearsal_issuer_authorization_for_plan(
    db: Session,
    request: dict[str, Any],
    *,
    harness_evidence_document: object,
) -> RehearsalIssuerAuthorizationV1:
    """Mint a rehearsal-issuer authorization for one lease against a plan's
    OWN standing terms -- never against caller-supplied values.

    `request` carries exactly `command_id`, `plan_id`, and optionally
    `actor_ref`. Any other key -- including every field C1's own statement
    derives -- is refused by name (`MALFORMED`).
    """
    unexpected = set(request) - _ALLOWED_REQUEST_FIELDS
    forbidden = unexpected & _FORBIDDEN_REQUEST_FIELDS
    if forbidden:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"the caller may not supply {sorted(forbidden)}; these are derived "
            "inside this issuance boundary from the plan's own standing terms, "
            "never accepted from a caller",
        )
    if unexpected:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"unexpected request field(s) {sorted(unexpected)}; only "
            f"{sorted(_ALLOWED_REQUEST_FIELDS)} are accepted",
        )
    missing = {"command_id", "plan_id"} - set(request)
    if missing:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"missing required request field(s) {sorted(missing)}",
        )

    security = _require_installed_security()
    effective_now = _control_now()

    # Verified BEFORE touching the database, per the brief: a forged or
    # expired presentation never earns a database lock.
    evidence = _fresh_harness_evidence(
        harness_evidence_document,
        harness_verifier=security.harness_verifier,
        now=effective_now,
    )

    command_id = str(request["command_id"])
    try:
        plan_id = UUID(str(request["plan_id"]))
    except ValueError as exc:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            f"plan_id {request['plan_id']!r} is not a UUID",
        ) from exc
    actor_ref = request.get("actor_ref")

    def handler(session: Session) -> dict[str, Any]:
        try:
            _target, plan = _load_plan_with_target_for_update(session, plan_id)
        except DeploymentControlError as exc:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.PLAN_UNRESOLVED, str(exc)
            ) from exc

        terms = _standing_plan_terms(session, plan)
        if isinstance(terms, facts.ApprovedPlanLookup):
            refusal = terms.refusal
            detail = "" if refusal is None else refusal.detail
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.APPROVAL_NOT_STANDING,
                f"plan {plan_id} has no standing approval: {detail}",
            )
        assert isinstance(terms, _StandingPlanTerms)  # narrows for mypy

        if terms.target.status != TargetStatus.ACTIVE.value:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.TARGET_NOT_ACTIVE,
                f"target {terms.target.target_ref} is {terms.target.status!r}, "
                "not active",
            )
        if terms.target.environment != REHEARSAL_ONLY_ENVIRONMENT:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.NOT_A_REHEARSAL_TARGET,
                f"target {terms.target.target_ref} has environment "
                f"{terms.target.environment!r}, not {REHEARSAL_ONLY_ENVIRONMENT!r}",
            )
        if terms.authorized_operation != "deploy":
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.WRONG_AUTHORIZED_OPERATION,
                f"plan {plan_id} authorizes operation "
                f"{terms.authorized_operation!r}, not 'deploy'; a rehearsal "
                "issuer exists to rehearse a deploy",
            )
        if evidence.target_ref != terms.target.target_ref:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.TARGET_MISMATCH,
                f"the harness evidence names target_ref {evidence.target_ref!r} "
                f"and plan {plan_id} resolves to {terms.target.target_ref!r}",
            )

        existing = session.execute(
            select(RehearsalIssuerAuthorizationRecord).where(
                RehearsalIssuerAuthorizationRecord.lease_id == evidence.lease_id
            )
        ).scalar_one_or_none()
        if existing is not None:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.LEASE_ALREADY_AUTHORIZED,
                f"lease {evidence.lease_id} was already authorized as "
                f"{existing.authorization_id}; a revoked lease is not "
                "reusable, present a NEW lease id",
            )

        issued_at = effective_now
        expires_at = min(issued_at + security.authorization_ttl, evidence.valid_until)
        if expires_at <= issued_at:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.EVIDENCE_WINDOW_EXCEEDED,
                f"the harness evidence's valid_until ({evidence.valid_until}) "
                f"leaves no room for an authorization window starting at "
                f"{issued_at}",
            )

        identity = security.signer.rehearsal_issuer_identity
        authorization_id = str(uuid4())
        statement = RehearsalIssuerAuthorizationStatementV1(
            authorization_id=authorization_id,
            immutable_reference=str(terms.plan.id),
            target_id=str(terms.target.id),
            target_ref=terms.target.target_ref,
            target_provenance=A6ProvenanceKind.DERIVED,
            desired_state_digest=terms.plan_digest.canonical,
            desired_state_provenance=A6ProvenanceKind.DERIVED,
            profile_digest=terms.descriptor_digest.canonical,
            profile_provenance=A6ProvenanceKind.DERIVED,
            authorized_image_digests=_authorized_image_digest_projection(
                terms.authorized_images
            ),
            authorized_images_provenance=A6ProvenanceKind.DERIVED,
            execution_plan_digest=terms.execution_plan_digest.canonical,
            execution_plan_provenance=A6ProvenanceKind.DERIVED,
            controller_fingerprint=evidence.controller_fingerprint,
            key_id=identity.key_id,
            algorithm=identity.algorithm,
            public_key_fingerprint=identity.public_key_fingerprint,
            lease_id=evidence.lease_id,
            single_use_reference=f"rehearsal-issuer:{uuid4()}",
            environment=REHEARSAL_ONLY_ENVIRONMENT,
            not_before=issued_at,
            issued_at=issued_at,
            expires_at=expires_at,
            control_version=_installed_control_version(),
        )
        envelope = issue_rehearsal_issuer_authorization(
            statement, signer=security.signer
        )

        # Genuine cryptographic self-verification against the INSTALLED
        # verifier -- the same one every other caller must satisfy, never a
        # shortcut. A metadata comparison against `statement` proves nothing:
        # `envelope.statement` IS the same object `statement` already built
        # from `identity`, so such a comparison can never disagree.
        self_check_subject = RehearsalIssuerAuthorizationSubject(
            immutable_reference=str(terms.plan.id),
            target_id=str(terms.target.id),
            target_ref=terms.target.target_ref,
            desired_state_digest=terms.plan_digest.canonical,
            profile_digest=terms.descriptor_digest.canonical,
            authorized_image_digests=_authorized_image_digest_projection(
                terms.authorized_images
            ),
            execution_plan_digest=terms.execution_plan_digest.canonical,
            controller_fingerprint=evidence.controller_fingerprint,
            environment=REHEARSAL_ONLY_ENVIRONMENT,
            signer_public_key_fingerprint=identity.public_key_fingerprint,
            lease_id=evidence.lease_id,
        )
        try:
            verify_rehearsal_issuer_authorization(
                envelope.as_mapping(),
                verifier=security.authorization_verifier,
                subject=self_check_subject,
                at=effective_now,
                revoked_authorization_ids=frozenset(),
                consumed_references=frozenset(),
            )
        except RehearsalIssuerAuthorizationRefusedError as exc:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.SIGNER_IDENTITY_MISMATCH,
                f"self-verification of the freshly issued envelope failed: {exc}",
            ) from exc

        record = RehearsalIssuerAuthorizationRecord(
            id=uuid4(),
            authorization_id=authorization_id,
            single_use_reference=statement.single_use_reference,
            lease_id=evidence.lease_id,
            plan_id=terms.plan.id,
            target_id=terms.target.id,
            controller_fingerprint=evidence.controller_fingerprint,
            harness_evidence_digest=evidence.digest.canonical,
            authorization_envelope=envelope.as_mapping(),
            not_before=statement.not_before,
            issued_at=statement.issued_at,
            expires_at=statement.expires_at,
            state=RehearsalIssuerAuthorizationState.ISSUED.value,
        )
        try:
            with conflict_savepoint(session):
                session.add(record)
                session.flush()
        except IntegrityError as exc:
            raise _refused(
                RehearsalIssuerIssuanceRefusalCode.LEASE_ALREADY_AUTHORIZED,
                f"lease {evidence.lease_id} or authorization {authorization_id} "
                f"collided with a concurrently issued row: {exc}",
            ) from exc

        _audit_and_emit(
            session,
            action=AUDIT_ACTION_REHEARSAL_ISSUER,
            event_type=facts.REHEARSAL_ISSUER_AUTHORIZATION_CHANGED_V1,
            entity_type=_ENTITY_REHEARSAL_ISSUER_AUTHORIZATION,
            entity_id=authorization_id,
            actor_ref=None if actor_ref is None else str(actor_ref),
            details={
                "lease_id": evidence.lease_id,
                "plan_id": str(terms.plan.id),
                "target_ref": terms.target.target_ref,
                "state": RehearsalIssuerAuthorizationState.ISSUED.value,
            },
        )
        return {"envelope": envelope.as_mapping()}

    outcome = process_once_platform(
        db,
        command_id=command_id,
        command_type=REHEARSAL_ISSUER_ISSUANCE_COMMAND_TYPE,
        handler=handler,
    )
    return RehearsalIssuerAuthorizationV1.parse(outcome.result["envelope"])


# ── Revocation ───────────────────────────────────────────────────────────────


def revoke_rehearsal_issuer_authorization(
    db: Session,
    *,
    authorization_id: str,
    revocation_ref: str,
    actor_ref: str | None = None,
) -> None:
    """Withdraw one lease's rehearsal-issuer authority. Terminal states are
    immutable (enforced by the ledger's own trigger; this is the app-level
    half of that same rule)."""
    if not isinstance(revocation_ref, str) or not revocation_ref.strip():
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            "revocation_ref must be a non-empty, non-whitespace-only string",
        )
    if len(revocation_ref) > 200:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.MALFORMED,
            "revocation_ref exceeds 200 characters",
        )
    row = db.execute(
        select(RehearsalIssuerAuthorizationRecord)
        .where(RehearsalIssuerAuthorizationRecord.authorization_id == authorization_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.NOT_RECORDED,
            f"no rehearsal-issuer authorization ledger row for {authorization_id}",
        )
    if row.state != RehearsalIssuerAuthorizationState.ISSUED.value:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.NOT_REVOCABLE,
            f"authorization {authorization_id} is {row.state!r}, not "
            f"{RehearsalIssuerAuthorizationState.ISSUED.value!r}",
        )
    now = _control_now()
    row.state = RehearsalIssuerAuthorizationState.REVOKED.value
    row.revoked_at = now
    row.revocation_ref = revocation_ref
    db.flush()
    _audit_and_emit(
        db,
        action=AUDIT_ACTION_REHEARSAL_ISSUER,
        event_type=facts.REHEARSAL_ISSUER_AUTHORIZATION_CHANGED_V1,
        entity_type=_ENTITY_REHEARSAL_ISSUER_AUTHORIZATION,
        entity_id=authorization_id,
        actor_ref=actor_ref,
        details={
            "state": RehearsalIssuerAuthorizationState.REVOKED.value,
            "revocation_ref": revocation_ref,
        },
    )


# ── Staged consumption ───────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RehearsalIssuerConsumptionStaged:
    """Staged, never committed by this function -- the caller commits as part
    of its own larger transaction. Matches `dc_0012`'s own "staged
    consumption is not a launch grant" framing."""

    authorization_id: str
    single_use_reference: str
    lease_id: str


def stage_rehearsal_issuer_consumption(
    db: Session,
    *,
    authorization_document: object,
    harness_evidence_document: object,
) -> RehearsalIssuerConsumptionStaged:
    """Spend one lease's rehearsal-issuer authority against Control's OWN
    re-verified, locked state -- never against the presented document's own
    claimed fields. This is what discharges C1's stated caller obligation
    ("the application does not authorize itself")."""
    security = _require_installed_security()
    effective_now = _control_now()

    # A SEPARATE, FRESH presentation from issuance-time evidence.
    evidence = _fresh_harness_evidence(
        harness_evidence_document,
        harness_verifier=security.harness_verifier,
        now=effective_now,
    )
    presented = RehearsalIssuerAuthorizationV1.parse(authorization_document)
    statement = presented.statement

    try:
        plan_id = UUID(statement.immutable_reference)
    except ValueError as exc:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.PLAN_UNRESOLVED,
            f"immutable_reference {statement.immutable_reference!r} is not a UUID",
        ) from exc
    try:
        _target, plan = _load_plan_with_target_for_update(db, plan_id)
    except DeploymentControlError as exc:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.PLAN_UNRESOLVED, str(exc)
        ) from exc

    row = db.execute(
        select(RehearsalIssuerAuthorizationRecord)
        .where(
            RehearsalIssuerAuthorizationRecord.authorization_id
            == statement.authorization_id
        )
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one_or_none()
    if row is None:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.NOT_RECORDED,
            f"no rehearsal-issuer authorization ledger row for "
            f"{statement.authorization_id}",
        )
    if canonical_json(presented.as_mapping()["statement"]) != canonical_json(
        row.authorization_envelope["statement"]
    ):
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH,
            f"the presented envelope for {statement.authorization_id} does "
            "not match the ledger's stored envelope byte-for-byte",
        )

    if evidence.digest.canonical == row.harness_evidence_digest:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.STALE_HARNESS_EVIDENCE,
            f"the presented harness evidence for {statement.authorization_id} "
            "is byte-identical to the evidence presented at issuance; a "
            "second presentation of the same evidence is a replay, not a "
            "fresh presentation",
        )
    if evidence.issued_at < row.issued_at:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.STALE_HARNESS_EVIDENCE,
            f"the presented harness evidence was issued at {evidence.issued_at} "
            f"which predates authorization {statement.authorization_id}'s own "
            f"issuance at {row.issued_at}; consumption evidence must be a "
            "later, fresh presentation",
        )

    # Re-derive standing terms from Control's OWN locked state -- never from
    # the presented document's claimed fields.
    terms = _standing_plan_terms(db, plan)
    if isinstance(terms, facts.ApprovedPlanLookup):
        refusal = terms.refusal
        detail = "" if refusal is None else refusal.detail
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.APPROVAL_NOT_STANDING,
            f"plan {plan.id} no longer has a standing approval: {detail}",
        )
    assert isinstance(terms, _StandingPlanTerms)

    if terms.target.status != TargetStatus.ACTIVE.value:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.TARGET_NOT_ACTIVE,
            f"target {terms.target.target_ref} is {terms.target.status!r}, "
            "not active",
        )
    if evidence.target_ref != terms.target.target_ref:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.TARGET_MISMATCH,
            f"the harness evidence names target_ref {evidence.target_ref!r} "
            f"and plan {plan.id} resolves to {terms.target.target_ref!r}",
        )

    subject = RehearsalIssuerAuthorizationSubject(
        immutable_reference=str(terms.plan.id),
        target_id=str(terms.target.id),
        target_ref=terms.target.target_ref,
        desired_state_digest=terms.plan_digest.canonical,
        profile_digest=terms.descriptor_digest.canonical,
        authorized_image_digests=_authorized_image_digest_projection(
            terms.authorized_images
        ),
        execution_plan_digest=terms.execution_plan_digest.canonical,
        controller_fingerprint=evidence.controller_fingerprint,
        environment=terms.target.environment,
        signer_public_key_fingerprint=statement.public_key_fingerprint,
        lease_id=evidence.lease_id,
    )
    revoked_ids = (
        frozenset({row.authorization_id})
        if row.state == RehearsalIssuerAuthorizationState.REVOKED.value
        else frozenset()
    )
    consumed_refs = (
        frozenset({row.single_use_reference})
        if row.state == RehearsalIssuerAuthorizationState.SPENT.value
        else frozenset()
    )
    try:
        verify_rehearsal_issuer_authorization(
            authorization_document,
            verifier=security.authorization_verifier,
            subject=subject,
            at=effective_now,
            revoked_authorization_ids=revoked_ids,
            consumed_references=consumed_refs,
        )
    except RehearsalIssuerAuthorizationRefusedError as exc:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.ENVELOPE_MISMATCH, str(exc)
        ) from exc

    if row.state != RehearsalIssuerAuthorizationState.ISSUED.value:
        raise _refused(
            RehearsalIssuerIssuanceRefusalCode.NOT_REVOCABLE,
            f"authorization {statement.authorization_id} is {row.state!r}, "
            "not consumable",
        )

    row.state = RehearsalIssuerAuthorizationState.SPENT.value
    row.spent_at = effective_now
    db.flush()
    return RehearsalIssuerConsumptionStaged(
        authorization_id=statement.authorization_id,
        single_use_reference=statement.single_use_reference,
        lease_id=evidence.lease_id,
    )


# ── Standing (read-only) ─────────────────────────────────────────────────────


def rehearsal_issuer_standing_for(
    db: Session,
    *,
    authorization_document: object | None,
    harness_evidence_document: object,
    now: datetime | None = None,
) -> RehearsalIssuerAuthorizationStandingResult:
    """An UNLOCKED read. A document with no matching ledger row reads exactly
    as C1's own absent/unresolved standing."""
    security = _require_installed_security()
    effective_now = now or _control_now()
    evidence = _fresh_harness_evidence(
        harness_evidence_document,
        harness_verifier=security.harness_verifier,
        now=effective_now,
    )
    if authorization_document is None:
        return rehearsal_issuer_standing(
            None,
            verifier=security.authorization_verifier,
            subject=_absent_subject(evidence),
            at=effective_now,
        )
    presented = RehearsalIssuerAuthorizationV1.parse(authorization_document)
    statement = presented.statement
    row = db.execute(
        select(RehearsalIssuerAuthorizationRecord).where(
            RehearsalIssuerAuthorizationRecord.authorization_id
            == statement.authorization_id
        )
    ).scalar_one_or_none()

    # A document with no matching ledger row, or one whose presented envelope
    # does not byte-match the ledger's own stored envelope, reads exactly as
    # C1's own absent/unresolved standing -- it must NOT be resolved into a
    # real subject just because the presented statement parses and names a
    # real plan/target. The ledger row is the sole source of truth for what
    # this authorization_id actually is.
    envelope_matches_ledger = row is not None and canonical_json(
        presented.as_mapping()["statement"]
    ) == canonical_json(row.authorization_envelope["statement"])

    target, plan = None, None
    if envelope_matches_ledger:
        try:
            plan = db.get(DeploymentPlan, UUID(statement.immutable_reference))
        except ValueError:
            plan = None
        if plan is not None:
            target = db.get(DeploymentTarget, plan.target_id)

    if plan is None or target is None:
        subject = _absent_subject(evidence)
    else:
        terms = _standing_plan_terms(db, plan)
        if isinstance(terms, facts.ApprovedPlanLookup):
            subject = _absent_subject(evidence)
        else:
            subject = RehearsalIssuerAuthorizationSubject(
                immutable_reference=str(terms.plan.id),
                target_id=str(terms.target.id),
                target_ref=terms.target.target_ref,
                desired_state_digest=terms.plan_digest.canonical,
                profile_digest=terms.descriptor_digest.canonical,
                authorized_image_digests=_authorized_image_digest_projection(
                    terms.authorized_images
                ),
                execution_plan_digest=terms.execution_plan_digest.canonical,
                controller_fingerprint=evidence.controller_fingerprint,
                environment=terms.target.environment,
                signer_public_key_fingerprint=statement.public_key_fingerprint,
                lease_id=evidence.lease_id,
            )

    revoked_ids = (
        frozenset({row.authorization_id})
        if row is not None
        and row.state == RehearsalIssuerAuthorizationState.REVOKED.value
        else frozenset()
    )
    consumed_refs = (
        frozenset({row.single_use_reference})
        if row is not None
        and row.state == RehearsalIssuerAuthorizationState.SPENT.value
        else frozenset()
    )
    return rehearsal_issuer_standing(
        authorization_document,
        verifier=security.authorization_verifier,
        subject=subject,
        at=effective_now,
        revoked_authorization_ids=revoked_ids,
        consumed_references=consumed_refs,
    )


def _absent_subject(
    evidence: ParsedRehearsalHarnessEvidence,
) -> RehearsalIssuerAuthorizationSubject:
    """A subject that cannot match any real statement -- used only to route a
    caller into C1's own UNRESOLVED/ABSENT standing outcome for an
    unresolvable reference, never treated as authority."""
    return RehearsalIssuerAuthorizationSubject(
        immutable_reference="",
        target_id="",
        target_ref="",
        desired_state_digest="sha256:" + "0" * 64,
        profile_digest="sha256:" + "0" * 64,
        authorized_image_digests=(),
        execution_plan_digest="sha256:" + "0" * 64,
        controller_fingerprint=evidence.controller_fingerprint,
        environment=REHEARSAL_ONLY_ENVIRONMENT,
        signer_public_key_fingerprint="",
        lease_id=evidence.lease_id,
    )
