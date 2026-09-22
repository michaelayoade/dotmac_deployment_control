"""Authority to operate the protected, disposable rehearsal issuer — not the
ADR-0013 §5-6 bootstrap, and not weakening it.

## What this authorizes, and what it is not

`dotmac_platform_control_plane`'s ADR-0013 §5-6 describes a single-use
bootstrap launcher for the REAL operator-authorization issuer
(`platform-cp-01`): create-only, structurally single-use (it refuses to run
if the target already holds a deployment receipt), and built on the rule
*"the application does not authorize itself"* — nothing in the deployed
application participates in authorizing the deployment that created it.

This module is a different document for a different act. It authorizes
operating a PROTECTED, DISPOSABLE REHEARSAL issuer for one bounded lease —
never the production issuer, never a step in standing that issuer up, and
never a substitute for its bootstrap. `REHEARSAL_ONLY_ENVIRONMENT` is the
structural device that keeps the two from being confused: this contract can
never be presented as authority over the target the bootstrap protects,
because its `environment` term is pinned to exactly one value and every other
value is refused before any other field is even read.

`dotmac_platform_control_plane`'s ADR-0013 amendment A6.4 is Platform CP's
rule, cited here by repository per that ADR's own instruction:

    Target, desired state, profile digest, authorized images and
    execution-plan inputs are derived from one immutable reference. No
    independently supplied value may silently join the plan.

This module implements the same derivation discipline for the rehearsal
path: each of those five values is bound to this statement together with a
typed :class:`A6ProvenanceKind` (`DERIVED` or `OVERRIDE`, closed at two
members — there is no third, "silent" member, because the absence of a typed
provenance field is what silence looks like, and this design makes that
unconstructable), and an `OVERRIDE` requires a non-empty, caller-supplied
reason so an approver reading the statement sees the exception without
reconstructing it.

## Why `environment` is pinned to exactly one value, not validated by convention

A convention ("call it `rehearsal`, please") is a promise a caller can break
by typing something else. Pinning `REHEARSAL_ONLY_ENVIRONMENT` as the one
value `environment` may equal, checked unconditionally in
`__post_init__` before any other field is read where practical, makes this a
STRUCTURAL guard rather than a naming habit: a statement naming any other
environment cannot be constructed at all, so there is no route by which this
contract's shape is ever presented as authority over a non-rehearsal target.

## Why single-use is PER LEASE, not a one-time lifetime instance

The ADR-0013 §5-6 bootstrap's single-use property is about a LAUNCHER: it
runs at most once, ever, for the real issuer, and it refuses outright if the
target already holds a deployment receipt. That is not what this contract
needs, because a rehearsal issuer is stood up and torn down repeatedly across
many rehearsal cycles, and a single-lifetime-instance rule would make it
impossible to rehearse a second time.

Instead, `single_use_reference` is the replay coordinate — the SAME discipline
`rehearsal_grant.py` already uses for its own field of the same name: *"A
re-presentable [document] is a second execution authority, so it is bound
into the signed statement and compared against a set of already-consumed
references the CALLER supplies."* Spending one coordinate exhausts authority
for ONE lease's rehearsal cycle, not for the issuer's entire existence — which
composes with, rather than contradicts, the bootstrap's true single-use
property: the bootstrap is single-use because a second production issuer must
never exist; this contract is single-use-per-lease because a second
presentation of the same signed lease authority must never grant a second
execution.

## Why `controller_fingerprint` and the signer's `public_key_fingerprint` are separate

The controller is the orchestrator process permitted to OPERATE the issuer
under this lease. The signer is whoever ISSUED this authorization. A
compromised controller and a compromised signing key are different failures
with different blast radii, and collapsing them into one field would make
either one undetectable independently of the other — a caller could not
refuse "the right key signed this, but the wrong controller is trying to use
it" or the reverse. They are bound and compared as two independently
refusable terms for exactly that reason.

## Say plainly what this module does and does not establish

This module is PURE. It performs no I/O, mints no lease, contacts no
process, and cannot itself enforce that the comparison subject it is handed
was supplied by the disposable rehearsal harness rather than by the
application under rehearsal. *"The application does not authorize itself"* is
a CALLER-SIDE obligation this type cannot verify — a caller of this contract
must not source the subject it verifies against from the CP instance being
rehearsed. What this module CAN and DOES do is refuse to construct or verify
a statement whose bound terms disagree with what the caller states, and
refuse every value on this contract other than the one rehearsal environment
it is pinned to.

## Two additions beyond the literal brief, made under the "one code per binding" rule

`RehearsalGrantRefusalCode`'s own docstring states the rule this module's
refusal codes obey: *"One code per binding, so a caller is told WHICH term
disagreed rather than being sent round the loop once per field."* Applying
that rule mechanically surfaces two gaps in the enumerated design and this
module closes both, named here rather than silently:

1. **`DESIRED_STATE_MISMATCH`.** A6.4 names five derived values — target,
   desired state, profile digest, authorized images, execution-plan inputs —
   and this statement binds all five. The originally decided refusal-code
   list names a mismatch code for four of the five (target, profile, image,
   execution-plan) and for a sixth term, `immutable_reference`
   (`CANDIDATE_MISMATCH`), but named none for `desired_state_digest`. A bound
   term with no refusal code is exactly the "silent" shape A6.4 forbids, so
   this module adds `DESIRED_STATE_MISMATCH` rather than leaving that term
   uncomparable.
2. **`RehearsalIssuerAuthorizationSubject.signer_public_key_fingerprint`.**
   The decided design names `SIGNER_MISMATCH` — *"wrong signer identity,
   distinct from `SIGNATURE_INVALID` which is a crypto failure"* — as one of
   the subject-comparison refusals, but the subject's own field list (stated
   to mirror `RehearsalSubject` and exclude "the signer... machinery") does
   not carry a signer-identity term to compare. Without one,
   `SIGNER_MISMATCH` cannot fire on anything. This module adds the one field
   needed to make that named refusal reachable, comparing it against the
   statement's `public_key_fingerprint`, and flags the addition here rather
   than silently dropping the requested code or silently widening the
   subject beyond its documented field list without comment.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.digests import (
    DescriptorDigestV1,
    ExecutionPlanDigestV1,
    ImageDigestV1,
    PlanDigestV1,
)
from dotmac_deployment_control.ports import DeploymentControlError, DigestEncodingError

__all__ = [
    "REHEARSAL_ISSUER_AUTHORIZATION_SCHEMA",
    "REHEARSAL_ISSUER_AUTHORIZATION_VERSION",
    "REHEARSAL_ISSUER_PURPOSE",
    "REHEARSAL_ONLY_ENVIRONMENT",
    "A6ProvenanceKind",
    "RehearsalIssuerAuthorizationRefusalCode",
    "RehearsalIssuerAuthorizationRefusedError",
    "RehearsalIssuerAuthorizationSignature",
    "RehearsalIssuerAuthorizationSigner",
    "RehearsalIssuerAuthorizationSignerIdentity",
    "RehearsalIssuerAuthorizationStandingResult",
    "RehearsalIssuerAuthorizationStanding",
    "RehearsalIssuerAuthorizationStatementV1",
    "RehearsalIssuerAuthorizationSubject",
    "RehearsalIssuerAuthorizationV1",
    "RehearsalIssuerAuthorizationVerifier",
    "issue_rehearsal_issuer_authorization",
    "rehearsal_issuer_standing",
    "verify_rehearsal_issuer_authorization",
]

#: Distinct from every other signer purpose in this package
#: (`deployment_authorization`, `deployment_dispatch`,
#: `target_execution_observation`, `deployment_recovery` and
#: `deployment_rehearsal`) for the reason all of them are separated: one key
#: answering two questions cannot be used to contradict itself. This purpose
#: authorizes STANDING UP the rehearsal issuer for a lease; `deployment_rehearsal`
#: authorizes one provoked act performed once the issuer already stands. They
#: are different signers because a compromise of one must not extend to the
#: other.
REHEARSAL_ISSUER_PURPOSE: Final = "deployment_rehearsal_issuer"
REHEARSAL_ISSUER_AUTHORIZATION_SCHEMA: Final = (
    "dotmac.deployment_control.rehearsal_issuer_authorization"
)
REHEARSAL_ISSUER_AUTHORIZATION_VERSION: Final = 1

#: The ONE value `environment` may ever equal on this contract. Validated
#: unconditionally in `__post_init__`, before any other field is read where
#: practical — a structural guard, not a naming convention. See the module
#: docstring's "Why `environment` is pinned" section.
REHEARSAL_ONLY_ENVIRONMENT: Final = "rehearsal"

_MAX_TEXT = 512


class A6ProvenanceKind(StrEnum):
    """How a bound A6.4 value reached this statement. Closed at two members.

    There is deliberately no third, "silent" member: ADR-0013 A6.4 defines
    silence as the RESIDUE — a value that was accepted, used, and covered by
    a digest, yet carries no provenance record at all. A value must always be
    one of these two; the type system makes a third, unrecorded state
    unconstructable rather than merely discouraged.
    """

    #: Resolved from the immutable reference. The ordinary path.
    DERIVED = "derived"
    #: Accepted despite NOT being resolved from the reference, carried with a
    #: required, non-empty reason so the exception is visible on the
    #: statement itself rather than reconstructed from context.
    OVERRIDE = "override"


class RehearsalIssuerAuthorizationRefusalCode(StrEnum):
    """Why this authorization does not stand for the rehearsal issuer in hand.

    One code per binding, so a caller is told WHICH term disagreed rather
    than being sent round the loop once per field — the same rule
    `rehearsal_grant.RehearsalGrantRefusalCode`'s own docstring states. See
    the module docstring's closing section for the two codes/fields this
    module adds beyond the originally enumerated design, and why.
    """

    MALFORMED = "rehearsal_issuer_authorization_malformed"
    #: The document is not this contract. Fires before any field is read.
    SCHEMA_MISMATCH = "rehearsal_issuer_authorization_schema_mismatch"
    PURPOSE_MISMATCH = "rehearsal_issuer_authorization_purpose_mismatch"
    SIGNER_PURPOSE_REUSED = "rehearsal_issuer_authorization_signer_purpose_reused"
    UNSIGNED = "rehearsal_issuer_authorization_unsigned"
    SIGNATURE_INVALID = "rehearsal_issuer_authorization_signature_invalid"
    #: `environment` is not `REHEARSAL_ONLY_ENVIRONMENT`. The structural
    #: non-production guard; see the module docstring.
    NOT_A_REHEARSAL_ENVIRONMENT = (
        "rehearsal_issuer_authorization_not_a_rehearsal_environment"
    )
    #: `immutable_reference` disagrees.
    CANDIDATE_MISMATCH = "rehearsal_issuer_authorization_candidate_mismatch"
    #: Presented signer identity disagrees. Distinct from `SIGNATURE_INVALID`,
    #: which is a cryptographic verification failure — this is a term
    #: mismatch on an otherwise validly-signed document.
    SIGNER_MISMATCH = "rehearsal_issuer_authorization_signer_mismatch"
    CONTROLLER_MISMATCH = "rehearsal_issuer_authorization_controller_mismatch"
    TARGET_MISMATCH = "rehearsal_issuer_authorization_target_mismatch"
    #: See the module docstring's closing section: added under the "one code
    #: per binding" rule because `desired_state_digest` is bound but the
    #: originally enumerated design named no code for it.
    DESIRED_STATE_MISMATCH = "rehearsal_issuer_authorization_desired_state_mismatch"
    PROFILE_MISMATCH = "rehearsal_issuer_authorization_profile_mismatch"
    IMAGE_MISMATCH = "rehearsal_issuer_authorization_image_mismatch"
    EXECUTION_PLAN_MISMATCH = "rehearsal_issuer_authorization_execution_plan_mismatch"
    #: An OVERRIDE with no reason, or a reason present on a DERIVED value — a
    #: reason with nothing to explain is itself a defect.
    PROVENANCE_MALFORMED = "rehearsal_issuer_authorization_provenance_malformed"
    NOT_YET_VALID = "rehearsal_issuer_authorization_not_yet_valid"
    EXPIRED = "rehearsal_issuer_authorization_expired"
    REVOKED = "rehearsal_issuer_authorization_revoked"
    #: The per-lease replay coordinate has already been spent. See the module
    #: docstring's "single-use is PER LEASE" section.
    ALREADY_CONSUMED = "rehearsal_issuer_authorization_already_consumed"


class RehearsalIssuerAuthorizationRefusedError(DeploymentControlError):
    """This authorization does not stand for the act in hand, and why."""

    def __init__(
        self, code: RehearsalIssuerAuthorizationRefusalCode, detail: str
    ) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(
    code: RehearsalIssuerAuthorizationRefusalCode, detail: str
) -> RehearsalIssuerAuthorizationRefusedError:
    return RehearsalIssuerAuthorizationRefusedError(code, detail)


class RehearsalIssuerAuthorizationStanding(StrEnum):
    """What this authorization is RIGHT NOW, distinct from whether it ever
    verified. Mirrors `rehearsal_grant.RehearsalStanding` member-for-member."""

    VALID = "valid"
    ABSENT = "absent"
    UNRESOLVED = "unresolved"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationSignerIdentity:
    """The rehearsal-issuer signer, which must be none of the other five."""

    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = REHEARSAL_ISSUER_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != REHEARSAL_ISSUER_PURPOSE:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH,
                "a rehearsal-issuer signer must declare "
                f"{REHEARSAL_ISSUER_PURPOSE!r}, not {self.purpose!r}",
            )


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationSignature:
    key_id: str
    algorithm: str
    purpose: str
    public_key_fingerprint: str
    signature: str


@runtime_checkable
class RehearsalIssuerAuthorizationSigner(Protocol):
    """Control-side rehearsal-issuer-authorization signer.

    Its members share no name with the authorization, dispatch, observation,
    recovery or rehearsal-grant signers, so one cannot be passed where
    another is expected even by accident.
    """

    @property
    def rehearsal_issuer_identity(
        self,
    ) -> RehearsalIssuerAuthorizationSignerIdentity: ...

    def sign_rehearsal_issuer_authorization(
        self, canonical_bytes: bytes
    ) -> RehearsalIssuerAuthorizationSignature: ...


@runtime_checkable
class RehearsalIssuerAuthorizationVerifier(Protocol):
    """Verifier for the rehearsal-issuer-authorization purpose only."""

    def verify_rehearsal_issuer_authorization(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationSubject:
    """What the caller says it is about to operate the rehearsal issuer for.

    Stated by the caller and compared against the signed statement term by
    term. Everything the statement binds except the signer/lease/window/replay
    machinery, PLUS one addition — `signer_public_key_fingerprint` — needed to
    make the decided `SIGNER_MISMATCH` refusal reachable; see the module
    docstring's closing section for why that field is here despite not being
    in the originally enumerated subject field list.
    """

    immutable_reference: str
    target_id: str
    target_ref: str
    desired_state_digest: str
    profile_digest: str
    authorized_image_digests: tuple[str, ...]
    execution_plan_digest: str
    controller_fingerprint: str
    environment: str
    signer_public_key_fingerprint: str


def _require_provenance(value: object) -> A6ProvenanceKind:
    if isinstance(value, A6ProvenanceKind):
        return value
    known = sorted(member.value for member in A6ProvenanceKind)
    if not isinstance(value, str) or value not in {
        member.value for member in A6ProvenanceKind
    }:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED,
            f"{value!r} is not a provenance this contract knows; it knows " f"{known}",
        )
    return A6ProvenanceKind(value)


def _text(value: object, field: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} exceeds {_MAX_TEXT} characters",
        )
    return value


def _optional_text(value: object, field: str) -> str | None:
    if value is None:
        return None
    return _text(value, field)


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} must be a datetime, got {type(value).__name__}",
        )
    if value.tzinfo is None:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} is naive; an instant without a zone is not an instant",
        )
    return value.astimezone(UTC)


def _instant(row: Mapping[str, Any], field: str) -> datetime:
    value = row.get(field)
    if not isinstance(value, str):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} must be an ISO instant",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            f"{field} is not an instant: {error}",
        ) from error
    return _aware_utc(parsed, field=field)


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationStatementV1:
    """The signed terms authorizing one lease's rehearsal-issuer operation."""

    authorization_id: str
    #: The A6.4 anchor coordinate. See `CANDIDATE_MISMATCH`.
    immutable_reference: str
    target_id: str
    target_ref: str
    target_provenance: A6ProvenanceKind
    #: `PlanDigestV1` — Control's own frozen DESIRED-STATE SNAPSHOT digest.
    #: `digests.py`'s `ControlPlanDigestV1` docstring names `PlanDigestV1`
    #: exactly this way ("the identity of a frozen DESIRED-STATE SNAPSHOT"),
    #: which is why this A6.4 value is parsed with that type rather than
    #: `SpecDigestV1` (a TARGET's reported running spec) or `DescriptorDigestV1`
    #: (the Foundation's descriptor, used below for `profile_digest`).
    desired_state_digest: str
    desired_state_provenance: A6ProvenanceKind
    #: `DescriptorDigestV1` — the Foundation's canonical deployment-descriptor
    #: digest. `AuthorizationStatementV3` already carries `descriptor_digest`
    #: alongside `plan_digest` (desired state) and `execution_plan_digest`
    #: (execution-plan inputs), so this reuses the same existing type for the
    #: same A6.4 "profile digest" term rather than inventing a fifth digest
    #: kind.
    profile_digest: str
    profile_provenance: A6ProvenanceKind
    #: Each parsed with `ImageDigestV1` — a registry manifest digest, never a
    #: mutable tag; see that type's docstring.
    authorized_image_digests: tuple[str, ...]
    authorized_images_provenance: A6ProvenanceKind
    #: `ExecutionPlanDigestV1` — the Foundation's execution plan digest,
    #: matching `rehearsal_grant.py`'s own use of this exact type.
    execution_plan_digest: str
    execution_plan_provenance: A6ProvenanceKind
    #: Identity of the controller/orchestrator process permitted to operate
    #: the issuer for this lease. Structurally separate from the signer's
    #: `public_key_fingerprint`; see the module docstring.
    controller_fingerprint: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    #: Bound by VALUE only, same discipline `authorization_v3.py` uses for
    #: Foundation's `HostLease.v2`: Control does not own the lease type.
    lease_id: str
    #: The per-lease replay coordinate. See the module docstring's
    #: "single-use is PER LEASE" section — a re-presentable authorization is
    #: a second execution authority, so it is bound into the signed statement
    #: and compared against a set of already-consumed references the CALLER
    #: supplies. This module is pure and performs no I/O, so it refuses a
    #: reference it is TOLD was consumed; it cannot itself know. The durable
    #: record of consumption belongs to whoever holds the store.
    single_use_reference: str
    #: Structurally pinned to `REHEARSAL_ONLY_ENVIRONMENT`; see the module
    #: docstring.
    environment: str
    not_before: datetime
    issued_at: datetime
    expires_at: datetime
    control_version: str
    purpose: str = REHEARSAL_ISSUER_PURPOSE
    #: Required, non-empty, only when the matching provenance is OVERRIDE;
    #: refused as malformed if present while the matching provenance is
    #: DERIVED. See `A6ProvenanceKind`.
    target_override_reason: str | None = None
    desired_state_override_reason: str | None = None
    profile_override_reason: str | None = None
    authorized_images_override_reason: str | None = None
    execution_plan_override_reason: str | None = None

    def __post_init__(self) -> None:
        # `environment` first, structurally, before any other field is read
        # where practical — see the module docstring's "Why `environment` is
        # pinned" section.
        if self.environment != REHEARSAL_ONLY_ENVIRONMENT:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT,
                f"environment must be {REHEARSAL_ONLY_ENVIRONMENT!r}, not "
                f"{self.environment!r}. This contract can never stand for a "
                "non-rehearsal target",
            )
        if self.purpose != REHEARSAL_ISSUER_PURPOSE:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH,
                "a rehearsal-issuer authorization statement must declare "
                f"{REHEARSAL_ISSUER_PURPOSE!r}",
            )
        for field, value in (
            ("authorization_id", self.authorization_id),
            ("immutable_reference", self.immutable_reference),
            ("target_id", self.target_id),
            ("target_ref", self.target_ref),
            ("controller_fingerprint", self.controller_fingerprint),
            ("key_id", self.key_id),
            ("algorithm", self.algorithm),
            ("public_key_fingerprint", self.public_key_fingerprint),
            ("lease_id", self.lease_id),
            ("single_use_reference", self.single_use_reference),
            ("control_version", self.control_version),
        ):
            _text(value, field)

        try:
            PlanDigestV1.parse(self.desired_state_digest)
        except DigestEncodingError as error:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                f"desired_state_digest is not a canonical desired-state "
                f"digest: {error}",
            ) from error
        try:
            DescriptorDigestV1.parse(self.profile_digest)
        except DigestEncodingError as error:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                f"profile_digest is not a canonical profile digest: {error}",
            ) from error
        try:
            ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        except DigestEncodingError as error:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                f"execution_plan_digest is not a canonical execution plan "
                f"digest: {error}",
            ) from error
        if not isinstance(self.authorized_image_digests, tuple):
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                "authorized_image_digests must be a tuple of image digests",
            )
        for image_digest in self.authorized_image_digests:
            try:
                ImageDigestV1.parse(image_digest)
            except DigestEncodingError as error:
                raise _refused(
                    RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                    f"{image_digest!r} is not a canonical image digest: {error}",
                ) from error

        object.__setattr__(
            self, "target_provenance", _require_provenance(self.target_provenance)
        )
        object.__setattr__(
            self,
            "desired_state_provenance",
            _require_provenance(self.desired_state_provenance),
        )
        object.__setattr__(
            self, "profile_provenance", _require_provenance(self.profile_provenance)
        )
        object.__setattr__(
            self,
            "authorized_images_provenance",
            _require_provenance(self.authorized_images_provenance),
        )
        object.__setattr__(
            self,
            "execution_plan_provenance",
            _require_provenance(self.execution_plan_provenance),
        )

        for provenance, reason, name in (
            (self.target_provenance, self.target_override_reason, "target"),
            (
                self.desired_state_provenance,
                self.desired_state_override_reason,
                "desired_state",
            ),
            (self.profile_provenance, self.profile_override_reason, "profile"),
            (
                self.authorized_images_provenance,
                self.authorized_images_override_reason,
                "authorized_images",
            ),
            (
                self.execution_plan_provenance,
                self.execution_plan_override_reason,
                "execution_plan",
            ),
        ):
            if provenance is A6ProvenanceKind.OVERRIDE:
                if not isinstance(reason, str) or not reason.strip():
                    raise _refused(
                        RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED,
                        f"{name}_provenance is OVERRIDE and requires a "
                        f"non-empty {name}_override_reason; an override with "
                        "no reason is itself a defect",
                    )
            elif reason is not None:
                raise _refused(
                    RehearsalIssuerAuthorizationRefusalCode.PROVENANCE_MALFORMED,
                    f"{name}_provenance is DERIVED and carries "
                    f"{name}_override_reason={reason!r}; a reason with "
                    "nothing to explain is itself a defect",
                )

        if not (self.not_before <= self.issued_at < self.expires_at):
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                "the authorized window is not not_before <= issued_at < "
                f"expires_at ({self.not_before}, {self.issued_at}, "
                f"{self.expires_at})",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": REHEARSAL_ISSUER_AUTHORIZATION_SCHEMA,
            "version": REHEARSAL_ISSUER_AUTHORIZATION_VERSION,
            "purpose": self.purpose,
            "authorization_id": self.authorization_id,
            "immutable_reference": self.immutable_reference,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "target_provenance": self.target_provenance.value,
            "target_override_reason": self.target_override_reason,
            "desired_state_digest": self.desired_state_digest,
            "desired_state_provenance": self.desired_state_provenance.value,
            "desired_state_override_reason": self.desired_state_override_reason,
            "profile_digest": self.profile_digest,
            "profile_provenance": self.profile_provenance.value,
            "profile_override_reason": self.profile_override_reason,
            "authorized_image_digests": list(self.authorized_image_digests),
            "authorized_images_provenance": self.authorized_images_provenance.value,
            "authorized_images_override_reason": (
                self.authorized_images_override_reason
            ),
            "execution_plan_digest": self.execution_plan_digest,
            "execution_plan_provenance": self.execution_plan_provenance.value,
            "execution_plan_override_reason": self.execution_plan_override_reason,
            "controller_fingerprint": self.controller_fingerprint,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
            "lease_id": self.lease_id,
            "single_use_reference": self.single_use_reference,
            "environment": self.environment,
            "not_before": _timestamp(self.not_before),
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "control_version": self.control_version,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_mapping(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @property
    def subject(self) -> RehearsalIssuerAuthorizationSubject:
        return RehearsalIssuerAuthorizationSubject(
            immutable_reference=self.immutable_reference,
            target_id=self.target_id,
            target_ref=self.target_ref,
            desired_state_digest=self.desired_state_digest,
            profile_digest=self.profile_digest,
            authorized_image_digests=self.authorized_image_digests,
            execution_plan_digest=self.execution_plan_digest,
            controller_fingerprint=self.controller_fingerprint,
            environment=self.environment,
            signer_public_key_fingerprint=self.public_key_fingerprint,
        )


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationV1:
    """A parsed rehearsal-issuer authorization. Only `.parse()` or issuance
    produce one."""

    statement: RehearsalIssuerAuthorizationStatementV1
    signature: str

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @classmethod
    def parse(cls, value: object) -> RehearsalIssuerAuthorizationV1:
        """The ONE place bytes become this type."""
        if not isinstance(value, Mapping):
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                "a rehearsal-issuer authorization must be a mapping, got "
                f"{type(value).__name__}",
            )
        if set(value) != {"statement", "signature"}:
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
                "a rehearsal-issuer authorization envelope has exactly "
                f"statement and signature; got {sorted(str(key) for key in value)}",
            )
        signature = value["signature"]
        if not isinstance(signature, str) or not signature.strip():
            raise _refused(
                RehearsalIssuerAuthorizationRefusalCode.UNSIGNED,
                "the rehearsal-issuer authorization carries no signature",
            )
        return cls(statement=_parse_statement(value["statement"]), signature=signature)


_STATEMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "authorization_id",
        "immutable_reference",
        "target_id",
        "target_ref",
        "target_provenance",
        "target_override_reason",
        "desired_state_digest",
        "desired_state_provenance",
        "desired_state_override_reason",
        "profile_digest",
        "profile_provenance",
        "profile_override_reason",
        "authorized_image_digests",
        "authorized_images_provenance",
        "authorized_images_override_reason",
        "execution_plan_digest",
        "execution_plan_provenance",
        "execution_plan_override_reason",
        "controller_fingerprint",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
        "lease_id",
        "single_use_reference",
        "environment",
        "not_before",
        "issued_at",
        "expires_at",
        "control_version",
    }
)


def _parse_statement(value: object) -> RehearsalIssuerAuthorizationStatementV1:
    if not isinstance(value, Mapping):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            "a rehearsal-issuer authorization statement must be a mapping, "
            f"got {type(value).__name__}",
        )
    row: Mapping[str, Any] = value
    # SCHEMA FIRST, before any field is read.
    if row.get("schema") != REHEARSAL_ISSUER_AUTHORIZATION_SCHEMA:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.SCHEMA_MISMATCH,
            f"{row.get('schema')!r} is not "
            f"{REHEARSAL_ISSUER_AUTHORIZATION_SCHEMA!r}. This authorization is "
            "for the rehearsal issuer alone; no other document becomes one by "
            "carrying a matching field",
        )
    if row.get("version") != REHEARSAL_ISSUER_AUTHORIZATION_VERSION:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.SCHEMA_MISMATCH,
            "unsupported rehearsal-issuer authorization version "
            f"{row.get('version')!r}",
        )
    keys = set(row)
    missing = sorted(_STATEMENT_KEYS - keys)
    unexpected = sorted(str(key) for key in keys - _STATEMENT_KEYS)
    if missing or unexpected:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            "rehearsal-issuer authorization statement keys differ: "
            f"missing={missing}, unexpected={unexpected}",
        )

    images = row.get("authorized_image_digests")
    if not isinstance(images, list) or not all(
        isinstance(digest, str) for digest in images
    ):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.MALFORMED,
            "authorized_image_digests must be a list of strings",
        )

    return RehearsalIssuerAuthorizationStatementV1(
        authorization_id=_text(row.get("authorization_id"), "authorization_id"),
        immutable_reference=_text(
            row.get("immutable_reference"), "immutable_reference"
        ),
        target_id=_text(row.get("target_id"), "target_id"),
        target_ref=_text(row.get("target_ref"), "target_ref"),
        target_provenance=_require_provenance(row.get("target_provenance")),
        target_override_reason=_optional_text(
            row.get("target_override_reason"), "target_override_reason"
        ),
        desired_state_digest=_text(
            row.get("desired_state_digest"), "desired_state_digest"
        ),
        desired_state_provenance=_require_provenance(
            row.get("desired_state_provenance")
        ),
        desired_state_override_reason=_optional_text(
            row.get("desired_state_override_reason"),
            "desired_state_override_reason",
        ),
        profile_digest=_text(row.get("profile_digest"), "profile_digest"),
        profile_provenance=_require_provenance(row.get("profile_provenance")),
        profile_override_reason=_optional_text(
            row.get("profile_override_reason"), "profile_override_reason"
        ),
        authorized_image_digests=tuple(images),
        authorized_images_provenance=_require_provenance(
            row.get("authorized_images_provenance")
        ),
        authorized_images_override_reason=_optional_text(
            row.get("authorized_images_override_reason"),
            "authorized_images_override_reason",
        ),
        execution_plan_digest=_text(
            row.get("execution_plan_digest"), "execution_plan_digest"
        ),
        execution_plan_provenance=_require_provenance(
            row.get("execution_plan_provenance")
        ),
        execution_plan_override_reason=_optional_text(
            row.get("execution_plan_override_reason"),
            "execution_plan_override_reason",
        ),
        controller_fingerprint=_text(
            row.get("controller_fingerprint"), "controller_fingerprint"
        ),
        key_id=_text(row.get("key_id"), "key_id"),
        algorithm=_text(row.get("algorithm"), "algorithm"),
        public_key_fingerprint=_text(
            row.get("public_key_fingerprint"), "public_key_fingerprint"
        ),
        lease_id=_text(row.get("lease_id"), "lease_id"),
        single_use_reference=_text(
            row.get("single_use_reference"), "single_use_reference"
        ),
        environment=_text(row.get("environment"), "environment"),
        not_before=_instant(row, "not_before"),
        issued_at=_instant(row, "issued_at"),
        expires_at=_instant(row, "expires_at"),
        control_version=_text(row.get("control_version"), "control_version"),
        purpose=_text(row.get("purpose"), "purpose"),
    )


@dataclass(frozen=True, slots=True)
class RehearsalIssuerAuthorizationStandingResult:
    """What this authorization is NOW, and — when it is not authority — which
    term failed."""

    standing: RehearsalIssuerAuthorizationStanding
    refusal: RehearsalIssuerAuthorizationRefusalCode | None = None

    @property
    def authorizes(self) -> bool:
        """The ONE question a surface may ask. Derived, never a stored flag."""
        return self.standing is RehearsalIssuerAuthorizationStanding.VALID


def issue_rehearsal_issuer_authorization(
    statement: RehearsalIssuerAuthorizationStatementV1,
    *,
    signer: RehearsalIssuerAuthorizationSigner,
) -> RehearsalIssuerAuthorizationV1:
    """Sign a rehearsal-issuer authorization. Takes the TYPE, never a mapping."""
    if not isinstance(signer, RehearsalIssuerAuthorizationSigner):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement rehearsal-issuer-"
            "authorization signing",
        )
    identity = signer.rehearsal_issuer_identity
    if not isinstance(identity, RehearsalIssuerAuthorizationSignerIdentity):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose a rehearsal-issuer identity",
        )
    if identity.public_key_fingerprint != statement.public_key_fingerprint:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.SIGNER_PURPOSE_REUSED,
            "the statement names a different key than the signer holds",
        )
    signed = signer.sign_rehearsal_issuer_authorization(statement.canonical_bytes())
    if not signed.signature.strip():
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.UNSIGNED,
            "the rehearsal-issuer signer returned an empty signature",
        )
    return RehearsalIssuerAuthorizationV1(
        statement=statement, signature=signed.signature
    )


def verify_rehearsal_issuer_authorization(
    value: object,
    *,
    verifier: RehearsalIssuerAuthorizationVerifier,
    subject: RehearsalIssuerAuthorizationSubject,
    at: datetime | None = None,
    revoked_authorization_ids: frozenset[str] = frozenset(),
    consumed_references: frozenset[str] = frozenset(),
) -> RehearsalIssuerAuthorizationV1:
    """Authority for THIS rehearsal issuer's lease, or a refusal naming the
    term that failed.

    Order is deliberate, mirroring `rehearsal_grant.verify_rehearsal_grant`:
    authenticity first, so a forged document never earns field-level
    diagnostics about what it would have had to say. Then the window,
    revocation and the per-lease replay coordinate, which are properties of
    the authorization itself. Then the subject, term by term, each with its
    own code — presence is not matching.
    """
    if not isinstance(verifier, RehearsalIssuerAuthorizationVerifier):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement rehearsal-issuer-"
            "authorization verification",
        )
    envelope = RehearsalIssuerAuthorizationV1.parse(value)
    statement = envelope.statement
    if not verifier.verify_rehearsal_issuer_authorization(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes(),
        signature=envelope.signature,
    ):
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.SIGNATURE_INVALID,
            "the rehearsal-issuer authorization signature does not verify "
            "over its canonical bytes",
        )

    now = _aware_utc(at or datetime.now(UTC), field="at")
    if now < statement.not_before:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.NOT_YET_VALID,
            f"the authorized window opens at {_timestamp(statement.not_before)}",
        )
    if now >= statement.expires_at:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.EXPIRED,
            f"the authorized window closed at {_timestamp(statement.expires_at)}",
        )
    if statement.authorization_id in revoked_authorization_ids:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.REVOKED,
            f"rehearsal-issuer authorization {statement.authorization_id} was "
            "revoked",
        )
    if statement.single_use_reference in consumed_references:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.ALREADY_CONSUMED,
            f"replay coordinate {statement.single_use_reference} has already "
            "been spent for this lease. A second presentation of the same "
            "document is a second execution authority",
        )

    if subject.environment != REHEARSAL_ONLY_ENVIRONMENT:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.NOT_A_REHEARSAL_ENVIRONMENT,
            f"environment must be {REHEARSAL_ONLY_ENVIRONMENT!r}, not "
            f"{subject.environment!r}",
        )
    if statement.immutable_reference != subject.immutable_reference:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.CANDIDATE_MISMATCH,
            "the authorization names immutable_reference="
            f"{statement.immutable_reference!r} and this rehearsal is of "
            f"{subject.immutable_reference!r}",
        )
    if statement.public_key_fingerprint != subject.signer_public_key_fingerprint:
        raise _refused(
            RehearsalIssuerAuthorizationRefusalCode.SIGNER_MISMATCH,
            "the authorization was signed by "
            f"{statement.public_key_fingerprint!r} and this rehearsal "
            f"expects {subject.signer_public_key_fingerprint!r}",
        )
    for field, code in (
        ("target_id", RehearsalIssuerAuthorizationRefusalCode.TARGET_MISMATCH),
        ("target_ref", RehearsalIssuerAuthorizationRefusalCode.TARGET_MISMATCH),
        (
            "desired_state_digest",
            RehearsalIssuerAuthorizationRefusalCode.DESIRED_STATE_MISMATCH,
        ),
        ("profile_digest", RehearsalIssuerAuthorizationRefusalCode.PROFILE_MISMATCH),
        (
            "authorized_image_digests",
            RehearsalIssuerAuthorizationRefusalCode.IMAGE_MISMATCH,
        ),
        (
            "execution_plan_digest",
            RehearsalIssuerAuthorizationRefusalCode.EXECUTION_PLAN_MISMATCH,
        ),
        (
            "controller_fingerprint",
            RehearsalIssuerAuthorizationRefusalCode.CONTROLLER_MISMATCH,
        ),
    ):
        bound = getattr(statement, field)
        asked = getattr(subject, field)
        if bound != asked:
            raise _refused(
                code,
                f"the authorization binds {field}={bound!r} and this "
                f"rehearsal is {field}={asked!r}",
            )
    return envelope


def rehearsal_issuer_standing(
    value: object | None,
    *,
    verifier: RehearsalIssuerAuthorizationVerifier,
    subject: RehearsalIssuerAuthorizationSubject,
    at: datetime | None = None,
    revoked_authorization_ids: frozenset[str] = frozenset(),
    consumed_references: frozenset[str] = frozenset(),
) -> RehearsalIssuerAuthorizationStandingResult:
    """What a surface may display, derived from the authorization and nothing
    else. `None` is ABSENT — nobody has authorized a rehearsal issuer for this
    lease."""
    if value is None:
        return RehearsalIssuerAuthorizationStandingResult(
            RehearsalIssuerAuthorizationStanding.ABSENT
        )
    try:
        verify_rehearsal_issuer_authorization(
            value,
            verifier=verifier,
            subject=subject,
            at=at,
            revoked_authorization_ids=revoked_authorization_ids,
            consumed_references=consumed_references,
        )
    except RehearsalIssuerAuthorizationRefusedError as refused:
        mapped = {
            RehearsalIssuerAuthorizationRefusalCode.NOT_YET_VALID: (
                RehearsalIssuerAuthorizationStanding.NOT_YET_VALID
            ),
            RehearsalIssuerAuthorizationRefusalCode.EXPIRED: (
                RehearsalIssuerAuthorizationStanding.EXPIRED
            ),
            RehearsalIssuerAuthorizationRefusalCode.REVOKED: (
                RehearsalIssuerAuthorizationStanding.REVOKED
            ),
            RehearsalIssuerAuthorizationRefusalCode.ALREADY_CONSUMED: (
                RehearsalIssuerAuthorizationStanding.CONSUMED
            ),
        }.get(refused.code, RehearsalIssuerAuthorizationStanding.UNRESOLVED)
        return RehearsalIssuerAuthorizationStandingResult(mapped, refused.code)
    return RehearsalIssuerAuthorizationStandingResult(
        RehearsalIssuerAuthorizationStanding.VALID
    )
