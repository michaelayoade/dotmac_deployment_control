"""A rehearsal is authorized by its own grant, and its subject is a REFUSAL.

## The act this exists for, stated before the design

Lane 3 item 8 is *"Rollback, provoked rather than simulated"*, and the
rehearsal document spells out what that means: *"apply a plan whose
verification must fail, and show the transaction restores the pre-change
snapshot."* The act deliberately breaks something so that a refusal fires.

Until this module the only authorization Control could issue for it was a
`deploy`. That is not a small mismatch. A production deployment authorization
would have been issued for an act whose entire purpose is to fail — and every
link in the chain would have been correct: a real approval, a real plan digest,
a real replay coordinate, a real signed result. The Foundation's own withdrawal
note names this exact shape and names it worse than a gap:

    A grant, a replay coordinate, a Control settlement and a signed result
    wrapped around an isolated rehearsal is a chain whose every link is correct
    and whose SUBJECT is the wrong act — and it would read as done.

## Why this is not a `rehearse` member of `DeploymentOperation`

That note was written when `recover` was added to the Foundation's `OPERATIONS`
tuple and withdrawn one commit later, and its conclusion is the rule this module
obeys: *"An executor existing is not the test; an executor for THE NAMED ACT
is."* Adding `rehearse` beside `deploy` and `rollback` would name an act in the
deployment vocabulary and then reach the deployment executor, the deployment
receipt shape, and `settle_attempt` — all of which are built for an act that is
supposed to SUCCEED. A rehearsal that succeeds is a rehearsal that failed.

So this is a different document, exactly as `recovery_grant.py` is, and for the
same stated reason: the type identifies the act, `schema` refuses every other
document before a field is read, and `purpose` binds a signer to rehearsals
alone. There is deliberately NO `operation` field here.

## `authorized_provocation` — a named act, not a mode

This is the field that decides whether the design is right, so it is worth
being explicit about what it is not.

A grant that said *"you may deploy, and by the way this one is a rehearsal"* is
a boolean wearing a type. It would authorize an act that MAY succeed, with a
note attached. The distinguishing property here is the opposite one:

**a rehearsal grant authorizes an act that must END IN A REFUSAL, and the
refusal is named.** :class:`AuthorizedProvocationV1` binds WHICH refusal
(:class:`ProvocableRefusal`, closed) and WHERE it may be provoked (a step from
the counterparty's published step vocabulary, mirrored below). The terminal
disposition is DERIVED from the refusal rather than declared beside it, so no
grant can carry a refusal and a terminal that disagree.

A grant cannot exist without a provocation: it is a required, undefaulted
field, its absence is `MALFORMED`, and a statement whose refusal or step is
outside the two closed sets is refused at parse. There is no "ordinary
rehearsal" shape this type can take.

## The vocabulary is closed at ONE refusal, and that is a statement

:class:`ProvocableRefusal` has a single member today. That is not a placeholder
and not the boolean returning by another door — the boolean is defeated by the
document being a different document with a different signer and a terminal
disposition a deploy grant cannot express. It is closed at one because exactly
one provocation is grounded in a published Lane 3 item and a published
counterparty step. A second member is a coordinated change to both systems, on
the same terms `operations.py` sets for its own vocabulary, and inventing one
here would be naming an act on the strength of something other than evidence
that it is performed.

## Binding is by comparison, never by presence

Every subject term — target, candidate artifact, execution plan digest, and the
provocation itself — is compared against what the caller states it is about to
rehearse, term by term, each with its own refusal code. A grant that CARRIES a
provocation is not thereby a grant FOR that provocation.

## Single use

`single_use_reference` is the replay coordinate. A re-presentable grant is a
second execution authority, so it is bound into the signed statement and
compared against a set of already-consumed references the CALLER supplies.

**Say plainly what that does and does not establish.** This module is pure and
performs no I/O, in common with every other module here, so it refuses a
reference it is TOLD was consumed. It cannot itself know. The durable record of
consumption — and therefore the actual at-most-once property — belongs to
whoever holds the store, and no such store exists in this repository today.
Until one does, the coordinate is bindable and reviewable and the region behind
it is UNMONITORED rather than covered.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.digests import ExecutionPlanDigestV1
from dotmac_deployment_control.ports import DeploymentControlError, DigestEncodingError

__all__ = [
    "FOUNDATION_STEP_KINDS",
    "FOUNDATION_STEP_KIND_SOURCE",
    "REHEARSAL_GRANT_SCHEMA",
    "REHEARSAL_GRANT_VERSION",
    "REHEARSAL_PURPOSE",
    "AuthorizedProvocationV1",
    "CandidateArtifactRef",
    "ProvocableRefusal",
    "ProvokedTerminal",
    "RehearsalGrantRefusalCode",
    "RehearsalGrantRefusedError",
    "RehearsalGrantSignature",
    "RehearsalGrantSigner",
    "RehearsalGrantSignerIdentity",
    "RehearsalGrantStatementV1",
    "RehearsalGrantV1",
    "RehearsalGrantVerifier",
    "RehearsalStanding",
    "RehearsalStandingResult",
    "RehearsalSubject",
    "issue_rehearsal_grant",
    "rehearsal_standing",
    "verify_rehearsal_grant",
]

#: The signer purpose. Separated from `deployment_authorization`,
#: `deployment_dispatch`, `target_execution_observation` and
#: `deployment_recovery` for the reason all of them are separated: one key
#: answering two questions cannot be used to contradict itself. A rehearsal
#: signer is the sharpest case of that rule — the key that authorizes an act
#: which must fail must not be the key that authorizes production.
REHEARSAL_PURPOSE: Final = "deployment_rehearsal"
REHEARSAL_GRANT_SCHEMA: Final = "dotmac.deployment_control.rehearsal_grant"
REHEARSAL_GRANT_VERSION: Final = 1

_MAX_TEXT = 512

#: Where the mirrored step vocabulary below was read from.
#:
#: `<repository>@<commit>:<path>`, an immutable coordinate rather than a branch,
#: on the same rule `counterparty.py` states: a claim about SOURCE at a commit,
#: deliberately not a claim about a published wheel.
FOUNDATION_STEP_KIND_SOURCE: Final = (
    "michaelayoade/dotmac_starter_mt"
    "@98435a0c076d4e62f4d6e2c486a3f4ff81290a6d"
    ":packages/dotmac-deployment-foundation/src/"
    "dotmac_deployment_foundation/engine/plan.py"
)

#: THE COUNTERPARTY'S PUBLISHED STEP VOCABULARY, MIRRORED.
#:
#: Foundation owns `StepKind`; this is where a provocation says WHERE. Control
#: does not depend on `dotmac-deployment-foundation` and must not start — they
#: are released independently — so every cross-repository coupling is cut at a
#: VALUE, exactly as `recovery_grant.PRESTATE_DISCRIMINATOR` and
#: `counterparty.EXECUTOR_OPERATIONS` are.
#:
#: WHAT PROTECTS THIS MIRROR, AND WHAT DOES NOT. Nothing in this repository's CI
#: compares these strings against their source, because the Foundation is not
#: installed here — and the alternative usually chosen, import-it-if-present,
#: is worse than nothing: a guard that skips is a guard that is off, and it
#: would be off for exactly the releases that needed it. So the closure below
#: always runs against the literal, and
#: `tests/unit/test_rehearsal_grant.py::test_the_step_vocabulary_matches_the_
#: installed_executor_when_one_is_present` compares it wherever the Foundation
#: IS importable. A transcription error at authoring time is caught by that
#: comparison and by nothing else.
#:
#: A step ABSENT here is refused rather than passed through. Accepting an
#: unknown step would let a grant name a place the executor has no step for,
#: which is the same defect as naming an operation no executor performs.
FOUNDATION_STEP_KINDS: Final[frozenset[str]] = frozenset(
    {
        "acquire_lock",
        "verify_image",
        "verify_revision",
        "verify_manifest",
        "verify_release_evidence",
        "refuse_dirty_state",
        "verify_materials",
        "verify_external_recovery_receipt",
        "product_preflight",
        "backup",
        "verify_backup",
        "migration_preflight",
        "stop_for_maintenance",
        "migrate",
        "verify_heads",
        "start_candidate",
        "gate_candidate",
        "switch",
        "verify_roles",
        "stabilise",
        "product_postflight",
        "bootstrap_principals",
        "record_evidence",
        "prune_images",
        "release_lock",
    }
)


class ProvokedTerminal(StrEnum):
    """How a provoked rehearsal must END for the grant to have been honoured.

    DERIVED from the refusal through `_TERMINAL_OF`, never declared beside it.
    A statement that carried both could carry two that disagree, and the
    disagreement would be about the only thing this grant is for.
    """

    #: The provoked refusal fired and the transaction restored the pre-change
    #: state. This is the rehearsal SUCCEEDING.
    ROLLED_BACK = "rolled_back"


class ProvocableRefusal(StrEnum):
    """Which refusal a rehearsal may deliberately provoke. Closed, one member.

    Read the module docstring before adding a member: a second one is a
    coordinated change to both systems, and it needs a published gate item and
    a published counterparty step, not an intention.
    """

    #: Lane 3 item 8, `provoked_rollback`: *"apply a plan whose verification
    #: must fail, and show the transaction restores the pre-change snapshot."*
    #: The named act is the VERIFICATION REFUSING; the rollback is what the
    #: refusal must produce, which is why the terminal is derived and not a
    #: second name for the same thing.
    PLAN_VERIFICATION_REFUSAL = "plan_verification_refusal"


_TERMINAL_OF: Final[Mapping[ProvocableRefusal, ProvokedTerminal]] = {
    ProvocableRefusal.PLAN_VERIFICATION_REFUSAL: ProvokedTerminal.ROLLED_BACK,
}


class RehearsalGrantRefusalCode(StrEnum):
    """Why a rehearsal grant does not authorize the rehearsal in hand.

    One code per binding, so a caller is told WHICH term disagreed rather than
    being sent round the loop once per field.
    """

    MALFORMED = "rehearsal_grant_malformed"
    #: The document is not a rehearsal grant. This is how a deployment
    #: authorization is refused, and it fires before any field is compared.
    SCHEMA_MISMATCH = "rehearsal_grant_schema_mismatch"
    PURPOSE_MISMATCH = "rehearsal_grant_purpose_mismatch"
    SIGNER_PURPOSE_REUSED = "rehearsal_grant_signer_purpose_reused"
    UNSIGNED = "rehearsal_grant_unsigned"
    SIGNATURE_INVALID = "rehearsal_grant_signature_invalid"
    PRODUCT_MISMATCH = "rehearsal_grant_product_mismatch"
    TARGET_MISMATCH = "rehearsal_grant_target_mismatch"
    ENVIRONMENT_MISMATCH = "rehearsal_grant_environment_mismatch"
    CANDIDATE_MISMATCH = "rehearsal_grant_candidate_mismatch"
    EXECUTION_PLAN_MISMATCH = "rehearsal_grant_execution_plan_mismatch"
    #: The grant authorizes a different refusal, or the same refusal somewhere
    #: else. Distinct from every other mismatch because it is the one that says
    #: the wrong ACT was authorized rather than the wrong subject.
    PROVOCATION_MISMATCH = "rehearsal_grant_provocation_mismatch"
    #: The grant names a refusal or a step this version cannot honour. The
    #: repair is a coordinated VERSION, not a re-issue: authorizing a
    #: provocation under rules this version does not have is not authorizing.
    PROVOCATION_UNKNOWN = "rehearsal_grant_provocation_unknown"
    APPROVAL_NOT_STANDING = "rehearsal_grant_approval_not_standing"
    NOT_YET_VALID = "rehearsal_grant_not_yet_valid"
    EXPIRED = "rehearsal_grant_expired"
    REVOKED = "rehearsal_grant_revoked"
    #: The replay coordinate has already been spent. A re-presentable grant is a
    #: second execution authority.
    ALREADY_CONSUMED = "rehearsal_grant_already_consumed"


class RehearsalGrantRefusedError(DeploymentControlError):
    """A rehearsal grant that does not authorize the act in hand, and why."""

    def __init__(self, code: RehearsalGrantRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(
    code: RehearsalGrantRefusalCode, detail: str
) -> RehearsalGrantRefusedError:
    return RehearsalGrantRefusedError(code, detail)


class RehearsalStanding(StrEnum):
    """What a grant is RIGHT NOW, as distinct from whether it ever verified.

    `ABSENT` is a claim and not a failure: nobody has authorized a rehearsal for
    this target. It is distinguishable from `CONSUMED`, `REVOKED` and `EXPIRED`
    on purpose — an operator seeing "unavailable" needs to know whether nobody
    authorized one, one was already spent, somebody withdrew one, or one ran out
    of time, because those are four different next actions.
    """

    VALID = "valid"
    ABSENT = "absent"
    #: A grant exists and does not resolve to authority for THIS rehearsal — a
    #: bad signature, a binding that names something else, an approval that no
    #: longer stands.
    UNRESOLVED = "unresolved"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"
    CONSUMED = "consumed"


@dataclass(frozen=True, slots=True)
class RehearsalGrantSignerIdentity:
    """The rehearsal signer, which must be none of the other four."""

    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = REHEARSAL_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != REHEARSAL_PURPOSE:
            raise _refused(
                RehearsalGrantRefusalCode.PURPOSE_MISMATCH,
                f"a rehearsal signer must declare {REHEARSAL_PURPOSE!r}, not "
                f"{self.purpose!r}",
            )


@dataclass(frozen=True, slots=True)
class RehearsalGrantSignature:
    key_id: str
    algorithm: str
    purpose: str
    public_key_fingerprint: str
    signature: str


@runtime_checkable
class RehearsalGrantSigner(Protocol):
    """Control-side rehearsal signer.

    Its members share no name with the authorization, dispatch, observation or
    recovery signers, so one cannot be passed where another is expected even by
    accident.
    """

    @property
    def rehearsal_identity(self) -> RehearsalGrantSignerIdentity: ...

    def sign_rehearsal(self, canonical_bytes: bytes) -> RehearsalGrantSignature: ...


@runtime_checkable
class RehearsalGrantVerifier(Protocol):
    """Verifier for the rehearsal purpose only."""

    def verify_rehearsal(
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
class CandidateArtifactRef:
    """The bytes the rehearsal is OF, by run and artifact id.

    Michael's terms. An artifact id is unique only within the repository that
    ran the workflow, so the repository is part of the identity rather than
    context — the pair alone names nothing.

    THE IDENTITY GAP THIS DOES NOT CLOSE, stated rather than left for a reader
    to discover. The counterparty's `RehearsalReceipt.v1` identifies the bytes
    it executed by `foundation_artifact_digest`, a sha256, and carries no run or
    artifact id at all. So this reference and that receipt cannot be compared
    directly; the mapping between them lives in the candidate's own
    `CandidateArtifact.v1`, which records `repository`, `run_id`, `artifact_id`
    and `sha256` together. Whether the grant should ALSO bind the digest — or
    whether binding both would give one artifact two identities, which is the
    defect this codebase has paid for before — is an open decision and is not
    taken here.
    """

    repository: str
    run_id: str
    artifact_id: str


@dataclass(frozen=True, slots=True)
class AuthorizedProvocationV1:
    """WHICH refusal may be provoked, and WHERE. Required; never a mode.

    The grant's subject. A rehearsal grant without one cannot be constructed,
    parsed or issued — see the module docstring for why "you may deploy, and by
    the way this one is a rehearsal" is the shape being refused.
    """

    refusal: ProvocableRefusal
    #: A member of `FOUNDATION_STEP_KINDS`. Held as text rather than an enum
    #: because Control does not own it and must not appear to.
    at_step: str

    def __post_init__(self) -> None:
        if not isinstance(self.refusal, ProvocableRefusal):
            raise _refused(
                RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN,
                f"{self.refusal!r} is not a provocable refusal; this version "
                f"knows {sorted(member.value for member in ProvocableRefusal)}",
            )
        if self.at_step not in FOUNDATION_STEP_KINDS:
            raise _refused(
                RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN,
                f"{self.at_step!r} is not a step the executor publishes. Its "
                f"step vocabulary was read from {FOUNDATION_STEP_KIND_SOURCE}. "
                "A provocation at a step nothing performs is an authorization "
                "for a place that does not exist",
            )

    @property
    def expected_terminal(self) -> ProvokedTerminal:
        """DERIVED. A rehearsal that ends any other way was not authorized.

        This is the property that makes the grant a named act rather than a
        flag: a deployment authorization permits an act that may succeed, and
        this one requires an act that must refuse.
        """
        return _TERMINAL_OF[self.refusal]


@dataclass(frozen=True, slots=True)
class RehearsalSubject:
    """What the caller says it is about to rehearse.

    Stated by the caller and compared against the signed grant term by term.
    """

    product_code: str
    target_id: str
    target_ref: str
    environment: str
    candidate: CandidateArtifactRef
    execution_plan_digest: str
    provocation: AuthorizedProvocationV1


@dataclass(frozen=True, slots=True)
class RehearsalGrantStatementV1:
    """The signed terms. No `operation`: the schema identifies the act."""

    grant_id: str
    #: The replay coordinate. One rehearsal per grant; see the module docstring
    #: for what this establishes here and what it leaves to a store.
    single_use_reference: str
    product_code: str
    target_id: str
    target_ref: str
    environment: str
    candidate_repository: str
    candidate_run_id: str
    candidate_artifact_id: str
    #: `ExecutionPlanDigestV1` — the counterparty's execution plan digest, so
    #: the middle term is real here too. Parsed with that exact type, which is
    #: strict and has no `over_json`: Control never recomputes this value.
    execution_plan_digest: str
    provocation_refusal: ProvocableRefusal
    provocation_at_step: str
    #: The lease under which the rehearsal may run. A rehearsal authorization
    #: must not outlive its window, and the window has two halves: the lease the
    #: target holds and the expiry on this document.
    lease_id: str
    approval_policy_code: str
    approval_policy_version: int
    approval_decision_ref: str
    approval_decision_status: str
    approved_at: datetime
    not_before: datetime
    issued_at: datetime
    expires_at: datetime
    control_version: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = REHEARSAL_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != REHEARSAL_PURPOSE:
            raise _refused(
                RehearsalGrantRefusalCode.PURPOSE_MISMATCH,
                f"a rehearsal grant statement must declare {REHEARSAL_PURPOSE!r}",
            )
        if not str(self.single_use_reference).strip():
            raise _refused(
                RehearsalGrantRefusalCode.MALFORMED,
                "single_use_reference is empty. A grant with no replay "
                "coordinate is re-presentable, and a re-presentable grant is a "
                "second execution authority",
            )
        # Constructing the provocation is the validation: it refuses an unknown
        # refusal and an unpublished step, and there is no route to a statement
        # that skips it.
        object.__setattr__(
            self,
            "provocation_refusal",
            _require_refusal(self.provocation_refusal),
        )
        _ = AuthorizedProvocationV1(
            refusal=self.provocation_refusal, at_step=self.provocation_at_step
        )
        try:
            ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        except DigestEncodingError as error:
            raise _refused(
                RehearsalGrantRefusalCode.MALFORMED,
                f"execution_plan_digest is not a canonical execution plan "
                f"digest: {error}",
            ) from error
        if not (self.not_before <= self.issued_at < self.expires_at):
            raise _refused(
                RehearsalGrantRefusalCode.MALFORMED,
                "the authorized window is not not_before <= issued_at < "
                f"expires_at ({self.not_before}, {self.issued_at}, "
                f"{self.expires_at})",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": REHEARSAL_GRANT_SCHEMA,
            "version": REHEARSAL_GRANT_VERSION,
            "purpose": self.purpose,
            "grant_id": self.grant_id,
            "single_use_reference": self.single_use_reference,
            "product_code": self.product_code,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "environment": self.environment,
            "candidate_repository": self.candidate_repository,
            "candidate_run_id": self.candidate_run_id,
            "candidate_artifact_id": self.candidate_artifact_id,
            "execution_plan_digest": self.execution_plan_digest,
            "provocation_refusal": self.provocation_refusal.value,
            "provocation_at_step": self.provocation_at_step,
            # DERIVED and EMITTED. A verifier on the other side of the wire
            # cannot reach `_TERMINAL_OF`, and the whole point of the grant is
            # that the authorized act must end in a refusal — so the terminal
            # travels with the document. It is written from the derivation, so
            # it can never disagree with the refusal it accompanies, and it is
            # re-derived rather than read back on parse.
            "expected_terminal": _TERMINAL_OF[self.provocation_refusal].value,
            "lease_id": self.lease_id,
            "approval_policy_code": self.approval_policy_code,
            "approval_policy_version": self.approval_policy_version,
            "approval_decision_ref": self.approval_decision_ref,
            "approval_decision_status": self.approval_decision_status,
            "approved_at": _timestamp(self.approved_at),
            "not_before": _timestamp(self.not_before),
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "control_version": self.control_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_mapping(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")

    @property
    def provocation(self) -> AuthorizedProvocationV1:
        return AuthorizedProvocationV1(
            refusal=self.provocation_refusal, at_step=self.provocation_at_step
        )

    @property
    def candidate(self) -> CandidateArtifactRef:
        return CandidateArtifactRef(
            repository=self.candidate_repository,
            run_id=self.candidate_run_id,
            artifact_id=self.candidate_artifact_id,
        )

    @property
    def subject(self) -> RehearsalSubject:
        return RehearsalSubject(
            product_code=self.product_code,
            target_id=self.target_id,
            target_ref=self.target_ref,
            environment=self.environment,
            candidate=self.candidate,
            execution_plan_digest=self.execution_plan_digest,
            provocation=self.provocation,
        )


@dataclass(frozen=True, slots=True)
class RehearsalGrantV1:
    """A parsed rehearsal grant. The only way to hold one is to parse or issue it."""

    statement: RehearsalGrantStatementV1
    signature: str

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @classmethod
    def parse(cls, value: object) -> RehearsalGrantV1:
        """The ONE place bytes become this type."""
        if not isinstance(value, Mapping):
            raise _refused(
                RehearsalGrantRefusalCode.MALFORMED,
                f"a rehearsal grant must be a mapping, got {type(value).__name__}",
            )
        if set(value) != {"statement", "signature"}:
            raise _refused(
                RehearsalGrantRefusalCode.MALFORMED,
                "a rehearsal grant envelope has exactly statement and "
                f"signature; got {sorted(str(key) for key in value)}",
            )
        signature = value["signature"]
        if not isinstance(signature, str) or not signature.strip():
            raise _refused(
                RehearsalGrantRefusalCode.UNSIGNED,
                "the rehearsal grant carries no signature",
            )
        return cls(statement=_parse_statement(value["statement"]), signature=signature)


_STATEMENT_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "grant_id",
        "single_use_reference",
        "product_code",
        "target_id",
        "target_ref",
        "environment",
        "candidate_repository",
        "candidate_run_id",
        "candidate_artifact_id",
        "execution_plan_digest",
        "provocation_refusal",
        "provocation_at_step",
        "expected_terminal",
        "lease_id",
        "approval_policy_code",
        "approval_policy_version",
        "approval_decision_ref",
        "approval_decision_status",
        "approved_at",
        "not_before",
        "issued_at",
        "expires_at",
        "control_version",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
    }
)

#: EMPTY, AND DELIBERATELY SO. `recovery_grant.py` needed an optional-key set
#: because a term was added to a schema that had already shipped. Nothing has
#: shipped against this schema, so every key is required in both directions and
#: an absent term is a refusal rather than a historical row. The name exists so
#: the next person adding a term reaches for the right mechanism instead of
#: quietly loosening the key comparison.
_OPTIONAL_STATEMENT_KEYS: Final[frozenset[str]] = frozenset()


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"{field} must be a datetime, got {type(value).__name__}",
        )
    if value.tzinfo is None:
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"{field} is naive; an instant without a zone is not an instant",
        )
    return value.astimezone(UTC)


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"{field} must be non-empty text",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"{field} exceeds {_MAX_TEXT} characters",
        )
    return value


def _instant(row: Mapping[str, Any], field: str) -> datetime:
    value = row.get(field)
    if not isinstance(value, str):
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED, f"{field} must be an ISO instant"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED, f"{field} is not an instant: {error}"
        ) from error
    return _aware_utc(parsed, field=field)


def _require_refusal(value: object) -> ProvocableRefusal:
    """The ONE gate on the refusal word. No default, no case fold.

    `operations.py`'s argument, applied to this vocabulary: a default infers the
    act from silence, and a case fold gives one act two identities. Here the act
    is *which refusal a rehearsal is allowed to cause*, so an inference would be
    an inference about what is allowed to break.
    """
    if isinstance(value, ProvocableRefusal):
        return value
    known = sorted(member.value for member in ProvocableRefusal)
    if not isinstance(value, str) or value not in {
        member.value for member in ProvocableRefusal
    }:
        raise _refused(
            RehearsalGrantRefusalCode.PROVOCATION_UNKNOWN,
            f"{value!r} is not a refusal this control plane can authorize the "
            f"provocation of; it knows {known}. The vocabulary is closed "
            "because a rehearsal that provokes something nobody named is an "
            "unplanned outage with a signed document attached",
        )
    return ProvocableRefusal(value)


def _parse_statement(value: object) -> RehearsalGrantStatementV1:
    if not isinstance(value, Mapping):
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"a rehearsal grant statement must be a mapping, got "
            f"{type(value).__name__}",
        )
    row: Mapping[str, Any] = value
    # SCHEMA FIRST, before any field is read. This is what refuses a deployment
    # authorization presented as rehearsal authority, and a rehearsal grant
    # presented to the deployment verifier fails the same way in the other
    # direction.
    if row.get("schema") != REHEARSAL_GRANT_SCHEMA:
        raise _refused(
            RehearsalGrantRefusalCode.SCHEMA_MISMATCH,
            f"{row.get('schema')!r} is not {REHEARSAL_GRANT_SCHEMA!r}. A "
            "rehearsal is authorized by its own grant; no deployment "
            "authorization becomes one by carrying a matching field",
        )
    if row.get("version") != REHEARSAL_GRANT_VERSION:
        raise _refused(
            RehearsalGrantRefusalCode.SCHEMA_MISMATCH,
            f"unsupported rehearsal grant version {row.get('version')!r}",
        )
    keys = set(row)
    missing = sorted(_STATEMENT_KEYS - keys)
    unexpected = sorted(
        str(key) for key in keys - _STATEMENT_KEYS - _OPTIONAL_STATEMENT_KEYS
    )
    if missing or unexpected:
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            f"rehearsal grant statement keys differ: missing={missing}, "
            f"unexpected={unexpected}",
        )
    version = row.get("approval_policy_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _refused(
            RehearsalGrantRefusalCode.MALFORMED,
            "approval_policy_version must be a positive integer",
        )
    refusal = _require_refusal(row.get("provocation_refusal"))
    # RE-DERIVED, never read back. The document carries `expected_terminal` so a
    # verifier on the other side of the wire can see it; trusting the value it
    # carries would let a grant name a refusal and a terminal that disagree,
    # which is the one contradiction this type exists to make unwritable.
    carried = row.get("expected_terminal")
    if carried != _TERMINAL_OF[refusal].value:
        raise _refused(
            RehearsalGrantRefusalCode.PROVOCATION_MISMATCH,
            f"this grant authorizes {refusal.value!r}, which must end in "
            f"{_TERMINAL_OF[refusal].value!r}, and the document says "
            f"{carried!r}. A grant that names an act and a contradicting "
            "outcome authorizes neither",
        )
    return RehearsalGrantStatementV1(
        grant_id=_text(row, "grant_id"),
        single_use_reference=_text(row, "single_use_reference"),
        product_code=_text(row, "product_code"),
        target_id=_text(row, "target_id"),
        target_ref=_text(row, "target_ref"),
        environment=_text(row, "environment"),
        candidate_repository=_text(row, "candidate_repository"),
        candidate_run_id=_text(row, "candidate_run_id"),
        candidate_artifact_id=_text(row, "candidate_artifact_id"),
        execution_plan_digest=_text(row, "execution_plan_digest"),
        provocation_refusal=refusal,
        provocation_at_step=_text(row, "provocation_at_step"),
        lease_id=_text(row, "lease_id"),
        approval_policy_code=_text(row, "approval_policy_code"),
        approval_policy_version=version,
        approval_decision_ref=_text(row, "approval_decision_ref"),
        approval_decision_status=_text(row, "approval_decision_status"),
        approved_at=_instant(row, "approved_at"),
        not_before=_instant(row, "not_before"),
        issued_at=_instant(row, "issued_at"),
        expires_at=_instant(row, "expires_at"),
        control_version=_text(row, "control_version"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
        purpose=_text(row, "purpose"),
    )


#: A rehearsal grant requires a GRANTED decision. Deployment authorizations also
#: accept `approval_exempt`, and this deliberately does not — for the same
#: reason `recovery_grant.py` does not. An exempt rehearsal would be a
#: deliberately provoked failure against a real target with no approval evidence
#: behind it. A rehearsal nobody approved is the case this grant is for, not an
#: exception to it.
_STANDING_APPROVAL: Final[frozenset[str]] = frozenset({"granted"})


@dataclass(frozen=True, slots=True)
class RehearsalStandingResult:
    """What a grant is now, and — when it is not authority — which term failed."""

    standing: RehearsalStanding
    refusal: RehearsalGrantRefusalCode | None = None

    @property
    def authorizes(self) -> bool:
        """The ONE question a surface may ask. Derived, never a stored flag."""
        return self.standing is RehearsalStanding.VALID


def issue_rehearsal_grant(
    statement: RehearsalGrantStatementV1, *, signer: RehearsalGrantSigner
) -> RehearsalGrantV1:
    """Sign a rehearsal grant. Takes the TYPE, never a mapping."""
    if not isinstance(signer, RehearsalGrantSigner):
        raise _refused(
            RehearsalGrantRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement the rehearsal purpose",
        )
    identity = signer.rehearsal_identity
    if not isinstance(identity, RehearsalGrantSignerIdentity):
        raise _refused(
            RehearsalGrantRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose a rehearsal identity",
        )
    if identity.public_key_fingerprint != statement.public_key_fingerprint:
        raise _refused(
            RehearsalGrantRefusalCode.SIGNER_PURPOSE_REUSED,
            "the statement names a different key than the signer holds",
        )
    signed = signer.sign_rehearsal(statement.canonical_bytes())
    if not signed.signature.strip():
        raise _refused(
            RehearsalGrantRefusalCode.UNSIGNED,
            "the rehearsal signer returned an empty signature",
        )
    return RehearsalGrantV1(statement=statement, signature=signed.signature)


def verify_rehearsal_grant(
    value: object,
    *,
    verifier: RehearsalGrantVerifier,
    subject: RehearsalSubject,
    at: datetime | None = None,
    revoked_grant_ids: frozenset[str] = frozenset(),
    consumed_references: frozenset[str] = frozenset(),
) -> RehearsalGrantV1:
    """Authority for THIS rehearsal, or a refusal naming the term that failed.

    Order is deliberate. Authenticity first, so a forged document never earns
    field-level diagnostics about what it would have had to say. Then the
    window, revocation and the replay coordinate, which are properties of the
    grant. Then the subject, term by term, with the PROVOCATION last — because
    a grant that fails on the target or the artifact is authority for a
    different rehearsal, and one that fails on the provocation is authority for
    a different ACT.
    """
    if not isinstance(verifier, RehearsalGrantVerifier):
        raise _refused(
            RehearsalGrantRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement rehearsal verification",
        )
    grant = RehearsalGrantV1.parse(value)
    statement = grant.statement
    if not verifier.verify_rehearsal(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes(),
        signature=grant.signature,
    ):
        raise _refused(
            RehearsalGrantRefusalCode.SIGNATURE_INVALID,
            "the rehearsal grant signature does not verify over its canonical bytes",
        )

    now = _aware_utc(at or datetime.now(UTC), field="at")
    if now < statement.not_before:
        raise _refused(
            RehearsalGrantRefusalCode.NOT_YET_VALID,
            f"the authorized window opens at {_timestamp(statement.not_before)}",
        )
    if now >= statement.expires_at:
        raise _refused(
            RehearsalGrantRefusalCode.EXPIRED,
            f"the authorized window closed at {_timestamp(statement.expires_at)}",
        )
    if statement.grant_id in revoked_grant_ids:
        raise _refused(
            RehearsalGrantRefusalCode.REVOKED,
            f"rehearsal grant {statement.grant_id} was revoked",
        )
    if statement.single_use_reference in consumed_references:
        raise _refused(
            RehearsalGrantRefusalCode.ALREADY_CONSUMED,
            f"replay coordinate {statement.single_use_reference} has already "
            "been spent. A rehearsal grant authorizes one execution; a second "
            "presentation of the same document is a second execution authority",
        )
    if statement.approval_decision_status not in _STANDING_APPROVAL:
        raise _refused(
            RehearsalGrantRefusalCode.APPROVAL_NOT_STANDING,
            f"the rehearsal grant carries {statement.approval_decision_status!r}; "
            "a rehearsal requires a standing granted decision, and unlike a "
            "deployment authorization it is not exempt-able",
        )

    # Subject, term by term, each with its own code. Presence is not matching.
    for field, code in (
        ("product_code", RehearsalGrantRefusalCode.PRODUCT_MISMATCH),
        ("target_id", RehearsalGrantRefusalCode.TARGET_MISMATCH),
        ("target_ref", RehearsalGrantRefusalCode.TARGET_MISMATCH),
        ("environment", RehearsalGrantRefusalCode.ENVIRONMENT_MISMATCH),
        (
            "execution_plan_digest",
            RehearsalGrantRefusalCode.EXECUTION_PLAN_MISMATCH,
        ),
    ):
        granted = getattr(statement, field)
        asked = getattr(subject, field)
        if granted != asked:
            raise _refused(
                code,
                f"the grant authorizes {field}={granted!r} and this rehearsal "
                f"is {field}={asked!r}",
            )
    if statement.candidate != subject.candidate:
        raise _refused(
            RehearsalGrantRefusalCode.CANDIDATE_MISMATCH,
            f"the grant authorizes a rehearsal of {statement.candidate} and "
            f"this rehearsal is of {subject.candidate}. A rehearsal of other "
            "bytes says nothing about these ones",
        )
    if statement.provocation != subject.provocation:
        raise _refused(
            RehearsalGrantRefusalCode.PROVOCATION_MISMATCH,
            f"the grant authorizes provoking "
            f"{statement.provocation.refusal.value!r} at "
            f"{statement.provocation.at_step!r} and this rehearsal would "
            f"provoke {subject.provocation.refusal.value!r} at "
            f"{subject.provocation.at_step!r}. A grant for one refusal is not "
            "a grant for another, and the same refusal at another step is a "
            "different act against a different part of the target",
        )
    return grant


def rehearsal_standing(
    value: object | None,
    *,
    verifier: RehearsalGrantVerifier,
    subject: RehearsalSubject,
    at: datetime | None = None,
    revoked_grant_ids: frozenset[str] = frozenset(),
    consumed_references: frozenset[str] = frozenset(),
) -> RehearsalStandingResult:
    """What a surface may display, derived from the grant and nothing else.

    `None` is ABSENT — nobody has authorized a rehearsal for this target — and
    it is deliberately distinct from CONSUMED, REVOKED, EXPIRED and UNRESOLVED.

    There is no path here that consults a deployment authorization. A live
    deployment authorization is not weak rehearsal authority; it is none.
    """
    if value is None:
        return RehearsalStandingResult(RehearsalStanding.ABSENT)
    try:
        verify_rehearsal_grant(
            value,
            verifier=verifier,
            subject=subject,
            at=at,
            revoked_grant_ids=revoked_grant_ids,
            consumed_references=consumed_references,
        )
    except RehearsalGrantRefusedError as refused:
        mapped = {
            RehearsalGrantRefusalCode.NOT_YET_VALID: RehearsalStanding.NOT_YET_VALID,
            RehearsalGrantRefusalCode.EXPIRED: RehearsalStanding.EXPIRED,
            RehearsalGrantRefusalCode.REVOKED: RehearsalStanding.REVOKED,
            RehearsalGrantRefusalCode.ALREADY_CONSUMED: RehearsalStanding.CONSUMED,
        }.get(refused.code, RehearsalStanding.UNRESOLVED)
        return RehearsalStandingResult(mapped, refused.code)
    return RehearsalStandingResult(RehearsalStanding.VALID)
