"""Recovery is authorized by its own grant, not by a deployment authorization.

## Why a distinct type rather than a fourth operation

`recover` is a member of this control plane's operation vocabulary and the
executor has not published support for it, so `counterparty.py` refuses to
freeze, sign or dispatch it. That fence stops the wrong thing being authorized.
It does not authorize the right one, and recovery is a real act that someone has
to consent to.

A recovery is not a deployment with a different word in a field. It binds things
a deployment authorization has no place for -- the bundle being restored from,
the incumbent the target was on when the bundle was taken, and a window during
which the restoration may run -- and it must not be satisfiable by anything that
authorizes a deploy. So it is a different document with a different signer.

## The type identifies the act. There is deliberately NO `operation` field

Michael's ruling, and the same one the Foundation's `RecoveryExecutionPlanV1`
received. An `operation` field here would do two jobs: constrain the vocabulary
AND make the document self-identifying. Drop it carelessly and the second job
goes unowned, so type confusion becomes the route by which the wrong act is
authorized -- a deployment envelope read as a recovery grant because both happen
to carry `operation: "recover"`.

The job is not dropped, it is MOVED: `schema` identifies the document and
parsing refuses any other, and `purpose` binds the signer to recovery alone. A
deployment authorization presented here is refused as a schema mismatch before a
single field is compared, and a recovery grant presented to the deployment
verifier fails the same way in the other direction.

## Binding is by comparison, never by presence

Every subject term is compared against what the caller states it is recovering,
field by field, each with its own refusal code. A grant that carries a
`recovery_bundle_digest` is not thereby a grant FOR that bundle; it is a grant
for the bundle the caller is about to restore only if the two are equal. "The
field is present" is not "the field matches", and the distinction is the whole
of what a binding is.
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.ports import DeploymentControlError

__all__ = [
    "RECOVERY_GRANT_SCHEMA",
    "RECOVERY_GRANT_VERSION",
    "RECOVERY_PURPOSE",
    "RecoveryGrantRefusalCode",
    "RecoveryGrantRefusedError",
    "RecoveryGrantSignature",
    "RecoveryGrantSigner",
    "RecoveryGrantSignerIdentity",
    "RecoveryGrantStatementV1",
    "RecoveryGrantV1",
    "RecoveryGrantVerifier",
    "RecoveryStanding",
    "RecoveryStandingResult",
    "RecoverySubject",
    "issue_recovery_grant",
    "recovery_standing",
    "verify_recovery_grant",
]

#: The signer purpose. Separated from `deployment_authorization`,
#: `deployment_dispatch` and `target_execution_observation` for the reason all
#: four are separated: one key answering two questions cannot be used to
#: contradict itself.
RECOVERY_PURPOSE: Final = "deployment_recovery"
RECOVERY_GRANT_SCHEMA: Final = "dotmac.deployment_control.recovery_grant"
RECOVERY_GRANT_VERSION: Final = 1

_MAX_TEXT = 512


#: THE FOUNDATION-OWNED PRESTATE DISCRIMINATOR, MIRRORED.
#:
#: Foundation owns this identity; Control stores it beside the digest and
#: REQUIRES it, and neither this module, `dc_0009`, nor a future
#: `RecoveryGrantV1` version may redefine what it means. Control does not depend
#: on `dotmac-deployment-foundation` — its runtime dependencies are the kernel
#: and SQLAlchemy, and every cross-repository coupling is cut at a VALUE, which
#: is what makes this module independently releasable. So the identity is
#: mirrored here rather than imported.
#:
#: WHAT PROTECTS THIS MIRROR, AND WHAT DOES NOT. Foundation's frozen release
#: canary asserts its three identity strings, so the identity cannot CHANGE
#: without turning a Foundation release red. That protection is real and it is
#: asymmetric: it stops the string moving underneath this file, and it cannot
#: detect a mirror that was WRONG WHEN WRITTEN — nothing in Control's CI can
#: compare these characters against their source, because Foundation is not
#: installed here. A transcription error at authoring time is caught by the
#: planted cases in `tests/unit/test_recovery_grant_prestate.py` and by nothing
#: else. Stated plainly rather than implied, on the same rule as any other
#: guard: say what it establishes and what it leaves unmonitored.
PRESTATE_DISCRIMINATOR: Final = (
    "dotmac.deployment_foundation.failed_system_observation.v1"
)

#: Every discriminator THIS version can honour. Closed, which is what makes an
#: unknown one refusable — accepting any string would trust a producer nobody
#: has met to have used rules nobody can check.
#:
#: RENAME HISTORY, recorded because Foundation's changelog does not carry it and
#: an archived transcript will outlive this comment. An earlier spelling of this
#: identity used `...incumbent_prestate...` — named after Control's FIELD.
#: Foundation renamed it to name the DOCUMENT it digests, before anything pinned
#: it. The old spelling is OBSOLETE AND REFUSED, deliberately not aliased: an
#: alias would give one contract two valid spellings, which is the defect the
#: rename existed to remove. A reader meeting the old string somewhere should
#: conclude it is dead, not that both are valid.
KNOWN_PRESTATE_DISCRIMINATORS: Final[frozenset[str]] = frozenset(
    {PRESTATE_DISCRIMINATOR}
)


class RecoveryGrantRefusalCode(StrEnum):
    """Why a recovery grant does not authorize the recovery in hand.

    One code per binding, so a caller is told WHICH term disagreed. An
    aggregate would send an operator round the loop once per field, during an
    incident, which is the worst moment available for that.
    """

    MALFORMED = "recovery_grant_malformed"
    #: The document is not a recovery grant. This is how a deployment
    #: authorization is refused, and it fires before any field is compared.
    SCHEMA_MISMATCH = "recovery_grant_schema_mismatch"
    PURPOSE_MISMATCH = "recovery_grant_purpose_mismatch"
    SIGNER_PURPOSE_REUSED = "recovery_grant_signer_purpose_reused"
    UNSIGNED = "recovery_grant_unsigned"
    SIGNATURE_INVALID = "recovery_grant_signature_invalid"
    PRODUCT_MISMATCH = "recovery_grant_product_mismatch"
    TARGET_MISMATCH = "recovery_grant_target_mismatch"
    ENVIRONMENT_MISMATCH = "recovery_grant_environment_mismatch"
    RECOVERY_PLAN_MISMATCH = "recovery_grant_recovery_plan_mismatch"
    BUNDLE_MISMATCH = "recovery_grant_bundle_mismatch"
    PRESTATE_MISMATCH = "recovery_grant_prestate_mismatch"
    #: The grant carries no Foundation prestate discriminator. A HISTORICAL row,
    #: and permanently unexecutable — never backfilled as the current identity by
    #: assumption. See `PRESTATE_DISCRIMINATOR` below for why the two are
    #: different facts and why assuming one manufactures provenance.
    PRESTATE_UNDISCRIMINATED = "recovery_grant_prestate_undiscriminated"
    #: The grant names a prestate encoding this version cannot honour. Distinct
    #: from a mismatch because the repair is a VERSION, not a re-observation:
    #: comparing under rules you do not have is not comparing.
    PRESTATE_UNKNOWN_DISCRIMINATOR = "recovery_grant_prestate_unknown_discriminator"
    APPROVAL_NOT_STANDING = "recovery_grant_approval_not_standing"
    NOT_YET_VALID = "recovery_grant_not_yet_valid"
    EXPIRED = "recovery_grant_expired"
    REVOKED = "recovery_grant_revoked"


class RecoveryGrantRefusedError(DeploymentControlError):
    """A recovery grant that does not authorize the act in hand, and why."""

    def __init__(self, code: RecoveryGrantRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


class RecoveryStanding(StrEnum):
    """What a grant is RIGHT NOW, as distinct from whether it ever verified.

    `ABSENT` is a claim and not a failure: this target has no recovery grant, so
    recovery is unavailable. It is distinguishable from `REVOKED` and `EXPIRED`
    on purpose -- an operator seeing "unavailable" needs to know whether nobody
    has authorized a recovery, somebody withdrew one, or one ran out of time,
    because those are three different next actions.
    """

    VALID = "valid"
    ABSENT = "absent"
    #: A grant exists and does not resolve to authority for this recovery --
    #: a bad signature, a binding that names something else, an approval that
    #: no longer stands. Distinct from ABSENT because somebody DID authorize
    #: something, and an operator needs to know that before authorizing again.
    UNRESOLVED = "unresolved"
    NOT_YET_VALID = "not_yet_valid"
    EXPIRED = "expired"
    REVOKED = "revoked"


def _refused(code: RecoveryGrantRefusalCode, detail: str) -> RecoveryGrantRefusedError:
    return RecoveryGrantRefusedError(code, detail)


@dataclass(frozen=True, slots=True)
class RecoveryGrantSignerIdentity:
    """The recovery signer, which may be none of the other three."""

    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = RECOVERY_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != RECOVERY_PURPOSE:
            raise _refused(
                RecoveryGrantRefusalCode.PURPOSE_MISMATCH,
                f"a recovery signer must declare {RECOVERY_PURPOSE!r}, not "
                f"{self.purpose!r}",
            )


@dataclass(frozen=True, slots=True)
class RecoveryGrantSignature:
    key_id: str
    algorithm: str
    purpose: str
    public_key_fingerprint: str
    signature: str


@runtime_checkable
class RecoveryGrantSigner(Protocol):
    """Control-side recovery signer.

    Its members share no name with the authorization, dispatch or observation
    signers, so one cannot be passed where another is expected even by
    accident. That is the same structural separation those three already have
    from each other, extended rather than re-argued.
    """

    @property
    def recovery_identity(self) -> RecoveryGrantSignerIdentity: ...

    def sign_recovery(self, canonical_bytes: bytes) -> RecoveryGrantSignature: ...


@runtime_checkable
class RecoveryGrantVerifier(Protocol):
    """Verifier for the recovery purpose only."""

    def verify_recovery(
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
class RecoverySubject:
    """What the caller says it is about to recover.

    Stated by the caller and compared against the signed grant term by term.
    A grant is not authority for a recovery because it mentions a bundle; it is
    authority for THIS recovery only if every term below is equal.
    """

    product_code: str
    target_id: str
    target_ref: str
    environment: str
    recovery_execution_plan_digest: str
    recovery_bundle_digest: str
    incumbent_prestate_digest: str
    #: Foundation's identity for the encoding that produced the digest
    #: above. Required, never defaulted: see `PRESTATE_DISCRIMINATOR`.
    incumbent_prestate_discriminator: str


@dataclass(frozen=True, slots=True)
class RecoveryGrantStatementV1:
    """The signed terms. No `operation`: the schema identifies the act."""

    grant_id: str
    product_code: str
    target_id: str
    target_ref: str
    environment: str
    recovery_execution_plan_digest: str
    recovery_bundle_digest: str
    incumbent_prestate_digest: str
    #: Foundation's identity for the encoding that produced the digest
    #: above. Required, never defaulted: see `PRESTATE_DISCRIMINATOR`.
    incumbent_prestate_discriminator: str
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
    purpose: str = RECOVERY_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != RECOVERY_PURPOSE:
            raise _refused(
                RecoveryGrantRefusalCode.PURPOSE_MISMATCH,
                f"a recovery grant statement must declare {RECOVERY_PURPOSE!r}",
            )
        if not (self.not_before <= self.issued_at < self.expires_at):
            raise _refused(
                RecoveryGrantRefusalCode.MALFORMED,
                "the authorized window is not not_before <= issued_at < "
                f"expires_at ({self.not_before}, {self.issued_at}, "
                f"{self.expires_at})",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": RECOVERY_GRANT_SCHEMA,
            "version": RECOVERY_GRANT_VERSION,
            "purpose": self.purpose,
            "grant_id": self.grant_id,
            "product_code": self.product_code,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "environment": self.environment,
            "recovery_execution_plan_digest": self.recovery_execution_plan_digest,
            "recovery_bundle_digest": self.recovery_bundle_digest,
            "incumbent_prestate_digest": self.incumbent_prestate_digest,
            "incumbent_prestate_discriminator": (
                self.incumbent_prestate_discriminator
            ),
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
    def subject(self) -> RecoverySubject:
        return RecoverySubject(
            product_code=self.product_code,
            target_id=self.target_id,
            target_ref=self.target_ref,
            environment=self.environment,
            recovery_execution_plan_digest=self.recovery_execution_plan_digest,
            recovery_bundle_digest=self.recovery_bundle_digest,
            incumbent_prestate_digest=self.incumbent_prestate_digest,
            incumbent_prestate_discriminator=(
                self.incumbent_prestate_discriminator
            ),
        )


@dataclass(frozen=True, slots=True)
class RecoveryGrantV1:
    """A parsed recovery grant. The only way to hold one is to parse or issue it."""

    statement: RecoveryGrantStatementV1
    signature: str

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @classmethod
    def parse(cls, value: object) -> RecoveryGrantV1:
        """The ONE place bytes become this type.

        A caller cannot half-parse a grant and pass the rest along loose, and
        cannot assemble a signed envelope from parts it happens to hold.
        """
        if not isinstance(value, Mapping):
            raise _refused(
                RecoveryGrantRefusalCode.MALFORMED,
                f"a recovery grant must be a mapping, got {type(value).__name__}",
            )
        if set(value) != {"statement", "signature"}:
            raise _refused(
                RecoveryGrantRefusalCode.MALFORMED,
                f"a recovery grant envelope has exactly statement and signature; "
                f"got {sorted(str(key) for key in value)}",
            )
        signature = value["signature"]
        if not isinstance(signature, str) or not signature.strip():
            raise _refused(
                RecoveryGrantRefusalCode.UNSIGNED,
                "the recovery grant carries no signature",
            )
        return cls(statement=_parse_statement(value["statement"]), signature=signature)


_STATEMENT_KEYS = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "grant_id",
        "product_code",
        "target_id",
        "target_ref",
        "environment",
        "recovery_execution_plan_digest",
        "recovery_bundle_digest",
        "incumbent_prestate_digest",
        # DELIBERATELY NOT REQUIRED AT PARSE. A grant written before this
        # term must stay READABLE so it can be refused as historical with
        # `PRESTATE_UNDISCRIMINATED`, which names what is wrong and what
        # cannot be repaired. Requiring it here would make such a row
        # unparseable instead, turning a precise verdict about provenance
        # into a generic malformed-document error — and an operator would
        # learn that the envelope was broken rather than that it predates
        # the identity nobody can now supply for it.
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


def _timestamp(value: datetime) -> str:
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: object, *, field: str) -> datetime:
    if not isinstance(value, datetime):
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"{field} must be a datetime, got {type(value).__name__}",
        )
    if value.tzinfo is None:
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"{field} is naive; an instant without a zone is not an instant",
        )
    return value.astimezone(UTC)


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row.get(field)
    if not isinstance(value, str) or not value.strip():
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"{field} must be non-empty text",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"{field} exceeds {_MAX_TEXT} characters",
        )
    return value


def _instant(row: Mapping[str, Any], field: str) -> datetime:
    value = row.get(field)
    if not isinstance(value, str):
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED, f"{field} must be an ISO instant"
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED, f"{field} is not an instant: {error}"
        ) from error
    return _aware_utc(parsed, field=field)


def _parse_statement(value: object) -> RecoveryGrantStatementV1:
    if not isinstance(value, Mapping):
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"a recovery grant statement must be a mapping, got "
            f"{type(value).__name__}",
        )
    row: Mapping[str, Any] = value
    # SCHEMA FIRST, before any field is read. This is what refuses a deployment
    # authorization presented as recovery authority: it is the wrong document,
    # and saying so is more useful than reporting whichever of its fields
    # happens to be missing.
    if row.get("schema") != RECOVERY_GRANT_SCHEMA:
        raise _refused(
            RecoveryGrantRefusalCode.SCHEMA_MISMATCH,
            f"{row.get('schema')!r} is not {RECOVERY_GRANT_SCHEMA!r}. A recovery "
            "is authorized by its own grant; no deployment authorization "
            "becomes one by carrying a matching field",
        )
    if row.get("version") != RECOVERY_GRANT_VERSION:
        raise _refused(
            RecoveryGrantRefusalCode.SCHEMA_MISMATCH,
            f"unsupported recovery grant version {row.get('version')!r}",
        )
    if set(row) != _STATEMENT_KEYS:
        missing = sorted(_STATEMENT_KEYS - set(row))
        unexpected = sorted(str(key) for key in set(row) - _STATEMENT_KEYS)
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            f"recovery grant statement keys differ: missing={missing}, "
            f"unexpected={unexpected}",
        )
    version = row.get("approval_policy_version")
    if not isinstance(version, int) or isinstance(version, bool) or version < 1:
        raise _refused(
            RecoveryGrantRefusalCode.MALFORMED,
            "approval_policy_version must be a positive integer",
        )
    return RecoveryGrantStatementV1(
        grant_id=_text(row, "grant_id"),
        product_code=_text(row, "product_code"),
        target_id=_text(row, "target_id"),
        target_ref=_text(row, "target_ref"),
        environment=_text(row, "environment"),
        recovery_execution_plan_digest=_text(row, "recovery_execution_plan_digest"),
        recovery_bundle_digest=_text(row, "recovery_bundle_digest"),
        incumbent_prestate_digest=_text(row, "incumbent_prestate_digest"),
        # `or ""` is the HISTORICAL row, not a default: absence becomes the
        # empty string the undiscriminated refusal is written against, and
        # never the current identity.
        incumbent_prestate_discriminator=(
            row.get("incumbent_prestate_discriminator") or ""
        ),
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


#: A recovery grant requires a GRANTED decision. Deployment authorizations also
#: accept `approval_exempt`, and this deliberately does not: an exempt recovery
#: would be a destructive act with no approval evidence, and "approval and
#: policy evidence" is one of the things this grant exists to bind. A recovery
#: nobody approved is the case the grant is for, not an exception to it.
_STANDING_APPROVAL: Final = frozenset({"granted"})


@dataclass(frozen=True, slots=True)
class RecoveryStandingResult:
    """What a grant is now, and -- when it is not authority -- which term failed."""

    standing: RecoveryStanding
    refusal: RecoveryGrantRefusalCode | None = None

    @property
    def authorizes(self) -> bool:
        """The ONE question a surface may ask. Derived, never a stored flag."""
        return self.standing is RecoveryStanding.VALID


def issue_recovery_grant(
    statement: RecoveryGrantStatementV1, *, signer: RecoveryGrantSigner
) -> RecoveryGrantV1:
    """Sign a recovery grant. Takes the TYPE, never a mapping.

    A caller cannot hand raw fields here and cannot assemble the result: the
    statement is already parsed and validated by the time it arrives, and the
    only signature that reaches the envelope is the one this function obtained.
    """
    if not isinstance(signer, RecoveryGrantSigner):
        raise _refused(
            RecoveryGrantRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement the recovery purpose",
        )
    identity = signer.recovery_identity
    if not isinstance(identity, RecoveryGrantSignerIdentity):
        raise _refused(
            RecoveryGrantRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose a recovery identity",
        )
    if identity.public_key_fingerprint != statement.public_key_fingerprint:
        raise _refused(
            RecoveryGrantRefusalCode.SIGNER_PURPOSE_REUSED,
            "the statement names a different key than the signer holds",
        )
    signed = signer.sign_recovery(statement.canonical_bytes())
    if not signed.signature.strip():
        raise _refused(
            RecoveryGrantRefusalCode.UNSIGNED,
            "the recovery signer returned an empty signature",
        )
    return RecoveryGrantV1(statement=statement, signature=signed.signature)


def verify_recovery_grant(
    value: object,
    *,
    verifier: RecoveryGrantVerifier,
    subject: RecoverySubject,
    at: datetime | None = None,
    revoked_grant_ids: frozenset[str] = frozenset(),
) -> RecoveryGrantV1:
    """Authority for THIS recovery, or a refusal naming the term that failed.

    Order is deliberate. Authenticity first, so a forged document never earns
    field-level diagnostics about what it would have had to say. Then the
    window and revocation, which are properties of the grant. Then the subject,
    term by term.
    """
    if not isinstance(verifier, RecoveryGrantVerifier):
        raise _refused(
            RecoveryGrantRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement recovery verification",
        )
    grant = RecoveryGrantV1.parse(value)
    statement = grant.statement
    if not verifier.verify_recovery(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes(),
        signature=grant.signature,
    ):
        raise _refused(
            RecoveryGrantRefusalCode.SIGNATURE_INVALID,
            "the recovery grant signature does not verify over its canonical bytes",
        )

    now = _aware_utc(at or datetime.now(UTC), field="at")
    if now < statement.not_before:
        raise _refused(
            RecoveryGrantRefusalCode.NOT_YET_VALID,
            f"the authorized window opens at {_timestamp(statement.not_before)}",
        )
    if now >= statement.expires_at:
        raise _refused(
            RecoveryGrantRefusalCode.EXPIRED,
            f"the authorized window closed at {_timestamp(statement.expires_at)}",
        )
    if statement.grant_id in revoked_grant_ids:
        raise _refused(
            RecoveryGrantRefusalCode.REVOKED,
            f"recovery grant {statement.grant_id} was revoked",
        )
    if statement.approval_decision_status not in _STANDING_APPROVAL:
        raise _refused(
            RecoveryGrantRefusalCode.APPROVAL_NOT_STANDING,
            f"the recovery grant carries {statement.approval_decision_status!r}; "
            "a recovery requires a standing granted decision, and unlike a "
            "deployment authorization it is not exempt-able",
        )

    # Subject, term by term, each with its own code. Presence is not matching.
    # THE DISCRIMINATOR IS CHECKED BEFORE THE DIGEST, and the order is the
    # point rather than a style. A digest alone is 64 hex characters and cannot
    # say which encoding produced it, so comparing it first would report
    # "the prestate is not the one authorized" for a value whose provenance was
    # never establishable. Three refusals, three destinations: a historical row
    # nobody can execute, a version this deployment does not have, and a host
    # holding the wrong incumbent.
    granted_discriminator = str(statement.incumbent_prestate_discriminator).strip()
    if not granted_discriminator:
        raise _refused(
            RecoveryGrantRefusalCode.PRESTATE_UNDISCRIMINATED,
            "this grant carries no Foundation prestate discriminator, so its "
            "stored digest cannot say which encoding produced it. The row is "
            "HISTORICAL AND UNEXECUTABLE and is never backfilled as "
            f"{PRESTATE_DISCRIMINATOR!r} by assumption — that would manufacture "
            "provenance for a value whose provenance is exactly what is missing",
        )
    if granted_discriminator not in KNOWN_PRESTATE_DISCRIMINATORS:
        raise _refused(
            RecoveryGrantRefusalCode.PRESTATE_UNKNOWN_DISCRIMINATOR,
            f"this grant names prestate encoding {granted_discriminator!r}, "
            "which this version of Control cannot honour; it knows "
            f"{sorted(KNOWN_PRESTATE_DISCRIMINATORS)}. Comparing under rules "
            "this version does not have is not comparing — the repair is a "
            "version, not a re-observation",
        )

    for field, code in (
        ("product_code", RecoveryGrantRefusalCode.PRODUCT_MISMATCH),
        (
            "incumbent_prestate_discriminator",
            RecoveryGrantRefusalCode.PRESTATE_UNKNOWN_DISCRIMINATOR,
        ),
        ("target_id", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("target_ref", RecoveryGrantRefusalCode.TARGET_MISMATCH),
        ("environment", RecoveryGrantRefusalCode.ENVIRONMENT_MISMATCH),
        (
            "recovery_execution_plan_digest",
            RecoveryGrantRefusalCode.RECOVERY_PLAN_MISMATCH,
        ),
        ("recovery_bundle_digest", RecoveryGrantRefusalCode.BUNDLE_MISMATCH),
        ("incumbent_prestate_digest", RecoveryGrantRefusalCode.PRESTATE_MISMATCH),
    ):
        granted = getattr(statement, field)
        asked = getattr(subject, field)
        if granted != asked:
            raise _refused(
                code,
                f"the grant authorizes {field}={granted!r} and this recovery is "
                f"{field}={asked!r}",
            )
    return grant


def recovery_standing(
    value: object | None,
    *,
    verifier: RecoveryGrantVerifier,
    subject: RecoverySubject,
    at: datetime | None = None,
    revoked_grant_ids: frozenset[str] = frozenset(),
) -> RecoveryStandingResult:
    """What a surface may display, derived from the grant and nothing else.

    `None` is ABSENT -- nobody has authorized a recovery for this target -- and
    it is deliberately distinct from REVOKED, EXPIRED and UNRESOLVED. An
    operator reading "unavailable" needs to know whether nobody authorized one,
    somebody withdrew one, one ran out of time, or one exists and does not
    authorize THIS recovery, because those are four different next actions.

    There is no path here that consults a deployment authorization. A dead
    deployment authorization is not weak recovery authority; it is none.
    """
    if value is None:
        return RecoveryStandingResult(RecoveryStanding.ABSENT)
    try:
        verify_recovery_grant(
            value,
            verifier=verifier,
            subject=subject,
            at=at,
            revoked_grant_ids=revoked_grant_ids,
        )
    except RecoveryGrantRefusedError as refused:
        mapped = {
            RecoveryGrantRefusalCode.NOT_YET_VALID: RecoveryStanding.NOT_YET_VALID,
            RecoveryGrantRefusalCode.EXPIRED: RecoveryStanding.EXPIRED,
            RecoveryGrantRefusalCode.REVOKED: RecoveryStanding.REVOKED,
        }.get(refused.code, RecoveryStanding.UNRESOLVED)
        return RecoveryStandingResult(mapped, refused.code)
    return RecoveryStandingResult(RecoveryStanding.VALID)
