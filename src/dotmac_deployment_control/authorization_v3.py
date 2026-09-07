"""V3: the successor authorization that BINDS Platform Health's evidence.

ADR-0070's 2026-09-07 amendment names the seam this module fills:

    Control verifies the inner signature, binds its digest to target,
    environment, operation, plan, descriptor, image and the exact
    required-component roster, then freezes and signs the outer
    authorization... Adding the health-evidence digest and roster to that
    signed authorization requires an explicit successor/versioned
    authorization schema; it must not silently widen or redefine the
    existing published statement.

`AuthorizationStatementV2` (`authorization.py`) is that existing published
statement and is UNCHANGED by this module — not one field is added to it, not
one refusal code is repurposed. `AuthorizationStatementV3` is a new type with
its own schema version, its own refusal codes, its own `parse`, and its own
`issue_authorization_envelope_v3` / `verify_authorization_envelope_v3`.

## What Control does NOT do here, stated because it is easy to blur

Control does not decide whether any component is healthy, does not compute
freshness, and does not import `dotmac_platform_health` (constraint, not
oversight — `dotmac_platform_health` and `dotmac_deployment_foundation` are
both entries in `SIBLING_ROOTS`,
`tests/architecture/test_deployment_control_module.py`'s existing
`TestTheModuleImportsNoSibling` sweep, which this task added). "Every state
healthy, every freshness fresh" is Foundation's ADMISSION decision at a later
stage, over the SAME frozen evidence this module binds. What Control DOES do
is narrower and structural: verify the evidence is genuinely signed by an
enrolled Platform Health key, verify its roster is EXACTLY the roster this
deployment requires, bind its digest immutably into a signed statement, and
refuse to authorize past the evidence's own `valid_until`.

## The wire shape Control reads, and why it is Control's own

`dotmac_platform_health.evidence.SignedHealthEvidence` (as of Starter PR #665,
branch `feat/platform-health-canonical-evidence`) is an in-process dataclass
with NO `.parse()`/`.as_mapping()` — Platform Health defines
`canonical_health_evidence_bytes` (the INNER document's deterministic
encoding) and `HealthEvidenceSigner`/`HealthEvidenceSignature`, and nothing
that serializes the OUTER (evidence, signature) pair across a process
boundary. Since Control must not import that package, this module defines its
own minimal wire contract for what crosses the boundary
(`parse_signed_health_evidence_document`): the EXACT canonical bytes Platform
Health signed, carried verbatim (never re-serialized — see
`digests.HealthEvidenceDigestV1` for why a second canonicalizer is refused
here), plus a signature block naming `key_id`, `algorithm` and the signature
itself. Control reads `schema`/`evaluated_at`/`valid_until`/`components` by
`json.loads`-ing those SAME bytes, exactly as `canonical_health_evidence_bytes`
promises a schema-aware reader may, and never rebuilds them.

`HealthEvidenceSignature.algorithm`, `.key_id` and `.signature` are the only
fields Platform Health's signature type carries — no `purpose`, no
`public_key_fingerprint` on the wire. Purpose separation and key-fingerprint
enrollment are therefore Control's own responsibility, carried entirely inside
the INJECTED `HealthEvidenceVerifier` (an assembly's concrete verifier is
expected to resolve `key_id` against ITS OWN enrolled-key/eligibility/
revocation registry and refuse an unenrolled or revoked key before returning
`True`) rather than travelling as extra wire fields this module would have to
invent on Platform Health's behalf.

## `product_code` / `environment`: Control terms, spelled differently by Foundation

Both already exist, unchanged, on `AuthorizationStatementV2` — Control has
owned this vocabulary since the a10 statement, and V3 inherits it rather than
inventing it. Foundation's `ProductDeploymentSpec` DOES carry the same two
concepts, but under different names: `product: str` and `environment: str`
(`dotmac_deployment_foundation/spec.py:2258-2259`) — `environment` happens to
match; Control's `product_code` and Foundation's `product` name the same
concept differently. Cross-validating the two sides against each other is a
named Foundation follow-up (Michael's ruling), not something this module
does: V3 signs Control's own terms and does not read, import, or reconcile
against Foundation's spec.

## `rollout_ref` and `execution_sequence` are NOT a lease

An earlier draft of this module mapped the brief's "lease" subject term onto
`(rollout_ref, execution_sequence)`, flagged as an inferred mapping rather
than an invented field, and asked whether that mapping was right. Michael's
ruling: it was the right restraint (no field was invented) but the wrong
name. Foundation already owns the real lease —
`HOST_LEASE_SCHEMA = "HostLease.v2"`
(`dotmac_deployment_foundation/lease.py:76`), which carries a mandatory
`authorization_run_id: str` (`lease.py:112`) and is bound at EXECUTION time
through that field. No authorization contract anywhere — not V1, not V2, not
this V3 — carries `lease_id`, confirmed by grep across Foundation's
authorization modules.

So `(rollout_ref, execution_sequence)` is not a lease at all; it is Control's
own pair of terms — WHICH rollout, and WHICH attempt under that rollout —
that this statement was issued for, unrelated to Foundation's
`HostLease.v2`. `AuthorizationEnvelopeV3RefusalCode.ROLLOUT_MISMATCH` and
`EXECUTION_SEQUENCE_MISMATCH` name exactly those two terms, separately, and
neither name nor implies a lease. `HostLease.v2` remains a SEPARATE
execution-time prerequisite, checked through `authorization_run_id`,
entirely outside this module's binding.

## `control_plan_digest` — canonical preimage and exclusion, made structural

`control_plan_digest` identifies the bound V3 statement as a whole. It is
never inside the bytes it is a digest of — the trap named for the Foundation
wheel digest applies identically here: a digest embedded in its own preimage
no longer identifies "this statement", it identifies "this statement, which
also happens to know its own hash", and two honestly-different statements
could be made to collide by adjusting the field the reader is not looking at.

`control_plan_digest_preimage` is the ONE function that builds the preimage,
and the exclusion is structural rather than a comment someone has to
remember: it is a set-difference filter, `control_plan_digest` is the first
and (today) only excluded key, and `control_plan_digest_preimage` itself
re-asserts the filter held before returning. The **canonical
preimage** is exactly: `AuthorizationStatementV3.as_mapping()` with the
`control_plan_digest` key removed, encoded with `digests.canonical_json`
(`json.dumps(..., sort_keys=True, separators=(",", ":")).encode("utf-8")`) —
the identical encoding every other digest in this package uses. A reader
holding a full, verified statement recovers the SAME preimage by calling
`control_plan_digest_preimage` on `as_mapping()` themselves; that is what
"canonical and re-derivable" means for this value, and
`test_authorization_v3.py::
test_control_plan_digest_is_stable_regardless_of_a_planted_self_reference`
proves the value does not move even when a caller tries to plant a
`control_plan_digest` field inside the mapping being hashed.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Mapping, Sequence
from collections.abc import Set as AbstractSet
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from importlib.metadata import PackageNotFoundError
from importlib.metadata import version as _distribution_version
from typing import Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.authorization import (
    AuthorizationSignature,
    AuthorizationSigner,
    AuthorizationSignerIdentity,
    AuthorizationVerifier,
)
from dotmac_deployment_control.digests import (
    ControlPlanDigestV1,
    DescriptorDigestV1,
    ExecutionPlanDigestV1,
    HealthEvidenceDigestV1,
    PlanDigestV1,
    PublicKeyFingerprintV1,
    canonical_json,
)
from dotmac_deployment_control.images import (
    AuthorizedImage,
    authorized_image_set,
    image_set_payload,
)
from dotmac_deployment_control.ports import DeploymentControlError, DigestEncodingError

__all__ = [
    "AUTHORIZATION_V3_PURPOSE",
    "AUTHORIZATION_V3_SCHEMA",
    "AUTHORIZATION_V3_VERSION",
    "DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA",
    "HEALTH_EVIDENCE_PURPOSE",
    "AuthorizationEnvelopeV3",
    "AuthorizationEnvelopeV3RefusalCode",
    "AuthorizationEnvelopeV3RefusedError",
    "AuthorizationStatementV3",
    "AuthorizationSubjectV3",
    "HealthEvidenceVerifier",
    "ParsedHealthEvidenceDocument",
    "control_plan_digest_preimage",
    "issue_authorization_envelope_v3",
    "parse_signed_health_evidence_document",
    "verify_authorization_envelope_v3",
]

#: Same physical purpose V1/V2 already declare. V3 is the successor of the
#: SAME act — authorizing a deployment — not a new one, on the same rule that
#: kept `AUTHORIZATION_PURPOSE` unchanged across the V1 -> V2 move. A genuinely
#: new act (rehearsal, dispatch, observation, recovery) gets its own purpose;
#: this is not that.
AUTHORIZATION_V3_PURPOSE: Final = "deployment_authorization"
AUTHORIZATION_V3_SCHEMA: Final = "dotmac.deployment-authorization"
AUTHORIZATION_V3_VERSION: Final = 3

#: Platform Health's own signing purpose for THIS document class. Distinct
#: from `AUTHORIZATION_V3_PURPOSE`: two different signers, two different
#: physical keys, two different parties (Control signs the outer statement;
#: Platform Health signs the inner evidence). Named here as a value this
#: module compares an injected verifier's declared purpose against, on the
#: same purpose-separation doctrine `rehearsal_grant.REHEARSAL_PURPOSE`
#: documents — never a purpose Control itself signs under.
HEALTH_EVIDENCE_PURPOSE: Final = "deployment_health_evidence"

#: Mirrored from `dotmac_platform_health.contracts.DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA`
#: (Starter PR #665, branch `feat/platform-health-canonical-evidence`,
#: `packages/dotmac-platform-health/src/dotmac_platform_health/contracts.py`).
#: A VALUE mirror, on the same terms `rehearsal_grant.FOUNDATION_STEP_KINDS`
#: mirrors Foundation's `StepKind` — Control does not depend on
#: `dotmac-platform-health` (independent release, and the import-linter
#: contract this task adds forbids it structurally), so the cross-repository
#: coupling is cut at a string value rather than an import.
DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA: Final = "DeploymentHealthEvidence.v1"

_MAX_TEXT = 512
_HEALTH_STATE_KEYS = frozenset(
    {"component_code", "observation_id", "observed_at", "state", "freshness"}
)
_HEALTH_EVIDENCE_KEYS = frozenset(
    {"schema", "evaluated_at", "valid_until", "components"}
)


class AuthorizationEnvelopeV3RefusalCode(StrEnum):
    """One code per binding. A caller is told WHICH term disagreed."""

    # -- structural / envelope --------------------------------------------
    MALFORMED = "authorization_v3_malformed"
    SCHEMA_MISMATCH = "authorization_v3_schema_mismatch"
    UNSUPPORTED_VERSION = "authorization_v3_unsupported_version"
    UNSIGNED = "authorization_v3_unsigned"
    SIGNER_IDENTITY_MISMATCH = "authorization_v3_signer_identity_mismatch"
    SIGNATURE_INVALID = "authorization_v3_signature_invalid"
    APPROVAL_NOT_STANDING = "authorization_v3_approval_not_standing"
    EXPIRED = "authorization_v3_expired"
    NOT_YET_VALID = "authorization_v3_not_yet_valid"
    CONTROL_VERSION_UNAVAILABLE = "authorization_v3_control_version_unavailable"
    PURPOSE_MISMATCH = "authorization_v3_purpose_mismatch"

    # -- health evidence, inner document ------------------------------------
    EVIDENCE_ABSENT = "authorization_v3_evidence_absent"
    EVIDENCE_MALFORMED = "authorization_v3_evidence_malformed"
    EVIDENCE_SCHEMA_MISMATCH = "authorization_v3_evidence_schema_mismatch"
    EVIDENCE_UNSIGNED = "authorization_v3_evidence_unsigned"
    EVIDENCE_VERIFIER_PURPOSE_MISMATCH = (
        "authorization_v3_evidence_verifier_purpose_mismatch"
    )
    EVIDENCE_SIGNATURE_INVALID = "authorization_v3_evidence_signature_invalid"
    #: The digest Control computed over the evidence bytes it was actually
    #: handed does not equal the digest already bound into a signed statement
    #: being re-verified. This is the TAMPER-detection arm for the evidence
    #: content specifically, distinct from `SIGNATURE_INVALID` (which fires on
    #: the Platform Health signature itself) and distinct from the outer
    #: `SIGNATURE_INVALID` on Control's own statement.
    EVIDENCE_DIGEST_MISMATCH = "authorization_v3_evidence_digest_mismatch"
    #: The evidence's own roster (its `components[].component_code` set) is
    #: not EXACTLY the roster this deployment requires — extra, missing, or
    #: both. Named separately from every subject-substitution code below
    #: because it is a statement about the evidence's CONTENT, not about which
    #: deployment the caller claims this authorization is for.
    EVIDENCE_ROSTER_MISMATCH = "authorization_v3_evidence_roster_mismatch"
    #: Control's own `expires_at` would authorize past the evidence's
    #: `valid_until`. "Outer Control expiry must not extend Platform Health's
    #: valid_until" (ADR-0070 amendment, 2026-09-07).
    EVIDENCE_WINDOW_EXCEEDED = "authorization_v3_evidence_window_exceeded"
    EVIDENCE_EXPIRED = "authorization_v3_evidence_expired"
    EVIDENCE_FUTURE_DATED = "authorization_v3_evidence_future_dated"

    # -- subject substitution, verify-time, term by term --------------------
    PRODUCT_MISMATCH = "authorization_v3_product_mismatch"
    ENVIRONMENT_MISMATCH = "authorization_v3_environment_mismatch"
    TARGET_MISMATCH = "authorization_v3_target_mismatch"
    #: `rollout_ref` names WHICH rollout this authorization was issued under.
    #: Deliberately NOT named "lease": Foundation's actual execution lease is
    #: `HostLease.v2` (`dotmac_deployment_foundation/lease.py`), bound through
    #: `authorization_run_id` at execution time, not through a subject term
    #: Control signs. See the module docstring's "rollout_ref and
    #: execution_sequence are not a lease" section.
    ROLLOUT_MISMATCH = "authorization_v3_rollout_mismatch"
    #: `execution_sequence` names WHICH attempt under that rollout. Compared
    #: separately from `ROLLOUT_MISMATCH`: the two terms answer different
    #: questions ("which rollout" vs. "which attempt of it") and a caller
    #: told which one disagreed does not have to re-derive it from a combined
    #: message.
    EXECUTION_SEQUENCE_MISMATCH = "authorization_v3_execution_sequence_mismatch"
    APPROVAL_MISMATCH = "authorization_v3_approval_mismatch"
    OPERATION_MISMATCH = "authorization_v3_operation_mismatch"
    RELEASE_MISMATCH = "authorization_v3_release_mismatch"
    IMAGES_MISMATCH = "authorization_v3_images_mismatch"
    PLAN_MISMATCH = "authorization_v3_plan_mismatch"
    DESCRIPTOR_MISMATCH = "authorization_v3_descriptor_mismatch"
    EXECUTION_PLAN_MISMATCH = "authorization_v3_execution_plan_mismatch"

    #: The statement's own `control_plan_digest` does not re-derive from its
    #: own bound terms. This can only happen to a hand-constructed or
    #: corrupted statement — `issue_authorization_envelope_v3` always computes
    #: it correctly — but a verifier re-checks it defensively rather than
    #: trusting a value merely because it parsed.
    CONTROL_PLAN_DIGEST_MISMATCH = "authorization_v3_control_plan_digest_mismatch"


class AuthorizationEnvelopeV3RefusedError(DeploymentControlError):
    """A V3 authorization that is not authority for the act in hand, and why."""

    def __init__(self, code: AuthorizationEnvelopeV3RefusalCode, detail: str) -> None:
        self.code = code
        self.detail = detail
        super().__init__(f"{code.value}: {detail}")


def _refused(
    code: AuthorizationEnvelopeV3RefusalCode, detail: str
) -> AuthorizationEnvelopeV3RefusedError:
    return AuthorizationEnvelopeV3RefusedError(code, detail)


# ── Control's own signer/verifier (outer statement) ─────────────────────────
#
# Reused verbatim from `authorization.py`'s `AuthorizationSigner` /
# `AuthorizationVerifier` shape rather than redefined: V3 is signed by the
# SAME purpose-holding key as V2 (see `AUTHORIZATION_V3_PURPOSE` above), so a
# second, differently-named protocol here would just be a structural copy an
# assembly would have to implement twice for the identical key. Re-exported
# from this module for a V3-only importer's convenience.
__all__ += [
    "AuthorizationSignature",
    "AuthorizationSigner",
    "AuthorizationSignerIdentity",
    "AuthorizationVerifier",
]


# ── Injected verifier for Platform Health's evidence signature ─────────────


@runtime_checkable
class HealthEvidenceVerifier(Protocol):
    """Verifies Platform Health's Ed25519 signature over evidence bytes.

    Control chooses no algorithm or key provider and holds no key material —
    identical restraint to `AuthorizationVerifier` and
    `rehearsal_grant.RehearsalGrantVerifier`. An assembly's concrete
    implementation is expected to resolve `key_id` against its OWN enrolled
    Platform-Health-key / eligibility / revocation registry (ADR-0070
    amendment: "Control owns the versioned public-key eligibility/revocation
    registry") and return `False` for an unenrolled or revoked key — that
    registry is out of scope for this pure, I/O-free module, on the same
    split `authorization.py`'s docstring draws between "verifies a signature"
    and "look up a live database row".

    `purpose` is supplied here by CONTROL (`HEALTH_EVIDENCE_PURPOSE`), not
    read off the wire — Platform Health's `HealthEvidenceSignature` carries no
    purpose field (measured: `algorithm`, `key_id`, `signature` only). The
    injected verifier is expected to refuse any key it has enrolled under a
    different purpose, exactly as `AuthorizationSignerIdentity.purpose`
    prevents a key from answering two questions.
    """

    def verify_health_evidence(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        canonical_bytes: bytes,
        signature: bytes,
    ) -> bool: ...


@dataclass(frozen=True, slots=True)
class ParsedHealthEvidenceDocument:
    """The result of reading Platform Health's wire document — NEVER re-built.

    `canonical_bytes` is carried unchanged from what Control received; every
    other field here is read OUT of those same bytes via `json.loads`, never
    re-serialized. `HealthEvidenceDigestV1.over_bytes(canonical_bytes)` is the
    digest this module binds — always computed over exactly these bytes.
    """

    canonical_bytes: bytes
    evaluated_at: datetime
    valid_until: datetime
    component_codes: tuple[str, ...]
    key_id: str
    algorithm: str
    signature: bytes

    @property
    def digest(self) -> HealthEvidenceDigestV1:
        return HealthEvidenceDigestV1.over_bytes(self.canonical_bytes)


def parse_signed_health_evidence_document(
    value: object,
) -> ParsedHealthEvidenceDocument:
    """Read Control's OWN wire contract for a signed health-evidence document.

    `{"canonical_bytes": <str, base64>, "signature": {"key_id": <str>,
    "algorithm": <str>, "signature": <str, base64>}}`.

    `canonical_bytes` decodes to the EXACT bytes Platform Health's
    `canonical_health_evidence_bytes` produced and signed — this function
    reads fields OUT of those decoded bytes with `json.loads` (schema,
    `evaluated_at`, `valid_until`, `components[].component_code`) and never
    reconstructs or re-encodes them. That is what keeps this a RECEIVING
    parser rather than a second canonicalizer of a document Platform Health
    owns (see `digests.HealthEvidenceDigestV1`'s docstring).
    """
    if value is None:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_ABSENT,
            "no health evidence document was supplied",
        )
    if not isinstance(value, Mapping) or set(value) != {"canonical_bytes", "signature"}:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "a signed health evidence document is exactly "
            "{canonical_bytes, signature}",
        )
    raw_b64 = value["canonical_bytes"]
    if not isinstance(raw_b64, str) or not raw_b64:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "canonical_bytes must be a non-empty base64 string",
        )
    try:
        canonical_bytes = base64.b64decode(raw_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "canonical_bytes is not valid base64",
        ) from exc

    signature_block = value["signature"]
    if not isinstance(signature_block, Mapping) or set(signature_block) != {
        "key_id",
        "algorithm",
        "signature",
    }:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_UNSIGNED,
            "a health evidence signature block is exactly "
            "{key_id, algorithm, signature}",
        )
    key_id = signature_block["key_id"]
    algorithm = signature_block["algorithm"]
    signature_b64 = signature_block["signature"]
    if not isinstance(key_id, str) or not key_id:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "signature.key_id must be a non-empty string",
        )
    if not isinstance(algorithm, str) or algorithm != "ed25519":
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            f"signature.algorithm must be 'ed25519' (Platform Health signs no "
            f"other algorithm); got {algorithm!r}",
        )
    if not isinstance(signature_b64, str) or not signature_b64:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_UNSIGNED,
            "signature.signature must be a non-empty base64 string",
        )
    try:
        signature = base64.b64decode(signature_b64, validate=True)
    except (ValueError, binascii.Error) as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "signature.signature is not valid base64",
        ) from exc

    try:
        document = json.loads(canonical_bytes)
    except (ValueError, UnicodeDecodeError) as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "canonical_bytes does not decode as UTF-8 JSON",
        ) from exc
    if not isinstance(document, dict) or set(document) != _HEALTH_EVIDENCE_KEYS:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "health evidence document keys differ from "
            f"{sorted(_HEALTH_EVIDENCE_KEYS)}",
        )
    if document.get("schema") != DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_SCHEMA_MISMATCH,
            f"unsupported evidence schema {document.get('schema')!r}, expected "
            f"{DEPLOYMENT_HEALTH_EVIDENCE_SCHEMA!r}",
        )
    evaluated_at = _parse_evidence_instant(
        document.get("evaluated_at"), field="evaluated_at"
    )
    valid_until = _parse_evidence_instant(
        document.get("valid_until"), field="valid_until"
    )
    components = document.get("components")
    if not isinstance(components, list):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "components must be a list",
        )
    codes: list[str] = []
    for entry in components:
        if not isinstance(entry, dict) or set(entry) != _HEALTH_STATE_KEYS:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
                f"each component entry must carry exactly {sorted(_HEALTH_STATE_KEYS)}",
            )
        code = entry.get("component_code")
        if not isinstance(code, str) or not code:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
                "component_code must be a non-empty string",
            )
        codes.append(code)
    if len(set(codes)) != len(codes):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            "components must not repeat a component_code",
        )

    return ParsedHealthEvidenceDocument(
        canonical_bytes=canonical_bytes,
        evaluated_at=evaluated_at,
        valid_until=valid_until,
        component_codes=tuple(codes),
        key_id=key_id,
        algorithm=algorithm,
        signature=signature,
    )


def _parse_evidence_instant(value: object, *, field: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            f"{field} must be a non-empty string",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def verify_health_evidence_signature(
    document: ParsedHealthEvidenceDocument, *, verifier: HealthEvidenceVerifier
) -> None:
    """The genuine cryptographic check — a bool the injected verifier decides.

    Non-vacuous by construction: `verifier.verify_health_evidence` receives
    the EXACT bytes Control parsed the document from, so a verifier stub that
    only recognizes one fixture's real signature refuses every other document
    — including one where a caller supplies matching-looking evidence and
    requirement values by hand (see
    `test_authorization_v3.py::test_the_one_caller_negative_control`).
    """
    if not isinstance(verifier, HealthEvidenceVerifier):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_VERIFIER_PURPOSE_MISMATCH,
            "the injected verifier does not implement health-evidence verification",
        )
    ok = verifier.verify_health_evidence(
        key_id=document.key_id,
        algorithm=document.algorithm,
        purpose=HEALTH_EVIDENCE_PURPOSE,
        canonical_bytes=document.canonical_bytes,
        signature=document.signature,
    )
    if not ok:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_SIGNATURE_INVALID,
            "the injected verifier refused Platform Health's signature over "
            "the evidence's canonical bytes",
        )


# ── The V3 statement ─────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AuthorizationStatementV3:
    """V2's exact terms, plus the health-evidence binding and `control_plan_digest`.

    Every field V2 signs is signed here unchanged (same name, same meaning);
    nothing is silently widened or redefined, per the ADR amendment's own
    instruction. New fields: `health_evidence_digest`,
    `required_component_roster`, `health_evidence_evaluated_at`,
    `health_evidence_valid_until`, `control_plan_digest`.
    """

    authorization_id: str
    execution_sequence: int
    rollout_ref: str
    plan_id: str
    target_id: str
    target_ref: str
    product_code: str
    environment: str
    operation: str
    release_ref: str
    authorized_images: tuple[AuthorizedImage, ...]
    plan_digest: str
    descriptor_digest: str
    execution_plan_digest: str
    approval_policy_code: str | None
    approval_policy_version: int | None
    approval_decision_ref: str | None
    approval_decision_status: str
    approved_at: datetime | None
    issued_at: datetime
    expires_at: datetime
    control_version: str
    key_id: str
    algorithm: str
    public_key_fingerprint: str
    health_evidence_digest: str
    required_component_roster: tuple[str, ...]
    health_evidence_evaluated_at: datetime
    health_evidence_valid_until: datetime
    control_plan_digest: str
    purpose: str = AUTHORIZATION_V3_PURPOSE

    def __post_init__(self) -> None:
        for field in (
            "authorization_id",
            "rollout_ref",
            "plan_id",
            "target_id",
            "target_ref",
            "product_code",
            "environment",
            "operation",
            "release_ref",
            "approval_decision_status",
            "control_version",
            "key_id",
            "algorithm",
        ):
            _bounded_text(getattr(self, field), field=field)
        if self.purpose != AUTHORIZATION_V3_PURPOSE:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.PURPOSE_MISMATCH,
                "the statement does not carry the deployment authorization purpose",
            )
        PlanDigestV1.parse(self.plan_digest)
        DescriptorDigestV1.parse(self.descriptor_digest)
        ExecutionPlanDigestV1.parse(self.execution_plan_digest)
        PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        try:
            HealthEvidenceDigestV1.parse(self.health_evidence_digest)
        except DigestEncodingError as error:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                f"health_evidence_digest is not a canonical digest: {error}",
            ) from error
        try:
            ControlPlanDigestV1.parse(self.control_plan_digest)
        except DigestEncodingError as error:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                f"control_plan_digest is not a canonical digest: {error}",
            ) from error
        if not self.required_component_roster:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "required_component_roster must be non-empty",
            )
        if tuple(sorted(self.required_component_roster)) != tuple(
            self.required_component_roster
        ):
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "required_component_roster must be the canonical sorted order",
            )
        if len(set(self.required_component_roster)) != len(
            self.required_component_roster
        ):
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "required_component_roster must not repeat a component code",
            )
        if (
            not isinstance(self.execution_sequence, int)
            or isinstance(self.execution_sequence, bool)
            or self.execution_sequence < 1
        ):
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "execution_sequence must be a positive integer",
            )
        canonical = authorized_image_set(
            self.authorized_images, where="authorization statement image set"
        )
        if canonical is None or canonical != self.authorized_images:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "authorized_images must be the canonical ordered image set",
            )
        issued = _aware_utc(self.issued_at, field="issued_at")
        expires = _aware_utc(self.expires_at, field="expires_at")
        if expires <= issued:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "expires_at must be later than issued_at",
            )
        valid_until = _aware_utc(
            self.health_evidence_valid_until, field="health_evidence_valid_until"
        )
        if expires > valid_until:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.EVIDENCE_WINDOW_EXCEEDED,
                "expires_at "
                f"({_timestamp(self.expires_at)}) is later than the evidence's "
                f"own valid_until ({_timestamp(self.health_evidence_valid_until)}); "
                "outer Control expiry must never extend Platform Health's window",
            )

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": AUTHORIZATION_V3_SCHEMA,
            "version": AUTHORIZATION_V3_VERSION,
            "purpose": self.purpose,
            "authorization_id": self.authorization_id,
            "execution_sequence": self.execution_sequence,
            "rollout_ref": self.rollout_ref,
            "plan_id": self.plan_id,
            "target_id": self.target_id,
            "target_ref": self.target_ref,
            "product_code": self.product_code,
            "environment": self.environment,
            "operation": self.operation,
            "release_ref": self.release_ref,
            "authorized_images": image_set_payload(self.authorized_images),
            "plan_digest": self.plan_digest,
            "descriptor_digest": self.descriptor_digest,
            "execution_plan_digest": self.execution_plan_digest,
            "approval_policy_code": self.approval_policy_code,
            "approval_policy_version": self.approval_policy_version,
            "approval_decision_ref": self.approval_decision_ref,
            "approval_decision_status": self.approval_decision_status,
            "approved_at": _timestamp(self.approved_at),
            "issued_at": _timestamp(self.issued_at),
            "expires_at": _timestamp(self.expires_at),
            "control_version": self.control_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint": self.public_key_fingerprint,
            "health_evidence_digest": self.health_evidence_digest,
            "required_component_roster": list(self.required_component_roster),
            "health_evidence_evaluated_at": _timestamp(
                self.health_evidence_evaluated_at
            ),
            "health_evidence_valid_until": _timestamp(self.health_evidence_valid_until),
            "control_plan_digest": self.control_plan_digest,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @property
    def subject(self) -> AuthorizationSubjectV3:
        return AuthorizationSubjectV3(
            product_code=self.product_code,
            environment=self.environment,
            target_id=self.target_id,
            target_ref=self.target_ref,
            rollout_ref=self.rollout_ref,
            execution_sequence=self.execution_sequence,
            approval_decision_ref=self.approval_decision_ref,
            approval_decision_status=self.approval_decision_status,
            operation=self.operation,
            release_ref=self.release_ref,
            authorized_images=self.authorized_images,
            plan_digest=self.plan_digest,
            descriptor_digest=self.descriptor_digest,
            execution_plan_digest=self.execution_plan_digest,
        )


@dataclass(frozen=True, slots=True)
class AuthorizationSubjectV3:
    """What the caller says a V3 envelope is standing authority FOR.

    Compared against the signed statement term by term at verify time.
    `rollout_ref` (which rollout) and `execution_sequence` (which attempt
    under it) are NOT a lease — see the module docstring's "rollout_ref and
    execution_sequence are not a lease" section for `HostLease.v2`, the real
    one, which belongs to Foundation.
    """

    product_code: str
    environment: str
    target_id: str
    target_ref: str
    rollout_ref: str
    execution_sequence: int
    approval_decision_ref: str | None
    approval_decision_status: str
    operation: str
    release_ref: str
    authorized_images: tuple[AuthorizedImage, ...]
    plan_digest: str
    descriptor_digest: str
    execution_plan_digest: str


# ── `control_plan_digest`: explicit canonical preimage and exclusion ───────

#: The frozen exclusion set for the `control_plan_digest` preimage.
#: `control_plan_digest` is first, because it is the value being computed —
#: a preimage that contained its own digest would make the digest identify
#: "this statement, including its own hash", which is not re-derivable and is
#: exactly the self-reference trap named for the Foundation wheel digest.
CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS: Final[frozenset[str]] = frozenset(
    {"control_plan_digest"}
)


def control_plan_digest_preimage(
    statement_mapping: Mapping[str, Any],
) -> dict[str, Any]:
    """THE canonical preimage for `control_plan_digest` — the only builder.

    - **Bytes**: `digests.canonical_json` over this function's return value —
      `json.dumps(..., sort_keys=True, separators=(",", ":")).encode("utf-8")`,
      the identical encoding every other digest in this package uses.
    - **Order**: irrelevant to the caller — `canonical_json`'s `sort_keys=True`
      makes the preimage's own key order unobservable in the resulting bytes.
    - **Exclusions**: exactly `CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS`, applied as
      a set-difference filter rather than an assembled dict a future edit
      could silently include a new field into. The filter's effect is
      re-asserted below before this function returns, so a coding error that
      somehow reintroduced the excluded key would raise here rather than
      silently producing a self-referential digest.

    Callable by ANY reader holding a full `AuthorizationStatementV3.as_mapping()`
    — Control calls it once, at issuance, and a verifier (this module's own
    `verify_authorization_envelope_v3`, or an entirely independent reader)
    calls it again to re-derive and compare. That symmetry is what "canonical
    and re-derivable" means for this value.
    """
    preimage = {
        key: value
        for key, value in statement_mapping.items()
        if key not in CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS
    }
    if CONTROL_PLAN_DIGEST_EXCLUDED_FIELDS & set(preimage):
        # Unreachable given the filter above; kept as a structural assertion
        # rather than a comment, so a future edit that stops filtering (e.g.
        # replacing the comprehension with `dict(statement_mapping)`) fails
        # loudly here instead of producing a self-referential digest that
        # merely happens to look stable in a test run.
        raise AssertionError(
            "control_plan_digest preimage still carries an excluded field; "
            "this is a defect in control_plan_digest_preimage itself"
        )
    return preimage


def _compute_control_plan_digest(statement_mapping: Mapping[str, Any]) -> str:
    preimage = control_plan_digest_preimage(statement_mapping)
    return ControlPlanDigestV1.over_bytes(canonical_json(preimage)).canonical


# ── Envelope ─────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AuthorizationEnvelopeV3:
    statement: AuthorizationStatementV3
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=16_384)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> AuthorizationEnvelopeV3:
        if isinstance(value, cls):
            return value
        mapping = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        statement = _parse_statement_v3(mapping["statement"])
        signature = mapping["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.UNSIGNED,
                "the portable authorization carries no signature",
            )
        return cls(statement=statement, signature=signature)


# ── Issuance ─────────────────────────────────────────────────────────────


def issue_authorization_envelope_v3(
    statement_fields: Mapping[str, Any],
    *,
    evidence_document: object,
    required_component_roster: Sequence[str],
    evidence_verifier: HealthEvidenceVerifier,
    signer: AuthorizationSigner,
) -> AuthorizationEnvelopeV3:
    """Verify Platform Health's evidence, bind it and every subject term,
    derive `control_plan_digest`, and sign — or refuse, naming the term.

    `evidence_document` is Control's own wire shape (see
    `parse_signed_health_evidence_document`) — never a
    `dotmac_platform_health` object; this module does not import that
    package. `required_component_roster` is the caller's declared EXACT
    roster this deployment needs; it is compared against the evidence's own
    (independently signed) roster below — see the module docstring's
    "one-caller negative control" discussion in `test_authorization_v3.py`
    for why this comparison is not the `CandidateArtifactV1` defect: one side
    of it is authenticated by a signature this caller cannot forge.
    """
    parsed_evidence = parse_signed_health_evidence_document(evidence_document)
    verify_health_evidence_signature(parsed_evidence, verifier=evidence_verifier)

    if not required_component_roster:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            "required_component_roster must be non-empty",
        )
    required = tuple(sorted(required_component_roster))
    if len(set(required)) != len(required):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            "required_component_roster must not repeat a component code",
        )
    evidence_roster = tuple(sorted(parsed_evidence.component_codes))
    if evidence_roster != required:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_ROSTER_MISMATCH,
            f"the evidence's roster is {list(evidence_roster)} and this "
            f"deployment requires {list(required)}. Evidence for a different "
            "roster describes a different deployment and is not authority "
            "for this one",
        )

    identity = signer.identity
    fields = dict(statement_fields)
    for forbidden in (
        "schema",
        "version",
        "control_version",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
        "purpose",
        "health_evidence_digest",
        "required_component_roster",
        "health_evidence_evaluated_at",
        "health_evidence_valid_until",
        "control_plan_digest",
    ):
        if forbidden in fields:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                f"{forbidden} is derived inside Control and cannot be supplied",
            )
    for field in ("approved_at", "issued_at", "expires_at"):
        value = fields.get(field)
        if isinstance(value, datetime):
            fields[field] = _timestamp(value)

    provisional = {
        "schema": AUTHORIZATION_V3_SCHEMA,
        "version": AUTHORIZATION_V3_VERSION,
        **fields,
        "control_version": _installed_control_version(),
        "key_id": identity.key_id,
        "algorithm": identity.algorithm,
        "public_key_fingerprint": identity.public_key_fingerprint,
        "purpose": identity.purpose,
        "health_evidence_digest": parsed_evidence.digest.canonical,
        "required_component_roster": list(required),
        "health_evidence_evaluated_at": _timestamp(parsed_evidence.evaluated_at),
        "health_evidence_valid_until": _timestamp(parsed_evidence.valid_until),
        # Placeholder only long enough to build a NORMALIZED statement to
        # derive from. `control_plan_digest_preimage` strips this key by
        # name regardless of its value, so its value here is irrelevant.
        "control_plan_digest": "sha256:" + "0" * 64,
    }
    # `provisional` still carries FIELDS AS THE CALLER SUPPLIED THEM —
    # `authorized_images` in whatever order the caller happened to list
    # them, for one. `AuthorizationStatementV3.as_mapping()` is what
    # PRODUCES the normalized form (canonical image order, canonicalized
    # timestamps) that a verifier reconstructs `control_plan_digest` from
    # (`verify_authorization_envelope_v3` calls
    # `_compute_control_plan_digest(statement.as_mapping())`, never over a
    # caller's raw fields). Computing the digest from `provisional` directly
    # would therefore disagree with the SAME statement's own re-derivation
    # the moment a caller's field order differs from the canonical one --
    # parse once (with the placeholder), derive from that parsed
    # statement's OWN `as_mapping()`, then parse again with the real value.
    # This is what makes issuance and verification compute the digest over
    # the identical representation, always.
    placeholder_statement = _parse_statement_v3(provisional)
    derived_digest = _compute_control_plan_digest(placeholder_statement.as_mapping())
    provisional["control_plan_digest"] = derived_digest

    statement = _parse_statement_v3(provisional)
    if identity.purpose != AUTHORIZATION_V3_PURPOSE:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.PURPOSE_MISMATCH,
            "an authorization signer must declare the deployment authorization "
            "purpose",
        )
    _require_standing_approval(statement)

    signed = signer.sign(statement.canonical_bytes)
    if (
        signed.key_id != statement.key_id
        or signed.algorithm != statement.algorithm
        or signed.public_key_fingerprint != statement.public_key_fingerprint
        or signed.purpose != statement.purpose
    ):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.SIGNER_IDENTITY_MISMATCH,
            "the signer returned a key identity or algorithm different from "
            "the identity already bound into the signed bytes",
        )
    if not signed.signature:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.UNSIGNED,
            "the signer returned an empty signature",
        )
    return AuthorizationEnvelopeV3(statement=statement, signature=signed.signature)


# ── Verification ─────────────────────────────────────────────────────────


def verify_authorization_envelope_v3(
    value: object,
    *,
    verifier: AuthorizationVerifier,
    expected_subject: AuthorizationSubjectV3,
    evidence_document_for_tamper_check: object | None = None,
    at: datetime | None = None,
) -> AuthorizationEnvelopeV3:
    """Authority for THIS deployment, or a refusal naming the term that failed.

    Order: authenticity of Control's own signature first (a forged envelope
    earns no field-level diagnostics), then window and approval standing —
    properties of the envelope — then `control_plan_digest`
    re-derivation, then the subject, term by term, each with its own code.
    If `evidence_document_for_tamper_check` is supplied, its digest is
    RECOMPUTED from the bytes handed in and compared against the bound
    `health_evidence_digest` — the tamper-detection arm this task's proofs
    require (mutate the evidence bytes and the recomputed digest disagrees;
    carrying the digest string alone would not catch that).
    """
    envelope = AuthorizationEnvelopeV3.parse(value)
    statement = envelope.statement
    now = _aware_utc(at or datetime.now(UTC), field="at")

    if not verifier.verify(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes,
        signature=envelope.signature,
    ):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.SIGNATURE_INVALID,
            "the injected verifier refused the signature over the canonical "
            "statement",
        )

    issued = _aware_utc(statement.issued_at, field="issued_at")
    expires = _aware_utc(statement.expires_at, field="expires_at")
    if now < issued:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.NOT_YET_VALID,
            "the authorization was presented before its issued_at instant",
        )
    if now >= expires:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EXPIRED,
            "the authorization has reached its expires_at instant",
        )
    valid_until = _aware_utc(
        statement.health_evidence_valid_until, field="health_evidence_valid_until"
    )
    if now >= valid_until:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EVIDENCE_EXPIRED,
            "the bound health evidence reached its own valid_until instant",
        )
    _require_standing_approval(statement)

    recomputed = _compute_control_plan_digest(statement.as_mapping())
    if recomputed != statement.control_plan_digest:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.CONTROL_PLAN_DIGEST_MISMATCH,
            f"control_plan_digest {statement.control_plan_digest!r} does not "
            f"re-derive from the statement's own bound terms (recomputed "
            f"{recomputed!r})",
        )

    if evidence_document_for_tamper_check is not None:
        parsed = parse_signed_health_evidence_document(
            evidence_document_for_tamper_check
        )
        if parsed.digest.canonical != statement.health_evidence_digest:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.EVIDENCE_DIGEST_MISMATCH,
                "the supplied evidence's digest "
                f"({parsed.digest.canonical}) does not equal the digest bound "
                f"into this authorization ({statement.health_evidence_digest}). "
                "Either the evidence bytes were altered after signing, or this "
                "is evidence for a different evaluation",
            )

    for field, expected_field, code in (
        (
            "product_code",
            "product_code",
            AuthorizationEnvelopeV3RefusalCode.PRODUCT_MISMATCH,
        ),
        (
            "environment",
            "environment",
            AuthorizationEnvelopeV3RefusalCode.ENVIRONMENT_MISMATCH,
        ),
        ("target_id", "target_id", AuthorizationEnvelopeV3RefusalCode.TARGET_MISMATCH),
        (
            "target_ref",
            "target_ref",
            AuthorizationEnvelopeV3RefusalCode.TARGET_MISMATCH,
        ),
        (
            "operation",
            "operation",
            AuthorizationEnvelopeV3RefusalCode.OPERATION_MISMATCH,
        ),
        (
            "release_ref",
            "release_ref",
            AuthorizationEnvelopeV3RefusalCode.RELEASE_MISMATCH,
        ),
        (
            "plan_digest",
            "plan_digest",
            AuthorizationEnvelopeV3RefusalCode.PLAN_MISMATCH,
        ),
        (
            "descriptor_digest",
            "descriptor_digest",
            AuthorizationEnvelopeV3RefusalCode.DESCRIPTOR_MISMATCH,
        ),
        (
            "execution_plan_digest",
            "execution_plan_digest",
            AuthorizationEnvelopeV3RefusalCode.EXECUTION_PLAN_MISMATCH,
        ),
    ):
        granted = getattr(statement, field)
        asked = getattr(expected_subject, expected_field)
        if granted != asked:
            raise _refused(
                code,
                f"the authorization binds {field}={granted!r} and this "
                f"request is {field}={asked!r}",
            )

    if statement.rollout_ref != expected_subject.rollout_ref:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.ROLLOUT_MISMATCH,
            f"the authorization binds rollout_ref={statement.rollout_ref!r} and "
            f"this request is rollout_ref={expected_subject.rollout_ref!r}. "
            "Authority granted for one rollout is not authority under another",
        )
    if statement.execution_sequence != expected_subject.execution_sequence:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.EXECUTION_SEQUENCE_MISMATCH,
            "the authorization binds execution_sequence="
            f"{statement.execution_sequence} and this request is "
            f"execution_sequence={expected_subject.execution_sequence}. "
            "Authority granted for one execution attempt under a rollout is "
            "not authority for another attempt under the same rollout",
        )

    if (
        statement.approval_decision_ref != expected_subject.approval_decision_ref
        or statement.approval_decision_status
        != expected_subject.approval_decision_status
    ):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.APPROVAL_MISMATCH,
            "the authorization binds approval "
            f"({statement.approval_decision_ref!r}, "
            f"{statement.approval_decision_status!r}) and this request "
            f"expects ({expected_subject.approval_decision_ref!r}, "
            f"{expected_subject.approval_decision_status!r})",
        )

    if statement.authorized_images != expected_subject.authorized_images:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.IMAGES_MISMATCH,
            "the authorization binds a different authorized image set than "
            "this request names",
        )

    return envelope


def _require_standing_approval(statement: AuthorizationStatementV3) -> None:
    if statement.approval_decision_status not in {"granted", "approval_exempt"}:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.APPROVAL_NOT_STANDING,
            "the portable authorization does not carry a standing approval; "
            "a signed historical decision is not permission to dispatch",
        )


# ── Parsing helpers ──────────────────────────────────────────────────────

_STATEMENT_KEYS_V3: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "authorization_id",
        "execution_sequence",
        "rollout_ref",
        "plan_id",
        "target_id",
        "target_ref",
        "product_code",
        "environment",
        "operation",
        "release_ref",
        "authorized_images",
        "plan_digest",
        "descriptor_digest",
        "execution_plan_digest",
        "approval_policy_code",
        "approval_policy_version",
        "approval_decision_ref",
        "approval_decision_status",
        "approved_at",
        "issued_at",
        "expires_at",
        "control_version",
        "key_id",
        "algorithm",
        "public_key_fingerprint",
        "health_evidence_digest",
        "required_component_roster",
        "health_evidence_evaluated_at",
        "health_evidence_valid_until",
        "control_plan_digest",
    }
)


def _parse_statement_v3(value: object) -> AuthorizationStatementV3:
    row = _exact_mapping(value, _STATEMENT_KEYS_V3, where="authorization statement")
    if not isinstance(row["schema"], str) or row["schema"] != AUTHORIZATION_V3_SCHEMA:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.SCHEMA_MISMATCH,
            f"unsupported authorization schema {row['schema']!r}",
        )
    if (
        not isinstance(row["version"], int)
        or isinstance(row["version"], bool)
        or row["version"] != AUTHORIZATION_V3_VERSION
    ):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.UNSUPPORTED_VERSION,
            f"unsupported authorization version {row['version']!r}",
        )
    images = authorized_image_set(
        _sequence(row["authorized_images"], field="authorized_images"),
        where="authorization statement image set",
    )
    assert images is not None
    roster_value = _sequence(
        row["required_component_roster"], field="required_component_roster"
    )
    roster: list[str] = []
    for entry in roster_value:
        if not isinstance(entry, str) or not entry:
            raise _refused(
                AuthorizationEnvelopeV3RefusalCode.MALFORMED,
                "required_component_roster entries must be non-empty strings",
            )
        roster.append(entry)
    return AuthorizationStatementV3(
        authorization_id=_text(row, "authorization_id"),
        execution_sequence=_required_positive_int(row, "execution_sequence"),
        rollout_ref=_text(row, "rollout_ref"),
        plan_id=_text(row, "plan_id"),
        target_id=_text(row, "target_id"),
        target_ref=_text(row, "target_ref"),
        product_code=_text(row, "product_code"),
        environment=_text(row, "environment"),
        operation=_text(row, "operation"),
        release_ref=_text(row, "release_ref"),
        authorized_images=images,
        plan_digest=_text(row, "plan_digest"),
        descriptor_digest=_text(row, "descriptor_digest"),
        execution_plan_digest=_text(row, "execution_plan_digest"),
        approval_policy_code=_optional_text(row, "approval_policy_code"),
        approval_policy_version=_optional_int(row, "approval_policy_version"),
        approval_decision_ref=_optional_text(row, "approval_decision_ref"),
        approval_decision_status=_text(row, "approval_decision_status"),
        approved_at=_optional_datetime(row, "approved_at"),
        issued_at=_datetime(row, "issued_at"),
        expires_at=_datetime(row, "expires_at"),
        control_version=_text(row, "control_version"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
        health_evidence_digest=_text(row, "health_evidence_digest"),
        required_component_roster=tuple(roster),
        health_evidence_evaluated_at=_datetime(row, "health_evidence_evaluated_at"),
        health_evidence_valid_until=_datetime(row, "health_evidence_valid_until"),
        control_plan_digest=_text(row, "control_plan_digest"),
        purpose=_text(row, "purpose"),
    )


def _installed_control_version() -> str:
    try:
        value = _distribution_version("dotmac-deployment-control")
    except PackageNotFoundError as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.CONTROL_VERSION_UNAVAILABLE,
            "the issuing dotmac-deployment-control distribution is not "
            "installed; Control will not guess its version from a source "
            "checkout",
        ) from exc
    return _bounded_text(value, field="control_version")


def _exact_mapping(
    value: object, keys: AbstractSet[str], *, where: str
) -> Mapping[str, Any]:
    if value is None:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED, f"{where} is absent"
        )
    if not isinstance(value, Mapping):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{where} must be a mapping, not {type(value).__name__}",
        )
    if any(not isinstance(key, str) for key in value):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{where} keys must all be strings",
        )
    actual = set(value)
    if actual != keys:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{where} keys differ: missing={sorted(keys - actual)}, "
            f"unknown={sorted(actual - keys)}",
        )
    return value


def _text(row: Mapping[str, Any], field: str) -> str:
    value = row[field]
    if not isinstance(value, str):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED, f"{field} must be a string"
        )
    return value


def _optional_text(row: Mapping[str, Any], field: str) -> str | None:
    value = row[field]
    if value is None:
        return None
    return _text(row, field)


def _optional_int(row: Mapping[str, Any], field: str) -> int | None:
    value = row[field]
    if value is None:
        return None
    if not isinstance(value, int) or isinstance(value, bool):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} must be an integer or null",
        )
    return value


def _required_positive_int(row: Mapping[str, Any], field: str) -> int:
    value = row[field]
    if not isinstance(value, int) or isinstance(value, bool) or value < 1:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} must be a positive integer",
        )
    return value


def _sequence(value: object, *, field: str) -> Sequence[object]:
    if not isinstance(value, Sequence) or isinstance(value, str | bytes):
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED, f"{field} must be a sequence"
        )
    return value


def _datetime(row: Mapping[str, Any], field: str) -> datetime:
    value = _text(row, field)
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} is not an ISO-8601 timestamp",
        ) from exc
    return _aware_utc(parsed, field=field)


def _optional_datetime(row: Mapping[str, Any], field: str) -> datetime | None:
    if row[field] is None:
        return None
    return _datetime(row, field)


def _timestamp(value: datetime | None) -> str | None:
    if value is None:
        return None
    return _aware_utc(value, field="timestamp").isoformat().replace("+00:00", "Z")


def _aware_utc(value: datetime, *, field: str) -> datetime:
    if value.tzinfo is None or value.utcoffset() is None:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} must carry a timezone",
        )
    return value.astimezone(UTC)


def _bounded_text(value: object, *, field: str, maximum: int = 512) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} must be a non-empty, whitespace-exact string",
        )
    if len(value) > maximum:
        raise _refused(
            AuthorizationEnvelopeV3RefusalCode.MALFORMED,
            f"{field} exceeds {maximum} characters",
        )
    return value
