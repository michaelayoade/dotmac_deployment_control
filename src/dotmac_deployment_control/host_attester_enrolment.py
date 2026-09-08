"""Binding a Fleet `host_id` to an attester incarnation, and its rotation.

## The custody ruling this implements

Foundation's trusted-provenance verifier needs two producers it does not yet
have: a **candidate signer** (the protected Starter release workflow identity)
and a **host signer** (a separate attester identity *per enrolled host
incarnation*). The two live under separate OpenBao principals and policies,
neither key usable by the other party, and **rebuilding a host revokes the old
key**. This module is the issuing-side contract for the second half: it binds
`host_id` to an attester-key fingerprint and incarnation, and makes
rotation-on-rebuild expressible and enforceable.

It does not build a Foundation verifier and does not build a Platform caller.
Exactly as `recovery_grant.py` and `rehearsal_grant.py` are consumed by a
verifier this repository does not contain, this module is a library a
Foundation-side verifier calls -- it is not that verifier.

## What Fleet measurably has, and what that rules out

Read directly from the Fleet registry (2026-09-08), not inferred:

- `host_id` is canonical, unique across all 26 hosts, zero stale or
  conflicted values. It is a **slug** (`db-primary`, `control-runner`,
  `ns1`), manually assigned in the Fleet declaration -- not derived from
  provider state, and it survives a rebuild only if a human keeps it
  constant. The provider reference (`proxmox:vm/124`) DOES change on
  reprovisioning.
- **There is no incarnation, generation, provisioning epoch or enrolment
  instance anywhere in Fleet.** `last_verified_at` exists; nothing records
  when a host was provisioned or re-imaged.

So `host_id` alone cannot discriminate an old incarnation from a new one --
it is the one value a rebuild is defined to PRESERVE. Anything used as the
incarnation must instead be a value a rebuild is defined to CHANGE.

## The incarnation IS the attester-key fingerprint -- not a second field

This module does not add an `incarnation_id` counter beside the fingerprint.
Two reasons, not one:

1. **Self-enforcement.** An incarnation counter that nobody increments is a
   constant, and evidence bound to a constant replays across a rebuild
   exactly as if unbound. A fingerprint is generated fresh with each new
   attester key, custody is already per-incarnation (a separate OpenBao
   principal per enrolled host incarnation, per the ruling above), and
   revoking the old key is the SAME act as ending the old incarnation. No
   second signal has to be kept in step with the first.
2. **One party cannot author two independent values that are supposed to
   agree.** A composite condition this week made a plant structurally
   unreachable by hiding eleven reasons behind one code; the mirror defect is
   an agreement whose two values are authored by the SAME party -- here, an
   enrolment record's author could pick a fresh fingerprint and a stale
   incarnation counter, or vice versa, and nothing would disagree. Making
   the incarnation *be* the fingerprint removes the second value instead of
   trying to keep two values honest.

The alternatives considered and set aside: a Fleet provisioning epoch (the
conceptually right place to answer "which build is this", but Fleet is
declarative and manually maintained -- nothing computes or increments an
epoch there today, so it would need its own enforcement problem solved
first) and a host-derived value such as machine-id (self-enforcing, but
host-authored: the subject of the claim would be in charge of its own
identity, which is the wrong custody direction here). **If a Fleet
provisioning epoch is added later, it is a second, INDEPENDENT signal that
this module's fingerprint-as-incarnation binding does not need and does not
assume.**

## What makes an old incarnation unusable, stated once

**The event: the host is rebuilt, its old attester key is revoked, and a new
key is generated and enrolled for the same `host_id`.**

**The enforcement, split across what this module owns and what it does not:**

- Structurally: `evaluate_enrolment` never accepts a fingerprint whose known
  status is `REVOKED` or `SUPERSEDED` for *any* host, permanently -- no
  *function* in this module performs or requests that reversal. (This is a
  claim about this module's functions, not about the caller's storage:
  `FingerprintRecord` is a plain exported dataclass, and nothing stops a
  caller from constructing `FingerprintRecord(host, ACTIVE)` directly or
  `dataclasses.replace`-ing one back to `ACTIVE` in ITS OWN registry. The
  guarantee is that this module never does that and never asks its caller
  to.)
- Operationally: evidence signed with the old key carries the old key's
  fingerprint by construction (a signature cannot be transplanted onto a
  different key's identity without invalidating it), so once that
  fingerprint's status is `REVOKED`, `host_attester_standing` reports
  `REVOKED` for every subsequent query naming it -- not just the one that
  observed the rotation.
- What this module does NOT do: hold the durable registry of which
  fingerprint is currently active for which host. Exactly as
  `rehearsal_grant.py`'s `consumed_references` and `recovery_grant.py`'s
  `revoked_grant_ids` are supplied by the caller because this package
  performs no I/O, `active_by_host` and `known_fingerprints` here are
  supplied by whoever holds the durable store. **That store does not exist
  in this repository today** (no migration is added by this module -- see
  "No table added here" below) -- the region behind it is UNMONITORED until
  one does.

## The cut-off rule this module makes expressible

Michael's ruling: whichever of consumption or revocation commits first wins
permanently, and a later revocation cannot reclaim a spent marker. Applied
here: this module never exposes an operation that moves a fingerprint OUT of
`REVOKED` or `SUPERSEDED`. A fingerprint's status is monotone in this
module's vocabulary -- `ACTIVE -> SUPERSEDED` (rotated away) and
`ACTIVE -> REVOKED` (revoked directly) are the only transitions this module's
functions can be asked to honour, and neither one has an inverse here. The
actual atomicity of "whichever commits first" -- i.e. what happens when a
consumption and a revocation race against the same durable row -- is the
holder-of-the-store's problem (a unique/compare-and-swap write, most likely
the Kernel idempotency ledger for the consumption half), and this module
states plainly that it does not resolve that race: it only refuses to ever
answer "no longer revoked."

## Evaluation order in `evaluate_enrolment`, and why

Two things could be judged first: the presented fingerprint's own global
status (is it already active for someone, revoked, or superseded), or the
target host's current binding (does it already have an active fingerprint,
or nothing to rotate away from). **This module judges the fingerprint's
global status first.** A `REVOKED` fingerprint presented as a fresh
enrolment for an already-enrolled host is reported as `FINGERPRINT_REVOKED`
-- never as `HOST_ALREADY_ENROLLED`, which would be true but would never
mention the revocation, the more urgent and more specific fact. The
fingerprint's namespace is global and permanent; the host's binding is
local and current; the more permanent fact is reported first.

The same reasoning extends to rotation: before trusting `active_by_host`'s
claim about what a rotation supersedes, `evaluate_enrolment` additionally
looks up the SUPERSEDED fingerprint itself in `known_fingerprints` and
requires it to be present, `ACTIVE`, and recorded against the SAME host
named in the statement. `active_by_host` alone is not trusted for the most
destructive operation this module can request -- superseding a fingerprint
retires it PERMANENTLY, so a rotation for host B naming a fingerprint that
`known_fingerprints` actually records as host A's active attester is
refused (`SUPERSEDES_FINGERPRINT_WRONG_HOST`) even if `active_by_host`
(a second, independently-supplied map) claims otherwise. This is the same
principle `host_attester_standing` already applies to its own two maps --
extended to the write path, where it matters more.

## `evaluate_enrolment` takes a STATEMENT, not a verified envelope

Unlike `recovery_grant.verify_recovery_grant` and
`rehearsal_grant.verify_rehearsal_grant`, which authenticate a signature and
apply their caller-supplied revocation/consumption sets in the SAME call,
this module splits authentication (`verify_host_attester_enrolment`) from
the registry-conflict check (`evaluate_enrolment`) into two functions. That
split means `evaluate_enrolment`'s `statement` parameter is NOT
cryptographically bound to anything by the time it is called -- every field
on it is caller-fabricable, and "no exception" is the only signal of
success. **The caller's obligation, stated here because nothing in the type
system enforces it:** always call `evaluate_enrolment` on
`verify_host_attester_enrolment(...).statement`, the product of a verified
envelope, never on a hand-built or merely-parsed statement.
`HostAttesterEnrolmentV1.parse`'s promise that "a caller cannot assemble one
from loose parts" protects the ENVELOPE; it says nothing about what a
caller does with a `HostAttesterEnrolmentStatementV1` obtained some other
way, which is exactly why this sentence exists.

## No table added here

`evaluate_enrolment` and `host_attester_standing` take `active_by_host` and
`known_fingerprints` as plain mappings the caller assembles. This mirrors
`recovery_grant.py` and `rehearsal_grant.py` exactly and is a deliberate
choice for this slice: `models.py` and the migration lineage are a sibling
lane's read-only territory for this task, and a genuine durable table for
"the currently active fingerprint per host_id" (which this contract will
eventually need, on the same shape as `TargetCredential`'s
`uq_target_credentials_fingerprint`) is real schema work that needs
sequencing with that lane, not a race against it. That is reported, not
silently deferred.

## The URN grammar is not frozen here, and here is what would freeze it

Nothing in this module assigns a global identifier scheme spanning Control,
Foundation and Fleet for "host X, incarnation Y" (e.g. a URN). Before that
can be frozen, someone with authority over both repositories needs to decide:
whether the wire form of an incarnation is the bare fingerprint text
(`sha256:<hex>`, what this module produces) or a composite
`urn:dotmac:host:<host_id>:<fingerprint>`; and whether a future Fleet
provisioning epoch, if it is built, becomes a THIRD bound term or stays out
of the URN entirely as Fleet-internal metadata. Both remain open.

**One sub-question is retired, not open.** Whether Fleet's `host_id` slug
alphabet is a closed DNS-label grammar `require_host_id` may validate
against, or an open string this module should only bound in length, was
open when this module was first written (it validated against three
example slugs only: `db-primary`, `control-runner`, `ns1`). It has since
been checked against ALL 26 Fleet hosts, and every one matches the DNS-label
grammar below -- so the closed grammar is safe to freeze and `require_host_id`
keeps enforcing it. If Fleet ever declares a `host_id` outside this
grammar, that host is unenrollable here until either Fleet's declaration or
this grammar changes -- a decision for whoever owns that declaration, not
this module.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Final, Protocol, runtime_checkable

from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.ports import DeploymentControlError, DigestEncodingError

__all__ = [
    "HOST_ATTESTER_ENROLMENT_PURPOSE",
    "HOST_ATTESTER_ENROLMENT_SCHEMA",
    "HOST_ATTESTER_ENROLMENT_VERSION",
    "FingerprintRecord",
    "FingerprintStatus",
    "HostAttesterEnrolmentRefusalCode",
    "HostAttesterEnrolmentRefusedError",
    "HostAttesterEnrolmentSignature",
    "HostAttesterEnrolmentSigner",
    "HostAttesterEnrolmentSignerIdentity",
    "HostAttesterEnrolmentStatementV1",
    "HostAttesterEnrolmentV1",
    "HostAttesterEnrolmentVerifier",
    "HostAttesterStanding",
    "HostAttesterStandingResult",
    "evaluate_enrolment",
    "host_attester_standing",
    "issue_host_attester_enrolment",
    "require_custody_pointer",
    "require_host_id",
    "verify_host_attester_enrolment",
]

#: The signer purpose. Separate from `deployment_authorization`,
#: `deployment_dispatch`, `target_execution_observation`, `deployment_recovery`
#: and `deployment_rehearsal`: one key answering two questions cannot be used
#: to contradict itself, and the enrolment authority is not any of those five.
HOST_ATTESTER_ENROLMENT_PURPOSE: Final = "host_attester_enrolment"
HOST_ATTESTER_ENROLMENT_SCHEMA: Final = (
    "dotmac.deployment_control.host_attester_enrolment"
)
HOST_ATTESTER_ENROLMENT_VERSION: Final = 1

_MAX_TEXT = 512
#: DNS-label shape, matching Fleet's measured examples (`db-primary`,
#: `control-runner`, `ns1`): lowercase alphanumerics, hyphen-separated,
#: 1-63 characters, no leading/trailing hyphen. This is a bound on what this
#: module accepts, not a claim that Fleet enforces the same grammar.
_HOST_ID = re.compile(r"\A[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\Z")
#: The one approved custody-pointer scheme observed in this repository
#: (`docs/CONTROL_EXCEPTIONS.md`: `bao://secret/dotmac/...`). A structural
#: check on SHAPE, never a scanner for secret CONTENT -- see the module
#: docstring's constraints section for what this does and does not establish.
_CUSTODY_SCHEME = "bao://"


class FingerprintStatus(StrEnum):
    """What a known fingerprint is, in the caller-supplied registry.

    Monotone: this module exposes no function that moves a fingerprint out of
    `SUPERSEDED` or `REVOKED`. Whoever holds the durable registry may of
    course still write anything to a column; the guarantee here is only that
    nothing IN THIS MODULE ever asks for or performs that reversal.
    """

    ACTIVE = "active"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class FingerprintRecord:
    """One row of the caller-supplied fingerprint registry."""

    host_id: str
    status: FingerprintStatus


class HostAttesterEnrolmentRefusalCode(StrEnum):
    """Why an enrolment or rotation statement does not bind. One code per
    condition -- an aggregate would tell an operator only that something
    among several unrelated things was wrong."""

    MALFORMED = "host_attester_enrolment_malformed"
    SCHEMA_MISMATCH = "host_attester_enrolment_schema_mismatch"
    PURPOSE_MISMATCH = "host_attester_enrolment_purpose_mismatch"
    SIGNER_PURPOSE_REUSED = "host_attester_enrolment_signer_purpose_reused"
    UNSIGNED = "host_attester_enrolment_unsigned"
    SIGNATURE_INVALID = "host_attester_enrolment_signature_invalid"
    HOST_ID_MALFORMED = "host_attester_enrolment_host_id_malformed"
    CUSTODY_POINTER_MALFORMED = "host_attester_enrolment_custody_pointer_malformed"
    FINGERPRINT_KEY_MISMATCH = "host_attester_enrolment_fingerprint_key_mismatch"
    SUPERSEDES_EQUALS_NEW = "host_attester_enrolment_supersedes_equals_new"
    #: Verify-time subject binding: the statement names a different host.
    HOST_ID_MISMATCH = "host_attester_enrolment_host_id_mismatch"
    #: Verify-time subject binding: the statement names a different key.
    FINGERPRINT_MISMATCH = "host_attester_enrolment_fingerprint_mismatch"
    #: `evaluate_enrolment`: an initial enrolment for a host that already has
    #: an active fingerprint. The repair is a rotation, not a new initial.
    HOST_ALREADY_ENROLLED = "host_attester_enrolment_host_already_enrolled"
    #: `evaluate_enrolment`: a rotation for a host with no active fingerprint
    #: to supersede.
    SUPERSEDES_WITHOUT_ACTIVE_ENROLMENT = (
        "host_attester_enrolment_supersedes_without_active_enrolment"
    )
    #: `evaluate_enrolment`: the rotation names a `supersedes_fingerprint`
    #: that is not the host's actual current active fingerprint, per
    #: `active_by_host`.
    SUPERSEDED_FINGERPRINT_MISMATCH = (
        "host_attester_enrolment_superseded_fingerprint_mismatch"
    )
    #: `evaluate_enrolment`: `active_by_host` and `known_fingerprints` agree
    #: on WHICH fingerprint is being superseded, but `known_fingerprints` has
    #: never heard of it. `active_by_host` alone is not trusted for the most
    #: destructive operation this module can request.
    SUPERSEDES_FINGERPRINT_UNKNOWN = (
        "host_attester_enrolment_supersedes_fingerprint_unknown"
    )
    #: `evaluate_enrolment`: the fingerprint being superseded is known but is
    #: not currently `ACTIVE` (already `REVOKED` or `SUPERSEDED`) -- it
    #: cannot be superseded a second time.
    SUPERSEDES_FINGERPRINT_NOT_ACTIVE = (
        "host_attester_enrolment_supersedes_fingerprint_not_active"
    )
    #: `evaluate_enrolment`: the fingerprint being superseded is `ACTIVE`,
    #: but `known_fingerprints` records it against a DIFFERENT host than the
    #: one this rotation names. This is the case a rotation must never be
    #: allowed to reach: retiring another host's attester by naming it as
    #: something this host is rotating away from.
    SUPERSEDES_FINGERPRINT_WRONG_HOST = (
        "host_attester_enrolment_supersedes_fingerprint_wrong_host"
    )
    #: `evaluate_enrolment`: the new fingerprint is already the ACTIVE
    #: attester for THIS SAME host -- a no-op resubmission masquerading as a
    #: fresh enrolment; rotation requires a NEW fingerprint. Distinct from
    #: `FINGERPRINT_REUSED_ACROSS_HOSTS`, which is the cross-host case.
    FINGERPRINT_ALREADY_ENROLLED = (
        "host_attester_enrolment_fingerprint_already_enrolled"
    )
    #: `evaluate_enrolment`: the new fingerprint is currently active for a
    #: DIFFERENT host. Two hosts sharing one incarnation.
    FINGERPRINT_REUSED_ACROSS_HOSTS = (
        "host_attester_enrolment_fingerprint_reused_across_hosts"
    )
    #: `evaluate_enrolment`: the fingerprint was revoked. Permanent; there is
    #: no un-revoke in this module's vocabulary.
    FINGERPRINT_REVOKED = "host_attester_enrolment_fingerprint_revoked"
    #: `evaluate_enrolment`: the fingerprint was previously rotated away
    #: (superseded), including by the SAME host. Permanent; rotation never
    #: rewinds to a prior key.
    FINGERPRINT_SUPERSEDED = "host_attester_enrolment_fingerprint_superseded"


class HostAttesterEnrolmentRefusedError(DeploymentControlError):
    """An enrolment or rotation statement that does not bind, and why."""

    def __init__(self, code: HostAttesterEnrolmentRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _refused(
    code: HostAttesterEnrolmentRefusalCode, detail: str
) -> HostAttesterEnrolmentRefusedError:
    return HostAttesterEnrolmentRefusedError(code, detail)


class HostAttesterStanding(StrEnum):
    """What a fingerprint is RIGHT NOW for a named host, as a surface may ask.

    `ABSENT` is a claim, not a failure: nobody has enrolled an attester for
    this host. Distinguished from `REVOKED`/`SUPERSEDED` because an operator
    needs to know whether nobody enrolled one, somebody withdrew one, or one
    was rotated away.

    One member per condition, on the same rule
    `HostAttesterEnrolmentRefusalCode` follows: `WRONG_HOST`,
    `NOT_ACTIVE_FOR_HOST` and `REGISTRY_DISAGREEMENT` were previously folded
    into a single `WRONG_HOST`, and each names a different operator action --
    "wrong fingerprint for this host" is not "this host has no active
    fingerprint at all", and neither is "the two registry maps disagree with
    each other", which is a caller-side data-integrity fault rather than a
    fact about this fingerprint.
    """

    VALID = "valid"
    ABSENT = "absent"
    #: `known_fingerprints` says this fingerprint is ACTIVE for a DIFFERENT
    #: host than the one asked about.
    WRONG_HOST = "wrong_host"
    #: `known_fingerprints` says this fingerprint is ACTIVE for the asked
    #: host, but `active_by_host` has no entry for that host at all.
    NOT_ACTIVE_FOR_HOST = "not_active_for_host"
    #: `known_fingerprints` says this fingerprint is ACTIVE for the asked
    #: host, and `active_by_host` names a DIFFERENT fingerprint for that same
    #: host -- the two caller-supplied maps contradict each other, and
    #: neither is trusted alone.
    REGISTRY_DISAGREEMENT = "registry_disagreement"
    SUPERSEDED = "superseded"
    REVOKED = "revoked"


@dataclass(frozen=True, slots=True)
class HostAttesterStandingResult:
    standing: HostAttesterStanding

    @property
    def authorizes(self) -> bool:
        """The ONE question a surface may ask. Derived, never a stored flag."""
        return self.standing is HostAttesterStanding.VALID


def require_host_id(value: object, *, where: str) -> str:
    """The Fleet-slug shape this module accepts. See the module docstring's
    "URN grammar is not frozen here" section for what is and is not settled."""
    if not isinstance(value, str) or not _HOST_ID.match(value):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.HOST_ID_MALFORMED,
            f"{where}: {value!r} is not a Fleet-shaped host_id (lowercase "
            "alphanumerics and hyphens, 1-63 characters, no leading/trailing "
            "hyphen)",
        )
    return value


def require_custody_pointer(value: object, *, where: str) -> str:
    """A `bao://` PATH POINTER, never a key or a secret value.

    This is a structural shape check, not a secret-content scanner: it
    refuses the wrong SCHEME and excess length, and cannot and does not
    attempt to distinguish a well-formed pointer from a well-formed pointer
    someone mistakenly populated with a live token. Say plainly what this
    does and does not establish.
    """
    if not isinstance(value, str) or not value.strip() or value != value.strip():
        raise _refused(
            HostAttesterEnrolmentRefusalCode.CUSTODY_POINTER_MALFORMED,
            f"{where}: a custody pointer must be non-empty exact text",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.CUSTODY_POINTER_MALFORMED,
            f"{where}: custody pointer exceeds {_MAX_TEXT} characters",
        )
    if "\n" in value or "\r" in value or " " in value:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.CUSTODY_POINTER_MALFORMED,
            f"{where}: custody pointer must not contain whitespace",
        )
    if not value.startswith(_CUSTODY_SCHEME):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.CUSTODY_POINTER_MALFORMED,
            f"{where}: {value!r} does not start with {_CUSTODY_SCHEME!r} -- a "
            "custody pointer names WHERE the key lives in OpenBao, never the "
            "key itself",
        )
    return value


@dataclass(frozen=True, slots=True)
class HostAttesterEnrolmentSignerIdentity:
    """The enrolment authority. A distinct identity from the attester key it
    enrols -- the signer authorizes the binding; it does not hold the bound
    key. Also distinct from every other purpose's signer identity in this
    package (see `HOST_ATTESTER_ENROLMENT_PURPOSE`)."""

    key_id: str
    algorithm: str
    public_key_fingerprint: str
    purpose: str = HOST_ATTESTER_ENROLMENT_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != HOST_ATTESTER_ENROLMENT_PURPOSE:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.PURPOSE_MISMATCH,
                "a host-attester enrolment signer must declare "
                f"{HOST_ATTESTER_ENROLMENT_PURPOSE!r}, not {self.purpose!r}",
            )


@dataclass(frozen=True, slots=True)
class HostAttesterEnrolmentSignature:
    key_id: str
    algorithm: str
    purpose: str
    public_key_fingerprint: str
    signature: str


@runtime_checkable
class HostAttesterEnrolmentSigner(Protocol):
    @property
    def enrolment_identity(self) -> HostAttesterEnrolmentSignerIdentity: ...

    def sign_enrolment(
        self, canonical_bytes: bytes
    ) -> HostAttesterEnrolmentSignature: ...


@runtime_checkable
class HostAttesterEnrolmentVerifier(Protocol):
    def verify_enrolment(
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
class HostAttesterEnrolmentStatementV1:
    """The signed terms binding `host_id` to one attester incarnation.

    No separate `incarnation_id` field -- see the module docstring for why
    the incarnation IS `public_key_fingerprint`. `supersedes_fingerprint`
    empty (`""`) means this is the host's FIRST enrolment; non-empty means
    this is a ROTATION, and it must name the exact fingerprint being
    replaced (checked by `evaluate_enrolment`, which is where the caller's
    registry is consulted -- this constructor only checks internal
    consistency).
    """

    enrolment_id: str
    host_id: str
    public_key_b64: str
    public_key_fingerprint: str
    supersedes_fingerprint: str
    key_custody_pointer: str
    issued_at: datetime
    control_version: str
    key_id: str
    algorithm: str
    public_key_fingerprint_signer: str  # the ENROLMENT AUTHORITY's own key
    purpose: str = HOST_ATTESTER_ENROLMENT_PURPOSE

    def __post_init__(self) -> None:
        if self.purpose != HOST_ATTESTER_ENROLMENT_PURPOSE:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.PURPOSE_MISMATCH,
                "a host-attester enrolment statement must declare "
                f"{HOST_ATTESTER_ENROLMENT_PURPOSE!r}",
            )
        require_host_id(self.host_id, where="host_id")
        require_custody_pointer(self.key_custody_pointer, where="key_custody_pointer")
        derived = PublicKeyFingerprintV1.from_public_key_b64(self.public_key_b64)
        try:
            recorded = PublicKeyFingerprintV1.parse(self.public_key_fingerprint)
        except DigestEncodingError as exc:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.MALFORMED,
                f"public_key_fingerprint is not a canonical digest: {exc}",
            ) from exc
        if derived != recorded:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.FINGERPRINT_KEY_MISMATCH,
                "the stated public_key_fingerprint does not match the "
                "fingerprint derived from public_key_b64 -- a caller cannot "
                "give the same key two identities or enrol an unrelated "
                "fingerprint",
            )
        if self.supersedes_fingerprint:
            if self.supersedes_fingerprint == self.public_key_fingerprint:
                raise _refused(
                    HostAttesterEnrolmentRefusalCode.SUPERSEDES_EQUALS_NEW,
                    "a rotation must name a NEW fingerprint; "
                    "supersedes_fingerprint equals public_key_fingerprint",
                )
            try:
                PublicKeyFingerprintV1.parse(self.supersedes_fingerprint)
            except DigestEncodingError as exc:
                raise _refused(
                    HostAttesterEnrolmentRefusalCode.MALFORMED,
                    f"supersedes_fingerprint is not a canonical digest: {exc}",
                ) from exc
        if self.issued_at.tzinfo is None:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.MALFORMED,
                "issued_at is naive; an instant without a zone is not an instant",
            )

    @property
    def is_rotation(self) -> bool:
        return bool(self.supersedes_fingerprint)

    #: The incarnation identity. A property, not a field: it is defined as
    #: `public_key_fingerprint` rather than stored a second time, so there is
    #: structurally nowhere for the two to disagree.
    @property
    def incarnation_id(self) -> str:
        return self.public_key_fingerprint

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": HOST_ATTESTER_ENROLMENT_SCHEMA,
            "version": HOST_ATTESTER_ENROLMENT_VERSION,
            "purpose": self.purpose,
            "enrolment_id": self.enrolment_id,
            "host_id": self.host_id,
            "public_key_b64": self.public_key_b64,
            "public_key_fingerprint": self.public_key_fingerprint,
            "supersedes_fingerprint": self.supersedes_fingerprint,
            "key_custody_pointer": self.key_custody_pointer,
            "issued_at": _timestamp(self.issued_at),
            "control_version": self.control_version,
            "key_id": self.key_id,
            "algorithm": self.algorithm,
            "public_key_fingerprint_signer": self.public_key_fingerprint_signer,
        }

    def canonical_bytes(self) -> bytes:
        return json.dumps(
            self.as_mapping(), sort_keys=True, separators=(",", ":")
        ).encode("utf-8")


@dataclass(frozen=True, slots=True)
class HostAttesterEnrolmentV1:
    """A parsed enrolment/rotation envelope. Only `parse` or `issue` produce
    one -- a caller cannot assemble one from loose parts."""

    statement: HostAttesterEnrolmentStatementV1
    signature: str

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @classmethod
    def parse(cls, value: object) -> HostAttesterEnrolmentV1:
        if not isinstance(value, Mapping):
            raise _refused(
                HostAttesterEnrolmentRefusalCode.MALFORMED,
                f"a host-attester enrolment must be a mapping, got "
                f"{type(value).__name__}",
            )
        if set(value) != {"statement", "signature"}:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.MALFORMED,
                "a host-attester enrolment envelope has exactly statement and "
                f"signature; got {sorted(str(key) for key in value)}",
            )
        signature = value["signature"]
        if not isinstance(signature, str) or not signature.strip():
            raise _refused(
                HostAttesterEnrolmentRefusalCode.UNSIGNED,
                "the host-attester enrolment carries no signature",
            )
        return cls(statement=_parse_statement(value["statement"]), signature=signature)


_STATEMENT_KEYS = frozenset(
    {
        "schema",
        "version",
        "purpose",
        "enrolment_id",
        "host_id",
        "public_key_b64",
        "public_key_fingerprint",
        "supersedes_fingerprint",
        "key_custody_pointer",
        "issued_at",
        "control_version",
        "key_id",
        "algorithm",
        "public_key_fingerprint_signer",
    }
)


def _timestamp(value: datetime) -> str:
    return value.astimezone(UTC).isoformat().replace("+00:00", "Z")


def _text(row: Mapping[str, Any], field: str, *, allow_empty: bool = False) -> str:
    value = row.get(field)
    if not isinstance(value, str):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED, f"{field} must be text"
        )
    if not allow_empty and not value.strip():
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"{field} must be non-empty text",
        )
    if len(value) > _MAX_TEXT:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"{field} exceeds {_MAX_TEXT} characters",
        )
    return value


def _instant(row: Mapping[str, Any], field: str) -> datetime:
    value = row.get(field)
    if not isinstance(value, str):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"{field} must be an ISO instant",
        )
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as error:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"{field} is not an instant: {error}",
        ) from error
    if parsed.tzinfo is None:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"{field} is naive; an instant without a zone is not an instant",
        )
    return parsed.astimezone(UTC)


def _parse_statement(value: object) -> HostAttesterEnrolmentStatementV1:
    if not isinstance(value, Mapping):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"a host-attester enrolment statement must be a mapping, got "
            f"{type(value).__name__}",
        )
    row: Mapping[str, Any] = value
    # SCHEMA FIRST, before any field is read -- this is how a document that
    # is not a host-attester enrolment is refused before a single term is
    # compared.
    if row.get("schema") != HOST_ATTESTER_ENROLMENT_SCHEMA:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.SCHEMA_MISMATCH,
            f"{row.get('schema')!r} is not {HOST_ATTESTER_ENROLMENT_SCHEMA!r}",
        )
    if row.get("version") != HOST_ATTESTER_ENROLMENT_VERSION:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.SCHEMA_MISMATCH,
            f"unsupported host-attester enrolment version {row.get('version')!r}",
        )
    keys = set(row)
    missing = sorted(_STATEMENT_KEYS - keys)
    unexpected = sorted(str(key) for key in keys - _STATEMENT_KEYS)
    if missing or unexpected:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.MALFORMED,
            f"host-attester enrolment statement keys differ: missing={missing}, "
            f"unexpected={unexpected}",
        )
    return HostAttesterEnrolmentStatementV1(
        enrolment_id=_text(row, "enrolment_id"),
        host_id=_text(row, "host_id"),
        public_key_b64=_text(row, "public_key_b64"),
        public_key_fingerprint=_text(row, "public_key_fingerprint"),
        supersedes_fingerprint=_text(row, "supersedes_fingerprint", allow_empty=True),
        key_custody_pointer=_text(row, "key_custody_pointer"),
        issued_at=_instant(row, "issued_at"),
        control_version=_text(row, "control_version"),
        key_id=_text(row, "key_id"),
        algorithm=_text(row, "algorithm"),
        public_key_fingerprint_signer=_text(row, "public_key_fingerprint_signer"),
        purpose=_text(row, "purpose"),
    )


def issue_host_attester_enrolment(
    statement: HostAttesterEnrolmentStatementV1, *, signer: HostAttesterEnrolmentSigner
) -> HostAttesterEnrolmentV1:
    """Sign an enrolment or rotation statement. Takes the TYPE, never a mapping."""
    if not isinstance(signer, HostAttesterEnrolmentSigner):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.PURPOSE_MISMATCH,
            "the injected signer does not implement the host-attester "
            "enrolment purpose",
        )
    identity = signer.enrolment_identity
    if not isinstance(identity, HostAttesterEnrolmentSignerIdentity):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.PURPOSE_MISMATCH,
            "the signer did not expose a host-attester enrolment identity",
        )
    if identity.public_key_fingerprint != statement.public_key_fingerprint_signer:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.SIGNER_PURPOSE_REUSED,
            "the statement names a different signer key than the signer holds",
        )
    signed = signer.sign_enrolment(statement.canonical_bytes())
    if not signed.signature.strip():
        raise _refused(
            HostAttesterEnrolmentRefusalCode.UNSIGNED,
            "the enrolment signer returned an empty signature",
        )
    return HostAttesterEnrolmentV1(statement=statement, signature=signed.signature)


def verify_host_attester_enrolment(
    value: object,
    *,
    verifier: HostAttesterEnrolmentVerifier,
) -> HostAttesterEnrolmentV1:
    """Authenticity of the ENVELOPE only: schema, signature, well-formedness.

    Does not consult the fingerprint registry -- that is `evaluate_enrolment`
    (issuance-time conflict checks, and ONLY on the `.statement` this function
    returns -- see the module docstring's "takes a STATEMENT, not a verified
    envelope" section) and `host_attester_standing` (a later query of "is this
    still the active attester for this host"), because this module performs
    no I/O and holds no registry itself.

    Deliberately no `at` parameter. Unlike `RecoveryGrantStatementV1` and
    `RehearsalGrantStatementV1`, this statement carries no `not_before`/
    `expires_at` -- there is nothing for an instant to be compared against.
    An earlier version of this function accepted `at` and silently discarded
    it, which is worse than no parameter: an authority-shaped argument that
    does nothing reads as a check that is not actually performed. If a
    validity window is added to the statement later, `at` is reintroduced
    bound to it, not restored as a no-op.
    """
    if not isinstance(verifier, HostAttesterEnrolmentVerifier):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier does not implement host-attester "
            "enrolment verification",
        )
    envelope = HostAttesterEnrolmentV1.parse(value)
    statement = envelope.statement
    if not verifier.verify_enrolment(
        key_id=statement.key_id,
        algorithm=statement.algorithm,
        purpose=statement.purpose,
        public_key_fingerprint=statement.public_key_fingerprint_signer,
        canonical_bytes=statement.canonical_bytes(),
        signature=envelope.signature,
    ):
        raise _refused(
            HostAttesterEnrolmentRefusalCode.SIGNATURE_INVALID,
            "the host-attester enrolment signature does not verify over its "
            "canonical bytes",
        )
    return envelope


def evaluate_enrolment(
    statement: HostAttesterEnrolmentStatementV1,
    *,
    active_by_host: Mapping[str, str],
    known_fingerprints: Mapping[str, FingerprintRecord],
) -> None:
    """Refuse an enrolment/rotation the caller's registry cannot admit.

    `active_by_host` maps `host_id -> currently active fingerprint`.
    `known_fingerprints` maps `fingerprint -> FingerprintRecord` for every
    fingerprint this registry has ever seen, active or not -- the permanent
    global namespace a fingerprint value lives in. Neither is held by this
    module; both are the caller's durable state, read immediately before the
    write that would admit this statement (their atomicity is the caller's
    responsibility, per the module docstring's cut-off-rule section).

    `statement` must be `verify_host_attester_enrolment(...).statement` --
    see the module docstring's "takes a STATEMENT, not a verified envelope"
    section for why this function cannot itself enforce that.

    Raises on any conflict; returns `None` (silently) when the statement may
    be admitted. Order is deliberate -- see the module docstring's
    "Evaluation order" section: the presented fingerprint's own global,
    permanent status is judged BEFORE the target host's current, local
    binding, and a rotation's superseded fingerprint is independently
    cross-checked against `known_fingerprints` rather than trusted from
    `active_by_host` alone.
    """
    new_fp = statement.public_key_fingerprint

    # 1. The new fingerprint's own global-namespace status, judged first: a
    #    revoked, superseded, or cross-host-active fingerprint is the more
    #    permanent and more urgent fact, and must be named even when the
    #    fingerprint is ALSO being presented to an already-enrolled host.
    known_new = known_fingerprints.get(new_fp)
    if known_new is not None:
        if known_new.status is FingerprintStatus.REVOKED:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.FINGERPRINT_REVOKED,
                f"fingerprint {new_fp!r} was revoked and cannot be re-enrolled "
                "for any host",
            )
        if known_new.status is FingerprintStatus.SUPERSEDED:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.FINGERPRINT_SUPERSEDED,
                f"fingerprint {new_fp!r} was previously rotated away and "
                "cannot be re-enrolled for any host, including its own prior "
                "host",
            )
        # ACTIVE.
        if known_new.host_id != statement.host_id:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.FINGERPRINT_REUSED_ACROSS_HOSTS,
                f"fingerprint {new_fp!r} is the active attester for host "
                f"{known_new.host_id!r}; it cannot also be enrolled for "
                f"{statement.host_id!r}",
            )
        raise _refused(
            HostAttesterEnrolmentRefusalCode.FINGERPRINT_ALREADY_ENROLLED,
            f"fingerprint {new_fp!r} is already the active attester for host "
            f"{statement.host_id!r}",
        )

    # 2. The target host's current binding.
    current_for_host = active_by_host.get(statement.host_id)

    if statement.is_rotation:
        if current_for_host is None:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.SUPERSEDES_WITHOUT_ACTIVE_ENROLMENT,
                f"host {statement.host_id!r} has no active attester to "
                "rotate away from; use an initial enrolment instead",
            )
        if current_for_host != statement.supersedes_fingerprint:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.SUPERSEDED_FINGERPRINT_MISMATCH,
                f"host {statement.host_id!r}'s active attester fingerprint is "
                f"{current_for_host!r}; this rotation names "
                f"{statement.supersedes_fingerprint!r}",
            )
        # 3. `active_by_host` named the right fingerprint; now cross-check
        #    the SUPERSEDED fingerprint's own record. This is the most
        #    destructive operation this module can request -- it retires a
        #    fingerprint PERMANENTLY -- so `active_by_host` alone is not
        #    trusted for it, on the same principle `host_attester_standing`
        #    already applies read-side.
        superseded_known = known_fingerprints.get(statement.supersedes_fingerprint)
        if superseded_known is None:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_UNKNOWN,
                f"supersedes_fingerprint {statement.supersedes_fingerprint!r} "
                "has no record in known_fingerprints",
            )
        if superseded_known.status is not FingerprintStatus.ACTIVE:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_NOT_ACTIVE,
                f"supersedes_fingerprint {statement.supersedes_fingerprint!r} "
                f"is {superseded_known.status.value!r}, not active, and "
                "cannot be superseded a second time",
            )
        if superseded_known.host_id != statement.host_id:
            raise _refused(
                HostAttesterEnrolmentRefusalCode.SUPERSEDES_FINGERPRINT_WRONG_HOST,
                f"supersedes_fingerprint {statement.supersedes_fingerprint!r} "
                f"is recorded as host {superseded_known.host_id!r}'s active "
                f"attester, not {statement.host_id!r}'s -- a rotation cannot "
                "retire another host's key",
            )
    elif current_for_host is not None:
        raise _refused(
            HostAttesterEnrolmentRefusalCode.HOST_ALREADY_ENROLLED,
            f"host {statement.host_id!r} already has an active attester "
            f"fingerprint ({current_for_host!r}); use a rotation, not a new "
            "initial enrolment",
        )


def host_attester_standing(
    *,
    host_id: str,
    fingerprint: str,
    active_by_host: Mapping[str, str],
    known_fingerprints: Mapping[str, FingerprintRecord],
) -> HostAttesterStandingResult:
    """What a surface (or a Foundation verifier) may ask: is `fingerprint`
    RIGHT NOW the enrolled attester for `host_id`. Derived from the caller's
    registry snapshot and nothing else."""
    known = known_fingerprints.get(fingerprint)
    if known is None:
        return HostAttesterStandingResult(HostAttesterStanding.ABSENT)
    if known.status is FingerprintStatus.REVOKED:
        return HostAttesterStandingResult(HostAttesterStanding.REVOKED)
    if known.status is FingerprintStatus.SUPERSEDED:
        return HostAttesterStandingResult(HostAttesterStanding.SUPERSEDED)
    # ACTIVE.
    if known.host_id != host_id:
        return HostAttesterStandingResult(HostAttesterStanding.WRONG_HOST)
    active_fp = active_by_host.get(host_id)
    if active_fp is None:
        return HostAttesterStandingResult(HostAttesterStanding.NOT_ACTIVE_FOR_HOST)
    if active_fp != fingerprint:
        # The two caller-supplied maps contradict each other: refuse rather
        # than trust either one alone.
        return HostAttesterStandingResult(HostAttesterStanding.REGISTRY_DISAGREEMENT)
    return HostAttesterStandingResult(HostAttesterStanding.VALID)
