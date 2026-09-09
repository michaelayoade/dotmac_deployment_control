"""The public, read-only, versioned facade over the durable attestation trust
registry (`attestation_trust_registry.py`).

## What this module is, in one sentence

A thin, typed translation layer: every answer this module returns is derived
by calling straight into `attestation_trust_registry`'s own read functions
against Control's durable tables, then copied into a plain, versioned,
serialisable dataclass -- nothing here holds, computes, or caches trust state
of its own.

## The defect this module does NOT reintroduce

The module this replaces (`feat/control-public-binding-api`,
`host_attester_binding.py`) predates the durable registry and took
`active_by_host`/`known_fingerprints` as plain CALLER-SUPPLIED mappings --
"the caller currently supplies the registry that decides whether the
caller's own key is trusted", the exact defect `attestation_trust_registry.py`
exists to close (see that module's docstring and
`tests/architecture/test_host_attester_enrolment_is_private.py`, which already
proves no function signature in this package's sibling module reintroduces
those two parameter names). This module carries no equivalent: every function
below takes a `Session` and a plain identity to look up (`custody_domain`,
`subject`, or `fingerprint`) -- never a mapping standing in for the registry,
and never a parameter that lets a caller pick WHICH of several candidate
answers to treat as current. `tests/unit/test_host_attester_enrolment.py`'s
sibling guard (`_CALLER_SUPPLIED_PARAMS`) is extended by this module's own
architecture test to cover this file too.

## What "read-only" means here, structurally

No function in this module calls `session.add`, `session.flush`,
`session.commit`, `session.execute` with an `INSERT`/`UPDATE`/`DELETE`, or any
`attestation_trust_registry` function that writes
(`enrol_root`/`rotate_root`/`revoke_root`/`repair_current_root`). Only
`resolve_current_root` and `fingerprint_standing` -- the registry's own two
read functions -- are called here.
`tests/architecture/test_attestation_binding_is_read_only.py` proves this by
an AST scan of this module's source for the write-shaped registry calls and
session-mutation methods.

## Ambiguity and staleness are the registry's refusals, surfaced unchanged

`resolve_current_root` returns `None` both when a subject has no open root
AND when it has more than one (`_derive_current_fingerprint`'s "ambiguity is
a refusal, never a tie-break" rule, applied on the read path too -- see that
function's own docstring). This module adds NO logic on top of that `None`:
`resolve_attestation_binding` forwards it as `None` exactly as received,
which is what "never resolve past it" means here -- there is no branch in
this module that could turn an ambiguous or absent answer into a picked one.
The same is true of a stale `attestation_current_roots` projection row naming
a closed (revoked or superseded) fingerprint: `resolve_current_root` already
refuses that BEFORE any reconciliation runs (checks the closures table
directly rather than trusting the projection), and this module changes
nothing about when or how that check happens -- it only copies the `None` or
the resolved view through.

## `key_custody_pointer` cannot be reached through this module, by construction

`AttestationBindingV1` lists every field it carries; `key_custody_pointer` is
not one of them, and never was reachable from
`attestation_trust_registry.AttestationRootView` either (that dataclass
already excludes it -- see its own definition). Nothing in this module reads
`AttestationEnrolment.key_custody_pointer` at all.
`tests/architecture/test_attestation_binding_no_custody_pointer.py` proves
this two ways: a `dataclasses.fields()` scan of `AttestationBindingV1` for
the exact column name, and an AST/source-text scan of this module for the
literal string `key_custody_pointer` anywhere in it.

## Two known gaps, stated rather than worked around

- **No public-key material for a host-attester `FingerprintRecord`.** Not
  relevant to THIS module -- `attestation_trust_registry.AttestationRootView`
  (what this module wraps) already carries `public_key_b64` and `algorithm`
  from the durable `AttestationEnrolment` row, so this gap (real in
  `host_attester_enrolment.FingerprintRecord`, the caller-supplied-mapping
  type the OLD binding module used) does not apply to the registry-backed
  read path this module exposes.
- **No trust-root / custody-domain / root-version vocabulary in Control
  beyond `AttestationCustodyDomain`'s two string values
  (`"host_attester"`/candidate-release).** This module does not invent one:
  `custody_domain` is passed through exactly as the registry stores it (an
  opaque string, per `AttestationEnrolment.custody_domain`'s own docstring),
  and this module performs no additional validation of its shape.

## Versioned wire contract, refusing an unsupported version rather than
## guessing

`AttestationBindingV1.parse` follows the same convention
`authorization.py`/`dispatch_envelope.py` use: schema and version are checked
FIRST, before any other field is read, and an unrecognised schema or an
unexpected version is refused (`AttestationBindingRefusalCode
.SCHEMA_MISMATCH`/`UNSUPPORTED_VERSION`) rather than silently accepted as if
it were this contract. `resolve_fingerprint_standing`, by contrast, returns
the bare `host_attester_enrolment.HostAttesterStanding` enum unwrapped --
that vocabulary is already the stable, versioned wire form
(`HostAttesterStanding(value)` itself refuses an unrecognised member), and
wrapping a single enum in its own schema/version envelope would add ceremony
without adding a real compatibility boundary.

## A binding returns facts, never a decision

`AttestationBindingV1` carries no `.authorizes`-shaped derived boolean, on
the same principle `HostAttesterEnrolmentSignerIdentity`,
`HostAttesterStandingResult` and the retired `HostAttesterBindingV1` all
state: a binding reports the fact (`standing`); the consumer decides what
that fact means for admission. Nothing here decides.

## Transaction authority

Receives a `Session` it never commits, rolls back, or closes -- exactly the
registry functions it wraps.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any, Final

from sqlalchemy.orm import Session

from dotmac_deployment_control import attestation_trust_registry
from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding
from dotmac_deployment_control.ports import DeploymentControlError

__all__ = [
    "ATTESTATION_BINDING_SCHEMA",
    "ATTESTATION_BINDING_VERSION",
    "AttestationBindingRefusalCode",
    "AttestationBindingRefusedError",
    "AttestationBindingV1",
    "resolve_attestation_binding",
    "resolve_fingerprint_standing",
]

ATTESTATION_BINDING_SCHEMA: Final = "dotmac.deployment_control.attestation_binding"
ATTESTATION_BINDING_VERSION: Final = 1

_EXPECTED_KEYS: Final[frozenset[str]] = frozenset(
    {
        "schema",
        "version",
        "custody_domain",
        "subject",
        "public_key_fingerprint",
        "public_key_b64",
        "algorithm",
        "enrolled_at",
        "standing",
    }
)


class AttestationBindingRefusalCode(StrEnum):
    """Why a wire-form binding does not parse. One code per condition."""

    MALFORMED = "attestation_binding_malformed"
    SCHEMA_MISMATCH = "attestation_binding_schema_mismatch"
    UNSUPPORTED_VERSION = "attestation_binding_unsupported_version"


class AttestationBindingRefusedError(DeploymentControlError):
    """A wire-form value that does not parse as `AttestationBindingV1`."""

    def __init__(self, code: AttestationBindingRefusalCode, detail: str) -> None:
        super().__init__(f"{code}: {detail}")
        self.code = code


def _timestamp(value: datetime) -> str:
    return value.isoformat().replace("+00:00", "Z")


def _instant(value: object, *, field: str) -> datetime:
    if not isinstance(value, str):
        raise AttestationBindingRefusedError(
            AttestationBindingRefusalCode.MALFORMED, f"{field} must be an ISO instant"
        )
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise AttestationBindingRefusedError(
            AttestationBindingRefusalCode.MALFORMED, f"{field} is not an instant: {exc}"
        ) from exc


def _text(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise AttestationBindingRefusedError(
            AttestationBindingRefusalCode.MALFORMED, f"{field} must be non-empty text"
        )
    return value


@dataclass(frozen=True, slots=True)
class AttestationBindingV1:
    """The public, read-only binding of a custody-domain subject to its
    currently trusted root, as the durable registry resolves it right now.

    Deliberately absent: `key_custody_pointer` (see the module docstring's
    "cannot be reached" section) and any `.authorizes`-shaped derived
    boolean (see "A binding returns facts, never a decision" above). Every
    field here is a plain string or `datetime`, copied out of
    `attestation_trust_registry.AttestationRootView` -- itself already free
    of ORM/session state -- so nothing ORM-shaped is reachable from this
    type either.
    """

    custody_domain: str
    subject: str
    public_key_fingerprint: str
    public_key_b64: str
    algorithm: str
    enrolled_at: datetime
    standing: HostAttesterStanding

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": ATTESTATION_BINDING_SCHEMA,
            "version": ATTESTATION_BINDING_VERSION,
            "custody_domain": self.custody_domain,
            "subject": self.subject,
            "public_key_fingerprint": self.public_key_fingerprint,
            "public_key_b64": self.public_key_b64,
            "algorithm": self.algorithm,
            "enrolled_at": _timestamp(self.enrolled_at),
            "standing": self.standing.value,
        }

    @classmethod
    def parse(cls, value: object) -> AttestationBindingV1:
        """The one place a mapping becomes this type.

        Refuses an unrecognised schema or an unexpected version rather than
        guessing at a shape it does not know -- a consumer must never
        silently accept a future, differently-shaped binding as if it were
        this one.
        """
        if not isinstance(value, Mapping):
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.MALFORMED,
                f"an attestation binding must be a mapping, got "
                f"{type(value).__name__}",
            )
        # SCHEMA AND VERSION FIRST, before any other field is read -- the
        # same ordering `authorization.py`/`dispatch_envelope.py` and the
        # retired `HostAttesterBindingV1.parse` all use.
        if value.get("schema") != ATTESTATION_BINDING_SCHEMA:
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.SCHEMA_MISMATCH,
                f"{value.get('schema')!r} is not {ATTESTATION_BINDING_SCHEMA!r}",
            )
        if value.get("version") != ATTESTATION_BINDING_VERSION:
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.UNSUPPORTED_VERSION,
                f"unsupported attestation binding version {value.get('version')!r}",
            )
        keys = set(value)
        missing = sorted(_EXPECTED_KEYS - keys)
        unexpected = sorted(str(key) for key in keys - _EXPECTED_KEYS)
        if missing or unexpected:
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.MALFORMED,
                f"attestation binding keys differ: missing={missing}, "
                f"unexpected={unexpected}",
            )
        standing_raw = value["standing"]
        if not isinstance(standing_raw, str):
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.MALFORMED, "standing must be text"
            )
        try:
            standing = HostAttesterStanding(standing_raw)
        except ValueError as exc:
            raise AttestationBindingRefusedError(
                AttestationBindingRefusalCode.MALFORMED,
                f"{standing_raw!r} is not a known attestation standing",
            ) from exc
        return cls(
            custody_domain=_text(value["custody_domain"], field="custody_domain"),
            subject=_text(value["subject"], field="subject"),
            public_key_fingerprint=_text(
                value["public_key_fingerprint"], field="public_key_fingerprint"
            ),
            public_key_b64=_text(value["public_key_b64"], field="public_key_b64"),
            algorithm=_text(value["algorithm"], field="algorithm"),
            enrolled_at=_instant(value["enrolled_at"], field="enrolled_at"),
            standing=standing,
        )


def resolve_attestation_binding(
    db: Session, *, custody_domain: str, subject: str
) -> AttestationBindingV1 | None:
    """The typed, versioned answer to "what is `subject`'s current trusted
    root in `custody_domain`, right now, per the durable registry".

    Delegates entirely to `attestation_trust_registry.resolve_current_root`
    -- see that function's own docstring for the full refusal list (stale
    projection naming a closed fingerprint, subject/custody-domain
    substitution, ambiguity) this module inherits unchanged. Returns `None`
    for every one of those cases exactly as the registry does; this function
    adds no branch that could distinguish or resolve past any of them.
    """
    view = attestation_trust_registry.resolve_current_root(
        db, custody_domain=custody_domain, subject=subject
    )
    if view is None:
        return None
    return AttestationBindingV1(
        custody_domain=view.custody_domain,
        subject=view.subject,
        public_key_fingerprint=view.public_key_fingerprint,
        public_key_b64=view.public_key_b64,
        algorithm=view.algorithm,
        enrolled_at=view.enrolled_at,
        standing=HostAttesterStanding(view.standing),
    )


def resolve_fingerprint_standing(
    db: Session, *, fingerprint: str
) -> HostAttesterStanding:
    """What `fingerprint` is RIGHT NOW, per the durable registry.

    A direct, unwrapped forward of
    `attestation_trust_registry.fingerprint_standing` -- see that function's
    docstring. Exposed here, rather than requiring a caller to import the
    registry module directly, because `attestation_trust_registry` is not
    itself part of this package's stable top-level surface (see that
    module's own docstring: it is what a public surface calls, never a
    network boundary itself).
    """
    return attestation_trust_registry.fingerprint_standing(db, fingerprint=fingerprint)
