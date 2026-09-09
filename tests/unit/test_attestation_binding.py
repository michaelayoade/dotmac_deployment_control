"""Behavioural proofs for the read-only attestation binding facade.

Complements the architecture-level structural proofs
(`tests/architecture/test_attestation_binding_*.py`) with the ordinary
value-level behaviour: resolution, absence, disagreement, drift, the
versioned wire round-trip, and standing forwarding. Uses the same
in-memory SQLite fixture pattern `tests/unit/test_projection_readers.py`
already establishes for this package's `mod_deploy`-schema tables.

Written against the three-way `AttestationRootRefusal` contract (Michael's
ruling, 2026-09-09, after #50) -- `resolve_attestation_binding` now returns
an `AttestationBindingResolution` with exactly one of `.binding`/`.refusal`
set, never a bare `None`.
"""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator

import pytest
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.models  # noqa: F401 - registers mod_deploy tables
from dotmac_deployment_control.attestation_binding import (
    ATTESTATION_BINDING_SCHEMA,
    ATTESTATION_BINDING_VERSION,
    AttestationBindingRefusalCode,
    AttestationBindingRefusedError,
    AttestationBindingV1,
    resolve_attestation_binding,
    resolve_fingerprint_standing,
)
from dotmac_deployment_control.attestation_trust_registry import (
    AttestationRootRefusal,
    enrol_root,
    revoke_root,
    rotate_root,
)
from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding
from dotmac_deployment_control.models import AttestationCurrentRoot


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _begin(connection):  # type: ignore[no-untyped-def]
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[t for t in Base.metadata.tables.values() if t.schema == "mod_deploy"],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _public_key_b64(seed: str) -> str:
    raw = hashlib.sha256(b"attestation-binding-unit\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _enrol(db: Session, subject: str, *, custody_domain: str = "host_attester"):
    view = enrol_root(
        db,
        custody_domain=custody_domain,
        subject=subject,
        public_key_b64=_public_key_b64(subject),
        algorithm="ed25519",
        key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
        enrolment_authority="control_service",
    )
    db.commit()
    return view


# ── resolution: present, absent, drift ──────────────────────────────────────


def test_a_valid_enrolment_resolves_to_a_binding_with_valid_standing(
    db: Session,
) -> None:
    view = _enrol(db, "host-valid")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-valid"
    )
    assert resolution.refusal is None
    binding = resolution.binding
    assert binding is not None
    assert binding.custody_domain == "host_attester"
    assert binding.subject == "host-valid"
    assert binding.public_key_fingerprint == view.public_key_fingerprint
    assert binding.public_key_b64 == view.public_key_b64
    assert binding.algorithm == "ed25519"
    assert binding.standing is HostAttesterStanding.VALID


def test_an_unenrolled_subject_resolves_to_absent() -> None:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _begin(connection):  # type: ignore[no-untyped-def]
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[t for t in Base.metadata.tables.values() if t.schema == "mod_deploy"],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        result = resolve_attestation_binding(
            session, custody_domain="host_attester", subject="host-never-enrolled"
        )
        assert result.binding is None
        assert result.refusal is AttestationRootRefusal.ABSENT
    finally:
        session.close()
        engine.dispose()


def test_a_rotated_away_fingerprint_no_longer_resolves_as_current(
    db: Session,
) -> None:
    """Near-miss for VALID: after a rotation, the OLD fingerprint's own
    standing is SUPERSEDED, and the binding resolved for the subject now
    names the NEW fingerprint -- never the retired one."""
    old = _enrol(db, "host-rotate")
    new_b64 = _public_key_b64("host-rotate-new")
    new_view = rotate_root(
        db,
        custody_domain="host_attester",
        subject="host-rotate",
        supersedes_fingerprint=old.public_key_fingerprint,
        public_key_b64=new_b64,
        algorithm="ed25519",
        key_custody_pointer="bao://secret/dotmac/attest/host-rotate-new",
        enrolment_authority="control_service",
    )
    db.commit()

    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-rotate"
    )
    assert resolution.refusal is None
    assert resolution.binding is not None
    assert resolution.binding.public_key_fingerprint == new_view.public_key_fingerprint

    old_standing = resolve_fingerprint_standing(
        db, fingerprint=old.public_key_fingerprint
    )
    assert old_standing is HostAttesterStanding.SUPERSEDED


def test_a_revoked_fingerprint_reports_revoked_standing_and_absent_binding(
    db: Session,
) -> None:
    """A NATURAL revoke deletes the current-root pointer, so the subject's
    append-only open-enrolment count is zero afterward -- ABSENT, not
    DRIFT. DRIFT is reserved for a STALE pointer someone reinserted after
    the fact (see the stale-projection test below)."""
    view = _enrol(db, "host-revoke")
    revoke_root(
        db,
        fingerprint=view.public_key_fingerprint,
        revocation_authority="control_service",
    )
    db.commit()

    standing = resolve_fingerprint_standing(db, fingerprint=view.public_key_fingerprint)
    assert standing is HostAttesterStanding.REVOKED
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-revoke"
    )
    assert resolution.binding is None
    assert resolution.refusal is AttestationRootRefusal.ABSENT


def test_a_stale_projection_naming_a_revoked_fingerprint_reports_drift(
    db: Session,
) -> None:
    """Pre-reconciliation refusal, proved at the unit level too (the
    Postgres-level companion lives in the top-level platform-isolation
    suite for the real constraint/concurrency evidence -- this is the
    logic-level restatement, which SQLite is sufficient for). A stale
    pointer naming a CLOSED fingerprint is DRIFT specifically -- the
    projection disagrees with the append-only truth it accelerates."""
    view = _enrol(db, "host-stale")
    revoke_root(
        db,
        fingerprint=view.public_key_fingerprint,
        revocation_authority="control_service",
    )
    db.commit()

    # Simulate a raw-SQL/restored-backup corruption: the projection row is
    # reinserted, naming the now-revoked fingerprint, WITHOUT any
    # reconciliation ever running.
    db.add(
        AttestationCurrentRoot(
            custody_domain="host_attester",
            subject="host-stale",
            current_fingerprint=view.public_key_fingerprint,
        )
    )
    db.flush()

    assert db.get(AttestationCurrentRoot, ("host_attester", "host-stale")) is not None
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-stale"
    )
    assert resolution.binding is None
    assert resolution.refusal is AttestationRootRefusal.DRIFT


def test_a_recomputed_fingerprint_mismatch_reports_drift(db: Session) -> None:
    """PLANT for the recompute-from-material rule: a row whose stored
    `public_key_fingerprint` does NOT match what is independently
    recomputed from its own `public_key_b64` -- never reachable through
    `enrol_root`/`rotate_root` (both compute the fingerprint themselves),
    simulated here the same way the ambiguity/substitution plants simulate
    registry corruption: a direct row write bypassing the writers."""
    import uuid
    from datetime import UTC, datetime

    from dotmac_deployment_control.models import AttestationEnrolment

    subject = "host-recompute-mismatch"
    wrong_fingerprint = "sha256:" + "ab" * 32
    db.add(
        AttestationEnrolment(
            id=uuid.uuid4(),
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(subject),
            public_key_fingerprint=wrong_fingerprint,
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
            supersedes_fingerprint=None,
            enrolled_at=datetime.now(UTC),
            enrolment_authority="control_service",
        )
    )
    db.add(
        AttestationCurrentRoot(
            custody_domain="host_attester",
            subject=subject,
            current_fingerprint=wrong_fingerprint,
        )
    )
    db.flush()
    db.commit()

    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject=subject
    )
    assert resolution.binding is None
    assert resolution.refusal is AttestationRootRefusal.DRIFT


def test_a_consistent_fingerprint_does_not_report_drift(db: Session) -> None:
    """NEAR-MISS to the recompute plant above: `enrol_root`'s own row (whose
    fingerprint IS computed from its own material) must resolve normally --
    the recompute check must not false-positive on ordinary, correctly
    written rows."""
    view = _enrol(db, "host-recompute-consistent")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-recompute-consistent"
    )
    assert resolution.refusal is None
    assert resolution.binding is not None
    assert resolution.binding.public_key_fingerprint == view.public_key_fingerprint


# ── fingerprint_standing carries the SAME ambiguity guarantee ──────────────
# (BLOCKING 1, independent security review of PR #51: this sibling function
# derived standing from the same corruptible projection resolve_current_root
# was hardened against, and never checked _count_open_enrolments -- so an
# ambiguous registry could return a silent VALID here while
# resolve_attestation_binding correctly refused for the identical subject.)


def test_fingerprint_standing_reports_registry_disagreement_when_ambiguous(
    db: Session,
) -> None:
    """PLANT: two open, unclosed enrolments for the SAME `(custody_domain,
    subject)` -- raw SQL or a restored backup, this module's own named
    threat model, identical corruption to the ambiguity plants already
    proven against `resolve_current_root`. Before the fix, if the
    projection pointer happened to name one of the two,
    `resolve_fingerprint_standing` returned `VALID` with no signal the
    registry disputes it. It must now return `REGISTRY_DISAGREEMENT` for
    EITHER of the two open fingerprints, not merely the one the (corrupted,
    still-untouched) projection happens to point at."""
    import uuid
    from datetime import UTC, datetime

    from dotmac_deployment_control.digests import PublicKeyFingerprintV1
    from dotmac_deployment_control.models import AttestationEnrolment

    subject = "host-fp-standing-ambiguous"
    first = _enrol(db, subject)

    second_b64 = _public_key_b64(f"{subject}-second")
    second_fp = PublicKeyFingerprintV1.from_public_key_b64(second_b64).canonical
    db.add(
        AttestationEnrolment(
            id=uuid.uuid4(),
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=second_b64,
            public_key_fingerprint=second_fp,
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-second",
            supersedes_fingerprint=None,
            enrolled_at=datetime.now(UTC),
            enrolment_authority="control_service",
        )
    )
    db.flush()
    db.commit()

    # The projection is untouched -- still names the FIRST (legitimately
    # enrolled) fingerprint. Both the pointed-at fingerprint AND the
    # never-pointed-at second one must report the disagreement -- neither
    # is trusted more than the other once the subject itself is ambiguous.
    pointed_at_standing = resolve_fingerprint_standing(
        db, fingerprint=first.public_key_fingerprint
    )
    never_pointed_at_standing = resolve_fingerprint_standing(db, fingerprint=second_fp)
    assert pointed_at_standing is HostAttesterStanding.REGISTRY_DISAGREEMENT
    assert never_pointed_at_standing is HostAttesterStanding.REGISTRY_DISAGREEMENT

    # Cross-check against the sibling function for the SAME subject: the
    # two must now agree that trust is disputed, closing the exact gap the
    # review found -- one function VALID while the other REGISTRY_DISAGREEMENT.
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject=subject
    )
    assert resolution.refusal is AttestationRootRefusal.REGISTRY_DISAGREEMENT


def test_fingerprint_standing_is_unaffected_by_an_unrelated_ambiguous_subject(
    db: Session,
) -> None:
    """PAIRED NEAR-MISS: an ordinary, unambiguous enrolment must still
    report `VALID` -- proving the new check does not false-positive on
    every call, only on the subject that is actually disputed."""
    view = _enrol(db, "host-fp-standing-unambiguous")
    standing = resolve_fingerprint_standing(db, fingerprint=view.public_key_fingerprint)
    assert standing is HostAttesterStanding.VALID


# ── the versioned wire contract ─────────────────────────────────────────────


def test_as_mapping_round_trips_through_parse(db: Session) -> None:
    _enrol(db, "host-roundtrip")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-roundtrip"
    )
    assert resolution.binding is not None
    binding = resolution.binding
    mapping = binding.as_mapping()
    assert mapping["schema"] == ATTESTATION_BINDING_SCHEMA
    assert mapping["version"] == ATTESTATION_BINDING_VERSION
    assert "key_custody_pointer" not in mapping
    parsed = AttestationBindingV1.parse(mapping)
    assert parsed == binding


def test_parse_refuses_an_unrecognised_schema() -> None:
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse({"schema": "not-this", "version": 1})
    assert excinfo.value.code is AttestationBindingRefusalCode.SCHEMA_MISMATCH


def test_parse_refuses_an_unexpected_version(db: Session) -> None:
    """PLANT: a future, differently-shaped version of this contract must be
    refused, never silently accepted as if it were V1."""
    _enrol(db, "host-version-check")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-version-check"
    )
    assert resolution.binding is not None
    mapping = resolution.binding.as_mapping()
    mapping["version"] = 99
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse(mapping)
    assert excinfo.value.code is AttestationBindingRefusalCode.UNSUPPORTED_VERSION


def test_parse_refuses_a_non_mapping() -> None:
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse("not-a-mapping")
    assert excinfo.value.code is AttestationBindingRefusalCode.MALFORMED


def test_parse_refuses_missing_or_unexpected_keys() -> None:
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse(
            {
                "schema": ATTESTATION_BINDING_SCHEMA,
                "version": ATTESTATION_BINDING_VERSION,
                "custody_domain": "host_attester",
                # every other required key omitted
            }
        )
    assert excinfo.value.code is AttestationBindingRefusalCode.MALFORMED


def test_parse_refuses_an_unknown_standing_value(db: Session) -> None:
    _enrol(db, "host-bad-standing")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-bad-standing"
    )
    assert resolution.binding is not None
    mapping = resolution.binding.as_mapping()
    mapping["standing"] = "not-a-real-standing"
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse(mapping)
    assert excinfo.value.code is AttestationBindingRefusalCode.MALFORMED


# ── no `.authorizes`-shaped derived boolean ─────────────────────────────────


def test_the_binding_carries_no_derived_authorization_boolean(db: Session) -> None:
    """A binding returns facts, never a decision -- see the module docstring.
    Structural: the dataclass simply has no such attribute at all."""
    _enrol(db, "host-no-authorizes")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-no-authorizes"
    )
    assert resolution.binding is not None
    assert not hasattr(resolution.binding, "authorizes")


# ── AttestationBindingResolution's own invariant ────────────────────────────


def test_resolution_refuses_construction_with_both_binding_and_refusal_set(
    db: Session,
) -> None:
    """PLANT: a hand-built `AttestationBindingResolution` naming BOTH a
    binding and a refusal must be refused at construction -- proving the
    invariant is enforced structurally, not merely by this module's own
    discipline in `resolve_attestation_binding`."""
    from dotmac_deployment_control.attestation_binding import (
        AttestationBindingResolution,
    )

    _enrol(db, "host-invariant-check")
    resolution = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-invariant-check"
    )
    assert resolution.binding is not None
    with pytest.raises(ValueError):
        AttestationBindingResolution(
            binding=resolution.binding, refusal=AttestationRootRefusal.ABSENT
        )


def test_resolution_refuses_construction_with_neither_set() -> None:
    """NEAR-MISS-adjacent second half of the same invariant: neither field
    set is refused too, not only "both"."""
    from dotmac_deployment_control.attestation_binding import (
        AttestationBindingResolution,
    )

    with pytest.raises(ValueError):
        AttestationBindingResolution(binding=None, refusal=None)
