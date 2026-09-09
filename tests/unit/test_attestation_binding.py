"""Behavioural proofs for the read-only attestation binding facade.

Complements the architecture-level structural proofs
(`tests/architecture/test_attestation_binding_*.py`) with the ordinary
value-level behaviour: resolution, absence, the versioned wire round-trip,
and standing forwarding. Uses the same in-memory SQLite fixture pattern
`tests/unit/test_projection_readers.py` already establishes for this
package's `mod_deploy`-schema tables.
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


# ── resolution: present, absent ─────────────────────────────────────────────


def test_a_valid_enrolment_resolves_to_a_binding_with_valid_standing(
    db: Session,
) -> None:
    view = _enrol(db, "host-valid")
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-valid"
    )
    assert binding is not None
    assert binding.custody_domain == "host_attester"
    assert binding.subject == "host-valid"
    assert binding.public_key_fingerprint == view.public_key_fingerprint
    assert binding.public_key_b64 == view.public_key_b64
    assert binding.algorithm == "ed25519"
    assert binding.standing is HostAttesterStanding.VALID


def test_an_unenrolled_subject_resolves_to_none() -> None:
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
        assert result is None
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

    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-rotate"
    )
    assert binding is not None
    assert binding.public_key_fingerprint == new_view.public_key_fingerprint

    old_standing = resolve_fingerprint_standing(
        db, fingerprint=old.public_key_fingerprint
    )
    assert old_standing is HostAttesterStanding.SUPERSEDED


def test_a_revoked_fingerprint_reports_revoked_standing(db: Session) -> None:
    view = _enrol(db, "host-revoke")
    revoke_root(
        db,
        fingerprint=view.public_key_fingerprint,
        revocation_authority="control_service",
    )
    db.commit()

    standing = resolve_fingerprint_standing(db, fingerprint=view.public_key_fingerprint)
    assert standing is HostAttesterStanding.REVOKED
    assert (
        resolve_attestation_binding(
            db, custody_domain="host_attester", subject="host-revoke"
        )
        is None
    )


def test_a_stale_projection_naming_a_revoked_fingerprint_returns_nothing(
    db: Session,
) -> None:
    """Pre-reconciliation refusal, proved at the unit level too (the
    Postgres-level companion lives in the top-level platform-isolation
    suite for the real constraint/concurrency evidence -- this is the
    logic-level restatement, which SQLite is sufficient for)."""
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
    assert (
        resolve_attestation_binding(
            db, custody_domain="host_attester", subject="host-stale"
        )
        is None
    )


# ── the versioned wire contract ─────────────────────────────────────────────


def test_as_mapping_round_trips_through_parse(db: Session) -> None:
    _enrol(db, "host-roundtrip")
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-roundtrip"
    )
    assert binding is not None
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
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-version-check"
    )
    assert binding is not None
    mapping = binding.as_mapping()
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
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-bad-standing"
    )
    assert binding is not None
    mapping = binding.as_mapping()
    mapping["standing"] = "not-a-real-standing"
    with pytest.raises(AttestationBindingRefusedError) as excinfo:
        AttestationBindingV1.parse(mapping)
    assert excinfo.value.code is AttestationBindingRefusalCode.MALFORMED


# ── no `.authorizes`-shaped derived boolean ─────────────────────────────────


def test_the_binding_carries_no_derived_authorization_boolean(db: Session) -> None:
    """A binding returns facts, never a decision -- see the module docstring.
    Structural: the dataclass simply has no such attribute at all."""
    _enrol(db, "host-no-authorizes")
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject="host-no-authorizes"
    )
    assert binding is not None
    assert not hasattr(binding, "authorizes")
