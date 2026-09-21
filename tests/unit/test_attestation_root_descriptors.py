"""The canonical registry writer creates only complete admission roots."""

from __future__ import annotations

import base64
import hashlib
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, func, select
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.models  # noqa: F401 - register module tables
from dotmac_deployment_control.attestation_trust_registry import (
    AttestationRefusalCode,
    AttestationRefusedError,
    AttestationRootDescriptorTerms,
    AttestationRootRefusal,
    AttestationRootView,
    enrol_root,
    resolve_admission_root,
    rotate_root,
)
from dotmac_deployment_control.models import (
    AttestationCurrentRoot,
    AttestationEnrolment,
    AttestationRootDescriptor,
)

NOW = datetime(2026, 9, 21, 12, tzinfo=UTC)


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
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
        ],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _public_key_b64(seed: str) -> str:
    raw = hashlib.sha256(b"descriptor-unit\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _descriptor(
    *,
    purpose: str = "dotmac.foundation.installed-host.v2",
    not_after: datetime = NOW + timedelta(hours=1),
) -> AttestationRootDescriptorTerms:
    return AttestationRootDescriptorTerms(
        issuer="control-test-issuer",
        attestation_key_id="host-key-1",
        evidence_purpose=purpose,
        not_after=not_after,
    )


def _enrol(
    db: Session, *, descriptor: AttestationRootDescriptorTerms
) -> AttestationRootView:
    return enrol_root(
        db,
        custody_domain="host_attester",
        subject="host:test-1",
        public_key_b64=_public_key_b64("host:test-1"),
        algorithm="ed25519",
        key_custody_pointer="bao://secret/dotmac/attest/host-test-1",
        enrolment_authority="control-test",
        descriptor=descriptor,
        enrolled_at=NOW,
    )


def _counts(db: Session) -> tuple[int, int]:
    return (
        db.scalar(select(func.count()).select_from(AttestationEnrolment)) or 0,
        db.scalar(select(func.count()).select_from(AttestationRootDescriptor)) or 0,
    )


def test_enrol_root_persists_one_immutable_complete_descriptor(db: Session) -> None:
    _enrol(db, descriptor=_descriptor())
    db.commit()

    enrolment = db.scalars(select(AttestationEnrolment)).one()
    descriptor = db.get(AttestationRootDescriptor, enrolment.id)
    assert descriptor is not None
    assert descriptor.issuer == "control-test-issuer"
    assert descriptor.attestation_key_id == "host-key-1"
    assert descriptor.evidence_purpose == "dotmac.foundation.installed-host.v2"
    assert descriptor.not_after.replace(tzinfo=UTC) == NOW + timedelta(hours=1)

    resolved, refusal = resolve_admission_root(
        db, custody_domain="host_attester", subject="host:test-1"
    )
    assert refusal is None
    assert resolved is not None
    assert resolved.root_version == str(enrolment.id)
    assert resolved.attestation_key_id == "host-key-1"


def test_legacy_root_without_descriptor_refuses_instead_of_defaulting(
    db: Session,
) -> None:
    _enrol(db, descriptor=_descriptor())
    db.flush()
    descriptor = db.scalars(select(AttestationRootDescriptor)).one()
    db.delete(descriptor)
    db.flush()

    resolved, refusal = resolve_admission_root(
        db, custody_domain="host_attester", subject="host:test-1"
    )
    assert resolved is None
    assert refusal is AttestationRootRefusal.MISSING_DESCRIPTOR


@pytest.mark.parametrize(
    ("descriptor", "code"),
    [
        (
            _descriptor(purpose="dotmac.foundation.candidate-artifact.v2"),
            AttestationRefusalCode.PURPOSE_MISMATCH,
        ),
        (
            _descriptor(not_after=(NOW + timedelta(hours=1)).replace(tzinfo=None)),
            AttestationRefusalCode.MALFORMED_DESCRIPTOR,
        ),
        (
            _descriptor(not_after=NOW),
            AttestationRefusalCode.MALFORMED_DESCRIPTOR,
        ),
    ],
)
def test_invalid_descriptor_terms_write_nothing(
    db: Session,
    descriptor: AttestationRootDescriptorTerms,
    code: AttestationRefusalCode,
) -> None:
    with pytest.raises(AttestationRefusedError) as raised:
        _enrol(db, descriptor=descriptor)
    assert raised.value.code is code
    db.rollback()
    assert _counts(db) == (0, 0)


def test_non_descriptor_value_is_typed_and_writes_nothing(db: Session) -> None:
    with pytest.raises(AttestationRefusedError) as raised:
        _enrol(db, descriptor=None)  # type: ignore[arg-type]
    assert raised.value.code is AttestationRefusalCode.MALFORMED_DESCRIPTOR
    db.rollback()
    assert _counts(db) == (0, 0)


def test_rotation_appends_a_complete_successor_without_rewriting_original(
    db: Session,
) -> None:
    original = _enrol(db, descriptor=_descriptor())
    db.commit()
    original_enrolment = db.scalars(
        select(AttestationEnrolment).where(
            AttestationEnrolment.public_key_fingerprint
            == original.public_key_fingerprint
        )
    ).one()
    original_descriptor = db.get(AttestationRootDescriptor, original_enrolment.id)
    assert original_descriptor is not None
    original_metadata = (
        original_descriptor.issuer,
        original_descriptor.attestation_key_id,
        original_descriptor.evidence_purpose,
        original_descriptor.not_after,
    )

    successor = rotate_root(
        db,
        custody_domain="host_attester",
        subject="host:test-1",
        supersedes_fingerprint=original.public_key_fingerprint,
        public_key_b64=_public_key_b64("host:test-1-successor"),
        algorithm="ed25519",
        key_custody_pointer="bao://secret/dotmac/attest/host-test-1-successor",
        enrolment_authority="control-test",
        descriptor=AttestationRootDescriptorTerms(
            issuer="control-test-issuer-2",
            attestation_key_id="host-key-2",
            evidence_purpose="dotmac.foundation.installed-host.v2",
            not_after=NOW + timedelta(hours=2),
        ),
        enrolled_at=NOW + timedelta(minutes=1),
    )
    db.commit()

    assert _counts(db) == (2, 2)
    db.refresh(original_descriptor)
    assert (
        original_descriptor.issuer,
        original_descriptor.attestation_key_id,
        original_descriptor.evidence_purpose,
        original_descriptor.not_after,
    ) == original_metadata
    current = db.get(AttestationCurrentRoot, ("host_attester", "host:test-1"))
    assert current is not None
    assert current.current_fingerprint == successor.public_key_fingerprint


@pytest.mark.parametrize(
    "descriptor",
    [
        _descriptor(purpose="dotmac.foundation.candidate-artifact.v2"),
        _descriptor(not_after=NOW + timedelta(minutes=1)),
    ],
)
def test_invalid_successor_descriptor_preserves_the_original_root(
    db: Session, descriptor: AttestationRootDescriptorTerms
) -> None:
    original = _enrol(db, descriptor=_descriptor())
    db.commit()

    with pytest.raises(AttestationRefusedError):
        rotate_root(
            db,
            custody_domain="host_attester",
            subject="host:test-1",
            supersedes_fingerprint=original.public_key_fingerprint,
            public_key_b64=_public_key_b64("invalid-successor"),
            algorithm="ed25519",
            key_custody_pointer="bao://secret/dotmac/attest/invalid-successor",
            enrolment_authority="control-test",
            descriptor=descriptor,
            enrolled_at=NOW + timedelta(minutes=1),
        )
    db.rollback()

    assert _counts(db) == (1, 1)
    current = db.get(AttestationCurrentRoot, ("host_attester", "host:test-1"))
    assert current is not None
    assert current.current_fingerprint == original.public_key_fingerprint
