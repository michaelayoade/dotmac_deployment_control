"""Append-only target-host and admission-policy truth proofs."""

from __future__ import annotations

from collections.abc import Generator
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

import dotmac_deployment_control.models  # noqa: F401
from dotmac_deployment_control.host_admission_service import (
    BindTargetHostCommand,
    HostAdmissionStateRefusalCode,
    HostAdmissionStateRefusedError,
    SetTargetAdmissionPolicyCommand,
    bind_target_host,
    resolve_current_target_admission_policy,
    resolve_current_target_host,
    revise_target_admission_policy,
    revoke_target_admission_policy,
    revoke_target_host,
    rotate_target_host,
    set_target_admission_policy,
)
from dotmac_deployment_control.models import (
    DeploymentTarget,
    TargetAdmissionPolicy,
    TargetCurrentAdmissionPolicy,
    TargetCurrentHost,
    TargetHostAssociation,
)


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(connection, _record):  # type: ignore[no-untyped-def]
        connection.isolation_level = None
        connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

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


def _target(db: Session) -> DeploymentTarget:
    row = DeploymentTarget(
        id=uuid4(),
        target_ref="target-1",
        subject_ref="subject-1",
        product_code="workspace",
        environment="production",
    )
    db.add(row)
    db.flush()
    return row


def _policy(target_id, *, package: str = "dotmac-workspace"):
    return SetTargetAdmissionPolicyCommand(
        target_id=target_id,
        candidate_root_subject="foundation-release",
        candidate_audience="foundation-candidate",
        installed_audience="foundation-installed",
        expected_foundation_package=package,
        authority="control-admin",
    )


def test_host_rotation_and_revocation_are_derived_from_append_only_truth(
    db: Session,
) -> None:
    target = _target(db)
    first = bind_target_host(
        db,
        BindTargetHostCommand(target.id, "host-one", "control-admin"),
    )
    assert resolve_current_target_host(db, target_id=target.id).host_id == "host-one"

    second = rotate_target_host(
        db,
        BindTargetHostCommand(target.id, "host-two", "control-admin"),
    )
    current = resolve_current_target_host(db, target_id=target.id)
    assert current.association_id == second
    assert current.host_id == "host-two"
    assert first != second

    revoke_target_host(db, target_id=target.id, authority="control-admin")
    with pytest.raises(HostAdmissionStateRefusedError) as caught:
        resolve_current_target_host(db, target_id=target.id)
    assert caught.value.code is HostAdmissionStateRefusalCode.HOST_ABSENT


def test_host_projection_drift_and_ambiguous_history_refuse(db: Session) -> None:
    target = _target(db)
    bind_target_host(
        db,
        BindTargetHostCommand(target.id, "host-one", "control-admin"),
    )
    pointer = db.get(TargetCurrentHost, target.id)
    assert pointer is not None
    db.delete(pointer)
    db.flush()
    with pytest.raises(HostAdmissionStateRefusedError) as drift:
        resolve_current_target_host(db, target_id=target.id)
    assert drift.value.code is HostAdmissionStateRefusalCode.HOST_DRIFT

    db.add(
        TargetHostAssociation(
            id=uuid4(),
            target_id=target.id,
            host_id="host-two",
            bound_at=datetime.now(UTC),
            authority="raw-repair",
        )
    )
    db.flush()
    with pytest.raises(HostAdmissionStateRefusedError) as ambiguous:
        resolve_current_target_host(db, target_id=target.id)
    assert ambiguous.value.code is HostAdmissionStateRefusalCode.HOST_AMBIGUOUS


def test_policy_revision_closes_predecessor_and_revoke_leaves_no_current(
    db: Session,
) -> None:
    target = _target(db)
    association_id = bind_target_host(
        db, BindTargetHostCommand(target.id, "host-one", "control-admin")
    )
    first = set_target_admission_policy(db, _policy(target.id))
    second = revise_target_admission_policy(
        db, _policy(target.id, package="dotmac-workspace-next")
    )
    current = resolve_current_target_admission_policy(db, target_id=target.id)
    assert current.policy_id == second
    assert current.host_association_id == association_id
    assert current.expected_foundation_package == "dotmac-workspace-next"
    assert first != second

    revoke_target_admission_policy(db, target_id=target.id, authority="control-admin")
    with pytest.raises(HostAdmissionStateRefusedError) as caught:
        resolve_current_target_admission_policy(db, target_id=target.id)
    assert caught.value.code is HostAdmissionStateRefusalCode.POLICY_ABSENT


def test_policy_projection_drift_and_ambiguous_history_refuse(db: Session) -> None:
    target = _target(db)
    association_id = bind_target_host(
        db, BindTargetHostCommand(target.id, "host-one", "control-admin")
    )
    first = set_target_admission_policy(db, _policy(target.id))
    pointer = db.get(TargetCurrentAdmissionPolicy, target.id)
    assert pointer is not None
    db.delete(pointer)
    db.flush()
    with pytest.raises(HostAdmissionStateRefusedError) as drift:
        resolve_current_target_admission_policy(db, target_id=target.id)
    assert drift.value.code is HostAdmissionStateRefusalCode.POLICY_DRIFT

    original = db.get(TargetAdmissionPolicy, first)
    assert original is not None
    db.add(
        TargetAdmissionPolicy(
            id=uuid4(),
            target_id=target.id,
            host_association_id=association_id,
            candidate_root_subject=original.candidate_root_subject,
            candidate_audience=original.candidate_audience,
            installed_audience=original.installed_audience,
            expected_foundation_package=original.expected_foundation_package,
            effective_at=original.effective_at,
            authority="raw-repair",
        )
    )
    db.flush()
    with pytest.raises(HostAdmissionStateRefusedError) as ambiguous:
        resolve_current_target_admission_policy(db, target_id=target.id)
    assert ambiguous.value.code is HostAdmissionStateRefusalCode.POLICY_AMBIGUOUS
