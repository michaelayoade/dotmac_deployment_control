"""`attestation_binding.py` never triggers reconciliation or repair, and
never resolves past the registry's own three-way refusal.

## Repaired since the first version of this file

Michael's ruling (2026-09-09, after #50) closed the gap this file's original
docstring MEASURED and reported: `resolve_current_root` used to answer an
ambiguous subject exactly the same way it answered an absent one -- a bare
`None`. It now returns a typed `AttestationRootResolution` naming exactly
which of `ABSENT`/`REGISTRY_DISAGREEMENT`/`DRIFT` applies
(`attestation_trust_registry.AttestationRootRefusal`), and this module's
`resolve_attestation_binding` forwards that SAME typed refusal inside its
own `AttestationBindingResolution`, never collapsing it back to `None`.

"Never resolves past it" is proved two ways:

1. **Static**: this module's source never calls `reconcile_current_root` or
   `repair_current_root` at all -- a caller of `resolve_attestation_binding`
   gets exactly what the append-only-truth-derived read path returns, with
   no reconciliation side effect ever triggered on its behalf.
2. **Behavioural**: two open enrolments are placed for the SAME
   `(custody_domain, subject)` (simulating the registry inconsistency
   `_derive_current_fingerprint`'s own docstring names -- e.g. a raw-SQL
   repair script), and `resolve_attestation_binding` is asserted to return
   the SPECIFIC `REGISTRY_DISAGREEMENT` refusal -- never one of the two
   candidates, never a bare falsy value, and never by calling
   `reconcile_current_root`/`repair_current_root` first (both are asserted
   NOT called via a monkeypatch spy in the test body). A PAIRED near-miss
   proves a genuinely absent subject returns `ABSENT` specifically, not
   `REGISTRY_DISAGREEMENT` -- the two refusals are not interchangeable
   "something is wrong" signals.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "src" / "dotmac_deployment_control" / "attestation_binding.py"

_RECONCILIATION_CALLS = frozenset({"reconcile_current_root", "repair_current_root"})


def _calls_reconciliation_functions(source: str) -> list[str]:
    """Every call expression in `source` naming a reconciliation/repair
    function, however it is referenced (bare name or `module.attr`). Pure
    over source text -- exercisable on a synthetic string by the sensitivity
    plant and near-miss below."""
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        name = func.id if isinstance(func, ast.Name) else None
        if name is None and isinstance(func, ast.Attribute):
            name = func.attr
        if name in _RECONCILIATION_CALLS:
            offenders.append(name)
    return offenders


# ── static: no call to reconcile/repair anywhere in this module ────────────


def test_the_real_module_never_calls_reconciliation_or_repair() -> None:
    offenders = _calls_reconciliation_functions(MODULE_PATH.read_text())
    assert offenders == []


def test_the_scan_flags_a_planted_repair_call() -> None:
    """PLANT (ADR-0018): a hypothetical future edit that "helpfully" repairs
    drift before resolving -- exactly the tie-break-by-side-effect this
    module must never perform."""
    planted = (
        "def resolve_attestation_binding(db, *, custody_domain, subject):\n"
        "    attestation_trust_registry.repair_current_root(\n"
        "        db, custody_domain=custody_domain, subject=subject\n"
        "    )\n"
        "    return attestation_trust_registry.resolve_current_root(\n"
        "        db, custody_domain=custody_domain, subject=subject\n"
        "    )\n"
    )
    assert _calls_reconciliation_functions(planted) == ["repair_current_root"]


def test_the_scan_does_not_flag_the_sanctioned_read_only_call() -> None:
    """NEAR-MISS: calling `resolve_current_root` itself -- the module's real,
    sanctioned behaviour -- must not be flagged, or every real run of this
    guard fails on the module's own legitimate call."""
    sanctioned = (
        "def resolve_attestation_binding(db, *, custody_domain, subject):\n"
        "    return attestation_trust_registry.resolve_current_root(\n"
        "        db, custody_domain=custody_domain, subject=subject\n"
        "    )\n"
    )
    assert _calls_reconciliation_functions(sanctioned) == []


# ── behavioural: an ambiguous registry, resolved through the facade ────────


@pytest.fixture
def sqlite_session():
    from dotmac_kernel.models import Base

    import dotmac_deployment_control.models  # noqa: F401 - registers tables

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
    factory = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    session: Session = factory()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _public_key_b64(seed: str) -> str:
    import base64
    import hashlib

    raw = hashlib.sha256(b"attestation-binding-ambiguity\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_two_open_enrolments_for_the_same_subject_refuse_through_the_facade(
    sqlite_session: Session, monkeypatch: pytest.MonkeyPatch
) -> None:
    """PLANT: an ambiguous registry -- two enrolments open for the identical
    `(custody_domain, subject)`, which `enrol_root` alone can never produce
    (its own `AttestationCurrentRoot` insert refuses a second one). Simulated
    here the same way the registry's own Postgres ambiguity tests simulate it:
    a second `AttestationEnrolment` row inserted directly, bypassing
    `enrol_root`, matching a raw-SQL repair script or restored-backup
    scenario `_derive_current_fingerprint`'s own docstring names."""
    import uuid
    from datetime import UTC, datetime

    import dotmac_deployment_control.attestation_trust_registry as registry
    from dotmac_deployment_control.attestation_binding import (
        resolve_attestation_binding,
    )
    from dotmac_deployment_control.attestation_trust_registry import (
        AttestationRootRefusal,
    )
    from dotmac_deployment_control.models import AttestationEnrolment

    subject = "host-ambiguous"
    registry.enrol_root(
        sqlite_session,
        custody_domain="host_attester",
        subject=subject,
        public_key_b64=_public_key_b64(f"{subject}-a"),
        algorithm="ed25519",
        key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-a",
        enrolment_authority="control_service",
    )
    sqlite_session.commit()

    # A second, independently-inserted OPEN enrolment for the same subject --
    # never reachable through `enrol_root`/`rotate_root` under ordinary
    # discipline, exactly the corruption this test targets.
    from dotmac_deployment_control.digests import PublicKeyFingerprintV1

    second_b64 = _public_key_b64(f"{subject}-b")
    second_fp = PublicKeyFingerprintV1.from_public_key_b64(second_b64).canonical
    sqlite_session.add(
        AttestationEnrolment(
            id=uuid.uuid4(),
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=second_b64,
            public_key_fingerprint=second_fp,
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-b",
            supersedes_fingerprint=None,
            enrolled_at=datetime.now(UTC),
            enrolment_authority="control_service",
        )
    )
    sqlite_session.flush()
    sqlite_session.commit()

    # Sensitivity control for the "never reconciles" claim: spy on both
    # reconciliation functions and assert neither is ever invoked while
    # resolving through the facade.
    reconcile_calls: list[object] = []
    repair_calls: list[object] = []
    monkeypatch.setattr(
        registry,
        "reconcile_current_root",
        lambda *a, **k: reconcile_calls.append((a, k)),
    )
    monkeypatch.setattr(
        registry, "repair_current_root", lambda *a, **k: repair_calls.append((a, k))
    )

    result = resolve_attestation_binding(
        sqlite_session, custody_domain="host_attester", subject=subject
    )

    assert result.binding is None
    # THE assertion this test exists for: the specific
    # REGISTRY_DISAGREEMENT refusal, never a bare falsy/`None` value that
    # could be confused with ABSENT -- see the paired near-miss below.
    assert result.refusal is AttestationRootRefusal.REGISTRY_DISAGREEMENT
    assert reconcile_calls == []
    assert repair_calls == []


def test_a_genuinely_absent_subject_returns_absent_not_registry_disagreement(
    sqlite_session: Session,
) -> None:
    """PAIRED NEAR-MISS to the ambiguity plant above: a subject that was
    NEVER enrolled at all must resolve to `ABSENT`, never
    `REGISTRY_DISAGREEMENT` -- proving the two refusals are distinguishable,
    not two spellings of "something is wrong"."""
    from dotmac_deployment_control.attestation_binding import (
        resolve_attestation_binding,
    )
    from dotmac_deployment_control.attestation_trust_registry import (
        AttestationRootRefusal,
    )

    result = resolve_attestation_binding(
        sqlite_session, custody_domain="host_attester", subject="host-never-enrolled"
    )

    assert result.binding is None
    assert result.refusal is AttestationRootRefusal.ABSENT


def test_an_unambiguous_subject_still_resolves_through_the_facade(
    sqlite_session: Session,
) -> None:
    """NEAR-MISS to the ambiguity test above: an entirely unrelated subject
    with exactly one open enrolment resolves normally through the identical
    facade function -- the refusal is about the ambiguity specifically, not
    about the facade having become universally unable to resolve anything."""
    from dotmac_deployment_control.attestation_binding import (
        resolve_attestation_binding,
    )
    from dotmac_deployment_control.attestation_trust_registry import enrol_root
    from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding

    subject = "host-unambiguous"
    view = enrol_root(
        sqlite_session,
        custody_domain="host_attester",
        subject=subject,
        public_key_b64=_public_key_b64(subject),
        algorithm="ed25519",
        key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
        enrolment_authority="control_service",
    )
    sqlite_session.commit()

    result = resolve_attestation_binding(
        sqlite_session, custody_domain="host_attester", subject=subject
    )

    assert result.refusal is None
    assert result.binding is not None
    assert result.binding.public_key_fingerprint == view.public_key_fingerprint
    assert result.binding.standing is HostAttesterStanding.VALID
