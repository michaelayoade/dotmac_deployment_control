"""No ORM object, session, query builder or raw row escapes
`attestation_binding.py`'s public boundary.

## Two proofs, because a source scan alone is not non-vacuous evidence

1. **Static**: every PUBLIC function's return annotation in this module is
   scanned for a forbidden ORM-shaped name -- `Session`, `AttestationRootView`
   (the registry's own internal projection type -- see below for why even
   THAT is not this module's public type), any mapped class
   (`AttestationEnrolment`/`AttestationCurrentRoot`/
   `AttestationFingerprintClosure`), `CursorResult`, or `Row`. Pure over
   source text, so the sensitivity plant and near-miss below never touch the
   real file.
2. **Behavioural**: `resolve_attestation_binding` is actually called against a
   real (SQLite) session, the session is closed, and the returned value is
   attribute-probed. An ORM instance whose session has closed raises
   `DetachedInstanceError` on lazy access; a plain frozen dataclass raises
   ordinary `AttributeError` for a name it never declared. That specific
   exception TYPE is the sensitivity control here -- it only differs from the
   plain-dataclass answer if something ORM-shaped actually leaked.

## Why `AttestationRootView` itself is in the forbidden list

`attestation_trust_registry.AttestationRootView` is already a plain,
ORM-free dataclass -- but it is not THIS module's public type, and it is not
version/schema-checked. If a future edit of `attestation_binding.py` started
returning it directly (a "the registry's own type is safe enough" shortcut),
that would silently drop this module's own versioned-contract discipline
(`AttestationBindingV1.parse`'s schema/version refusal) and its own field
allowlist (see `test_attestation_binding_no_custody_pointer.py`). The static
scan below treats it as forbidden for that reason, not because it carries
anything unsafe itself.
"""

from __future__ import annotations

import ast
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker

REPO_ROOT = Path(__file__).resolve().parents[2]
MODULE_PATH = REPO_ROOT / "src" / "dotmac_deployment_control" / "attestation_binding.py"

_FORBIDDEN_RETURN_TOKENS = (
    "Session",
    "AttestationRootView",
    "AttestationEnrolment",
    "AttestationCurrentRoot",
    "AttestationFingerprintClosure",
    "CursorResult",
    "Row",
    "Query",
)


def _annotation_text(node: ast.AST | None) -> str:
    if node is None:
        return ""
    return ast.unparse(node)


def _public_functions_with_forbidden_return_annotation(source: str) -> list[str]:
    """Every top-level, non-underscore-prefixed `def` whose return
    annotation mentions a forbidden ORM-shaped token. Pure over source text --
    exercisable with a synthetic string, never the real file, by the
    sensitivity tests below."""
    tree = ast.parse(source)
    offenders: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
            continue
        if node.name.startswith("_"):
            continue
        annotation = _annotation_text(node.returns)
        if any(token in annotation for token in _FORBIDDEN_RETURN_TOKENS):
            offenders.append(node.name)
    return offenders


# ── static scan: non-vacuity + sensitivity plant + near-miss ───────────────


def test_the_real_module_returns_no_orm_shaped_type() -> None:
    offenders = _public_functions_with_forbidden_return_annotation(
        MODULE_PATH.read_text()
    )
    assert offenders == []


def test_the_scan_flags_a_planted_orm_returning_function() -> None:
    """PLANT (ADR-0018): a function whose return annotation names the
    registry's own ORM-adjacent projection type directly."""
    planted = (
        "def resolve_something(db, *, subject: str) -> AttestationRootView | None:\n"
        "    pass\n"
    )
    assert _public_functions_with_forbidden_return_annotation(planted) == [
        "resolve_something"
    ]


def test_the_scan_flags_a_planted_session_returning_function() -> None:
    """A second, independent PLANT: leaking the session itself, not a row."""
    planted = "def get_session(db) -> Session:\n    pass\n"
    assert _public_functions_with_forbidden_return_annotation(planted) == [
        "get_session"
    ]


def test_the_scan_does_not_flag_a_private_helper_with_a_forbidden_return_type() -> None:
    """NEAR-MISS: a leading-underscore helper legitimately returns the
    registry's own internal type as an implementation detail -- this module's
    real `_derive_current_fingerprint`-shaped helpers are never part of the
    public contract, and flagging them would make the guard fail on
    ordinary internal plumbing rather than the boundary it targets."""
    synthetic = (
        "def _internal(db, *, subject: str) -> AttestationRootView | None:\n"
        "    pass\n"
    )
    assert _public_functions_with_forbidden_return_annotation(synthetic) == []


def test_the_scan_does_not_flag_a_correctly_typed_public_function() -> None:
    """NEAR-MISS: the module's actual public shape must not be flagged, or
    every real run of this guard fails for a reason unrelated to the
    property it checks."""
    synthetic = (
        "def resolve_attestation_binding(db, *, custody_domain: str, "
        "subject: str) -> AttestationBindingV1 | None:\n    pass\n"
    )
    assert _public_functions_with_forbidden_return_annotation(synthetic) == []


# ── behavioural: an actual resolved binding, after the session closes ──────


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

    raw = hashlib.sha256(b"attestation-binding-facade\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def test_a_resolved_binding_survives_session_close_as_a_plain_dataclass(
    sqlite_session: Session,
) -> None:
    """Sensitivity control: if this module ever started returning the ORM
    row (or the registry's `AttestationRootView` while somehow still
    session-bound), closing the session below and then touching an
    undeclared attribute would raise `sqlalchemy.orm.exc.DetachedInstanceError`
    -- a DIFFERENT exception type than the plain `AttributeError` a frozen
    dataclass raises. This test would fail loudly (wrong exception type) if
    that regression were reintroduced."""
    from dotmac_deployment_control.attestation_binding import (
        AttestationBindingV1,
        resolve_attestation_binding,
    )
    from dotmac_deployment_control.attestation_trust_registry import enrol_root
    from dotmac_deployment_control.models import (
        AttestationCurrentRoot,
        AttestationEnrolment,
    )

    subject = "host-orm-leak-check"
    enrol_root(
        sqlite_session,
        custody_domain="host_attester",
        subject=subject,
        public_key_b64=_public_key_b64(subject),
        algorithm="ed25519",
        key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
        enrolment_authority="control_service",
    )
    sqlite_session.commit()

    resolution = resolve_attestation_binding(
        sqlite_session, custody_domain="host_attester", subject=subject
    )
    sqlite_session.close()

    assert resolution.refusal is None
    binding = resolution.binding
    assert isinstance(binding, AttestationBindingV1)
    assert not isinstance(binding, AttestationEnrolment)
    assert not isinstance(binding, AttestationCurrentRoot)
    assert not hasattr(binding, "_sa_instance_state")
    with pytest.raises(AttributeError):
        _ = binding.this_field_does_not_exist_on_the_dataclass  # type: ignore[attr-defined]
