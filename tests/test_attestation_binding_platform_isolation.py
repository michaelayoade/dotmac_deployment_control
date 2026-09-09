"""PostgreSQL companions to `attestation_binding.py`'s structural proofs.

Discovered by `scripts/run_platform_isolation_canaries.py`'s glob
(`tests/test_*_platform_isolation.py`); requires real Postgres
(`make test-db-up` / `make test-integration`) and is written, never executed
here -- CI is the acceptance owner.

`tests/test_attestation_trust_registry_platform_isolation.py` already proves
these two properties AT THE REGISTRY LAYER
(`test_a_projection_backed_by_an_ambiguous_registry_never_returns_a_root` and
`test_a_projection_naming_a_revoked_fingerprint_never_returns_a_root`), against
real Postgres constraint/read semantics. This file restates both THROUGH THE
FACADE specifically -- proving the wrapper does not lose either property on
the real database engine, not merely under SQLite's weaker constraint
enforcement. The SQLite-level restatements
(`tests/unit/test_attestation_binding.py`) already cover the same logic for
fast local iteration; this file is the reviewer-facing Postgres evidence for
the identical two claims.
"""

from __future__ import annotations

import base64
import hashlib
import os
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from dotmac_deployment_control import versions_dir as deploy_versions_dir
from dotmac_deployment_control.attestation_binding import resolve_attestation_binding
from dotmac_deployment_control.attestation_trust_registry import enrol_root, revoke_root
from dotmac_deployment_control.digests import PublicKeyFingerprintV1
from dotmac_deployment_control.models import AttestationCurrentRoot

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_VERSIONS = Path(kernel_versions_dir())
DEPLOY_VERSIONS = Path(deploy_versions_dir())


def _superuser_url() -> str:
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set -- this canary needs Postgres")
    return url


def _url_for(base_url: str, dbname: str, *, user: str | None = None) -> str:
    scheme_userhost, _, _ = base_url.rpartition("/")
    if user is not None:
        scheme, _, userhost = scheme_userhost.partition("://")
        host = userhost.rpartition("@")[2]
        scheme_userhost = f"{scheme}://{user}@{host}"
    return f"{scheme_userhost}/{dbname}"


def _public_key_b64(seed: str) -> str:
    raw = hashlib.sha256(b"attestation-binding-facade\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def _fingerprint_of(seed: str) -> str:
    return PublicKeyFingerprintV1.from_public_key_b64(_public_key_b64(seed)).canonical


@pytest.fixture(scope="module")
def migrated_scratch() -> Iterator[tuple[str, str, str]]:
    """`(admin_url, platform_api_url, app_user_url)` at the composed head."""
    superuser = _superuser_url()
    name = f"attestbind_{uuid.uuid4().hex[:12]}"
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))

    setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
    with setup.connect() as conn:
        conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
        conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
        for role in ("app_user", "platform_api"):
            conn.execute(text(f'GRANT CONNECT ON DATABASE "{name}" TO {role}'))
            conn.execute(text(f"GRANT USAGE ON SCHEMA public TO {role}"))
    setup.dispose()

    admin_url = _url_for(superuser, name, user="app_admin")
    try:
        from alembic import command
        from alembic.config import Config

        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("version_locations", f"{KERNEL_VERSIONS} {DEPLOY_VERSIONS}")
        os.environ["MIGRATION_DATABASE_URL"] = admin_url
        command.upgrade(cfg, "heads")

        yield (
            admin_url,
            _url_for(superuser, name, user="platform_api"),
            _url_for(superuser, name, user="app_user"),
        )
    finally:
        with server.connect() as conn:
            conn.execute(
                text(
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity "
                    "WHERE datname = :n AND pid <> pg_backend_pid()"
                ),
                {"n": name},
            )
            conn.execute(text(f'DROP DATABASE IF EXISTS "{name}"'))
        server.dispose()


@pytest.fixture
def engine(migrated_scratch: tuple[str, str, str]):
    admin_url, _, _ = migrated_scratch
    eng = create_engine(admin_url, future=True)
    try:
        yield eng
    finally:
        eng.dispose()


@pytest.fixture
def sessions(engine):
    return sessionmaker(bind=engine, autocommit=False, autoflush=False, future=True)


def test_a_stale_projection_naming_a_revoked_fingerprint_never_resolves(
    migrated_scratch, sessions
) -> None:
    """The registry-layer proof restated through the public facade: a
    corrupted `attestation_current_roots` row naming an already-revoked
    fingerprint must return no binding -- BEFORE any reconciliation runs,
    and on real Postgres, not only under SQLite's weaker enforcement."""
    subject = f"host-facade-stale-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        view = enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(f"{subject}-a"),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-a",
            enrolment_authority="control_service",
        )
        db.commit()
    fp = view.public_key_fingerprint

    with sessions() as db:
        revoke_root(db, fingerprint=fp, revocation_authority="control_service")
        db.commit()

    # Simulate a raw-SQL/restored-backup corruption re-inserting a pointer
    # to the now-revoked fingerprint -- the same hazard the registry's own
    # equivalent test simulates, restated here at the facade boundary.
    admin_url, _, _ = migrated_scratch
    eng = create_engine(admin_url)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO mod_deploy.attestation_current_roots "
                    "(custody_domain, subject, current_fingerprint) "
                    "VALUES ('host_attester', :subject, :fp)"
                ),
                {"subject": subject, "fp": fp},
            )
    finally:
        eng.dispose()

    with sessions() as db:
        assert db.get(AttestationCurrentRoot, ("host_attester", subject)) is not None
        assert (
            resolve_attestation_binding(
                db, custody_domain="host_attester", subject=subject
            )
            is None
        )


def test_an_ambiguous_registry_never_resolves_through_the_facade(
    migrated_scratch, sessions
) -> None:
    """The registry-layer ambiguity proof restated through the facade: two
    OPEN enrolments for one `(custody_domain, subject)` (a raw-SQL insert
    of a second, never-closed row, exactly `_derive_current_fingerprint`'s
    own docstring names) must refuse -- never pick either candidate."""
    subject = f"host-facade-ambiguous-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        view = enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(f"{subject}-a"),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-a",
            enrolment_authority="control_service",
        )
        db.commit()

    admin_url, _, _ = migrated_scratch
    eng = create_engine(admin_url)
    other_seed = f"{subject}-ambiguous-second"
    other_fp = _fingerprint_of(other_seed)
    try:
        with eng.begin() as conn:
            conn.execute(
                text(
                    "INSERT INTO mod_deploy.attestation_enrolments ("
                    " id, custody_domain, subject, public_key_b64,"
                    " public_key_fingerprint, algorithm,"
                    " key_custody_pointer, enrolled_at, enrolment_authority"
                    ") VALUES (:id, 'host_attester', :subject, :pub, :fp,"
                    " 'ed25519', 'bao://secret/dotmac/attest/ambiguous', now(),"
                    " 'manual_repair_script')"
                ),
                {
                    "id": uuid.uuid4(),
                    "subject": subject,
                    "pub": _public_key_b64(other_seed),
                    "fp": other_fp,
                },
            )
    finally:
        eng.dispose()

    with sessions() as db:
        # The projection is untouched -- still points at the original,
        # legitimately-enrolled fingerprint.
        assert (
            db.get(
                AttestationCurrentRoot, ("host_attester", subject)
            ).current_fingerprint
            == view.public_key_fingerprint
        )
        assert (
            resolve_attestation_binding(
                db, custody_domain="host_attester", subject=subject
            )
            is None
        )

    # Near miss: an unrelated, unambiguous subject still resolves normally
    # through the identical facade function.
    other_subject = f"host-facade-unambiguous-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        other_view = enrol_root(
            db,
            custody_domain="host_attester",
            subject=other_subject,
            public_key_b64=_public_key_b64(f"{other_subject}-a"),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{other_subject}-a",
            enrolment_authority="control_service",
        )
        db.commit()
    with sessions() as db:
        resolved_other = resolve_attestation_binding(
            db, custody_domain="host_attester", subject=other_subject
        )
        assert resolved_other is not None
        assert (
            resolved_other.public_key_fingerprint == other_view.public_key_fingerprint
        )


def test_the_facade_binding_carries_no_orm_or_session_state_on_postgres(
    sessions,
) -> None:
    """Restates `tests/architecture/test_attestation_binding_no_orm_leak.py`'s
    behavioural plant against a real Postgres-backed session -- a leaked ORM
    object would raise `DetachedInstanceError` after the session closes;
    a plain frozen dataclass raises ordinary `AttributeError`."""
    subject = f"host-facade-orm-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(subject),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
            enrolment_authority="control_service",
        )
        db.commit()
    db = sessions()
    binding = resolve_attestation_binding(
        db, custody_domain="host_attester", subject=subject
    )
    db.close()
    assert binding is not None
    assert isinstance(binding.enrolled_at, datetime)
    assert not hasattr(binding, "_sa_instance_state")
    with pytest.raises(AttributeError):
        _ = binding.this_field_does_not_exist_on_the_dataclass  # type: ignore[attr-defined]
