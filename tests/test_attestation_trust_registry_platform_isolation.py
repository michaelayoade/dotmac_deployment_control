"""Postgres proofs for the durable attestation trust registry (dc_0011).

Michael was explicit: "SQLite evidence is insufficient for this lane." Every
test in this file that is about a CONCURRENCY or ORDERING guarantee runs
against a real, migrated PostgreSQL database and asserts on the actual
`IntegrityError` PostgreSQL raises -- never on application-level bookkeeping
that could pass under SQLite's much weaker constraint enforcement.

Requires real Postgres (`make test-db-up` / `make test-integration`). This
file is written, never executed here -- CI is the acceptance owner.

## The four required proofs, and where each lives

1. Concurrent enrolment -- `TestConcurrentEnrolment`.
2. Cross-role fingerprint reuse, refused BY THE DATABASE --
   `TestCrossRoleFingerprintReuseIsADatabaseConstraint`.
3. Rotation versus revocation ordering (whichever commits first wins
   permanently; a later act cannot reclaim it; recovery is a new signed
   attempt, never a reset) -- `TestRotationVersusRevocationOrdering`.
4. Stale-reader behaviour -- `TestStaleReaderBehaviour`.

Plus the standing proof obligations: enrolment rows cannot be mutated in
place (`TestAppendOnlyEnforcement`), no ORM object/session/row escapes the
public boundary (`test_the_public_view_carries_no_orm_or_session_state`), a
revoked key is never reported active
(`test_a_revoked_fingerprint_is_never_reported_valid`), and the
`attestation_current_roots` projection can drift from raw SQL and be
detected and repaired (`TestCurrentRootDriftDetectionAndRepair`) -- the
concrete evidence for why that table is a projection and not a fourth
persistence owner.
"""

from __future__ import annotations

import base64
import hashlib
import os
import threading
import uuid
from collections.abc import Iterator
from datetime import datetime
from pathlib import Path

import pytest
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import versions_dir as deploy_versions_dir
from dotmac_deployment_control.attestation_trust_registry import (
    AttestationRefusalCode,
    AttestationRefusedError,
    enrol_root,
    fingerprint_standing,
    reconcile_current_root,
    repair_current_root,
    resolve_current_root,
    revoke_root,
    rotate_root,
)
from dotmac_deployment_control.host_attester_enrolment import HostAttesterStanding
from dotmac_deployment_control.models import (
    AttestationCurrentRoot,
    AttestationEnrolment,
    AttestationFingerprintClosure,
)

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_VERSIONS = Path(kernel_versions_dir())
DEPLOY_VERSIONS = Path(deploy_versions_dir())

SCHEMA = "mod_deploy"
TABLES = (
    "attestation_enrolments",
    "attestation_fingerprint_closures",
    "attestation_current_roots",
)
EVIDENCE_TABLES = ("attestation_enrolments", "attestation_fingerprint_closures")


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
    """A fresh, deterministic, valid unpadded-base64url public key per seed."""
    raw = hashlib.sha256(b"attestation-trust-registry\0" + seed.encode()).digest()
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


@pytest.fixture(scope="module")
def migrated_scratch() -> Iterator[tuple[str, str, str]]:
    """`(admin_url, platform_api_url, app_user_url)` at the composed head."""
    superuser = _superuser_url()
    name = f"attest_{uuid.uuid4().hex[:12]}"
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


def _has_privilege(url: str, table: str, privilege: str, *, role: str) -> bool:
    eng = create_engine(url)
    try:
        with eng.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT has_table_privilege(:r, :t, :p)"),
                    {"r": role, "t": f"{SCHEMA}.{table}", "p": privilege},
                ).scalar()
            )
    finally:
        eng.dispose()


# ── Migration from empty ─────────────────────────────────────────────────────


class TestTheLineageBuildsTheRegistry:
    def test_every_table_exists(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                for table in TABLES:
                    assert (
                        conn.execute(
                            text("SELECT to_regclass(:t)"),
                            {"t": f"{SCHEMA}.{table}"},
                        ).scalar()
                        is not None
                    ), table
        finally:
            eng.dispose()

    def test_the_fingerprint_uniqueness_is_a_real_constraint_not_an_index_alone(
        self, migrated_scratch
    ) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                found = conn.execute(
                    text(
                        "SELECT conname FROM pg_constraint c "
                        "JOIN pg_class t ON t.oid = c.conrelid "
                        "JOIN pg_namespace n ON n.oid = t.relnamespace "
                        "WHERE n.nspname = :s AND t.relname = 'attestation_enrolments' "
                        "AND conname = 'uq_attestation_enrolments_fingerprint' "
                        "AND contype = 'u'"
                    ),
                    {"s": SCHEMA},
                ).scalar()
            assert found == "uq_attestation_enrolments_fingerprint"
        finally:
            eng.dispose()

    def test_the_closures_primary_key_is_the_fingerprint_column(
        self, migrated_scratch
    ) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                columns = (
                    conn.execute(
                        text(
                            "SELECT a.attname FROM pg_index i "
                            "JOIN pg_attribute a ON a.attrelid = i.indrelid "
                            "AND a.attnum = ANY(i.indkey) "
                            "WHERE i.indrelid = CAST(:t AS regclass) AND i.indisprimary"
                        ),
                        {"t": f"{SCHEMA}.attestation_fingerprint_closures"},
                    )
                    .scalars()
                    .all()
                )
            assert columns == ["fingerprint"]
        finally:
            eng.dispose()

    def test_the_current_roots_primary_key_is_the_composite_domain_and_subject(
        self, migrated_scratch
    ) -> None:
        """PK `(custody_domain, subject)` is what makes two concurrent INITIAL
        enrolments for the same subject a database conflict -- see
        `TestConcurrentEnrolment` for the behavioural half of this proof."""
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                columns = (
                    conn.execute(
                        text(
                            "SELECT a.attname FROM pg_index i "
                            "JOIN pg_attribute a ON a.attrelid = i.indrelid "
                            "AND a.attnum = ANY(i.indkey) "
                            "WHERE i.indrelid = CAST(:t AS regclass) "
                            "AND i.indisprimary "
                            "ORDER BY array_position(i.indkey, a.attnum)"
                        ),
                        {"t": f"{SCHEMA}.attestation_current_roots"},
                    )
                    .scalars()
                    .all()
                )
            assert columns == ["custody_domain", "subject"]
        finally:
            eng.dispose()

    @pytest.mark.parametrize(
        ("constraint_name", "table"),
        [
            ("fk_attestation_closures_fingerprint", "attestation_fingerprint_closures"),
            (
                "fk_attestation_closures_superseded_by",
                "attestation_fingerprint_closures",
            ),
            (
                "fk_attestation_current_roots_fingerprint",
                "attestation_current_roots",
            ),
        ],
    )
    def test_every_declared_foreign_key_exists(
        self, migrated_scratch, constraint_name: str, table: str
    ) -> None:
        """Every FK the migration declares, present on the table it names --
        not merely that SOME foreign key exists, but the exact named one, so
        a migration that dropped and silently replaced it with a
        differently-scoped constraint would still be caught."""
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                found = conn.execute(
                    text(
                        "SELECT conname FROM pg_constraint c "
                        "JOIN pg_class t ON t.oid = c.conrelid "
                        "JOIN pg_namespace n ON n.oid = t.relnamespace "
                        "WHERE n.nspname = :s AND t.relname = :table "
                        "AND conname = :name AND contype = 'f'"
                    ),
                    {"s": SCHEMA, "table": table, "name": constraint_name},
                ).scalar()
            assert found == constraint_name
        finally:
            eng.dispose()

    def test_no_table_has_row_level_security(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                for table in TABLES:
                    enabled, forced = conn.execute(
                        text(
                            "SELECT relrowsecurity, relforcerowsecurity "
                            "FROM pg_class WHERE oid = CAST(:t AS regclass)"
                        ),
                        {"t": f"{SCHEMA}.{table}"},
                    ).one()
                    assert not enabled and not forced, table
        finally:
            eng.dispose()

    @pytest.mark.parametrize("table", TABLES)
    def test_app_user_holds_no_privilege(self, migrated_scratch, table: str) -> None:
        admin_url, _, _ = migrated_scratch
        for privilege in ("SELECT", "INSERT", "UPDATE", "DELETE", "TRUNCATE"):
            assert not _has_privilege(admin_url, table, privilege, role="app_user"), (
                table,
                privilege,
            )

    @pytest.mark.parametrize("table", EVIDENCE_TABLES)
    def test_platform_api_may_not_update_the_evidence_tables(
        self, migrated_scratch, table: str
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert not _has_privilege(admin_url, table, "UPDATE", role="platform_api")
        assert not _has_privilege(admin_url, table, "DELETE", role="platform_api")

    def test_platform_api_may_update_and_delete_the_current_root_projection(
        self, migrated_scratch
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert _has_privilege(
            admin_url, "attestation_current_roots", "UPDATE", role="platform_api"
        )
        assert _has_privilege(
            admin_url, "attestation_current_roots", "DELETE", role="platform_api"
        )


# ── Append-only enforcement, with a sensitivity proof (ADR-0018) ───────────


class TestAppendOnlyEnforcement:
    """Plant the defect the trigger targets (an UPDATE / a DELETE), and prove
    it is caught. A guard that only passes over an untouched table proves
    nothing about itself."""

    def _seed_enrolment(self, conn, *, seed: str) -> str:
        fingerprint = _fingerprint_of(seed)
        conn.execute(
            text(
                "INSERT INTO mod_deploy.attestation_enrolments ("
                " id, custody_domain, subject, public_key_b64,"
                " public_key_fingerprint, algorithm, key_custody_pointer,"
                " enrolled_at, enrolment_authority"
                ") VALUES (:id, 'host_attester', :subject, :pub, :fp,"
                " 'ed25519', 'bao://secret/dotmac/attest/x', now(),"
                " 'control_service')"
            ),
            {
                "id": uuid.uuid4(),
                "subject": f"host-{seed}",
                "pub": _public_key_b64(seed),
                "fp": fingerprint,
            },
        )
        return fingerprint

    def test_an_enrolment_row_cannot_be_updated(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                with conn.begin():
                    self._seed_enrolment(conn, seed="update-target")
                with pytest.raises(DBAPIError, match="append-only"), conn.begin():
                    conn.execute(
                        text(
                            "UPDATE mod_deploy.attestation_enrolments "
                            "SET enrolment_authority = 'someone_else' "
                            "WHERE subject = 'host-update-target'"
                        )
                    )
        finally:
            eng.dispose()

    def test_an_enrolment_row_cannot_be_deleted(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                with conn.begin():
                    self._seed_enrolment(conn, seed="delete-target")
                with pytest.raises(DBAPIError, match="append-only"), conn.begin():
                    conn.execute(
                        text(
                            "DELETE FROM mod_deploy.attestation_enrolments "
                            "WHERE subject = 'host-delete-target'"
                        )
                    )
        finally:
            eng.dispose()

    def test_a_closure_row_cannot_be_updated_the_near_miss_the_pk_alone_would_not_catch(
        self, migrated_scratch
    ) -> None:
        """Sensitivity proof, near-miss half: the PRIMARY KEY on `fingerprint`
        stops a SECOND row from claiming the same fingerprint, but it does
        nothing to stop an UPDATE of the one row that already exists -- only
        the trigger does. If the trigger were absent, this UPDATE would
        succeed silently and the ordering guarantee this table exists for
        would be gone even though the PK still looked intact."""
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                with conn.begin():
                    fp = self._seed_enrolment(conn, seed="closure-update-target")
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                            "(fingerprint, closure_kind, closed_at, closure_authority) "
                            "VALUES (:fp, 'revoked', now(), 'control_service')"
                        ),
                        {"fp": fp},
                    )
                with pytest.raises(DBAPIError, match="append-only"), conn.begin():
                    conn.execute(
                        text(
                            "UPDATE mod_deploy.attestation_fingerprint_closures "
                            "SET closure_kind = 'superseded' WHERE fingerprint = :fp"
                        ),
                        {"fp": fp},
                    )
        finally:
            eng.dispose()

    @pytest.mark.parametrize(
        "table", ["attestation_enrolments", "attestation_fingerprint_closures"]
    )
    def test_truncate_is_refused_on_both_evidence_tables(
        self, migrated_scratch, table: str
    ) -> None:
        """The TRUNCATE trigger, behaviourally -- matching `dc_0010`'s own
        `TRUNCATE mod_deploy.rollout_attempt_settlements` proof. A per-row
        `BEFORE UPDATE OR DELETE` trigger alone would say nothing about
        TRUNCATE, which is a per-statement operation an UPDATE/DELETE trigger
        never fires for."""
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn, conn.begin():
                fp = self._seed_enrolment(conn, seed=f"truncate-{table}")
                if table == "attestation_fingerprint_closures":
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                            "(fingerprint, closure_kind, closed_at, closure_authority) "
                            "VALUES (:fp, 'revoked', now(), 'control_service')"
                        ),
                        {"fp": fp},
                    )
            with (
                eng.begin() as conn,
                pytest.raises(DBAPIError, match="append-only"),
            ):
                conn.execute(text(f"TRUNCATE {SCHEMA}.{table}"))
        finally:
            eng.dispose()

    def test_app_admin_cannot_rewrite_an_enrolment_either(
        self, migrated_scratch
    ) -> None:
        """The offline role is not a higher authority against this table --
        matching `dc_0001`'s own three evidence tables."""
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.connect() as conn:
                with conn.begin():
                    self._seed_enrolment(conn, seed="admin-cannot-rewrite")
                with pytest.raises(DBAPIError, match="append-only"), conn.begin():
                    conn.execute(
                        text(
                            "UPDATE mod_deploy.attestation_enrolments "
                            "SET algorithm = 'rewritten' "
                            "WHERE subject = 'host-admin-cannot-rewrite'"
                        )
                    )
        finally:
            eng.dispose()


def _fingerprint_of(seed: str) -> str:
    from dotmac_deployment_control.digests import PublicKeyFingerprintV1

    return PublicKeyFingerprintV1.from_public_key_b64(_public_key_b64(seed)).canonical


# ── The custody-pointer shape check is wired in, not merely available ──────


@pytest.mark.parametrize("call", ["enrol_root", "rotate_root"])
def test_a_malformed_custody_pointer_is_refused_before_anything_is_written(
    sessions, call: str
) -> None:
    """`host_attester_enrolment.require_custody_pointer` already implements
    the `bao://` shape check; this proves it is actually CALLED from the
    write path rather than merely existing beside it. A plain secret-shaped
    string (no `bao://` scheme) must be refused, and refused before any row
    lands -- checked by confirming the fingerprint was never enrolled."""
    subject = f"host-bad-pointer-{call}-{uuid.uuid4().hex[:8]}"
    bad_pointer = "not-a-bao-pointer"

    if call == "enrol_root":
        attempted_seed = subject
        with sessions() as db, pytest.raises(Exception, match="bao://"):
            enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                public_key_b64=_public_key_b64(attempted_seed),
                algorithm="ed25519",
                key_custody_pointer=bad_pointer,
                enrolment_authority="control_service",
            )
            db.commit()
    else:
        attempted_seed = f"{subject}-new"
        with sessions() as db:
            view = enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                public_key_b64=_public_key_b64(f"{subject}-old"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-old",
                enrolment_authority="control_service",
            )
            db.commit()
        with sessions() as db, pytest.raises(Exception, match="bao://"):
            rotate_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                supersedes_fingerprint=view.public_key_fingerprint,
                public_key_b64=_public_key_b64(attempted_seed),
                algorithm="ed25519",
                key_custody_pointer=bad_pointer,
                enrolment_authority="control_service",
            )
            db.commit()

    with sessions() as db:
        attempted_fp = _fingerprint_of(attempted_seed)
        assert (
            db.query(AttestationEnrolment)
            .filter(AttestationEnrolment.public_key_fingerprint == attempted_fp)
            .count()
            == 0
        )


# ── Proof 1: concurrent enrolment ───────────────────────────────────────────


class TestConcurrentEnrolment:
    """Two sessions racing to enrol. Both possible races are exercised:
    the SAME fingerprint (global uniqueness) and two DIFFERENT fresh
    fingerprints for the SAME subject (the current-root primary key)."""

    def test_two_sessions_enrolling_the_identical_fingerprint_leave_exactly_one_row(
        self, sessions
    ) -> None:
        subject = f"host-race-same-{uuid.uuid4().hex[:8]}"
        seed = f"same-fp-{uuid.uuid4().hex[:8]}"
        public_key_b64 = _public_key_b64(seed)
        results: dict[int, object] = {}
        barrier = threading.Barrier(2)

        def worker(index: int) -> None:
            db: Session = sessions()
            try:
                barrier.wait(timeout=30)
                try:
                    enrol_root(
                        db,
                        custody_domain="host_attester",
                        subject=subject,
                        public_key_b64=public_key_b64,
                        algorithm="ed25519",
                        key_custody_pointer="bao://secret/dotmac/attest/race",
                        enrolment_authority="control_service",
                    )
                    db.commit()
                    results[index] = "won"
                except AttestationRefusedError as exc:
                    db.rollback()
                    results[index] = exc.code
            finally:
                db.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()

        outcomes = list(results.values())
        assert outcomes.count("won") == 1
        assert outcomes.count(AttestationRefusalCode.ALREADY_ENROLLED) == 1

        with sessions() as db:
            rows = (
                db.query(AttestationEnrolment)
                .filter(AttestationEnrolment.subject == subject)
                .all()
            )
            assert len(rows) == 1
            roots = (
                db.query(AttestationCurrentRoot)
                .filter(AttestationCurrentRoot.subject == subject)
                .all()
            )
            assert len(roots) == 1

    def test_two_sessions_enrolling_different_fresh_keys_leave_one_current_root(
        self, sessions
    ) -> None:
        subject = f"host-race-diff-{uuid.uuid4().hex[:8]}"
        results: dict[int, object] = {}
        barrier = threading.Barrier(2)

        def worker(index: int) -> None:
            db: Session = sessions()
            try:
                barrier.wait(timeout=30)
                try:
                    enrol_root(
                        db,
                        custody_domain="host_attester",
                        subject=subject,
                        public_key_b64=_public_key_b64(f"race-diff-{subject}-{index}"),
                        algorithm="ed25519",
                        key_custody_pointer="bao://secret/dotmac/attest/race-diff",
                        enrolment_authority="control_service",
                    )
                    db.commit()
                    results[index] = "won"
                except AttestationRefusedError as exc:
                    db.rollback()
                    results[index] = exc.code
            finally:
                db.close()

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(2)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()

        outcomes = list(results.values())
        # BOTH enrolment inserts may succeed (they name different global
        # fingerprints, so uq_attestation_enrolments_fingerprint does not fire)
        # -- it is the SECOND attestation_current_roots insert, keyed on
        # (custody_domain, subject), that must refuse exactly one of them.
        assert outcomes.count("won") == 1
        assert outcomes.count(AttestationRefusalCode.ALREADY_ENROLLED) == 1

        with sessions() as db:
            roots = (
                db.query(AttestationCurrentRoot)
                .filter(AttestationCurrentRoot.subject == subject)
                .all()
            )
            assert len(roots) == 1
            enrolments = (
                db.query(AttestationEnrolment)
                .filter(AttestationEnrolment.subject == subject)
                .all()
            )
            # The loser's caller rolls back on `AttestationRefusedError`
            # (documented caller discipline, matching every other
            # conflict_savepoint consumer in this package), which undoes the
            # loser's OWN enrolment insert along with it -- there is exactly
            # one enrolment row and one current root, both the winner's.
            assert len(enrolments) == 1
            assert enrolments[0].public_key_fingerprint == roots[0].current_fingerprint
            assert (
                fingerprint_standing(db, fingerprint=roots[0].current_fingerprint)
                is HostAttesterStanding.VALID
            )


# ── Proof 2: cross-role fingerprint reuse, refused BY THE DATABASE ─────────


class TestCrossRoleFingerprintReuseIsADatabaseConstraint:
    """The headline invariant. Refused by `uq_attestation_enrolments_fingerprint`
    directly -- via raw SQL, so no application code stands between the attempt
    and the constraint."""

    def test_raw_sql_insert_of_the_same_fingerprint_in_the_other_domain_is_refused(
        self, migrated_scratch
    ) -> None:
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        seed = f"cross-role-{uuid.uuid4().hex[:8]}"
        fp = _fingerprint_of(seed)
        pub = _public_key_b64(seed)
        try:
            with eng.connect() as conn:
                with conn.begin():
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.attestation_enrolments ("
                            " id, custody_domain, subject, public_key_b64,"
                            " public_key_fingerprint, algorithm,"
                            " key_custody_pointer, enrolled_at,"
                            " enrolment_authority"
                            ") VALUES (:id, 'host_attester', 'host-x', :pub, :fp,"
                            " 'ed25519', 'bao://secret/dotmac/attest/x', now(),"
                            " 'control_service')"
                        ),
                        {"id": uuid.uuid4(), "pub": pub, "fp": fp},
                    )
                with pytest.raises(IntegrityError), conn.begin():
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.attestation_enrolments ("
                            " id, custody_domain, subject, public_key_b64,"
                            " public_key_fingerprint, algorithm,"
                            " key_custody_pointer, enrolled_at,"
                            " enrolment_authority"
                            ") VALUES (:id, 'candidate_release_signer',"
                            " 'foundation-release-signer', :pub, :fp, 'ed25519',"
                            " 'bao://secret/dotmac/attest/y', now(),"
                            " 'control_service')"
                        ),
                        {"id": uuid.uuid4(), "pub": pub, "fp": fp},
                    )
        finally:
            eng.dispose()

    def test_the_service_layer_reports_the_same_refusal(self, sessions) -> None:
        seed = f"cross-role-service-{uuid.uuid4().hex[:8]}"
        pub = _public_key_b64(seed)
        with sessions() as db:
            enrol_root(
                db,
                custody_domain="host_attester",
                subject="host-service-x",
                public_key_b64=pub,
                algorithm="ed25519",
                key_custody_pointer="bao://secret/dotmac/attest/service-x",
                enrolment_authority="control_service",
            )
            db.commit()
        with sessions() as db:
            with pytest.raises(AttestationRefusedError) as excinfo:
                enrol_root(
                    db,
                    custody_domain="candidate_release_signer",
                    subject="foundation-release-signer",
                    public_key_b64=pub,
                    algorithm="ed25519",
                    key_custody_pointer="bao://secret/dotmac/attest/service-y",
                    enrolment_authority="control_service",
                )
            db.rollback()
        assert excinfo.value.code is AttestationRefusalCode.ALREADY_ENROLLED


# ── Proof 3: rotation versus revocation ordering ────────────────────────────


class TestRotationVersusRevocationOrdering:
    """Michael's ruling, made structural by the closure table's primary key
    on `fingerprint`: whichever of a revocation and a supersession commits
    first wins permanently; the later act cannot reclaim it; recovery is a
    new signed attempt, never a reset of the closed marker."""

    def _enrol(self, db: Session, *, subject: str, seed: str) -> str:
        view = enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(seed),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{seed}",
            enrolment_authority="control_service",
        )
        return view.public_key_fingerprint

    def test_revocation_committed_first_permanently_refuses_a_later_rotation(
        self, sessions
    ) -> None:
        subject = f"host-order-revoke-first-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            fp = self._enrol(db, subject=subject, seed=f"{subject}-a")
            db.commit()

        with sessions() as db:
            revoke_root(db, fingerprint=fp, revocation_authority="control_service")
            db.commit()

        with sessions() as db:
            with pytest.raises(AttestationRefusedError) as excinfo:
                rotate_root(
                    db,
                    custody_domain="host_attester",
                    subject=subject,
                    supersedes_fingerprint=fp,
                    public_key_b64=_public_key_b64(f"{subject}-b"),
                    algorithm="ed25519",
                    key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-b",
                    enrolment_authority="control_service",
                )
            db.rollback()
        assert excinfo.value.code is AttestationRefusalCode.NO_ACTIVE_ROOT_TO_ROTATE

        # Recovery is a NEW signed initial enrolment, never a resurrection of
        # the revoked marker.
        with sessions() as db:
            recovered = enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                public_key_b64=_public_key_b64(f"{subject}-recovery"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-recovery",
                enrolment_authority="control_service",
            )
            db.commit()
            assert recovered.standing == HostAttesterStanding.VALID.value

        with sessions() as db:
            assert (
                fingerprint_standing(db, fingerprint=fp) is HostAttesterStanding.REVOKED
            )

    def test_a_committed_rotation_permanently_refuses_a_later_revocation_of_the_old_key(
        self, sessions
    ) -> None:
        """The mirror case: the old key was already rotated away before the
        revocation's closure INSERT could claim the same primary-key slot."""
        subject = f"host-order-rotate-first-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            old_fp = self._enrol(db, subject=subject, seed=f"{subject}-old")
            db.commit()

        with sessions() as db:
            rotate_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                supersedes_fingerprint=old_fp,
                public_key_b64=_public_key_b64(f"{subject}-new"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-new",
                enrolment_authority="control_service",
            )
            db.commit()

        with sessions() as db:
            with pytest.raises(AttestationRefusedError) as excinfo:
                revoke_root(
                    db, fingerprint=old_fp, revocation_authority="control_service"
                )
            db.rollback()
        assert excinfo.value.code is AttestationRefusalCode.FINGERPRINT_SUPERSEDED

        with sessions() as db:
            assert (
                fingerprint_standing(db, fingerprint=old_fp)
                is HostAttesterStanding.SUPERSEDED
            )

    def test_two_concurrent_closures_of_one_fingerprint_leave_exactly_one_winner(
        self, sessions
    ) -> None:
        """The real ordering race, driven through two threads rather than
        sequential calls: a rotation and a revocation both targeting the SAME
        prior fingerprint, started concurrently. Whichever commits first must
        win the closure's primary key; the other must observe a permanent
        refusal, never a silent second closure."""
        subject = f"host-order-race-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            fp = self._enrol(db, subject=subject, seed=f"{subject}-base")
            db.commit()

        outcomes: dict[str, object] = {}
        barrier = threading.Barrier(2)

        def do_rotate() -> None:
            db: Session = sessions()
            try:
                barrier.wait(timeout=30)
                try:
                    rotate_root(
                        db,
                        custody_domain="host_attester",
                        subject=subject,
                        supersedes_fingerprint=fp,
                        public_key_b64=_public_key_b64(f"{subject}-rotate-winner"),
                        algorithm="ed25519",
                        key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-rw",
                        enrolment_authority="control_service",
                    )
                    db.commit()
                    outcomes["rotate"] = "won"
                except AttestationRefusedError as exc:
                    db.rollback()
                    outcomes["rotate"] = exc.code
            finally:
                db.close()

        def do_revoke() -> None:
            db: Session = sessions()
            try:
                barrier.wait(timeout=30)
                try:
                    revoke_root(
                        db, fingerprint=fp, revocation_authority="control_service"
                    )
                    db.commit()
                    outcomes["revoke"] = "won"
                except AttestationRefusedError as exc:
                    db.rollback()
                    outcomes["revoke"] = exc.code
            finally:
                db.close()

        threads = (
            threading.Thread(target=do_rotate),
            threading.Thread(target=do_revoke),
        )
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)
            assert not t.is_alive()

        # Exactly one of the two operations won; the loser was permanently
        # refused, never silently accepted alongside the winner.
        wins = [v for v in outcomes.values() if v == "won"]
        assert len(wins) == 1
        with sessions() as db:
            standing = fingerprint_standing(db, fingerprint=fp)
        assert standing in (
            HostAttesterStanding.REVOKED,
            HostAttesterStanding.SUPERSEDED,
        )
        if outcomes["rotate"] == "won":
            assert standing is HostAttesterStanding.SUPERSEDED
            assert outcomes["revoke"] in (
                AttestationRefusalCode.FINGERPRINT_SUPERSEDED,
                AttestationRefusalCode.LOST_ROTATION_RACE,
            )
        else:
            assert standing is HostAttesterStanding.REVOKED
            assert outcomes["rotate"] in (
                AttestationRefusalCode.FINGERPRINT_REVOKED,
                AttestationRefusalCode.LOST_ROTATION_RACE,
            )


# ── Proof 4: stale-reader behaviour ──────────────────────────────────────────


class TestStaleReaderBehaviour:
    """What a reader holding an older snapshot sees. A REPEATABLE READ
    transaction takes its snapshot at its first statement; a revocation
    committed by another session afterwards must not appear inside it, and a
    fresh read after that transaction ends must see it."""

    def test_a_repeatable_read_transaction_does_not_see_a_concurrent_revocation(
        self, engine, sessions
    ) -> None:
        subject = f"host-stale-{uuid.uuid4().hex[:8]}"
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

        reader = engine.connect().execution_options(isolation_level="REPEATABLE READ")
        reader_txn = reader.begin()
        # Take the snapshot with a real read before the concurrent write.
        before = reader.execute(
            text(
                "SELECT count(*) FROM mod_deploy.attestation_fingerprint_closures "
                "WHERE fingerprint = :fp"
            ),
            {"fp": fp},
        ).scalar_one()
        assert before == 0

        with sessions() as writer:
            revoke_root(writer, fingerprint=fp, revocation_authority="control_service")
            writer.commit()

        # Still inside the reader's REPEATABLE READ transaction: the
        # committed revocation must not be visible.
        during = reader.execute(
            text(
                "SELECT count(*) FROM mod_deploy.attestation_fingerprint_closures "
                "WHERE fingerprint = :fp"
            ),
            {"fp": fp},
        ).scalar_one()
        assert during == 0, (
            "a REPEATABLE READ snapshot taken before the revocation committed "
            "must not observe it -- caching this read across the concurrent "
            "write would be exactly this false negative"
        )
        reader_txn.rollback()
        reader.close()

        # A FRESH read (new snapshot) sees the committed revocation.
        with sessions() as fresh:
            after = fresh.execute(
                text(
                    "SELECT count(*) FROM mod_deploy.attestation_fingerprint_closures "
                    "WHERE fingerprint = :fp"
                ),
                {"fp": fp},
            ).scalar_one()
            standing = fingerprint_standing(fresh, fingerprint=fp)
        assert after == 1
        assert standing is HostAttesterStanding.REVOKED


# ── Standing proof obligations beyond the four Postgres proofs ─────────────


def test_the_public_view_carries_no_orm_or_session_state(sessions) -> None:
    """Plant: a caller who tries to read an ORM attribute off the returned
    value must get a plain, ordinary `AttributeError` for a name the
    dataclass never declares -- not a `DetachedInstanceError`, which is what
    an ORM object would raise once its session closed. That specific
    exception type is the sensitivity control: it only differs from a bare
    dataclass's `AttributeError` if something ORM-shaped actually leaked."""
    subject = f"host-boundary-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        view = enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject,
            public_key_b64=_public_key_b64(subject),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
            enrolment_authority="control_service",
        )
        db.commit()
    # The session is closed. A leaked ORM object would now raise
    # DetachedInstanceError on lazy access; the typed view raises plain
    # AttributeError for an undeclared field, proving it never was one.
    assert not isinstance(view, AttestationEnrolment)
    assert not hasattr(view, "_sa_instance_state")
    with pytest.raises(AttributeError):
        _ = view.this_field_does_not_exist_on_the_dataclass  # type: ignore[attr-defined]
    assert isinstance(view.enrolled_at, datetime)
    assert isinstance(view.public_key_fingerprint, str)


def test_a_revoked_fingerprint_is_never_reported_valid(sessions) -> None:
    """Plant: a fingerprint that has been revoked. Near miss: a merely
    SUPERSEDED fingerprint, which must read distinctly, never as VALID and
    never confused with REVOKED."""
    subject = f"host-never-valid-{uuid.uuid4().hex[:8]}"
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

    with sessions() as db:
        assert fingerprint_standing(db, fingerprint=fp) is HostAttesterStanding.REVOKED
        assert (
            resolve_current_root(db, custody_domain="host_attester", subject=subject)
            is None
        )

    # Near miss: a SUPERSEDED fingerprint (a different subject) must read as
    # SUPERSEDED, not REVOKED and not VALID -- proving the guard actually
    # distinguishes the two terminal states rather than treating "closed" as
    # one bucket.
    subject2 = f"host-superseded-not-revoked-{uuid.uuid4().hex[:8]}"
    with sessions() as db:
        old = enrol_root(
            db,
            custody_domain="host_attester",
            subject=subject2,
            public_key_b64=_public_key_b64(f"{subject2}-old"),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject2}-old",
            enrolment_authority="control_service",
        )
        db.commit()
    with sessions() as db:
        rotate_root(
            db,
            custody_domain="host_attester",
            subject=subject2,
            supersedes_fingerprint=old.public_key_fingerprint,
            public_key_b64=_public_key_b64(f"{subject2}-new"),
            algorithm="ed25519",
            key_custody_pointer=f"bao://secret/dotmac/attest/{subject2}-new",
            enrolment_authority="control_service",
        )
        db.commit()
    with sessions() as db:
        assert (
            fingerprint_standing(db, fingerprint=old.public_key_fingerprint)
            is HostAttesterStanding.SUPERSEDED
        )


# ── The downgrade guard: append-only evidence is not a rollback's to discard ─


def test_the_downgrade_refuses_to_discard_append_only_evidence(
    migrated_scratch, sessions
) -> None:
    """dc_0010's own convention (`rollout_attempt_settlements`'s downgrade:
    LOCK, check for rows, raise rather than drop) applied to the two
    append-only tables this revision adds. An unrelated rollback during an
    incident must not be able to silently erase the attestation trust
    evidence this whole feature exists to make durable.

    `attestation_current_roots` is deliberately NOT covered by this guard --
    it is a re-derivable projection over the two append-only tables
    (`attestation_trust_registry.reconcile_current_root`/
    `repair_current_root`), so `dc_0011`'s `downgrade()` drops it
    unconditionally, and that is correct.
    """
    subject = f"host-downgrade-guard-{uuid.uuid4().hex[:8]}"
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

    from alembic import command
    from alembic.config import Config

    admin_url, _, _ = migrated_scratch
    cfg = Config(str(REPO_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
    cfg.set_main_option("version_locations", f"{KERNEL_VERSIONS} {DEPLOY_VERSIONS}")
    previous_migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    os.environ["MIGRATION_DATABASE_URL"] = admin_url
    try:
        with pytest.raises(RuntimeError, match="refuses to discard"):
            command.downgrade(cfg, "dc_0010_attempt_settlements")
    finally:
        if previous_migration_url is None:
            os.environ.pop("MIGRATION_DATABASE_URL", None)
        else:
            os.environ["MIGRATION_DATABASE_URL"] = previous_migration_url

    # The refusal itself is not proof that nothing was dropped first --
    # confirm every dc_0011 table is still standing.
    admin_engine = create_engine(admin_url)
    try:
        with admin_engine.connect() as conn:
            for table in TABLES:
                assert (
                    conn.execute(
                        text("SELECT to_regclass(:t)"),
                        {"t": f"{SCHEMA}.{table}"},
                    ).scalar()
                    is not None
                ), table
    finally:
        admin_engine.dispose()


# ── attestation_current_roots: derived projection, drift and repair ────────


class TestCurrentRootDriftDetectionAndRepair:
    """`attestation_current_roots` is a derived projection over the two
    append-only tables (see `models.AttestationCurrentRoot`'s docstring).
    This proves it can actually drift when corrupted out from under the
    service (a raw-SQL write, the exact hazard the projection's own design
    note names), that `reconcile_current_root` detects it, and that
    `repair_current_root` removes it without touching the append-only
    tables."""

    def test_a_raw_sql_corruption_is_detected_and_repaired(
        self, migrated_scratch, sessions
    ) -> None:
        """An UNAMBIGUOUS drift: exactly one enrolment is open for this
        subject, but the projection points somewhere else entirely (a
        raw-SQL write, a restored backup). `repair_current_root` may safely
        fix this one, because there is only ever one candidate to write --
        never a choice among several."""
        subject = f"host-drift-{uuid.uuid4().hex[:8]}"
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
        correct_fp = view.public_key_fingerprint

        # Enrol a SECOND, unrelated fingerprint directly by raw SQL and
        # immediately CLOSE it, so it never counts as open -- then repoint
        # the projection at it. The append-only truth still names exactly
        # one open enrolment (`correct_fp`); only the projection is wrong.
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        other_seed = f"{subject}-drift-fp"
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
                        " 'ed25519', 'bao://secret/dotmac/attest/drift', now(),"
                        " 'manual_repair_script')"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "subject": subject,
                        "pub": _public_key_b64(other_seed),
                        "fp": other_fp,
                    },
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.attestation_fingerprint_closures "
                        "(fingerprint, closure_kind, closed_at, closure_authority) "
                        "VALUES (:fp, 'superseded', now(), 'manual_repair_script')"
                    ),
                    {"fp": other_fp},
                )
                conn.execute(
                    text(
                        "UPDATE mod_deploy.attestation_current_roots "
                        "SET current_fingerprint = :fp "
                        "WHERE custody_domain = 'host_attester' AND subject = :subject"
                    ),
                    {"fp": other_fp, "subject": subject},
                )
        finally:
            eng.dispose()

        with sessions() as db:
            drift = reconcile_current_root(
                db, custody_domain="host_attester", subject=subject
            )
        assert drift.drifted
        assert drift.recorded_fingerprint == other_fp
        assert drift.expected_fingerprint == correct_fp
        assert drift.open_enrolment_count == 1

        with sessions() as db:
            repair_current_root(db, custody_domain="host_attester", subject=subject)
            db.commit()

        with sessions() as db:
            repaired = reconcile_current_root(
                db, custody_domain="host_attester", subject=subject
            )
            assert not repaired.drifted
            assert repaired.recorded_fingerprint == correct_fp
            assert repaired.recorded_fingerprint == repaired.expected_fingerprint

        # Confirm no write ever touched the append-only tables during either
        # the corruption or the repair, other than the deliberate raw-SQL
        # writes above.
        with sessions() as db:
            count = (
                db.query(AttestationEnrolment)
                .filter(AttestationEnrolment.subject == subject)
                .count()
            )
            closures = (
                db.query(AttestationFingerprintClosure)
                .filter(
                    AttestationFingerprintClosure.fingerprint.in_(
                        [correct_fp, other_fp]
                    )
                )
                .count()
            )
        assert count == 2
        assert closures == 1

    def test_repair_refuses_to_persist_a_choice_among_ambiguous_open_enrolments(
        self, migrated_scratch, sessions
    ) -> None:
        """The plant: two open enrolments exist for one `(custody_domain,
        subject)` -- the append-only truth itself does not agree on a single
        answer. `repair_current_root` must refuse and write NOTHING, rather
        than persist `_derive_current_fingerprint`'s old most-recent-wins
        pick -- a write here would convert a transient registry
        inconsistency into DURABLE state that even `reconcile_current_root`
        would then treat as settled. The near-miss: closing the extra
        enrolment removes the ambiguity, and the identical call on the
        identical subject then succeeds."""
        subject = f"host-ambiguous-repair-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            original = enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                public_key_b64=_public_key_b64(f"{subject}-a"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject}-a",
                enrolment_authority="control_service",
            )
            db.commit()

        # A second, never-closed enrolment for the SAME subject/domain,
        # inserted directly by raw SQL. The projection is left untouched --
        # it still (legitimately) names `original`.
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        second_seed = f"{subject}-ambiguous-second"
        second_fp = _fingerprint_of(second_seed)
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
                        "pub": _public_key_b64(second_seed),
                        "fp": second_fp,
                    },
                )
        finally:
            eng.dispose()

        with sessions() as db:
            drift = reconcile_current_root(
                db, custody_domain="host_attester", subject=subject
            )
        assert drift.drifted
        assert drift.open_enrolment_count == 2
        assert drift.expected_fingerprint is None

        with sessions() as db:
            with pytest.raises(AttestationRefusedError) as excinfo:
                repair_current_root(db, custody_domain="host_attester", subject=subject)
            db.rollback()
        assert excinfo.value.code is AttestationRefusalCode.AMBIGUOUS_CURRENT_ROOT

        # The refusal wrote nothing: the projection still names exactly what
        # it did before repair was ever called.
        with sessions() as db:
            row = db.get(AttestationCurrentRoot, ("host_attester", subject))
            assert row is not None
            assert row.current_fingerprint == original.public_key_fingerprint

        # Near miss: close the extra enrolment (revoke it) -- the ambiguity
        # is gone, and the identical repair call on the identical subject now
        # succeeds.
        with sessions() as db:
            revoke_root(
                db, fingerprint=second_fp, revocation_authority="control_service"
            )
            db.commit()
        with sessions() as db:
            repair_current_root(db, custody_domain="host_attester", subject=subject)
            db.commit()
        with sessions() as db:
            repaired = reconcile_current_root(
                db, custody_domain="host_attester", subject=subject
            )
            assert not repaired.drifted
            assert repaired.recorded_fingerprint == original.public_key_fingerprint

    def test_a_projection_naming_a_revoked_fingerprint_never_returns_a_root(
        self, migrated_scratch, sessions
    ) -> None:
        """Michael's ruling, stated as a test: `attestation_current_roots` may
        ACCELERATE a read; it may never independently ESTABLISH standing. A
        projection row pointing at a fingerprint the append-only closures
        table has already revoked must return no root -- EVEN BEFORE
        `reconcile_current_root`/`repair_current_root` ever runs. This is
        deliberately NOT the drift-and-repair flow above: no reconciliation
        call happens anywhere in this test, because the refusal must hold at
        the moment of the READ, not only after a separate repair step."""
        subject = f"host-corrupt-to-revoked-{uuid.uuid4().hex[:8]}"
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
        # `revoke_root` deletes the projection row on its own correct path;
        # the corruption below simulates a raw-SQL write or a restored
        # backup that reinserts a pointer to that now-REVOKED fingerprint --
        # the exact hazard the projection's own design note names.
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
            # The corrupted row is still present and still names the revoked
            # fingerprint -- confirmed here so the assertion below is known
            # to be exercising the corrupted state, not a state the INSERT
            # above silently failed to create.
            assert (
                db.get(AttestationCurrentRoot, ("host_attester", subject)) is not None
            )
            assert (
                resolve_current_root(
                    db, custody_domain="host_attester", subject=subject
                )
                is None
            )
            # `fingerprint_standing` never consulted the projection for this
            # fingerprint's standing in the first place; restated here as the
            # cross-check that both read paths agree a revoked key is never
            # reported active.
            assert (
                fingerprint_standing(db, fingerprint=fp) is HostAttesterStanding.REVOKED
            )

    def test_a_projection_naming_another_hosts_fingerprint_never_returns_a_root(
        self, migrated_scratch, sessions
    ) -> None:
        """Pre-reconciliation negative control, same pattern as the
        revoked-fingerprint test above: a projection row corrupted (raw SQL,
        a restored backup) to point at a fingerprint that is genuinely
        enrolled, current, and unrevoked -- but for a DIFFERENT subject --
        must still refuse. `resolve_current_root` builds its returned view
        from the RESOLVED enrolment's own fields; without checking that
        enrolment's `subject` against the one requested, this corruption
        would silently hand the caller another host's key. No
        `reconcile_current_root`/`repair_current_root` call happens anywhere
        in this test."""
        subject_a = f"host-cross-a-{uuid.uuid4().hex[:8]}"
        subject_b = f"host-cross-b-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject_a,
                public_key_b64=_public_key_b64(f"{subject_a}-a"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject_a}-a",
                enrolment_authority="control_service",
            )
            db.commit()
        with sessions() as db:
            view_b = enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject_b,
                public_key_b64=_public_key_b64(f"{subject_b}-b"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject_b}-b",
                enrolment_authority="control_service",
            )
            db.commit()

        # Corrupt subject_a's projection row to point at subject_b's
        # perfectly valid, current, unrevoked fingerprint.
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE mod_deploy.attestation_current_roots "
                        "SET current_fingerprint = :fp "
                        "WHERE custody_domain = 'host_attester' AND subject = :subject"
                    ),
                    {"fp": view_b.public_key_fingerprint, "subject": subject_a},
                )
        finally:
            eng.dispose()

        with sessions() as db:
            assert (
                db.get(
                    AttestationCurrentRoot, ("host_attester", subject_a)
                ).current_fingerprint
                == view_b.public_key_fingerprint
            )
            assert (
                resolve_current_root(
                    db, custody_domain="host_attester", subject=subject_a
                )
                is None
            )
            # Near miss: subject_b's OWN, uncorrupted lookup still resolves
            # normally -- the refusal above is about the substitution, not
            # about subject_b's fingerprint being unresolvable in general.
            resolved_b = resolve_current_root(
                db, custody_domain="host_attester", subject=subject_b
            )
            assert resolved_b is not None
            assert resolved_b.public_key_fingerprint == view_b.public_key_fingerprint

    def test_a_projection_naming_another_domains_fingerprint_never_returns_a_root(
        self, migrated_scratch, sessions
    ) -> None:
        """The domain-substitution mirror of the host-substitution test
        above: the SAME subject string enrolled independently in both
        custody domains, then one domain's projection row corrupted to point
        at the OTHER domain's fingerprint. Refused before any
        reconciliation."""
        shared_subject = f"shared-subject-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            enrol_root(
                db,
                custody_domain="host_attester",
                subject=shared_subject,
                public_key_b64=_public_key_b64(f"{shared_subject}-host"),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{shared_subject}-host",
                enrolment_authority="control_service",
            )
            db.commit()
        with sessions() as db:
            release_view = enrol_root(
                db,
                custody_domain="candidate_release_signer",
                subject=shared_subject,
                public_key_b64=_public_key_b64(f"{shared_subject}-release"),
                algorithm="ed25519",
                key_custody_pointer=(
                    f"bao://secret/dotmac/attest/{shared_subject}-release"
                ),
                enrolment_authority="control_service",
            )
            db.commit()

        # Corrupt the host_attester projection row to point at the
        # candidate_release_signer fingerprint for the SAME subject string.
        admin_url, _, _ = migrated_scratch
        eng = create_engine(admin_url)
        try:
            with eng.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE mod_deploy.attestation_current_roots "
                        "SET current_fingerprint = :fp "
                        "WHERE custody_domain = 'host_attester' AND subject = :subject"
                    ),
                    {
                        "fp": release_view.public_key_fingerprint,
                        "subject": shared_subject,
                    },
                )
        finally:
            eng.dispose()

        with sessions() as db:
            assert (
                db.get(
                    AttestationCurrentRoot, ("host_attester", shared_subject)
                ).current_fingerprint
                == release_view.public_key_fingerprint
            )
            assert (
                resolve_current_root(
                    db, custody_domain="host_attester", subject=shared_subject
                )
                is None
            )
            # Near miss: the candidate_release_signer domain's own,
            # uncorrupted lookup for the SAME subject string still resolves
            # -- the refusal above is about the domain substitution, not
            # about the subject string being ambiguous by itself.
            resolved_release = resolve_current_root(
                db,
                custody_domain="candidate_release_signer",
                subject=shared_subject,
            )
            assert resolved_release is not None
            assert (
                resolved_release.public_key_fingerprint
                == release_view.public_key_fingerprint
            )

    def test_a_projection_backed_by_an_ambiguous_registry_never_returns_a_root(
        self, migrated_scratch, sessions
    ) -> None:
        """The append-only truth can hold more than one OPEN enrolment for a
        single `(custody_domain, subject)` even though the projection's
        primary key can only ever name one -- a raw-SQL insert of a second,
        never-closed enrolment is exactly the anomaly
        `_derive_current_fingerprint`'s own docstring names. Trusting the
        projection's single pointer in that state would silently convert a
        registry inconsistency into a confident answer. Refused at the
        moment of the READ; no `reconcile_current_root`/`repair_current_root`
        call happens anywhere in this test."""
        subject = f"host-ambiguous-{uuid.uuid4().hex[:8]}"
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

        # Insert a SECOND, never-closed enrolment for the same subject/domain
        # directly by raw SQL -- the projection still names the first
        # (correct, current) fingerprint untouched.
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
                resolve_current_root(
                    db, custody_domain="host_attester", subject=subject
                )
                is None
            )

        # Near miss: an entirely unrelated subject, with exactly one open
        # enrolment, still resolves normally under the identical code path --
        # the refusal above is about the ambiguity, not about
        # `resolve_current_root` having become universally unable to
        # resolve.
        other_subject = f"host-unambiguous-{uuid.uuid4().hex[:8]}"
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
            resolved_other = resolve_current_root(
                db, custody_domain="host_attester", subject=other_subject
            )
            assert resolved_other is not None
            assert (
                resolved_other.public_key_fingerprint
                == other_view.public_key_fingerprint
            )

    def test_repair_deletes_the_projection_when_there_is_no_open_enrolment(
        self, sessions
    ) -> None:
        subject = f"host-drift-absent-{uuid.uuid4().hex[:8]}"
        with sessions() as db:
            view = enrol_root(
                db,
                custody_domain="host_attester",
                subject=subject,
                public_key_b64=_public_key_b64(subject),
                algorithm="ed25519",
                key_custody_pointer=f"bao://secret/dotmac/attest/{subject}",
                enrolment_authority="control_service",
            )
            db.commit()
        with sessions() as db:
            revoke_root(
                db,
                fingerprint=view.public_key_fingerprint,
                revocation_authority="control_service",
            )
            db.commit()
        # revoke_root already deletes the projection row on this path; call
        # repair anyway to prove it is idempotent against an already-correct
        # (absent) state.
        with sessions() as db:
            repair_current_root(db, custody_domain="host_attester", subject=subject)
            db.commit()
        with sessions() as db:
            assert db.get(AttestationCurrentRoot, ("host_attester", subject)) is None
