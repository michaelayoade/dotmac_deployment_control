"""Postgres proof for `mod_deploy`: migration, grants, isolation, append-only.

Provisions its own scratch database and composes the module's lineage explicitly,
because the reference assembly deliberately does not compose
`dotmac-deployment-control`: a module that decides what a FLEET should run cannot
live inside one of the deployments it decides about (ADR-0033 § 7).

Beyond the usual platform-plane proofs, this file carries the two the V6 source
design earned and this port must not lose:

1. **The claim/proof separation holds against RAW SQL**, not only against the
   service. Both CHECK constraints are exercised directly.
2. **`app_admin` cannot rewrite an attempt or a receipt.** A rewritable tripwire
   is decoration, and a rewritable `original_verdict` lets an at-least-once
   transport be made to look like a state change.

Requires real Postgres (`make test-db-up` / `make test-integration`).
"""

from __future__ import annotations

import os
import uuid
from collections.abc import Iterator
from pathlib import Path

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError, ProgrammingError

REPO_ROOT = Path(__file__).resolve().parent.parent
KERNEL_VERSIONS = (
    REPO_ROOT / "packages/dotmac-kernel/src/dotmac_kernel/migrations/versions"
)
ASSEMBLY_VERSIONS = REPO_ROOT / "alembic/versions"
DEPLOY_VERSIONS = (
    REPO_ROOT
    / "packages/dotmac-deployment-control/src/dotmac_deployment_control"
    / "migrations/versions"
)

SCHEMA = "mod_deploy"
TABLES = (
    "deployment_targets",
    "target_credentials",
    "deployment_plans",
    "rollouts",
    "rollout_attempts",
    "observation_receipts",
    "observation_attempts",
)
EVIDENCE_TABLES = ("rollout_attempts", "observation_attempts", "observation_receipts")
MUTABLE_TABLES = (
    "deployment_targets",
    "target_credentials",
    "deployment_plans",
    "rollouts",
)

#: All seven. A revoke that covers six is not a revoke.
ALL_PRIVILEGES = (
    "SELECT",
    "INSERT",
    "UPDATE",
    "DELETE",
    "TRUNCATE",
    "REFERENCES",
    "TRIGGER",
)
ROW_DML = ("SELECT", "INSERT", "UPDATE", "DELETE")


def _superuser_url() -> str:
    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — the platform canary needs Postgres")
    return url


def _url_for(base_url: str, dbname: str, *, user: str | None = None) -> str:
    scheme_userhost, _, _ = base_url.rpartition("/")
    if user is not None:
        scheme, _, userhost = scheme_userhost.partition("://")
        host = userhost.rpartition("@")[2]
        scheme_userhost = f"{scheme}://{user}@{host}"
    return f"{scheme_userhost}/{dbname}"


@pytest.fixture(scope="module")
def migrated_scratch() -> Iterator[tuple[str, str, str]]:
    """`(admin_url, platform_api_url, app_user_url)` at the composed head."""
    superuser = _superuser_url()
    name = f"deploy_{uuid.uuid4().hex[:12]}"
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))

    setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
    with setup.connect() as conn:
        conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
        # A MODULE lineage creates its own schema, and `CREATE SCHEMA` needs
        # CREATE on the DATABASE — not merely ownership of `public`.
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
        cfg.set_main_option(
            "version_locations",
            f"{KERNEL_VERSIONS} {ASSEMBLY_VERSIONS} {DEPLOY_VERSIONS}",
        )
        os.environ["MIGRATION_DATABASE_URL"] = admin_url
        # From an EMPTY database to the composed head, so the lineage's
        # prerequisite verification runs for real against a catalog the kernel
        # lineage built moments earlier.
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


def _has_privilege(url: str, table: str, privilege: str, *, role: str) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT has_table_privilege(:r, :t, :p)"),
                    {"r": role, "t": f"mod_deploy.{table}", "p": privilege},
                ).scalar()
            )
    finally:
        engine.dispose()


def _insert_target(conn, **overrides: object) -> uuid.UUID:  # type: ignore[no-untyped-def]
    params: dict[str, object] = {
        "id": uuid.uuid4(),
        "ref": f"tgt-{uuid.uuid4().hex[:10]}",
    }
    params.update(overrides)
    conn.execute(
        text(
            "INSERT INTO mod_deploy.deployment_targets ("
            " id, target_ref, subject_ref, product_code, environment, status,"
            " desired_revision, record_version"
            ") VALUES (:id, :ref, 'acme', 'dotmac_sub', 'production',"
            " 'registered', 0, 1)"
        ),
        params,
    )
    return params["id"]  # type: ignore[return-value]


# ── Migration from empty ────────────────────────────────────────────────────


class TestTheLineageBuildsFromAnEmptyDatabase:
    def test_every_table_exists(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                for table in TABLES:
                    assert (
                        conn.execute(
                            text("SELECT to_regclass(:t)"),
                            {"t": f"mod_deploy.{table}"},
                        ).scalar()
                        is not None
                    ), table
        finally:
            engine.dispose()

    def test_no_table_carries_a_tenant_column(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT table_name FROM information_schema.columns "
                        "WHERE table_schema = :s AND column_name = 'tenant_id'"
                    ),
                    {"s": SCHEMA},
                ).all()
            assert not rows, rows
        finally:
            engine.dispose()

    def test_no_column_anywhere_is_a_provider_credential(
        self, migrated_scratch
    ) -> None:
        """Provider credentials are the Integrator's (hard rule 28), and the
        absence must hold in the LIVE catalog rather than only in the model
        layer — the two are separate artifacts."""
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT table_name, column_name "
                        "FROM information_schema.columns "
                        "WHERE table_schema = :s AND ("
                        "  column_name LIKE '%private%'"
                        "  OR column_name LIKE '%secret%'"
                        "  OR column_name LIKE '%password%'"
                        "  OR column_name LIKE '%endpoint%'"
                        "  OR column_name LIKE '%credential_ref%')"
                    ),
                    {"s": SCHEMA},
                ).all()
            assert not rows, rows
        finally:
            engine.dispose()

    def test_no_table_has_row_level_security(self, migrated_scratch) -> None:
        """Not even ENABLEd-with-no-policy, which denies every row to the
        control plane while reading as protected (hard rule 27)."""
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                for table in TABLES:
                    enabled, forced = conn.execute(
                        text(
                            "SELECT relrowsecurity, relforcerowsecurity "
                            "FROM pg_class WHERE oid = CAST(:t AS regclass)"
                        ),
                        {"t": f"mod_deploy.{table}"},
                    ).one()
                    assert not enabled and not forced, table
        finally:
            engine.dispose()

    def test_no_foreign_key_leaves_the_module_schema(self, migrated_scratch) -> None:
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                foreign = conn.execute(
                    text(
                        """
                        SELECT c.conname, tn.nspname
                        FROM pg_constraint c
                        JOIN pg_class t  ON t.oid  = c.conrelid
                        JOIN pg_namespace n ON n.oid = t.relnamespace
                        JOIN pg_class tt ON tt.oid = c.confrelid
                        JOIN pg_namespace tn ON tn.oid = tt.relnamespace
                        WHERE c.contype = 'f' AND n.nspname = :s
                          AND tn.nspname <> :s
                        """
                    ),
                    {"s": SCHEMA},
                ).all()
            assert not foreign, foreign
        finally:
            engine.dispose()


# ── Isolation ───────────────────────────────────────────────────────────────


class TestTheTenantAppRoleCanReachNothing:
    @pytest.mark.parametrize("table", TABLES)
    @pytest.mark.parametrize("privilege", ALL_PRIVILEGES)
    def test_app_user_holds_no_privilege(
        self, migrated_scratch, table: str, privilege: str
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert not _has_privilege(admin_url, table, privilege, role="app_user")

    @pytest.mark.parametrize("table", TABLES)
    def test_app_user_holds_no_column_level_privilege(
        self, migrated_scratch, table: str
    ) -> None:
        """Column grants survive a table-level REVOKE that names only tables."""
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                rows = conn.execute(
                    text(
                        "SELECT column_name, privilege_type "
                        "FROM information_schema.column_privileges "
                        "WHERE table_schema = :s AND table_name = :t "
                        "AND grantee = 'app_user'"
                    ),
                    {"s": SCHEMA, "t": table},
                ).all()
            assert not rows, rows
        finally:
            engine.dispose()

    def test_a_real_select_as_app_user_is_refused(self, migrated_scratch) -> None:
        _, _, app_user_url = migrated_scratch
        engine = create_engine(app_user_url)
        try:
            with (
                engine.connect() as conn,
                pytest.raises((DBAPIError, ProgrammingError)),
            ):
                conn.execute(text("SELECT 1 FROM mod_deploy.deployment_targets"))
        finally:
            engine.dispose()


class TestTheOnlinePlatformRoleCanActuallyWork:
    @pytest.mark.parametrize("table", TABLES)
    def test_platform_api_holds_at_least_one_row_dml_privilege(
        self, migrated_scratch, table: str
    ) -> None:
        """Declared and unusable is a violation too — a REVOKE-only suite would
        pass if `platform_api` had been granted nothing at all."""
        admin_url, _, _ = migrated_scratch
        held = [
            p
            for p in ROW_DML
            if _has_privilege(admin_url, table, p, role="platform_api")
        ]
        assert held, f"platform_api cannot reach {table} at all"

    @pytest.mark.parametrize("table", MUTABLE_TABLES)
    def test_platform_api_may_update_the_lifecycle_tables(
        self, migrated_scratch, table: str
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert _has_privilege(admin_url, table, "UPDATE", role="platform_api")

    @pytest.mark.parametrize("table", EVIDENCE_TABLES)
    def test_platform_api_may_not_update_the_evidence_tables(
        self, migrated_scratch, table: str
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert not _has_privilege(admin_url, table, "UPDATE", role="platform_api")

    def test_platform_api_can_insert_a_target_and_read_it_back(
        self, migrated_scratch
    ) -> None:
        _, platform_url, _ = migrated_scratch
        engine = create_engine(platform_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
                found = conn.execute(
                    text(
                        "SELECT status FROM mod_deploy.deployment_targets "
                        "WHERE id = :id"
                    ),
                    {"id": target_id},
                ).scalar()
            assert found == "registered"
        finally:
            engine.dispose()


# ── The claim/proof CHECKs, against raw SQL ─────────────────────────────────


class TestTheClaimProofSeparationIsStructural:
    """The property the whole observation design rests on, proven where it
    matters: against raw SQL, not against the service that would never write it."""

    @pytest.fixture
    def admin_url(self, migrated_scratch) -> str:
        return migrated_scratch[0]

    def _attempt(self, conn, **overrides: object) -> None:  # type: ignore[no-untyped-def]
        params: dict[str, object] = {
            "id": uuid.uuid4(),
            "sig": "valid",
            "elig": "eligible",
            "auth": "tgt-1",
        }
        params.update(overrides)
        conn.execute(
            text(
                "INSERT INTO mod_deploy.observation_attempts ("
                " id, received_at, raw_body_truncated, signature_status,"
                " eligibility_at_receipt, authenticated_target_ref, disposition"
                ") VALUES (:id, now(), false, :sig, :elig, :auth, 'accepted')"
            ),
            params,
        )

    def test_an_authenticated_ref_without_a_valid_signature_is_refused(
        self, admin_url: str
    ) -> None:
        """The attack in one row: claim an identity you did not prove. Without
        this constraint the two columns are just two strings a careless writer
        can fill identically."""
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError):
                self._attempt(conn, sig="unresolved", elig="n/a", auth="tgt-1")
        finally:
            engine.dispose()

    def test_a_non_na_eligibility_without_a_valid_signature_is_refused(
        self, admin_url: str
    ) -> None:
        """The eligibility of an unproven claim is not a meaningful question,
        and recording an answer to it would make a tripwire look adjudicated."""
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError):
                self._attempt(conn, sig="invalid", elig="eligible", auth=None)
        finally:
            engine.dispose()

    def test_an_unauthenticated_attempt_with_na_eligibility_is_accepted(
        self, admin_url: str
    ) -> None:
        """The other half: the constraints must not block the tripwire rows the
        module exists to record. A guard that refused these would make every
        failed arrival unloggable while passing both tests above."""
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                self._attempt(conn, sig="unresolved", elig="n/a", auth=None)
        finally:
            engine.dispose()


# ── Append-only evidence ────────────────────────────────────────────────────


class TestTheEvidenceTablesAreAppendOnlyAgainstEveryRole:
    @pytest.fixture
    def seeded(self, migrated_scratch) -> str:
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.observation_attempts ("
                        " id, received_at, raw_body_truncated, signature_status,"
                        " eligibility_at_receipt, disposition"
                        ") VALUES (:id, now(), false, 'unresolved', 'n/a',"
                        " 'unknown_key')"
                    ),
                    {"id": uuid.uuid4()},
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.observation_receipts ("
                        " id, authenticated_target_ref, report_id, key_id,"
                        " first_received_at, original_verdict"
                        ") VALUES (:id, :ref, :rep, 'k1', now(), 'accepted')"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "ref": f"tgt-{uuid.uuid4().hex[:8]}",
                        "rep": f"rep-{uuid.uuid4().hex[:8]}",
                    },
                )
        finally:
            engine.dispose()
        return admin_url

    def test_app_admin_cannot_update_an_observation_attempt(self, seeded) -> None:
        """A rewritable tripwire is decoration. `app_admin` legitimately holds
        full DML on the four lifecycle tables; the trigger is the only place the
        rule holds for it here."""
        engine = create_engine(seeded)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
                conn.execute(
                    text(
                        "UPDATE mod_deploy.observation_attempts "
                        "SET disposition = 'accepted'"
                    )
                )
        finally:
            engine.dispose()

    def test_app_admin_cannot_rewrite_an_original_verdict(self, seeded) -> None:
        """An editable `original_verdict` lets an at-least-once transport be made
        to look like a state change."""
        engine = create_engine(seeded)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
                conn.execute(
                    text(
                        "UPDATE mod_deploy.observation_receipts "
                        "SET original_verdict = 'conflict'"
                    )
                )
        finally:
            engine.dispose()

    def test_app_admin_cannot_delete_an_observation_attempt(self, seeded) -> None:
        engine = create_engine(seeded)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
                conn.execute(text("DELETE FROM mod_deploy.observation_attempts"))
        finally:
            engine.dispose()

    def test_appending_a_further_attempt_still_works(self, seeded) -> None:
        """The trigger must refuse rewrites without refusing the append every
        later arrival depends on."""
        engine = create_engine(seeded)
        try:
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.observation_attempts ("
                        " id, received_at, raw_body_truncated, signature_status,"
                        " eligibility_at_receipt, disposition"
                        ") VALUES (:id, now(), false, 'invalid', 'n/a',"
                        " 'bad_signature')"
                    ),
                    {"id": uuid.uuid4()},
                )
        finally:
            engine.dispose()

    def test_a_rollout_attempt_cannot_be_rewritten(self, migrated_scratch) -> None:
        """An attempt log that can be tidied is a log that will be, and the
        tidying always removes the attempt that explains the outage."""
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
                plan_id, rollout_id = uuid.uuid4(), uuid.uuid4()
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.deployment_plans ("
                        " id, target_id, sequence, status, desired_revision,"
                        " plan_digest, requires_approval, record_version"
                        ") VALUES (:id, :tid, 1, 'approved', 1, :digest, false, 1)"
                    ),
                    {"id": plan_id, "tid": target_id, "digest": uuid.uuid4().hex},
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.rollouts ("
                        " id, rollout_ref, target_id, plan_id, status,"
                        " record_version"
                        ") VALUES (:id, :ref, :tid, :pid, 'dispatched', 1)"
                    ),
                    {
                        "id": rollout_id,
                        "ref": f"rol-{uuid.uuid4().hex[:8]}",
                        "tid": target_id,
                        "pid": plan_id,
                    },
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.rollout_attempts ("
                        " id, rollout_id, attempt_no, outcome"
                        ") VALUES (:id, :rid, 1, 'failed')"
                    ),
                    {"id": uuid.uuid4(), "rid": rollout_id},
                )
            with engine.begin() as conn, pytest.raises(DBAPIError, match="append-only"):
                conn.execute(
                    text("UPDATE mod_deploy.rollout_attempts SET outcome = 'succeeded'")
                )
        finally:
            engine.dispose()


# ── Constraints hold against raw SQL ────────────────────────────────────────


class TestTheConstraintsHoldWithoutTheService:
    @pytest.fixture
    def admin_url(self, migrated_scratch) -> str:
        return migrated_scratch[0]

    def test_a_duplicate_target_ref_is_refused(self, admin_url: str) -> None:
        engine = create_engine(admin_url)
        ref = f"tgt-{uuid.uuid4().hex[:10]}"
        try:
            with engine.begin() as conn:
                _insert_target(conn, ref=ref)
            with engine.begin() as conn, pytest.raises(DBAPIError):
                _insert_target(conn, ref=ref)
        finally:
            engine.dispose()

    def test_two_credentials_cannot_share_a_fingerprint(self, admin_url: str) -> None:
        """The fingerprint is over the DECODED key bytes precisely so two
        spellings of one key cannot enrol separately."""
        engine = create_engine(admin_url)
        fingerprint = f"sha256:{uuid.uuid4().hex}"
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.target_credentials ("
                        " id, target_id, key_id, public_key_b64,"
                        " public_key_fingerprint, status, enrollment_authority"
                        ") VALUES (:id, :tid, :kid, 'AAAA', :fp, 'pending',"
                        " 'policy')"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "tid": target_id,
                        "kid": f"k-{uuid.uuid4().hex[:8]}",
                        "fp": fingerprint,
                    },
                )
            with engine.begin() as conn, pytest.raises(DBAPIError):
                target_id = _insert_target(conn)
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.target_credentials ("
                        " id, target_id, key_id, public_key_b64,"
                        " public_key_fingerprint, status, enrollment_authority"
                        ") VALUES (:id, :tid, :kid, 'BBBB', :fp, 'pending',"
                        " 'policy')"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "tid": target_id,
                        "kid": f"k-{uuid.uuid4().hex[:8]}",
                        "fp": fingerprint,
                    },
                )
        finally:
            engine.dispose()

    def test_two_plans_cannot_share_a_digest(self, admin_url: str) -> None:
        """Two approvals could otherwise bind to one snapshot, which is exactly
        the ambiguity the digest exists to remove."""
        engine = create_engine(admin_url)
        digest = uuid.uuid4().hex
        try:
            for expectation in (None, DBAPIError):
                context = (
                    pytest.raises(expectation) if expectation else _NoExceptionContext()
                )
                with context, engine.begin() as conn:
                    target_id = _insert_target(conn)
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.deployment_plans ("
                            " id, target_id, sequence, status, desired_revision,"
                            " plan_digest, requires_approval, record_version"
                            ") VALUES (:id, :tid, 1, 'proposed', 1, :digest,"
                            " true, 1)"
                        ),
                        {"id": uuid.uuid4(), "tid": target_id, "digest": digest},
                    )
        finally:
            engine.dispose()

    def test_a_receipt_key_is_scoped_to_the_proven_identity(
        self, admin_url: str
    ) -> None:
        """One target's `report_id` must never collide with another's."""
        engine = create_engine(admin_url)
        report_id = f"rep-{uuid.uuid4().hex[:8]}"
        try:
            with engine.begin() as conn:
                for ref in ("tgt-a", "tgt-b"):
                    conn.execute(
                        text(
                            "INSERT INTO mod_deploy.observation_receipts ("
                            " id, authenticated_target_ref, report_id, key_id,"
                            " first_received_at, original_verdict"
                            ") VALUES (:id, :ref, :rep, 'k1', now(), 'accepted')"
                        ),
                        {"id": uuid.uuid4(), "ref": ref, "rep": report_id},
                    )
            with engine.begin() as conn, pytest.raises(DBAPIError):
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.observation_receipts ("
                        " id, authenticated_target_ref, report_id, key_id,"
                        " first_received_at, original_verdict"
                        ") VALUES (:id, 'tgt-a', :rep, 'k1', now(), 'accepted')"
                    ),
                    {"id": uuid.uuid4(), "rep": report_id},
                )
        finally:
            engine.dispose()

    def test_a_non_positive_attempt_number_is_refused(self, admin_url: str) -> None:
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError):
                target_id = _insert_target(conn)
                plan_id, rollout_id = uuid.uuid4(), uuid.uuid4()
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.deployment_plans ("
                        " id, target_id, sequence, status, desired_revision,"
                        " plan_digest, requires_approval, record_version"
                        ") VALUES (:id, :tid, 1, 'approved', 1, :digest, false, 1)"
                    ),
                    {"id": plan_id, "tid": target_id, "digest": uuid.uuid4().hex},
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.rollouts ("
                        " id, rollout_ref, target_id, plan_id, status,"
                        " record_version"
                        ") VALUES (:id, :ref, :tid, :pid, 'requested', 1)"
                    ),
                    {
                        "id": rollout_id,
                        "ref": f"rol-{uuid.uuid4().hex[:8]}",
                        "tid": target_id,
                        "pid": plan_id,
                    },
                )
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.rollout_attempts ("
                        " id, rollout_id, attempt_no, outcome"
                        ") VALUES (:id, :rid, 0, 'pending')"
                    ),
                    {"id": uuid.uuid4(), "rid": rollout_id},
                )
        finally:
            engine.dispose()


class _NoExceptionContext:
    """`pytest.raises`'s shape for the "must succeed" half of a paired test."""

    def __enter__(self) -> None:
        return None

    def __exit__(self, *exc_info: object) -> bool:
        return False
