"""Postgres proof for `mod_deploy`: migration, grants, isolation, append-only.

Provisions its own scratch database and composes the module's lineage explicitly,
because the reference assembly deliberately does not compose
`dotmac-deployment-control`: a module that decides what a FLEET should run cannot
live inside one of the deployments it decides about (ADR-0057 § 7).

Beyond the usual platform-plane proofs, this file carries three proofs the V6
source design earned and this port must not lose:

1. **The claim/proof separation holds against RAW SQL**, not only against the
   service. Both CHECK constraints are exercised directly.
2. **Concurrent arrivals are serialized on the target.** The waiter is observed
   blocked on the real PostgreSQL row lock before the winner is released; this
   proves replay, revocation and monotonic projection against production lock
   semantics rather than relying on thread timing.
3. **`app_admin` cannot rewrite an attempt or a receipt.** A rewritable tripwire
   is decoration, and a rewritable `original_verdict` lets an at-least-once
   transport be made to look like a state change.

Requires real Postgres (`make test-db-up` / `make test-integration`).
"""

from __future__ import annotations

import json
import os
import threading
import time
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime
from pathlib import Path

import pytest
from dotmac_kernel.audit_actions import (
    AuditActionRegistry,
    AuditActionsNotInstalledError,
    active_audit_actions,
    install_audit_actions,
)
from dotmac_kernel.database_catalog_comparator import (
    observe_postgres_tables_columns,
    verify_module_database_catalog,
)
from dotmac_kernel.migrations import versions_dir as kernel_versions_dir
from dotmac_kernel.product_database_catalog import (
    ComposedDatabaseLineageHeadV1,
    DatabaseCatalogOwnerKind,
    DatabaseCatalogOwnerV1,
)
from sqlalchemy import create_engine, event, select, text
from sqlalchemy.engine import Engine
from sqlalchemy.exc import DBAPIError, ProgrammingError
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    ApprovalEvidence,
    ApprovePlanCommand,
    AuthorizationEnvelopeDigestV1,
    AuthorizationEnvelopeV2,
    CredentialTransitionCommand,
    DesiredDeployment,
    EnrolCredentialCommand,
    ObservationAttempt,
    ObservationDisposition,
    ObservationReceipt,
    ObservationVerdict,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    RevokePlanApprovalCommand,
    RuntimeIdentityV1,
    SetDesiredStateCommand,
    activate_credential,
    approve_plan,
    build_database_catalog_snapshot,
    dispatch_attempt,
    enrol_credential,
    issue_execution_observation_envelope,
    module,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    revoke_credential,
    revoke_plan_approval,
    set_desired_state,
    spec_digest,
)
from dotmac_deployment_control import versions_dir as deploy_versions_dir
from dotmac_deployment_control.models import (
    DeploymentPlan,
    DeploymentTarget,
    Rollout,
    RolloutAttempt,
    TargetCredential,
)
from tests.authorization_support import SIGNER, VERIFIER
from tests.dispatch_support import DISPATCH_SIGNER
from tests.execution_observation_support import (
    OBSERVATION_VERIFIER,
    TestExecutionObservationSigner,
    observation_public_key_b64,
)

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── SECOND CHANGE, 2026-09-01 — `dc_0003`'s binding, recorded not absorbed ───
#
# `observation_race` now seeds a bound plan and rollout, and the two racing
# reports carry `rollout_ref` / `operation` / `execution_plan_digest`. Not
# cosmetic: since `dc_0003` an accepted observation must bind the same execution
# plan and operation across proposal, authorization and report, so an unbound
# report is quarantined BEFORE the canonical-receipt lookup — and this test's
# `assert len(gate.thread_ids) == 2` is exactly the guard that catches a race
# which stopped racing. It caught it. Recorded here rather than absorbed,
# because this file's whole value is that its provenance is legible.
#
# ── ADAPTED AT EXTRACTION, 2026-08-29 — the first change to this file ────────
#
# In the repository this test came from, all three lineages were directories in
# the same tree. Here the kernel and this module are INSTALLED packages, so the
# paths are asked of the packages rather than assumed of the checkout. Every
# other line of this 1,001-line canary was byte-identical to the source at
# extraction; the block above records the one later change.
#
# `ASSEMBLY_VERSIONS` is GONE, and its absence changes what this test proves:
# the scratch database is now built from kernel + `mod_deploy` alone, with no
# host assembly present. That is a narrower estate than the original and, for a
# repository whose module must stand on its own, the more faithful one — the
# module's declared prerequisites (`idempotency_ledger.v1`, `platform_audit_log.v1`)
# are both the KERNEL's, and the file's own docstring notes the reference
# assembly deliberately does not compose this module. It is still a change to a
# preserved test surface and is recorded as one rather than absorbed silently.
KERNEL_VERSIONS = Path(kernel_versions_dir())
DEPLOY_VERSIONS = Path(deploy_versions_dir())

#: A stand-in for the Deployment Foundation's `ExecutionPlanDigestV1`. Written
#: out and never computed: an accepted observation now has to BIND to an
#: authorization, and Control cannot derive this value — deriving it in a
#: fixture would exercise a capability the module deliberately does not have.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32

SCHEMA = "mod_deploy"
TABLES = (
    "deployment_targets",
    "target_credentials",
    "deployment_plans",
    "rollouts",
    "rollout_attempts",
    "observation_receipts",
    "observation_attempts",
    "recovery_grants",
)
EVIDENCE_TABLES = ("rollout_attempts", "observation_attempts", "observation_receipts")
MUTABLE_TABLES = (
    "deployment_targets",
    "target_credentials",
    "deployment_plans",
    "rollouts",
    # Revocation UPDATEs a grant in place; it does not delete one. The row is
    # the record of the withdrawal.
    "recovery_grants",
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
COLUMN_PRIVILEGES = ("SELECT", "INSERT", "UPDATE", "REFERENCES")
DC_0006_COLUMNS = (
    ("deployment_targets", "last_execution_sequence", True),
    ("deployment_targets", "last_execution_attempt_no", True),
    ("deployment_targets", "last_execution_state_digest", True),
    ("target_credentials", "algorithm", True),
    ("target_credentials", "purpose", True),
    ("rollouts", "execution_sequence", True),
    ("observation_receipts", "execution_sequence", False),
    ("observation_receipts", "attempt_no", False),
    ("observation_receipts", "observed_state_digest", False),
)

_OBSERVED_AT = datetime(2026, 8, 21, 12, 0, tzinfo=UTC)


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
            f"{KERNEL_VERSIONS} {DEPLOY_VERSIONS}",
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


def _has_column_privilege(
    url: str, table: str, column: str, privilege: str, *, role: str
) -> bool:
    engine = create_engine(url)
    try:
        with engine.connect() as conn:
            return bool(
                conn.execute(
                    text("SELECT has_column_privilege(:r, :t, :c, :p)"),
                    {
                        "r": role,
                        "t": f"mod_deploy.{table}",
                        "c": column,
                        "p": privilege,
                    },
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


def _insert_plan(conn, target_id: uuid.UUID) -> uuid.UUID:  # type: ignore[no-untyped-def]
    plan_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO mod_deploy.deployment_plans ("
            " id, target_id, sequence, status, desired_revision,"
            " plan_digest, requires_approval, record_version"
            ") VALUES (:id, :tid, 1, 'approved', 1, :digest, false, 1)"
        ),
        {"id": plan_id, "tid": target_id, "digest": uuid.uuid4().hex},
    )
    return plan_id


def _insert_rollout(
    conn,
    target_id: uuid.UUID,
    plan_id: uuid.UUID,
    *,
    execution_sequence: int | None,
    authorization_envelope: dict[str, object] | None = None,
) -> uuid.UUID:  # type: ignore[no-untyped-def]
    rollout_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO mod_deploy.rollouts ("
            " id, rollout_ref, target_id, plan_id, status, record_version,"
            " authorization_envelope, execution_sequence"
            ") VALUES (:id, :ref, :tid, :pid, 'requested', 1,"
            " CAST(:auth AS jsonb), :sequence)"
        ),
        {
            "id": rollout_id,
            "ref": f"rol-{uuid.uuid4().hex[:8]}",
            "tid": target_id,
            "pid": plan_id,
            "auth": (
                json.dumps(authorization_envelope)
                if authorization_envelope is not None
                else None
            ),
            "sequence": execution_sequence,
        },
    )
    return rollout_id


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

    def test_source_owned_catalogue_equals_the_clean_room_migration_result(
        self, migrated_scratch
    ) -> None:
        """The declaration is authored from migrations and checked against them.

        This scratch catalogue is evidence about the checked-in lineage, never
        an authoring input and never a substitute for the declaration.
        """
        admin_url, _, _ = migrated_scratch
        engine = create_engine(admin_url)
        try:
            with engine.connect() as conn:
                observation = observe_postgres_tables_columns(
                    conn,
                    schemas=(SCHEMA,),
                )
        finally:
            engine.dispose()

        snapshot = build_database_catalog_snapshot(
            distribution_version=module.version,
            composed_lineage_head=ComposedDatabaseLineageHeadV1(
                owner=DatabaseCatalogOwnerV1(
                    kind=DatabaseCatalogOwnerKind.MODULE,
                    code=module.code,
                ),
                revision="dc_0008_recovery_grants",
            ),
        )
        comparison = verify_module_database_catalog(
            declaration_bytes=snapshot.to_json_bytes(),
            declaration_digest=snapshot.digest,
            observation_bytes=observation.to_json_bytes(),
            observation_digest=observation.digest,
        )

        assert comparison.matched
        assert comparison.drifts == ()
        assert comparison.declaration_digest == snapshot.digest
        assert comparison.observation_digest == observation.digest

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


def test_the_head_downgrades_to_the_exact_dc_0005_extent() -> None:
    """The reverse path removes every post-`dc_0005` fact, then reapplies.

    Named for the invariant rather than for whichever revision is head. It
    was `test_dc_0007_...` and went one revision stale the moment `dc_0008`
    landed -- the same way `test_the_set_is_exactly_two` did, and the same
    fix: a name that states the relationship survives the next revision, a
    name that states a number is wrong silently.

    The head extent is 133 columns across eight tables; `dc_0005` is 105.
    `dc_0008` drops `recovery_grants` entirely on the way down, so the
    difference is the whole table rather than a column count drifting.
    """
    from alembic import command
    from alembic.config import Config

    superuser = _superuser_url()
    name = f"deploy_down_{uuid.uuid4().hex[:10]}"
    server = create_engine(superuser, isolation_level="AUTOCOMMIT")
    previous_migration_url = os.environ.get("MIGRATION_DATABASE_URL")
    with server.connect() as conn:
        conn.execute(text(f'CREATE DATABASE "{name}"'))
    setup = create_engine(_url_for(superuser, name), isolation_level="AUTOCOMMIT")
    try:
        with setup.connect() as conn:
            conn.execute(text("ALTER SCHEMA public OWNER TO app_admin"))
            conn.execute(text(f'GRANT CREATE ON DATABASE "{name}" TO app_admin'))
        admin_url = _url_for(superuser, name, user="app_admin")
        cfg = Config(str(REPO_ROOT / "alembic.ini"))
        cfg.set_main_option("script_location", str(REPO_ROOT / "alembic"))
        cfg.set_main_option("version_locations", f"{KERNEL_VERSIONS} {DEPLOY_VERSIONS}")
        os.environ["MIGRATION_DATABASE_URL"] = admin_url
        command.upgrade(cfg, "heads")
        admin = create_engine(admin_url)
        try:
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT count(*) FROM information_schema.columns "
                            "WHERE table_schema = 'mod_deploy'"
                        )
                    ).scalar_one()
                    == 133
                )
            command.downgrade(cfg, "dc_0005_portable_authorization")
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT count(*) FROM information_schema.columns "
                            "WHERE table_schema = 'mod_deploy'"
                        )
                    ).scalar_one()
                    == 105
                )
                remaining = conn.execute(
                    text(
                        "SELECT table_name, column_name "
                        "FROM information_schema.columns "
                        "WHERE table_schema = 'mod_deploy' AND ("
                        " (table_name, column_name) IN ("
                        "  ('deployment_targets', 'last_execution_sequence'),"
                        "  ('deployment_targets', 'last_execution_attempt_no'),"
                        "  ('deployment_targets', 'last_execution_state_digest'),"
                        "  ('target_credentials', 'algorithm'),"
                        "  ('target_credentials', 'purpose'),"
                        "  ('rollouts', 'execution_sequence'),"
                        "  ('observation_receipts', 'execution_sequence'),"
                        "  ('observation_receipts', 'attempt_no'),"
                        "  ('observation_receipts', 'observed_state_digest'),"
                        "  ('rollout_attempts', 'dispatch_envelope')))"
                    )
                ).all()
                assert remaining == []
                assert (
                    conn.execute(
                        text(
                            "SELECT to_regprocedure("
                            "'mod_deploy.refuse_rollout_issuance_rewrite()')"
                        )
                    ).scalar_one()
                    is None
                )
            command.upgrade(cfg, "heads")
            with admin.connect() as conn:
                assert (
                    conn.execute(
                        text(
                            "SELECT count(*) FROM information_schema.columns "
                            "WHERE table_schema = 'mod_deploy'"
                        )
                    ).scalar_one()
                    == 133
                )
        finally:
            admin.dispose()
    finally:
        if previous_migration_url is None:
            os.environ.pop("MIGRATION_DATABASE_URL", None)
        else:
            os.environ["MIGRATION_DATABASE_URL"] = previous_migration_url
        setup.dispose()
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

    @pytest.mark.parametrize(("table", "column", "_mutable"), DC_0006_COLUMNS)
    @pytest.mark.parametrize("privilege", COLUMN_PRIVILEGES)
    def test_app_user_has_no_privilege_on_any_dc_0006_column(
        self,
        migrated_scratch,
        table: str,
        column: str,
        _mutable: bool,
        privilege: str,
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert not _has_column_privilege(
            admin_url, table, column, privilege, role="app_user"
        )


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

    @pytest.mark.parametrize(("table", "column", "mutable"), DC_0006_COLUMNS)
    def test_dc_0006_columns_keep_the_intended_effective_privileges(
        self,
        migrated_scratch,
        table: str,
        column: str,
        mutable: bool,
    ) -> None:
        admin_url, _, _ = migrated_scratch
        assert _has_column_privilege(
            admin_url, table, column, "SELECT", role="platform_api"
        )
        assert _has_column_privilege(
            admin_url, table, column, "INSERT", role="platform_api"
        )
        assert (
            _has_column_privilege(
                admin_url, table, column, "UPDATE", role="platform_api"
            )
            is mutable
        )


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


# ── Stable verdict under a genuinely contended first arrival ───────────────


class _TargetLockGate:
    """Place both workers at the target-row serialization boundary.

    dc_0006 deliberately makes the old "both saw no receipt" race impossible:
    the target is locked before the canonical-receipt lookup.  This barrier runs
    immediately before each worker issues that production ``FOR UPDATE`` query;
    after both arrive, PostgreSQL admits one and blocks the other until commit.
    """

    def __init__(self) -> None:
        self.barrier = threading.Barrier(2)
        self.lock = threading.Lock()
        self.thread_ids: set[int] = set()

    def before_cursor_execute(
        self,
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalised = " ".join(statement.lower().split())
        if (
            "from mod_deploy.deployment_targets" not in normalised
            or "for update" not in normalised
        ):
            return
        thread_id = threading.get_ident()
        with self.lock:
            if thread_id in self.thread_ids:
                return
            self.thread_ids.add(thread_id)
        self.barrier.wait(timeout=30)


class _HoldOneTargetLock:
    """Pause one named worker after PostgreSQL grants the target row lock."""

    def __init__(self) -> None:
        self.holder_thread_id: int | None = None
        self.acquired = threading.Event()
        self.release = threading.Event()

    def after_cursor_execute(
        self,
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        if threading.get_ident() != self.holder_thread_id:
            return
        normalised = " ".join(statement.lower().split())
        if (
            "from mod_deploy.deployment_targets" not in normalised
            or "for update" not in normalised
        ):
            return
        self.acquired.set()
        if not self.release.wait(timeout=30):
            raise AssertionError("the target-lock holder was never released")


def _wait_until_postgres_reports_lock(engine: Engine, backend_pid: int) -> None:
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        with engine.connect() as conn:
            wait_type = conn.execute(
                text(
                    "SELECT wait_event_type FROM pg_stat_activity " "WHERE pid = :pid"
                ),
                {"pid": backend_pid},
            ).scalar_one_or_none()
        if wait_type == "Lock":
            return
        time.sleep(0.02)
    raise AssertionError(
        f"PostgreSQL never reported backend {backend_pid} waiting on a lock"
    )


@pytest.fixture
def _module_audit_actions() -> Iterator[None]:
    """Install this standalone module's vocabulary without leaking process state."""
    try:
        previous_audit_actions = active_audit_actions()
    except AuditActionsNotInstalledError:
        previous_audit_actions = None
    install_audit_actions(AuditActionRegistry.from_manifests([module]))
    try:
        yield
    finally:
        if previous_audit_actions is not None:
            install_audit_actions(previous_audit_actions)


@pytest.fixture
def observation_race(
    migrated_scratch: tuple[str, str, str],
    _module_audit_actions: None,
) -> Iterator[tuple[Engine, str, str, str]]:
    """One target with an active credential AND a bound, dispatchable rollout.

    The rollout is new since `dc_0003`. An accepted observation is now a
    three-party fact — proposal, authorization and report must bind the same
    execution plan and operation — so a report with nothing to bind against is
    quarantined `unbound_report` and never reaches the canonical-receipt lookup
    this race exists to force. Without it the gate below observes zero absent
    lookups and the concurrency obligation goes untested while the suite reports
    green.
    """
    admin_url, _, _ = migrated_scratch
    engine = create_engine(admin_url, future=True)
    suffix = uuid.uuid4().hex[:10]
    target_ref = f"race-target-{suffix}"
    key_id = f"race-key-{suffix}"
    with Session(engine) as db:
        target = register_target(
            db,
            RegisterTargetCommand(
                command_id=f"seed-target-{suffix}",
                target_ref=target_ref,
                subject_ref=f"subject-{suffix}",
                product_code="dotmac_sub",
                environment="production",
            ),
        )
        credential_id = enrol_credential(
            db,
            EnrolCredentialCommand(
                command_id=f"seed-key-{suffix}",
                target_id=target.id,
                key_id=key_id,
                algorithm="test-sha256",
                public_key_b64=observation_public_key_b64(key_id),
                enrollment_authority="platform_admin_policy",
            ),
        )
        activate_credential(
            db,
            CredentialTransitionCommand(
                command_id=f"activate-key-{suffix}",
                credential_id=credential_id,
            ),
        )
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=f"seed-desired-{suffix}",
                target_id=target.id,
                desired=DesiredDeployment(
                    release_ref="dotmac_sub@1", spec={"replicas": 2}, images=[]
                ),
            ),
        )
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=f"seed-plan-{suffix}",
                target_id=target.id,
                operation="deploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_EXECUTION_PLAN,
                requires_approval=True,
                approval_policy_code="deployment.production",
                approval_policy_version=1,
            ),
        )
        approve_plan(
            db,
            ApprovePlanCommand(
                command_id=f"approve-plan-{suffix}",
                plan_id=plan.id,
                evidence=ApprovalEvidence(
                    policy_code="deployment.production",
                    policy_version=1,
                    decision_ref=f"decision-{suffix}",
                    content_digest=plan.plan_digest or "",
                    decided_at=datetime.now(UTC),
                    operation="deploy",
                    execution_plan_digest=_EXECUTION_PLAN,
                    decision_status="granted",
                ),
            ),
        )
        rollout_ref = f"race-rollout-{suffix}"
        rollout = request_rollout(
            db,
            RequestRolloutCommand(
                command_id=f"seed-rollout-{suffix}",
                rollout_ref=rollout_ref,
                plan_id=plan.id,
                authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            ),
            signer=SIGNER,
        )
        dispatch_attempt(
            db,
            command_id=f"seed-dispatch-{suffix}",
            rollout_id=rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        db.commit()
    try:
        yield engine, target_ref, key_id, rollout_ref
    finally:
        engine.dispose()


def _record_race_observation(
    db: Session,
    *,
    target_ref: str,
    key_id: str,
    rollout_ref: str,
    report_id: str,
    observed_revision: str,
) -> ObservationVerdict:
    rollout = db.execute(
        select(Rollout).where(Rollout.rollout_ref == rollout_ref)
    ).scalar_one()
    plan = db.get(DeploymentPlan, rollout.plan_id)
    target = db.execute(
        select(DeploymentTarget).where(DeploymentTarget.target_ref == target_ref)
    ).scalar_one()
    assert plan is not None
    snapshot = dict(plan.snapshot or {})
    authorization = AuthorizationEnvelopeV2.parse(rollout.authorization_envelope)
    attempt = db.execute(
        select(RolloutAttempt).where(RolloutAttempt.rollout_id == rollout.id)
    ).scalar_one()
    observed_at = _OBSERVED_AT
    envelope = issue_execution_observation_envelope(
        {
            "report_id": report_id,
            "authorization_id": str(rollout.id),
            "authorization_plan_id": authorization.statement.plan_id,
            "authorization_control_version": authorization.statement.control_version,
            "authorization_envelope_digest": (
                AuthorizationEnvelopeDigestV1.over_bytes(
                    authorization.canonical_bytes
                ).canonical
            ),
            "execution_sequence": authorization.statement.execution_sequence,
            "attempt_no": attempt.attempt_no,
            "rollout_ref": rollout_ref,
            "target_id": str(target.id),
            "target_ref": target_ref,
            "product_code": target.product_code,
            "environment": target.environment,
            "operation": "deploy",
            "release_ref": "dotmac_sub@1",
            "observed_release_ref": "dotmac_sub@1",
            "authorized_images": [],
            "observed_images": [],
            "plan_digest": plan.plan_digest,
            "descriptor_digest": snapshot["descriptor_digest"],
            "execution_plan_digest": _EXECUTION_PLAN,
            "observed_spec_digest": spec_digest({"replicas": 2}),
            "observed_revision": observed_revision,
            "runtime_identity": RuntimeIdentityV1(
                kind="oci_container", identifier="container:race"
            ),
            "outcome": "succeeded",
            "observed_at": observed_at,
        },
        signer=TestExecutionObservationSigner(key_id),
    )
    return record_observation(
        db,
        RecordObservationCommand(
            command_id=f"arrival-{uuid.uuid4()}",
            observation=envelope.canonical_bytes,
        ),
        observation_verifier=OBSERVATION_VERIFIER,
        authorization_verifier=VERIFIER,
    )


@pytest.mark.parametrize(
    ("second_digest", "loser_disposition"),
    [
        pytest.param(
            "sha256:first", ObservationDisposition.IDEMPOTENT_REPLAY.value, id="replay"
        ),
        pytest.param(
            "sha256:second", ObservationDisposition.CONFLICT.value, id="conflict"
        ),
    ],
)
def test_concurrent_first_arrivals_keep_one_receipt_and_the_winners_verdict(
    observation_race: tuple[Engine, str, str, str],
    second_digest: str,
    loser_disposition: str,
) -> None:
    """The Vendor V6 concurrency obligation, driven through the real service.

    Both workers observe the receipt as absent. Exactly one may establish it;
    the loser must retain its attempt, point at the winner, and return that
    receipt's original verdict instead of leaking an IntegrityError or deciding
    the observation again.
    """
    engine, target_ref, key_id, rollout_ref = observation_race
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    gate = _TargetLockGate()
    event.listen(engine, "before_cursor_execute", gate.before_cursor_execute)
    report_id = f"report-{uuid.uuid4().hex[:10]}"
    results: dict[int, ObservationVerdict] = {}
    errors: dict[int, BaseException] = {}

    def worker(index: int, digest: str) -> None:
        db = sessions()
        try:
            results[index] = _record_race_observation(
                db,
                target_ref=target_ref,
                key_id=key_id,
                rollout_ref=rollout_ref,
                report_id=report_id,
                observed_revision=digest,
            )
            db.commit()
        except BaseException as exc:
            errors[index] = exc
            db.rollback()
        finally:
            db.close()

    threads = (
        threading.Thread(target=worker, args=(0, "sha256:first")),
        threading.Thread(target=worker, args=(1, second_digest)),
    )
    try:
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=60)
            assert not thread.is_alive(), "the receipt race deadlocked"
    finally:
        event.remove(engine, "before_cursor_execute", gate.before_cursor_execute)

    if errors:
        raise next(iter(errors.values()))
    assert len(gate.thread_ids) == 2, "the test never forced target-lock contention"
    dispositions = {result.disposition for result in results.values()}
    assert dispositions == {
        ObservationDisposition.ACCEPTED.value,
        loser_disposition,
    }
    loser = next(
        result for result in results.values() if result.disposition == loser_disposition
    )
    assert loser.changed_state is False
    assert loser.verdict == ObservationDisposition.ACCEPTED.value

    with Session(engine) as db:
        receipts = tuple(
            db.execute(
                select(ObservationReceipt).where(
                    ObservationReceipt.authenticated_target_ref == target_ref,
                    ObservationReceipt.report_id == report_id,
                )
            ).scalars()
        )
        attempts = tuple(
            db.execute(
                select(ObservationAttempt).where(
                    ObservationAttempt.authenticated_target_ref == target_ref,
                    ObservationAttempt.report_id == report_id,
                )
            ).scalars()
        )
    assert len(receipts) == 1
    assert len(attempts) == 2
    assert {attempt.receipt_id for attempt in attempts} == {receipts[0].id}
    assert receipts[0].original_verdict == ObservationDisposition.ACCEPTED.value


@pytest.mark.parametrize(
    ("revocation_kind", "first_operation", "expected_disposition", "has_receipt"),
    [
        pytest.param(
            "plan",
            "observation",
            ObservationDisposition.ACCEPTED.value,
            True,
            id="plan-admission-first",
        ),
        pytest.param(
            "plan",
            "revocation",
            ObservationDisposition.AUTHORIZATION_REVOKED.value,
            True,
            id="plan-revocation-first",
        ),
        pytest.param(
            "credential",
            "observation",
            ObservationDisposition.ACCEPTED.value,
            True,
            id="credential-admission-first",
        ),
        pytest.param(
            "credential",
            "revocation",
            ObservationDisposition.NOT_ELIGIBLE.value,
            False,
            id="credential-revocation-first",
        ),
    ],
)
def test_admission_and_revocation_linearize_on_the_target_lock(
    observation_race: tuple[Engine, str, str, str],
    revocation_kind: str,
    first_operation: str,
    expected_disposition: str,
    has_receipt: bool,
) -> None:
    """Four real two-session schedules, with PostgreSQL proving contention.

    The trusted timestamps are captured at each service entry. The target lock
    then makes the rows coherent without rewriting that arrival order:
    admission-first may finish, while revoke-first is refused.
    """
    engine, target_ref, key_id, rollout_ref = observation_race
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with Session(engine) as lookup:
        rollout = lookup.execute(
            select(Rollout).where(Rollout.rollout_ref == rollout_ref)
        ).scalar_one()
        plan_id = rollout.plan_id
        credential_id = lookup.execute(
            select(TargetCredential.id).where(TargetCredential.key_id == key_id)
        ).scalar_one()

    gate = _HoldOneTargetLock()
    event.listen(engine, "after_cursor_execute", gate.after_cursor_execute)
    result: dict[str, ObservationVerdict] = {}
    errors: dict[str, BaseException] = {}
    backend_pids: dict[str, int] = {}

    def observe_worker() -> None:
        db = sessions()
        gate.holder_thread_id = (
            threading.get_ident()
            if first_operation == "observation"
            else gate.holder_thread_id
        )
        try:
            backend_pids["observation"] = int(
                db.execute(text("SELECT pg_backend_pid() ")).scalar_one()
            )
            result["observation"] = _record_race_observation(
                db,
                target_ref=target_ref,
                key_id=key_id,
                rollout_ref=rollout_ref,
                report_id=f"race-{revocation_kind}-{first_operation}",
                observed_revision="git:race",
            )
            db.commit()
        except BaseException as exc:
            errors["observation"] = exc
            db.rollback()
        finally:
            db.close()

    def revoke_worker() -> None:
        db = sessions()
        gate.holder_thread_id = (
            threading.get_ident()
            if first_operation == "revocation"
            else gate.holder_thread_id
        )
        try:
            backend_pids["revocation"] = int(
                db.execute(text("SELECT pg_backend_pid() ")).scalar_one()
            )
            if revocation_kind == "plan":
                revoke_plan_approval(
                    db,
                    RevokePlanApprovalCommand(
                        command_id=f"revoke-plan-{uuid.uuid4()}",
                        plan_id=plan_id,
                        revocation_ref=f"decision-{uuid.uuid4()}",
                    ),
                )
            else:
                revoke_credential(
                    db,
                    CredentialTransitionCommand(
                        command_id=f"revoke-key-{uuid.uuid4()}",
                        credential_id=credential_id,
                        reason="test revocation",
                    ),
                )
            db.commit()
        except BaseException as exc:
            errors["revocation"] = exc
            db.rollback()
        finally:
            db.close()

    first = observe_worker if first_operation == "observation" else revoke_worker
    second = revoke_worker if first_operation == "observation" else observe_worker
    first_thread = threading.Thread(target=first)
    second_thread = threading.Thread(target=second)
    try:
        first_thread.start()
        assert gate.acquired.wait(timeout=20), "first operation never locked target"
        second_thread.start()
        deadline = time.monotonic() + 10
        second_name = (
            "revocation" if first_operation == "observation" else "observation"
        )
        while second_name not in backend_pids and time.monotonic() < deadline:
            time.sleep(0.01)
        assert second_name in backend_pids, "second operation never opened a backend"
        _wait_until_postgres_reports_lock(engine, backend_pids[second_name])
        gate.release.set()
        for thread in (first_thread, second_thread):
            thread.join(timeout=30)
            assert not thread.is_alive(), "admission/revocation race deadlocked"
    finally:
        gate.release.set()
        event.remove(engine, "after_cursor_execute", gate.after_cursor_execute)

    if errors:
        raise next(iter(errors.values()))
    verdict = result["observation"]
    assert verdict.disposition == expected_disposition
    assert (verdict.receipt_id is not None) is has_receipt


@pytest.mark.parametrize("first_coordinate", ("older", "newer"))
def test_concurrent_execution_coordinates_leave_the_newer_state_authoritative(
    observation_race: tuple[Engine, str, str, str],
    first_coordinate: str,
) -> None:
    """Both lock schedules converge on the higher execution coordinate.

    This is not a thread-timing test: PostgreSQL reports the second backend
    waiting on the target row before the first transaction is released.
    """
    engine, target_ref, key_id, older_rollout_ref = observation_race
    sessions = sessionmaker(bind=engine, autocommit=False, autoflush=False)
    with Session(engine) as db:
        older_rollout = db.execute(
            select(Rollout).where(Rollout.rollout_ref == older_rollout_ref)
        ).scalar_one()
        newer_rollout_ref = f"newer-{uuid.uuid4().hex[:10]}"
        newer_rollout = request_rollout(
            db,
            RequestRolloutCommand(
                command_id=f"request-{newer_rollout_ref}",
                rollout_ref=newer_rollout_ref,
                plan_id=older_rollout.plan_id,
                authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
            ),
            signer=SIGNER,
        )
        dispatch_attempt(
            db,
            command_id=f"dispatch-{newer_rollout_ref}",
            rollout_id=newer_rollout.id,
            verifier=VERIFIER,
            dispatch_signer=DISPATCH_SIGNER,
        )
        target = db.execute(
            select(DeploymentTarget).where(DeploymentTarget.target_ref == target_ref)
        ).scalar_one()
        baseline_version = target.record_version
        db.commit()

    coordinates = {
        "older": (older_rollout_ref, "git:older"),
        "newer": (newer_rollout_ref, "git:newer"),
    }
    second_coordinate = "newer" if first_coordinate == "older" else "older"
    gate = _HoldOneTargetLock()
    event.listen(engine, "after_cursor_execute", gate.after_cursor_execute)
    results: dict[str, ObservationVerdict] = {}
    errors: dict[str, BaseException] = {}
    backend_pids: dict[str, int] = {}

    def worker(coordinate: str, *, hold: bool) -> None:
        db = sessions()
        if hold:
            gate.holder_thread_id = threading.get_ident()
        try:
            backend_pids[coordinate] = int(
                db.execute(text("SELECT pg_backend_pid() ")).scalar_one()
            )
            rollout_ref, observed_revision = coordinates[coordinate]
            results[coordinate] = _record_race_observation(
                db,
                target_ref=target_ref,
                key_id=key_id,
                rollout_ref=rollout_ref,
                report_id=f"report-{coordinate}-{uuid.uuid4().hex[:8]}",
                observed_revision=observed_revision,
            )
            db.commit()
        except BaseException as exc:
            errors[coordinate] = exc
            db.rollback()
        finally:
            db.close()

    first_thread = threading.Thread(
        target=worker, args=(first_coordinate,), kwargs={"hold": True}
    )
    second_thread = threading.Thread(
        target=worker, args=(second_coordinate,), kwargs={"hold": False}
    )
    try:
        first_thread.start()
        assert gate.acquired.wait(timeout=20), "first observation never locked target"
        second_thread.start()
        deadline = time.monotonic() + 10
        while second_coordinate not in backend_pids and time.monotonic() < deadline:
            time.sleep(0.01)
        assert second_coordinate in backend_pids, "second observation has no backend"
        _wait_until_postgres_reports_lock(engine, backend_pids[second_coordinate])
        gate.release.set()
        for thread in (first_thread, second_thread):
            thread.join(timeout=30)
            assert not thread.is_alive(), "execution-coordinate race deadlocked"
    finally:
        gate.release.set()
        event.remove(engine, "after_cursor_execute", gate.after_cursor_execute)

    if errors:
        raise next(iter(errors.values()))
    expected = {
        "older": ObservationDisposition.ACCEPTED.value,
        "newer": ObservationDisposition.ACCEPTED.value,
    }
    if first_coordinate == "newer":
        expected["older"] = ObservationDisposition.STALE_OBSERVATION.value
    assert {name: result.disposition for name, result in results.items()} == expected
    with Session(engine) as db:
        target = db.execute(
            select(DeploymentTarget).where(DeploymentTarget.target_ref == target_ref)
        ).scalar_one()
        assert target.last_execution_sequence == 2
        assert target.last_execution_attempt_no == 1
        assert target.observed_revision == 1
        newer_receipt = db.execute(
            select(ObservationReceipt).where(
                ObservationReceipt.authenticated_target_ref == target_ref,
                ObservationReceipt.execution_sequence == 2,
            )
        ).scalar_one()
        assert target.last_execution_state_digest == newer_receipt.observed_state_digest
        expected_increments = 2 if first_coordinate == "older" else 1
        assert target.record_version == baseline_version + expected_increments


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

    @pytest.mark.parametrize(
        "assignment",
        (
            "last_execution_sequence = 1",
            "last_execution_sequence = 1, last_execution_attempt_no = 1",
            "last_execution_sequence = 0, last_execution_attempt_no = 1, "
            "last_execution_state_digest = 'sha256:00'",
        ),
    )
    def test_a_partial_or_non_positive_target_high_water_is_refused(
        self, admin_url: str, assignment: str
    ) -> None:
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
            with engine.begin() as conn, pytest.raises(DBAPIError):
                conn.execute(
                    text(
                        "UPDATE mod_deploy.deployment_targets SET "
                        f"{assignment} WHERE id = :id"
                    ),
                    {"id": target_id},
                )
        finally:
            engine.dispose()

    @pytest.mark.parametrize(
        ("sequence", "attempt_no", "state_digest"),
        (
            (1, None, None),
            (1, 1, None),
            (0, 1, "sha256:00"),
            (1, 0, "sha256:00"),
        ),
    )
    def test_a_partial_or_non_positive_receipt_coordinate_is_refused(
        self,
        admin_url: str,
        sequence: int | None,
        attempt_no: int | None,
        state_digest: str | None,
    ) -> None:
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn, pytest.raises(DBAPIError):
                conn.execute(
                    text(
                        "INSERT INTO mod_deploy.observation_receipts ("
                        " id, authenticated_target_ref, report_id, key_id,"
                        " first_received_at, original_verdict, execution_sequence,"
                        " attempt_no, observed_state_digest"
                        ") VALUES (:id, 'tgt-raw', :report, 'key-raw', now(),"
                        " 'accepted', :sequence, :attempt_no, :state_digest)"
                    ),
                    {
                        "id": uuid.uuid4(),
                        "report": f"rep-{uuid.uuid4().hex[:8]}",
                        "sequence": sequence,
                        "attempt_no": attempt_no,
                        "state_digest": state_digest,
                    },
                )
        finally:
            engine.dispose()

    def test_rollout_execution_sequence_is_positive_and_unique_per_target(
        self, admin_url: str
    ) -> None:
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
                plan_id = _insert_plan(conn, target_id)
            with engine.begin() as conn, pytest.raises(DBAPIError):
                _insert_rollout(
                    conn,
                    target_id,
                    plan_id,
                    execution_sequence=0,
                )
            with engine.begin() as conn:
                _insert_rollout(
                    conn,
                    target_id,
                    plan_id,
                    execution_sequence=1,
                )
            with engine.begin() as conn, pytest.raises(DBAPIError):
                _insert_rollout(
                    conn,
                    target_id,
                    plan_id,
                    execution_sequence=1,
                )
        finally:
            engine.dispose()

    def test_rollout_issuance_is_immutable_but_lifecycle_may_advance(
        self, admin_url: str
    ) -> None:
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
                plan_id = _insert_plan(conn, target_id)
                rollout_id = _insert_rollout(
                    conn,
                    target_id,
                    plan_id,
                    execution_sequence=1,
                    authorization_envelope={"schema": "AuthorizationEnvelope.v2"},
                )
            with (
                engine.begin() as conn,
                pytest.raises(DBAPIError, match="immutable issuance evidence"),
            ):
                conn.execute(
                    text(
                        "UPDATE mod_deploy.rollouts "
                        "SET authorization_envelope = '{}'::jsonb WHERE id = :id"
                    ),
                    {"id": rollout_id},
                )
            with (
                engine.begin() as conn,
                pytest.raises(DBAPIError, match="immutable issuance evidence"),
            ):
                conn.execute(
                    text(
                        "UPDATE mod_deploy.rollouts "
                        "SET execution_sequence = 2 WHERE id = :id"
                    ),
                    {"id": rollout_id},
                )
            with engine.begin() as conn:
                conn.execute(
                    text(
                        "UPDATE mod_deploy.rollouts "
                        "SET status = 'dispatched' WHERE id = :id"
                    ),
                    {"id": rollout_id},
                )
                assert (
                    conn.execute(
                        text("SELECT status FROM mod_deploy.rollouts WHERE id = :id"),
                        {"id": rollout_id},
                    ).scalar_one()
                    == "dispatched"
                )
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


def _insert_recovery_grant(  # type: ignore[no-untyped-def]
    conn, target_id: uuid.UUID, *, not_before: str, issued_at: str, expires_at: str
) -> uuid.UUID:
    grant_id = uuid.uuid4()
    conn.execute(
        text(
            "INSERT INTO mod_deploy.recovery_grants ("
            " id, grant_id, target_id, product_code, environment,"
            " recovery_execution_plan_digest, recovery_bundle_digest,"
            " incumbent_prestate_digest, grant_envelope,"
            " not_before, issued_at, expires_at, record_version"
            ") VALUES (:id, :grant_id, :target_id, 'dotmac_sub', 'production',"
            " 'sha256:aa', 'sha256:bb', 'sha256:cc', '{}'::jsonb,"
            " :not_before, :issued_at, :expires_at, 1)"
        ),
        {
            "id": grant_id,
            "grant_id": f"g-{grant_id.hex[:10]}",
            "target_id": target_id,
            "not_before": not_before,
            "issued_at": issued_at,
            "expires_at": expires_at,
        },
    )
    return grant_id


class TestTheRecoveryWindowCheckAgreesWithTheType:
    """Two statements of one rule, proved equivalent rather than assumed.

    `RecoveryGrantStatementV1.__post_init__` OWNS the window invariant. The
    `ck_recovery_grants_window` CHECK is a backstop for callers that never
    construct the type -- raw SQL, a repair script, a migration -- and is not a
    second decision, because it cannot reach a different verdict about the same
    predicate.

    It CAN drift, though, and that is the hazard worth a test: relax one half
    and the other refuses rows its partner accepts, surfacing as an opaque
    IntegrityError far from the cause. So the boundary is walked here, in the
    tier where the CHECK actually exists, and the day either half moves this
    fails.
    """

    #: `(not_before, issued_at, expires_at, the type accepts it)`. Each invalid
    #: case sits adjacent to a valid one, because a boundary test that only
    #: samples the middle of each range cannot see an off-by-one.
    WINDOWS = (
        ("2026-09-04T11:55Z", "2026-09-04T12:00Z", "2026-09-04T14:00Z", True),
        # not_before == issued_at is the closed lower bound, and valid.
        ("2026-09-04T12:00Z", "2026-09-04T12:00Z", "2026-09-04T14:00Z", True),
        # issued_at == expires_at is the open upper bound, and is not.
        ("2026-09-04T11:55Z", "2026-09-04T12:00Z", "2026-09-04T12:00Z", False),
        # not_before after issued_at.
        ("2026-09-04T12:01Z", "2026-09-04T12:00Z", "2026-09-04T14:00Z", False),
        # expires_at before not_before, which fails both halves at once.
        ("2026-09-04T12:00Z", "2026-09-04T12:00Z", "2026-09-04T11:00Z", False),
    )

    @pytest.mark.parametrize(
        ("not_before", "issued_at", "expires_at", "accepted"), WINDOWS
    )
    def test_the_database_refuses_exactly_what_the_type_refuses(
        self,
        admin_url: str,
        not_before: str,
        issued_at: str,
        expires_at: str,
        accepted: bool,
    ) -> None:
        from datetime import datetime

        from dotmac_deployment_control.ports import DeploymentControlError
        from dotmac_deployment_control.recovery_grant import RecoveryGrantStatementV1

        def _instant(value: str) -> datetime:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))

        # What the TYPE says about this window.
        try:
            RecoveryGrantStatementV1(
                grant_id="g",
                product_code="dotmac_sub",
                target_id="t",
                target_ref="r",
                environment="production",
                recovery_execution_plan_digest="sha256:aa",
                recovery_bundle_digest="sha256:bb",
                incumbent_prestate_digest="sha256:cc",
                approval_policy_code="p",
                approval_policy_version=1,
                approval_decision_ref="d",
                approval_decision_status="granted",
                approved_at=_instant(not_before),
                not_before=_instant(not_before),
                issued_at=_instant(issued_at),
                expires_at=_instant(expires_at),
                control_version="0.0.0",
                key_id="k",
                algorithm="ed25519",
                public_key_fingerprint="fp",
            )
            type_accepts = True
        except DeploymentControlError:
            type_accepts = False

        assert type_accepts is accepted, (
            "the fixture's own expectation disagrees with the type, so this "
            "comparison would prove nothing"
        )

        # What the DATABASE says about the same window.
        engine = create_engine(admin_url)
        try:
            with engine.begin() as conn:
                target_id = _insert_target(conn)
            if accepted:
                with engine.begin() as conn:
                    _insert_recovery_grant(
                        conn,
                        target_id,
                        not_before=not_before,
                        issued_at=issued_at,
                        expires_at=expires_at,
                    )
            else:
                with engine.begin() as conn, pytest.raises(DBAPIError):
                    _insert_recovery_grant(
                        conn,
                        target_id,
                        not_before=not_before,
                        issued_at=issued_at,
                        expires_at=expires_at,
                    )
        finally:
            engine.dispose()
