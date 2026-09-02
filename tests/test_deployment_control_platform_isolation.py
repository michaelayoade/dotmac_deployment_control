"""Postgres proof for `mod_deploy`: migration, grants, isolation, append-only.

Provisions its own scratch database and composes the module's lineage explicitly,
because the reference assembly deliberately does not compose
`dotmac-deployment-control`: a module that decides what a FLEET should run cannot
live inside one of the deployments it decides about (ADR-0057 § 7).

Beyond the usual platform-plane proofs, this file carries three proofs the V6
source design earned and this port must not lose:

1. **The claim/proof separation holds against RAW SQL**, not only against the
   service. Both CHECK constraints are exercised directly.
2. **Concurrent first arrivals keep one stable verdict.** Both real sessions
   are gated after observing no receipt, so the rehearsal forces the production
   unique-key race rather than relying on thread timing.
3. **`app_admin` cannot rewrite an attempt or a receipt.** A rewritable tripwire
   is decoration, and a rewritable `original_verdict` lets an at-least-once
   transport be made to look like a state change.

Requires real Postgres (`make test-db-up` / `make test-integration`).
"""

from __future__ import annotations

import os
import threading
import uuid
from collections.abc import Iterator
from datetime import UTC, datetime, timedelta
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
    CredentialTransitionCommand,
    DesiredDeployment,
    EnrolCredentialCommand,
    ObservationAttempt,
    ObservationDisposition,
    ObservationReceipt,
    ObservationVerdict,
    ObservedState,
    ProposePlanCommand,
    RecordObservationCommand,
    RegisterTargetCommand,
    RequestRolloutCommand,
    SetDesiredStateCommand,
    SignatureStatus,
    activate_credential,
    build_database_catalog_snapshot,
    enrol_credential,
    module,
    propose_plan,
    record_observation,
    register_target,
    request_rollout,
    set_desired_state,
)
from dotmac_deployment_control import versions_dir as deploy_versions_dir
from tests.authorization_support import SIGNER

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
                revision="dc_0005_portable_authorization",
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


# ── Stable verdict under a genuinely contended first arrival ───────────────


class _ReceiptLookupGate:
    """Hold both workers after their first receipt lookup returned.

    A barrier before the service call is not a concurrency proof: one worker can
    run the entire call and commit before the other reaches the lookup. This
    hook gates the production query *after* both transactions observed no
    receipt, making the unique-constraint race deterministic. Later winner
    lookups are not gated, or the loser would deadlock after its savepoint
    rolls back.
    """

    def __init__(self) -> None:
        self.barrier = threading.Barrier(2)
        self.lock = threading.Lock()
        self.thread_ids: set[int] = set()

    def after_cursor_execute(
        self,
        _conn: object,
        _cursor: object,
        statement: str,
        _parameters: object,
        _context: object,
        _executemany: bool,
    ) -> None:
        normalised = " ".join(statement.lower().split())
        if "from mod_deploy.observation_receipts" not in normalised:
            return
        thread_id = threading.get_ident()
        with self.lock:
            if thread_id in self.thread_ids:
                return
            self.thread_ids.add(thread_id)
        self.barrier.wait(timeout=30)


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
                public_key_b64="AAAA",
                public_key_fingerprint=f"sha256:{suffix}{'0' * (64 - len(suffix))}",
                enrollment_authority="platform_admin_policy",
            ),
        )
        activate_credential(
            db,
            CredentialTransitionCommand(
                command_id=f"activate-key-{suffix}",
                credential_id=credential_id,
                at=_OBSERVED_AT - timedelta(minutes=1),
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
                requires_approval=False,
            ),
        )
        rollout_ref = f"race-rollout-{suffix}"
        request_rollout(
            db,
            RequestRolloutCommand(
                command_id=f"seed-rollout-{suffix}",
                rollout_ref=rollout_ref,
                plan_id=plan.id,
                authorization_expires_at=datetime(2099, 1, 1, tzinfo=UTC),
                authorization_issued_at=_OBSERVED_AT,
            ),
            signer=SIGNER,
        )
        db.commit()
    try:
        yield engine, target_ref, key_id, rollout_ref
    finally:
        engine.dispose()


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
    gate = _ReceiptLookupGate()
    event.listen(engine, "after_cursor_execute", gate.after_cursor_execute)
    report_id = f"report-{uuid.uuid4().hex[:10]}"
    results: dict[int, ObservationVerdict] = {}
    errors: dict[int, BaseException] = {}

    def worker(index: int, digest: str) -> None:
        db = sessions()
        try:
            results[index] = record_observation(
                db,
                RecordObservationCommand(
                    command_id=f"arrival-{index}-{uuid.uuid4()}",
                    received_at=_OBSERVED_AT,
                    observed=ObservedState(
                        report_id=report_id,
                        observed_release_ref="dotmac_sub@1",
                        observed_spec_digest="sha256:spec",
                        reported_at=_OBSERVED_AT,
                        authenticated_target_ref=target_ref,
                        claimed_target_ref=target_ref,
                        key_id=key_id,
                        raw_body=digest.encode(),
                        raw_body_digest=digest,
                        signature_status=SignatureStatus.VALID.value,
                        rollout_ref=rollout_ref,
                        operation="deploy",
                        execution_plan_digest=_EXECUTION_PLAN,
                    ),
                ),
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
        event.remove(engine, "after_cursor_execute", gate.after_cursor_execute)

    if errors:
        raise next(iter(errors.values()))
    assert len(gate.thread_ids) == 2, "the test never forced two absent lookups"
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
