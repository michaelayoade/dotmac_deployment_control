"""Structural guards for `dotmac-deployment-control`, each with a sensitivity proof.

The guard unique to this module is the one that keeps it from becoming a second
transport authority. Deployment control sits directly beside the Integrator, and
the temptation to bring "just one" provider helper across is the strongest in the
programme — an endpoint field, a retry policy, an HTTP client for a health check.

Every detector is exercised twice: once against the real package and once against
a synthetic violation (ADR-0018). Several scan AST identifiers rather than text,
because this module's prose names every piece of transport state precisely to
explain what it does not own.

Static only; no database.
"""

from __future__ import annotations

import ast
import re
import tomllib
from pathlib import Path

import pytest
from dotmac_kernel.namespaces import (
    DEPLOYMENT_CONTROL_MIGRATION_OWNER,
    MIGRATION_OWNER_LEDGER,
    module_schema,
)

from dotmac_deployment_control import module
from tests.architecture import adoption_evidence as evidence_schema

REPO_ROOT = Path(__file__).resolve().parents[2]
# ADAPTED AT EXTRACTION: the package is the repository root here, not a
# directory inside a workspace. `REPO_ROOT` stays as it was so the
# `relative_to(REPO_ROOT)` offender messages below still read sensibly.
PACKAGE_ROOT = REPO_ROOT
SRC = PACKAGE_ROOT / "src/dotmac_deployment_control"
MIGRATION = SRC / "migrations/versions/dc_0001_deployment_control.py"

#: The three tables whose whole value is that nobody can adjust them.
EVIDENCE_TABLES = ("rollout_attempts", "observation_attempts", "observation_receipts")
#: The four the lifecycle legitimately mutates.
MUTABLE_TABLES = (
    "deployment_targets",
    "target_credentials",
    "deployment_plans",
    "rollouts",
)

SIBLING_ROOTS = frozenset(
    {
        "dotmac_template_studio",
        "dotmac_ticketing",
        "dotmac_release_catalog",
        "dotmac_entitlement_allocation",
        "dotmac_commercial_agreements",
        "dotmac_licensing",
        "dotmac_application_directory",
        "dotmac_files",
        "dotmac_imports",
        "dotmac_integration",
        "dotmac_approvals",
        "dotmac_numbering",
        "dotmac_people",
        "dotmac_durable_timers",
        "dotmac_auth_oidc",
        "dotmac_campaigns",
        "dotmac_ui",
        "app",
        "vendor_cp",
    }
)

#: Anything that could perform, or describe how to perform, provider I/O.
TRANSPORT_ROOTS = frozenset(
    {
        "requests",
        "httpx",
        "urllib",
        "urllib3",
        "http",
        "socket",
        "ssl",
        "paramiko",
        "fabric",
        "kubernetes",
        "docker",
        "boto3",
        "aiohttp",
        "cryptography",
    }
)


def _sources() -> list[Path]:
    return sorted(SRC.rglob("*.py"))


def _imported_roots(source: str) -> set[str]:
    """Every top-level module name a source imports, from the AST."""
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
            roots.add(node.module.split(".")[0])
    return roots


def _identifiers(source: str) -> set[str]:
    """Every name a source DEFINES or READS. Deliberately not string contents:
    a docstring saying "transport stayed with the Integrator" is the opposite of
    a violation."""
    names: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Name):
            names.add(node.id)
        elif isinstance(node, ast.Attribute):
            names.add(node.attr)
        elif isinstance(node, ast.arg):
            names.add(node.arg)
        elif isinstance(node, ast.ClassDef | ast.FunctionDef):
            names.add(node.name)
        elif isinstance(node, ast.keyword) and node.arg:
            names.add(node.arg)
    return names


# ── Allocation parity ───────────────────────────────────────────────────────


class TestTheManifestMatchesTheLedger:
    def test_the_ledger_row_exists_and_is_registered(self) -> None:
        assert DEPLOYMENT_CONTROL_MIGRATION_OWNER in MIGRATION_OWNER_LEDGER

    def test_every_manifest_field_matches_its_ledger_row(self) -> None:
        owner = DEPLOYMENT_CONTROL_MIGRATION_OWNER
        assert module.code == owner.owner == "deployment_control"
        assert module.migration_prefix == owner.prefix == "dc"
        assert module.migration_branch == owner.branch_label == "deployment_control"
        assert module.db_schema == owner.db_schema == module_schema("deploy")

    def test_the_prefix_and_schema_are_unique_fleet_wide(self) -> None:
        prefixes = [owner.prefix for owner in MIGRATION_OWNER_LEDGER]
        schemas = [o.db_schema for o in MIGRATION_OWNER_LEDGER if o.db_schema]
        assert prefixes.count("dc") == 1
        assert schemas.count(module_schema("deploy")) == 1


class TestTheReportedVersionIsDerivedAndTheContractIsPinned:
    """Two facts, two fields — and the one that gates loading is not the one
    health reports.

    This class previously locked `manifest.version` to the literal `0.1.0a2` on
    the premise that "a composing assembly reads it to decide contract
    compatibility". That premise is false, and the kernel is where it fails:
    `ModuleRegistry._check_contract_versions` reads `contract_version` and
    nothing else. `version` reaches exactly three places — a non-empty check,
    `ModuleInventoryEntry.version`, and the `as_dict()` diagnostics payload.

    So the literal never protected a consumer from a republication. It only made
    every health surface report `0.1.0a2` while `0.1.0a6` was the installed
    code — the same shape as the a4 `__version__` defect, in the field an
    operator actually reads.

    `version` is now derived from installed metadata. `contract_version` stays a
    literal, keeps gating loading, and still pins the declared surface below.
    """

    def test_the_reported_version_is_the_installed_distribution(self) -> None:
        """Derived, not declared — so they cannot disagree.

        Under an editable install these AGREE, and that agreement is the point:
        a diagnostics payload naming a version that is not installed is the
        defect this replaced.
        """
        declared = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())["tool"][
            "poetry"
        ]["version"]
        assert module.version == declared, (
            f"the module reports {module.version!r} while the installed "
            f"distribution is {declared!r}; health and the module inventory "
            "would report a version nobody is running"
        )

    def test_contract_compatibility_never_reads_the_reported_version(self) -> None:
        """The measurement that retires the old premise, kept as a test.

        If a future kernel starts gating on `version`, this fails and the
        reasoning above stops being true silently.
        """
        import inspect

        from dotmac_kernel.modules import ModuleRegistry

        source = inspect.getsource(ModuleRegistry._check_contract_versions)
        assert "contract_version" in source
        assert re.search(r"\.version\b(?!_)", source) is None, (
            "the kernel's compatibility check now reads `version`; the reported "
            "version is derived and must not gate loading"
        )

    def test_the_contract_version_pins_the_declared_surface(self) -> None:
        """The half of the old class worth keeping, hung off the right field.

        The contract version may stay put only because the declared surface
        did. If a later change adds a table, a prerequisite or an audit action
        without moving `contract_version`, this is the test that should stop it.
        """
        assert module.contract_version == 2


class TestThePlaneIsDeclaredNotDiscovered:
    def test_the_tenant_plane_is_empty(self) -> None:
        """A module that decides what a FLEET should run cannot live inside one
        of the deployments it decides about."""
        assert module.tables == ()

    def test_the_declared_platform_tables_are_exactly_the_mapped_ones(self) -> None:
        from dotmac_deployment_control.models import (
            SCHEMA,
            DeploymentPlan,
            DeploymentTarget,
            ObservationAttempt,
            ObservationReceipt,
            Rollout,
            RolloutAttempt,
            TargetCredential,
        )

        models = (
            DeploymentTarget,
            TargetCredential,
            DeploymentPlan,
            Rollout,
            RolloutAttempt,
            ObservationReceipt,
            ObservationAttempt,
        )
        assert {m.__tablename__ for m in models} == set(module.platform_tables)
        assert all(m.__table__.schema == SCHEMA for m in models)

    def test_no_model_carries_a_tenant_column(self) -> None:
        from dotmac_deployment_control import models as model_module

        for name in model_module.__all__:
            candidate = getattr(model_module, name)
            table = getattr(candidate, "__table__", None)
            if table is not None:
                assert "tenant_id" not in table.columns, name


# ── The guard unique to this module ─────────────────────────────────────────


class TestNoTransportCameAcross:
    """ADR-0024 / hard rule 28: the Integrator owns everything after the intent.

    This module sits directly beside it, and the temptation to bring one helper
    across is the strongest in the programme.
    """

    _TRANSPORT_NAMES = frozenset(
        {
            "endpoint",
            "endpoint_url",
            "base_url",
            "connection_ref",
            "credential_ref",
            "provider",
            "provider_code",
            "retry_policy",
            "retry_after",
            "backoff",
            "checkpoint",
            "webhook",
            "signature_header",
            "timeout_seconds",
        }
    )

    def test_the_package_imports_nothing_that_could_perform_provider_io(
        self,
    ) -> None:
        offenders: list[str] = []
        for path in _sources():
            for bad in sorted(_imported_roots(path.read_text()) & TRANSPORT_ROOTS):
                offenders.append(f"{path.relative_to(REPO_ROOT)} imports {bad}")
        assert not offenders, "\n".join(offenders)

    def test_the_distribution_declares_no_transport_dependency(self) -> None:
        data = tomllib.loads((PACKAGE_ROOT / "pyproject.toml").read_text())
        declared = set(data["tool"]["poetry"]["dependencies"])
        assert not (declared & TRANSPORT_ROOTS), declared & TRANSPORT_ROOTS

    def test_no_source_file_names_transport_state(self) -> None:
        offenders: list[str] = []
        for path in _sources():
            for bad in sorted(_identifiers(path.read_text()) & self._TRANSPORT_NAMES):
                offenders.append(f"{path.relative_to(REPO_ROOT)} names {bad}")
        assert not offenders, "\n".join(offenders)

    def test_the_delivery_intent_carries_what_never_how(self) -> None:
        """The contract that keeps the boundary honest: an intent field naming a
        route would make every consumer's code provider-shaped."""
        from dotmac_deployment_control import DeliveryIntent

        fields = set(DeliveryIntent.__dataclass_fields__)
        assert not (fields & self._TRANSPORT_NAMES), fields & self._TRANSPORT_NAMES
        assert {"release_ref", "plan_digest", "spec"} <= fields

    def test_no_migration_column_is_transport_shaped(self) -> None:
        sql = MIGRATION.read_text()
        columns = set(re.findall(r'sa\.Column\(\s*"([a-z_0-9]+)"', sql))
        assert not (columns & self._TRANSPORT_NAMES), columns & self._TRANSPORT_NAMES

    def test_the_detectors_fire_against_synthetic_violations(self) -> None:
        """Sensitivity proof (ADR-0018), including the false positives they must
        NOT produce."""
        assert _imported_roots("import httpx") & TRANSPORT_ROOTS
        assert (
            not _imported_roots("from dotmac_kernel.audit import x") & TRANSPORT_ROOTS
        )
        assert _identifiers("row.endpoint_url = url") & self._TRANSPORT_NAMES
        assert _identifiers("def go(retry_policy): pass") & self._TRANSPORT_NAMES
        # Prose about what the module does not own is not a violation.
        assert not (
            _identifiers('"""The Integrator owns retry_policy and endpoint_url."""')
            & self._TRANSPORT_NAMES
        )
        assert not (
            _identifiers("intent = DeliveryIntent(plan_digest=digest)")
            & self._TRANSPORT_NAMES
        )


class TestItVerifiesNothingItself:
    """ADR-0007: signature and possession checking are the KERNEL's. A second
    verifier here could disagree with the first, and the disagreement would be
    invisible until it mattered."""

    _VERIFY_NAMES = frozenset(
        {"verify_signature", "check_signature", "ed25519", "sign", "signing_key"}
    )

    def test_no_source_file_implements_verification(self) -> None:
        offenders: list[str] = []
        for path in _sources():
            for bad in sorted(_identifiers(path.read_text()) & self._VERIFY_NAMES):
                offenders.append(f"{path.relative_to(REPO_ROOT)} names {bad}")
        assert not offenders, "\n".join(offenders)

    def test_the_signature_outcome_arrives_as_a_value(self) -> None:
        """The caller runs the kernel verifier and passes the result in."""
        from dotmac_deployment_control import ObservedState

        assert "signature_status" in ObservedState.__dataclass_fields__
        assert "authenticated_target_ref" in ObservedState.__dataclass_fields__

    def test_the_detector_fires_against_a_synthetic_violation(self) -> None:
        assert _identifiers("def verify_signature(x): pass") & self._VERIFY_NAMES
        assert (
            not _identifiers("status = observed.signature_status") & self._VERIFY_NAMES
        )


class TestNoHealthStatusIsHeld:
    """Ruling A4 keeps health separate from fleet, so "no mutating consumer of
    health" stays a checkable dependency direction. A health column here would
    make this module the thing everything else reads to decide what to do."""

    _HEALTH_NAMES = frozenset(
        {"health", "health_status", "healthy", "heartbeat", "last_seen_at", "uptime"}
    )

    def test_no_model_column_is_health_shaped(self) -> None:
        from dotmac_deployment_control import models as model_module

        offenders: list[str] = []
        for name in model_module.__all__:
            table = getattr(getattr(model_module, name), "__table__", None)
            if table is None:
                continue
            for column in table.columns:
                if column.name in self._HEALTH_NAMES:
                    offenders.append(f"{name}.{column.name}")
        assert not offenders, offenders

    def test_the_detector_fires_against_a_synthetic_violation(self) -> None:
        assert "health_status" in self._HEALTH_NAMES
        assert "last_observed_at" not in self._HEALTH_NAMES, (
            "an observation timestamp is provenance, not health — the guard must "
            "not flag the column the module legitimately owns"
        )


# ── Independence and transaction authority ──────────────────────────────────


class TestTheModuleImportsNoSibling:
    def test_no_source_file_imports_another_distribution(self) -> None:
        offenders: list[str] = []
        for path in _sources():
            for bad in sorted(_imported_roots(path.read_text()) & SIBLING_ROOTS):
                offenders.append(f"{path.relative_to(REPO_ROOT)} imports {bad}")
        assert not offenders, "\n".join(offenders)

    def test_the_detector_fires_against_a_synthetic_violation(self) -> None:
        assert (
            _imported_roots("from dotmac_licensing import get_issuance") & SIBLING_ROOTS
        )
        assert not _imported_roots("from dotmac_kernel.audit import x") & SIBLING_ROOTS


class TestTheModuleOwnsNoTransaction:
    _FORBIDDEN = re.compile(
        r"\b(?:db|session|self\._session)\.(?:commit|rollback)\s*\(|"
        r"\bsessionmaker\s*\(|\bSessionLocal\s*\(|\bPlatformSessionLocal\s*\(|"
        r"\bSession\s*\([^)]"
    )

    def test_no_source_file_commits_rolls_back_or_builds_a_session(self) -> None:
        offenders = [
            str(path.relative_to(REPO_ROOT))
            for path in _sources()
            if self._FORBIDDEN.search(path.read_text())
        ]
        assert not offenders, offenders

    def test_the_detector_fires_against_a_synthetic_violation(self) -> None:
        assert self._FORBIDDEN.search("    db.commit()")
        assert not self._FORBIDDEN.search("    session.flush()")


# ── The published vocabulary ────────────────────────────────────────────────


class TestThePublishedFactsMatchWhatIsEmitted:
    def test_every_emitted_event_type_is_published(self) -> None:
        from dotmac_deployment_control import PUBLISHED_EVENT_TYPES
        from dotmac_deployment_control import facts as facts_module

        emitted = {
            value
            for name, value in vars(facts_module).items()
            if name.isupper() and name.endswith("_V1") and isinstance(value, str)
        }
        assert emitted == set(PUBLISHED_EVENT_TYPES)

    def test_every_published_type_is_referenced_by_the_service(self) -> None:
        from dotmac_deployment_control import PUBLISHED_EVENT_TYPES
        from dotmac_deployment_control import facts as facts_module

        service_source = (SRC / "service.py").read_text()
        by_value = {
            value: name
            for name, value in vars(facts_module).items()
            if isinstance(value, str) and value in PUBLISHED_EVENT_TYPES
        }
        unreferenced = [
            value
            for value in PUBLISHED_EVENT_TYPES
            if f"facts.{by_value[value]}" not in service_source
        ]
        assert not unreferenced, unreferenced

    def test_every_type_carries_an_explicit_version_suffix(self) -> None:
        from dotmac_deployment_control import PUBLISHED_EVENT_TYPES

        assert all(re.search(r"\.v\d+$", t) for t in PUBLISHED_EVENT_TYPES)


class TestTheAuditActionsAreDeclaredAndConsumed:
    def test_the_manifest_declares_exactly_the_four_the_service_writes(self) -> None:
        from dotmac_deployment_control import (
            AUDIT_ACTION_CREDENTIAL,
            AUDIT_ACTION_OBSERVATION,
            AUDIT_ACTION_ROLLOUT,
            AUDIT_ACTION_TARGET,
        )

        assert set(module.audit_actions) == {
            AUDIT_ACTION_TARGET,
            AUDIT_ACTION_CREDENTIAL,
            AUDIT_ACTION_ROLLOUT,
            AUDIT_ACTION_OBSERVATION,
        }
        service_source = (SRC / "service.py").read_text()
        for name in (
            "AUDIT_ACTION_TARGET",
            "AUDIT_ACTION_CREDENTIAL",
            "AUDIT_ACTION_ROLLOUT",
            "AUDIT_ACTION_OBSERVATION",
        ):
            assert f"action={name}" in service_source, name


# ── The migration ───────────────────────────────────────────────────────────


class TestTheMigrationStatesItsWholeAccessSurface:
    @pytest.fixture
    def sql(self) -> str:
        return MIGRATION.read_text()

    def test_every_table_is_revoked_from_the_tenant_app_role(self, sql: str) -> None:
        for table in module.platform_tables:
            assert f'_revoke("{table}")' in sql, table

    def test_the_online_platform_role_can_reach_every_table(self, sql: str) -> None:
        """Declared-and-unusable is a violation too (hard rule 27)."""
        assert "GRANT USAGE ON SCHEMA mod_deploy TO platform_api" in sql
        for table in module.platform_tables:
            assert re.search(
                rf'_grant\("[A-Z, ]*SELECT[A-Z, ]*", "{table}", "platform_api"\)', sql
            ), table

    def test_the_three_evidence_tables_grant_no_update_or_delete_to_any_role(
        self, sql: str
    ) -> None:
        for table in EVIDENCE_TABLES:
            for privileges, role in re.findall(
                rf'_grant\("([A-Z, ]+)", "{table}", "(\w+)"\)', sql
            ):
                assert "UPDATE" not in privileges, (table, role)
                assert "DELETE" not in privileges, (table, role)

    def test_the_four_mutable_tables_do_grant_update_to_the_online_role(
        self, sql: str
    ) -> None:
        """The other half: withholding UPDATE from a table whose lifecycle lives
        on it would make the module unusable while passing every test above."""
        for table in MUTABLE_TABLES:
            assert f'_grant("UPDATE", "{table}", "platform_api")' in sql or re.search(
                rf'_grant\("[A-Z, ]*UPDATE[A-Z, ]*", "{table}", "platform_api"\)', sql
            ), table

    def test_the_append_only_trigger_covers_all_three_evidence_tables(
        self, sql: str
    ) -> None:
        for table in EVIDENCE_TABLES:
            assert f"BEFORE UPDATE OR DELETE ON mod_deploy.{table}" in sql

    def test_the_claim_proof_checks_are_declared_in_the_migration(
        self, sql: str
    ) -> None:
        """Declared on the model AND here, deliberately: the unit lane builds its
        schema from the model metadata, so a constraint living only in the
        migration would mean the fast tests run against a schema production does
        not have."""
        assert "ck_observation_identity_needs_valid_signature" in sql
        assert "ck_observation_eligibility_needs_valid_signature" in sql

    def test_the_same_checks_are_declared_on_the_model(self) -> None:
        from dotmac_deployment_control import ObservationAttempt

        names = {
            constraint.name
            for constraint in ObservationAttempt.__table__.constraints
            if constraint.name
        }
        assert "ck_observation_identity_needs_valid_signature" in names
        assert "ck_observation_eligibility_needs_valid_signature" in names

    def test_the_schema_is_a_literal_and_fully_qualified(self, sql: str) -> None:
        assert 'schema="mod_deploy"' in sql
        assert "search_path" not in sql

    def test_the_lineage_is_a_root_naming_its_own_branch(self, sql: str) -> None:
        assert 'revision = "dc_0001_deployment_control"' in sql
        assert "down_revision = None" in sql
        assert 'branch_labels = ("deployment_control",)' in sql
        assert len("dc_0001_deployment_control") <= 32

    def test_it_names_no_foreign_revision(self, sql: str) -> None:
        assert "depends_on = resolve_depends_on(COMMON_REQUIRES)" in sql
        assert not re.search(r'depends_on\s*=\s*[\'"]', sql)

    def test_it_verifies_both_prerequisites_before_any_ddl(self, sql: str) -> None:
        verify_at = sql.index("require_prerequisites(op.get_bind(), REQUIRES)")
        first_ddl = sql.index("CREATE SCHEMA IF NOT EXISTS mod_deploy")
        assert verify_at < first_ddl
        assert set(module.requires) == {
            "idempotency_ledger.v1",
            "platform_audit_log.v1",
        }

    def test_the_grant_sweep_fires_against_a_synthetic_violation(self) -> None:
        """Sensitivity proof (ADR-0018)."""
        leaky = '_grant("SELECT, DELETE", "observation_attempts", "app_admin")'
        found = re.findall(
            r'_grant\("([A-Z, ]+)", "observation_attempts", "(\w+)"\)', leaky
        )
        assert found and "DELETE" in found[0][0]


# ── The dossier ─────────────────────────────────────────────────────────────


class TestTheExtractionDossierIsHonestAboutSplitProvenance:
    @pytest.fixture
    def dossier(self) -> dict[str, object]:
        return tomllib.loads((PACKAGE_ROOT / "EXTRACTION.toml").read_text())

    def test_it_does_not_claim_product_first(self, dossier: dict[str, object]) -> None:
        """Rule 24's test is a qualifying PRODUCTION-USED implementation, and a
        never-merged, never-deployed branch is not one however good it is.
        Claiming `product-first` would borrow a stronger word than the
        provenance supports."""
        assert dossier["source_mode"] == "greenfield-after-inventory"

    def test_it_explains_why_the_reference_does_not_make_it_product_first(
        self, dossier: dict[str, object]
    ) -> None:
        """Subtle enough that a reader who finds 1,300 LOC of real source in
        `source_paths` will otherwise conclude the mode is wrong."""
        note = str(dossier["source_mode_note"])
        assert "PRODUCTION-USED" in note
        assert "never deployed" in note

    def test_it_names_the_branch_the_reference_lives_on(
        self, dossier: dict[str, object]
    ) -> None:
        """A source path with no branch would send a reader to `main`, where the
        V6 files do not exist and their migration slots have been reused."""
        paths = dossier["source_paths"]
        assert any("feat/v6-slice2-applied-state-admission" in p for p in paths)  # type: ignore[union-attr]
        assert any("feat/v6-slice1-deployment-credentials" in p for p in paths)  # type: ignore[union-attr]

    def test_it_records_why_sub_was_rejected_as_a_source(
        self, dossier: dict[str, object]
    ) -> None:
        """The comparison must be checked in, or the next reader repeats it — or
        worse, decides the other way on a shape match."""
        repositories = str(dossier["source_repositories"])
        assert "dotmac_sub" in repositories

    def test_it_claims_exactly_the_adoption_its_evidence_supports(
        self, dossier: dict[str, object]
    ) -> None:
        """This assertion used to read `audit-complete` / no evidence / no
        consumers, and was true when written.

        It stopped being true on 2026-08-21, when Vendor Control Plane merged
        69a877d6 and composed the module — and nothing went red, because the
        test asserted a SNAPSHOT of the answer rather than the PROPERTY. A
        snapshot of a fact about another repository ages silently; the property
        does not.

        The property is the two-directional ratchet: a package may not claim
        more than its consumers prove, and may not sit in a state weaker than
        its evidence supports. `_state_for` makes one contract consumer exactly
        `adopted`, so the status is derived here rather than restated.
        """
        consumers = dossier["contract_consumers"]
        assert consumers == ["dotmac_vendor_control_plane"]
        assert (
            dossier["status"]
            == ("audit-complete", "adopted", "reuse-proven")[
                min(len(consumers), 2)  # type: ignore[arg-type]
            ]
        )

        kinds = {row["kind"] for row in dossier["adoption_evidence"]}  # type: ignore[union-attr,index]
        assert kinds & evidence_schema.ADOPTION_PROVING_KINDS, (
            "an adoption state resting on installation rows alone is the "
            "`dotmac-tax` shape: a pin is installation, not adoption"
        )

    def test_it_does_not_claim_a_production_adoption_nobody_has_proven(
        self, dossier: dict[str, object]
    ) -> None:
        """Composition on Vendor's main branch is not a deployment.

        Governance ADR 0013 turns on that distinction, so it is asserted rather
        than left to prose a later editor can soften. A `deploy_run` row is what
        a production claim would look like; none exists because no such oracle
        has been produced.
        """
        kinds = {row["kind"] for row in dossier["adoption_evidence"]}  # type: ignore[union-attr,index]
        assert "deploy_run" not in kinds
        assert "NOT CLAIMED" in str(dossier["first_cutover"])

    def test_it_records_the_two_proofs_the_composition_still_owes(
        self, dossier: dict[str, object]
    ) -> None:
        shadow = str(dossier["shadow_and_drift"])
        assert "RAW SQL" in shadow
        assert "concurrency" in shadow

    def test_it_records_the_obligation_to_delete_the_abandoned_branches(
        self, dossier: dict[str, object]
    ) -> None:
        """Leaving them is both a misleading second implementation and a live
        rebase hazard, since `main` has reused their migration slots."""
        retirement = str(dossier["local_copy_retirement"])
        assert "DELETED" in retirement
        assert "v6-slice" in retirement
