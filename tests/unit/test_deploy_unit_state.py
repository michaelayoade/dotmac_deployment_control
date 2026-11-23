"""Persisted deploy-unit state: settings, legacy policy versions, sets, binding.

In-memory SQLite, logic only. The append-only and grant surface of `dc_0017` is
proved against PostgreSQL by the platform isolation canary.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime, timedelta

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.models import Base
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    get_target,
    module,
    plan_digest_of,
    plan_snapshot,
    propose_plan,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control import service as svc
from dotmac_deployment_control.deploy_binding import (
    DeployBindingRefusedError,
    DeploymentSet,
    DeployPlanInputs,
)
from dotmac_deployment_control.deploy_unit import (
    DeployUnitError,
    canonical_render,
    params_env_digest,
    parse_deploy_unit,
)
from dotmac_deployment_control.digests import DeployUnitDigestV1
from dotmac_deployment_control.legacy_policy import (
    AttendedApproval,
    LegacyPolicyRefusedError,
    LegacyRetirementEvidence,
)
from dotmac_deployment_control.models import DeploymentTarget, LegacyEnvPolicyVersion
from dotmac_deployment_control.ports import (
    ApprovalEvidence,
    ApprovalRefusedError,
    PlanMaterialUnsuppliedError,
    PlanRefusedError,
    ReleaseDescriptorEvidence,
    ReleaseDescriptorRefusedError,
    ReleaseDescriptorUnavailableError,
    TransitionRefusedError,
)
from dotmac_deployment_control.service import (
    ApproveDeploymentSetCommand,
    CreateDeploymentSetCommand,
    EnableLegacyPolicyCommand,
    ExtendLegacyPolicyCommand,
    RetireLegacyPolicyCommand,
    ReviseLegacyPolicyCommand,
    SetDeploySettingCommand,
    approve_deployment_set,
    create_deployment_set,
    enable_legacy_policy,
    extend_legacy_policy,
    get_deploy_settings,
    get_deployment_set,
    get_legacy_policy,
    list_deployment_sets,
    retire_legacy_policy,
    revise_legacy_policy,
    set_deploy_setting,
)

_ERP = "dotmac-erp-v2"
_COMPANION = "dotmac-integrator-companion"
#: Target refs are `<product_code>/<environment>/<host>` (the target-API grammar).
_E = "dotmac-erp-v2/production/"
_C = "dotmac-integrator-companion/production/"
_REF = _E + "host-a"
_NAMESPACES = {_ERP: "erp", _COMPANION: "erp-integrator"}
_SHA = "sha256:" + "a" * 64
_SHA2 = "sha256:" + "b" * 64
_D1 = "sha256:" + "1" * 64
_T1 = "sha256:" + "8" * 64
_T2 = "sha256:" + "9" * 64
_REPO = "registry.example.test/team/app"
_LOOP = "127.0.0.1:5000/team/app"
_REV = "a" * 40
_EXEC = "sha256:" + "1a" * 32
_DESC = "sha256:" + "3c" * 32
_ATTENDED = AttendedApproval("operator", True, "register-line-1")
_UNATTENDED = AttendedApproval("operator", False, "register-line-1")
_NAMES = ("API_SECRET", "DB_PASSWORD")
_PATH = "deploy/deploy-unit.toml"
_CPATH = "deploy/companion/deploy-unit.toml"
_INPUTS = DeployPlanInputs(lease_ttl_seconds=900, loopback_port=5000)


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture
def db() -> Generator[Session, None, None]:
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection, _record):  # type: ignore[no-untyped-def]
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection):  # type: ignore[no-untyped-def]
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
            or table.name
            in {
                "platform_idempotency_records",
                "platform_audit_events",
                "platform_admins",
                "platform_outbox_events",
            }
        ],
    )
    session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
    try:
        yield session
    finally:
        session.close()
        engine.dispose()


def _cmd() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _descriptor_text(
    *,
    product: str = _ERP,
    pull: bool = False,
    legacy: bool = False,
    active: tuple[str, ...] = (),
    companion: bool = False,
    companion_required: bool = False,
    workers: bool = True,
    job_materials: tuple[str, ...] = (),
    omit_bindings: tuple[str, ...] = (),
    import_job: bool = False,
    import_active: bool = True,
    import_scoped: bool = True,
    import_extra_material: str | None = None,
    import_legacy_pre_staged: bool = False,
    hold: bool = False,
) -> str:
    spec = (
        "deploy/companion/product.toml"
        if product == _COMPANION
        else "deploy/product.toml"
    )
    out = (
        'schema = "dotmac.deploy_unit/1"\n'
        f'product = "{product}"\nspec = "{spec}"\n'
        f'secrets_namespace = "{_NAMESPACES[product]}"\n'
        f'[image]\nsource = "{"pull" if pull else "transfer"}"\n'
        '[params.image_repository]\ntype = "image_repository"\n'
        'required_in = ["production"]\n'
        '[params.image_digest]\ntype = "image_digest"\nrequired_in = ["production"]\n'
    )
    if workers:
        out += (
            '[params.workers]\ntype = "int"\nmin = 1\nmax = 8\ndefault = 2\n'
            'material = "WORKERS"\n'
        )
    if legacy:
        out += (
            '[params.legacy_path]\ntype = "path"\n'
            '[legacy_env_file]\nnames = ["API_SECRET", "DB_PASSWORD"]\n'
            'path_param = "legacy_path"\n'
        )
    if product == _ERP:
        for name in ("API_SECRET", "DB_PASSWORD"):
            if name in omit_bindings:
                continue
            state = "" if name in active else 'state = "pre_staged"\n'
            # Distinct roles: a role is all-or-nothing active (F3), so a test can
            # activate one binding without tripping the other's role.
            role = "app" if name == "API_SECRET" else "db"
            out += (
                f'[[bindings]]\nname = "{name}"\n{state}kind = "key"\n'
                f'roles = ["{role}"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
                "single_use = false\n"
            )
    if job_materials:
        names = ", ".join(f'"{m}"' for m in job_materials)
        out += (
            '[[jobs]]\nname = "import"\ncommand = ["run", "import"]\n'
            f'timeout_seconds = 600\ntrigger = "operator"\nmaterials = [{names}]\n'
            'runbook = "docs/rehearsal.md"\n'
        )
    if hold:
        out += (
            '[params.hold_seconds]\ntype = "duration_seconds"\ndefault = 1800\n'
            "min = 60\nmax = 3600\n"
            '[[hold_points]]\nname = "g"\nmember = "companion"\nbefore = "migrate"\n'
            'timeout_param = "hold_seconds"\n'
            'on_timeout = "abandon_member_record_deviation"\n'
            'released_by = "operator"\n'
        )
    if companion:
        out += (
            f'[[companions]]\nproduct = "{_COMPANION}"\ndescriptor = "{_CPATH}"\n'
            'order = "after_primary_ready"\n'
            f"required_at_switch = {str(companion_required).lower()}\n"
            'host = "same"\n'
        )
    if import_job:
        state = "" if import_active else 'state = "pre_staged"\n'
        legacy_state = 'state = "pre_staged"\n' if import_legacy_pre_staged else state
        scope = 'jobs = ["import"]\n' if import_scoped else ""
        extra = f', "{import_extra_material}"' if import_extra_material else ""
        out += (
            '[params.import_approved]\ntype = "bool"\ndefault = false\n'
            f'material = "ERP_IMPORT_APPROVED"\n{scope}'
            '[params.import_payable]\ntype = "string"\n'
            'material = "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF"\n'
            f'pattern = "^[A-Za-z0-9._:-]+$"\nmax_length = 64\n{scope}'
            '[[bindings]]\nname = "MIGRATION_DATABASE_URL"\n'
            f'{state}kind = "pg_login_dsn"\n'
            'roles = ["migrate", "import"]\nwriter = "ceremony"\n'
            'rotation = "copy_only"\nsingle_use = true\n'
            '[[bindings]]\nname = "LEGACY_DATABASE_URL"\n'
            f'{legacy_state}kind = "pg_login_dsn"\n'
            'roles = ["import"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
            "single_use = true\n"
            '[[jobs]]\nname = "import"\nrole = "import"\n'
            'command = ["run", "import"]\ntimeout_seconds = 600\n'
            'trigger = "operator"\n'
            'materials = ["MIGRATION_DATABASE_URL", "LEGACY_DATABASE_URL", '
            f'"ERP_IMPORT_APPROVED", "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF"{extra}]\n'
            'runbook = "docs/rehearsal.md"\n'
            '[[jobs.args]]\nflag = "--mode"\ntype = "enum"\n'
            'choices = ["plan", "execute"]\nrequired = true\n'
        )
    return out


class FakeSource:
    """A `ReleaseDescriptorSource` the tests can bend; counts its resolves."""

    def __init__(self, text: str | None = None, **kw: object) -> None:
        self.calls = 0
        self.unavailable = False
        self.texts = {_PATH: text or _descriptor_text(**kw)}  # type: ignore[arg-type]
        self.image_digest = _D1
        self.image_repository = _REPO
        self.product_override: str | None = None
        self.attested_override: str | None = None
        self.revision = _REV
        self.toml_sha: str | None = _T1
        self.toml_path_override: str | None = None
        self.drop_toml = False

    @property
    def text(self) -> str:
        return self.texts[_PATH]

    def set_text(self, text: str) -> None:
        self.texts[_PATH] = text

    def resolve(self, release_ref, *, product_code, descriptor_path):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.unavailable or descriptor_path not in self.texts:
            raise ReleaseDescriptorUnavailableError("no such descriptor")
        data = self.texts[descriptor_path].encode()
        sibling = descriptor_path.rsplit("/", 1)[0] + "/product.toml"
        return ReleaseDescriptorEvidence(
            release_ref=release_ref,
            product_code=self.product_override or product_code,
            descriptor_path=descriptor_path,
            source_revision=self.revision,
            image_repository=self.image_repository,
            image_digest=self.image_digest,
            deploy_unit_bytes=data,
            attested_digest=self.attested_override
            or DeployUnitDigestV1.over_bytes(data).canonical,
            product_toml_path=None
            if self.drop_toml
            else (self.toml_path_override or sibling),
            product_toml_sha256=None if self.drop_toml else self.toml_sha,
        )


def _unit_digest(source: FakeSource, path: str = _PATH) -> str:
    return DeployUnitDigestV1.over_bytes(source.texts[path].encode()).canonical


def _register(
    db: Session, ref: str = _REF, product: str = _ERP, env: str = "production"
):  # type: ignore[no-untyped-def]
    return register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=ref,
            subject_ref="acme-operator",
            product_code=product,
            environment=env,
        ),
    )


def _plain_target(db: Session, ref: str = _REF):  # type: ignore[no-untyped-def]
    view = _register(db, ref)
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=view.id,
            desired=DesiredDeployment(release_ref=f"{ref}@1", images=[]),
        ),
    )
    return view


def _desired(db, target_id, source, *, path=_PATH, repo=_LOOP, **kw):  # type: ignore[no-untyped-def]
    params = kw.pop("params", {"image_repository": repo})
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target_id,
            desired=DesiredDeployment(release_ref="erp@1", **kw),
            descriptor_path=path,
            params=params,
        ),
        release_source=source,
    )


def _bound_target(db, source, ref=_REF, product=_ERP, path=_PATH, **kw):  # type: ignore[no-untyped-def]
    target = _register(db, ref, product)
    _desired(db, target.id, source, path=path, **kw)
    return target


def _set(db: Session, name: str, value: object, approval=_ATTENDED):  # type: ignore[no-untyped-def]
    return set_deploy_setting(
        db,
        SetDeploySettingCommand(
            command_id=_cmd(), name=name, value=value, approval=approval
        ),
    )


def _legacy_target(db: Session, source: FakeSource):  # type: ignore[no-untyped-def]
    """A descriptor-backed ERP target that is allowed to use the bridge."""
    _set(db, "legacy_env_file_allowed_targets", [_REF])
    _set(db, "legacy_env_file_ceiling", 1)
    return _bound_target(db, source)


def _enable(db, target_id, source, **overrides):  # type: ignore[no-untyped-def]
    args: dict[str, object] = {
        "command_id": _cmd(),
        "target_id": target_id,
        "names": _NAMES,
        "sha256": _SHA,
        "secret_names": _NAMES,
        "cutover_at": datetime.now(UTC),
        "approval": _ATTENDED,
    }
    args.update(overrides)
    return enable_legacy_policy(
        db,
        EnableLegacyPolicyCommand(**args),  # type: ignore[arg-type]
        release_source=source,
    )


def _propose(db, target_id, source, inputs=_INPUTS):  # type: ignore[no-untyped-def]
    return propose_plan(
        db,
        ProposePlanCommand(
            command_id=_cmd(),
            target_id=target_id,
            operation="run_job" if inputs and inputs.job else "deploy",
            descriptor_digest=_DESC,
            execution_plan_digest=_EXEC,
            purpose="foundation_execution",
            requires_approval=True,
            approval_policy_code="deployment.production",
            approval_policy_version=4,
            deploy_inputs=inputs,
        ),
        release_source=source,
    )


# ── Settings ────────────────────────────────────────────────────────────────


def test_settings_default_to_empty_default_deny_and_zero(db: Session) -> None:
    view = get_deploy_settings(db)
    assert view.public_pull_repositories == ()
    assert view.legacy_env_file_allowed_targets == ()
    assert view.legacy_env_file_ceiling == 0


def test_a_setting_change_needs_an_attended_approval_and_is_validated(
    db: Session,
) -> None:
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        _set(db, "public_pull_repositories", [_REPO], _UNATTENDED)
    for name, bad in (
        ("public_pull_repositories", ["127.0.0.1:5000/team/app"]),
        ("public_pull_repositories", ["registry.example.test:abc/x"]),
        ("legacy_env_file_ceiling", -1),
        ("legacy_env_file_allowed_targets", ["bad target"]),
        ("not_a_setting", []),
    ):
        with pytest.raises(DeployUnitError):
            _set(db, name, bad)
    assert _set(
        db, "public_pull_repositories", [_REPO, _REPO]
    ).public_pull_repositories == (_REPO,)
    view = _set(db, "legacy_env_file_allowed_targets", [_REF, "x/y/z"])
    assert view.legacy_env_file_allowed_targets == (_REF, "x/y/z")


def test_the_ceiling_can_only_be_raised_by_a_setting_change(db: Session) -> None:
    assert _set(db, "legacy_env_file_ceiling", 2).legacy_env_file_ceiling == 2
    with pytest.raises(LegacyPolicyRefusedError):
        _set(db, "legacy_env_file_ceiling", 1)


# ── Legacy policy (descriptor-derived) ──────────────────────────────────────


def test_legacy_enable_refusals(db: Session) -> None:
    source = FakeSource(legacy=True)
    # Not on the allowed-targets list: the descriptor itself is refused.
    with pytest.raises(DeployUnitError, match="default-deny"):
        _bound_target(db, source, ref=_E + "denied")
    erp = _legacy_target(db, source)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        _enable(db, erp.id, source, approval=_UNATTENDED)
    with pytest.raises(LegacyPolicyRefusedError, match="not declared"):
        _enable(
            db,
            erp.id,
            source,
            names=(*_NAMES, "EXTRA"),
            secret_names=(*_NAMES, "EXTRA"),
        )
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _enable(db, erp.id, None)
    assert get_legacy_policy(db, erp.id) is None
    # The ceiling starts at 0.
    other = FakeSource(legacy=True)
    _set(db, "legacy_env_file_allowed_targets", [_REF, _E + "host-b"])
    second = _bound_target(db, other, ref=_E + "host-b")
    _enable(db, erp.id, source)
    with pytest.raises(LegacyPolicyRefusedError, match="ceiling"):
        _enable(db, second.id, other)
    # A companion path is refused whatever the allowlist says.
    companion = FakeSource(text=_descriptor_text(product=_COMPANION))
    companion.texts[_CPATH] = companion.texts.pop(_PATH)
    _set(
        db,
        "legacy_env_file_allowed_targets",
        [_REF, _C + "host-a"],
    )
    ctarget = _bound_target(
        db,
        companion,
        ref=_C + "host-a",
        product=_COMPANION,
        path=_CPATH,
    )
    with pytest.raises(LegacyPolicyRefusedError):
        _enable(db, ctarget.id, companion)


def test_legacy_versions_append_and_retirement_decrements_the_ceiling(
    db: Session,
) -> None:
    source = FakeSource(legacy=True)
    erp = _legacy_target(db, source)
    first = _enable(db, erp.id, source)
    assert (first.policy_version, first.state, first.file_sha256) == (
        1,
        "enabled",
        _SHA,
    )
    revised = revise_legacy_policy(
        db,
        ReviseLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            names=_NAMES[:1],
            sha256=_SHA2,
            approval=_ATTENDED,
        ),
    )
    assert (revised.policy_version, revised.file_sha256) == (2, _SHA2)
    with pytest.raises(LegacyPolicyRefusedError, match="only shrink"):
        revise_legacy_policy(
            db,
            ReviseLegacyPolicyCommand(
                command_id=_cmd(),
                target_id=erp.id,
                names=_NAMES,
                sha256=_SHA2,
                approval=_ATTENDED,
            ),
        )
    extended = extend_legacy_policy(
        db,
        ExtendLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            new_expires_at=revised.expires_at + timedelta(days=7),
            approval=_ATTENDED,
        ),
    )
    assert extended.policy_version == 3
    retired = retire_legacy_policy(
        db,
        RetireLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            evidence=LegacyRetirementEvidence(True, True, True),
            approval=_ATTENDED,
        ),
    )
    assert (retired.state, retired.names, retired.policy_version) == ("retired", (), 4)
    assert get_deploy_settings(db).legacy_env_file_ceiling == 0
    rows = db.execute(select(LegacyEnvPolicyVersion)).scalars().all()
    assert sorted(r.policy_version for r in rows) == [1, 2, 3, 4]


# ── The binding is DERIVED by Control ───────────────────────────────────────


def _binding_of(plan) -> dict:  # type: ignore[no-untyped-def]
    return plan.snapshot["deploy_binding"]


def test_plan_binds_params_env_digest(db: Session) -> None:
    """The bound digest IS the digest of the canonical render of the params."""
    source = FakeSource()
    erp = _bound_target(db, source)
    plan = _propose(db, erp.id, source)
    unit = parse_deploy_unit(source.text)
    params = get_target(db, erp.id).desired_spec["deploy_unit"]["params"]
    render = canonical_render(
        unit, params, app_image=f"{_LOOP}@{_D1}", environment="production"
    )
    assert _binding_of(plan)["params_env_digest"] == params_env_digest(render)
    # And that digest is the one of these fixed bytes, not just of the function.
    assert render == f"APP_IMAGE={_LOOP}@{_D1}\nWORKERS=2\n".encode()
    assert _binding_of(plan)["params_env_digest"] == (
        "sha256:6deb479b927ce1ac4db421665dcb9d561f2314749151ca0f78ca43146ea3526a"
    )
    # Different params give a different derived digest (and a different plan).
    _desired(db, erp.id, source, params={"image_repository": _LOOP, "workers": 3})
    again = _propose(db, erp.id, source)
    assert (
        _binding_of(again)["params_env_digest"]
        != _binding_of(plan)["params_env_digest"]
    )
    params3 = get_target(db, erp.id).desired_spec["deploy_unit"]["params"]
    assert _binding_of(again)["params_env_digest"] == params_env_digest(
        canonical_render(
            unit, params3, app_image=f"{_LOOP}@{_D1}", environment="production"
        )
    )


def test_lease_ttl_is_capped_by_the_plan(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    for bad in (0, -1, 3601, 86400):
        with pytest.raises(DeployBindingRefusedError, match="TTL"):
            _propose(db, erp.id, source, DeployPlanInputs(bad, 5000))
    plan = _propose(db, erp.id, source, DeployPlanInputs(3600, 5000))
    assert _binding_of(plan)["lease_ttl_seconds"] == 3600


def test_a_descriptor_backed_plan_needs_inputs_and_others_refuse_them(
    db: Session,
) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    with pytest.raises(PlanRefusedError, match="deploy inputs"):
        _propose(db, erp.id, source, None)
    with pytest.raises(PlanRefusedError, match="loopback port"):
        _propose(db, erp.id, source, DeployPlanInputs(900, None))
    plain = _plain_target(db, _E + "plain")
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose(db, plain.id, source, _INPUTS)
    assert "deploy_binding" not in _propose(db, plain.id, source, None).snapshot


def test_the_binding_is_derived_images_bindings_and_companions(db: Session) -> None:
    source = FakeSource(companion=True)
    erp = _bound_target(db, source)
    binding = _binding_of(_propose(db, erp.id, source))
    assert binding["deploy_unit_digest"] == _unit_digest(source)
    assert binding["product_toml_sha256"] == _T1
    assert binding["companion_order"] == "after_primary_ready"
    assert binding["active_binding_names"] == []
    # Roles and the primary service are DERIVED from the descriptor and bound.
    assert binding["primary_service"] == "dotmac-erp-v2"
    assert binding["roles"] == []
    image = binding["images"][0]
    assert (image["source"], image["planned_repository"]) == ("transfer", _LOOP)
    assert (image["release_repository"], image["release_digest"]) == (_REPO, _D1)


def test_legacy_part_is_required_and_always_checked(db: Session) -> None:
    source = FakeSource(legacy=True)
    erp = _legacy_target(db, source)
    # The descriptor declares the bridge but no policy is enabled yet.
    with pytest.raises(LegacyPolicyRefusedError, match="no enabled legacy policy"):
        _propose(db, erp.id, source)
    _enable(db, erp.id, source)
    legacy = _binding_of(_propose(db, erp.id, source))["legacy"]
    assert (legacy["policy_version"], legacy["sha256"]) == (1, _SHA)
    assert legacy["names"] == list(_NAMES)
    # The expiry is bound into the plan, in the contract's timestamp format.
    from dotmac_deployment_control.target_api import parse_stamp

    assert parse_stamp(legacy["expires_at"]) > datetime.now(UTC)
    # L5: an expired policy refuses the plan.
    original = svc._control_now
    svc._control_now = lambda: datetime.now(UTC) + timedelta(days=31)
    try:
        with pytest.raises(LegacyPolicyRefusedError, match="expired"):
            _propose(db, erp.id, source)
    finally:
        svc._control_now = original
    # A new release whose descriptor DROPPED the bridge, while the policy is
    # still enabled: desired state is set from it (so the digest matches), and
    # the plan is refused by the policy-versus-descriptor check itself.
    dropped = FakeSource()
    _desired(db, erp.id, dropped)
    with pytest.raises(
        LegacyPolicyRefusedError, match=r"declares no \[legacy_env_file\]"
    ):
        _propose(db, erp.id, dropped)


def test_an_active_binding_on_a_legacy_name_is_refused_until_retired(
    db: Session,
) -> None:
    source = FakeSource(legacy=True, active=("DB_PASSWORD",))
    _set(db, "legacy_env_file_allowed_targets", [_REF, _E + "tmp"])
    _set(db, "legacy_env_file_ceiling", 1)
    # An ACTIVE binding on a legacy name collides at parse already (L2).
    with pytest.raises(DeployUnitError, match="collide"):
        _bound_target(db, source, ref=_E + "tmp")
    # Pre-staged first, policy enabled; then the descriptor activates the name.
    pre = FakeSource(legacy=True)
    erp = _bound_target(db, pre)
    _enable(db, erp.id, pre)
    activated = FakeSource(legacy=False, active=("DB_PASSWORD",))
    # Same target, new release with the bridge dropped but the policy live.
    _desired(db, erp.id, activated)
    with pytest.raises(
        LegacyPolicyRefusedError, match=r"declares no \[legacy_env_file\]"
    ):
        _propose(db, erp.id, activated)
    retire_legacy_policy(
        db,
        RetireLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            evidence=LegacyRetirementEvidence(True, True, True),
            approval=_ATTENDED,
        ),
    )
    plan = _propose(db, erp.id, activated)
    assert _binding_of(plan)["active_binding_names"] == ["DB_PASSWORD"]
    assert _binding_of(plan)["legacy"] is None


def test_a_descriptor_backed_target_cannot_drop_its_descriptor(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    with pytest.raises(PlanRefusedError, match="descriptor-backed"):
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=erp.id,
                desired=DesiredDeployment(release_ref="erp@2", images=[]),
            ),
        )
    # A stale revision is refused under the lock.
    with pytest.raises(Exception, match="desired revision"):
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=erp.id,
                desired=DesiredDeployment(release_ref="erp@1"),
                descriptor_path=_PATH,
                params={"image_repository": _LOOP},
                expected_desired_revision=0,
            ),
            release_source=source,
        )


def test_a_pull_image_needs_the_stored_allowlist_at_set_and_propose(
    db: Session,
) -> None:
    source = FakeSource(pull=True)
    erp = _register(db)
    with pytest.raises(ReleaseDescriptorRefusedError, match="release_image_mismatch"):
        _desired(db, erp.id, source, repo=_REPO)
    _set(db, "public_pull_repositories", [_REPO])
    _desired(db, erp.id, source, repo=_REPO)
    image = _binding_of(_propose(db, erp.id, source, DeployPlanInputs(900)))["images"][
        0
    ]
    assert (image["source"], image["planned_repository"]) == ("pull", _REPO)
    _set(db, "public_pull_repositories", [])
    with pytest.raises(ReleaseDescriptorRefusedError, match="public_pull_repositories"):
        _propose(db, erp.id, source, DeployPlanInputs(900))


# ── The release descriptor: one refusal test per code ───────────────────────


def test_descriptor_digest_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    source.attested_override = "sha256:" + "9" * 64
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, source)
    assert info.value.code == "descriptor_digest_mismatch"


def test_release_image_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    erp = _register(db)
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(db, erp.id, source, repo="127.0.0.1:5000/team/other")
    assert info.value.code == "release_image_mismatch"
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(
            db,
            erp.id,
            source,
            params={"image_repository": _LOOP, "image_digest": "sha256:" + "2" * 64},
        )
    assert info.value.code == "release_image_mismatch"
    other = [{"service": "app", "repository": _REPO, "digest": "sha256:" + "2" * 64}]
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(db, erp.id, source, images=other)
    assert info.value.code == "release_image_mismatch"
    assert db.get(DeploymentTarget, erp.id).desired_images is None


def test_product_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    source.product_override = "someone-else"
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, source)
    assert info.value.code == "descriptor_product_mismatch"
    other = FakeSource(text=_descriptor_text().replace(_ERP, "other-app"))
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, other, ref=_E + "x")
    assert info.value.code == "descriptor_product_mismatch"


def test_the_companion_path_rule_holds_through_the_release_source(db: Session) -> None:
    text = _descriptor_text(product=_COMPANION, legacy=True)
    source = FakeSource(text=text)
    source.texts[_CPATH] = source.texts.pop(_PATH)
    _set(
        db,
        "legacy_env_file_allowed_targets",
        [_C + "host-a"],
    )
    with pytest.raises(DeployUnitError, match="companion"):
        _bound_target(
            db,
            source,
            ref=_C + "host-a",
            product=_COMPANION,
            path=_CPATH,
        )


def test_an_unavailable_source_fails_closed(db: Session) -> None:
    erp = _register(db)
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _desired(db, erp.id, None)
    source = FakeSource()
    source.unavailable = True
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _desired(db, erp.id, source)
    with pytest.raises(PlanRefusedError, match="descriptor_path"):
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=erp.id,
                desired=DesiredDeployment(release_ref="erp@1"),
                params={"workers": 2},
            ),
        )
    with pytest.raises(PlanRefusedError, match="reserved"):
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=erp.id,
                desired=DesiredDeployment(
                    release_ref="erp@1", spec={"deploy_unit": {"params": {}}}
                ),
            ),
        )


def test_desired_state_keeps_only_the_digest_the_pins_and_the_values(
    db: Session,
) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    view = get_target(db, erp.id)
    unit = view.desired_spec["deploy_unit"]
    assert unit["descriptor_digest"] == _unit_digest(source)
    assert unit["source_revision"] == _REV
    assert unit["params"]["workers"] == "2"
    assert unit["params"]["image_digest"] == _D1
    assert view.desired_images is not None
    assert view.desired_images[0].repository == _REPO
    assert "dotmac.deploy_unit" not in repr(view.desired_spec)
    assert "pre_staged" not in repr(view.desired_spec)


def test_propose_re_resolves_and_refuses_when_the_release_moved(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    before = source.calls
    assert _propose(db, erp.id, source).plan_digest
    assert source.calls > before, "propose did not re-resolve the descriptor"
    original = source.text
    source.set_text(original + "\n# edited\n")
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose(db, erp.id, source)
    assert info.value.code == "descriptor_digest_mismatch"
    source.set_text(original)
    source.toml_sha = _T2
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose(db, erp.id, source)
    assert info.value.code == "descriptor_digest_mismatch"
    source.toml_sha = _T1
    source.revision = "b" * 40
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose(db, erp.id, source)
    assert info.value.code == "descriptor_evidence_mismatch"
    source.revision = _REV
    source.image_digest = "sha256:" + "7" * 64
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose(db, erp.id, source)
    assert info.value.code == "release_image_mismatch"
    source.image_digest = _D1
    source.unavailable = True
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose(db, erp.id, source)
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose(db, erp.id, None)


def test_source_revision_is_validated(db: Session) -> None:
    source = FakeSource()
    source.revision = "not-a-revision"
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, source)
    assert info.value.code == "descriptor_evidence_mismatch"


def test_product_toml_evidence_binds_the_plan_and_is_checked(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    plan = _propose(db, erp.id, source)
    assert plan.snapshot["spec"]["deploy_unit"]["product_toml_sha256"] == _T1
    assert _binding_of(plan)["product_toml_sha256"] == _T1
    row = db.get(DeploymentTarget, erp.id)
    before = plan_digest_of(plan_snapshot(row, purpose="foundation_execution"))
    spec = dict(row.desired_spec)
    spec["deploy_unit"] = {**spec["deploy_unit"], "product_toml_sha256": _T2}
    row.desired_spec = spec
    after = plan_digest_of(plan_snapshot(row, purpose="foundation_execution"))
    assert before != after
    for index, (path, absent) in enumerate(
        (("deploy/other.toml", False), (None, True))
    ):
        bad = FakeSource()
        bad.toml_path_override = path
        bad.drop_toml = absent
        with pytest.raises(ReleaseDescriptorRefusedError) as info:
            _bound_target(db, bad, ref=f"{_E}bad-{index}")
        assert info.value.code == "descriptor_evidence_mismatch"


def test_a_companion_with_no_product_toml_yet_can_be_set_but_never_planned(
    db: Session,
) -> None:
    source = FakeSource(text=_descriptor_text(product=_COMPANION))
    source.texts[_CPATH] = source.texts.pop(_PATH)
    source.drop_toml = True
    target = _bound_target(
        db,
        source,
        ref=_C + "host-a",
        product=_COMPANION,
        path=_CPATH,
    )
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose(db, target.id, source)
    assert info.value.code == "product_toml_absent"


# ── Deployment sets ─────────────────────────────────────────────────────────


def _set_fixture(db: Session, *, required: bool = False):  # type: ignore[no-untyped-def]
    source = FakeSource(companion=True, companion_required=required)
    source.texts[_CPATH] = _descriptor_text(product=_COMPANION)
    erp = _bound_target(db, source)
    integ = _bound_target(
        db,
        source,
        ref=_C + "host-a",
        product=_COMPANION,
        path=_CPATH,
    )
    return source, erp, integ, _propose(db, erp.id, source)


def test_a_deployment_set_is_validated_against_the_primary_descriptor(
    db: Session,
) -> None:
    source, _erp, integ, primary = _set_fixture(db)
    companion_plan = _propose(db, integ.id, source)
    made = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion_plan.id,
        ),
        release_source=source,
    )
    assert (
        made.set_digest
        == DeploymentSet(primary.plan_digest, companion_plan.plan_digest).set_digest()
    )
    assert made.required_at_switch is False
    again = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion_plan.id,
        ),
        release_source=source,
    )
    assert again.id == made.id
    assert get_deployment_set(db, made.id) == made
    assert list_deployment_sets(db) == (made,)
    with pytest.raises(PlanRefusedError, match="not a companion"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(
                command_id=_cmd(),
                primary_plan_id=primary.id,
                companion_plan_id=primary.id,
            ),
            release_source=source,
        )


def test_set_membership_refusals(db: Session) -> None:
    source, erp, integ, primary = _set_fixture(db, required=True)
    # required_at_switch comes from the descriptor: a primary that requires its
    # companion cannot form a set without one.
    with pytest.raises(PlanRefusedError, match="requires its companion"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(command_id=_cmd(), primary_plan_id=primary.id),
            release_source=source,
        )
    companion_plan = _propose(db, integ.id, source)
    made = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion_plan.id,
        ),
        release_source=source,
    )
    assert made.required_at_switch is True
    # A plan for an unrelated product is not the descriptor's companion.
    other_src = FakeSource(text=_descriptor_text())
    other_src.texts[_PATH] = _descriptor_text()
    stranger = _bound_target(db, other_src, ref=_E + "stranger")
    stranger_plan = _propose(db, stranger.id, other_src)
    with pytest.raises(PlanRefusedError, match="not a companion"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(
                command_id=_cmd(),
                primary_plan_id=primary.id,
                companion_plan_id=stranger_plan.id,
            ),
            release_source=source,
        )
    # An unbound plan cannot be a member.
    plain = _plain_target(db, _E + "plain")
    unbound = _propose(db, plain.id, source, None)
    with pytest.raises(PlanRefusedError, match="no deploy binding"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(command_id=_cmd(), primary_plan_id=unbound.id),
            release_source=source,
        )
    # A superseded plan is no longer live (a new desired state, then a new plan).
    _desired(db, erp.id, source)
    _propose(db, erp.id, source)
    with pytest.raises(PlanRefusedError, match="not live"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(command_id=_cmd(), primary_plan_id=primary.id),
            release_source=source,
        )


def _evidence(digest: str, **overrides: object) -> ApprovalEvidence:
    args: dict[str, object] = {
        "policy_code": "deployment.production",
        "policy_version": 4,
        "decision_ref": "decision-1",
        "content_digest": digest,
        "decided_at": datetime.now(UTC),
        "approver_refs": ("operator",),
        "decision_status": "granted",
    }
    args.update(overrides)
    return ApprovalEvidence(**args)  # type: ignore[arg-type]


def _made_set(db: Session):  # type: ignore[no-untyped-def]
    source, erp, integ, primary = _set_fixture(db)
    companion_plan = _propose(db, integ.id, source)
    made = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion_plan.id,
        ),
        release_source=source,
    )
    return source, erp, integ, primary, companion_plan, made


def _approve_set(db, set_id, evidence):  # type: ignore[no-untyped-def]
    return approve_deployment_set(
        db,
        ApproveDeploymentSetCommand(
            command_id=_cmd(), set_id=set_id, evidence=evidence
        ),
    )


def test_an_approval_is_bound_to_the_set_digest(db: Session) -> None:
    _source, _erp, _integ, primary, _comp, made = _made_set(db)
    with pytest.raises(ApprovalRefusedError, match="different set digest"):
        _approve_set(db, made.id, _evidence("sha256:" + "0" * 64))
    with pytest.raises(ApprovalRefusedError, match="not a set digest"):
        _approve_set(db, made.id, _evidence("nope"))
    # The PLAN digest is not the set digest.
    with pytest.raises(ApprovalRefusedError, match="different set digest"):
        _approve_set(db, made.id, _evidence(primary.plan_digest))
    assert _approve_set(db, made.id, _evidence(made.set_digest)).id == made.id


def test_a_set_approval_accepts_no_less_than_a_plan_approval(db: Session) -> None:
    """R2-M1: revoked, unstated and denied decisions never become a fact."""
    _source, _erp, _integ, _primary, _comp, made = _made_set(db)
    with pytest.raises(ApprovalRefusedError, match="standing 'revoked'"):
        _approve_set(db, made.id, _evidence(made.set_digest, decision_status="revoked"))
    with pytest.raises(ApprovalRefusedError, match="does not say what the decision"):
        _approve_set(db, made.id, _evidence(made.set_digest, decision_status=None))
    with pytest.raises(ApprovalRefusedError, match="not a decision standing"):
        _approve_set(db, made.id, _evidence(made.set_digest, decision_status="denied"))
    with pytest.raises(ApprovalRefusedError, match="not proposed under"):
        _approve_set(db, made.id, _evidence(made.set_digest, policy_version=9))
    with pytest.raises(ApprovalRefusedError, match="not proposed under"):
        _approve_set(
            db, made.id, _evidence(made.set_digest, policy_code="other.policy")
        )
    with pytest.raises(ApprovalRefusedError, match="names no decision"):
        _approve_set(db, made.id, _evidence(made.set_digest, decision_ref=" "))
    assert not _approved_facts(db), "a refused approval emitted the fact"


def _approved_facts(db: Session) -> list[object]:
    from dotmac_kernel.messaging.models import PlatformOutboxEvent

    return list(
        db.execute(
            select(PlatformOutboxEvent).where(
                PlatformOutboxEvent.event_type == "deployment.set.approved.v1"
            )
        )
        .scalars()
        .all()
    )


def test_a_set_approval_refuses_a_non_live_member_plan(db: Session) -> None:
    _source, erp, _integ, _primary, _comp, made = _made_set(db)
    # A newer plan for the primary supersedes it: the set's member is no longer live.
    _desired(db, erp.id, _source)
    _propose(db, erp.id, _source)
    with pytest.raises(ApprovalRefusedError, match="not live"):
        _approve_set(db, made.id, _evidence(made.set_digest))
    assert not _approved_facts(db)


def test_a_set_is_approved_once(db: Session) -> None:
    _source, _erp, _integ, _primary, _comp, made = _made_set(db)
    _approve_set(db, made.id, _evidence(made.set_digest))
    assert len(_approved_facts(db)) == 1
    with pytest.raises(ApprovalRefusedError, match="already has an approval"):
        _approve_set(db, made.id, _evidence(made.set_digest, decision_ref="decision-2"))
    assert len(_approved_facts(db)) == 1
    fact = _approved_facts(db)[0]
    assert fact.payload["authoritative"] is False  # type: ignore[attr-defined]


def test_preview_shows_no_digest_for_a_descriptor_backed_target(db: Session) -> None:
    """R2-L1: propose can never produce the binding-less digest, so none is shown."""
    from dotmac_deployment_control import preview_plan_proposal

    source = FakeSource()
    backed = _bound_target(db, source)
    shown = preview_plan_proposal(db, backed.id)
    assert shown is not None
    assert shown.binding_derived_at_propose is True
    assert shown.plan_digest == ""
    plain = _plain_target(db, _E + "plain")
    unbound = preview_plan_proposal(db, plain.id)
    assert unbound is not None
    assert unbound.binding_derived_at_propose is False
    assert unbound.plan_digest.startswith("sha256:")


def test_a_pull_image_refuses_a_loopback_port(db: Session) -> None:
    """R2-L3: a pulled image has no loopback registry, so a port is an error."""
    source = FakeSource(pull=True)
    erp = _register(db)
    _set(db, "public_pull_repositories", [_REPO])
    _desired(db, erp.id, source, repo=_REPO)
    with pytest.raises(PlanRefusedError, match="no loopback registry"):
        _propose(db, erp.id, source, DeployPlanInputs(900, 5000))
    assert _propose(db, erp.id, source, DeployPlanInputs(900))


def test_set_members_must_match_their_frozen_descriptor_and_host(
    db: Session,
) -> None:
    """R2-L4: a set is validated against each plan's frozen descriptor digest."""
    source, _erp, integ, primary = _set_fixture(db)
    companion_plan = _propose(db, integ.id, source)
    # The primary descriptor changes after the plans were frozen (new release).
    source.set_text(source.text + "\n# changed\n")
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(
                command_id=_cmd(),
                primary_plan_id=primary.id,
                companion_plan_id=companion_plan.id,
            ),
            release_source=source,
        )
    assert info.value.code == "descriptor_digest_mismatch"


def test_the_companion_must_run_on_the_declared_host(db: Session) -> None:
    source = FakeSource(companion=True)
    source.texts[_CPATH] = _descriptor_text(product=_COMPANION)
    erp = _bound_target(db, source)
    elsewhere = _bound_target(
        db,
        source,
        ref=_C + "other-host",
        product=_COMPANION,
        path=_CPATH,
    )
    primary = _propose(db, erp.id, source)
    companion_plan = _propose(db, elsewhere.id, source)
    with pytest.raises(PlanRefusedError, match="not on 'host-a'"):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(
                command_id=_cmd(),
                primary_plan_id=primary.id,
                companion_plan_id=companion_plan.id,
            ),
            release_source=source,
        )


def test_active_binding_roles_are_derived_and_bound_into_the_plan(db: Session) -> None:
    """R3: roles minting secret_ids come from the verified descriptor, signed."""
    text = _descriptor_text(active=("API_SECRET", "DB_PASSWORD"))
    source = FakeSource(text=text)
    erp = _bound_target(db, source)
    binding = _binding_of(_propose(db, erp.id, source))
    assert binding["roles"] == [
        {"role": "app", "single_use": False},
        {"role": "db", "single_use": False},
    ]
    assert binding["primary_service"] == "dotmac-erp-v2"
    # The OpenBao naming comes from the descriptor and the target, in the plan.
    assert binding["secrets_namespace"] == "erp"
    assert binding["secrets_environment"] == "prod"


def test_a_descriptor_backed_target_ref_is_tied_to_product_and_environment(
    db: Session,
) -> None:
    """R3-L6: the ref the API routes on names the same product and environment."""
    source = FakeSource()
    for ref in (
        "erp/prod/host-a",
        "dotmac-erp-v2/staging/host-a",
        "dotmac-erp-v2/production",
    ):
        target = _register(db, ref)
        with pytest.raises(PlanRefusedError, match=r"<product_code>/<environment>"):
            _desired(db, target.id, source)
        assert "deploy_unit" not in get_target(db, target.id).desired_spec
    # A plain (non-descriptor) target is unaffected.
    assert _plain_target(db, "legacy-style-ref")


def test_a_published_test_key_cannot_be_enrolled(db: Session) -> None:
    """R3-L7: the vector file's public keys authenticate nobody."""
    from dotmac_deployment_control import EnrolCredentialCommand, enrol_credential
    from dotmac_deployment_control.target_api import DENIED_PUBLIC_KEYS_B64U

    target = _register(db)
    for index, key in enumerate(sorted(DENIED_PUBLIC_KEYS_B64U)):
        with pytest.raises(Exception, match="published test seed"):
            enrol_credential(
                db,
                EnrolCredentialCommand(
                    command_id=_cmd(),
                    target_id=target.id,
                    key_id=f"vector-key-{index}",
                    algorithm="ed25519",
                    public_key_b64=key,
                    enrollment_authority="platform_admin_policy",
                ),
            )


def test_a_job_material_nothing_supplies_is_refused_at_propose(db: Session) -> None:
    """C-3: a job's material must come from a param, an active binding or the
    legacy names of THIS plan, so the gap fails at plan time, not mid-deploy."""
    source = FakeSource(job_materials=("DB_PASSWORD",))
    erp = _bound_target(db, source)
    # DB_PASSWORD is only a PRE-STAGED binding: it delivers nothing yet.
    with pytest.raises(PlanMaterialUnsuppliedError, match="DB_PASSWORD"):
        _propose(db, erp.id, source, _PLAIN)
    # A param material supplies it.
    by_param = FakeSource(job_materials=("WORKERS",))
    ok = _bound_target(db, by_param, ref=_E + "host-p")
    assert _propose(db, ok.id, by_param, _PLAIN)
    # An ACTIVE binding supplies it.
    active = FakeSource(job_materials=("DB_PASSWORD",), active=("DB_PASSWORD",))
    got = _bound_target(db, active, ref=_E + "host-b")
    assert _propose(db, got.id, active, _PLAIN)


def test_a_legacy_name_supplies_a_job_material(db: Session) -> None:
    source = FakeSource(legacy=True, job_materials=("DB_PASSWORD",))
    erp = _legacy_target(db, source)
    _enable(db, erp.id, source)
    assert _propose(db, erp.id, source, _PLAIN)


def test_the_legacy_exit_must_be_pre_staged_in_the_descriptor(db: Session) -> None:
    """C-4: exit_prestaged is derived, not an operator bool."""
    source = FakeSource(legacy=True, omit_bindings=("DB_PASSWORD",))
    erp = _legacy_target(db, source)
    with pytest.raises(LegacyPolicyRefusedError, match="pre-staged"):
        _enable(db, erp.id, source)
    assert get_legacy_policy(db, erp.id) is None
    # Names that DO have pre-staged bindings enable; the claim is not a field.
    assert "exit_prestaged" not in EnableLegacyPolicyCommand.__dataclass_fields__
    _set(db, "legacy_env_file_allowed_targets", [_REF, _E + "host-s"])
    _set(db, "legacy_env_file_ceiling", 2)
    staged = FakeSource(legacy=True)
    other = _bound_target(db, staged, ref=_E + "host-s")
    assert _enable(db, other.id, staged).state == "enabled"


def test_the_namespace_env_is_fixed_at_registration(db: Session) -> None:
    """V-1: the OpenBao namespace-env is a fact about the TARGET, from either CP
    environment spelling, fixed at registration and never assumed."""
    from dotmac_deployment_control.ports import TransitionRefusedError

    for env, expected in (
        ("production", "prod"),
        ("prod", "prod"),
        ("staging", "staging"),
    ):
        view = _register(db, f"dotmac-erp-v2/{env}/host-1", env=env)
        assert db.get(DeploymentTarget, view.id).bao_environment == expected
    # An environment the table does not know has none until it is stated.
    odd = _register(db, "dotmac-erp-v2/pilot/host-1", env="pilot")
    assert db.get(DeploymentTarget, odd.id).bao_environment is None
    with pytest.raises(PlanRefusedError, match="namespace-env"):
        _desired(db, odd.id, FakeSource())
    stated = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref="dotmac-erp-v2/pilot/host-2",
            subject_ref="acme-operator",
            product_code=_ERP,
            environment="pilot",
            secrets_environment="pilot",
        ),
    )
    assert db.get(DeploymentTarget, stated.id).bao_environment == "pilot"
    assert _desired(db, stated.id, FakeSource())
    with pytest.raises(TransitionRefusedError, match="lowercase segment"):
        register_target(
            db,
            RegisterTargetCommand(
                command_id=_cmd(),
                target_ref="dotmac-erp-v2/pilot/host-3",
                subject_ref="acme-operator",
                product_code=_ERP,
                environment="pilot",
                secrets_environment="Bad Env",
            ),
        )
    # A target registered under the `prod` spelling is descriptor-backed too.
    assert _desired(
        db,
        _register(db, _E.replace("production", "prod") + "host-9", env="prod").id,
        FakeSource(),
    )


def test_an_explicit_namespace_env_may_not_contradict_a_known_default(
    db: Session,
) -> None:
    """R5-3: explicit values are for environments the table does not list."""
    from dotmac_deployment_control.ports import TransitionRefusedError

    for env, wrong in (
        ("staging", "prod"),
        ("production", "staging"),
        ("prod", "staging"),
    ):
        with pytest.raises(TransitionRefusedError, match="contradicts"):
            register_target(
                db,
                RegisterTargetCommand(
                    command_id=_cmd(),
                    target_ref=f"dotmac-erp-v2/{env}/host-x",
                    subject_ref="acme-operator",
                    product_code=_ERP,
                    environment=env,
                    secrets_environment=wrong,
                ),
            )
    # Equal to the default is fine, and an unlisted environment takes its own.
    for env, same in (("staging", "staging"), ("production", "prod")):
        view = register_target(
            db,
            RegisterTargetCommand(
                command_id=_cmd(),
                target_ref=f"dotmac-erp-v2/{env}/host-y",
                subject_ref="acme-operator",
                product_code=_ERP,
                environment=env,
                secrets_environment=same,
            ),
        )
        assert db.get(DeploymentTarget, view.id).bao_environment == same


def _a17_target(db: Session, ref: str, env: str):  # type: ignore[no-untyped-def]
    """A target registered before `bao_environment` existed: the column is NULL."""
    view = _register(db, ref, env=env)
    row = db.get(DeploymentTarget, view.id)
    row.bao_environment = None
    db.flush()
    return view


def test_the_namespace_env_is_set_once_while_null(db: Session) -> None:
    """R5-2: the one-time attended writer for targets registered under a17."""
    from dotmac_deployment_control import SetBaoEnvironmentCommand, set_bao_environment
    from dotmac_deployment_control.ports import TransitionRefusedError

    def command(target_id, value, approval=_ATTENDED):  # type: ignore[no-untyped-def]
        return SetBaoEnvironmentCommand(
            command_id=_cmd(),
            target_id=target_id,
            bao_environment=value,
            approval=approval,
        )

    old = _a17_target(db, _E + "host-old", "production")
    # Not descriptor-backed until it has one.
    with pytest.raises(PlanRefusedError, match="namespace-env"):
        _desired(db, old.id, FakeSource())
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        set_bao_environment(db, command(old.id, "prod", _UNATTENDED))
    with pytest.raises(TransitionRefusedError, match="contradicts"):
        set_bao_environment(db, command(old.id, "staging"))
    with pytest.raises(TransitionRefusedError, match="lowercase segment"):
        set_bao_environment(db, command(old.id, "Prod"))
    assert db.get(DeploymentTarget, old.id).bao_environment is None
    set_bao_environment(db, command(old.id, "prod"))
    assert db.get(DeploymentTarget, old.id).bao_environment == "prod"
    # Fixed once set: a second writer is refused, even with the same value.
    for value in ("prod", "staging"):
        with pytest.raises(TransitionRefusedError, match="fixed once set"):
            set_bao_environment(db, command(old.id, value))
    assert _desired(db, old.id, FakeSource())
    # A target registered with a value cannot be re-pointed either.
    fresh = _register(db, _E + "host-new")
    with pytest.raises(TransitionRefusedError, match="fixed once set"):
        set_bao_environment(db, command(fresh.id, "prod"))
    # An unlisted environment states its own, once.
    pilot = _a17_target(db, "dotmac-erp-v2/pilot/host-1", "pilot")
    set_bao_environment(db, command(pilot.id, "pilot"))
    assert db.get(DeploymentTarget, pilot.id).bao_environment == "pilot"


def test_a_plan_with_roles_needs_the_targets_namespace_env(db: Session) -> None:
    """Propose refuses when roles exist and `bao_environment` is NULL."""
    from dotmac_deployment_control import SetBaoEnvironmentCommand, set_bao_environment

    roles = FakeSource(text=_descriptor_text(active=("API_SECRET", "DB_PASSWORD")))
    erp = _bound_target(db, roles)
    row = db.get(DeploymentTarget, erp.id)
    row.bao_environment = None  # a target registered before the column existed
    db.flush()
    with pytest.raises(PlanRefusedError, match="namespace-env"):
        _propose(db, erp.id, roles)
    set_bao_environment(
        db,
        SetBaoEnvironmentCommand(
            command_id=_cmd(),
            target_id=erp.id,
            bao_environment="prod",
            approval=_ATTENDED,
        ),
    )
    binding = _binding_of(_propose(db, erp.id, roles))
    assert (binding["secrets_namespace"], binding["secrets_environment"]) == (
        "erp",
        "prod",
    )
    # No roles, nothing to mint: a NULL namespace-env still plans, carrying null.
    quiet = FakeSource()
    other = _bound_target(db, quiet, ref=_E + "host-q")
    db.get(DeploymentTarget, other.id).bao_environment = None
    db.flush()
    binding = _binding_of(_propose(db, other.id, quiet))
    assert binding["roles"] == []
    assert binding["secrets_namespace"] == "erp"
    assert binding["secrets_environment"] is None


# ── Import-only OpenBao ─────────────────────────────────────────────────────


_ARGS = {"--mode": "execute"}
_JP = {"import_approved": "true", "import_payable": "acct.net-payable"}
_JOB = DeployPlanInputs(
    lease_ttl_seconds=900,
    loopback_port=5000,
    job="import",
    job_args=_ARGS,
    job_params=_JP,
)
#: A job plan for a role-less descriptor job (no declared args or params).
_PLAIN = DeployPlanInputs(lease_ttl_seconds=900, loopback_port=5000, job="import")


def _open_window(db: Session, target_id, window_id: str = "w1"):  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    return svc.open_role_job_window(
        db,
        svc.OpenRoleJobWindowCommand(
            command_id=_cmd(),
            target_id=target_id,
            role="import",
            window_id=window_id,
            closes_at=now + timedelta(hours=1),
            hard_stop_at=now + timedelta(hours=2),
            approval=_ATTENDED,
        ),
    )


def _import_params(**extra: str) -> dict[str, str]:
    # Job-scoped values are per-dispatch (`_JP`), never stored desired state.
    return {"image_repository": _LOOP, **extra}


def _import_target(db: Session, source: FakeSource, ref: str = _E + "host-i"):  # type: ignore[no-untyped-def]
    target = _register(db, ref)
    _desired(db, target.id, source, params=_import_params())
    _open_window(db, target.id)
    return target


def test_a_job_role_is_derived_for_the_job_only_and_its_params_are_scoped(
    db: Session,
) -> None:
    from dotmac_deployment_control.deploy_unit import (
        canonical_job_render,
        canonical_render,
        params_env_digest,
        parse_deploy_unit,
    )

    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    serving = _binding_of(_propose(db, erp.id, source))
    # F1: a serving plan binds no job. It mints `migrate` only; `import` belongs
    # to the job. F7: the serving names exclude the import-only credential.
    assert serving["roles"] == [{"role": "migrate", "single_use": True}]
    assert serving["dispatched_job"] is None
    assert serving["active_binding_names"] == ["MIGRATION_DATABASE_URL"]
    assert serving["job_binding_names"] == [
        "LEGACY_DATABASE_URL",
        "MIGRATION_DATABASE_URL",
    ]
    binding = _binding_of(_propose(db, erp.id, source, _JOB))
    # A dispatch plan binds exactly ONE job and mints no serving role (F1).
    assert binding["roles"] == []
    assert binding["companion_order"] is None
    job = binding["dispatched_job"]
    assert job["name"] == "import"
    # E2: the closed argv (command + declared args) is in the signed binding.
    assert job["argv"] == ["run", "import", "--mode", "execute"]
    assert job["timeout_seconds"] == 600
    assert job["window"]["window_id"] == "w1"
    assert job["window"]["closes_at"].endswith("Z")
    assert job["role"] == "import"
    assert job["single_use"] is True  # P-SEC rev4: one secret_id per dispatched run
    assert job["materials"] == [
        "ERP_IMPORT_APPROVED",
        "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF",
        "LEGACY_DATABASE_URL",
        "MIGRATION_DATABASE_URL",
    ]
    assert job["params"] == _JP
    unit = parse_deploy_unit(source.text)
    params = get_target(db, erp.id).desired_spec["deploy_unit"]["params"]
    assert "import_approved" not in params  # per dispatch, never stored
    image = f"{_LOOP}@{_D1}"
    app = canonical_render(unit, params, app_image=image, environment="production")
    assert app == f"APP_IMAGE={image}\nWORKERS=2\n".encode()
    assert binding["params_env_digest"] == params_env_digest(app)
    job_render = canonical_job_render(
        unit, _JP, job_name="import", environment="production"
    )
    assert job_render == (
        b"ERP_IMPORT_APPROVED=true\n"
        b"ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF=acct.net-payable\n"
    )
    assert job["params_env_digest"] == params_env_digest(job_render)
    assert binding["secrets_environment"] == "prod"


def test_job_scoped_values_move_the_job_digest_and_the_plan_not_the_app_digest(
    db: Session,
) -> None:
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    first = _propose(db, erp.id, source, _JOB)
    # M1: the value is a per-dispatch input, never desired state.
    other = DeployPlanInputs(
        900,
        5000,
        "import",
        _ARGS,
        {**_JP, "import_payable": "other-acct"},
    )
    second = _propose(db, erp.id, source, other)
    assert _binding_of(second)["dispatched_job"]["params"]["import_payable"] == (
        "other-acct"
    )
    # A gate defaults to "0" when it is not entered.
    bare = DeployPlanInputs(900, 5000, "import", _ARGS, {"import_payable": "x"})
    assert (
        _binding_of(_propose(db, erp.id, source, bare))["dispatched_job"]["params"][
            "import_approved"
        ]
        == "false"
    )
    # Stored as desired state, a job-scoped param is refused outright.
    with pytest.raises(Exception, match="per-dispatch"):
        _desired(db, erp.id, source, params=_import_params(import_approved="true"))
    a, b = _binding_of(first), _binding_of(second)
    assert a["params_env_digest"] == b["params_env_digest"]
    assert (
        a["dispatched_job"]["params_env_digest"]
        != b["dispatched_job"]["params_env_digest"]
    )
    assert first.plan_digest != second.plan_digest


def test_the_job_scope_is_covered_by_the_plan_digest(db: Session) -> None:
    scoped = FakeSource(import_job=True, import_scoped=True)
    one = _import_target(db, scoped, _E + "host-s1")
    binding = _binding_of(_propose(db, one.id, scoped, _JOB))
    assert binding["dispatched_job"]["params"] == _JP
    assert binding["dispatched_job"]["materials"]
    # Unscoped, the same params would be APP materials and so could not supply
    # the role job: the plan is refused rather than leaking them into the app.
    unscoped = FakeSource(import_job=True, import_scoped=False)
    two = _import_target(db, unscoped, _E + "host-s2")
    with pytest.raises(PlanMaterialUnsuppliedError, match="ERP_IMPORT_APPROVED"):
        _propose(db, two.id, unscoped, DeployPlanInputs(900, 5000, "import", _ARGS))


def test_a_role_job_needs_an_active_role_binding_and_scoped_params(
    db: Session,
) -> None:
    pre = FakeSource(import_job=True, import_active=False)
    erp = _import_target(db, pre)
    with pytest.raises(PlanMaterialUnsuppliedError, match="no ACTIVE binding"):
        _propose(db, erp.id, pre, _JOB)
    # A serving plan binds no job, so it is not held up by the pre-staged import.
    assert _binding_of(_propose(db, erp.id, pre))["dispatched_job"] is None
    # A material of the role job that nothing supplies is still refused (C-3).
    loose = FakeSource(import_job=True, import_extra_material="WORKERS")
    other = _import_target(db, loose, _E + "host-l")
    with pytest.raises(PlanMaterialUnsuppliedError, match="WORKERS"):
        _propose(db, other.id, loose, _JOB)


def test_no_boot_or_legacy_fallback_supplies_a_job_credential(db: Session) -> None:
    """A job's credentials come only from its role's mint: a legacy name, an
    app param or an active binding of ANOTHER role never supply them."""
    source = FakeSource(
        legacy=True,
        import_job=True,
        import_active=True,
    )
    _set(db, "legacy_env_file_allowed_targets", [_E + "host-f"])
    _set(db, "legacy_env_file_ceiling", 1)
    erp = _register(db, _E + "host-f")
    _desired(db, erp.id, source, params=_import_params())
    _enable(db, erp.id, source)
    plan = _binding_of(_propose(db, erp.id, source))
    # The policy's names are the legacy file's; none is a job credential.
    assert plan["legacy"]["names"] == ["API_SECRET", "DB_PASSWORD"]
    assert not {"MIGRATION_DATABASE_URL", "LEGACY_DATABASE_URL"} & set(
        plan["legacy"]["names"]
    )


def test_a_job_role_needs_the_targets_namespace_env(db: Session) -> None:
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    db.get(DeploymentTarget, erp.id).bao_environment = None
    db.flush()
    with pytest.raises(PlanRefusedError, match="namespace-env"):
        _propose(db, erp.id, source)


def test_a_job_lease_is_its_timeout_plus_120_under_the_target_ceiling(
    db: Session,
) -> None:
    """H1: lease = timeout + 120, refused over the per-target ceiling (default
    900, hard maximum 3600, attended). A caller's TTL does not set it."""
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    plan = _propose(db, erp.id, source, _JOB)
    assert _binding_of(plan)["lease_ttl_seconds"] == 720
    assert _binding_of(plan)["dispatched_job"]["timeout_seconds"] == 600
    # A serving plan is not capped by the job ceiling.
    serving = _propose(db, erp.id, source, DeployPlanInputs(3600, 5000))
    assert _binding_of(serving)["lease_ttl_seconds"] == 3600
    # A 23-minute job does not fit the default ceiling...
    long_text = _descriptor_text(import_job=True).replace(
        "timeout_seconds = 600\n", "timeout_seconds = 1800\n"
    )
    slow = FakeSource(long_text)
    other = _import_target(db, slow, _E + "host-long")
    with pytest.raises(PlanRefusedError, match="ceiling of 900s"):
        _propose(db, other.id, slow, _JOB)
    # ...until an attended setting raises THIS target's ceiling.
    with pytest.raises(Exception, match="seconds"):
        _set(db, "role_job_lease_ceiling_seconds", {other.target_ref: 3601})
    _set(db, "role_job_lease_ceiling_seconds", {other.target_ref: 2000})
    long_plan = _propose(db, other.id, slow, _JOB)
    assert _binding_of(long_plan)["lease_ttl_seconds"] == 1920
    # Another target keeps the default.
    with pytest.raises(PlanRefusedError, match="ceiling of 900s"):
        third = _import_target(db, FakeSource(long_text), _E + "host-long2")
        _propose(db, third.id, FakeSource(long_text), _JOB)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        _set(
            db,
            "role_job_lease_ceiling_seconds",
            {other.target_ref: 2000},
            approval=_UNATTENDED,
        )


def test_a_dispatch_plan_names_one_existing_job(db: Session) -> None:
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    with pytest.raises(PlanRefusedError, match="no job"):
        _propose(db, erp.id, source, DeployPlanInputs(900, 5000, job="ghost"))
    one = _propose(db, erp.id, source, _JOB)
    assert _binding_of(one)["dispatched_job"]["name"] == "import"
    # The plan digest covers the job: a serving plan is a different plan.
    assert one.plan_digest != _propose(db, erp.id, source).plan_digest
    # The operation and the job agree: run_job names a job, nothing else does.
    with pytest.raises(PlanRefusedError, match="belong to a run_job"):
        _propose(db, erp.id, source, DeployPlanInputs(900, 5000, None, _ARGS))
    with pytest.raises(PlanRefusedError):
        svc.propose_plan(
            db,
            ProposePlanCommand(
                command_id=_cmd(),
                target_id=erp.id,
                operation="deploy",
                descriptor_digest=_DESC,
                execution_plan_digest=_EXEC,
                purpose="foundation_execution",
                requires_approval=True,
                approval_policy_code="deployment.production",
                approval_policy_version=4,
                deploy_inputs=_JOB,
            ),
            release_source=source,
        )
    # A job plan and a deploy plan do not supersede each other.
    serving = _propose(db, erp.id, source)
    again = _propose(
        db,
        erp.id,
        source,
        DeployPlanInputs(900, 5000, "import", {"--mode": "plan"}, _JP),
    )
    assert db.get(svc.DeploymentPlan, serving.id).status == "proposed"
    assert db.get(svc.DeploymentPlan, one.id).status == "superseded"
    assert again.id != one.id


def test_a_changed_closed_argv_moves_the_plan_digest(db: Session) -> None:
    one = FakeSource(import_job=True)
    erp = _import_target(db, one)
    first = _propose(db, erp.id, one, _JOB)
    other = DeployPlanInputs(
        900, 5000, job="import", job_args={"--mode": "plan"}, job_params=_JP
    )
    second = _propose(db, erp.id, one, other)
    assert _binding_of(second)["dispatched_job"]["argv"] == [
        "run",
        "import",
        "--mode",
        "plan",
    ]
    assert first.plan_digest != second.plan_digest
    # An undeclared flag, a bad value or a missing required one is refused.
    for args in ({"--mode": "plan", "--source-url-env": "X"}, {"--mode": "x"}, {}):
        with pytest.raises(PlanRefusedError):
            _propose(db, erp.id, one, DeployPlanInputs(900, 5000, "import", args, _JP))


def test_a_role_is_all_or_nothing_active_when_minted(db: Session) -> None:
    """F3: MIGRATION active, LEGACY pre-staged: the import role is refused (its
    secret_id would render the pre-staged path too)."""
    source = FakeSource(import_job=True, import_legacy_pre_staged=True)
    erp = _import_target(db, source)
    with pytest.raises(PlanRefusedError, match="LEGACY_DATABASE_URL"):
        _propose(db, erp.id, source, _JOB)
    # The same rule guards a serving role: `migrate` is whole, so it mints.
    assert _binding_of(_propose(db, erp.id, source))["roles"] == [
        {"role": "migrate", "single_use": True}
    ]


def test_a_serving_lease_must_cover_the_hold_points(db: Session) -> None:
    source = FakeSource(import_job=True, hold=True)
    erp = _import_target(db, source)
    with pytest.raises(DeployBindingRefusedError, match="hold"):
        _propose(db, erp.id, source, DeployPlanInputs(900, 5000))
    plan = _propose(db, erp.id, source, DeployPlanInputs(1800, 5000))
    assert _binding_of(plan)["lease_ttl_seconds"] == 1800
    # A dispatch plan is not held to the serving deploy's hold points.
    assert _binding_of(_propose(db, erp.id, source, _JOB))["dispatched_job"]


# ── The role-job window ─────────────────────────────────────────────────────


def _window_cmd(target_id, **kw):  # type: ignore[no-untyped-def]
    now = datetime.now(UTC)
    base = {
        "command_id": _cmd(),
        "target_id": target_id,
        "role": "import",
        "window_id": "w9",
        "closes_at": now + timedelta(hours=1),
        "hard_stop_at": now + timedelta(hours=2),
        "approval": _ATTENDED,
    }
    base.update(kw)
    return svc.OpenRoleJobWindowCommand(**base)


def test_a_window_is_opened_attended_and_bounded_by_the_hard_stop(
    db: Session,
) -> None:
    target = _register(db, _E + "host-w1")
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        svc.open_role_job_window(db, _window_cmd(target.id, approval=_UNATTENDED))
    now = datetime.now(UTC)
    for bad in (
        {"closes_at": now - timedelta(minutes=1)},
        {"closes_at": now + timedelta(hours=3)},  # later than the hard stop
    ):
        with pytest.raises(TransitionRefusedError):
            svc.open_role_job_window(db, _window_cmd(target.id, **bad))
    rows = svc.open_role_job_window(db, _window_cmd(target.id))
    assert [(w.role, w.window_id, w.state) for w in rows] == [("import", "w9", "open")]
    # One open window per role; an id is never reused.
    with pytest.raises(TransitionRefusedError, match="already"):
        svc.open_role_job_window(db, _window_cmd(target.id, window_id="w10"))
    # The generic deploy setting can never write the windows.
    with pytest.raises(Exception, match="not a deploy setting"):
        _set(db, "role_job_windows", {})


def test_a_job_plan_is_refused_outside_an_open_window(db: Session) -> None:
    source = FakeSource(import_job=True)
    erp = _register(db, _E + "host-w2")
    _desired(db, erp.id, source, params=_import_params())
    with pytest.raises(PlanRefusedError, match="no open window"):
        _propose(db, erp.id, source, _JOB)
    _open_window(db, erp.id)
    assert _propose(db, erp.id, source, _JOB)
    # An expired window refuses too.
    original = svc._control_now
    svc._control_now = lambda: datetime.now(UTC) + timedelta(hours=5)
    try:
        with pytest.raises(PlanRefusedError, match="no open window"):
            _propose(db, erp.id, source, _JOB)
    finally:
        svc._control_now = original


def test_closing_a_window_is_permanent_and_cancels_outstanding_job_plans(
    db: Session,
) -> None:
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    job_plan = _propose(db, erp.id, source, _JOB)
    serving = _propose(db, erp.id, source)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        svc.close_role_job_window(
            db,
            svc.CloseRoleJobWindowCommand(_cmd(), erp.id, "w1", _UNATTENDED),
        )
    rows = svc.close_role_job_window(
        db, svc.CloseRoleJobWindowCommand(_cmd(), erp.id, "w1", _ATTENDED)
    )
    assert rows[0].state == "closed"
    assert db.get(svc.DeploymentPlan, job_plan.id).status == "cancelled"
    # A serving plan is not a job: closing the window leaves it alone.
    assert db.get(svc.DeploymentPlan, serving.id).status == "proposed"
    with pytest.raises(PlanRefusedError, match="no open window"):
        _propose(db, erp.id, source, _JOB)
    with pytest.raises(TransitionRefusedError, match="already closed"):
        svc.close_role_job_window(
            db, svc.CloseRoleJobWindowCommand(_cmd(), erp.id, "w1", _ATTENDED)
        )
    # Re-opening needs a NEW id; the closed one is never reused.
    with pytest.raises(TransitionRefusedError, match="already exists"):
        _open_window(db, erp.id, "w1")
    _open_window(db, erp.id, "w2")
    assert (
        _binding_of(_propose(db, erp.id, source, _JOB))["dispatched_job"]["window"][
            "window_id"
        ]
        == "w2"
    )


def test_dispatch_re_checks_the_window(db: Session) -> None:
    """The window is checked at propose AND at dispatch."""
    source = FakeSource(import_job=True)
    erp = _import_target(db, source)
    plan = db.get(svc.DeploymentPlan, _propose(db, erp.id, source, _JOB).id)
    target = db.get(DeploymentTarget, erp.id)
    svc._require_window_for_plan(db, target, plan)  # open: passes
    svc.close_role_job_window(
        db, svc.CloseRoleJobWindowCommand(_cmd(), erp.id, "w1", _ATTENDED)
    )
    # (the close cancelled the plan; dispatch of a stale approval still refuses)
    with pytest.raises(TransitionRefusedError, match="no open window"):
        svc._require_window_for_plan(db, target, plan)
    # A deploy plan has no window to check.
    serving = db.get(svc.DeploymentPlan, _propose(db, erp.id, source).id)
    svc._require_window_for_plan(db, target, serving)
