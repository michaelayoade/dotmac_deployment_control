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
    PlanRefusedError,
    ReleaseDescriptorEvidence,
    ReleaseDescriptorRefusedError,
    ReleaseDescriptorUnavailableError,
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
_REF = "erp/prod/host-a"
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
) -> str:
    spec = (
        "deploy/companion/product.toml"
        if product == _COMPANION
        else "deploy/product.toml"
    )
    out = (
        'schema = "dotmac.deploy_unit/1"\n'
        f'product = "{product}"\nspec = "{spec}"\n'
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
            state = "" if name in active else 'state = "pre_staged"\n'
            out += (
                f'[[bindings]]\nname = "{name}"\n{state}kind = "key"\n'
                'roles = ["app"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
                "single_use = false\n"
            )
    if companion:
        out += (
            f'[[companions]]\nproduct = "{_COMPANION}"\ndescriptor = "{_CPATH}"\n'
            'order = "after_primary_ready"\n'
            f"required_at_switch = {str(companion_required).lower()}\n"
            'host = "same"\n'
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
        "exit_prestaged": True,
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
            operation="deploy",
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
        _bound_target(db, source, ref="erp/prod/denied")
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
    _set(db, "legacy_env_file_allowed_targets", [_REF, "erp/prod/host-b"])
    second = _bound_target(db, other, ref="erp/prod/host-b")
    _enable(db, erp.id, source)
    with pytest.raises(LegacyPolicyRefusedError, match="ceiling"):
        _enable(db, second.id, other)
    # A companion path is refused whatever the allowlist says.
    companion = FakeSource(text=_descriptor_text(product=_COMPANION))
    companion.texts[_CPATH] = companion.texts.pop(_PATH)
    _set(db, "legacy_env_file_allowed_targets", [_REF, "integrator/prod/host-a"])
    ctarget = _bound_target(
        db, companion, ref="integrator/prod/host-a", product=_COMPANION, path=_CPATH
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
    plain = _plain_target(db, "erp/prod/plain")
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
    _set(db, "legacy_env_file_allowed_targets", [_REF, "erp/prod/tmp"])
    _set(db, "legacy_env_file_ceiling", 1)
    # An ACTIVE binding on a legacy name collides at parse already (L2).
    with pytest.raises(DeployUnitError, match="collide"):
        _bound_target(db, source, ref="erp/prod/tmp")
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
        _bound_target(db, other, ref="erp/prod/x")
    assert info.value.code == "descriptor_product_mismatch"


def test_the_companion_path_rule_holds_through_the_release_source(db: Session) -> None:
    text = _descriptor_text(product=_COMPANION, legacy=True)
    source = FakeSource(text=text)
    source.texts[_CPATH] = source.texts.pop(_PATH)
    _set(db, "legacy_env_file_allowed_targets", ["integrator/prod/host-a"])
    with pytest.raises(DeployUnitError, match="companion"):
        _bound_target(
            db, source, ref="integrator/prod/host-a", product=_COMPANION, path=_CPATH
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
            _bound_target(db, bad, ref=f"erp/prod/bad-{index}")
        assert info.value.code == "descriptor_evidence_mismatch"


def test_a_companion_with_no_product_toml_yet_can_be_set_but_never_planned(
    db: Session,
) -> None:
    source = FakeSource(text=_descriptor_text(product=_COMPANION))
    source.texts[_CPATH] = source.texts.pop(_PATH)
    source.drop_toml = True
    target = _bound_target(
        db, source, ref="integrator/prod/host-a", product=_COMPANION, path=_CPATH
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
        db, source, ref="integrator/prod/host-a", product=_COMPANION, path=_CPATH
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
    stranger = _bound_target(db, other_src, ref="erp/prod/stranger")
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
    plain = _plain_target(db, "erp/prod/plain")
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
    plain = _plain_target(db, "erp/prod/plain")
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
        db, source, ref="integrator/prod/other-host", product=_COMPANION, path=_CPATH
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
