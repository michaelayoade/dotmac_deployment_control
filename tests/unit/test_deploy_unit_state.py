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
    module,
    propose_plan,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control.deploy_binding import (
    DeploymentSet,
    PlannedImage,
    build_deploy_binding,
)
from dotmac_deployment_control.deploy_unit import DeployUnitError
from dotmac_deployment_control.digests import DeployUnitDigestV1
from dotmac_deployment_control.image_policy import PullAllowlist
from dotmac_deployment_control.legacy_policy import (
    AttendedApproval,
    LegacyPolicyRefusedError,
    LegacyRetirementEvidence,
)
from dotmac_deployment_control.models import LegacyEnvPolicyVersion
from dotmac_deployment_control.ports import (
    PlanRefusedError,
    ReleaseDescriptorEvidence,
    ReleaseDescriptorRefusedError,
    ReleaseDescriptorUnavailableError,
)
from dotmac_deployment_control.service import (
    CreateDeploymentSetCommand,
    EnableLegacyPolicyCommand,
    ExtendLegacyPolicyCommand,
    RetireLegacyPolicyCommand,
    ReviseLegacyPolicyCommand,
    SetDeploySettingCommand,
    create_deployment_set,
    enable_legacy_policy,
    extend_legacy_policy,
    get_deploy_settings,
    get_deployment_set,
    get_legacy_policy,
    legacy_plan_binding,
    list_deployment_sets,
    retire_legacy_policy,
    revise_legacy_policy,
    set_deploy_setting,
)

_ERP = "dotmac-erp-v2"
_SHA = "sha256:" + "a" * 64
_SHA2 = "sha256:" + "b" * 64
_D1 = "sha256:" + "1" * 64
_U1 = "sha256:" + "5" * 64
_P1 = "sha256:" + "3" * 64
_REPO = "registry.example.test/team/app"
_EXEC = "sha256:" + "1a" * 32
_DESC = "sha256:" + "3c" * 32
_ATTENDED = AttendedApproval("operator", True, "register-line-1")
_UNATTENDED = AttendedApproval("operator", False, "register-line-1")
_NAMES = ("DB_PASSWORD", "API_SECRET")


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


def _target(db: Session, *, ref: str = "erp/prod/host-a", product: str = _ERP):
    view = register_target(
        db,
        RegisterTargetCommand(
            command_id=_cmd(),
            target_ref=ref,
            subject_ref="acme-operator",
            product_code=product,
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=view.id,
            desired=DesiredDeployment(
                release_ref=f"{ref}@1", spec={"replicas": 1}, images=[]
            ),
        ),
    )
    return view


def _set(db: Session, name: str, value: object, approval=_ATTENDED):  # type: ignore[no-untyped-def]
    return set_deploy_setting(
        db,
        SetDeploySettingCommand(
            command_id=_cmd(), name=name, value=value, approval=approval
        ),
    )


def _enable(db: Session, target_id, **overrides: object):  # type: ignore[no-untyped-def]
    args: dict[str, object] = {
        "command_id": _cmd(),
        "target_id": target_id,
        "names": _NAMES,
        "sha256": _SHA,
        "secret_names": _NAMES,
        "param_materials": ("PUBLIC_HOST",),
        "binding_names": (),
        "cutover_at": datetime.now(UTC),
        "exit_prestaged": True,
        "approval": _ATTENDED,
    }
    args.update(overrides)
    return enable_legacy_policy(db, EnableLegacyPolicyCommand(**args))  # type: ignore[arg-type]


def _propose(db: Session, target_id, binding=None):  # type: ignore[no-untyped-def]
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
            deploy_binding=binding,
        ),
    )


def _image(**overrides: str) -> PlannedImage:
    args = {
        "service": "app",
        "source": "transfer",
        "release_repository": _REPO,
        "release_digest": _D1,
        "planned_repository": "127.0.0.1:5000/team/app",
        "planned_digest": _D1,
    }
    args.update(overrides)
    return PlannedImage(**args)


def _binding(allowlist: PullAllowlist | None = None, **overrides: object):
    args: dict[str, object] = {
        "deploy_unit_digest": _U1,
        "params_env_digest": _P1,
        "images": [_image()],
        "lease_ttl_seconds": 900,
        "allowlist": allowlist or PullAllowlist(),
    }
    args.update(overrides)
    return build_deploy_binding(**args)  # type: ignore[arg-type]


# ── Settings ────────────────────────────────────────────────────────────────


def test_settings_default_to_empty_default_deny_and_zero(db: Session) -> None:
    view = get_deploy_settings(db)
    assert view.public_pull_repositories == ()
    assert view.legacy_env_file_allowed_products == (_ERP,)
    assert view.legacy_env_file_ceiling == 0


def test_a_setting_change_needs_an_attended_approval_and_is_validated(
    db: Session,
) -> None:
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        _set(db, "public_pull_repositories", [_REPO], _UNATTENDED)
    with pytest.raises(DeployUnitError):
        _set(db, "public_pull_repositories", ["127.0.0.1:5000/team/app"])
    with pytest.raises(DeployUnitError):
        _set(db, "legacy_env_file_ceiling", -1)
    with pytest.raises(DeployUnitError):
        _set(db, "not_a_setting", [])
    assert get_deploy_settings(db).public_pull_repositories == ()
    view = _set(db, "public_pull_repositories", [_REPO, _REPO])
    assert view.public_pull_repositories == (_REPO,)
    view = _set(db, "legacy_env_file_allowed_products", [_ERP, "other-app"])
    assert view.legacy_env_file_allowed_products == (_ERP, "other-app")


def test_the_ceiling_can_only_be_raised_by_a_setting_change(db: Session) -> None:
    assert _set(db, "legacy_env_file_ceiling", 2).legacy_env_file_ceiling == 2
    with pytest.raises(LegacyPolicyRefusedError):
        _set(db, "legacy_env_file_ceiling", 1)


# ── Legacy policy ───────────────────────────────────────────────────────────


def test_legacy_enable_is_refused_at_ceiling_zero_and_for_unlisted_products(
    db: Session,
) -> None:
    erp = _target(db)
    with pytest.raises(LegacyPolicyRefusedError, match="ceiling"):
        _enable(db, erp.id)
    _set(db, "legacy_env_file_ceiling", 1)
    sub = _target(db, ref="sub/prod/host-a", product="dotmac-sub")
    with pytest.raises(LegacyPolicyRefusedError, match="allowed_products"):
        _enable(db, sub.id)
    with pytest.raises(LegacyPolicyRefusedError, match="companion"):
        _enable(db, erp.id, companion=True)
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        _enable(db, erp.id, approval=_UNATTENDED)
    assert get_legacy_policy(db, erp.id) is None


def test_legacy_versions_append_and_retirement_decrements_the_ceiling(
    db: Session,
) -> None:
    erp = _target(db)
    _set(db, "legacy_env_file_ceiling", 1)
    first = _enable(db, erp.id)
    assert (first.policy_version, first.state, first.file_sha256) == (
        1,
        "enabled",
        _SHA,
    )
    assert first.names == tuple(sorted(_NAMES))

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
    with pytest.raises(LegacyPolicyRefusedError, match="attended"):
        extend_legacy_policy(
            db,
            ExtendLegacyPolicyCommand(
                command_id=_cmd(),
                target_id=erp.id,
                new_expires_at=extended.expires_at + timedelta(days=7),
                approval=_UNATTENDED,
            ),
        )

    # The plan binds the CURRENT version's sha and names.
    bound = legacy_plan_binding(db, erp.id)
    assert (bound.policy_version, bound.sha256) == (3, _SHA2)
    with pytest.raises(LegacyPolicyRefusedError, match="sha"):
        legacy_plan_binding(db, erp.id, observed_sha256=_SHA)

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
    # Every version is kept as its own row; none was edited.
    rows = db.execute(select(LegacyEnvPolicyVersion)).scalars().all()
    assert sorted(r.policy_version for r in rows) == [1, 2, 3, 4]
    with pytest.raises(LegacyPolicyRefusedError):
        legacy_plan_binding(db, erp.id)


# ── The binding is reachable, descriptor-backed and re-checked at proposal ────

_PATH = "deploy/deploy-unit.toml"


def _descriptor_text(*, pull: bool = False) -> str:
    return (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
        f'[image]\nsource = "{"pull" if pull else "transfer"}"\n'
        '[params.image_repository]\ntype = "image_repository"\n'
        'required_in = ["production"]\n'
        '[params.image_digest]\ntype = "image_digest"\nrequired_in = ["production"]\n'
        '[params.workers]\ntype = "int"\nmin = 1\nmax = 8\ndefault = 2\n'
        'material = "WORKERS"\n'
        '[[bindings]]\nname = "DB_PASSWORD"\nstate = "pre_staged"\nkind = "key"\n'
        'roles = ["app"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
        "single_use = false\n"
    )


class FakeSource:
    """A `ReleaseDescriptorSource` the tests can bend; counts its resolves."""

    def __init__(self, *, pull: bool = False) -> None:
        self.calls = 0
        self.unavailable = False
        self.set_text(_descriptor_text(pull=pull))
        self.image_digest = _D1
        self.image_repository = _REPO
        self.product_code = _ERP
        self.attested_override: str | None = None

    def set_text(self, text: str) -> None:
        self.text = text

    def resolve(self, release_ref, *, product_code, descriptor_path):  # type: ignore[no-untyped-def]
        self.calls += 1
        if self.unavailable:
            raise ReleaseDescriptorUnavailableError("the catalogue is down")
        data = self.text.encode()
        return ReleaseDescriptorEvidence(
            release_ref=release_ref,
            product_code=self.product_code,
            descriptor_path=descriptor_path,
            source_revision="a" * 40,
            image_repository=self.image_repository,
            image_digest=self.image_digest,
            deploy_unit_bytes=data,
            attested_digest=self.attested_override
            or DeployUnitDigestV1.over_bytes(data).canonical,
        )


def _unit_digest(source: FakeSource) -> str:
    return DeployUnitDigestV1.over_bytes(source.text.encode()).canonical


def _desired(db: Session, target_id, source, *, repo="127.0.0.1:5000/team/app", **kw):  # type: ignore[no-untyped-def]
    params = kw.pop("params", {"image_repository": repo})
    return set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_cmd(),
            target_id=target_id,
            desired=DesiredDeployment(release_ref="erp@1", **kw),
            descriptor_path=_PATH,
            params=params,
        ),
        release_source=source,
    )


def _bound_target(db: Session, source: FakeSource):  # type: ignore[no-untyped-def]
    erp = _target(db)
    _desired(db, erp.id, source)
    return erp


def _propose_with(db, target_id, source, binding=None):  # type: ignore[no-untyped-def]
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
            deploy_binding=binding,
        ),
        release_source=source,
    )


def test_a_plan_with_a_binding_freezes_it_inside_the_plan_snapshot(
    db: Session,
) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    plain = _propose_with(db, erp.id, source)
    bound = _propose_with(
        db, erp.id, source, _binding(deploy_unit_digest=_unit_digest(source))
    )
    assert bound.plan_digest != plain.plan_digest
    assert bound.snapshot["deploy_binding"]["params_env_digest"] == _P1
    assert bound.snapshot["deploy_binding"]["deploy_unit_digest"] == _unit_digest(
        source
    )
    assert "deploy_binding" not in plain.snapshot


def test_a_pull_binding_is_refused_unless_the_stored_allowlist_has_it(
    db: Session,
) -> None:
    source = FakeSource(pull=True)
    erp = _target(db)
    # A pull descriptor whose image_repository must be the release repository.
    with pytest.raises(ReleaseDescriptorRefusedError, match="release_image_mismatch"):
        _desired(db, erp.id, source, repo=_REPO)
    _set(db, "public_pull_repositories", [_REPO])
    _desired(db, erp.id, source, repo=_REPO)
    forged = _binding(
        deploy_unit_digest=_unit_digest(source),
        allowlist=PullAllowlist.of([_REPO]),
        images=[_image(source="pull", planned_repository=_REPO)],
    )
    assert (
        _propose_with(db, erp.id, source, forged).snapshot["deploy_binding"]["images"][
            0
        ]["source"]
        == "pull"
    )
    # The stored allowlist is re-read at proposal: remove it and the binding fails.
    _set(db, "public_pull_repositories", [])
    with pytest.raises(ReleaseDescriptorRefusedError, match="public_pull_repositories"):
        _propose_with(db, erp.id, source, forged)


def test_a_stale_legacy_binding_is_refused_at_proposal(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    _set(db, "legacy_env_file_ceiling", 1)
    _enable(db, erp.id)
    current = legacy_plan_binding(db, erp.id)
    digest = _unit_digest(source)
    assert _propose_with(
        db, erp.id, source, _binding(deploy_unit_digest=digest, legacy=current)
    ).plan_digest
    revise_legacy_policy(
        db,
        ReviseLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            names=_NAMES[:1],
            sha256=_SHA2,
            approval=_ATTENDED,
        ),
    )
    with pytest.raises(PlanRefusedError, match="current policy"):
        _propose_with(
            db, erp.id, source, _binding(deploy_unit_digest=digest, legacy=current)
        )


# ── The release descriptor: one refusal test per code ───────────────────────


def test_descriptor_digest_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    source.attested_override = "sha256:" + "9" * 64
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, source)
    assert info.value.code == "descriptor_digest_mismatch"


def test_release_image_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    erp = _target(db)
    # The repository param must be the release's own, loopback form.
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(db, erp.id, source, repo="127.0.0.1:5000/team/other")
    assert info.value.code == "release_image_mismatch"
    # The digest param is Control's: a different one is refused.
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(
            db,
            erp.id,
            source,
            params={
                "image_repository": "127.0.0.1:5000/team/app",
                "image_digest": "sha256:" + "2" * 64,
            },
        )
    assert info.value.code == "release_image_mismatch"
    # Declared images must be exactly the release's image.
    other = [{"service": "app", "repository": _REPO, "digest": "sha256:" + "2" * 64}]
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _desired(db, erp.id, source, images=other)
    assert info.value.code == "release_image_mismatch"
    # Nothing was half-written.
    assert get_target_images(db, erp.id) == []  # still the empty declared set


def get_target_images(db: Session, target_id):  # type: ignore[no-untyped-def]
    from dotmac_deployment_control.models import DeploymentTarget

    return db.get(DeploymentTarget, target_id).desired_images


def test_product_mismatch_is_refused(db: Session) -> None:
    source = FakeSource()
    source.product_code = "someone-else"
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, source)
    assert info.value.code == "descriptor_product_mismatch"
    # A descriptor that declares another product is refused as well.
    other = FakeSource()
    other.set_text(_descriptor_text().replace("dotmac-erp-v2", "other-app"))
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _bound_target(db, other)
    assert info.value.code == "descriptor_product_mismatch"


def test_the_companion_path_rule_holds_through_the_release_source(
    db: Session,
) -> None:
    source = FakeSource()
    source.set_text(
        _descriptor_text()
        .replace("deploy/product.toml", "deploy/companion/product.toml")
        .replace(
            "[image]",
            '[legacy_env_file]\nnames = ["DB_PASSWORD"]\npath_param = "lp"\n[image]',
        )
        + '[params.lp]\ntype = "path"\n'
    )
    erp = _target(db)
    with pytest.raises(DeployUnitError, match="companion"):
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=_cmd(),
                target_id=erp.id,
                desired=DesiredDeployment(release_ref="erp@1"),
                descriptor_path="deploy/companion/deploy-unit.toml",
                params={"image_repository": "127.0.0.1:5000/team/app"},
            ),
            release_source=source,
        )


def test_an_unavailable_source_fails_closed(db: Session) -> None:
    erp = _target(db)
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _desired(db, erp.id, None)
    source = FakeSource()
    source.unavailable = True
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _desired(db, erp.id, source)
    # Without a descriptor_path there is no evidence path at all, and params or a
    # reserved key cannot be smuggled in through the spec.
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
    view = get_target_view(db, erp.id)
    unit = view.desired_spec["deploy_unit"]
    assert unit["descriptor_digest"] == _unit_digest(source)
    assert unit["params"]["workers"] == "2"
    assert unit["params"]["image_digest"] == _D1
    assert view.desired_images is not None
    assert view.desired_images[0].repository == _REPO
    # No descriptor text anywhere in what was stored.
    assert "dotmac.deploy_unit" not in repr(view.desired_spec)
    assert "pre_staged" not in repr(view.desired_spec)


def get_target_view(db: Session, target_id):  # type: ignore[no-untyped-def]
    from dotmac_deployment_control import get_target

    return get_target(db, target_id)


def test_propose_re_resolves_and_refuses_when_the_release_moved(
    db: Session,
) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    before = source.calls
    assert _propose_with(db, erp.id, source).plan_digest
    assert source.calls > before, "propose did not re-resolve the descriptor"
    # The descriptor bytes changed after desired state was set.
    source.set_text(source.text + "\n# edited\n")
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose_with(db, erp.id, source)
    assert info.value.code == "descriptor_digest_mismatch"
    source.set_text(_descriptor_text())
    # The release image changed.
    source.image_digest = "sha256:" + "7" * 64
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose_with(db, erp.id, source)
    assert info.value.code == "release_image_mismatch"
    source.image_digest = _D1
    # The source went away.
    source.unavailable = True
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose_with(db, erp.id, source)
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose_with(db, erp.id, None)


def test_a_binding_must_agree_with_the_re_verified_descriptor(db: Session) -> None:
    source = FakeSource()
    erp = _bound_target(db, source)
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose_with(db, erp.id, source, _binding(deploy_unit_digest=_U1))
    assert info.value.code == "descriptor_digest_mismatch"
    digest = _unit_digest(source)
    wrong_image = _binding(
        deploy_unit_digest=digest,
        images=[
            _image(
                release_digest="sha256:" + "2" * 64, planned_digest="sha256:" + "2" * 64
            )
        ],
    )
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose_with(db, erp.id, source, wrong_image)
    assert info.value.code == "release_image_mismatch"
    wrong_names = _binding(deploy_unit_digest=digest, active_binding_names=["X_NAME"])
    with pytest.raises(ReleaseDescriptorRefusedError) as info:
        _propose_with(db, erp.id, source, wrong_names)
    assert info.value.code == "descriptor_evidence_mismatch"
    # A binding with no descriptor-backed desired state has nothing to verify.
    plain = _target(db, ref="erp/prod/host-z")
    with pytest.raises(ReleaseDescriptorUnavailableError):
        _propose_with(db, plain.id, source, _binding(deploy_unit_digest=digest))


def test_a_plan_with_an_active_binding_on_a_legacy_name_is_refused(
    db: Session,
) -> None:
    source = FakeSource()
    # The descriptor activates DB_PASSWORD, which the legacy file still supplies.
    source.set_text(_descriptor_text().replace('state = "pre_staged"\n', ""))
    erp = _bound_target(db, source)
    _set(db, "legacy_env_file_ceiling", 1)
    _enable(db, erp.id)
    digest = _unit_digest(source)
    clash = _binding(deploy_unit_digest=digest, active_binding_names=["DB_PASSWORD"])
    with pytest.raises(LegacyPolicyRefusedError, match="retire the name"):
        _propose_with(db, erp.id, source, clash)
    retire_legacy_policy(
        db,
        RetireLegacyPolicyCommand(
            command_id=_cmd(),
            target_id=erp.id,
            evidence=LegacyRetirementEvidence(True, True, True),
            approval=_ATTENDED,
        ),
    )
    assert _propose_with(db, erp.id, source, clash).snapshot["deploy_binding"][
        "active_binding_names"
    ] == ["DB_PASSWORD"]


# ── Deployment sets ─────────────────────────────────────────────────────────


def test_a_deployment_set_is_recorded_once_per_digest(db: Session) -> None:
    primary = _propose(db, _target(db).id)
    companion = _propose(db, _target(db, ref="integrator/prod/host-a").id)
    made = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion.id,
        ),
    )
    assert (
        made.set_digest
        == DeploymentSet(primary.plan_digest, companion.plan_digest).set_digest()
    )
    again = create_deployment_set(
        db,
        CreateDeploymentSetCommand(
            command_id=_cmd(),
            primary_plan_id=primary.id,
            companion_plan_id=companion.id,
        ),
    )
    assert again.id == made.id
    assert get_deployment_set(db, made.id) == made
    assert list_deployment_sets(db) == (made,)
    # A set cannot name one plan twice.
    with pytest.raises(DeployUnitError):
        create_deployment_set(
            db,
            CreateDeploymentSetCommand(
                command_id=_cmd(),
                primary_plan_id=primary.id,
                companion_plan_id=primary.id,
            ),
        )
