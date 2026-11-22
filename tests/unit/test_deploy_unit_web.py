"""HTTP-level tests for the deploy-unit POST routes (settings, sets, params).

Driven through the surface's own router on a bare application, as the existing
browser-surface suite does. The composed-route guards (CSRF, facet
authentication, the digest refusal) are proven structurally in
`tests/architecture/test_browser_surface_contract.py`.
"""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select
from sqlalchemy.orm import Session

from dotmac_deployment_control import get_deploy_settings, get_target
from dotmac_deployment_control.models import DeploymentSet, DeploySetting
from tests.asgi_driver import call
from tests.unit import test_deployment_control_browser_surface as bs
from tests.unit.test_deploy_unit_state import (
    _CPATH,
    _LOOP,
    _PATH,
    FakeSource,
    _bound_target,
    _descriptor_text,
    _propose,
    _register,
)

# The browser-surface suite's fixtures, shared by name: one in-memory database
# on a single connection (the handlers run on a worker thread), the module's
# templates, and the installed audit actions.
db = bs.db
_composed_templates = bs._composed_templates
_installed_module_audit_actions = bs._installed_module_audit_actions
_app = bs._app
_principal = bs._principal


def _web(db: Session, source: object | None = None):  # type: ignore[no-untyped-def]
    app = _app(db, principal=_principal())
    app.state.deployment_control_release_source = source
    return app


def _settings_rows(db: Session) -> int:
    return len(db.execute(select(DeploySetting)).scalars().all())


# ── /deploy-settings ────────────────────────────────────────────────────────


def test_a_setting_post_without_attendance_is_refused_and_changes_nothing(
    db: Session,
) -> None:
    response = call(
        _web(db),
        "POST",
        "/deploy-settings",
        form={
            "name": "public_pull_repositories",
            "value": "registry.example.test/team/app",
            "register_ref": "line-1",
        },
    )
    assert response.status == 400, response.text
    assert "attended" in response.text
    assert _settings_rows(db) == 0


def test_an_attended_setting_post_is_stored_and_redirects(db: Session) -> None:
    response = call(
        _web(db),
        "POST",
        "/deploy-settings",
        form={
            "name": "public_pull_repositories",
            "value": "registry.example.test/team/app",
            "attended": "on",
            "register_ref": "line-1",
        },
    )
    assert response.status == 303, response.text
    assert get_deploy_settings(db).public_pull_repositories == (
        "registry.example.test/team/app",
    )


@pytest.mark.parametrize(
    ("form", "needle"),
    [
        (
            {"name": "nonsense", "value": "x", "attended": "on", "register_ref": "r"},
            "not a deploy setting",
        ),
        (
            {
                "name": "legacy_env_file_ceiling",
                "value": "many",
                "attended": "on",
                "register_ref": "r",
            },
            "whole number",
        ),
        (
            {"name": "legacy_env_file_ceiling", "value": "2", "attended": "on"},
            "attended",
        ),
        (
            {
                "name": "legacy_env_file_ceiling",
                "value": "2",
                "attended": "on",
                "register_ref": "r",
                "extra": "1",
            },
            "unexpected form field",
        ),
        (
            {
                "name": "legacy_env_file_allowed_targets",
                "value": "sha256:" + "a" * 64,
                "attended": "on",
                "register_ref": "r",
            },
            "supplies a plan digest",
        ),
    ],
)
def test_bad_setting_posts_are_refused(
    db: Session,
    form: dict[str, str],
    needle: str,
) -> None:
    response = call(_web(db), "POST", "/deploy-settings", form=form)
    assert response.status == 400, response.text
    assert needle in response.text
    assert _settings_rows(db) == 0


def test_the_settings_page_renders_the_defaults(db: Session) -> None:
    response = call(_web(db), "GET", "/deploy-settings")
    assert response.status == 200
    assert "legacy_env_file_allowed_targets" in response.text


# ── /deployments/{id}/params ────────────────────────────────────────────────


def _form(target_id, revision: int = 0, **params: str) -> dict[str, str]:  # type: ignore[no-untyped-def]
    return {
        "release_ref": "erp@1",
        "descriptor_path": _PATH,
        "expected_desired_revision": str(revision),
        **{f"param__{k}": v for k, v in params.items()},
    }


def test_the_params_form_is_rendered_from_the_param_specs(db: Session) -> None:
    source = FakeSource()
    target = _register(db)
    response = call(
        _web(db, source),
        "GET",
        f"/deployments/{target.id}/params",
        query={"release_ref": "erp@1"},
    )
    assert response.status == 200, response.text
    assert 'name="param__workers"' in response.text
    assert 'name="param__image_repository"' in response.text
    # The image digest is Control's, pinned from the evidence: no field for it.
    assert "param__image_digest" not in response.text
    assert "descriptor_text" not in response.text


def test_a_params_post_sets_a_descriptor_backed_desired_state(
    db: Session,
) -> None:
    source = FakeSource()
    target = _register(db)
    response = call(
        _web(db, source),
        "POST",
        f"/deployments/{target.id}/params",
        form=_form(target.id, image_repository=_LOOP, workers="4"),
    )
    assert response.status == 303, response.text
    spec = get_target(db, target.id).desired_spec["deploy_unit"]
    assert spec["params"]["workers"] == "4"
    assert spec["descriptor_digest"].startswith("sha256:")


def test_a_stale_params_submit_with_different_values_is_refused_not_replayed(
    db: Session,
) -> None:
    """R2-L2: the command id carries the values, so a stale resubmit is checked."""
    source = FakeSource()
    target = _register(db)
    app = _web(db, source)
    path = f"/deployments/{target.id}/params"
    mine = {"image_repository": _LOOP}
    first = call(app, "POST", path, form=_form(target.id, workers="4", **mine))
    assert first.status == 303, first.text
    stale = call(app, "POST", path, form=_form(target.id, workers="5", **mine))
    assert stale.status == 400, stale.text
    assert "desired revision" in stale.text
    spec = get_target(db, target.id).desired_spec["deploy_unit"]
    assert spec["params"]["workers"] == "4"
    # The identical submit is an idempotent replay, not a second change.
    again = call(app, "POST", path, form=_form(target.id, workers="4", **mine))
    assert again.status == 303
    assert get_target(db, target.id).desired_revision == 1


@pytest.mark.parametrize(
    ("mutate", "needle"),
    [
        (lambda f: f.update(param__workers="99"), "above the maximum"),
        (lambda f: f.update(param__bogus="1"), "unknown param"),
        (
            lambda f: f.update(param__image_repository="127.0.0.1:5000/team/other"),
            "release_image_mismatch",
        ),
        (lambda f: f.update(expected_desired_revision="7"), "desired revision"),
        (lambda f: f.update(descriptor_text="schema = 1"), "unexpected form field"),
        (lambda f: f.update(plan_digest="x"), "supplies a plan digest"),
        (
            lambda f: f.update(param__workers="sha256:" + "a" * 64),
            "supplies a plan digest",
        ),
    ],
)
def test_bad_params_posts_are_refused_and_change_nothing(
    db: Session,
    mutate,  # type: ignore[no-untyped-def]
    needle: str,
) -> None:
    source = FakeSource()
    target = _register(db)
    form = _form(target.id, image_repository=_LOOP, workers="2")
    mutate(form)
    response = call(
        _web(db, source), "POST", f"/deployments/{target.id}/params", form=form
    )
    assert response.status == 400, response.text
    assert needle in response.text
    assert "deploy_unit" not in get_target(db, target.id).desired_spec


def test_a_params_post_without_a_configured_source_fails_closed(
    db: Session,
) -> None:
    target = _register(db)
    response = call(
        _web(db, None),
        "POST",
        f"/deployments/{target.id}/params",
        form=_form(target.id, image_repository=_LOOP),
    )
    assert response.status == 400, response.text
    assert "no release descriptor source" in response.text


# ── /deployment-sets ────────────────────────────────────────────────────────


def _two_plans(db: Session):  # type: ignore[no-untyped-def]
    source = FakeSource(companion=True)
    source.texts[_CPATH] = _descriptor_text(product="dotmac-integrator-companion")
    erp = _bound_target(db, source)
    integ = _bound_target(
        db,
        source,
        ref="integrator/prod/host-a",
        product="dotmac-integrator-companion",
        path=_CPATH,
    )
    return source, _propose(db, erp.id, source), _propose(db, integ.id, source)


def test_a_set_post_validates_membership_and_redirects(db: Session) -> None:
    source, primary, companion = _two_plans(db)
    response = call(
        _web(db, source),
        "POST",
        "/deployment-sets",
        form={
            "primary_plan_id": str(primary.id),
            "companion_plan_id": str(companion.id),
        },
    )
    assert response.status == 303, response.text
    row = db.execute(select(DeploymentSet)).scalar_one()
    assert str(row.primary_plan_id) == str(primary.id)
    assert call(_web(db, source), "GET", "/deployment-sets").status == 200


@pytest.mark.parametrize(
    ("form", "needle"),
    [
        ({}, "primary_plan_id is required"),
        ({"primary_plan_id": "not-a-uuid"}, "must be a plan id"),
        ({"primary_plan_id": str(uuid.uuid4())}, "not found"),
        ({"primary_plan_id": "x", "required_at_switch": "on"}, "unexpected form field"),
    ],
)
def test_bad_set_posts_are_refused(
    db: Session,
    form: dict[str, str],
    needle: str,
) -> None:
    response = call(_web(db, FakeSource()), "POST", "/deployment-sets", form=form)
    assert response.status == 400, response.text
    assert needle in response.text
    assert db.execute(select(DeploymentSet)).first() is None
