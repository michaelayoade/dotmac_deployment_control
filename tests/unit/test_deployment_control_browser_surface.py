"""The browser surface, driven with real requests.

The property this file exists for is one sentence: **the browser may never
submit its own PlanDigest.**

That sentence is easy to satisfy by accident and impossible to keep by accident.
`ProposePlanCommand` has no digest field and `PlanProposalPreview` takes no
input, so today neither the write path nor the read path can accept one — but
both of those are ABSENCES. An absence passes silently when someone adds a
field, and nothing has ever watched it hold. So the surface carries a REFUSAL as
well, declared on the router and therefore covering every route mounted there,
and this file plants requests that supply a digest and observes it fire.

Three plants, because a digest can arrive three ways and a guard that caught one
would leave the other two open:

* under a field NAMED for a digest;
* under a field the surface legitimately reads, carrying a digest-SHAPED value;
* in the query string of a safe method that never submits anything.

And a POSITIVE CONTROL, which is the half that stops all of this being a guard
that refuses everything: the same submission without a digest succeeds, and the
plan it creates carries exactly the digest the server derived — a value the
request never contained.

In-memory SQLite; logic only. Grants, triggers and the claim/proof CHECKs are
proven against real PostgreSQL in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from typing import Any

import pytest
from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
from dotmac_kernel.deps import get_platform_db
from dotmac_kernel.facet_principal import (
    FacetPrincipal,
    FacetPrincipalPlaneMismatchError,
    FacetPrincipalUnavailableError,
    record_facet_principal,
)
from dotmac_kernel.models import Base
from dotmac_kernel.templating import compose_templates
from dotmac_kernel.web_surfaces import BrowserSecurityPlane
from fastapi import Depends, FastAPI, Request
from fastapi.responses import PlainTextResponse
from sqlalchemy import create_engine, event, select
from sqlalchemy.orm import Session, sessionmaker

from dotmac_deployment_control import (
    DEPLOYMENT_CONTROL_SURFACE,
    DeploymentPlan,
    DesiredDeployment,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    module,
    plan_digest_of,
    plan_snapshot,
    preview_plan_proposal,
    register_target,
    set_desired_state,
)
from dotmac_deployment_control import web as surface
from dotmac_deployment_control.models import DeploymentTarget
from tests.asgi_driver import call

#: A real, well-formed digest of something. It is never a plan's digest here —
#: what matters is that it LOOKS like one, because that is all an attacker or a
#: careless client would have.
_DIGEST = "sha256:" + "a1" * 32
_BARE_HEX_DIGEST = "b2" * 32

_PLATFORM_SUBJECT = uuid.uuid4()


@pytest.fixture(autouse=True)
def _installed_module_audit_actions() -> None:
    install_audit_actions(AuditActionRegistry.from_manifests([module]))


@pytest.fixture(autouse=True)
def _composed_templates() -> Generator[None, None, None]:
    """Resolve the module's templates through their declared namespace.

    Exactly what `create_app` does with `surface_registry.template_packages`,
    reduced to the one package under test. Reset afterwards, because the Jinja
    loader is process-static and a leaked override is the same class of bug as a
    leaked global.
    """
    templates = DEPLOYMENT_CONTROL_SURFACE.templates
    assert templates is not None
    compose_templates(namespaced_dirs={templates.namespace: templates.root})
    yield
    compose_templates()


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


def _principal(plane: BrowserSecurityPlane = BrowserSecurityPlane.PLATFORM) -> Any:
    return FacetPrincipal(
        facet="platform_admin",
        security_plane=plane,
        subject_id=_PLATFORM_SUBJECT,
        subject=object(),
        tenant_id=uuid.uuid4() if plane is BrowserSecurityPlane.TENANT else None,
    )


def _app(db: Session, *, principal: Any | None = None) -> FastAPI:
    """The surface's own router on a bare application.

    Bare on purpose. The full facet composition adds `require_csrf` and the
    facet's cookie authentication in front of every route, and a test that had
    to hold a live platform session to reach the handler would be proving the
    kernel's authentication rather than this surface's refusal. That the refusal
    survives composition — and that CSRF and the facet guard are in front of
    it — is proven structurally in
    `tests/architecture/test_browser_surface_contract.py`.

    The principal is published exactly the way the composed facet publishes it,
    through `record_facet_principal`, so `_actor_ref` reads the same
    request-scoped projection here as in production. `principal=None` builds an
    application where the facet authenticated nobody, which is the case a
    mutation must refuse rather than attribute to nobody.
    """

    def plant(request: Request) -> None:
        if principal is not None:
            record_facet_principal(request, principal)

    app = FastAPI(dependencies=[Depends(plant)])
    app.include_router(surface.router)

    @app.post("/logout", name="logout")
    def logout() -> PlainTextResponse:
        """The platform shell links to its facet's logout route by name. On a
        bare application there is no facet, so `surface_url` falls back to
        `request.url_for` and needs a route with that name to exist."""
        return PlainTextResponse("", status_code=204)

    app.dependency_overrides[get_platform_db] = lambda: db
    return app


def _target(db: Session, *, release: str = "release-1", revision_bump: bool = True):
    view = register_target(
        db,
        RegisterTargetCommand(
            command_id=str(uuid.uuid4()),
            target_ref="edge-lagos-01",
            subject_ref="tenant-1",
            product_code="isp",
            environment="production",
        ),
    )
    if revision_bump:
        set_desired_state(
            db,
            SetDesiredStateCommand(
                command_id=str(uuid.uuid4()),
                target_id=view.id,
                desired=DesiredDeployment(
                    release_ref=release, spec={"replicas": 2}, licence_ref="lic-1"
                ),
            ),
        )
    return view.id


def _propose_form(revision: int, **extra: str) -> dict[str, str]:
    return {
        "expected_desired_revision": str(revision),
        "requires_approval": "on",
        "approval_policy_code": "deployment.production",
        "approval_policy_version": "4",
        **extra,
    }


# ── THE REFUSAL ─────────────────────────────────────────────────────────────


class TestTheBrowserMayNotSupplyAPlanDigest:
    """Three plants and a positive control."""

    def test_a_form_field_named_for_a_digest_is_refused(self, db: Session) -> None:
        """PLANT 1 — the obvious one: a client that adds `plan_digest`.

        The plan is created from immutable evidence coordinates alone. A request
        that also names the digest is asking this module to accept, as the value
        an approval will later be bound to, a string the caller chose.
        """
        target_id = _target(db)
        app = _app(db, principal=_principal())

        response = call(
            app,
            "POST",
            f"/deployments/{target_id}/plans",
            form=_propose_form(1, plan_digest=_DIGEST),
        )

        assert response.status == 400, response.text
        assert "supplies a plan digest" in response.text
        assert "field 'plan_digest'" in response.text
        assert self._plans(db) == 0, "a refused request created a plan anyway"

    def test_a_digest_shaped_value_in_an_accepted_field_is_refused(
        self, db: Session
    ) -> None:
        """PLANT 2 — the one that makes PLANT 1 more than a spelling rule.

        A refusal that only knew field NAMES would be got past by putting the
        digest somewhere the surface legitimately reads. So the value is checked
        too, in both encodings this module has ever issued: the canonical
        `sha256:<hex>` and `0.1.0a4`'s bare hex.
        """
        target_id = _target(db)
        app = _app(db, principal=_principal())

        for smuggled in (_DIGEST, _BARE_HEX_DIGEST):
            response = call(
                app,
                "POST",
                f"/deployments/{target_id}/plans",
                form=_propose_form(1, approval_policy_code=smuggled),
            )
            assert response.status == 400, response.text
            assert "the value of 'approval_policy_code'" in response.text
        assert self._plans(db) == 0

    def test_a_digest_in_the_query_string_of_a_read_is_refused(
        self, db: Session
    ) -> None:
        """PLANT 3 — a safe method, which submits nothing and is refused anyway.

        The rule is about the SURFACE, not about the mutation: a read that
        accepted a digest would be a place a caller could establish one, and the
        refusal is declared on the router so it covers every route regardless of
        method.
        """
        target_id = _target(db)
        app = _app(db, principal=_principal())

        response = call(
            app,
            "GET",
            f"/deployments/{target_id}",
            query={"plan_digest": _DIGEST},
        )

        assert response.status == 400, response.text
        assert "in the query string" in response.text

    def test_the_same_submission_without_a_digest_creates_the_derived_one(
        self, db: Session
    ) -> None:
        """POSITIVE CONTROL, and the property itself.

        Without this, every refusal above is equally consistent with a surface
        that rejects all form submissions. It also states the thing the refusal
        is protecting: the digest the plan ends up carrying is the one the
        SERVER derived from the target, byte for byte, and it was never in the
        request.
        """
        target_id = _target(db)
        preview = preview_plan_proposal(db, target_id)
        assert preview is not None
        app = _app(db, principal=_principal())

        response = call(
            app,
            "POST",
            f"/deployments/{target_id}/plans",
            form=_propose_form(preview.desired_revision),
        )

        assert response.status == 303, response.text
        assert str(target_id) in (response.header("location") or "")

        plan = db.execute(select(DeploymentPlan)).scalars().one()
        assert plan.plan_digest == preview.plan_digest
        assert plan.plan_digest != _DIGEST

    def test_the_stored_digest_is_recomputable_from_the_target_alone(
        self, db: Session
    ) -> None:
        """The strongest statement available: the plan's digest is a FUNCTION of
        module-owned state, so it is reproducible without the request that
        created it."""
        target_id = _target(db)
        app = _app(db, principal=_principal())
        call(app, "POST", f"/deployments/{target_id}/plans", form=_propose_form(1))

        plan = db.execute(select(DeploymentPlan)).scalars().one()
        target = db.get(DeploymentTarget, target_id)
        assert target is not None
        assert plan.plan_digest == plan_digest_of(plan_snapshot(target)).canonical

    @staticmethod
    def _plans(db: Session) -> int:
        return len(db.execute(select(DeploymentPlan)).scalars().all())


# ── The rest of the surface's refusals ──────────────────────────────────────


def test_an_unexpected_form_field_is_refused_rather_than_ignored(
    db: Session,
) -> None:
    """A field the server silently drops is a value an operator believes they
    set. The surface reads a closed set and says so."""
    target_id = _target(db)
    app = _app(db, principal=_principal())

    response = call(
        app,
        "POST",
        f"/deployments/{target_id}/plans",
        form=_propose_form(1, force="yes"),
    )

    assert response.status == 400, response.text
    assert "unexpected form field" in response.text
    assert "force" in response.text


def test_a_submission_with_no_evidence_coordinate_at_all_is_refused(
    db: Session,
) -> None:
    """Plan creation is FROM coordinates, so a request that names none is not a
    weaker version of the same thing — it is a different operation, one that
    freezes whatever happens to be current."""
    target_id = _target(db)
    app = _app(db, principal=_principal())

    form = _propose_form(1)
    form.pop("expected_desired_revision")
    response = call(app, "POST", f"/deployments/{target_id}/plans", form=form)

    assert response.status == 400, response.text
    assert "expected_desired_revision is required" in response.text
    assert not db.execute(select(DeploymentPlan)).scalars().all()


def test_a_stale_evidence_coordinate_is_refused_in_the_modules_own_words(
    db: Session,
) -> None:
    """Plan creation is FROM IMMUTABLE EVIDENCE COORDINATES.

    The operator submits the desired revision they were shown. If the desired
    state moved between the page render and the click, the plan they would get
    is not the plan they read — and the digest they were shown is not the digest
    it would carry. The module refuses, and the screen repeats the module's
    words rather than paraphrasing them.
    """
    target_id = _target(db)
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=str(uuid.uuid4()),
            target_id=target_id,
            desired=DesiredDeployment(release_ref="release-2", spec={"replicas": 3}),
        ),
    )
    app = _app(db, principal=_principal())

    response = call(
        app,
        "POST",
        f"/deployments/{target_id}/plans",
        form=_propose_form(1),  # the revision the stale page was showing
    )

    assert response.status == 400, response.text
    assert "is not the plan this would freeze" in response.text
    assert not db.execute(select(DeploymentPlan)).scalars().all()


def test_a_mutation_with_no_facet_principal_is_refused_not_attributed_to_nobody(
    db: Session,
) -> None:
    """No actor, no mutation.

    `require_facet_principal` refuses an absent principal rather than returning
    `None`, and this surface never re-authenticates to manufacture one. A route
    that expected an actor and quietly received nothing is how an unattributed
    deployment decision gets written.
    """
    target_id = _target(db)
    app = _app(db, principal=None)

    with pytest.raises(FacetPrincipalUnavailableError):
        call(app, "POST", f"/deployments/{target_id}/plans", form=_propose_form(1))
    assert not db.execute(select(DeploymentPlan)).scalars().all()


def test_a_tenant_plane_principal_cannot_decide_a_fleet_deployment(
    db: Session,
) -> None:
    """SENSITIVITY for the plane declaration.

    Without this, `plane=PLATFORM` is a constant nobody has seen refuse
    anything. A tenant-plane identity reaching a platform surface is a privilege
    confusion, not a weaker actor to be tolerated: the two planes have different
    isolation rules entirely.
    """
    target_id = _target(db)
    app = _app(db, principal=_principal(BrowserSecurityPlane.TENANT))

    with pytest.raises(FacetPrincipalPlaneMismatchError):
        call(app, "POST", f"/deployments/{target_id}/plans", form=_propose_form(1))
    assert not db.execute(select(DeploymentPlan)).scalars().all()


# ── The screens render, and render server-computed answers ──────────────────


def test_the_fleet_list_renders_and_links_to_the_detail_screen(db: Session) -> None:
    target_id = _target(db)
    app = _app(db, principal=_principal())

    response = call(app, "GET", "/deployments")

    assert response.status == 200, response.text
    assert "edge-lagos-01" in response.text
    assert str(target_id) in response.text


def test_the_detail_screen_shows_the_server_derived_plan_and_digest(
    db: Session,
) -> None:
    """The canonical plan on the page is the exact serialization the digest was
    taken over — not a pretty-printed rendering of a mapping beside a number."""
    target_id = _target(db)
    preview = preview_plan_proposal(db, target_id)
    assert preview is not None
    app = _app(db, principal=_principal())

    response = call(app, "GET", f"/deployments/{target_id}")

    assert response.status == 200, response.text
    assert preview.plan_digest in response.text
    assert "release-1" in response.text
    # The form submits the coordinate and never the digest.
    assert 'name="expected_desired_revision"' in response.text
    assert 'name="plan_digest"' not in response.text
    # And it carries the CSRF proof the kernel's transport contract requires of
    # a native POST form.
    assert 'name="csrf_token"' in response.text


def test_a_target_that_cannot_be_planned_for_shows_the_modules_reasons(
    db: Session,
) -> None:
    """The eligibility decision is the MODULE's, computed once in
    `_plan_blockers` and consumed both by `propose_plan`'s refusal and by the
    preview. The screen renders `can_propose`; it does not work one out from
    `status` and `desired_release_ref`."""
    target_id = _target(db, revision_bump=False)  # registered, no desired release
    app = _app(db, principal=_principal())

    response = call(app, "GET", f"/deployments/{target_id}")

    assert response.status == 200, response.text
    assert "cannot be planned for right now" in response.text
    assert "has no desired release" in response.text
    assert 'name="expected_desired_revision"' not in response.text


def test_the_arrivals_screen_renders_with_nothing_to_show(db: Session) -> None:
    """The empty case is the one a fleet screen meets first, and an empty read
    must render rather than raise."""
    app = _app(db, principal=_principal())

    response = call(app, "GET", "/deployment-arrivals")

    assert response.status == 200, response.text
    assert "Nothing has arrived yet." in response.text


def test_a_missing_target_is_a_404_not_a_blank_screen(db: Session) -> None:
    app = _app(db, principal=_principal())
    response = call(app, "GET", f"/deployments/{uuid.uuid4()}")
    assert response.status == 404, response.text


def test_the_reconciliation_panel_separates_unknown_from_wrong(
    db: Session,
) -> None:
    """`never_observed` and `drifted` are different answers and the screen keeps
    them apart. A freshly registered deployment is unknown, not an incident."""
    target_id = _target(db)
    app = _app(db, principal=_principal())

    response = call(app, "GET", f"/deployments/{target_id}")

    assert response.status == 200, response.text
    assert "Missing evidence." in response.text
    assert "Drifted." not in response.text
    assert "Converged." not in response.text


def test_timestamps_render_as_explicit_utc_and_never_as_a_python_repr(
    db: Session,
) -> None:
    """Every rendered instant says which zone it is in.

    The kernel's `local_datetime` filter is deliberately NOT used here: it
    resolves TENANT display settings, and this is the platform plane, where
    there is no tenant and where an assembly that never registered the `display`
    specs — the vendor control plane has not — would turn every dated screen
    into a 500 inside the fallback. So the surface states UTC.

    Asserted on the OUTPUT: a bare `{{ value }}` would render Python's
    `2026-09-01 12:00:00+00:00`, which is both unlabelled and dialect-dependent.
    """
    target_id = _target(db)
    app = _app(db, principal=_principal())
    call(app, "POST", f"/deployments/{target_id}/plans", form=_propose_form(1))
    response = call(app, "GET", f"/deployments/{target_id}")

    assert response.status == 200, response.text
    assert "+00:00" not in response.text
    assert "datetime.datetime(" not in response.text
