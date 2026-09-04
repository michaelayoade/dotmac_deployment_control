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
that refuses everything.

That control CHANGED with `dc_0003`, and the change is worth stating rather than
absorbing. A plan is now bound to the Deployment Foundation's
`ExecutionPlanDigestV1`, which this surface is forbidden to send — by SHAPE, so
renaming the field does not help, and correctly, because a browser has rendered
no execution plan. So a clean submission from here no longer creates a plan; it
is refused for a DIFFERENT reason, in different words, having reached the
handler. That difference is the positive control: it proves the digest guard
fires specifically rather than the surface rejecting every form, and it is a
stronger statement than the old one, because it distinguishes two refusals
instead of distinguishing a refusal from a success.

The property the old control asserted — the plan's digest is a function of
module-owned state — is asserted directly against the service below, where it
does not depend on a route that can no longer reach it.

In-memory SQLite; logic only. Grants, triggers and the claim/proof CHECKs are
proven against real PostgreSQL in
`tests/test_deployment_control_platform_isolation.py`.
"""

from __future__ import annotations

import uuid
from collections.abc import Generator
from datetime import UTC, datetime
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
from sqlalchemy.pool import StaticPool

from dotmac_deployment_control import (
    DEPLOYMENT_CONTROL_SURFACE,
    ApprovalEvidence,
    ApprovePlanCommand,
    DeploymentPlan,
    DesiredDeployment,
    ProposePlanCommand,
    RegisterTargetCommand,
    SetDesiredStateCommand,
    approve_plan,
    module,
    plan_digest_of,
    plan_snapshot,
    preview_plan_proposal,
    propose_plan,
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
#: The Deployment Foundation's execution plan digest, as a fixture. It is
#: canonical and well-formed; what matters here is that no request in this file
#: can carry it, which is why every plan below is created through the service.
_EXECUTION_PLAN = "sha256:" + "1a" * 32
_DESCRIPTOR = "sha256:" + "3c" * 32

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
    """One in-memory database, on ONE connection, reachable from any thread.

    Both halves are needed here and neither is needed by the module's other
    suites, which is why this fixture is not the one they use.

    Starlette runs a `def` endpoint in a worker threadpool — the correct
    production shape for a route that makes blocking database calls, and the
    shape the kernel's own platform surface uses. So the handler executes on a
    different thread from the one this fixture ran on. `check_same_thread=False`
    lifts pysqlite's affinity assertion, and `StaticPool` keeps it to a SINGLE
    connection: the default pool would hand the worker thread a NEW connection,
    which for `sqlite://` is a brand-new empty database, and every screen would
    fail with `no such table: mod_deploy.deployment_targets`.
    """
    engine = create_engine(
        "sqlite://",
        future=True,
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )

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
        # A WORD, and one a browser may legitimately send. Every test that is
        # about something else needs it present, or the command's own
        # vocabulary refusal would fire first and every refusal in this file
        # would read the same.
        "operation": "deploy",
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

    def test_a_clean_submission_reaches_the_handler_and_is_refused_elsewhere(
        self, db: Session
    ) -> None:
        """POSITIVE CONTROL — the half that stops all of the above being a guard
        that refuses everything.

        The same submission WITHOUT a digest is not refused by
        `refuse_client_supplied_digest`. It gets past it, reaches the handler,
        and is refused there for a different reason and in different words: this
        surface cannot bind a plan to an execution plan the Deployment
        Foundation rendered, because it is forbidden to send a digest and has
        rendered nothing.

        Two refusals with two texts is what makes the three plants above
        attributable. A single "400 for everything" surface would satisfy them
        all and prove nothing.
        """
        target_id = _target(db)
        preview = preview_plan_proposal(db, target_id)
        assert preview is not None
        app = _app(db, principal=_principal())

        response = call(
            app,
            "POST",
            f"/deployments/{target_id}/plans",
            form=_propose_form(preview.desired_revision, operation="deploy"),
        )

        assert response.status == 400, response.text
        # NOT the digest guard's words. That is the whole assertion.
        assert "supplies a plan digest" not in response.text
        assert "execution plan digest" in response.text
        assert self._plans(db) == 0

    def test_an_operation_outside_the_closed_vocabulary_is_refused(
        self, db: Session
    ) -> None:
        """The operation IS a thing a browser may send — it is a word, not a
        digest — and the vocabulary is closed. `redeploy` is not coerced to
        `deploy`, and neither is `Deploy`."""
        target_id = _target(db)
        app = _app(db, principal=_principal())

        for word in ("redeploy", "Deploy", ""):
            response = call(
                app,
                "POST",
                f"/deployments/{target_id}/plans",
                form=_propose_form(1, operation=word),
            )
            assert response.status == 400, response.text
            assert "is not an operation" in response.text, word
        assert self._plans(db) == 0

    def test_the_stored_digest_is_recomputable_from_the_target_alone(
        self, db: Session
    ) -> None:
        """The property the old positive control carried, asserted where it can
        still be reached: the plan's digest is a FUNCTION of module-owned state,
        reproducible without the request that created it.

        Driven through the service rather than the surface, because the surface
        can no longer create a plan — and stating the property against the
        service is the honest place for it, since it was never a property of the
        route.
        """
        target_id = _target(db)
        plan = propose_plan(
            db,
            ProposePlanCommand(
                command_id=str(uuid.uuid4()),
                target_id=target_id,
                operation="deploy",
                descriptor_digest=_DESCRIPTOR,
                execution_plan_digest=_EXECUTION_PLAN,
                requires_approval=False,
            ),
        )
        target = db.get(DeploymentTarget, target_id)
        assert target is not None
        assert (
            plan.plan_digest
            == plan_digest_of(
                plan_snapshot(target, descriptor_digest=_DESCRIPTOR)
            ).canonical
        )
        # And the value the browser could never have sent is stored EXACTLY as
        # the caller supplied it — not re-rendered, not normalized.
        assert plan.execution_plan_digest == _EXECUTION_PLAN

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
    propose_plan(
        db,
        ProposePlanCommand(
            command_id=str(uuid.uuid4()),
            target_id=target_id,
            operation="deploy",
            descriptor_digest=_DESCRIPTOR,
            execution_plan_digest=_EXECUTION_PLAN,
            requires_approval=False,
        ),
    )
    app = _app(db, principal=_principal())
    response = call(app, "GET", f"/deployments/{target_id}")

    assert response.status == 200, response.text
    assert "+00:00" not in response.text
    assert "datetime.datetime(" not in response.text


# ── Three states in Python are three states on the screen ───────────────────
#
# THE FAILURE THIS SECTION EXISTS FOR is not a wrong value; it is a value that
# is right in Python and flattened in Jinja. `PlanView.operation_is_executable`
# is `bool | None`, `TargetView.desired_images` and `PlanView.authorized_images`
# are `tuple | None`, and `ExecutionBindingStanding` has four members — and
# every one of them collapses under `{% if value %}`, under
# `{% for x in value or () %}`, and under a cell that renders an em dash for
# anything falsy. Jinja is where the type checker stops looking.
#
# So every assertion below is on the RESPONSE BODY and states both directions:
# the state that IS rendered, and the neighbouring state that must not be.
# Asserting only the first passes against a template that renders one phrase for
# two states.
#
# The rendered spans are matched with their closing tag (`>executable</span>`)
# rather than as bare words, because "not executable" contains "executable" and
# an assertion that could not tell them apart would be exactly the flattening it
# is meant to catch.

_NOT_DECLARED = ">not declared</span>"
_NONE_AUTHORIZED = ">none authorized</span>"
_EXECUTABLE = ">executable</span>"
_NOT_EXECUTABLE = ">not executable</span>"
_MATCHES = ">matches</span>"
_DIVERGES = ">diverges</span>"
_NOT_AUTHORIZED = ">not authorized</span>"
_UNBOUND = ">unbound</span>"
_NO_PLAN = ">no plan</span>"
_AWAITING = ">awaiting a decision</span>"


def _image(service: str = "api") -> dict[str, str]:
    return {
        "service": service,
        "repository": f"registry.dotmac.io/{service}",
        "digest": "sha256:" + "aa" * 32,
    }


def _target_with_images(db: Session, images: object):  # type: ignore[no-untyped-def]
    """A target whose declared image set is exactly what the caller says.

    `images` is passed through untouched so the three states reach the column:
    `None` (never declared), `[]` (authorizes none) and a list.
    """
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
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=str(uuid.uuid4()),
            target_id=view.id,
            desired=DesiredDeployment(
                release_ref="release-1",
                spec={"replicas": 2},
                licence_ref="lic-1",
                images=images,  # type: ignore[arg-type]
            ),
        ),
    )
    return view.id


def _plan(db: Session, target_id, operation: str = "deploy", **extra: object):  # type: ignore[no-untyped-def]
    fields: dict[str, object] = {
        "command_id": str(uuid.uuid4()),
        "target_id": target_id,
        "operation": operation,
        "descriptor_digest": _DESCRIPTOR,
        "execution_plan_digest": _EXECUTION_PLAN,
        "requires_approval": True,
        "approval_policy_code": "deployment.production",
        "approval_policy_version": 4,
    }
    fields.update(extra)
    return propose_plan(db, ProposePlanCommand(**fields))  # type: ignore[arg-type]


def _approve(db: Session, plan):  # type: ignore[no-untyped-def]
    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=str(uuid.uuid4()),
            plan_id=plan.id,
            evidence=ApprovalEvidence(
                policy_code="deployment.production",
                policy_version=4,
                decision_ref=f"apr-{uuid.uuid4().hex[:8]}",
                content_digest=plan.plan_digest or "",
                decided_at=datetime(2026, 9, 4, 12, 0, tzinfo=UTC),
                operation="deploy",
                execution_plan_digest=_EXECUTION_PLAN,
                decision_status="granted",
            ),
        ),
    )


class TestTheDeclaredImageSetRendersThreeWays:
    """`None` is not `()`. Asserted on the fleet list, which renders the target's
    image set and no plan's — so a phrase found there came from this column."""

    def test_a_target_that_declared_nothing_says_so(self, db: Session) -> None:
        _target_with_images(db, None)
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert _NOT_DECLARED in response.text
        assert _NONE_AUTHORIZED not in response.text, (
            "an undeclared image set rendered as a deliberate empty one; the "
            "screen told an operator this target authorizes no image when "
            "nobody has said anything about images at all"
        )

    def test_a_target_that_declared_an_empty_set_says_THAT(self, db: Session) -> None:
        _target_with_images(db, [])
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert _NONE_AUTHORIZED in response.text
        assert _NOT_DECLARED not in response.text, (
            "a deliberate empty set rendered as 'nobody declared one' -- the "
            "opposite flattening, and the one a `or ()` in the loop produces"
        )

    def test_a_declared_set_renders_the_images_and_neither_phrase(
        self, db: Session
    ) -> None:
        """THE POSITIVE CONTROL for the two above. Without it both pass against
        a column that renders one of those phrases unconditionally."""
        _target_with_images(db, [_image()])
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert "api=registry.dotmac.io/api@sha256:" + "aa" * 32 in response.text
        assert _NOT_DECLARED not in response.text
        assert _NONE_AUTHORIZED not in response.text

    def test_the_plans_table_gives_the_frozen_set_its_own_three_way_branch(
        self, db: Session
    ) -> None:
        """The plan's `authorized_images` is `| None` and the receipt's is not.

        A plan frozen from a target that declared nothing must say `not
        declared` in its own cell rather than render an empty one — which is
        what `{% for image in plan.authorized_images or () %}` produces, and
        what the receipt's columns may correctly do because their field has no
        `None` state to lose.
        """
        target_id = _target_with_images(db, None)
        _plan(db, target_id)
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        # Twice: the target's declared set and the plan's frozen copy of it.
        assert response.text.count(_NOT_DECLARED) >= 2, (
            "the plan's frozen image set rendered as an empty cell; an operator "
            "cannot tell a plan that authorizes no image from one whose target "
            "never declared a set"
        )


class TestExecutabilityRendersThreeWays:
    """`None` is not `False`. The module says `False` when it knows the
    counterparty cannot perform the operation, and `None` when the plan names
    none to ask about — 'this can never run' versus 'nobody has said'."""

    def test_a_deploy_plan_reads_executable(self, db: Session) -> None:
        target_id = _target_with_images(db, [_image()])
        _plan(db, target_id, operation="deploy")
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _EXECUTABLE in response.text
        assert _NOT_EXECUTABLE not in response.text

    def test_a_recover_plan_reads_NOT_executable_and_still_renders(
        self, db: Session
    ) -> None:
        """The operation the pinned executor cannot perform. The page must show
        it as inexecutable and must still be a page: a screen that raised on a
        historical operation is the read-path-calls-the-write-gate defect
        arriving one layer up."""
        target_id = _target_with_images(db, [_image()])
        _plan(db, target_id, operation="recover")
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _NOT_EXECUTABLE in response.text
        assert _EXECUTABLE not in response.text

    def test_a_plan_declaring_no_operation_reads_not_declared(
        self, db: Session
    ) -> None:
        """The third state, and not a soft 'no'.

        The target declares an image set on purpose: both image columns then
        render images, so `not declared` on this page can only have come from
        the executability cell.
        """
        target_id = _target_with_images(db, [_image()])
        plan = _plan(db, target_id)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.operation = None
        row.authorized_operation = None
        db.flush()
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _NOT_DECLARED in response.text
        assert _NOT_EXECUTABLE not in response.text, (
            "a plan that names no operation rendered as one the executor "
            "cannot perform"
        )
        assert _EXECUTABLE not in response.text


class TestTheExecutionBindingRendersFourWays:
    """`UNAUTHORIZED` must never render as `DIVERGES`.

    They are the pair a `proposed != authorized` comparison merges, and they
    send an operator to different systems: one to the approvals authority, the
    other to whoever can edit this database.
    """

    def test_a_proposed_but_unapproved_plan_is_NOT_AUTHORIZED_not_DIVERGES(
        self, db: Session
    ) -> None:
        """THE named condition."""
        target_id = _target_with_images(db, [_image()])
        _plan(db, target_id)
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _NOT_AUTHORIZED in response.text
        assert _DIVERGES not in response.text, (
            "a plan waiting for a decision rendered as an execution binding "
            "that disagrees with itself -- a tampering-shaped finding about a "
            "plan nothing is wrong with"
        )
        assert _MATCHES not in response.text

    def test_an_approved_plan_MATCHES(self, db: Session) -> None:
        """THE POSITIVE CONTROL. Three refusals above and no admission would
        pass against a column that never says `matches`."""
        target_id = _target_with_images(db, [_image()])
        _approve(db, _plan(db, target_id))
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _MATCHES in response.text
        assert _NOT_AUTHORIZED not in response.text
        assert _DIVERGES not in response.text

    def test_an_edited_authorization_DIVERGES(self, db: Session) -> None:
        """Nothing in this package can write this row — `approve_plan` refuses
        evidence that does not match what was proposed — so it is planted the
        only way it can occur: by editing the database behind the module."""
        target_id = _target_with_images(db, [_image()])
        plan = _approve(db, _plan(db, target_id))
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.authorized_execution_plan_digest = "sha256:" + "9f" * 32
        db.flush()
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _DIVERGES in response.text
        assert _MATCHES not in response.text

    def test_a_plan_binding_no_execution_is_UNBOUND(self, db: Session) -> None:
        """A `0.1.0a7` row. Not a binding that failed — one that was never
        made — and rendering it as a mismatch would report a schema-era absence
        as an incident."""
        target_id = _target_with_images(db, [_image()])
        plan = _plan(db, target_id)
        row = db.get(DeploymentPlan, plan.id)
        assert row is not None
        row.execution_plan_digest = None
        db.flush()
        response = call(
            _app(db, principal=_principal()), "GET", f"/deployments/{target_id}"
        )
        assert response.status == 200, response.text
        assert _UNBOUND in response.text
        assert _NOT_AUTHORIZED not in response.text
        assert _DIVERGES not in response.text


class TestTheApprovalStandingRendersFourWays:
    """On the fleet list, where the question is which targets hold an undecided
    or withdrawn authorization. `no plan` and `awaiting a decision` are the pair
    that must not merge — the second is the one an operator is scanning for."""

    def test_a_target_with_no_plan_says_no_plan(self, db: Session) -> None:
        _target_with_images(db, [_image()])
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert _NO_PLAN in response.text
        assert _AWAITING not in response.text

    def test_a_plan_carrying_no_decision_says_awaiting_a_decision(
        self, db: Session
    ) -> None:
        target_id = _target_with_images(db, [_image()])
        _plan(db, target_id)
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert _AWAITING in response.text
        assert _NO_PLAN not in response.text
        assert ">granted</span>" not in response.text, (
            "a plan carrying no decision rendered as an approved one -- an "
            "authorization read out of a blank column"
        )

    def test_an_approved_plan_says_granted(self, db: Session) -> None:
        target_id = _target_with_images(db, [_image()])
        _approve(db, _plan(db, target_id))
        response = call(_app(db, principal=_principal()), "GET", "/deployments")
        assert response.status == 200, response.text
        assert ">granted</span>" in response.text
        assert _AWAITING not in response.text
        assert _NO_PLAN not in response.text
