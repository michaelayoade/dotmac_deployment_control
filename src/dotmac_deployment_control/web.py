"""The operator's browser surface, contributed to the `platform_admin` facet.

A contract-v2 `WebSurfaceContribution` — not legacy `web_routers`/`nav`. The
distinction is not stylistic: the legacy adapter is staff-admin-only and the
kernel refuses to compose it without a facet carrying an `admission_permission`,
which a platform-plane assembly is simultaneously forbidden to declare (the
permission would be evaluated with `authorize_party`, and there is no
tenant-scoped `Party` on this plane). A v2 contribution joins the existing
platform facet instead, and the facet owns the prefix, the shell, the session
policy and the authentication.

## What this file is allowed to be

An adapter. It validates the request, asks the module's own service layer, and
renders. It builds no query, holds no state and reimplements no command — every
statement these screens need is a typed read contract in `service.py`
(`list_targets`, `preview_plan_proposal`, `plans_for_target`,
`rollouts_for_target`, `observation_log`, `observation_receipts`, `drift`). A
consuming assembly building those queries itself would be a second read
authority over tables it does not own.

The prose here deliberately does not spell the SQLAlchemy statement
constructor. `test_read_contracts.py`'s query-construction guard is a substring
scan over every module beside `service.py`, and a docstring explaining that this
file contains none would trip it — the exact false positive
`TestNoTransportCameAcross` moved to an AST for. The guard is right to stay
strict; the sentence is what changes.

## It declares no authentication, and that is deliberate

The composed `platform_admin` facet authenticates every non-entry route it
mounts, through the assembly-bound `kernel_platform_session` profile. Adding a
guard here would be a SECOND authentication owner on the same route, not defence
in depth — and the obvious candidate, the kernel's `require_platform_admin`, is
the BEARER guard for the JSON API. Carrying it inside a browser facet makes a
valid cookie session pass the facet and then fail the handler for want of an
`Authorization` header, which is a 401 on the one credential the screen exists
to accept. The two credential populations stay apart.

So the actor is read from `dotmac_kernel.facet_principal`, the request-scoped
projection of whoever the facet already authenticated. It reads no cookie, no
header and no database; it refuses an absent principal and refuses one from the
wrong security plane. This surface declares `PLATFORM`, so a tenant-plane
identity can never be attributed a fleet decision.

## The digest a browser may not send

`propose_plan` derives a plan's digest from state this module owns, and an
approval is later bound to that digest. A caller that could supply one would be
naming the thing its own authorization is checked against.

`ProposePlanCommand` carries no PLAN digest field, so the write path cannot
accept one, and `PlanProposalPreview` takes no input, so the read path cannot
either. Those are absences, and an absence is a convention: nothing fails if a
later change adds a field, and nothing ever observed it holding.

It does carry an `execution_plan_digest`, and that is not a loosening of this
rule — it is the rule applied to a value of the opposite kind. A plan digest is
DERIVED by Control, so a caller naming one would be choosing what its own
approval binds to. An execution plan digest is the Deployment Foundation's,
over bytes Control has no renderer for and cannot reach; a value this module
cannot derive must be supplied or the binding cannot exist.

**A browser still cannot supply one, and the consequence is deliberate.**
`refuse_client_supplied_digest` refuses it by SHAPE whatever the field is
called, which is right: a browser is not the Deployment Foundation and has
rendered no execution plan. So `POST /deployments/{id}/plans` from this surface
now refuses — the command cannot be constructed without a binding, and the route
renders the module's own words at 400. That is the architecture and not a
regression: a proposal that can produce a receipt is made by Platform CP's
composition adapter, after the Foundation has rendered and digested the plan.
An operator's part of the flow is upstream, in the desired state this surface
already shows.

`refuse_client_supplied_digest` is the same rule as a REFUSAL, and it is
declared on the ROUTER so it covers every route in this surface rather than the
ones somebody remembered. It inspects query parameters and, for unsafe methods,
the form body, and it refuses in two directions:

* by NAME — a parameter called `plan_digest`, `content_digest`, `digest`…;
* by SHAPE — any value that looks like a digest this module would have issued
  (`sha256:<64 hex>`, or a4's bare 64-hex form), whatever the field is called.

The second is what keeps the first from being cosmetic: renaming the field does
not get a digest past it, and neither does hiding one in a field the surface
does legitimately accept.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Annotated, Any, Final
from uuid import UUID

from dotmac_kernel.deps import get_platform_db
from dotmac_kernel.facet_principal import require_facet_principal
from dotmac_kernel.templating import render
from dotmac_kernel.web_surfaces import (
    BrowserSecurityPlane,
    LocalizedText,
    TemplatePackage,
    WebNavItem,
    WebSurfaceContribution,
    surface_path,
)
from fastapi import APIRouter, Depends, HTTPException, Request, status
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session

from dotmac_deployment_control import facts, service
from dotmac_deployment_control.ports import DeploymentControlError

#: The stable identity of this contribution inside the facet. Route names are
#: derived from it by the kernel, so it is part of the composed surface's
#: contract and not a label.
SURFACE_CODE: Final[str] = "deployments"

#: Templates ship as PACKAGE DATA and resolve through this namespace, which the
#: kernel installs on a prefix loader. Namespaced rather than anonymous is the
#: point: an assembly file called `targets.html` cannot silently shadow the
#: module's own screen.
TEMPLATE_NAMESPACE: Final[str] = "deployment_control"

#: Field names that are asking for a digest by any spelling. Matched on the
#: normalized parameter name, so `Plan-Digest` and `plan_digest` are one thing.
_DIGEST_FIELD_NAMES: Final[frozenset[str]] = frozenset(
    {
        "digest",
        "plan_digest",
        "plandigest",
        "content_digest",
        "spec_digest",
        "snapshot_digest",
        "payload_digest",
        "raw_body_digest",
        "expected_digest",
    }
)

#: The two encodings this module has ever issued for a digest: the canonical
#: `sha256:<64 lowercase hex>` and `0.1.0a4`'s bare hex. Matching the a4 form is
#: not nostalgia — a refusal that only knew the current spelling would be got
#: past by sending the old one.
_DIGEST_VALUE = re.compile(r"\A(?:sha256:)?[0-9a-fA-F]{64}\Z")

#: Fields this surface genuinely reads. Anything else in a submitted form is
#: refused rather than ignored: a field the server silently drops is a field an
#: operator believes they set.
_PROPOSE_FIELDS: Final[frozenset[str]] = frozenset(
    {
        "expected_desired_revision",
        "requires_approval",
        "approval_policy_code",
        "approval_policy_version",
        # A WORD, not a digest, and therefore a thing a browser may legitimately
        # send: `deploy` or `rollback`, declared by the operator. Michael's rule
        # is that an operation is never inferred — not from a diff, not from a
        # command name — so the surface that offers the action must name it, and
        # a form with two buttons is exactly that declaration.
        "operation",
    }
)

#: `require_csrf` puts its proof here and the kernel validates it before this
#: surface sees the request. It is allowed through the field allowlist for that
#: reason and for no other.
_CSRF_FIELD: Final[str] = "csrf_token"

#: The platform-plane session, declared once. `Annotated` rather than a
#: `Depends(...)` default: the default form evaluates a call at import time,
#: and one alias also means the surface has exactly one place where it says
#: which database plane it reads.
PlatformSession = Annotated[Session, Depends(get_platform_db)]

_PAGE_SIZE: Final[int] = 25
_LOG_LIMIT: Final[int] = 100


class BrowserSuppliedDigestError(HTTPException):
    """A browser request carried a digest. It never may.

    A 400 rather than a rendered page on purpose: this is a protocol violation
    by whatever built the request, not an operator mistake to be explained on a
    screen. An operator has no way to produce it through the interface.
    """

    def __init__(self, where: str) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"this request supplies a plan digest ({where}). Deployment "
                "Control derives a plan's digest from state it owns, and an "
                "approval is bound to that value; a digest chosen by the "
                "caller would name the thing its own authorization is checked "
                "against. No screen in this surface submits one."
            ),
        )


class BrowserFieldError(HTTPException):
    """A submitted form carried a field this surface does not read."""

    def __init__(self, names: tuple[str, ...]) -> None:
        super().__init__(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                f"unexpected form field(s): {', '.join(names)}. This surface "
                "reads a closed set of fields; one it silently ignored would be "
                "a value an operator believes they set."
            ),
        )


def _digest_offence(name: str, value: str) -> str | None:
    """Name the offence, or `None`. Both directions, and the order matters:
    a field NAMED for a digest is refused even when empty, because the shape it
    is asking for is the problem."""
    if name.strip().lower().replace("-", "_") in _DIGEST_FIELD_NAMES:
        return f"field {name!r}"
    if _DIGEST_VALUE.fullmatch(value.strip()):
        return f"the value of {name!r}"
    return None


async def refuse_client_supplied_digest(request: Request) -> None:
    """Router-level: no request into this surface may carry a digest.

    Declared once on the router rather than per handler. A per-handler check is
    a rule the next route can forget; this one holds for every route that has
    ever been mounted here and for every route that ever will be.

    Both halves of the request are inspected, because a browser can put a value
    in either. The form is read only for unsafe methods — Starlette caches the
    parsed body, so this does not consume it out from under `require_csrf` or
    the handler.
    """
    for name, value in request.query_params.multi_items():
        offence = _digest_offence(name, value)
        if offence is not None:
            raise BrowserSuppliedDigestError(f"{offence} in the query string")
    if request.method in {"GET", "HEAD", "OPTIONS", "TRACE"}:
        return
    form = await request.form()
    for field, submitted in form.multi_items():
        offence = _digest_offence(field, str(submitted))
        if offence is not None:
            raise BrowserSuppliedDigestError(f"{offence} in the form body")


router = APIRouter(
    tags=["deployment-control-web"],
    dependencies=[Depends(refuse_client_supplied_digest)],
)


def _moment(value: datetime | None) -> str:
    """A timestamp, rendered UNAMBIGUOUSLY in UTC, or an em dash.

    Deliberately NOT the kernel's `local_datetime`/`local_date` filters, and the
    reason is a composition fact rather than a preference. Those read
    `DisplaySettings`, which is resolved per TENANT (`load_display(db,
    tenant_id)`) and falls back to `default_display()` — which itself reads the
    `display` setting specs. This is the PLATFORM plane: there is no tenant, and
    an assembly that never registered those specs (the vendor control plane does
    not) would get a `KeyError` out of the fallback and a 500 out of every
    screen that rendered a date.

    A fleet operator is also the reader least served by a localized stamp: the
    deployments are in different places, the reports arrive from all of them,
    and "when did this arrive relative to that" is the question. So the surface
    states UTC and says so, the same choice the JSON API makes.

    Naive values are treated as UTC, which is what this module stores and what
    SQLite hands back; an aware value is converted rather than assumed.
    """
    if value is None:
        return "\u2014"
    moment = value if value.tzinfo is not None else value.replace(tzinfo=UTC)
    return moment.astimezone(UTC).strftime("%Y-%m-%d %H:%M:%S UTC")


def _render(
    request: Request,
    template: str,
    context: dict[str, Any],
    *,
    status_code: int = 200,
) -> HTMLResponse:
    """Render one of this surface's screens.

    The single place `moment` enters a template context. Passing it per render
    rather than installing a Jinja global is the point: a module that reached
    into the shared environment would be changing every other surface's
    templates from inside its own package.
    """
    return render(
        request,
        f"{TEMPLATE_NAMESPACE}/{template}",
        {**context, "moment": _moment},
        status_code=status_code,
    )


def _actor_ref(request: Request) -> str:
    """Who the FACET authenticated, projected — never re-authenticated here.

    `plane=PLATFORM` is a declaration by this caller, not a reading of whatever
    turned up: it is what lets the projection refuse a tenant-plane identity
    rather than quietly attributing a fleet decision to it.
    """
    principal = require_facet_principal(request, plane=BrowserSecurityPlane.PLATFORM)
    return f"platform-admin:{principal.subject_id}"


async def _read_form(request: Request, allowed: frozenset[str]) -> dict[str, str]:
    """The submitted fields, refusing any this surface does not read."""
    form = await request.form()
    permitted = allowed | {_CSRF_FIELD}
    unexpected = tuple(sorted({k for k in form if k not in permitted}))
    if unexpected:
        raise BrowserFieldError(unexpected)
    return {key: str(form[key]) for key in form if key != _CSRF_FIELD}


def _optional_int(values: Mapping[str, str], name: str) -> int | None:
    raw = values.get(name, "").strip()
    if not raw:
        return None
    try:
        return int(raw)
    except ValueError:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"{name} must be a whole number, got {raw!r}",
        ) from None


# ── Screens ─────────────────────────────────────────────────────────────────


@router.get("/deployments", response_class=HTMLResponse, name="targets")
def targets(
    request: Request,
    db: PlatformSession,
    product_code: str | None = None,
    environment: str | None = None,
    target_status: str | None = None,
    never_observed: bool | None = None,
    page: int = 1,
) -> HTMLResponse:
    """The fleet, filtered by the module's own typed filter.

    The query parameters are mapped onto `TargetFilter` and nothing else. There
    is no sort column, no predicate and no page-size parameter: an unbounded or
    caller-shaped query would make every future read the client's decision, and
    `TargetFilter` is where this module says what its read surface is.

    `target_status` rather than `status` because `status` is what an HTTP
    response has; naming the filter after the domain keeps the two apart in the
    handler signature.
    """
    try:
        criteria = facts.TargetFilter(
            product_code=product_code or None,
            environment=environment or None,
            status=target_status or None,
            never_observed=never_observed,
            page=max(1, page),
            page_size=_PAGE_SIZE,
        )
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc
    result = service.list_targets(db, criteria)
    return _render(
        request,
        "targets.html",
        {
            "page_title": "Deployments",
            "result": result,
            "criteria": criteria,
        },
    )


def _detail_context(
    db: Session, target_id: UUID, *, refusal: str | None = None
) -> dict[str, Any]:
    """Everything one target's page shows, read through the module's contracts.

    Assembled here rather than in the template because a template that fetched
    its own panels would be deciding what the page means. Every value below is a
    frozen view or a scalar; no ORM row reaches Jinja.
    """
    target = service.get_target(db, target_id)
    if target is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail="Deployment target not found"
        )
    return {
        "page_title": f"Deployment — {target.target_ref}",
        "target": target,
        # The plan that WOULD be frozen, and its server-derived digest. The one
        # place either is computed is `preview_plan_proposal`.
        "preview": service.preview_plan_proposal(db, target_id),
        "plans": service.plans_for_target(db, target_id),
        "rollouts": service.rollouts_for_target(db, target_id),
        # Reconciliation. `drift` is computed on demand and never cached, so a
        # screen cannot show a stale verdict.
        "drift": service.drift(db, target_id),
        "receipts": service.observation_receipts(
            db, target_ref=target.target_ref, limit=_LOG_LIMIT
        ),
        "arrivals": service.observation_log(
            db, target_ref=target.target_ref, limit=_LOG_LIMIT
        ),
        "refusal": refusal,
    }


@router.get(
    "/deployments/{target_id}", response_class=HTMLResponse, name="target_detail"
)
def target_detail(
    request: Request,
    target_id: UUID,
    db: PlatformSession,
) -> HTMLResponse:
    return _render(request, "target_detail.html", _detail_context(db, target_id))


@router.post(
    "/deployments/{target_id}/plans",
    response_model=None,
    name="propose_plan",
)
async def propose_plan_submit(
    request: Request,
    target_id: UUID,
    db: PlatformSession,
) -> HTMLResponse | RedirectResponse:
    """Freeze a plan from the coordinates the operator was shown.

    What crosses the wire is `expected_desired_revision` — an integer THIS
    MODULE issued, identifying which desired state the preview described — plus
    the approval policy the operator is declaring this plan sensitive under.
    Nothing else. The canonical plan and its digest are derived by
    `propose_plan` from the target, exactly as `preview_plan_proposal` derived
    the ones on the page.

    The command id is derived from the same coordinates rather than generated,
    so a double submit lands on the kernel's at-most-once ledger and returns the
    plan the first one made instead of a second plan for the same revision.
    """
    values = await _read_form(request, _PROPOSE_FIELDS)
    actor = _actor_ref(request)
    expected = _optional_int(values, "expected_desired_revision")
    if expected is None:
        # The coordinate is REQUIRED here even though the command treats it as
        # optional, and the two are not in tension: a caller inside one
        # transaction has no gap between reading and writing, while a browser
        # always does. Without it this route would freeze whatever is current
        # and the command id below would degenerate to one key per target,
        # making a later legitimate proposal look like a replay of this one.
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(
                "expected_desired_revision is required. A plan is created from "
                "the immutable coordinates the operator was shown, so this "
                "route will not freeze a desired state nobody read."
            ),
        )
    requires_approval = values.get("requires_approval", "").strip().lower() in {
        "on",
        "true",
        "yes",
        "1",
    }
    # CONSTRUCTED INSIDE THE TRY, because the command now refuses on its own
    # inputs: an operation outside the closed vocabulary, and — from this
    # surface, always — the absence of an execution plan digest a browser is
    # forbidden to send. Both are `DeploymentControlError`s the operator should
    # read at 400 on the page they came from, not 500s from a construction that
    # happened outside the handler.
    try:
        command = service.ProposePlanCommand(
            command_id=f"web.propose_plan:{target_id}:{expected}",
            target_id=target_id,
            operation=values.get("operation", "").strip(),
            # THE ABSENCE, stated. There is no value this surface could put
            # here: `refuse_client_supplied_digest` rejects a digest by shape
            # whatever it is called, and it is right to — a browser has rendered
            # no execution plan. The empty string is refused by the command, and
            # the refusal explains where a bound proposal comes from instead.
            execution_plan_digest="",
            requires_approval=requires_approval,
            approval_policy_code=values.get("approval_policy_code", "").strip() or None,
            approval_policy_version=_optional_int(values, "approval_policy_version"),
            expected_desired_revision=expected,
            actor_ref=actor,
        )
        service.propose_plan(db, command)
    except DeploymentControlError as exc:
        # The module refused. Re-render the page it was refused from, at 400,
        # carrying the module's own words: a surface that paraphrased them would
        # be a second, untested account of why deployments are refused.
        return _render(
            request,
            "target_detail.html",
            _detail_context(db, target_id, refusal=str(exc)),
            status_code=status.HTTP_400_BAD_REQUEST,
        )
    return RedirectResponse(
        url=surface_path(request, "target_detail", target_id=target_id),
        status_code=status.HTTP_303_SEE_OTHER,
    )


@router.get("/deployment-arrivals", response_class=HTMLResponse, name="arrivals")
def arrivals(
    request: Request,
    db: PlatformSession,
) -> HTMLResponse:
    """Every inbound observation, including the ones that proved nothing.

    This screen exists for the rows a per-target page structurally cannot show.
    An arrival under an unknown key, a malformed envelope or a bad signature
    never resolves to a target, so it appears on no target's detail page — and
    those are precisely the tripwires. A fleet-wide log is where the
    missing-evidence cases are visible at all.
    """
    return _render(
        request,
        "arrivals.html",
        {
            "page_title": "Deployment arrivals",
            "arrivals": service.observation_log(db, limit=_LOG_LIMIT),
            "receipts": service.observation_receipts(db, limit=_LOG_LIMIT),
        },
    )


# ── The composed contribution ───────────────────────────────────────────────

#: Where the packaged templates live, resolved by PACKAGE PATH. An installed
#: wheel lives outside any assembly's working directory, so a relative lookup
#: would find nothing; `pyproject.toml` ships this directory as package data and
#: `scripts/artifact_canaries.py` proves it against the built artifact rather
#: than against this tree.
_TEMPLATE_ROOT = TemplatePackage(
    namespace=TEMPLATE_NAMESPACE,
    root=Path(__file__).resolve().parent / "templates",
)

DEPLOYMENT_CONTROL_SURFACE = WebSurfaceContribution(
    code=SURFACE_CODE,
    # The kernel's existing platform facet. It owns `/platform`, the shell
    # template, the session policy and the authentication; this module supplies
    # routes and navigation and authors none of those things. Every path above
    # is facet-relative for that reason — a route that spelled the prefix would
    # be a second opinion about where these pages live.
    facet="platform_admin",
    routers=(router,),
    navigation=(
        WebNavItem(
            code="deployment_control.fleet",
            region="primary",
            label=LocalizedText("deployment_control.nav.fleet", "Deployments"),
            route_name="targets",
            order=40,
        ),
        WebNavItem(
            code="deployment_control.arrivals",
            region="primary",
            label=LocalizedText("deployment_control.nav.arrivals", "Arrivals"),
            route_name="arrivals",
            order=50,
        ),
    ),
    templates=_TEMPLATE_ROOT,
    # UI contract 1, which is the contract `dotmac-ui` publishes today and the
    # one the kernel's own platform surface declares. It is a different axis
    # from the module contract version above: this says what the SCREENS may
    # assume about tokens and classes, and declaring a contract nobody has
    # published would refuse composition rather than gain anything.
    supported_ui_contract_versions=frozenset({1}),
)

__all__ = [
    "DEPLOYMENT_CONTROL_SURFACE",
    "SURFACE_CODE",
    "TEMPLATE_NAMESPACE",
    "BrowserFieldError",
    "BrowserSuppliedDigestError",
    "refuse_client_supplied_digest",
    "router",
]
