"""Structural guards for the browser surface, each with a sensitivity proof.

`tests/unit/test_deployment_control_browser_surface.py` drives the surface with
real requests on a bare application. That is the right place to observe the
refusal firing and the wrong place to prove anything about COMPOSITION: a bare
router is not what a consuming assembly mounts.

So this file composes the module into a real `WebSurfaceRegistry` against the
kernel's own `platform_admin` facet and asks the composed graph what it carries.
Every guard here is exercised twice — once against the real surface and once
against a planted violation — because a check nobody has seen refuse is a step
name (ADR-0018).

Static and in-memory: no database, no network, no application startup.
"""

from __future__ import annotations

import ast
import dataclasses
import re
from pathlib import Path
from typing import Any

import pytest
from dotmac_kernel.deps import require_permission
from dotmac_kernel.middleware.csrf import CSRF_PROTECTED_ATTR
from dotmac_kernel.platform_auth import (
    PLATFORM_COOKIE,
    PLATFORM_COOKIE_AUTHENTICATION,
)
from dotmac_kernel.route_metadata import CAPABILITY_CODE_ATTR, PERMISSION_CODE_ATTR
from dotmac_kernel.web_runtime import mount_web_surfaces
from dotmac_kernel.web_surfaces import (
    AuthenticationProfileBinding,
    BrowserSecurityPlane,
    BrowserSessionPolicy,
    LocalizedText,
    NavigationRegion,
    RouteCompositionError,
    TemplateRef,
    WebFacetMount,
    WebNavItem,
    WebSurfaceContribution,
    WebSurfaceRegistry,
)
from fastapi import APIRouter, Depends, FastAPI
from fastapi.routing import APIRoute

from dotmac_deployment_control import DEPLOYMENT_CONTROL_SURFACE, module
from dotmac_deployment_control import web as surface

REPO_ROOT = Path(__file__).resolve().parents[2]
SRC = REPO_ROOT / "src" / "dotmac_deployment_control"
WEB = SRC / "web.py"
TEMPLATES = SRC / "templates"

#: The `dotmac-ui` role tokens these screens are authored against — the CLOSED
#: vocabulary this module declares for itself.
#:
#: The list is here rather than derived, and that is deliberate: this
#: distribution does not depend on `dotmac-ui` (importing it is refused by the
#: sibling guard), so it cannot read the published token set at test time. What
#: it CAN do is refuse to grow the vocabulary silently — a new token name has to
#: be added here, in the change that uses it, where a reviewer can check it
#: against `dotmac-ui`'s published surface.
DECLARED_UI_TOKENS = frozenset(
    {
        "--dmui-action-neutral-default",
        "--dmui-action-neutral-on",
        "--dmui-action-primary-default",
        "--dmui-action-primary-on",
        "--dmui-border-default",
        "--dmui-border-strong",
        "--dmui-border-subtle",
        "--dmui-font-mono",
        "--dmui-font-size-base",
        "--dmui-font-size-sm",
        "--dmui-font-size-xs",
        "--dmui-font-weight-semibold",
        "--dmui-radius-md",
        "--dmui-radius-sm",
        "--dmui-space-2xs",
        "--dmui-space-3xs",
        "--dmui-space-lg",
        "--dmui-space-md",
        "--dmui-space-sm",
        "--dmui-status-negative-border",
        "--dmui-status-negative-foreground",
        "--dmui-status-negative-surface",
        "--dmui-status-positive-foreground",
        "--dmui-status-warning-foreground",
        "--dmui-surface-elevated",
        "--dmui-surface-primary",
        "--dmui-surface-secondary",
        "--dmui-text-primary",
        "--dmui-text-secondary",
    }
)

#: Anything that authenticates. None of it may appear in `web.py`: the facet is
#: the single browser authentication authority for this surface, and
#: `require_platform_admin` in particular is the BEARER guard — carrying it
#: inside a browser facet makes a valid cookie session fail the handler after
#: passing the facet.
AUTHENTICATION_NAMES = frozenset(
    {
        "require_platform_admin",
        "require_platform_web_auth",
        "require_web_auth",
        "require_user_auth",
        "require_role",
        "authenticate_request",
        "authenticate_platform_request",
        "authenticate_machine",
        # Not a guard, and forbidden for the opposite reason: calling it is a
        # claim to have authenticated somebody, which is exactly the authority
        # the projection refuses to distribute.
        "record_facet_principal",
    }
)


def _facet() -> tuple[WebFacetMount, AuthenticationProfileBinding]:
    """The kernel's own platform facet, reconstructed exactly.

    Rebuilt rather than imported because `dotmac_kernel.app_factory` keeps it
    private. If the kernel's shape moves, the composition below stops matching
    production and this file should be updated in the change that notices.
    """
    profile = AuthenticationProfileBinding(
        code="kernel_platform_session",
        provider=PLATFORM_COOKIE_AUTHENTICATION,
        session=BrowserSessionPolicy(
            cookie_name=PLATFORM_COOKIE, cookie_path="/platform"
        ),
        security_plane=BrowserSecurityPlane.PLATFORM,
    )
    facet = WebFacetMount(
        code="platform_admin",
        url_prefix="/platform",
        shell=TemplateRef("layouts/platform.html"),  # nosec B604 - Jinja ref
        authentication_profile=profile.code,
        navigation_regions=(NavigationRegion("primary"),),
    )
    return facet, profile


def _registry(*extra: WebSurfaceContribution) -> WebSurfaceRegistry:
    facet, profile = _facet()
    return WebSurfaceRegistry(
        manifests=(module,),
        facets=(facet,),
        authentication_profiles=(profile,),
        ui_contract_version=1,
        built_in_surfaces=tuple(("planted", item) for item in extra),
    )


def _registered() -> Any:
    for item in _registry().surfaces:
        if item.identity == (module.code, surface.SURFACE_CODE):
            return item
    raise AssertionError("the module's browser surface did not compose at all")


def _routes(contribution: WebSurfaceContribution) -> dict[str, APIRoute]:
    return {
        route.name: route
        for router in contribution.routers
        for route in router.routes
        if isinstance(route, APIRoute)
    }


def _dependency_calls(route: APIRoute) -> list[Any]:
    found: list[Any] = []

    def walk(dependant: Any) -> None:
        call = getattr(dependant, "call", None)
        if call is not None:
            found.append(call)
        for child in getattr(dependant, "dependencies", ()):
            walk(child)

    walk(route.dependant)
    return found


def _composed_routes(app: FastAPI) -> list[Any]:
    """Every composed route, across BOTH of FastAPI's include shapes.

    Through roughly 0.13x, `include_router` materialised an `APIRoute` straight
    into `app.routes`. Newer versions defer it: `app.routes` holds an
    `_IncludedRouter`, and the real route — with the include's dependencies
    merged in — is built lazily by `effective_candidates()`. This distribution
    declares `dotmac-kernel`, which accepts `fastapi >=0.111,<0.141`, so both
    shapes are resolvable and a walk that knew only one would silently find
    nothing.

    "Silently find nothing" is the failure this helper is most likely to have,
    so every caller below asserts the COUNT first. A traversal that stops
    working must fail, not pass over an empty set.
    """
    seen: set[int] = set()
    found: list[Any] = []

    def visit(node: Any) -> None:
        if id(node) in seen:
            return
        seen.add(id(node))
        if getattr(node, "dependant", None) is not None and isinstance(
            getattr(node, "name", None), str
        ):
            found.append(node)
            return
        expand = getattr(node, "effective_candidates", None)
        if callable(expand):
            for child in expand():
                visit(child)
            return
        for child in getattr(node, "routes", ()):
            visit(child)

    visit(app)
    return found


def _codes(route: APIRoute, attribute: str) -> tuple[str, ...]:
    return tuple(
        sorted(
            {
                code
                for call in _dependency_calls(route)
                if isinstance(code := getattr(call, attribute, None), str)
            }
        )
    )


# ── The contract shape ──────────────────────────────────────────────────────


class TestItIsAContractV2Contribution:
    def test_the_manifest_declares_web_surfaces_and_no_legacy_pair(self) -> None:
        """Contract 2, and nothing of the v1 shape.

        The legacy pair would drag in the compatibility adapter, which demands a
        `staff_admin` facet carrying an `admission_permission` — and the kernel
        separately REFUSES an admission permission on a platform-plane profile,
        because admission is evaluated against a tenant-scoped `Party` that does
        not exist here. For a platform assembly those two rules are jointly
        unsatisfiable, so the way through is to not be a legacy surface.
        """
        assert module.contract_version == 2
        assert module.web_surfaces == (DEPLOYMENT_CONTROL_SURFACE,)
        assert not module.web_routers
        assert not module.nav

    def test_it_joins_the_kernel_platform_facet_rather_than_declaring_one(
        self,
    ) -> None:
        assert DEPLOYMENT_CONTROL_SURFACE.facet == "platform_admin"
        assert not hasattr(DEPLOYMENT_CONTROL_SURFACE, "admission_permission")

    def test_it_declares_the_published_ui_contract(self) -> None:
        """UI contract 1 is what `dotmac-ui` publishes and what the kernel's own
        platform surface declares. Naming a contract nobody has released would
        refuse composition and gain nothing."""
        assert DEPLOYMENT_CONTROL_SURFACE.supported_ui_contract_versions == frozenset(
            {1}
        )

    def test_every_route_is_facet_relative(self) -> None:
        """The facet owns `/platform`. A route that spelled it would be a second
        opinion about where these pages live — and the kernel refuses it."""
        for name, route in _routes(DEPLOYMENT_CONTROL_SURFACE).items():
            assert not route.path.startswith("/platform"), name

    def test_a_planted_absolute_route_is_REFUSED_by_the_kernel(self) -> None:
        """SENSITIVITY. Without this, "our paths are relative" is an untested
        habit that would keep passing if the kernel dropped the rule."""
        planted = APIRouter()

        @planted.get("/platform/deployments", name="planted")
        def _planted() -> str:
            return ""

        with pytest.raises(RouteCompositionError, match="facet-relative"):
            _registry(
                WebSurfaceContribution(
                    code="planted",
                    facet="platform_admin",
                    routers=(planted,),
                    supported_ui_contract_versions=frozenset({1}),
                )
            )

    def test_the_templates_ship_beside_the_package(self) -> None:
        templates = DEPLOYMENT_CONTROL_SURFACE.templates
        assert templates is not None
        assert templates.namespace == "deployment_control"
        assert Path(templates.root).resolve() == TEMPLATES.resolve()

    def test_the_distribution_declares_the_templates_as_package_data(self) -> None:
        """The wheel must carry them. The kernel checks the template root with
        `is_dir()` while building the surface graph, so a wheel that shipped
        `web.py` alone imports cleanly and composes nowhere —
        `scripts/artifact_canaries.py` proves it against the built artifact, and
        this proves the declaration that makes it possible."""
        pyproject = (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
        assert "src/dotmac_deployment_control/templates/**/*" in pyproject


# ── Navigation authorization is DERIVED from the routes ─────────────────────


class TestNavigationCannotDriftFromItsRoutes:
    """Nav authorization and route authorization are the same fact, once.

    They cannot drift because the nav item does not DECLARE anything: the kernel
    reads the permission and capability codes off the dependency graph of the
    route each item names. The tests below state that, and then plant a guarded
    route to prove the derivation is live rather than vacuously empty.
    """

    def test_every_nav_item_names_a_route_in_this_same_surface(self) -> None:
        registered = _registered()
        routes = _routes(DEPLOYMENT_CONTROL_SURFACE)
        for item in DEPLOYMENT_CONTROL_SURFACE.navigation:
            assert item.route_name in routes, item.code
        assert len(registered.navigation) == len(DEPLOYMENT_CONTROL_SURFACE.navigation)

    def test_a_planted_nav_item_pointing_nowhere_is_REFUSED(self) -> None:
        """A dead sidebar link is a 404 an operator finds; this is where it is
        supposed to be found instead."""
        planted = APIRouter()

        @planted.get("/planted", name="planted")
        def _planted() -> str:
            return ""

        with pytest.raises(RouteCompositionError, match="missing route"):
            _registry(
                WebSurfaceContribution(
                    code="planted",
                    facet="platform_admin",
                    routers=(planted,),
                    navigation=(
                        WebNavItem(
                            code="planted.gone",
                            region="primary",
                            label=LocalizedText("planted.gone", "Gone"),
                            route_name="no_such_route",
                        ),
                    ),
                    supported_ui_contract_versions=frozenset({1}),
                )
            )

    def test_each_registered_nav_item_carries_exactly_its_routes_codes(self) -> None:
        """Derived, and re-derived here INDEPENDENTLY of the kernel's helper.

        Recomputing from the route's own dependency graph rather than asserting
        `== ()` is what makes this a parity check instead of a restatement of
        today's emptiness.
        """
        registered = _registered()
        routes = _routes(DEPLOYMENT_CONTROL_SURFACE)
        by_code = {item.code: item for item in registered.navigation}
        for declared in DEPLOYMENT_CONTROL_SURFACE.navigation:
            item = by_code[declared.code]
            route = routes[declared.route_name]
            assert item.required_permissions == _codes(route, PERMISSION_CODE_ATTR)
            assert item.required_capabilities == _codes(route, CAPABILITY_CODE_ATTR)

    def test_a_guarded_route_makes_its_nav_item_carry_the_permission(self) -> None:
        """THE SENSITIVITY PROOF, and the one that matters here.

        Every assertion above is currently comparing an empty tuple to an empty
        tuple, which is equally consistent with a kernel that derives nothing at
        all. Plant a route behind a declared permission and require the nav item
        the kernel registers for it to carry that permission. If the derivation
        is ever removed, this fails and the parity claims above stop being true
        silently.
        """
        planted = APIRouter()

        guard = require_permission("deployment.planted")

        @planted.get("/planted", name="planted", dependencies=[Depends(guard)])
        def _planted() -> str:
            return ""

        registry = _registry(
            WebSurfaceContribution(
                code="planted",
                facet="platform_admin",
                routers=(planted,),
                navigation=(
                    WebNavItem(
                        code="planted.guarded",
                        region="primary",
                        label=LocalizedText("planted.guarded", "Guarded"),
                        route_name="planted",
                    ),
                ),
                supported_ui_contract_versions=frozenset({1}),
            )
        )
        registered = next(
            item for item in registry.surfaces if item.contribution.code == "planted"
        )
        nav_item = registered.navigation[0]
        assert nav_item.required_permissions == ("deployment.planted",)


# ── Unsafe actions stay CSRF-protected, and the digest refusal survives ─────


class TestTheComposedRoutesKeepTheirGuards:
    """What the ASSEMBLY mounts, not what the bare router declares.

    The unit tests drive the surface on a bare application, which is the only
    way to observe the refusal without holding a live platform session. This
    class answers the question that shape cannot: does any of it survive
    composition?
    """

    #: Every route the surface contributes. A count, so a traversal that stops
    #: finding routes fails instead of passing over an empty set.
    EXPECTED_ROUTES = 4

    def _surface_routes(self) -> list[Any]:
        app = FastAPI()
        mount_web_surfaces(
            app, registry=_registry(), enabled_modules=frozenset({module.code})
        )
        prefix = f"web:platform_admin:{module.code}:{surface.SURFACE_CODE}:"
        routes = [
            route for route in _composed_routes(app) if route.name.startswith(prefix)
        ]
        assert len(routes) == self.EXPECTED_ROUTES, (
            f"found {len(routes)} composed routes for this surface, expected "
            f"{self.EXPECTED_ROUTES}. Either the surface changed shape or "
            "`_composed_routes` no longer understands how this FastAPI mounts "
            "an included router — and every check below would then pass over an "
            "empty set."
        )
        return routes

    def test_every_composed_route_is_mounted_under_the_facets_prefix(self) -> None:
        """The facet owns the prefix. The module authored none of these paths."""
        for route in self._surface_routes():
            assert route.path.startswith("/platform/"), route.name

    def test_every_composed_route_carries_the_kernels_csrf_dependency(self) -> None:
        """Not "the unsafe ones": the kernel puts `require_csrf` on ALL of them
        and the dependency itself exempts the safe methods. That is the shape
        that cannot be got wrong by adding a route."""
        for route in self._surface_routes():
            protected = [
                call
                for call in _dependency_calls(route)
                if getattr(call, CSRF_PROTECTED_ATTR, False)
            ]
            assert protected, f"{route.name} composed without CSRF protection"

    def test_every_composed_route_still_carries_the_digest_refusal(self) -> None:
        """The refusal is declared on the ROUTER, and the include merges
        router-level dependencies into every route it mounts. This is the check
        that the merge actually happens — a refusal that survived on the bare
        router and was dropped by composition would pass every unit test and
        protect nothing in production."""
        for route in self._surface_routes():
            assert surface.refuse_client_supplied_digest in _dependency_calls(
                route
            ), route.name

    def test_the_refusal_runs_AFTER_authentication_not_instead_of_it(self) -> None:
        """Order is a property here, not an accident.

        `mount_web_surfaces` puts CSRF and the facet's authentication in front
        of anything the module declares. So an unauthenticated request carrying
        a digest is refused as unauthenticated, and the digest refusal is what
        an authenticated caller meets. Input validation must never be the thing
        standing in for a guard.
        """
        for route in self._surface_routes():
            calls = _dependency_calls(route)
            csrf = next(
                index
                for index, call in enumerate(calls)
                if getattr(call, CSRF_PROTECTED_ATTR, False)
            )
            assert csrf < calls.index(surface.refuse_client_supplied_digest), route.name

    def test_the_detector_would_notice_a_router_without_the_refusal(self) -> None:
        """SENSITIVITY. A router built WITHOUT the dependency must fail the same
        check, or the check is measuring nothing."""
        bare = APIRouter()

        @bare.post("/planted", name="planted")
        def _planted() -> str:
            return ""

        app = FastAPI()
        app.include_router(bare)
        routes = [route for route in _composed_routes(app) if route.name == "planted"]
        assert len(routes) == 1, "the traversal could not find the planted route"
        assert surface.refuse_client_supplied_digest not in _dependency_calls(routes[0])


# ── The adapter stays an adapter ────────────────────────────────────────────


class TestTheSurfaceIsAThinAdapter:
    """No query, no session, no second authentication owner.

    Checked on the AST and not with a grep. `web.py`'s own docstring names
    `select(...)` while explaining that it contains none, and a substring scan
    would be satisfied by exactly that prose — a mistake this repository has
    made four times.
    """

    _SESSION_NAMES = frozenset({"db", "session", "conn", "connection"})
    _QUERY_METHODS = frozenset(
        {"query", "execute", "scalars", "scalar", "add", "delete", "flush", "get"}
    )
    _QUERY_BUILDERS = frozenset({"select", "insert", "update", "delete", "text"})

    @classmethod
    def _queries(cls, source: str) -> list[str]:
        found: list[str] = []
        for node in ast.walk(ast.parse(source)):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            if isinstance(func, ast.Name) and func.id in cls._QUERY_BUILDERS:
                found.append(f"{func.id}(...)")
            elif (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id in cls._SESSION_NAMES
                and func.attr in cls._QUERY_METHODS
            ):
                found.append(f"{func.value.id}.{func.attr}(...)")
        return sorted(set(found))

    def test_the_web_module_builds_no_query_of_its_own(self) -> None:
        """Every read these screens need is a module contract in `service.py`.
        A query here would be a second read authority over this module's tables,
        living in the layer least likely to be tested."""
        offenders = self._queries(WEB.read_text(encoding="utf-8"))
        assert not offenders, offenders

    def test_the_query_detector_fires_against_synthetic_violations(self) -> None:
        assert self._queries("rows = db.execute(statement)")
        assert self._queries("statement = select(DeploymentTarget)")
        assert self._queries("row = db.get(DeploymentTarget, target_id)")
        # And the shape the adapter legitimately has must NOT be flagged.
        assert not self._queries("result = service.list_targets(db, criteria)")
        assert not self._queries("preview = service.preview_plan_proposal(db, tid)")

    def test_the_web_module_declares_no_authentication_of_its_own(self) -> None:
        """One browser authentication authority, and it is the facet."""
        tree = ast.parse(WEB.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)} | {
            alias.asname or alias.name
            for node in ast.walk(tree)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        offenders = sorted(names & AUTHENTICATION_NAMES)
        assert not offenders, (
            f"web.py names {offenders}. The composed facet is the single browser "
            "authentication authority for this surface; a second owner on the "
            "same route is how a valid session passes the facet and then fails "
            "the handler."
        )

    def test_the_authentication_detector_fires_against_a_planted_import(self) -> None:
        planted = ast.parse(
            "from dotmac_kernel.platform_auth import require_platform_admin"
        )
        names = {
            alias.asname or alias.name
            for node in ast.walk(planted)
            if isinstance(node, ast.ImportFrom)
            for alias in node.names
        }
        assert names & AUTHENTICATION_NAMES
        # The module's docstring EXPLAINS why `require_platform_admin` is wrong
        # here. Prose is not a violation, which is the whole reason this is an
        # AST check.
        assert "require_platform_admin" in WEB.read_text(encoding="utf-8")

    def test_it_reads_the_actor_through_the_facet_principal_projection(self) -> None:
        """The supported way to know who is acting, and the only one that does
        not re-read a credential."""
        tree = ast.parse(WEB.read_text(encoding="utf-8"))
        names = {node.id for node in ast.walk(tree) if isinstance(node, ast.Name)}
        assert "require_facet_principal" in names
        assert any(
            isinstance(node, ast.Attribute) and node.attr == "PLATFORM"
            for node in ast.walk(tree)
        )


# ── The templates ───────────────────────────────────────────────────────────


class TestTheTemplatesDecideNothingAndInventNoDesignSystem:
    def _templates(self) -> list[Path]:
        return sorted(TEMPLATES.glob("*.html"))

    def test_there_are_templates_to_check(self) -> None:
        """Non-vacuity: a sweep over an empty set passes for the wrong reason."""
        assert len(self._templates()) >= 4

    def test_no_template_opts_out_of_escaping(self) -> None:
        """`| safe` renders attacker-influenced text as markup. Nothing on these
        screens is sanitized in Python, so nothing may claim to be."""
        for path in self._templates():
            assert "| safe" not in path.read_text(encoding="utf-8"), path.name

    def test_no_template_receives_or_renders_raw_observation_bytes(self) -> None:
        """Only the safe typed receipt projection reaches the browser.

        Payload digests are coordinates and may render; `payload` and
        `raw_body` are attacker-controlled bytes and remain behind the service
        boundary even when a quarantined receipt must be diagnosable.
        """
        raw_evidence = re.compile(r"\.(?:payload|raw_body)\b")
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            assert not raw_evidence.search(text), path.name
        context_source = ast.parse(WEB.read_text(encoding="utf-8"))
        names = {
            node.id for node in ast.walk(context_source) if isinstance(node, ast.Name)
        }
        assert "ObservationReceipt" not in names
        assert "ObservationAttempt" not in names

    def test_every_screen_extends_the_facets_shell_or_is_a_fragment(self) -> None:
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            assert path.name.startswith("_") or "{% extends" in text, path.name

    def test_no_template_authors_a_design_system_class(self) -> None:
        """`.dmui-*` names belong to `dotmac-ui`. A module that invented one
        would ship a class the design system does not define, and every consumer
        would render it unstyled."""
        for path in self._templates():
            text = path.read_text(encoding="utf-8")
            assert not re.search(r'class="[^"]*\bdmui-', text), path.name

    def test_every_design_token_used_is_one_this_module_declares(self) -> None:
        used: set[str] = set()
        for path in self._templates():
            used |= set(re.findall(r"--dmui-[a-z0-9-]+", path.read_text("utf-8")))
        undeclared = sorted(used - DECLARED_UI_TOKENS)
        assert not undeclared, (
            f"these templates use design tokens this module has not declared: "
            f"{undeclared}. Add them to DECLARED_UI_TOKENS in the change that "
            "uses them, having checked each against `dotmac-ui`'s published "
            "token set — this distribution cannot import it to check for you."
        )

    def test_the_declared_token_vocabulary_is_all_used(self) -> None:
        """A two-directional ratchet. A declared token nothing renders is a name
        nobody checked against `dotmac-ui` and nobody will."""
        used: set[str] = set()
        for path in self._templates():
            used |= set(re.findall(r"--dmui-[a-z0-9-]+", path.read_text("utf-8")))
        assert not sorted(DECLARED_UI_TOKENS - used)

    def test_no_template_renders_a_timestamp_without_saying_which_zone(
        self,
    ) -> None:
        """Every `*_at` goes through `moment(...)`, which states UTC.

        Deliberately not the kernel's `local_datetime`: that resolves TENANT
        display settings, and on the platform plane there is no tenant — an
        assembly that never registered the `display` specs gets a `KeyError` out
        of the fallback and a 500 out of every dated screen.
        """
        pattern = re.compile(r"\{\{[^}]*\b[a-z_]+\.[a-z_]*(?:_at|_date)\b[^}]*\}\}")
        for path in self._templates():
            for expression in pattern.findall(path.read_text(encoding="utf-8")):
                assert "moment(" in expression, f"{path.name}: {expression}"

    def test_that_timestamp_detector_fires_against_a_bare_render(self) -> None:
        pattern = re.compile(r"\{\{[^}]*\b[a-z_]+\.[a-z_]*(?:_at|_date)\b[^}]*\}\}")
        assert pattern.findall("{{ target.last_observed_at }}")
        assert "moment(" not in pattern.findall("{{ target.last_observed_at }}")[0]
        assert "moment(" in pattern.findall("{{ moment(target.last_observed_at) }}")[0]


# ── The anti-rot ratchet ────────────────────────────────────────────────────
#
# THE ROT THIS CATCHES: a field is added to a view, the service fills it, the
# tests assert its value, and no screen ever shows it. Nothing fails. The
# module's read contract and the operator's read contract drift apart one field
# at a time, and the drift is invisible because every individual change was
# complete on its own terms.
#
# So the claim below is stated over `dataclasses.fields` rather than over a list
# somebody maintains: every field of the two views these screens render either
# appears in a template, or is named here with a REASON on the line. Authored
# after R5 deliberately — written any earlier it would have enumerated fields
# that had no column yet and failed on its own siblings, which is the point.

#: The loop/context variable each view is bound to in the templates. The
#: detector is qualified by it, because an unqualified `.id` would find
#: `target.id` and pass `PlanView.id` on the strength of a different view's
#: field.
VIEW_BINDINGS: dict[str, str] = {"PlanView": "plan", "TargetView": "target"}

#: Fields these screens deliberately do NOT render, each with its reason ON THE
#: LINE. Kept small on purpose: this is the escape hatch, and an escape hatch
#: nobody counts is where the rot goes.
NOT_RENDERED: dict[str, dict[str, str]] = {
    "PlanView": {
        "id": (
            "no route in this surface takes a plan id. `sequence` is the "
            "operator's handle and `plan_digest` is the plan's identity; a "
            "UUID column would be noise nobody reads."
        ),
        "target_id": (
            "every row in this table belongs to the target the page is about. "
            "Repeating it per row states one fact N times."
        ),
        "record_version": (
            "an optimistic-concurrency coordinate. It says how many times the "
            "row was written, which is not a fact about the deployment."
        ),
        "snapshot": (
            "the canonical bytes are rendered in the propose panel, for the "
            "plan being frozen, where they are the thing the digest is taken "
            "over. A JSON document is not a table cell, and `plan_digest` is "
            "this row's handle to exactly these bytes."
        ),
    },
    "TargetView": {
        "record_version": (
            "as above -- concurrency, not deployment. The target's own history "
            "is the arrivals and rollout tables."
        ),
    },
}


def _view_classes() -> dict[str, Any]:
    from dotmac_deployment_control import facts

    return {"PlanView": facts.PlanView, "TargetView": facts.TargetView}


#: `{# ... #}`. Stripped before every scan below, because a template comment is
#: prose about the code and not the code: a field named only in a comment must
#: not count as rendered, and a rule quoting the shape it forbids must not trip
#: over its own quotation.
_JINJA_COMMENT = re.compile(r"\{#.*?#\}", re.DOTALL)


def _uncommented(path: Path) -> str:
    return _JINJA_COMMENT.sub(" ", path.read_text(encoding="utf-8"))


def _template_text() -> str:
    return "\n".join(_uncommented(path) for path in sorted(TEMPLATES.glob("*.html")))


def _unrendered(view: str, cls: Any, text: str) -> list[str]:
    """Fields of `cls` that no template mentions through its bound name."""
    binding = VIEW_BINDINGS[view]
    return [
        field.name
        for field in dataclasses.fields(cls)
        if f"{binding}.{field.name}" not in text
    ]


class TestEveryViewFieldReachesAScreenOrSaysWhyNot:
    def test_there_is_something_to_check(self) -> None:
        """Non-vacuity. A sweep over no fields and no templates passes."""
        text = _template_text()
        assert len(text) > 5_000
        for cls in _view_classes().values():
            assert len(dataclasses.fields(cls)) >= 15

    @pytest.mark.parametrize("view", sorted(VIEW_BINDINGS))
    def test_every_field_is_rendered_or_deliberately_not(self, view: str) -> None:
        cls = _view_classes()[view]
        missing = set(_unrendered(view, cls, _template_text()))
        undeclared = sorted(missing - set(NOT_RENDERED[view]))
        assert not undeclared, (
            f"{view} carries {undeclared} and no screen renders them. The "
            "module computes a fact the operator never sees, which is how a "
            "read contract and a screen drift apart one field at a time. "
            "Render it, or name it in NOT_RENDERED with the reason."
        )

    @pytest.mark.parametrize("view", sorted(VIEW_BINDINGS))
    def test_the_exemption_list_names_only_fields_that_exist(self, view: str) -> None:
        """A stale exemption is a silenced field nobody removed. It also hides
        the next field that takes the same name."""
        cls = _view_classes()[view]
        names = {field.name for field in dataclasses.fields(cls)}
        stale = sorted(set(NOT_RENDERED[view]) - names)
        assert not stale, f"{view} exempts fields it no longer has: {stale}"

    @pytest.mark.parametrize("view", sorted(VIEW_BINDINGS))
    def test_no_exemption_is_still_true_by_accident(self, view: str) -> None:
        """The other direction: a field named here that a screen DOES render.
        Left in place, the exemption would go on excusing the next change that
        removed the column."""
        cls = _view_classes()[view]
        missing = set(_unrendered(view, cls, _template_text()))
        rendered_anyway = sorted(set(NOT_RENDERED[view]) - missing)
        assert not rendered_anyway, (
            f"{view} exempts {rendered_anyway}, and a template renders them. "
            "Remove the exemption."
        )

    @pytest.mark.parametrize("view", sorted(VIEW_BINDINGS))
    def test_every_exemption_states_a_reason(self, view: str) -> None:
        for name, reason in NOT_RENDERED[view].items():
            assert len(reason.split()) >= 8, (
                f"{view}.{name} is exempt with no argument. An exemption states "
                "an enforceable premise or the field is unmonitored rather "
                "than exempt."
            )

    def test_the_exemption_count_only_moves_deliberately(self) -> None:
        """TWO-DIRECTIONAL. Failing when the count RISES stops a new field being
        silenced by appending a line; failing when it FALLS stops the ratchet
        being loosened by a change that quietly rendered one and left the
        number alone."""
        counts = {view: len(names) for view, names in NOT_RENDERED.items()}
        assert counts == {"PlanView": 4, "TargetView": 1}, (
            f"the unrendered-field backlog moved to {counts}. Lower the number "
            "in the same change that renders a field; raise it only with the "
            "reason on the line and a reviewer who read it."
        )

    def test_the_detector_notices_a_field_no_template_renders(self) -> None:
        """SENSITIVITY (ADR-0018). A check nobody has seen refuse is a name.

        A synthetic view is used rather than the real ones, so the proof does
        not depend on the current field set and cannot be silenced by the very
        drift it watches.
        """

        @dataclasses.dataclass(frozen=True)
        class _Probe:
            target_ref: str = ""
            #: Deliberately absent from every template.
            never_rendered_anywhere: str = ""

        found = _unrendered("TargetView", _Probe, _template_text())
        assert found == ["never_rendered_anywhere"], found


class TestNoTemplateLaundersATriStateThroughADefault:
    """`{% for image in plan.authorized_images or () %}` is the one-character
    change that undoes R1 and R5 on the screen.

    `None` and `()` are different declarations — nobody said, versus nobody may
    — and `or ()` renders both as an empty loop. Same for `or []` and `or {}`.
    The receipt's image columns are a bare loop CORRECTLY, because their field
    is `tuple[...] = ()` with no third state; the rule below is about the
    defaulting, not the looping.
    """

    _DEFAULTED = re.compile(r"\bor\s*(?:\(\s*\)|\[\s*\]|\{\s*\})")

    def test_no_template_defaults_an_empty_collection(self) -> None:
        for path in sorted(TEMPLATES.glob("*.html")):
            offenders = self._DEFAULTED.findall(_uncommented(path))
            assert not offenders, (
                f"{path.name} defaults a collection to empty: {offenders}. A "
                "tri-state read through `or ()` is flattened to two states in "
                "Jinja, where no type checker looks."
            )

    def test_that_detector_fires_against_the_planted_line(self) -> None:
        """The exact expression the rule names, and the two spellings of it."""
        assert self._DEFAULTED.findall(
            "{% for image in plan.authorized_images or () %}"
        )
        assert self._DEFAULTED.findall("{% for x in target.desired_images or [] %}")
        assert not self._DEFAULTED.findall(
            "{% if images is none %}{% elif images|length == 0 %}"
        )
