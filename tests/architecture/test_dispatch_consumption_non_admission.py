"""Only Control's unified authenticated finalizer may reach the private stage."""

from __future__ import annotations

import ast
import inspect
from pathlib import Path

import pytest

from dotmac_deployment_control import (
    admit_and_consume_host_admission,
    install_foundation_consumption_security,
)

_ROOT = Path(__file__).resolve().parents[2]
_PRODUCTION_ROOTS = (_ROOT / "src", _ROOT / "scripts", _ROOT / "alembic")
_SEAM = "_stage_dispatch_consumption"
_RESOLVE_CONTEXT_FUNCTION = "resolve_host_admission_context"
_PREPARE_SIGNATURE = ((), ("db",), ("attempt_id", "presentation"), None, None)


def _calls(source: str) -> int:
    tree = ast.parse(source)
    aliases = {_SEAM}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            aliases.update(
                item.asname or item.name for item in node.names if item.name == _SEAM
            )
    return sum(
        isinstance(node, ast.Call)
        and (
            isinstance(node.func, ast.Name)
            and node.func.id in aliases
            or isinstance(node.func, ast.Attribute)
            and node.func.attr == _SEAM
        )
        for node in ast.walk(tree)
    )


def _production_python_sources() -> list[tuple[Path, str]]:
    sources: list[tuple[Path, str]] = []
    for root in _PRODUCTION_ROOTS:
        for path in root.rglob("*"):
            if not path.is_file():
                continue
            try:
                source = path.read_text()
                ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                if path.suffix == ".py":
                    raise
                continue
            sources.append((path, source))
    return sources


def _prepare_signature(
    source: str,
) -> tuple[tuple[str, ...], tuple[str, ...], tuple[str, ...], str | None, str | None]:
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.FunctionDef) and node.name == _RESOLVE_CONTEXT_FUNCTION:
            return (
                tuple(argument.arg for argument in node.args.posonlyargs),
                tuple(argument.arg for argument in node.args.args),
                tuple(argument.arg for argument in node.args.kwonlyargs),
                node.args.vararg.arg if node.args.vararg is not None else None,
                node.args.kwarg.arg if node.args.kwarg is not None else None,
            )
    raise AssertionError(f"{_RESOLVE_CONTEXT_FUNCTION} definition is absent")


def test_private_dispatch_consumption_has_exactly_one_production_caller() -> None:
    callers = [
        path
        for path, source in _production_python_sources()
        for _ in range(_calls(source))
    ]
    assert callers == [
        _ROOT / "src" / "dotmac_deployment_control" / "host_admission_coordinator.py",
    ]


def test_non_admission_ratchet_detects_every_call_shape_not_prose() -> None:
    assert _calls("_stage_dispatch_consumption(db)") == 1
    assert _calls("from x import _stage_dispatch_consumption as stage\nstage(db)") == 1
    assert (
        _calls(
            "import dotmac_deployment_control.service as control\n"
            "control._stage_dispatch_consumption(db)"
        )
        == 1
    )
    assert (
        _calls(
            "from dotmac_deployment_control import service\n"
            "service._stage_dispatch_consumption(db)"
        )
        == 1
    )
    assert (
        _calls(
            "from dotmac_deployment_control import service as control\n"
            "control._stage_dispatch_consumption(db)"
        )
        == 1
    )
    assert (
        _calls(
            "import dotmac_deployment_control.service\n"
            "dotmac_deployment_control.service._stage_dispatch_consumption(db)"
        )
        == 1
    )
    assert _calls('"_stage_dispatch_consumption(db)"') == 0


def test_prepare_cannot_accept_request_selected_authentication_dependencies() -> None:
    source = (
        _ROOT / "src" / "dotmac_deployment_control" / "host_admission_coordinator.py"
    ).read_text()
    assert _prepare_signature(source) == _PREPARE_SIGNATURE


def test_foundation_finalizer_has_no_per_call_verifier_or_clock() -> None:
    parameters = tuple(inspect.signature(admit_and_consume_host_admission).parameters)
    assert parameters == ("db", "context", "foreign_evidence", "execution")
    assert (
        inspect.signature(admit_and_consume_host_admission)
        .parameters["execution"]
        .default
        is inspect.Parameter.empty
    )
    installed = tuple(
        inspect.signature(install_foundation_consumption_security).parameters
    )
    assert installed == ("authorization_verifier", "dispatch_verifier", "clock")


def _requires_verified_v3_expectation(function: object) -> bool:
    parameter = inspect.signature(function).parameters.get("foundation_expected")
    return (
        parameter is not None
        and parameter.default is inspect.Parameter.empty
        and parameter.annotation == "_ExpectedFoundationConsumption"
    )


def test_private_stage_requires_verified_v3_expectation_with_sensitivity() -> None:
    from dotmac_deployment_control.service import _stage_dispatch_consumption

    assert _requires_verified_v3_expectation(_stage_dispatch_consumption)

    def missing(*, foundation_expected=None):  # type: ignore[no-untyped-def]
        return foundation_expected

    def optional(  # type: ignore[no-untyped-def]
        *, foundation_expected: object | None = None
    ):
        return foundation_expected

    assert not _requires_verified_v3_expectation(missing)
    assert not _requires_verified_v3_expectation(optional)


def test_private_stage_is_not_a_published_product_api() -> None:
    import dotmac_deployment_control as control

    assert _SEAM not in control.__all__


@pytest.mark.parametrize(
    "parameters",
    [
        "db, *, attempt_id, presentation, security",
        "db, *, attempt_id, presentation, time_source",
        "db, *, attempt_id, presentation, **kwargs",
    ],
)
def test_prepare_dependency_guard_has_renamed_and_vararg_plants(
    parameters: str,
) -> None:
    planted = f"def {_RESOLVE_CONTEXT_FUNCTION}({parameters}):\n    return None\n"
    assert _prepare_signature(planted) != _PREPARE_SIGNATURE
