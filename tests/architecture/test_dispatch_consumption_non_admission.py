"""The private staging seam has one authenticated Control finalizer caller."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
_PRODUCTION_ROOTS = (_ROOT / "src", _ROOT / "scripts", _ROOT / "alembic")
_SEAM = "_stage_dispatch_consumption"
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
        if isinstance(node, ast.FunctionDef) and node.name == "prepare_host_admission":
            return (
                tuple(argument.arg for argument in node.args.posonlyargs),
                tuple(argument.arg for argument in node.args.args),
                tuple(argument.arg for argument in node.args.kwonlyargs),
                node.args.vararg.arg if node.args.vararg is not None else None,
                node.args.kwarg.arg if node.args.kwarg is not None else None,
            )
    raise AssertionError("prepare_host_admission definition is absent")


def test_private_dispatch_consumption_has_exactly_one_production_caller() -> None:
    callers = [
        path
        for path, source in _production_python_sources()
        for _ in range(_calls(source))
    ]
    assert callers == [
        _ROOT / "src" / "dotmac_deployment_control" / "host_admission_coordinator.py"
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
    planted = f"def prepare_host_admission({parameters}):\n    return None\n"
    assert _prepare_signature(planted) != _PREPARE_SIGNATURE
