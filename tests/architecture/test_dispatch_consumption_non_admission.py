"""The private staging seam stays callerless until trusted composition exists."""

from __future__ import annotations

import ast
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
_PRODUCTION_ROOTS = (_ROOT / "src", _ROOT / "scripts", _ROOT / "alembic")
_SEAM = "_stage_dispatch_consumption"


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


def _production_python_sources() -> list[str]:
    sources: list[str] = []
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
            sources.append(source)
    return sources


def test_private_dispatch_consumption_has_zero_production_callers() -> None:
    assert sum(_calls(source) for source in _production_python_sources()) == 0


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
