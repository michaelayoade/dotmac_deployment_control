"""Control never imports the release catalogue, and never stores descriptor text.

The assembly implements `ReleaseDescriptorSource`; `release_ref` stays opaque to
Control (ADR-0006 D1). Descriptor BYTES are verified and dropped: only the
digest and the image pins are kept, and no input anywhere accepts descriptor
text.
"""

from __future__ import annotations

import ast
import re
from pathlib import Path

SRC = Path(__file__).resolve().parents[2] / "src" / "dotmac_deployment_control"
_FORBIDDEN_ROOTS = frozenset({"dotmac_release_catalog", "dotmac_licensing"})
_TEXT_NAMES = re.compile(
    r"(descriptor|deploy_unit)_(text|bytes|body|content|toml)", re.IGNORECASE
)


def _imports(source: str) -> set[str]:
    roots: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            roots |= {alias.name.split(".")[0] for alias in node.names}
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    return roots


def test_control_never_imports_the_release_catalogue() -> None:
    offenders = [
        path.name
        for path in SRC.rglob("*.py")
        if _imports(path.read_text()) & _FORBIDDEN_ROOTS
    ]
    assert not offenders, offenders


def test_the_import_detector_fires() -> None:
    assert "dotmac_release_catalog" in _imports("import dotmac_release_catalog.x")
    assert "dotmac_release_catalog" in _imports("from dotmac_release_catalog import y")


def test_no_table_column_holds_descriptor_text() -> None:
    from dotmac_deployment_control import models

    offenders = [
        f"{name}.{column.name}"
        for name in models.__all__
        if (table := getattr(getattr(models, name), "__table__", None)) is not None
        for column in table.columns
        if _TEXT_NAMES.search(column.name)
    ]
    assert not offenders, offenders


def test_no_command_or_form_accepts_descriptor_text() -> None:
    """Only `ReleaseDescriptorEvidence` carries bytes, and the web form has none."""
    from dotmac_deployment_control import service, web
    from dotmac_deployment_control.ports import ReleaseDescriptorEvidence

    carriers = {
        name
        for name, obj in vars(service).items()
        if name.endswith("Command") and hasattr(obj, "__dataclass_fields__")
        for field in obj.__dataclass_fields__
        if _TEXT_NAMES.search(field)
    }
    assert not carriers, carriers
    assert "deploy_unit_bytes" in ReleaseDescriptorEvidence.__dataclass_fields__
    assert not {f for f in web._PARAMS_FIELDS if _TEXT_NAMES.search(f)}
    web_source = (SRC / "web.py").read_text()
    assert not re.search(r'form\[["\'](descriptor_text|deploy_unit)', web_source)
