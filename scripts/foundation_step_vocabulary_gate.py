"""The required CI gate over Foundation's OWN pinned source. No install.

Reads `dotmac_deployment_control.rehearsal_grant.FOUNDATION_STEP_KIND_SOURCE`
(`<repository>@<commit>:<path>`), fetches the raw file at that EXACT pinned
commit over HTTPS — nothing beyond the standard library, no
`dotmac-deployment-foundation` dependency of any kind, dev or runtime — and
compares it against the mirror with
`dotmac_deployment_control.foundation_source_gate
.require_foundation_step_vocabulary_agreement`.

## Why this does not simply `import dotmac_deployment_control.foundation_source_gate`

It was measured to fail on real CI: `import
dotmac_deployment_control.foundation_source_gate` first executes
`dotmac_deployment_control/__init__.py`, and that file eagerly imports the
REST of the package — `service.py`, `database_catalog.py`, and eventually
something requiring `dotmac_kernel`, a private-index dependency this
job installs nothing for on purpose (see `ci.yml`'s comment on this job: "no
`poetry install` here on purpose"). The failure —
`ModuleNotFoundError: No module named 'dotmac_kernel'` — was the package
`__init__` running, not this script's own logic.

The five files this script actually needs (`ports.py`, `digests.py`,
`candidate_artifact.py`, `rehearsal_grant.py`, `foundation_source_gate.py`)
import ONLY each other and the standard library — none of them, individually,
needs `dotmac_kernel` or anything else from the wider package. So `_load_module`
below loads each one directly from its file with
`importlib.util.spec_from_file_location`, registers it under its real dotted
name in `sys.modules` (so the modules' OWN `from dotmac_deployment_control.X
import Y` statements resolve to each other rather than re-triggering the
package `__init__`), and never executes `dotmac_deployment_control/__init__.py`
at all. A bare stub package object satisfies `import dotmac_deployment_control
.<submodule>`'s parent-package requirement without running a single line of
the real `__init__.py`.

This keeps the property Michael named: ONE comparator
(`foundation_source_gate.require_foundation_step_vocabulary_agreement`), never
a second copy reimplemented for "the script that must stay dependency-free" —
the two rejected alternatives were a hand-duplicated stdlib-only comparator
(a second copy, which is the exact drift this gate exists to prevent) and
making the package `__init__` lazy (correct in principle, but a change whose
blast radius is every consumer of this package, not this one CI job — out of
scope here and left untouched).

## What this buys, and what it costs

Cost: this loader is coupled to the five files' OWN internal import graph
staying free of the wider package — if `rehearsal_grant.py` ever gained an
import of, say, `service.py`, this script would need the same fix again. That
coupling is implicit rather than statically enforced; `tests/unit/test_
foundation_source_gate.py` importing the module normally (inside a `poetry
install`ed environment where the whole package is available) is what would
actually notice a NEW heavy import creeping in, since that test suite's job
does run `poetry install`.

Exit 0: the pinned source agrees with the mirror. Exit 1: it does not, or it
could not be read — both are gate failures, and the message distinguishes
which because they need different repairs (see
`FoundationVocabularySourceError` vs `FoundationVocabularyDriftError`).
"""

from __future__ import annotations

import importlib.util
import sys
import types
import urllib.error
import urllib.request
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    # For the type checker ONLY. mypy resolves this against the real package
    # (it has no trouble with a normal import graph); at runtime this branch
    # never executes, so it cannot be the thing that drags `dotmac_kernel` in
    # — the actual loading below still goes through `_load_module`.
    from dotmac_deployment_control.foundation_source_gate import SourceCoordinate

_SRC = Path(__file__).resolve().parent.parent / "src" / "dotmac_deployment_control"

#: Dependency order matters: each module's own `from dotmac_deployment_control
#: .X import Y` must already be resolvable in `sys.modules` by the time it is
#: loaded, since none of these are installed and Python cannot resolve them by
#: searching `sys.path` the normal way once the parent is a bare stub.
_LOAD_ORDER = (
    "ports",
    "digests",
    "candidate_artifact",
    "rehearsal_grant",
    "foundation_source_gate",
)


def _load_module(name: str) -> types.ModuleType:
    """Load `dotmac_deployment_control.<name>` from its file, alone.

    Never executes `dotmac_deployment_control/__init__.py` — the parent
    package entry in `sys.modules` is a bare, empty stub, present only so that
    the loaded module's own `from dotmac_deployment_control.X import Y`
    statements have a parent package to resolve against.
    """
    full_name = f"dotmac_deployment_control.{name}"
    spec = importlib.util.spec_from_file_location(full_name, _SRC / f"{name}.py")
    if spec is None or spec.loader is None:  # pragma: no cover - defensive
        raise ImportError(f"could not build an import spec for {full_name}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[full_name] = module
    spec.loader.exec_module(module)
    return module


def _load_gate_without_the_package_init() -> types.ModuleType:
    if "dotmac_deployment_control" not in sys.modules:
        stub = types.ModuleType("dotmac_deployment_control")
        stub.__path__ = [str(_SRC)]  # makes it look like a real package
        sys.modules["dotmac_deployment_control"] = stub
    loaded: dict[str, types.ModuleType] = {}
    for name in _LOAD_ORDER:
        loaded[name] = _load_module(name)
    return loaded["foundation_source_gate"]


_gate = _load_gate_without_the_package_init()
_ports = sys.modules["dotmac_deployment_control.ports"]

require_foundation_step_vocabulary_agreement = (
    _gate.require_foundation_step_vocabulary_agreement
)
FoundationVocabularyDriftError = _ports.FoundationVocabularyDriftError
FoundationVocabularySourceError = _ports.FoundationVocabularySourceError

_TIMEOUT_SECONDS = 30


class _RawGithubReader:
    """Fetches `raw.githubusercontent.com/<repo>/<commit>/<path>`.

    A pinned COMMIT in the URL, never a branch — `raw.githubusercontent.com`
    serves the exact blob at that commit regardless of what any branch points
    at later, which is what makes this read reproducible rather than a read of
    whatever main happens to be today.
    """

    def read(self, coordinate: SourceCoordinate) -> str:
        url = (
            f"https://raw.githubusercontent.com/{coordinate.repository}/"
            f"{coordinate.commit}/{coordinate.path}"
        )
        if not url.startswith("https://raw.githubusercontent.com/"):
            raise ValueError(f"refusing a non-pinned-host URL: {url}")
        request = urllib.request.Request(  # noqa: S310 - fixed https host, checked above
            url, headers={"Accept": "text/plain"}
        )
        with urllib.request.urlopen(  # noqa: S310 - fixed https host, checked above
            request, timeout=_TIMEOUT_SECONDS
        ) as response:
            return response.read().decode("utf-8")


def main() -> int:
    try:
        require_foundation_step_vocabulary_agreement(_RawGithubReader())
    except FoundationVocabularySourceError as error:
        print(f"foundation-step-vocabulary-gate: SOURCE UNAVAILABLE: {error}")
        return 1
    except FoundationVocabularyDriftError as error:
        print(f"foundation-step-vocabulary-gate: DRIFT: {error}")
        return 1
    except urllib.error.URLError as error:
        print(f"foundation-step-vocabulary-gate: NETWORK FAILURE: {error}")
        return 1
    print("foundation-step-vocabulary-gate: the pinned source agrees with the mirror")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
