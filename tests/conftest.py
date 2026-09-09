"""A skip in the lane that exists to run a test is a failure.

`tests/test_deployment_control_platform_isolation.py` is 1,001 lines of proof
that the claim/proof CHECK constraints hold against RAW SQL — the gap between
"the service refuses this write" and "the database refuses this write". It
opens with:

    url = os.getenv("TEST_MIGRATION_DATABASE_URL") or os.getenv("TEST_DATABASE_URL")
    if not url:
        pytest.skip("TEST_DATABASE_URL not set — the platform canary needs Postgres")

In the repository it came from that was correct: a dedicated integration lane
set the URL, and a developer without Postgres got a fast local suite. Carried
into a repository whose whole reason for having a Postgres lane is this file,
the same line becomes the defect it was never meant to be — **an absent thing
reading as success**. Forget the environment variable in one workflow edit and
the strongest proof in the repository reports green having executed nothing.

So the lane that is supposed to run it sets ``REQUIRE_NO_SKIPS=1`` and every
skip becomes a failure. The variable is deliberately not defaulted on: a local
run without Postgres should still skip, because that is a developer choice
rather than a silent hole in CI. The difference between the two is the presence
of the flag, which is a fact about the lane rather than about the machine.

## Three stages a skip can be reported from -- all three are covered

A skip is not one event; it is three different pytest hook paths, and a guard
that only covers one of them still reports green for the other two:

1. **Setup-stage** -- a fixture (or a `pytest.mark.skip`, which is
   implemented as a setup-time check) calls `pytest.skip()` before the test
   body runs. Reported through `pytest_runtest_makereport` with
   `report.when == "setup"`.
2. **Call-stage** -- the test body itself calls `pytest.skip()` (e.g. an
   assumption it discovers mid-test doesn't hold). Reported through the
   SAME `pytest_runtest_makereport` hook, but with `report.when == "call"` --
   the original guard's `report.when == "setup"` check let this one straight
   through.
3. **Collection/module-level** -- `pytest.skip(..., allow_module_level=True)`
   or `pytest.importorskip(...)` at import time, before any test ITEM exists
   for `pytest_runtest_makereport` to ever see. Reported through the entirely
   separate `pytest_collectreport` hook, which the original guard did not
   implement at all.

`tests/test_require_no_skips_hook.py` plants a defect and a near-miss for
each of the three, driving a real subprocess pytest run against a throwaway
project rather than asserting on this module's internals.
"""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

import pytest

# Enables the `pytester` fixture (`tests/test_require_no_skips_hook.py`),
# which drives a real subprocess pytest run against a throwaway project to
# prove this file's hooks -- not merely available, per pytest's own docs;
# must be declared in the top-level conftest of the collected tree.
pytest_plugins = ["pytester"]

REQUIRE_NO_SKIPS_ENV = "REQUIRE_NO_SKIPS"

# The two stages `pytest_runtest_makereport` sees a skip through. Teardown is
# deliberately excluded: pytest does not skip a test from teardown.
_ITEM_SKIP_STAGES = ("setup", "call")


def _skips_are_failures() -> bool:
    return os.getenv(REQUIRE_NO_SKIPS_ENV) == "1"


def _skip_reason(longrepr: object) -> str:
    if isinstance(longrepr, tuple) and len(longrepr) == 3:
        return str(longrepr[2])
    if longrepr:
        return str(longrepr)
    return ""


def _forced_failure_message(nodeid: str, stage: str, reason: str) -> str:
    return (
        f"{nodeid} was SKIPPED ({stage}) while {REQUIRE_NO_SKIPS_ENV}=1.\n"
        f"  reason: {reason or '<none given>'}\n"
        "  This lane exists to run this test. A skip here is the "
        "'absent reads as success' defect: the suite reports green having "
        "executed nothing. Provide the environment the test needs, or "
        "remove the lane's claim to run it."
    )


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: Any
) -> Generator[None, None, None]:
    """Setup-stage AND call-stage skips of an already-collected item."""
    outcome = yield
    if not _skips_are_failures():
        return
    report = outcome.get_result()  # type: ignore[attr-defined]
    if report.skipped and report.when in _ITEM_SKIP_STAGES:
        report.outcome = "failed"
        report.longrepr = _forced_failure_message(
            item.nodeid, report.when, _skip_reason(report.longrepr)
        )


@pytest.hookimpl(hookwrapper=True)
def pytest_collectreport(report: pytest.CollectReport) -> Generator[None, None, None]:
    """Collection/module-level skips -- a module that never produced a single
    test item, so `pytest_runtest_makereport` above never fires for it.

    Mutated BEFORE `yield`, not after: `Session.pytest_collectreport` (an
    alias for `Session.pytest_runtest_logreport`, which increments
    `session.testsfailed` from `report.failed`) is a plain, non-wrapper hook
    implementation, and `Session` registers itself as a plugin AFTER this
    conftest is loaded -- under pluggy's default LIFO ordering it would run
    BEFORE this hook's own impl if this were a plain (non-wrapper) function,
    reading the original "skipped" outcome and never counting the failure. A
    hookwrapper's pre-`yield` code runs before every non-wrapper
    implementation regardless of relative registration order, which is what
    makes flipping `report.outcome` here -- rather than after `yield`, as the
    item-level hook above does -- the correct half of the wrapper to use.
    """
    if _skips_are_failures() and report.skipped:
        report.outcome = "failed"
        report.longrepr = _forced_failure_message(
            report.nodeid, "collection", _skip_reason(report.longrepr)
        )
    yield
