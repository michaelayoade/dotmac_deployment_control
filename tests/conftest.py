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
"""

from __future__ import annotations

import os
from collections.abc import Generator
from typing import Any

import pytest

REQUIRE_NO_SKIPS_ENV = "REQUIRE_NO_SKIPS"


def _skips_are_failures() -> bool:
    return os.getenv(REQUIRE_NO_SKIPS_ENV) == "1"


@pytest.hookimpl(hookwrapper=True)
def pytest_runtest_makereport(
    item: pytest.Item, call: Any
) -> Generator[None, None, None]:
    outcome = yield
    if not _skips_are_failures():
        return
    report = outcome.get_result()  # type: ignore[attr-defined]
    if report.skipped and report.when == "setup":
        reason = ""
        if isinstance(report.longrepr, tuple) and len(report.longrepr) == 3:
            reason = str(report.longrepr[2])
        report.outcome = "failed"
        report.longrepr = (
            f"{item.nodeid} was SKIPPED while {REQUIRE_NO_SKIPS_ENV}=1.\n"
            f"  reason: {reason or '<none given>'}\n"
            "  This lane exists to run this test. A skip here is the "
            "'absent reads as success' defect: the suite reports green having "
            "executed nothing. Provide the environment the test needs, or "
            "remove the lane's claim to run it."
        )
