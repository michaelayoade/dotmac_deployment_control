"""Sensitivity proof for `tests/conftest.py`'s `REQUIRE_NO_SKIPS` hooks.

A skip is not one event; it is three distinct pytest hook paths (see the
"Three stages" section of `tests/conftest.py`'s module docstring). Before
this file existed, only the setup-stage path was proven -- and it was never
proven at all, only asserted in prose. A test that skips inside its own BODY,
or a module that skips at IMPORT time, still reported green under
`REQUIRE_NO_SKIPS=1` even though the guard's whole purpose is to make that
impossible.

Each of the three stages below gets a PLANT (the exact skip shape that stage
produces, proven to fail once the guard is armed) and a NEAR-MISS (the same
shape, with the guard NOT armed, proving the guard is what converted it --
not some unrelated failure -- and that a normal developer run without
`REQUIRE_NO_SKIPS=1` still gets an ordinary, green skip).

Every plant/near-miss pair drives a REAL subprocess pytest run
(`pytester.runpytest_subprocess`) against a throwaway project whose conftest
is a byte-for-byte copy of the production `tests/conftest.py` -- this proves
the actual hook code, not a reimplementation of it that could silently drift
from what ships.
"""

from __future__ import annotations

from pathlib import Path
from textwrap import dedent

import pytest

pytest_plugins = ["pytester"]

_PRODUCTION_CONFTEST = (Path(__file__).parent / "conftest.py").read_text()


def _seed(pytester: pytest.Pytester, test_source: str) -> None:
    """Copy the real conftest.py into the throwaway project, then add the
    test module under proof."""
    pytester.makeconftest(_PRODUCTION_CONFTEST)
    pytester.makepyfile(dedent(test_source))


# ── Stage 1: setup ──────────────────────────────────────────────────────────


class TestSetupStageSkip:
    def test_plant_a_fixture_skip_fails_under_require_no_skips(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.setenv("REQUIRE_NO_SKIPS", "1")
        _seed(
            pytester,
            """
            import pytest

            @pytest.fixture
            def unavailable_dependency():
                pytest.skip("dependency not available")

            def test_uses_the_unavailable_dependency(unavailable_dependency):
                assert True

            def test_an_ordinary_pass_is_unaffected():
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(passed=1, failed=1)
        result.stdout.fnmatch_lines(["*was SKIPPED (setup) while REQUIRE_NO_SKIPS=1*"])

    def test_near_miss_the_identical_skip_stays_a_skip_without_the_flag(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("REQUIRE_NO_SKIPS", raising=False)
        _seed(
            pytester,
            """
            import pytest

            @pytest.fixture
            def unavailable_dependency():
                pytest.skip("dependency not available")

            def test_uses_the_unavailable_dependency(unavailable_dependency):
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(skipped=1)


# ── Stage 2: call ────────────────────────────────────────────────────────────


class TestCallStageSkip:
    def test_plant_a_skip_raised_from_inside_the_test_body_fails(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The near-miss the ORIGINAL `report.when == "setup"` guard could not
        catch: this skip is raised from the test's own CALL phase, not from a
        fixture's setup phase."""
        monkeypatch.setenv("REQUIRE_NO_SKIPS", "1")
        _seed(
            pytester,
            """
            import pytest

            def test_skips_from_its_own_body():
                pytest.skip("discovered mid-test that this does not apply")

            def test_an_ordinary_pass_is_unaffected():
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(passed=1, failed=1)
        result.stdout.fnmatch_lines(["*was SKIPPED (call) while REQUIRE_NO_SKIPS=1*"])

    def test_near_miss_the_identical_skip_stays_a_skip_without_the_flag(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("REQUIRE_NO_SKIPS", raising=False)
        _seed(
            pytester,
            """
            import pytest

            def test_skips_from_its_own_body():
                pytest.skip("discovered mid-test that this does not apply")
            """,
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(skipped=1)


# ── Stage 3: collection / module-level ──────────────────────────────────────


class TestCollectionLevelSkip:
    def test_plant_a_module_level_skip_fails_under_require_no_skips(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The near-miss NEITHER stage-1 nor stage-2 could catch: the whole
        module skips itself at IMPORT time, before a single test item exists
        for `pytest_runtest_makereport` to ever see. Only `pytest_collectreport`
        observes this one."""
        monkeypatch.setenv("REQUIRE_NO_SKIPS", "1")
        _seed(
            pytester,
            """
            import pytest

            pytest.skip("whole module unavailable", allow_module_level=True)

            def test_never_actually_collected():
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        assert result.ret != 0, (
            "a module-level skip must make the run exit non-zero under "
            "REQUIRE_NO_SKIPS=1 -- a green exit here is exactly the "
            "'absent reads as success' defect this guard exists to close"
        )
        result.stdout.fnmatch_lines(
            ["*was SKIPPED (collection) while REQUIRE_NO_SKIPS=1*"]
        )

    def test_near_miss_an_ordinary_module_still_collects_and_passes(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """Selectivity half of the same plant: an ORDINARY module (no skip at
        all) under the SAME `REQUIRE_NO_SKIPS=1` flag must collect and pass
        normally -- the guard fails a skip, not a plain successful module."""
        monkeypatch.setenv("REQUIRE_NO_SKIPS", "1")
        _seed(
            pytester,
            """
            def test_an_ordinary_module_with_no_skip_at_all():
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        result.assert_outcomes(passed=1)
        assert result.ret == 0

    def test_near_miss_the_identical_module_level_skip_stays_a_skip_without_the_flag(
        self, pytester: pytest.Pytester, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        monkeypatch.delenv("REQUIRE_NO_SKIPS", raising=False)
        _seed(
            pytester,
            """
            import pytest

            pytest.skip("whole module unavailable", allow_module_level=True)

            def test_never_actually_collected():
                assert True
            """,
        )
        result = pytester.runpytest_subprocess()
        assert result.ret == 0
