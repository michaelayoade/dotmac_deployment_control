"""VERIFIED or UNPROVABLE, and never a generic success marker.

`0.1.0a3` was published by a run cancelled during its own verification. The
bytes landed; the evidence chain did not. So the decision below has exactly two
outcomes, and the one that matters is the second: **UNPROVABLE is a result**, not
a retry signal, and it must be reachable — a verdict function that can only
return VERIFIED is the "OK printed on a path nobody exercised" defect wearing a
return value.

Every property is tested for its own refusal. A decision that returned
UNPROVABLE for the right reason on one input and the wrong reason on another
would look identical from the outside, which is why each finding is asserted by
number rather than by the overall verdict alone.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "verify_release", REPO_ROOT / "scripts" / "verify_release.py"
)
assert _spec is not None and _spec.loader is not None
verify = importlib.util.module_from_spec(_spec)
# REGISTERED before execution, and not optional. `@dataclass` resolves field
# types by looking the defining module up in `sys.modules`; a module executed
# from a spec without being registered there raises
# `AttributeError: 'NoneType' object has no attribute '__dict__'` at class
# definition. The failure is in the loader, not the code under test, and it
# would have looked like a defect in verify_release.py.
sys.modules[_spec.name] = verify
_spec.loader.exec_module(verify)

VERSION = "0.1.0a3"
HEAD = "31b6b82f14fee65d22c6d1d218455d21bb12c0f6"
WHEEL = f"dotmac_deployment_control-{VERSION}-py3-none-any.whl"
SDIST = f"dotmac_deployment_control-{VERSION}.tar.gz"
WHEEL_SHA = "fbdd4825e691547d16b3e45c4d513629b25a7cb019df21574c804de295dce1fd"
SDIST_SHA = "081bcba585d09cfa3d5c18a04c77adf2d743c0e78c4a7053f857e1c18d12f559"

PYPROJECT = (
    f'[tool.poetry]\nname = "dotmac-deployment-control"\nversion = "{VERSION}"\n'
)


def observations(**overrides: object) -> dict[str, object]:
    base: dict[str, object] = {
        "version": VERSION,
        "run": {
            "id": 33295149495,
            "path": ".github/workflows/release.yml",
            "event": "workflow_dispatch",
            "head_branch": "main",
            "head_sha": HEAD,
        },
        "publish_job_conclusion": "success",
        "head_sha_on_main": True,
        "pyproject_at_head": PYPROJECT,
        "built_hashes": {WHEEL: WHEEL_SHA, SDIST: SDIST_SHA},
        "fetched": {WHEEL: WHEEL_SHA, SDIST: SDIST_SHA},
        "consumer_installed": True,
        "read_back_ok": True,
        "index_filenames": [WHEEL, SDIST],
    }
    base.update(overrides)
    return base


def finding(outcome: object, number: int) -> object:
    return next(f for f in outcome.findings if f.prop == number)  # type: ignore[attr-defined]


# ── the positive control comes first ────────────────────────────────────────


def test_a_complete_evidence_chain_is_verified() -> None:
    """Without this, every refusal below is consistent with a function that can
    only ever return UNPROVABLE."""
    outcome = verify.evaluate(**observations())
    assert outcome.verdict == verify.VERIFIED, outcome.render()
    assert all(f.proven for f in outcome.findings)
    assert len(outcome.findings) == 5


def test_the_render_names_the_verdict_and_never_says_ok() -> None:
    rendered = verify.evaluate(**observations()).render()
    assert rendered.startswith("## VERIFIED")
    assert "OK" not in rendered
    assert "success" not in rendered.lower()


# ── property 1: registry bytes are that run's bytes ─────────────────────────


def test_a_served_file_with_a_different_hash_is_unprovable() -> None:
    outcome = verify.evaluate(
        **observations(fetched={WHEEL: "0" * 64, SDIST: SDIST_SHA})
    )
    assert outcome.verdict == verify.UNPROVABLE
    assert not finding(outcome, 1).proven
    assert "built" in finding(outcome, 1).detail


def test_a_file_the_run_did_not_build_is_unprovable() -> None:
    outcome = verify.evaluate(**observations(fetched={"other-1.0.whl": "a" * 64}))
    assert not finding(outcome, 1).proven
    assert "not built by that run" in finding(outcome, 1).detail


def test_a_missing_run_artifact_is_unprovable_rather_than_ignored() -> None:
    """The artifact expires after 90 days. When it is gone the honest answer is
    UNPROVABLE — not "nothing to compare, therefore fine"."""
    outcome = verify.evaluate(**observations(built_hashes={}))
    assert outcome.verdict == verify.UNPROVABLE
    assert "artifact could not be read" in finding(outcome, 1).detail


def test_a_built_file_the_index_does_not_serve_is_unprovable() -> None:
    outcome = verify.evaluate(**observations(fetched={WHEEL: WHEEL_SHA}))
    assert not finding(outcome, 1).proven
    assert "could not be fetched from the index" in finding(outcome, 1).detail


# ── property 2: provenance, which a matching hash does NOT establish ────────


def test_a_matching_hash_from_the_wrong_workflow_is_unprovable() -> None:
    """THE DISTINCTION THIS EXISTS FOR. Bytes can match while provenance does
    not: the hash proves somebody built them, the run proves who and from what."""
    run = dict(observations()["run"])  # type: ignore[arg-type]
    run["path"] = ".github/workflows/ci.yml"
    outcome = verify.evaluate(**observations(run=run))
    assert outcome.verdict == verify.UNPROVABLE
    assert finding(outcome, 1).proven, "the bytes still match — only provenance fails"
    assert not finding(outcome, 2).proven


@pytest.mark.parametrize(
    ("override", "fragment"),
    [
        ({"publish_job_conclusion": "cancelled"}, "publish job was 'cancelled'"),
        ({"publish_job_conclusion": "absent"}, "publish job was 'absent'"),
        ({"head_sha_on_main": False}, "not an ancestor of protected main"),
        ({"pyproject_at_head": None}, "could not be read"),
    ],
)
def test_each_provenance_link_is_required(override: dict, fragment: str) -> None:
    outcome = verify.evaluate(**observations(**override))
    assert outcome.verdict == verify.UNPROVABLE
    assert fragment in finding(outcome, 2).detail, finding(outcome, 2).detail


def test_a_head_commit_declaring_another_version_is_unprovable() -> None:
    """The run may be genuine and still not be the run for THIS version."""
    other = PYPROJECT.replace(VERSION, "0.1.0a9")
    outcome = verify.evaluate(**observations(pyproject_at_head=other))
    assert not finding(outcome, 2).proven
    assert "0.1.0a9" in finding(outcome, 2).detail


def test_a_head_commit_declaring_another_distribution_is_unprovable() -> None:
    other = PYPROJECT.replace("dotmac-deployment-control", "dotmac-kernel")
    outcome = verify.evaluate(**observations(pyproject_at_head=other))
    assert not finding(outcome, 2).proven


# ── properties 3, 4, 5 ──────────────────────────────────────────────────────


def test_a_failed_read_back_is_unprovable() -> None:
    outcome = verify.evaluate(**observations(read_back_ok=False))
    assert outcome.verdict == verify.UNPROVABLE
    assert not finding(outcome, 3).proven


def test_a_consumer_that_cannot_install_is_unprovable() -> None:
    outcome = verify.evaluate(**observations(consumer_installed=False))
    assert outcome.verdict == verify.UNPROVABLE
    assert not finding(outcome, 4).proven
    assert "could not install" in finding(outcome, 4).detail


def test_hash_equality_and_installation_are_independent() -> None:
    """THE COLLISION THAT MADE a3 UNPROVABLE, now impossible by construction.

    The first design asked one question of a `pip download`: "did the consumer
    retrieve everything the run built?" pip takes the wheel and leaves the
    sdist, so a sound release looked unproven. These are two questions and each
    must be able to fail alone.
    """
    only_bytes = verify.evaluate(**observations(consumer_installed=False))
    assert only_bytes.verdict == verify.UNPROVABLE
    assert finding(only_bytes, 1).proven and not finding(only_bytes, 4).proven

    only_install = verify.evaluate(**observations(fetched={WHEEL: WHEEL_SHA}))
    assert only_install.verdict == verify.UNPROVABLE
    assert finding(only_install, 4).proven and not finding(only_install, 1).proven


def test_the_sdist_is_not_optional() -> None:
    """a3's exact shape: wheel present and matching, sdist never compared. The
    ruling that made a3 unreleasable rests on this refusal, so narrowing it
    would retroactively pass the version Michael declared unreleasable."""
    outcome = verify.evaluate(**observations(fetched={WHEEL: WHEEL_SHA}))
    assert outcome.verdict == verify.UNPROVABLE
    assert SDIST in finding(outcome, 1).detail


@pytest.mark.parametrize(
    "listing",
    [
        [WHEEL, WHEEL, SDIST],
        [WHEEL],
        [SDIST],
        [],
    ],
)
def test_anything_but_one_wheel_and_one_sdist_is_unprovable(listing: list[str]) -> None:
    """Property 5. A second wheel for one version is what an overwrite or a
    re-upload looks like from the outside."""
    outcome = verify.evaluate(**observations(index_filenames=listing))
    assert outcome.verdict == verify.UNPROVABLE
    assert not finding(outcome, 5).proven


def test_another_versions_files_do_not_satisfy_property_five() -> None:
    outcome = verify.evaluate(
        **observations(
            index_filenames=[
                "dotmac_deployment_control-0.1.0a2-py3-none-any.whl",
                "dotmac_deployment_control-0.1.0a2.tar.gz",
            ]
        )
    )
    assert not finding(outcome, 5).proven


# ── the report itself ───────────────────────────────────────────────────────


def test_an_unprovable_report_says_what_was_not_proven_and_forbids_a_retry() -> None:
    rendered = verify.evaluate(**observations(read_back_ok=False)).render()
    assert rendered.startswith("## UNPROVABLE")
    assert "NOT PROVEN" in rendered
    assert "not a retry signal" in rendered
    assert "tidier" in rendered


def test_the_report_lists_every_property_even_when_one_fails() -> None:
    """A report that stopped at the first failure would hide whether the rest
    hold — and 'the bytes matched but provenance did not' is exactly the
    distinction a reader needs."""
    outcome = verify.evaluate(**observations(read_back_ok=False))
    assert {f.prop for f in outcome.findings} == {1, 2, 3, 4, 5}
    assert len(outcome.unproven) == 1
