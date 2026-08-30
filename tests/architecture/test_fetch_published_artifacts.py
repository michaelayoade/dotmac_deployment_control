"""The layer that FEEDS the verdict, which nothing was watching.

`scripts/verify_release.py` is thoroughly tested and its refusals are real. But
every one of them reasons over a `fetched` mapping produced by
`scripts/fetch_published_artifacts.py`, and that script had no tests at all — so
the property "the verifier notices a missing artifact" rested on the fetcher
reporting one honestly.

That is exactly the shape that made `0.1.0a3` unprovable and let `0.1.0a4` be
tagged: not a check that returned the wrong answer, but a check that was never
asked the question. `pip download` returned the wheel, the comparison ran over
what it returned, and the sdist was never named by anything.

So the enumeration comes from the release run's own hash manifest, and these
tests exercise the two pure functions that turn that manifest into requests —
including the case where the index does not list a file the run built, which
must surface as an absence the verdict can see rather than a shorter list
nobody counted.
"""

from __future__ import annotations

import importlib.util
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
_spec = importlib.util.spec_from_file_location(
    "fetch_published_artifacts", REPO_ROOT / "scripts" / "fetch_published_artifacts.py"
)
assert _spec is not None and _spec.loader is not None
fetcher = importlib.util.module_from_spec(_spec)
sys.modules[_spec.name] = fetcher
_spec.loader.exec_module(fetcher)

WHEEL = "dotmac_deployment_control-0.1.0a4-py3-none-any.whl"
SDIST = "dotmac_deployment_control-0.1.0a4.tar.gz"

MANIFEST = (
    f"ad1aaaa2d20b9a565d0656f64762564f4dfd90eb4c367187aa63fdd54a33c37e  {WHEEL}\n"
    f"a5dae85d76e17ab34b1868741def46aab514ffba119110ec750794f5dc1c6e2c  {SDIST}\n"
)

INDEX_HTML = f"""<!DOCTYPE html><html><body>
<a href="../../files/{WHEEL}#sha256=ad1aaa">{WHEEL}</a><br/>
<a href="../../files/{SDIST}#sha256=a5dae8">{SDIST}</a><br/>
</body></html>"""


# ── the manifest is the enumeration, and it must name BOTH artifacts ────────


def test_both_artifacts_are_enumerated_from_the_manifest() -> None:
    """THE a3 DEFECT, stated as a requirement. A resolver picks the wheel; the
    manifest names everything the run built."""
    assert fetcher.parse_manifest(MANIFEST) == [WHEEL, SDIST]


def test_a_manifest_naming_only_the_wheel_yields_only_the_wheel() -> None:
    """SENSITIVITY. If `parse_manifest` invented the sdist — or returned a fixed
    pair — the test above would pass for the wrong reason."""
    only_wheel = MANIFEST.splitlines()[0] + "\n"
    assert fetcher.parse_manifest(only_wheel) == [WHEEL]


def test_blank_lines_and_binary_markers_do_not_become_filenames() -> None:
    """`sha256sum -b` prefixes the name with `*`, and a trailing newline yields
    a blank line. Either one silently becomes a filename that no index will
    serve, which would report a sound release as unprovable."""
    text = f"\n{'0' * 64} *{WHEEL}\n\n"
    assert fetcher.parse_manifest(text) == [WHEEL]


# ── locating a file on the index page ───────────────────────────────────────


def test_each_enumerated_file_is_found_on_the_index_page() -> None:
    for name in (WHEEL, SDIST):
        assert fetcher.find_href(INDEX_HTML, name) is not None


def test_a_file_the_index_does_not_list_is_reported_absent_not_guessed() -> None:
    """THE NEGATIVE CONTROL. `None` is what makes the verdict function see a
    missing artifact; a fetcher that fabricated a plausible URL, or skipped the
    name quietly, would hand `verify_release.evaluate` a shorter `fetched` map
    and it would have no way to tell that from a release with fewer files."""
    absent = "dotmac_deployment_control-0.1.0a9.tar.gz"
    assert fetcher.find_href(INDEX_HTML, absent) is None


def test_a_prefix_match_is_not_a_match() -> None:
    """`0.1.0a4` is a prefix of `0.1.0a40`, and `.tar.gz` of nothing helpful.
    A substring search would let a neighbouring version's bytes be fetched,
    hashed, and compared against the wrong manifest entry — which fails, but
    for a reason no one could read."""
    html = INDEX_HTML.replace("0.1.0a4.tar.gz", "0.1.0a40.tar.gz")
    assert fetcher.find_href(html, SDIST) is None
    assert fetcher.find_href(html, "dotmac_deployment_control-0.1.0a40.tar.gz")


def test_the_fragment_is_not_part_of_the_filename() -> None:
    """Forgejo appends `#sha256=…`. Comparing the raw href would never match."""
    assert fetcher.find_href(f'<a href="/files/{WHEEL}#sha256=deadbeef">x</a>', WHEEL)


# ── the credential never reaches a URL ──────────────────────────────────────


def test_the_credential_is_read_from_the_environment_not_a_url() -> None:
    """The fetcher exists partly because a curl one-liner would have put
    `user:token@host` in a URL. Asserted on the source rather than trusted: the
    token goes into an `Authorization` header built from an environment
    variable, so it is in neither the URL nor the process arguments."""
    source = (REPO_ROOT / "scripts" / "fetch_published_artifacts.py").read_text(
        encoding="utf-8"
    )
    assert 'os.environ.get("INDEX_TOKEN"' in source
    for line in source.splitlines():
        code = line.split("#", 1)[0]
        if "://" in code and "token" in code.lower():
            raise AssertionError(f"a token may be reaching a URL: {line.strip()}")
