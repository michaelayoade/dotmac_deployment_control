"""Decide whether a published version is VERIFIED or UNPROVABLE.

There is no third outcome and there is deliberately no generic success marker.
`0.1.0a3` was published by a run that was cancelled during its own verification,
so the bytes exist and the evidence chain does not. A step printing "OK" on a
path it did not exercise would be the same defect that produced this situation:
a reassurance that cannot observe what it claims to summarise.

UNPROVABLE is a legitimate result. It means the evidence needed to authenticate
this artifact could not be gathered — an expired run artifact, a registry that
will not serve the file, a provenance link that cannot be closed. It is reported
as unprovable and never retried into looking green.

## The five properties, and why each is separate

1. The registry's wheel matches the artifact produced by the exact release run.
2. Distribution, version, source revision and hashes all agree.
3. The publisher can read the published version back.
4. A clean read-only consumer can install those exact bytes.
5. No second upload or overwrite occurred.

1 and 2 are not the same claim, and conflating them is the gap this exists to
close. A wheel on the index with the expected sha256 proves the BYTES are the
ones somebody built; it says nothing about WHICH run built them or from what
source. Property 2 is what ties the hash to a workflow run, that run to a head
commit, and that commit to a declared name and version.
"""

from __future__ import annotations

import hashlib
import json
import tomllib
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

VERIFIED = "VERIFIED"
UNPROVABLE = "UNPROVABLE"

DISTRIBUTION = "dotmac-deployment-control"
RELEASE_WORKFLOW = ".github/workflows/release.yml"
PUBLISH_JOB = "publish"


@dataclass
class Finding:
    """One property, its verdict, and what was actually observed."""

    prop: int
    name: str
    proven: bool
    detail: str


@dataclass
class Outcome:
    verdict: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def unproven(self) -> list[Finding]:
        return [f for f in self.findings if not f.proven]

    def render(self) -> str:
        lines = [f"## {self.verdict}", ""]
        for f in sorted(self.findings, key=lambda f: f.prop):
            mark = "proven" if f.proven else "NOT PROVEN"
            lines.append(f"- **{f.prop}. {f.name}** — {mark}. {f.detail}")
        if self.verdict == UNPROVABLE:
            lines += [
                "",
                "`UNPROVABLE` is a result, not a retry signal. The bytes on the "
                "index may be perfectly sound; what could not be established is "
                "the evidence chain above. Publishing a new version to make this "
                "record tidier is explicitly not the repair.",
            ]
        return "\n".join(lines)


def sha256_of(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def parse_hash_manifest(text: str) -> dict[str, str]:
    """`sha256sum` output -> {filename: digest}."""
    found: dict[str, str] = {}
    for line in text.splitlines():
        if not line.strip():
            continue
        digest, _, name = line.partition(" ")
        found[name.strip().lstrip("*")] = digest.strip()
    return found


def evaluate(
    *,
    version: str,
    run: dict[str, Any],
    publish_job_conclusion: str | None,
    head_sha_on_main: bool,
    pyproject_at_head: str | None,
    built_hashes: dict[str, str],
    downloaded: dict[str, str],
    read_back_ok: bool,
    index_filenames: list[str],
) -> Outcome:
    """Pure. Every input is something the workflow observed; nothing is fetched
    here, so the whole decision is testable without a network."""
    findings: list[Finding] = []

    # ── 2 first: provenance, because 1 is meaningless without it ────────────
    provenance_problems: list[str] = []
    if run.get("path") != RELEASE_WORKFLOW:
        provenance_problems.append(f"run came from {run.get('path')!r}")
    if run.get("event") != "workflow_dispatch":
        provenance_problems.append(f"event was {run.get('event')!r}")
    if run.get("head_branch") != "main":
        provenance_problems.append(f"head branch was {run.get('head_branch')!r}")
    if publish_job_conclusion != "success":
        provenance_problems.append(f"its publish job was {publish_job_conclusion!r}")
    if not head_sha_on_main:
        provenance_problems.append("head SHA is not an ancestor of protected main")

    declared = None
    if pyproject_at_head is None:
        provenance_problems.append("pyproject at the head SHA could not be read")
    else:
        poetry = tomllib.loads(pyproject_at_head)["tool"]["poetry"]
        declared = (poetry["name"], poetry["version"])
        if declared != (DISTRIBUTION, version):
            provenance_problems.append(
                f"the head commit declares {declared[0]} {declared[1]}, "
                f"not {DISTRIBUTION} {version}"
            )

    findings.append(
        Finding(
            2,
            "distribution, version, source revision and hashes agree",
            not provenance_problems,
            (
                f"run {run.get('id')} on {str(run.get('head_sha'))[:12]}… dispatched "
                f"from {RELEASE_WORKFLOW}, publish job succeeded, head commit "
                f"declares {DISTRIBUTION} {version}"
                if not provenance_problems
                else "; ".join(provenance_problems)
            ),
        )
    )

    # ── 1: the registry's bytes are that run's bytes ────────────────────────
    if not built_hashes:
        detail, proven = "the release run's artifact could not be read", False
    elif not downloaded:
        detail, proven = "nothing was retrieved from the registry", False
    else:
        mismatched = []
        for name, digest in sorted(downloaded.items()):
            want = built_hashes.get(name)
            if want is None:
                mismatched.append(f"{name} was served but not built by that run")
            elif want != digest:
                mismatched.append(f"{name}: built {want[:12]}…, served {digest[:12]}…")
        missing = sorted(set(built_hashes) - set(downloaded))
        proven = not mismatched and not missing
        detail = (
            "; ".join(mismatched + [f"{m} was not served" for m in missing])
            if not proven
            else ", ".join(f"{n} {d[:12]}…" for n, d in sorted(downloaded.items()))
        )
    findings.append(
        Finding(
            1, "registry bytes are the exact release run's artifact", proven, detail
        )
    )

    # ── 3 ───────────────────────────────────────────────────────────────────
    findings.append(
        Finding(
            3,
            "publisher-authenticated read-back",
            read_back_ok,
            "the publisher retrieved the version from the index"
            if read_back_ok
            else "the publisher could not read the version back",
        )
    )

    # ── 4 ───────────────────────────────────────────────────────────────────
    findings.append(
        Finding(
            4,
            "a clean read-only consumer installs those bytes",
            bool(downloaded),
            f"ci-reader retrieved {len(downloaded)} file(s) into a clean environment"
            if downloaded
            else "the read-only consumer retrieved nothing",
        )
    )

    # ── 5: exactly one of each artifact for this version ────────────────────
    for_version = [n for n in index_filenames if version in n]
    wheels = [n for n in for_version if n.endswith(".whl")]
    sdists = [n for n in for_version if n.endswith(".tar.gz")]
    single = len(wheels) == 1 and len(sdists) == 1
    findings.append(
        Finding(
            5,
            "no second upload or overwrite",
            single,
            f"the index lists exactly one wheel and one sdist for {version}"
            if single
            else f"the index lists {len(wheels)} wheel(s) and {len(sdists)} sdist(s) "
            f"for {version}: {sorted(for_version)}",
        )
    )

    verdict = VERIFIED if all(f.proven for f in findings) else UNPROVABLE
    return Outcome(verdict, findings)


def main() -> int:  # pragma: no cover - the workflow's adapter
    import argparse

    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--observations", required=True)
    args = parser.parse_args()

    data = json.loads(Path(args.observations).read_text(encoding="utf-8"))
    outcome = evaluate(**data)
    print(outcome.render())
    summary = Path(__import__("os").environ.get("GITHUB_STEP_SUMMARY", "/dev/null"))
    with summary.open("a", encoding="utf-8") as handle:
        handle.write(outcome.render() + "\n")
    return 0 if outcome.verdict == VERIFIED else 1


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
