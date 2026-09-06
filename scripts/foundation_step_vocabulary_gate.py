"""The required CI gate over Foundation's OWN pinned source. No install.

Reads `dotmac_deployment_control.rehearsal_grant.FOUNDATION_STEP_KIND_SOURCE`
(`<repository>@<commit>:<path>`), fetches the raw file at that EXACT pinned
commit over HTTPS — nothing beyond the standard library, no
`dotmac-deployment-foundation` dependency of any kind, dev or runtime — and
compares it against the mirror with
`dotmac_deployment_control.foundation_source_gate
.require_foundation_step_vocabulary_agreement`.

This script is the ONLY place in this repository that performs the network
read. Everything it calls into (`foundation_source_gate.py`) is pure and
injected with a `SourceReader`, so the comparison's own sensitivity is provable
without network access — see `tests/unit/test_foundation_source_gate.py`. This
file is the thin, untested-by-design wrapper that supplies the real reader,
matching the split `scripts/kernel_floor.py` and `scripts/fetch_published_
artifacts.py` already draw between "the network I/O" and "the logic".

Exit 0: the pinned source agrees with the mirror. Exit 1: it does not, or it
could not be read — both are gate failures, and the message distinguishes
which because they need different repairs (see
`FoundationStepVocabularySourceError` vs `FoundationStepVocabularyDriftError`).
"""

from __future__ import annotations

import sys
import urllib.error
import urllib.request

sys.path.insert(0, "src")

from dotmac_deployment_control.foundation_source_gate import (
    SourceCoordinate,
    require_foundation_step_vocabulary_agreement,
)
from dotmac_deployment_control.ports import (
    FoundationStepVocabularyDriftError,
    FoundationStepVocabularySourceError,
)

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
    except FoundationStepVocabularySourceError as error:
        print(f"foundation-step-vocabulary-gate: SOURCE UNAVAILABLE: {error}")
        return 1
    except FoundationStepVocabularyDriftError as error:
        print(f"foundation-step-vocabulary-gate: DRIFT: {error}")
        return 1
    except urllib.error.URLError as error:
        print(f"foundation-step-vocabulary-gate: NETWORK FAILURE: {error}")
        return 1
    print("foundation-step-vocabulary-gate: the pinned source agrees with the mirror")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
