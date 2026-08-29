"""PORTED GATE 4 — the extraction dossier says only what its evidence supports.

Source: `dotmac_starter_mt` `tests/architecture/test_product_first_extraction.py`,
ported as an equivalent property. The original is two thousand lines governing
ninety dossiers; there is one here, and copying that machinery would create a
fourth unpinned fork of Starter code.

The property that must survive the move is the TWO-DIRECTIONAL ratchet: a
package may not claim more than its consumers prove, and may not sit in a state
weaker than its evidence supports. One contract consumer is exactly `adopted` —
not a floor. A floor would let a package with two consumers keep claiming
`audit-complete` forever, which is how the previous model quietly stopped
meaning anything.

`adoption_evidence.py` — the copied vocabulary this uses — is itself held by a
blob-id pin in `test_vocabulary_is_not_a_fork.py`, so this gate cannot be made
to pass by loosening the vocabulary underneath it.
"""

from __future__ import annotations

import copy
import tomllib
from pathlib import Path
from typing import Any

import pytest

from tests.architecture import adoption_evidence as evidence

REPO_ROOT = Path(__file__).resolve().parents[2]
DOSSIER = REPO_ROOT / "EXTRACTION.toml"

EVIDENCE_STATES = ("audit-complete", "adopted", "reuse-proven")
RAN_IN_A_PRODUCT = frozenset({"adopted", "reuse-proven"})
AUDITED_SOURCE_MODES = frozenset({"product-first", "greenfield-after-inventory"})
WRITER_STATES = frozenset(
    {"qualifying_source", "legacy_writer", "no_writer", "inventory_only"}
)


def _state_for(consumer_count: int) -> str:
    """Exact in both directions, never a floor."""
    if consumer_count == 0:
        return "audit-complete"
    if consumer_count == 1:
        return "adopted"
    return "reuse-proven"


def dossier_problems(dossier: dict[str, Any]) -> list[str]:
    """The whole decision, pure, so the live check and the plants share it."""
    problems: list[str] = []

    status = dossier.get("status")
    consumers = dossier.get("contract_consumers")
    if not isinstance(consumers, list) or not all(
        isinstance(c, str) and c.strip() for c in consumers
    ):
        problems.append("contract_consumers must be a non-empty string list")
        consumers = []

    if status not in EVIDENCE_STATES:
        problems.append(f"status {status!r} must be one of {list(EVIDENCE_STATES)}")
    else:
        required = _state_for(len(set(consumers)))
        if status != required:
            problems.append(
                f"status is {status!r} but {len(set(consumers))} contract "
                f"consumer(s) support exactly {required!r}. The ratchet runs "
                "both ways: a package may not claim more than its consumers "
                "prove, nor sit in a state weaker than its evidence supports"
            )

    if dossier.get("source_mode") not in AUDITED_SOURCE_MODES:
        problems.append(
            f"source_mode {dossier.get('source_mode')!r} must be one of "
            f"{sorted(AUDITED_SOURCE_MODES)} — an audited mode is what backs the "
            "claim that the inventory was done"
        )

    problems += evidence.evidence_problems(
        rows=dossier.get("adoption_evidence") or [],
        pointers=dossier.get("adoption_evidence_pointer"),
        schema_marker=dossier.get("adoption_evidence_schema"),
        distribution=str(dossier.get("package", "")),
    )
    problems += evidence.adoption_state_problems(
        status=status,
        rows=dossier.get("adoption_evidence") or [],
        adoption_states=RAN_IN_A_PRODUCT,
    )

    for index, writer in enumerate(dossier.get("product_writers") or []):
        where = f"product_writers[{index}]"
        if writer.get("writer_state") not in WRITER_STATES:
            problems.append(
                f"{where}.writer_state must be one of {sorted(WRITER_STATES)}"
            )
        revision = writer.get("revision")
        if not isinstance(revision, str) or not evidence.IMMUTABLE_COMMIT.fullmatch(
            revision
        ):
            problems.append(
                f"{where}.revision must be an immutable 40-hex commit — a claim "
                "measured against a moving branch is not a claim"
            )
    return problems


def _dossier() -> dict[str, Any]:
    return tomllib.loads(DOSSIER.read_text(encoding="utf-8"))


def test_the_dossier_in_this_repository_is_coherent() -> None:
    assert dossier_problems(_dossier()) == []


def test_the_dossier_is_the_package_it_claims_to_be() -> None:
    data = _dossier()
    pyproject = tomllib.loads(
        (REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8")
    )
    assert data["package"] == pyproject["tool"]["poetry"]["name"]


@pytest.mark.parametrize(
    ("mutation", "fragment"),
    [
        ({"status": "audit-complete"}, "support exactly 'adopted'"),
        ({"status": "reuse-proven"}, "support exactly 'adopted'"),
        ({"contract_consumers": []}, "support exactly 'audit-complete'"),
        ({"contract_consumers": ["a", "b"]}, "support exactly 'reuse-proven'"),
        ({"source_mode": "vibes"}, "must be one of"),
        ({"adoption_evidence": []}, "claims a product composed this capability"),
    ],
)
def test_the_gate_catches_a_violation_this_repository_could_commit(
    mutation: dict[str, Any], fragment: str
) -> None:
    """PLANTED VIOLATIONS — the acceptance test for this port.

    Each is a real edit someone could make to `EXTRACTION.toml` in this
    repository: understate the adoption, overstate it, drop the consumer, add a
    consumer nobody proved, claim an unaudited provenance, or delete the
    evidence while keeping the claim. Moving the file would satisfy nobody;
    catching these is what "the gate is ported" has to mean.
    """
    mutated = copy.deepcopy(_dossier())
    mutated.update(mutation)
    problems = dossier_problems(mutated)
    assert any(fragment in p for p in problems), (fragment, problems)


def test_the_writer_revision_must_be_an_immutable_commit() -> None:
    mutated = copy.deepcopy(_dossier())
    mutated["product_writers"][0]["revision"] = "main"
    problems = dossier_problems(mutated)
    assert any("immutable 40-hex commit" in p for p in problems), problems
