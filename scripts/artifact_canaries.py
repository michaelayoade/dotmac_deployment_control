"""Behavioural canaries that run against the INSTALLED distribution.

## Why this file is not a test

`tests/` runs against the source tree. That is the right place for almost
everything, and it is exactly why `0.1.0a4` shipped a wheel whose
`__version__` said `0.1.0a2`: every check that could have caught it was reading
`src/`, where the two literals were equally wrong and equally invisible. A
proof about an ARTIFACT has to execute the artifact.

So this is a standalone script, run by the interpreter of an environment that
has the wheel installed and does not have this repository importable:

    /path/to/venv/bin/python scripts/artifact_canaries.py --expect-version 0.1.0a5

It imports no pytest, because the environment being proven contains only the
distribution's real runtime dependencies. Adding a test framework to that
environment would change the thing under test.

## The first canary is the one that makes the rest mean anything

`installed_not_source` proves the module under test came out of the
environment's `site-packages` and not out of a checkout. Without it every
canary below could pass while reading the working tree, and the suite would be
a slower copy of the unit tests wearing a stronger claim. ADR-0018's first
failure mode, in the place it would do the most damage.

## What each canary corresponds to

Every one of these is a property `0.1.0a4` got wrong, or a property whose
absence let a4's defect survive publication:

* `installed_not_source`      — the proof is about the artifact.
* `version_agreement`         — `__version__`, wheel METADATA and the declared
                                version are one fact. a4 had two, disagreeing.
* `propose_emits_canonical`   — `propose_plan` freezes `sha256:<64 hex>`, not
                                bare hex.
* `exact_digest_approves`     — the digest Control emits, handed straight back,
                                authorizes. The happy path a4 also passed, kept
                                because the fix must not break it.
* `a4_bare_hex_still_binds`   — a4's encoding still authorizes, normalized
                                INSIDE Control. This is the sensitivity proof:
                                a string-comparing implementation fails it.
* `encoding_fault_is_not_a_mutation` — an unreadable digest raises
                                `DigestEncodingError` and never says the plan
                                changed. The defect itself.
* `mutation_after_authorization_is_refused` — and the refusal a4 was reaching
                                for still happens, on a real change.
"""

from __future__ import annotations

import argparse
import re
import sys
import sysconfig
import traceback
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

DISTRIBUTION = "dotmac-deployment-control"
IMPORT_NAME = "dotmac_deployment_control"
CANONICAL_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


class CanaryFailure(AssertionError):
    """A canary observed something the published artifact must never do."""


# ── the environment under test ──────────────────────────────────────────────


def _site_directories() -> list[Path]:
    """Every directory this interpreter installs distributions into."""
    found: list[Path] = []
    for key in ("purelib", "platlib"):
        path = sysconfig.get_paths().get(key)
        if path:
            found.append(Path(path).resolve())
    return found


def canary_installed_not_source() -> str:
    """The module under test is the INSTALLED one.

    Three independent statements, because each catches a different way this
    could be reading a checkout: the import resolved inside an install
    directory; there is no `src/` layout anywhere on the path that could have
    supplied it; and the distribution's metadata is discoverable, which a bare
    directory on `sys.path` would not be.
    """
    import importlib.metadata

    module = __import__(IMPORT_NAME)
    origin = Path(module.__file__ or "").resolve()
    sites = _site_directories()
    if not sites:
        raise CanaryFailure("this interpreter reports no install directory at all")
    if not any(origin.is_relative_to(site) for site in sites):
        raise CanaryFailure(
            f"{IMPORT_NAME} was imported from {origin}, which is not inside any "
            f"of this interpreter's install directories ({sites}). This canary "
            "is a statement about a built artifact; run it with the interpreter "
            "of an environment that has the wheel installed."
        )

    shadowing = [
        entry
        for entry in sys.path
        if entry
        and (Path(entry).resolve() / IMPORT_NAME / "__init__.py").is_file()
        and not any(Path(entry).resolve().is_relative_to(site) for site in sites)
    ]
    if shadowing:
        raise CanaryFailure(
            f"a source copy of {IMPORT_NAME} is importable from {shadowing}. Even "
            "though the install won this time, a path ordering change would "
            "silently move every canary below onto the checkout."
        )

    # Discoverable METADATA is the third statement: a directory dropped on
    # `sys.path` supplies a module and no distribution, so this fails on a
    # checkout even when the two path checks somehow pass.
    metadata_dir = importlib.metadata.distribution(DISTRIBUTION).locate_file("")
    return f"imported from {origin} (metadata under {metadata_dir})"


def canary_version_agreement(expect_version: str) -> str:
    """`__version__`, the wheel's METADATA and the declared version are ONE fact.

    a4 published `__version__ = "0.1.0a2"` from a tree declaring `0.1.0a4`. An
    authorization recording which version of Control decided something would
    have recorded the wrong one, and no check anywhere compared the two.
    """
    import importlib.metadata

    module = __import__(IMPORT_NAME)
    reported = getattr(module, "__version__", None)
    metadata_version = importlib.metadata.version(DISTRIBUTION)
    raw = importlib.metadata.metadata(DISTRIBUTION)["Version"]

    disagreements = []
    if reported != expect_version:
        disagreements.append(f"{IMPORT_NAME}.__version__ == {reported!r}")
    if metadata_version != expect_version:
        disagreements.append(f"importlib.metadata.version() == {metadata_version!r}")
    if raw != expect_version:
        disagreements.append(f"METADATA Version: == {raw!r}")
    if disagreements:
        raise CanaryFailure(
            f"the declared version is {expect_version!r} but "
            + "; ".join(disagreements)
            + ". Two literals for one fact is the a4 defect; there must be one."
        )
    if reported == "0.0.0+not-installed":
        raise CanaryFailure(
            "__version__ fell back to its not-installed sentinel, so the "
            "distribution's metadata was not found from inside its own package"
        )
    return f"__version__ == METADATA Version: == {expect_version}"


# ── a database, inside the environment under test ───────────────────────────


def _session() -> Any:
    """The same in-memory SQLite shape `tests/unit` builds.

    Duplicated rather than imported: importing the test module would pull the
    repository's `tests/` package into the environment being proven, which is
    the one thing these canaries exist to avoid.
    """
    from dotmac_kernel.audit_actions import AuditActionRegistry, install_audit_actions
    from dotmac_kernel.models import Base
    from sqlalchemy import create_engine, event
    from sqlalchemy.orm import sessionmaker

    from dotmac_deployment_control import module

    install_audit_actions(AuditActionRegistry.from_manifests([module]))
    engine = create_engine("sqlite://", future=True)

    @event.listens_for(engine, "connect")
    def _attach(dbapi_connection: Any, _record: Any) -> None:
        dbapi_connection.isolation_level = None
        dbapi_connection.execute("ATTACH DATABASE ':memory:' AS mod_deploy")

    @event.listens_for(engine, "begin")
    def _emit_begin(connection: Any) -> None:
        connection.exec_driver_sql("BEGIN")

    Base.metadata.create_all(
        engine,
        tables=[
            table
            for table in Base.metadata.tables.values()
            if table.schema == "mod_deploy"
            or table.name
            in {
                "platform_idempotency_records",
                "platform_audit_events",
                "platform_admins",
                "platform_outbox_events",
            }
        ],
    )
    return sessionmaker(bind=engine, autocommit=False, autoflush=False)()


_NOW = datetime(2026, 9, 1, 12, 0, tzinfo=UTC)
_POLICY = "deployment.production"
_POLICY_VERSION = 4


def _command_id() -> str:
    return f"cmd-{uuid.uuid4().hex[:12]}"


def _proposed_plan(db: Any, *, replicas: int = 2) -> Any:
    """register -> set desired -> propose, returning the frozen plan."""
    from dotmac_deployment_control import (
        DesiredDeployment,
        ProposePlanCommand,
        RegisterTargetCommand,
        SetDesiredStateCommand,
        propose_plan,
        register_target,
        set_desired_state,
    )

    target = register_target(
        db,
        RegisterTargetCommand(
            command_id=_command_id(),
            target_ref=f"tgt-{uuid.uuid4().hex[:8]}",
            subject_ref="acme-operator",
            product_code="dotmac_sub",
            environment="production",
        ),
    )
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_command_id(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@7.187.1",
                spec={"replicas": replicas},
                licence_ref="lic-1",
                brand_profile_ref="brand-acme",
            ),
        ),
    )
    plan = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )
    return target, plan


def _evidence(digest: str) -> Any:
    from dotmac_deployment_control import ApprovalEvidence

    return ApprovalEvidence(
        policy_code=_POLICY,
        policy_version=_POLICY_VERSION,
        decision_ref=f"apr-{uuid.uuid4().hex[:8]}",
        content_digest=digest,
        decided_at=_NOW,
    )


def _approve(db: Any, plan_id: Any, digest: str) -> Any:
    from dotmac_deployment_control import ApprovePlanCommand, approve_plan

    return approve_plan(
        db,
        ApprovePlanCommand(
            command_id=_command_id(), plan_id=plan_id, evidence=_evidence(digest)
        ),
    )


# ── the behavioural canaries ────────────────────────────────────────────────


def canary_propose_emits_canonical() -> str:
    """`propose_plan` freezes a CANONICAL `PlanDigestV1`, not bare hex."""
    from dotmac_deployment_control import PlanDigestV1, snapshot_digest

    db = _session()
    _, plan = _proposed_plan(db)
    frozen = plan.plan_digest or ""
    if not CANONICAL_DIGEST.fullmatch(frozen):
        raise CanaryFailure(
            f"propose_plan froze {frozen!r}, which is not `sha256:<64 lowercase "
            "hex>`. Through 0.1.0a4 it froze bare hex, which cannot say which "
            "algorithm produced it."
        )
    recomputed = PlanDigestV1.over_json(plan.snapshot)
    if PlanDigestV1.parse(frozen) != recomputed:
        raise CanaryFailure(
            f"the frozen digest {frozen} is not the digest of the snapshot it "
            f"was frozen from ({recomputed.canonical})"
        )
    if snapshot_digest(plan.snapshot) != frozen:
        raise CanaryFailure("snapshot_digest disagrees with the stored digest")
    return f"frozen {frozen}"


def canary_exact_digest_approves() -> str:
    """The digest Control emitted, handed straight back, AUTHORIZES."""
    from dotmac_deployment_control import PlanStatus

    db = _session()
    _, plan = _proposed_plan(db)
    approved = _approve(db, plan.id, plan.plan_digest or "")
    if approved.status != PlanStatus.APPROVED.value:
        raise CanaryFailure(
            f"supplying the exact frozen digest left the plan {approved.status!r}"
        )
    return f"plan {approved.id} approved on {plan.plan_digest}"


def canary_a4_bare_hex_still_binds() -> str:
    """THE SENSITIVITY PROOF, and the reason it is worth its length.

    The evidence carries a4's bare-hex encoding of the SAME digest. As STRINGS
    the two values differ, so the `0.1.0a4` implementation — `evidence
    .content_digest != row.plan_digest` — refuses this and says the plan
    changed. Approval succeeding here therefore cannot be satisfied by a
    string comparison, and the normalization has demonstrably happened INSIDE
    Control: the caller handed over exactly what a4 would have produced and did
    no work of its own.
    """
    from dotmac_deployment_control import PlanDigestV1, PlanStatus

    db = _session()
    _, plan = _proposed_plan(db)
    frozen_text = plan.plan_digest or ""
    a4_text = PlanDigestV1.parse(frozen_text).a4_bare_hex
    if a4_text == frozen_text:
        raise CanaryFailure(
            "the a4 encoding and the canonical encoding are the same string, so "
            "this canary would pass against a string comparison and prove "
            "nothing. Control is no longer emitting a canonical digest."
        )
    approved = _approve(db, plan.id, a4_text)
    if approved.status != PlanStatus.APPROVED.value:
        raise CanaryFailure(
            f"a4's bare-hex encoding of the plan's own digest left the plan "
            f"{approved.status!r}"
        )
    return (
        f"caller supplied {a4_text[:16]}… (a4 form, {len(a4_text)} chars); "
        f"Control bound it to {frozen_text[:23]}… ({len(frozen_text)} chars)"
    )


def canary_encoding_fault_is_not_a_mutation() -> str:
    """THE DEFECT ITSELF: an unreadable digest never says the plan changed."""
    from dotmac_deployment_control import ApprovalRefusedError, DigestEncodingError

    unreadable = [
        "",
        "not-a-digest",
        "SHA256:" + "a" * 64,
        "sha256:" + "A" * 64,
        "sha256:" + "a" * 63,
        "md5:" + "a" * 32,
        "sha512:" + "a" * 128,
    ]
    for value in unreadable:
        db = _session()
        _, plan = _proposed_plan(db)
        try:
            _approve(db, plan.id, value)
        except DigestEncodingError as exc:
            message = str(exc).lower()
            for forbidden in ("plan changed", "new approval is required"):
                if forbidden in message:
                    raise CanaryFailure(
                        f"an unreadable digest ({value!r}) was refused with "
                        f"{forbidden!r} in the message. That is a security "
                        "finding standing in for a formatting bug — the exact "
                        f"defect 0.1.0a5 was cut for. Message: {exc}"
                    ) from exc
            if isinstance(exc, ApprovalRefusedError):
                raise CanaryFailure(
                    "DigestEncodingError is a subclass of ApprovalRefusedError, "
                    "so a caller cannot tell an encoding fault from a changed "
                    "plan by type either"
                ) from exc
        except ApprovalRefusedError as exc:
            raise CanaryFailure(
                f"an unreadable digest ({value!r}) raised ApprovalRefusedError: "
                f"{exc}. Unreadable is not changed."
            ) from exc
        else:
            raise CanaryFailure(
                f"an unreadable digest ({value!r}) was ACCEPTED and the plan "
                "approved"
            )
    return f"{len(unreadable)} unreadable encodings refused, none as a mutation"


def canary_mutation_after_authorization_is_refused() -> str:
    """And the refusal a4 was REACHING for still happens, on a real change.

    Approval evidence bound to plan 1's digest must not authorize plan 2. That
    is ADR-0026 § 2's binding, and separating the encoding fault from it must
    not have loosened it — a fix that made everything approve would satisfy
    every canary above.
    """
    from dotmac_deployment_control import (
        ApprovalRefusedError,
        DesiredDeployment,
        DigestEncodingError,
        ProposePlanCommand,
        SetDesiredStateCommand,
        propose_plan,
        set_desired_state,
    )

    db = _session()
    target, first = _proposed_plan(db, replicas=2)
    set_desired_state(
        db,
        SetDesiredStateCommand(
            command_id=_command_id(),
            target_id=target.id,
            desired=DesiredDeployment(
                release_ref="dotmac_sub@7.187.1",
                spec={"replicas": 9},
                licence_ref="lic-1",
                brand_profile_ref="brand-acme",
            ),
        ),
    )
    second = propose_plan(
        db,
        ProposePlanCommand(
            command_id=_command_id(),
            target_id=target.id,
            requires_approval=True,
            approval_policy_code=_POLICY,
            approval_policy_version=_POLICY_VERSION,
        ),
    )
    if second.plan_digest == first.plan_digest:
        raise CanaryFailure(
            "the plan changed and its digest did not, so the binding cannot "
            "detect anything"
        )
    try:
        _approve(db, second.id, first.plan_digest or "")
    except DigestEncodingError as exc:
        raise CanaryFailure(
            f"a genuinely stale-but-well-formed digest was reported as an "
            f"encoding fault: {exc}"
        ) from exc
    except ApprovalRefusedError as exc:
        if "plan changed" not in str(exc).lower():
            raise CanaryFailure(
                f"the refusal does not say the plan changed: {exc}"
            ) from exc
        stale = (first.plan_digest or "")[:23]
        return f"stale digest {stale}… refused for plan {second.id}"
    raise CanaryFailure(
        "approval evidence bound to a superseded plan's digest AUTHORIZED a "
        "different plan"
    )


# ── runner ──────────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--expect-version",
        required=True,
        help=(
            "the version the artifact must report. Supplied by the caller so "
            "the canary compares the artifact against an EXTERNAL statement of "
            "what was built, rather than against itself."
        ),
    )
    args = parser.parse_args(argv)

    canaries: list[tuple[str, Callable[[], str]]] = [
        ("installed_not_source", canary_installed_not_source),
        ("version_agreement", lambda: canary_version_agreement(args.expect_version)),
        ("propose_emits_canonical", canary_propose_emits_canonical),
        ("exact_digest_approves", canary_exact_digest_approves),
        ("a4_bare_hex_still_binds", canary_a4_bare_hex_still_binds),
        (
            "encoding_fault_is_not_a_mutation",
            canary_encoding_fault_is_not_a_mutation,
        ),
        (
            "mutation_after_authorization_is_refused",
            canary_mutation_after_authorization_is_refused,
        ),
    ]

    print(f"artifact canaries — {DISTRIBUTION} {args.expect_version}")
    print(f"interpreter: {sys.executable}")
    failures: list[str] = []
    for name, canary in canaries:
        try:
            detail = canary()
        except Exception as exc:  # every failure is reported, none escapes
            failures.append(name)
            print(f"  FAIL  {name}")
            for line in traceback.format_exception_only(type(exc), exc):
                print(f"        {line.rstrip()}")
            if not isinstance(exc, CanaryFailure):
                print(f"        (raised {type(exc).__name__}, not a canary refusal)")
        else:
            print(f"  ok    {name}: {detail}")

    if failures:
        print(f"\n{len(failures)} canary/canaries failed: {', '.join(failures)}")
        return 1
    print(f"\nall {len(canaries)} canaries passed against the installed artifact")
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
