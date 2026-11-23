"""Builder of `contract/target_api_v2.json`: the v2 job-plan, lease and
observation vectors.

Run `python -m tests.unit.target_api_v2_vectors --write` to regenerate. v1 is NOT
touched: v2 is a delta that leaves the signed wire envelope unchanged. Every
expected value is produced by Control's own functions (`target_api_v2`,
`deploy_binding`), so the file and the code cannot drift apart.
"""

from __future__ import annotations

import base64
import copy
import json
import sys
from dataclasses import asdict, dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dotmac_deployment_control import attestation_pair as ap
from dotmac_deployment_control import target_api as api
from dotmac_deployment_control import target_api_v2 as v2
from dotmac_deployment_control.agent_observation import (
    KIND_OUTCOMES,
    AgentObservationEnvelopeV2,
    issue_agent_observation_envelope,
    verify_agent_observation_envelope,
)
from dotmac_deployment_control.deploy_binding import (
    PlanJob,
    PlanJobDefinition,
    PlanJobWindow,
    PlannedImage,
    PlanRole,
    build_deploy_binding,
)
from dotmac_deployment_control.deploy_unit import params_env_digest
from dotmac_deployment_control.digests import (
    AttestationDigestV1,
    AttestationKeyFingerprintV1,
    PublicKeyFingerprintV1,
    canonical_json,
)
from dotmac_deployment_control.execution_observation import (
    EXECUTION_OBSERVATION_PURPOSE,
    ExecutionObservationRefusedError,
    ExecutionObservationVerificationKey,
)
from dotmac_deployment_control.image_policy import PullAllowlist
from dotmac_deployment_control.reconcile_decision import decide_reconcile
from tests.unit import ed25519_reference as ed
from tests.unit import target_api_vectors as v1_builder

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "dotmac_deployment_control"
    / "contract"
    / "target_api_v2.json"
)

_REF = "dotmac-erp-v2/production/host-a"
_WORK_PATTERN = "^/var/lib/dotmac/erp-v2/job-work/import_execute/[A-Za-z0-9._-]+$"
_D1 = "sha256:" + "1" * 64
_T0 = datetime(2026, 12, 1, 10, 0, 0, tzinfo=UTC)
_JOB_PARAMS = {
    "ERP_ENROLMENT_ACTOR_ID": "11111111-2222-3333-4444-555555555555",
    "ERP_IMPORT_APPLY_OK": "1",
    "ERP_IMPORT_APPROVED": "1",
    "ERP_PAYROLL_NET_PAYABLE_ACCOUNT_REF": "acct.net-payable",
}
_JOB_ARGV = [
    "python",
    "-m",
    "erp_v2.importer",
    "execute",
    "--receipt",
    "/var/lib/dotmac/erp-v2/job-work/import_execute/receipt.json",
    "--manifest",
    "/var/lib/dotmac/erp-v2/job-work/import_execute/manifest.json",
    "--apply",
]


def _image(source: str) -> PlannedImage:
    return PlannedImage(
        service="dotmac-erp-v2",
        source=source,
        release_repository="registry.example.test/team/app",
        release_digest=_D1,
        planned_repository="127.0.0.1:5000/team/app",
        planned_digest=_D1,
    )


def _definition() -> PlanJobDefinition:
    return PlanJobDefinition(
        name="import_execute",
        role="import",
        command=("python", "-m", "erp_v2.importer", "execute"),
        materials=("LEGACY_DATABASE_URL", "MIGRATION_DATABASE_URL"),
        params=tuple(sorted(("import_apply_ok", "import_approved"))),
        args=(
            {
                "flag": "--receipt",
                "type": "path",
                "required": True,
                "pattern": _WORK_PATTERN,
                "choices": [],
                "max_length": 240,
            },
        ),
        run_limit_seconds=3000,
    )


def _job_render() -> bytes:
    return "".join(f"{k}={v}\n" for k, v in sorted(_JOB_PARAMS.items())).encode()


def _snapshot(binding: Any) -> dict[str, Any]:
    return {
        "plan_purpose": "foundation_execution",
        "target_ref": _REF,
        "product_code": "dotmac-erp-v2",
        "environment": "production",
        "deploy_binding": binding.payload(),
    }


def _serving() -> dict[str, Any]:
    binding = build_deploy_binding(
        deploy_unit_digest="sha256:" + "5" * 64,
        product_toml_sha256="sha256:" + "8" * 64,
        params_env_digest="sha256:" + "3" * 64,
        images=[_image("transfer")],
        lease_ttl_seconds=600,
        lease_max_seconds=3120,
        allowlist=PullAllowlist(),
        roles=[
            PlanRole("app", False),
            PlanRole("backup", False),
            PlanRole("migrate", True),
        ],
        primary_service="dotmac-erp-v2",
        secrets_namespace="erp",
        secrets_environment="prod",
        active_binding_names=["API_SECRET"],
        job_binding_names=[],
        jobs=[_definition()],
    )
    return _snapshot(binding)


def _job() -> dict[str, Any]:
    dispatched = PlanJob(
        name="import_execute",
        argv=tuple(_JOB_ARGV),
        role="import",
        single_use=True,
        materials=("LEGACY_DATABASE_URL", "MIGRATION_DATABASE_URL"),
        params=tuple(sorted(_JOB_PARAMS.items())),
        params_env_digest=params_env_digest(_job_render()),
        run_limit_seconds=3000,
        window=PlanJobWindow("window-1", "2026-12-31T00:00:00Z"),
    )
    binding = build_deploy_binding(
        deploy_unit_digest="sha256:" + "5" * 64,
        product_toml_sha256="sha256:" + "8" * 64,
        params_env_digest="sha256:" + "3" * 64,
        images=[_image("present")],
        lease_ttl_seconds=3120,
        lease_max_seconds=3120,
        allowlist=PullAllowlist(),
        primary_service="dotmac-erp-v2",
        secrets_namespace="erp",
        secrets_environment="prod",
        job_binding_names=["LEGACY_DATABASE_URL", "MIGRATION_DATABASE_URL"],
        jobs=[_definition()],
        dispatched_job=dispatched,
        job_lease_ceiling_seconds=3600,
    )
    return _snapshot(binding)


def _code(call: Any) -> str:
    try:
        call()
    except api.TargetApiError as exc:
        return exc.code
    raise AssertionError("expected a refusal")  # pragma: no cover


def _mutate(base: dict[str, Any], path: list[str], value: Any) -> dict[str, Any]:
    out = copy.deepcopy(base)
    node = out["deploy_binding"]
    for key in path[:-1]:
        node = node[key]
    node[path[-1]] = value
    return out


def _binding_vectors() -> dict[str, Any]:
    serving, job = _serving(), _job()
    v2.check_deploy_binding(serving["deploy_binding"], operation="deploy")
    v2.check_deploy_binding(job["deploy_binding"], operation="run_job")
    cases = [
        (
            "roles without naming: no namespace",
            _mutate(serving, ["secrets_namespace"], ""),
            "deploy",
        ),
        (
            "roles without naming: no environment",
            _mutate(serving, ["secrets_environment"], None),
            "deploy",
        ),
        (
            "a job role without naming",
            _mutate(job, ["secrets_environment"], None),
            "run_job",
        ),
        (
            "run_job without a dispatched job",
            _mutate(job, ["dispatched_job"], None),
            "run_job",
        ),
        ("a dispatched job on a deploy", job, "deploy"),
        (
            "a serving lease ttl over 900",
            _mutate(serving, ["lease_ttl_seconds"], 901),
            "deploy",
        ),
        (
            "a serving lease ttl under 120",
            _mutate(serving, ["lease_ttl_seconds"], 119),
            "deploy",
        ),
        (
            "a serving lease max over 10800",
            _mutate(serving, ["lease_max_seconds"], 10801),
            "deploy",
        ),
        (
            "a serving lease max under its ttl",
            _mutate(serving, ["lease_max_seconds"], 599),
            "deploy",
        ),
        (
            "a job lease that is not timeout + 120",
            _mutate(job, ["lease_ttl_seconds"], 900),
            "run_job",
        ),
        (
            "a job lease max that differs from its ttl",
            _mutate(job, ["lease_max_seconds"], 3600),
            "run_job",
        ),
        (
            "job params keyed by param name, not material",
            _mutate(job, ["dispatched_job", "params"], {"import_approved": "1"}),
            "run_job",
        ),
        (
            "job params with a non-string value",
            _mutate(job, ["dispatched_job", "params"], {"ERP_IMPORT_APPROVED": 1}),
            "run_job",
        ),
        (
            "a window without a role",
            _mutate(job, ["dispatched_job", "role"], None),
            "run_job",
        ),
        ("an empty argv", _mutate(job, ["dispatched_job", "argv"], []), "run_job"),
        (
            "an unsorted materials list",
            _mutate(job, ["dispatched_job", "materials"], ["B", "A"]),
            "run_job",
        ),
        (
            "a job plan that transfers an image",
            _mutate(job, ["images", 0, "source"], "transfer")
            if False
            else _with_source(job, "transfer"),
            "run_job",
        ),
        (
            "a job plan that mints a serving role",
            _mutate(job, ["roles"], [{"role": "app", "single_use": False}]),
            "run_job",
        ),
        (
            "a dispatched job with a stray key",
            _mutate(job, ["dispatched_job", "extra"], 1),
            "run_job",
        ),
    ]
    refused = []
    for name, snapshot, operation in cases:
        code = _code(
            lambda s=snapshot, o=operation: v2.check_deploy_binding(
                s["deploy_binding"], operation=o
            )
        )
        refused.append(
            {"name": name, "operation": operation, "snapshot": snapshot, "code": code}
        )
    return {
        "rule": (
            "plan_snapshot.deploy_binding gains `jobs` (definitions only; nothing "
            "runs from them), `dispatched_job` (null unless operation is run_job), "
            "`job_binding_names`, `lease_max_seconds`, and the OpenBao naming "
            "(`secrets_namespace`, `secrets_environment`) that roles require. "
            "`dispatched_job.params` is keyed by MATERIAL name and lists every "
            "scoped material of the job with defaults filled; params_env_digest is "
            "the sha256 of exactly its sorted `K=V\\n` lines. A run_job plan has "
            "roles [], image source `present` and lease ttl = max = timeout + 120."
        ),
        "serving": {"operation": "deploy", "snapshot": serving},
        "job": {"operation": "run_job", "snapshot": job},
        "job_params_render": {
            "params": dict(_JOB_PARAMS),
            "render_utf8": _job_render().decode("ascii"),
            "params_env_digest": params_env_digest(_job_render()),
        },
        "refused": refused,
    }


def _with_source(base: dict[str, Any], source: str) -> dict[str, Any]:
    out = copy.deepcopy(base)
    out["deploy_binding"]["images"][0]["source"] = source
    return out


def _lease_body_vectors() -> dict[str, Any]:
    ok = {
        "lease/acquire": {
            "request": {"dispatch_run": "run-0001", "ttl_seconds": 600},
            "response": {"lease_id": "lease-0001", "ttl_seconds": 600},
        },
        "lease/covers": {
            "request": {"lease_id": "lease-0001", "dispatch_run": "run-0001"},
            "response": {"covers": True},
        },
        "lease/renew": {
            "request": {"lease_id": "lease-0001", "dispatch_run": "run-0001"},
            "response": {"lease_id": "lease-0001", "ttl_seconds": 600},
        },
        "lease/release": {
            "request": {"lease_id": "lease-0001", "host_mutated": False},
            "response": {"released": True, "replay": False},
        },
        "lease/standing": {
            "request": {},
            "response": {"standing": "held", "dispatch_run": None},
        },
    }
    refused = [
        ("lease/renew", "request", {"lease_id": "lease-0001"}),
        ("lease/renew", "request", {"lease_id": "l", "dispatch_run": "r", "x": 1}),
        ("lease/acquire", "request", {"dispatch_run": "r", "ttl_seconds": True}),
        ("lease/acquire", "request", {"dispatch_run": "r", "ttl_seconds": "600"}),
        ("lease/release", "request", {"lease_id": "l", "host_mutated": "no"}),
        ("lease/release", "response", {"released": True}),
        ("lease/covers", "response", {"covers": 1}),
        ("lease/standing", "response", {"standing": "maybe", "dispatch_run": None}),
        (
            "lease/standing",
            "response",
            {"standing": "expired_unreleased", "dispatch_run": None},
        ),
        ("lease/standing", "response", {"standing": "held", "dispatch_run": "run-1"}),
        ("lease/standing", "response", {"standing": "free"}),
        ("lease/renew", "response", {"lease_id": "l", "ttl_seconds": 0}),
        ("lease/lock", "request", {}),
    ]
    out_ok = []
    for route, bodies in ok.items():
        for direction, body in bodies.items():
            v2.check_lease_body(route, direction, body)
            out_ok.append({"route": route, "direction": direction, "body": body})
    return {
        "ok": out_ok,
        "refused": [
            {
                "route": route,
                "direction": direction,
                "body": body,
                "code": _code(
                    lambda r=route, d=direction, b=body: v2.check_lease_body(r, d, b)
                ),
            }
            for route, direction, body in refused
        ],
    }


def _step(ledger: v2.LeaseLedger, at: int, call: str, **args: Any) -> dict[str, Any]:
    now = _T0 + timedelta(seconds=at)
    entry: dict[str, Any] = {"at": at, "call": call, "args": dict(args)}
    try:
        if call == "acquire":
            body = ledger.acquire(
                now=now,
                dispatch_run=args["dispatch_run"],
                ttl_seconds=args["ttl_seconds"],
                lease_max_seconds=args["lease_max_seconds"],
                marker_present=args["marker_present"],
            )
        elif call == "covers":
            body = ledger.covers(
                now=now, lease_id=args["lease_id"], dispatch_run=args["dispatch_run"]
            )
        elif call == "renew":
            body = ledger.renew(
                now=now, lease_id=args["lease_id"], dispatch_run=args["dispatch_run"]
            )
        elif call == "release":
            body = ledger.release(
                lease_id=args["lease_id"], host_mutated=args["host_mutated"], now=now
            )
        else:
            body = ledger.standing(now=now)
    except api.TargetApiError as exc:
        entry.update(status=v2.LEASE_ERRORS[exc.code], error=exc.code)
    else:
        entry.update(status=200, body=body)
    return entry


def _scenarios() -> list[dict[str, Any]]:
    acquire = {
        "dispatch_run": "run-1",
        "ttl_seconds": 600,
        "lease_max_seconds": 1500,
        "marker_present": True,
    }
    bare = {**acquire, "marker_present": False}
    held = {"lease_id": "lease-0001", "dispatch_run": "run-1"}
    plans: list[tuple[str, list[tuple[int, str, dict[str, Any]]]]] = [
        (
            "renew in grants; the last is capped, then the lease expires",
            [
                (0, "acquire", acquire),
                (400, "renew", held),
                (900, "renew", held),
                (1400, "renew", held),
                (1450, "renew", held),
                (1500, "renew", held),
                (1500, "standing", {}),
            ],
        ),
        (
            "the last grant is capped to what remains of the maximum",
            [
                (
                    0,
                    "acquire",
                    {**acquire, "ttl_seconds": 600, "lease_max_seconds": 600},
                ),
                (599, "renew", held),
            ],
        ),
        (
            "a never-leased host acquires without a marker",
            [(0, "standing", {}), (1, "acquire", bare)],
        ),
        (
            "after an expiry the acquire needs the marker (a signed 409 without it)",
            [
                (0, "acquire", acquire),
                (700, "standing", {}),
                (710, "acquire", {**bare, "dispatch_run": "run-2"}),
                (720, "acquire", {**acquire, "dispatch_run": "run-2"}),
            ],
        ),
        (
            "after a clean release the next acquire needs no marker",
            [
                (0, "acquire", acquire),
                (50, "release", {"lease_id": "lease-0001", "host_mutated": False}),
                (60, "acquire", {**bare, "dispatch_run": "run-2"}),
            ],
        ),
        (
            "a replayed acquire by the same run returns the REMAINING ttl",
            [
                (0, "acquire", acquire),
                (10, "acquire", acquire),
                (20, "covers", held),
            ],
        ),
        (
            "another run cannot acquire a held host",
            [
                (0, "acquire", acquire),
                (100, "acquire", {**acquire, "dispatch_run": "run-2"}),
            ],
        ),
        (
            "a double release is a signed 200 replay",
            [
                (0, "acquire", acquire),
                (50, "release", {"lease_id": "lease-0001", "host_mutated": True}),
                (60, "release", {"lease_id": "lease-0001", "host_mutated": True}),
                (70, "covers", held),
                (80, "standing", {}),
            ],
        ),
        (
            "renew by another run is lease_not_held",
            [
                (0, "acquire", acquire),
                (10, "renew", {"lease_id": "lease-0001", "dispatch_run": "run-2"}),
                (20, "renew", {"lease_id": "lease-9999", "dispatch_run": "run-1"}),
            ],
        ),
        (
            "an expired lease cannot be renewed and is expired_unreleased",
            [
                (0, "acquire", acquire),
                (599, "standing", {}),
                (700, "standing", {}),
                (700, "covers", held),
                (700, "renew", held),
            ],
        ),
    ]
    out = []
    for name, steps in plans:
        ledger = v2.LeaseLedger()
        out.append(
            {
                "name": name,
                "steps": [_step(ledger, at, call, **args) for at, call, args in steps],
            }
        )
    return out


def _observation_vectors() -> dict[str, Any]:
    ok = [
        ("deploy", "deploy"),
        ("deploy", "rollback"),
        ("reconcile", "deploy"),
        ("reconcile", "run_job"),
        ("job", "run_job"),
    ]
    refused = [
        ("job", "deploy"),
        ("job", "rollback"),
        ("deploy", "run_job"),
        ("deploy", "recover"),
        ("other", "deploy"),
        ("job", None),
    ]
    for kind, operation in ok:
        v2.check_observation_kind(kind, operation)
    return {
        "kinds": list(v2.OBSERVATION_KINDS),
        "rule": "kind `job` is the observation of a run_job plan, and only of one",
        "ok": [{"kind": k, "operation": o} for k, o in ok],
        "refused": [
            {
                "kind": k,
                "operation": o,
                "code": _code(lambda k=k, o=o: v2.check_observation_kind(k, o)),
            }
            for k, o in refused
        ],
    }


def _renew_grant_vectors() -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for ttl, maximum, held in (
        (600, 3120, 0),
        (600, 3120, 2700),
        (600, 3120, 2520),
        (600, 3120, 3000),
        (600, 3120, 3119),
        (600, 3120, 3120),
        (600, 3120, 4000),
    ):
        try:
            out.append(
                {
                    "ttl_seconds": ttl,
                    "lease_max_seconds": maximum,
                    "held_seconds": held,
                    "grant": v2.renew_grant(
                        ttl_seconds=ttl, lease_max_seconds=maximum, held_seconds=held
                    ),
                }
            )
        except api.TargetApiError as exc:
            out.append(
                {
                    "ttl_seconds": ttl,
                    "lease_max_seconds": maximum,
                    "held_seconds": held,
                    "code": exc.code,
                }
            )
    return out


# ── The agent observation envelope (N-1) ────────────────────────────────────

_OBS_SEED = v1_builder._REQUEST_SEED
_OBS_KEY_ID = "cred-0001"
_DISPATCH = "00000000-0000-4000-8000-000000000001"


class _EdVerifier:
    """The injected primitive: the vectors verify with the public reference."""

    def verify_execution_observation(
        self,
        *,
        key_id: str,
        algorithm: str,
        purpose: str,
        public_key_b64: str,
        public_key_fingerprint: str,
        canonical_bytes: bytes,
        signature: str,
    ) -> bool:
        return ed.verify(
            api.b64u_decode(public_key_b64),
            canonical_bytes,
            api.b64u_decode(signature),
        )


def _obs_key() -> ExecutionObservationVerificationKey:
    public = api.b64u_encode(ed.public_key(_OBS_SEED))
    return ExecutionObservationVerificationKey(
        key_id=_OBS_KEY_ID,
        algorithm="ed25519",
        public_key_b64=public,
        public_key_fingerprint=PublicKeyFingerprintV1.from_public_key_b64(
            public
        ).canonical,
        purpose=EXECUTION_OBSERVATION_PURPOSE,
    )


def _issue(**fields: Any) -> AgentObservationEnvelopeV2:
    base = {
        "kind": "deploy",
        "dispatch_id": _DISPATCH,
        "target_ref": _REF,
        "key_id": _OBS_KEY_ID,
        "outcome": "succeeded",
        "reason": "",
        "details": {},
        "observed_at": "2026-12-01T10:05:00Z",
    }
    base.update(fields)
    return issue_agent_observation_envelope(
        base, sign=lambda raw: api.b64u_encode(ed.sign(_OBS_SEED, raw))
    )


_D_OLD = "sha256:" + "1" * 64
_D_NEW = "sha256:" + "2" * 64
_D_COMMITTED = "sha256:" + "3" * 64
_EXPIRED_DISPATCH = "00000000-0000-4000-8000-0000000000e1"


def _reconcile_details(
    configured: list[str], running: list[tuple[str, str]]
) -> dict[str, Any]:
    return {
        "expired_dispatch_id": _EXPIRED_DISPATCH,
        "configured": configured,
        "containers": [
            {
                "name": name,
                "image_ref": f"127.0.0.1:5000/team/app@{digest}",
                "image_id": digest,
                "repo_digests": [f"127.0.0.1:5000/team/app@{digest}"],
            }
            for name, digest in running
        ],
    }


def _decision_vectors() -> dict[str, Any]:
    """Control decides; the agent only reports facts."""
    expired, committed = [_D_OLD], [_D_COMMITTED]
    cases = [
        (
            "every configured container runs the expired plan's digest",
            ["app", "worker"],
            [("app", _D_OLD), ("worker", _D_OLD)],
            False,
        ),
        (
            "the expired plan's digest wins even if the dispatch was consumed",
            ["app"],
            [("app", _D_OLD)],
            True,
        ),
        (
            "all run the last committed digest and the dispatch was never consumed",
            ["app", "worker"],
            [("app", _D_COMMITTED), ("worker", _D_COMMITTED)],
            False,
        ),
        (
            "all run the last committed digest but the dispatch WAS consumed",
            ["app"],
            [("app", _D_COMMITTED)],
            True,
        ),
        (
            "one container runs a digest from neither",
            ["app", "worker"],
            [("app", _D_OLD), ("worker", _D_NEW)],
            False,
        ),
        (
            "a mix of expired and committed digests",
            ["app", "worker"],
            [("app", _D_OLD), ("worker", _D_COMMITTED)],
            False,
        ),
        (
            "a configured container the agent did not observe",
            ["app", "worker"],
            [("app", _D_OLD)],
            False,
        ),
        ("nothing is configured", [], [], False),
    ]
    out = []
    for name, configured, running, consumed in cases:
        details = _reconcile_details(configured, running)
        out.append(
            {
                "name": name,
                "details": details,
                "expired_dispatch_id": _EXPIRED_DISPATCH,
                "expired_plan_digests": expired,
                "last_committed_digests": committed,
                "expired_dispatch_consumed": consumed,
                "decision": decide_reconcile(
                    details,
                    expired_dispatch_id=_EXPIRED_DISPATCH,
                    expired_plan_digests=expired,
                    last_committed_digests=committed,
                    expired_dispatch_consumed=consumed,
                ),
            }
        )
    wrong = _reconcile_details(["app"], [("app", _D_OLD)])
    out.append(
        {
            "name": "details that name another dispatch",
            "details": wrong,
            "expired_dispatch_id": "another-dispatch",
            "expired_plan_digests": expired,
            "last_committed_digests": committed,
            "expired_dispatch_consumed": False,
            "decision": decide_reconcile(
                wrong,
                expired_dispatch_id="another-dispatch",
                expired_plan_digests=expired,
                last_committed_digests=committed,
                expired_dispatch_consumed=False,
            ),
        }
    )
    return {
        "rule": (
            "The agent reports facts: outcome `reconciled` (the host was observed "
            "completely) or `failed` (it could not be); it never sends `not_needed`. "
            "Control DECIDES from `details` ({expired_dispatch_id, configured[], "
            "containers[{name, image_ref, image_id, repo_digests}]}): every configured "
            "container on a digest of the expired plan -> marker `reconciled`; all on "
            "the last committed digest and the expired dispatch never consumed -> "
            "marker `not_needed`; anything else -> no marker (attended "
            "restore-and-fix-forward). A marker is asked for only when the host's "
            "latest lease row is expired_unreleased."
        ),
        "cases": out,
    }


def _agent_observation_vectors() -> dict[str, Any]:
    ok_cases = [
        {},
        {
            "kind": "reconcile",
            "outcome": "reconciled",
            "reason": "observed",
            "details": _reconcile_details(["app"], [("app", _D_OLD)]),
        },
        {"kind": "reconcile", "outcome": "failed", "reason": "docker unreachable"},
        {
            "kind": "job",
            "outcome": "failed",
            "reason": "exit 1",
            "details": {"exit_code": 1, "accessor_prefix": "abcd1234"},
        },
    ]
    ok = []
    for fields in ok_cases:
        envelope = _issue(**fields)
        wire = canonical_json(envelope.as_mapping())
        parsed = AgentObservationEnvelopeV2.parse_bytes(wire)
        verify_agent_observation_envelope(
            parsed, verifier=_EdVerifier(), verification_key=_obs_key()
        )
        ok.append(
            {
                "statement": envelope.statement.as_mapping(),
                "report_id": envelope.statement.report_id,
                "signed_bytes_hex": envelope.statement.canonical_bytes.hex(),
                "signature_b64u": envelope.signature,
                "wire_utf8": wire.decode("ascii"),
            }
        )
    good = _issue()
    mapping = good.as_mapping()

    def with_statement(**changes: Any) -> bytes:
        doc = copy.deepcopy(mapping)
        doc["statement"].update(changes)
        return json.dumps(doc, sort_keys=True, separators=(",", ":")).encode()

    bodies = {
        "duplicate key": b'{"statement":{},"signature":"x","signature":"y"}',
        "not json": b"not json",
        "wrong schema": with_statement(schema="dotmac.agent-observation/1"),
        "unknown kind": with_statement(kind="upgrade"),
        "outcome not for the kind": with_statement(kind="job", outcome="reconciled"),
        "a float in details": with_statement(details={"x": 1.5}),
        "an extra statement key": with_statement(extra=1),
        "details too deep": with_statement(
            details={"a": {"b": {"c": {"d": {"e": 1}}}}}
        ),
        "bad observed_at": with_statement(observed_at="2026-12-01 10:05:00"),
        "empty dispatch id": with_statement(dispatch_id=""),
        "missing signature": json.dumps({"statement": mapping["statement"]}).encode(),
        "oversize": b"{" + b" " * 70000 + b"}",
    }
    refused_parse = []
    for name, body in bodies.items():
        try:
            AgentObservationEnvelopeV2.parse_bytes(body)
        except ExecutionObservationRefusedError as exc:
            refused_parse.append(
                {
                    "name": name,
                    "body_hex": body.hex() if len(body) < 4096 else "",
                    "code": exc.code.value,
                }
            )
        else:  # pragma: no cover
            raise AssertionError(name)
    tampered = copy.deepcopy(mapping)
    tampered["statement"]["outcome"] = "failed"
    wrong_key = _issue(key_id="cred-9999").as_mapping()
    refused_verify = []
    for name, doc in (
        ("a statement changed after signing", tampered),
        ("a different key id", wrong_key),
    ):
        try:
            verify_agent_observation_envelope(
                doc, verifier=_EdVerifier(), verification_key=_obs_key()
            )
        except ExecutionObservationRefusedError as exc:
            refused_verify.append(
                {
                    "name": name,
                    "wire_utf8": json.dumps(doc, sort_keys=True, separators=(",", ":")),
                    "code": exc.code.value,
                }
            )
        else:  # pragma: no cover
            raise AssertionError(name)
    rules = []
    for case, kind, op in (
        ("a deploy report of a deploy plan", "deploy", "deploy"),
        ("a deploy report of a rollback plan", "deploy", "rollback"),
        ("a job report of a run_job plan", "job", "run_job"),
        ("a reconcile of a deploy plan", "reconcile", "deploy"),
        ("a reconcile of a run_job plan", "reconcile", "run_job"),
        ("a job report of a deploy plan", "job", "deploy"),
        ("a deploy report of a run_job plan", "deploy", "run_job"),
        ("a reconcile of a recover plan", "reconcile", "recover"),
    ):
        try:
            v2.check_observation_kind(kind, op)
            disposition = "accepted"
        except api.TargetApiError:
            disposition = "operation_mismatch"
        rules.append(
            {
                "case": case,
                "kind": kind,
                "plan_operation": op,
                "disposition": disposition,
            }
        )
    rules += [
        {
            "case": "the statement names another target than the credential's",
            "disposition": "target_mismatch",
        },
        {
            "case": "the dispatch id is not a dispatch of this target",
            "disposition": "unbound_report",
        },
        {"case": "an unknown key id", "disposition": "unknown_key"},
        {"case": "a bad signature", "disposition": "bad_signature"},
        {"case": "the same bytes again", "disposition": "idempotent_replay"},
        {"case": "the same report id with different bytes", "disposition": "conflict"},
        {"case": "an unparseable body", "disposition": "malformed"},
    ]
    return {
        "rule": (
            "One ingestion path, owned by Control: `record_observation` parses the "
            "envelope, selects the ENROLLED credential by statement.key_id, verifies "
            "the Ed25519 signature over the statement's canonical JSON bytes under "
            "that credential's key, and requires statement.target_ref to equal the "
            "credential's target. The statement is {schema, kind, dispatch_id, "
            "target_ref, key_id, outcome, reason, details, observed_at}; the report "
            "id is `agent:<kind>:<dispatch_id>` (a reconcile appends "
            "`:<observed_at>` so a "
            "failed one can be retried). Kind deploy|reconcile|job must agree "
            "with the dispatch's plan operation (job <=> run_job; deploy <=> "
            "deploy/rollback; reconcile settles an expired lease of any). An accepted "
            "observation changes no desired or observed state: it is attributable "
            "evidence."
        ),
        "schema": "dotmac.agent-observation/2",
        "kind_outcomes": {k: list(v) for k, v in KIND_OUTCOMES.items()},
        "limits": {
            "max_envelope_bytes": 65536,
            "max_details_bytes": 16384,
            "max_details_depth": 4,
        },
        "key": {
            "key_id": _OBS_KEY_ID,
            "seed_b64u": api.b64u_encode(_OBS_SEED),
            "public_b64u": api.b64u_encode(ed.public_key(_OBS_SEED)),
            "algorithm": "ed25519",
            "purpose": EXECUTION_OBSERVATION_PURPOSE,
        },
        "reconcile_decisions": _decision_vectors(),
        "ok": ok,
        "refused_parse": refused_parse,
        "refused_verify": refused_verify,
        "ingestion_rules": rules,
    }


def _domain_separation_vectors() -> dict[str, Any]:
    message = api.request_message(
        method="POST",
        path=api.target_path(_REF, "observations"),
        body=b"{}",
        credential_id=_OBS_KEY_ID,
        target_ref=_REF,
        issued_at="2026-11-22T10:00:00Z",
        nonce=v1_builder._nonce(1),
    )
    envelope = _issue()
    statement_bytes = envelope.statement.canonical_bytes
    wire = canonical_json(envelope.as_mapping())
    public = ed.public_key(_OBS_SEED)
    request_sig = ed.sign(_OBS_SEED, message)
    statement_sig = ed.sign(_OBS_SEED, statement_bytes)
    return {
        "rule": (
            "The PoP key signs both a target request and an agent observation. The "
            "byte domains are disjoint: a request message is 8 LF-joined lines whose "
            "first is `dotmac.target_request.v1`; an observation's signed bytes are "
            "canonical JSON containing the schema `dotmac.agent-observation/2` and "
            "begin with `{`. Neither parses as the other, and a signature over one "
            "never verifies as a signature over the other."
        ),
        "request_message_utf8": message.decode("utf-8"),
        "observation_signed_bytes_utf8": statement_bytes.decode("ascii"),
        "observation_wire_utf8": wire.decode("ascii"),
        "request_parses_as_request": v2.parse_request_message(message),
        "request_as_observation_code": _code(lambda: _obs_parse(message)),
        "observation_as_request_code": _code(
            lambda: v2.parse_request_message(statement_bytes)
        ),
        "wire_as_request_code": _code(lambda: v2.parse_request_message(wire)),
        "request_signature_verifies_over_request": ed.verify(
            public, message, request_sig
        ),
        "request_signature_verifies_over_observation": ed.verify(
            public, statement_bytes, request_sig
        ),
        "observation_signature_verifies_over_observation": ed.verify(
            public, statement_bytes, statement_sig
        ),
        "observation_signature_verifies_over_request": ed.verify(
            public, message, statement_sig
        ),
    }


def _obs_parse(raw: bytes) -> None:
    try:
        AgentObservationEnvelopeV2.parse_bytes(raw)
    except ExecutionObservationRefusedError as exc:
        raise api.TargetApiError(str(exc), exc.code.value) from None


# ── The attestation pair (Ruling 1) ─────────────────────────────────────────

_CAND_SEED = bytes(range(64, 96))
_HOST_SEED = bytes(range(96, 128))
_ATT_NOW = datetime(2026, 12, 1, 10, 0, 0, tzinfo=UTC)
_ATT_HOST = "host-a"
_ATT_PACKAGE = "dotmac-deployment-foundation"
_ATT_DISPATCH = "00000000-0000-4000-8000-0000000000aa"


@dataclass(frozen=True)
class _Root:
    custody_domain: str
    subject: str
    issuer: str
    key_id: str
    purpose: str
    root_version: str
    not_before: datetime
    not_after: datetime
    algorithm: str
    public_key_base64: str
    public_key_fingerprint: str
    standing: str = "active"
    revoked: bool = False


@dataclass(frozen=True)
class _Ctx:
    """Duck-typed `HostAdmissionVerificationContextV1`: the attributes read."""

    candidate_root: _Root
    installed_root: _Root
    candidate_audience: str
    installed_audience: str
    expected_foundation_package: str
    host_id: str
    dispatch_id: str
    context_digest: str


class _AttVerifier:
    def verify(
        self, *, public_key: bytes, algorithm: str, message: bytes, signature: str
    ) -> bool:
        return ed.verify(
            public_key, message, base64.b64decode(signature, validate=True)
        )


def _std(raw: bytes) -> str:
    return base64.b64encode(raw).decode("ascii")


def _stamp(moment: datetime) -> str:
    return moment.strftime("%Y-%m-%dT%H:%M:%SZ")


def _root(role: str, seed: bytes) -> _Root:
    public = _std(ed.public_key(seed))
    return _Root(
        custody_domain="candidate_release_signer"
        if role == "candidate"
        else "host_attester",
        subject="release-signer" if role == "candidate" else _ATT_HOST,
        issuer=f"{role}-issuer",
        key_id=f"key-{role}",
        purpose=ap.CANDIDATE_PURPOSE if role == "candidate" else ap.INSTALLED_PURPOSE,
        root_version="1",
        not_before=datetime(2026, 11, 1, tzinfo=UTC),
        not_after=datetime(2027, 11, 1, tzinfo=UTC),
        algorithm="ed25519",
        public_key_base64=public,
        public_key_fingerprint=AttestationKeyFingerprintV1.from_standard_base64(
            public
        ).canonical,
    )


def _root_doc(root: _Root) -> dict[str, Any]:
    return {
        "custody_domain": root.custody_domain,
        "subject": root.subject,
        "issuer": root.issuer,
        "key_id": root.key_id,
        "purpose": root.purpose,
        "root_version": root.root_version,
        "not_before": _stamp(root.not_before),
        "not_after": _stamp(root.not_after),
        "algorithm": root.algorithm,
        "public_key_base64": root.public_key_base64,
        "public_key_fingerprint": root.public_key_fingerprint,
        "standing": root.standing,
        "revoked": root.revoked,
    }


def _envelope(
    root: _Root, seed: bytes, aud: str, subject: dict[str, Any], **over: Any
) -> dict[str, Any]:
    doc: dict[str, Any] = {
        "schema": ap.ATTESTATION_SCHEMA,
        "purpose": root.purpose,
        "issuer": root.issuer,
        "key_id": root.key_id,
        "algorithm": root.algorithm,
        "public_key_fingerprint": root.public_key_fingerprint,
        "custody_domain": root.custody_domain,
        "trust_root_version": root.root_version,
        "issued_at": "2026-12-01T09:00:00Z",
        "expires_at": "2026-12-01T11:00:00Z",
        "audience": aud,
        "observation_id": _ATT_DISPATCH,
        "subject": subject,
    }
    doc.update(over)
    doc["signature"] = _std(
        ed.sign(
            seed, canonical_json({k: v for k, v in doc.items() if k != "signature"})
        )
    )
    return doc


def _candidate_subject(**over: Any) -> dict[str, Any]:
    subject = {
        "package": _ATT_PACKAGE,
        "version": "0.4.0a1",
        "wheel_sha256": "sha256:" + "c" * 64,
        "source_revision": "a" * 40,
        "repository": "example/repository",
        "run_id": "100",
        "artifact_id": "200",
    }
    subject.update(over)
    return subject


def _installed_subject(candidate: dict[str, Any], **over: Any) -> dict[str, Any]:
    subject = {
        "host_identity": _ATT_HOST,
        "package": candidate["package"],
        "version": candidate["version"],
        "wheel_sha256": candidate["wheel_sha256"],
        "candidate_subject_digest": AttestationDigestV1.over_document(
            candidate
        ).canonical,
    }
    subject.update(over)
    return subject


def _attestation_pair_vectors() -> dict[str, Any]:
    cand_root, host_root = (
        _root("candidate", _CAND_SEED),
        _root("installed", _HOST_SEED),
    )

    def build(
        *,
        cand_subject: dict[str, Any] | None = None,
        inst_subject: dict[str, Any] | None = None,
        cand_over: dict[str, Any] | None = None,
        inst_over: dict[str, Any] | None = None,
        cand_root_: _Root = cand_root,
        host_root_: _Root = host_root,
        ctx: dict[str, Any] | None = None,
        now: datetime = _ATT_NOW,
        candidate_absent: bool = False,
        tamper: bool = False,
    ) -> dict[str, Any]:
        cs = cand_subject if cand_subject is not None else _candidate_subject()
        candidate = _envelope(
            cand_root, _CAND_SEED, "dotmac.foundation", cs, **(cand_over or {})
        )
        is_ = inst_subject if inst_subject is not None else _installed_subject(cs)
        installed = _envelope(
            host_root, _HOST_SEED, _ATT_HOST, is_, **(inst_over or {})
        )
        if tamper:
            candidate["subject"] = {**candidate["subject"], "version": "9.9.9"}
        context = {
            "candidate_root": cand_root_,
            "installed_root": host_root_,
            "candidate_audience": "dotmac.foundation",
            "installed_audience": _ATT_HOST,
            "expected_foundation_package": _ATT_PACKAGE,
            "host_id": _ATT_HOST,
            "dispatch_id": _ATT_DISPATCH,
            "context_digest": "sha256:" + "d" * 64,
        }
        context.update(ctx or {})
        return {
            "resolution": {
                "candidate_root": _root_doc(context["candidate_root"]),
                "installed_root": _root_doc(context["installed_root"]),
                **{
                    k: v
                    for k, v in context.items()
                    if k not in {"candidate_root", "installed_root"}
                },
            },
            "presented": {
                "candidate": None if candidate_absent else candidate,
                "installed": installed,
            },
            "now": _stamp(now),
            "_ctx": _Ctx(**context),
            "_now": now,
        }

    def run(case: dict[str, Any]) -> dict[str, Any]:
        presented = ap.PresentedAttestationPairV1(
            candidate=case["presented"]["candidate"],
            installed=case["presented"]["installed"],
        )
        try:
            evidence = ap.verify_attestation_pair(
                case["_ctx"], presented, verifier=_AttVerifier(), now=case["_now"]
            )
        except ap.AttestationPairRefusedError as exc:
            return {"code": exc.code}
        return {"evidence": asdict(evidence)}

    good = build()
    ok = {k: v for k, v in good.items() if not k.startswith("_")}
    ok["expected"] = run(good)
    assert "evidence" in ok["expected"], ok["expected"]
    cs = _candidate_subject()
    mutations: list[tuple[str, dict[str, Any]]] = [
        ("the candidate is absent", {"candidate_absent": True}),
        (
            "a widened candidate subject",
            {"cand_subject": _candidate_subject(extra="x")},
        ),
        (
            "the two roles share a custody domain (roots not distinct)",
            {
                "host_root_": _Root(
                    **{**host_root.__dict__, "custody_domain": cand_root.custody_domain}
                )
            },
        ),
        (
            "one key signed both",
            {"inst_over": {"public_key_fingerprint": cand_root.public_key_fingerprint}},
        ),
        (
            "an unknown key",
            {"inst_over": {"public_key_fingerprint": "sha256:" + "9" * 64}},
        ),
        (
            "a revoked root",
            {"host_root_": _Root(**{**host_root.__dict__, "revoked": True})},
        ),
        ("a root not yet valid", {"now": datetime(2026, 10, 1, tzinfo=UTC)}),
        (
            "an attestation of the wrong purpose",
            {"inst_over": {"purpose": ap.CANDIDATE_PURPOSE}},
        ),
        (
            "an attestation whose issuer differs from the root",
            {"cand_over": {"issuer": "someone-else"}},
        ),
        ("a candidate audience that differs", {"cand_over": {"audience": "elsewhere"}}),
        (
            "an installed audience that is not the host",
            {"ctx": {"installed_audience": "host-b"}},
        ),
        ("a stale attestation", {"now": datetime(2026, 12, 1, 12, 0, 0, tzinfo=UTC)}),
        (
            "an attestation issued in the future",
            {
                "cand_over": {
                    "issued_at": "2026-12-01T10:30:00Z",
                    "expires_at": "2026-12-01T11:30:00Z",
                }
            },
        ),
        ("a tampered subject", {"tamper": True}),
        (
            "an installed observation id that is not the dispatch",
            {"ctx": {"dispatch_id": "00000000-0000-4000-8000-0000000000bb"}},
        ),
        (
            "a different expected package",
            {"ctx": {"expected_foundation_package": "another-package"}},
        ),
        (
            "an installed subject that does not bind the candidate",
            {
                "inst_subject": _installed_subject(
                    cs, candidate_subject_digest="sha256:" + "e" * 64
                )
            },
        ),
        (
            "an installed subject for another host",
            {"inst_subject": _installed_subject(cs, host_identity="host-b")},
        ),
        (
            "the host attests different bytes",
            {"inst_subject": _installed_subject(cs, wheel_sha256="sha256:" + "f" * 64)},
        ),
    ]
    refused = []
    for name, kwargs in mutations:
        case = build(**kwargs)
        result = run(case)
        assert "code" in result, name
        refused.append(
            {
                "name": name,
                **{k: v for k, v in case.items() if not k.startswith("_")},
                "expected": result,
            }
        )
    return {
        "rule": (
            "verify_attestation_pair(resolution, presented, verifier, now): Control's "
            "resolved roots and context verify the pair a target presented, in "
            "process, with an injected Ed25519 verifier and no Foundation dependency. "
            "The format is Foundation's TrustedHostAttestation.v2: the signature is "
            "standard base64 over the canonical JSON (sorted keys, no spaces) of the "
            "envelope without its `signature`; the root fingerprint is sha256 over the "
            "raw public key; the installed subject binds the candidate by "
            "sha256(canonical JSON of the candidate subject). Refusal codes are "
            "Foundation's. These vectors are generated from the format read in "
            "Foundation's trusted_host_source.py and are to be confirmed by "
            "Foundation's own published vectors."
        ),
        "codes": sorted({r["expected"]["code"] for r in refused}),
        "keys": {
            "candidate_seed_b64u": api.b64u_encode(_CAND_SEED),
            "installed_seed_b64u": api.b64u_encode(_HOST_SEED),
        },
        "ok": ok,
        "refused": refused,
    }


def build_vectors() -> dict[str, Any]:
    return {
        "contract": v2.CONTRACT_NAME_V2,
        "file": "target_api_v2.json",
        "extends": {
            "contract": v2.EXTENDS["contract"],
            "file": v2.EXTENDS["file"],
            "unchanged": list(v2.EXTENDS["unchanged"]),
        },
        "note": (
            "A delta over v1: the signed wire envelope is unchanged. The deploy "
            "agent and CP vendor this file next to v1 and pin its sha256, which the "
            "CHANGELOG records. Every expected value comes from Control's functions."
        ),
        "constants": {
            "endpoints_added": [list(item) for item in v2.ENDPOINTS_ADDED],
            "retry_idempotency_added": dict(v2.RETRY_IDEMPOTENCY_ADDED),
            "lease_errors": dict(v2.LEASE_ERRORS),
            "standing_values": list(v2.STANDING_VALUES),
            "observation_kinds": list(v2.OBSERVATION_KINDS),
            "lease_ttl_range": [v2.MIN_LEASE_TTL, v2.MAX_LEASE_TTL],
            "lease_max_limit": v2.MAX_LEASE_MAX,
            "lease_margin_seconds": v2.LEASE_MARGIN,
            "lease_bodies": {
                r: {d: dict(spec) for d, spec in b.items()}
                for r, b in v2.LEASE_BODIES.items()
            },
        },
        "lease_body_vectors": _lease_body_vectors(),
        "renew_grant_vectors": _renew_grant_vectors(),
        "lease_scenarios": _scenarios(),
        "observation_vectors": _observation_vectors(),
        "binding": _binding_vectors(),
        "agent_observation": _agent_observation_vectors(),
        "domain_separation": _domain_separation_vectors(),
        "attestation_pair": _attestation_pair_vectors(),
    }


def dump(vectors: dict[str, Any]) -> bytes:
    return (
        json.dumps(vectors, indent=2, sort_keys=True, ensure_ascii=True) + "\n"
    ).encode("ascii")


if __name__ == "__main__":  # pragma: no cover - the regeneration entry point
    if "--write" in sys.argv:
        VECTOR_PATH.parent.mkdir(parents=True, exist_ok=True)
        VECTOR_PATH.write_bytes(dump(build_vectors()))
        print(f"wrote {VECTOR_PATH}")
    else:
        sys.stdout.write(dump(build_vectors()).decode("ascii"))
