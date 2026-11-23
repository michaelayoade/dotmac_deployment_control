"""Builder of `contract/target_api_v2.json`: the v2 job-plan, lease and
observation vectors.

Run `python -m tests.unit.target_api_v2_vectors --write` to regenerate. v1 is NOT
touched: v2 is a delta that leaves the signed wire envelope unchanged. Every
expected value is produced by Control's own functions (`target_api_v2`,
`deploy_binding`), so the file and the code cannot drift apart.
"""

from __future__ import annotations

import copy
import json
import sys
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from dotmac_deployment_control import target_api as api
from dotmac_deployment_control import target_api_v2 as v2
from dotmac_deployment_control.deploy_binding import (
    PlanJob,
    PlanJobDefinition,
    PlanJobWindow,
    PlannedImage,
    PlanRole,
    build_deploy_binding,
)
from dotmac_deployment_control.deploy_unit import params_env_digest
from dotmac_deployment_control.image_policy import PullAllowlist

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
        "lease/standing": {"request": {}, "response": {"standing": "held"}},
    }
    refused = [
        ("lease/renew", "request", {"lease_id": "lease-0001"}),
        ("lease/renew", "request", {"lease_id": "l", "dispatch_run": "r", "x": 1}),
        ("lease/acquire", "request", {"dispatch_run": "r", "ttl_seconds": True}),
        ("lease/acquire", "request", {"dispatch_run": "r", "ttl_seconds": "600"}),
        ("lease/release", "request", {"lease_id": "l", "host_mutated": "no"}),
        ("lease/release", "response", {"released": True}),
        ("lease/covers", "response", {"covers": 1}),
        ("lease/standing", "response", {"standing": "maybe"}),
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
                reconciled=args["reconcile_marker"],
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
                lease_id=args["lease_id"], host_mutated=args["host_mutated"]
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
        "reconcile_marker": True,
    }
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
            "acquire without the reconcile marker is a signed 409",
            [(0, "acquire", {**acquire, "reconcile_marker": False})],
        ),
        (
            "re-acquiring by the same run returns its lease",
            [(0, "acquire", acquire), (10, "acquire", acquire), (20, "covers", held)],
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
    ok = [("deploy", "deploy"), ("deploy", "rollback"), ("job", "run_job")]
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
                r: {d: dict(s) for d, s in b.items()}
                for r, b in v2.LEASE_BODIES.items()
            },
        },
        "lease_body_vectors": _lease_body_vectors(),
        "renew_grant_vectors": _renew_grant_vectors(),
        "lease_scenarios": _scenarios(),
        "observation_vectors": _observation_vectors(),
        "binding": _binding_vectors(),
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
