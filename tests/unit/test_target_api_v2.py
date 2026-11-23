"""The v2 contract file, and Control's functions that produce and enforce it."""

from __future__ import annotations

import copy
import hashlib
import json
import re
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from dotmac_deployment_control import target_api as api
from dotmac_deployment_control import target_api_v2 as v2
from dotmac_deployment_control.deploy_unit import params_env_digest
from tests.unit import target_api_v2_vectors as builder

_REPO_ROOT = Path(__file__).resolve().parents[2]
_V = json.loads(v2.vector_bytes_v2())


def test_the_v2_file_is_exactly_what_the_builder_produces() -> None:
    assert v2.vector_bytes_v2() == builder.dump(builder.build_vectors())
    assert v2.vector_bytes_v2() == builder.dump(builder.build_vectors())
    assert _V["contract"] == "dotmac.target_api/2"
    assert v2.vector_bytes_v2().decode("ascii").endswith("}\n")


def test_the_changelog_records_the_v2_files_sha256() -> None:
    digest = hashlib.sha256(v2.vector_bytes_v2()).hexdigest()
    assert (
        f"target_api_v2.json sha256 {digest}"
        in (_REPO_ROOT / "CHANGELOG.md").read_text()
    )


def test_v2_is_a_delta_and_leaves_v1_alone() -> None:
    v1 = json.loads(api.vector_bytes())
    assert v1["contract"] == "dotmac.target_api/1"
    assert _V["extends"]["file"] == "target_api_v1.json"
    # The wire envelope and the existing routes and verbs are unchanged.
    v1_routes = {route for _, route, _ in api.ENDPOINTS}
    for verb, route, caller in v2.ENDPOINTS_ADDED:
        assert route not in v1_routes
        assert (verb, caller) == ("POST", "agent")
    assert set(v2.LEASE_BODIES) <= v1_routes | {r for _, r, _ in v2.ENDPOINTS_ADDED}
    assert set(v2.RETRY_IDEMPOTENCY_ADDED) == {r for _, r, _ in v2.ENDPOINTS_ADDED}
    assert v1["constants"]["base_path"] == api.BASE_PATH


def test_no_credential_shaped_literal_sits_in_the_v2_file() -> None:
    text = v2.vector_bytes_v2().decode("ascii")
    for shape in (
        r"ghp_[A-Za-z0-9]{20,}",
        r"-----BEGIN [A-Z ]*-----",
        r"hvs\.[A-Za-z0-9_-]{8,}",
        r"AKIA[A-Z0-9]{16}",
        r"://[^/\s:@]+:[^/\s@]+@",
    ):
        assert not re.search(shape, text), shape


def test_lease_body_vectors_replay() -> None:
    for item in _V["lease_body_vectors"]["ok"]:
        v2.check_lease_body(item["route"], item["direction"], item["body"])
    for item in _V["lease_body_vectors"]["refused"]:
        with pytest.raises(api.TargetApiError) as refused:
            v2.check_lease_body(item["route"], item["direction"], item["body"])
        assert refused.value.code == item["code"]
    # A bool is never an int, in either direction.
    with pytest.raises(api.TargetApiError):
        v2.check_lease_body(
            "lease/acquire", "request", {"dispatch_run": "r", "ttl_seconds": True}
        )


def test_renew_grants_the_smaller_of_ttl_and_what_remains() -> None:
    for item in _V["renew_grant_vectors"]:
        if "code" in item:
            with pytest.raises(api.TargetApiError) as refused:
                v2.renew_grant(
                    ttl_seconds=item["ttl_seconds"],
                    lease_max_seconds=item["lease_max_seconds"],
                    held_seconds=item["held_seconds"],
                )
            assert refused.value.code == item["code"] == "lease_max_reached"
        else:
            assert item["grant"] == min(
                item["ttl_seconds"], item["lease_max_seconds"] - item["held_seconds"]
            )


def test_every_lease_scenario_replays_on_a_fresh_ledger() -> None:
    base = datetime(2026, 12, 1, 10, 0, 0, tzinfo=UTC)
    seen_errors: set[str] = set()
    for scenario in _V["lease_scenarios"]:
        ledger = v2.LeaseLedger()
        for step in scenario["steps"]:
            now = base + timedelta(seconds=step["at"])
            a = step["args"]
            try:
                if step["call"] == "acquire":
                    body = ledger.acquire(
                        now=now,
                        dispatch_run=a["dispatch_run"],
                        ttl_seconds=a["ttl_seconds"],
                        lease_max_seconds=a["lease_max_seconds"],
                        reconciled=a["reconcile_marker"],
                    )
                elif step["call"] == "covers":
                    body = ledger.covers(
                        now=now, lease_id=a["lease_id"], dispatch_run=a["dispatch_run"]
                    )
                elif step["call"] == "renew":
                    body = ledger.renew(
                        now=now, lease_id=a["lease_id"], dispatch_run=a["dispatch_run"]
                    )
                elif step["call"] == "release":
                    body = ledger.release(
                        lease_id=a["lease_id"], host_mutated=a["host_mutated"]
                    )
                else:
                    body = ledger.standing(now=now)
            except api.TargetApiError as exc:
                assert step["status"] == v2.LEASE_ERRORS[exc.code] == 409
                assert step["error"] == exc.code
                seen_errors.add(exc.code)
            else:
                assert step["status"] == 200
                assert step["body"] == body
    # The contract's named refusals are each exercised.
    assert {
        "reconcile_marker_required",
        "lease_not_held",
        "lease_expired",
        "lease_held",
    } <= seen_errors


def test_a_missing_reconcile_marker_is_refused_before_anything_else() -> None:
    ledger = v2.LeaseLedger()
    with pytest.raises(api.TargetApiError) as refused:
        ledger.acquire(
            now=datetime(2026, 12, 1, tzinfo=UTC),
            dispatch_run="r",
            ttl_seconds=600,
            lease_max_seconds=3120,
            reconciled=False,
        )
    assert refused.value.code == "reconcile_marker_required"
    assert v2.LEASE_ERRORS["reconcile_marker_required"] == 409


def test_a_double_release_is_a_replay_not_an_error() -> None:
    ledger = v2.LeaseLedger()
    now = datetime(2026, 12, 1, tzinfo=UTC)
    got = ledger.acquire(
        now=now,
        dispatch_run="r",
        ttl_seconds=600,
        lease_max_seconds=3120,
        reconciled=True,
    )
    first = ledger.release(lease_id=str(got["lease_id"]), host_mutated=False)
    again = ledger.release(lease_id=str(got["lease_id"]), host_mutated=False)
    assert (first, again) == (
        {"released": True, "replay": False},
        {"released": True, "replay": True},
    )


def test_observation_kind_and_operation_must_agree() -> None:
    for item in _V["observation_vectors"]["ok"]:
        v2.check_observation_kind(item["kind"], item["operation"])
    for item in _V["observation_vectors"]["refused"]:
        with pytest.raises(api.TargetApiError) as refused:
            v2.check_observation_kind(item["kind"], item["operation"])
        assert refused.value.code == item["code"]
    assert {i["code"] for i in _V["observation_vectors"]["refused"]} == {
        "observation_kind_mismatch",
        "observation_kind_unknown",
    }


def test_binding_vectors_replay_and_pin_the_example_snapshots() -> None:
    binding = _V["binding"]
    v2.check_deploy_binding(
        binding["serving"]["snapshot"]["deploy_binding"], operation="deploy"
    )
    v2.check_deploy_binding(
        binding["job"]["snapshot"]["deploy_binding"], operation="run_job"
    )
    serving = binding["serving"]["snapshot"]["deploy_binding"]
    # The example carries the roles AND the naming keys, and the split lease.
    assert {r["role"] for r in serving["roles"]} == {"app", "backup", "migrate"}
    assert (serving["secrets_namespace"], serving["secrets_environment"]) == (
        "erp",
        "prod",
    )
    assert serving["lease_ttl_seconds"] == 600 and serving["lease_max_seconds"] == 3120
    assert serving["dispatched_job"] is None and serving["jobs"]
    job = binding["job"]["snapshot"]["deploy_binding"]
    assert job["roles"] == [] and job["images"][0]["source"] == "present"
    assert job["lease_ttl_seconds"] == job["lease_max_seconds"] == 3120
    for item in binding["refused"]:
        with pytest.raises(api.TargetApiError) as refused:
            v2.check_deploy_binding(
                item["snapshot"]["deploy_binding"], operation=item["operation"]
            )
        assert refused.value.code == item["code"], item["name"]
    names = {i["name"] for i in binding["refused"]}
    assert any("roles without naming" in n for n in names)


def test_job_params_are_keyed_by_material_and_the_digest_covers_exactly_them() -> None:
    render = _V["binding"]["job_params_render"]
    params = render["params"]
    assert all(re.fullmatch(r"[A-Z][A-Z0-9_]*", k) for k in params)
    lines = "".join(f"{k}={params[k]}\n" for k in sorted(params))
    assert render["render_utf8"] == lines
    digest = params_env_digest(lines.encode())
    assert render["params_env_digest"] == digest
    job = _V["binding"]["job"]["snapshot"]["deploy_binding"]["dispatched_job"]
    assert job["params"] == params and job["params_env_digest"] == digest
    # Changing any value or key moves the digest.
    changed = copy.deepcopy(params)
    changed["ERP_IMPORT_APPROVED"] = "0"
    other = "".join(f"{k}={changed[k]}\n" for k in sorted(changed))
    assert params_env_digest(other.encode()) != digest
