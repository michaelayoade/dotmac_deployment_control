"""Control's functions reproduce every vector in `contract/target_api_v1.json`.

The vector file is the contract's oracle: this suite proves Control's own
functions agree with it; Platform CP replays the same vectors through its real
router and the deploy agent vendors the file byte-for-byte.
"""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path

import pytest

from dotmac_deployment_control import target_api as api
from dotmac_deployment_control.deploy_unit import (
    DeployUnitError,
    ParamRefusedError,
    ParamSpec,
    canonical_render,
    derive_secret_ref,
    params_env_digest,
    parse_deploy_unit,
    validate_param_value,
)
from tests.unit import ed25519_reference as ed
from tests.unit import target_api_vectors as builder

_REPO_ROOT = Path(__file__).resolve().parents[2]
_VECTORS = json.loads(api.vector_bytes())
_KEY = _VECTORS["keys"]


def _public(which: str) -> bytes:
    return api.b64u_decode(_KEY[which]["public_b64u"])


# ── The file itself ─────────────────────────────────────────────────────────


def test_the_vector_file_is_exactly_what_the_builder_produces() -> None:
    """Stable and deterministic: no timestamps, no randomness, sorted keys."""
    assert api.vector_bytes() == builder.dump(builder.build_vectors())
    assert api.vector_bytes() == builder.dump(builder.build_vectors())
    text = api.vector_bytes().decode("ascii")
    assert text.endswith("}\n")
    assert json.loads(text)["contract"] == "dotmac.target_api/1"


def test_the_changelog_records_the_vector_files_sha256() -> None:
    """The agent pins this value; a vector change is a v2 file and a new release."""
    digest = hashlib.sha256(api.vector_bytes()).hexdigest()
    changelog = (_REPO_ROOT / "CHANGELOG.md").read_text()
    assert f"target_api_v1.json sha256 {digest}" in changelog


def test_the_vector_file_is_package_data() -> None:
    pyproject = (_REPO_ROOT / "pyproject.toml").read_text()
    assert "src/dotmac_deployment_control/contract/**/*" in pyproject


def test_no_credential_shaped_literal_sits_in_the_file() -> None:
    """Secret-shaped values are stored as parts; no whole token appears."""
    text = api.vector_bytes().decode("ascii")
    for shape in (
        r"ghp_[A-Za-z0-9]{20,}",
        r"-----BEGIN [A-Z ]*-----",
        r"hvs\.[A-Za-z0-9_-]{8,}",
        r"AKIA[A-Z0-9]{16}",
        r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.",
        r"://[^/\s:@]+:[^/\s@]+@",
    ):
        assert not re.search(shape, text), shape


# ── Wire ────────────────────────────────────────────────────────────────────


def test_request_vectors_reproduce_and_verify() -> None:
    for case in _VECTORS["request_vectors"]:
        message = api.request_message(
            method=case["method"],
            path=case["path"],
            body=case["body_utf8"].encode(),
            credential_id=case["credential_id"],
            target_ref=case["target_ref"],
            issued_at=case["issued_at"],
            nonce=case["nonce"],
        )
        assert message.decode() == case["message_utf8"]
        lines = case["message_utf8"].split("\n")
        assert lines[0] == "dotmac.target_request.v1"
        assert len(lines) == 8
        assert ed.verify(
            _public("request"), message, api.b64u_decode(case["signature_b64u"])
        )
        assert case["headers"] == api.request_headers(
            credential_id=case["credential_id"],
            target_ref=case["target_ref"],
            issued_at=case["issued_at"],
            nonce=case["nonce"],
            signature_b64u=case["signature_b64u"],
        )
        # A signature over any other byte does not verify.
        assert not ed.verify(
            _public("request"),
            message + b"x",
            api.b64u_decode(case["signature_b64u"]),
        )


def test_a_get_signs_the_empty_body_hash() -> None:
    empty = hashlib.sha256(b"").hexdigest()
    get = next(c for c in _VECTORS["request_vectors"] if c["method"] == "GET")
    assert get["message_utf8"].split("\n")[3] == empty


def test_response_vectors_reproduce_and_verify_under_the_response_key() -> None:
    for case in _VECTORS["response_vectors"]:
        message = api.response_message(
            method=case["method"],
            path=case["path"],
            request_nonce=case["request_nonce"],
            status=case["status"],
            body=case["body_utf8"].encode(),
        )
        assert message.decode() == case["message_utf8"]
        assert message.decode().split("\n")[0] == "cp-target-response.v1"
        signature = api.b64u_decode(case["signature_b64u"])
        assert ed.verify(_public("response"), message, signature)
        # The response key is DISTINCT from the request (PoP) key.
        assert not ed.verify(_public("request"), message, signature)


def test_the_header_names_are_fixed() -> None:
    assert _VECTORS["constants"]["headers"] == {
        "credential_id": "X-Dotmac-Credential-Id",
        "target_ref": "X-Dotmac-Target-Ref",
        "issued_at": "X-Dotmac-Issued-At",
        "nonce": "X-Dotmac-Nonce",
        "signature": "X-Dotmac-Signature",
        "response_signature": "X-Dotmac-Response-Signature",
    }


def test_a_signed_field_with_a_line_break_is_refused() -> None:
    kwargs = {
        "method": "GET",
        "path": "/x",
        "body": b"",
        "credential_id": "c",
        "target_ref": "a/b/c",
        "issued_at": "2026-11-22T10:00:00Z",
        "nonce": "0" * 32,
    }
    api.request_message(**kwargs)  # type: ignore[arg-type]
    for field in ("credential_id", "target_ref", "path"):
        with pytest.raises(api.TargetApiError):
            api.request_message(**{**kwargs, field: "a\nb"})  # type: ignore[arg-type]
    with pytest.raises(api.TargetApiError):
        api.request_message(**{**kwargs, "nonce": "NOT-A-NONCE"})  # type: ignore[arg-type]


# ── Paths and routes ────────────────────────────────────────────────────────


def test_path_vectors() -> None:
    paths = _VECTORS["paths"]
    assert paths["base"] == "/platform/deploy/target/v1"
    for case in paths["ok"]:
        path = api.target_path(
            case["target_ref"], case["route"], dispatch_id=case.get("dispatch_id")
        )
        assert path == case["path"]
        ref, route, dispatch = api.parse_target_path(path)
        assert ref == case["target_ref"]
        assert dispatch == case.get("dispatch_id")
        assert "%" not in path
        assert "?" not in path
        assert len(path.split("/targets/")[1].split("/")) >= 4
    for case in paths["refused"]:
        with pytest.raises(api.TargetApiError):
            api.parse_target_path(case["path"])
    assert [(r["method"], r["route"], r["caller"]) for r in paths["routes"]] == list(
        api.ENDPOINTS
    )
    for case in paths["wrong_verbs"]:
        with pytest.raises(api.TargetApiError):
            api.check_route(case["method"], case["route"])
    for verb, route, _caller in api.ENDPOINTS:
        api.check_route(verb, route)


def test_a_target_ref_is_three_path_segments() -> None:
    api.target_path("a/b/c", "materials")
    for bad in ("a/b", "a/b/c/d", "a%2Fb%2Fc", "A/b/c", "", "a//c"):
        with pytest.raises(api.TargetApiError):
            api.target_path(bad, "materials")
    with pytest.raises(api.TargetApiError):
        api.target_path("a/b/c", "materials", dispatch_id="x")
    with pytest.raises(api.TargetApiError):
        api.target_path("a/b/c", "committed")


# ── Encoding, time, nonce, status ───────────────────────────────────────────


def test_encoding_vectors() -> None:
    enc = _VECTORS["encoding"]
    for case in enc["base64url"]["ok"]:
        raw = bytes.fromhex(case["hex"])
        assert api.b64u_encode(raw) == case["text"]
        assert api.b64u_decode(case["text"]) == raw
        assert "=" not in case["text"]
    for text in enc["base64url"]["refused"]:
        with pytest.raises(api.TargetApiError):
            api.b64u_decode(text)
    for stamp in enc["stamps"]["ok"]:
        assert api.format_stamp(api.parse_stamp(stamp)) == stamp
    for stamp in enc["stamps"]["refused"]:
        with pytest.raises(api.TargetApiError):
            api.parse_stamp(stamp)
    for nonce in enc["nonces"]["ok"]:
        assert api.check_nonce(nonce) == nonce
    for nonce in enc["nonces"]["refused"]:
        with pytest.raises(api.TargetApiError):
            api.check_nonce(nonce)
    for case in enc["skew"]:
        if case["ok"]:
            api.check_skew(case["issued_at"], case["store_now"])
        else:
            with pytest.raises(api.TargetApiError):
                api.check_skew(case["issued_at"], case["store_now"])
    for status, outcome in enc["unsigned_status"].items():
        assert api.classify_unsigned_response(int(status)) == outcome
    assert enc["unsigned_status"]["429"] == "cp_unreachable"
    assert enc["unsigned_status"]["413"] == "cp_unreachable"
    assert enc["unsigned_status"]["403"] == "response_signature_invalid"
    for case in _VECTORS["stamp_vectors"]:
        assert (
            api.format_stamp(datetime.fromisoformat(case["input"])) == case["expected"]
        )


# ── Materials ───────────────────────────────────────────────────────────────


def test_materials_vectors() -> None:
    materials = _VECTORS["materials"]
    api.check_materials_shape(materials["ok"])
    api.check_materials_shape(materials["idle"])
    assert materials["schema"] == "dotmac.deploy_target_materials/1"
    assert materials["always_keys"] == sorted(api.MATERIALS_ALWAYS)
    assert materials["pending_keys"] == sorted(api.MATERIALS_PENDING)
    assert materials["removed_keys"] == sorted(api.MATERIALS_FORBIDDEN_KEYS)
    snapshot = materials["ok"]["plan_snapshot"]
    assert api.plan_snapshot_digest(snapshot) == materials["plan_digest"]
    assert api.expected_app_image(snapshot) == materials["expected_app_image"]
    assert materials["ok"]["app_image"] == materials["expected_app_image"]
    reasons = []
    for case in materials["refused"]:
        with pytest.raises(api.TargetApiError):
            api.check_materials_shape(case["document"])
        reasons.append(case["reason"])
    for case in materials["archive_names"]:
        assert api.archive_name(case["service"], case["digest"]) == case["name"]
    assert materials["archive_names"][0]["name"].endswith(".oci.tar")
    # Everything the plan binds is READ from the snapshot, not carried beside it.
    for removed in (
        "params_env_digest",
        "images",
        "legacy",
        "lease_ttl_seconds",
        "roles",
        "previous_app_image",
    ):
        assert removed not in materials["ok"]
        assert removed not in api.MATERIALS_KEYS
    # Each R3-L3 gap has its own negative vector.
    for needle in (
        "dispatch_id differs",
        "target_ref differs",
        "the signed plan digest",
        "pending is not a bool",
        "nothing pending but dispatch fields",
        "removed key previous_app_image",
        "removed key roles",
        "no single-image fallback",
    ):
        assert any(needle in reason for reason in reasons), needle


def test_roles_come_from_the_signed_plan_only() -> None:
    materials = _VECTORS["materials"]
    snapshot = materials["ok"]["plan_snapshot"]
    assert api.plan_roles(snapshot) == [
        ("app", False),
        ("backup", False),
        ("migrate", True),
    ]
    assert materials["plan_roles"] == [
        ["app", False],
        ["backup", False],
        ["migrate", True],
    ]
    with pytest.raises(api.TargetApiError):
        api.plan_roles({"deploy_binding": {}})
    with pytest.raises(api.TargetApiError):
        api.plan_roles({"deploy_binding": {"roles": [{"role": "app"}]}})


def test_the_primary_image_is_named_by_the_binding_with_no_fallback() -> None:
    snapshot = _VECTORS["materials"]["ok"]["plan_snapshot"]
    assert api.primary_image(snapshot)["service"] == "dotmac-erp-v2"
    binding = dict(snapshot["deploy_binding"])
    for broken in (
        {**binding, "primary_service": ""},
        {**binding, "primary_service": "other"},
        {k: v for k, v in binding.items() if k != "primary_service"},
    ):
        with pytest.raises(api.TargetApiError):
            api.primary_image({**snapshot, "deploy_binding": broken})
    # One image, no name: still refused. There is no single-image fallback.
    lone = {**binding, "primary_service": None}
    with pytest.raises(api.TargetApiError):
        api.primary_image({**snapshot, "deploy_binding": lone})


def test_the_legacy_part_of_the_snapshot_carries_expires_at() -> None:
    legacy = _VECTORS["materials"]["ok"]["plan_snapshot"]["deploy_binding"]["legacy"]
    assert set(legacy) == {"policy_version", "sha256", "names", "expires_at"}
    assert api.parse_stamp(legacy["expires_at"])


def test_env_names_are_the_ruled_set() -> None:
    constants = _VECTORS["constants"]
    assert constants["bindings_env_names"] == [
        "HOST_ADMISSION_MATERIALS",
        "EXECUTION_CONTEXT_MATERIALS",
        "AUTHORIZATION_VERIFICATION_IDENTITY",
        "DISPATCH_VERIFICATION_IDENTITY",
        "RELEASE_EVIDENCE_VERIFICATION_IDENTITY",
        "RELEASE_EVIDENCE_REPOSITORY",
        "DISPATCH_CLOCK_SKEW_LIMIT_SECONDS",
    ]
    assert constants["deploy_env_names"][-1] == "CREDENTIALS_DIRECTORY"
    # No database DSN is ever passed.
    for name in constants["bindings_env_names"] + constants["deploy_env_names"]:
        assert "DATABASE" not in name
        assert not name.startswith("PG")


# ── Render, values, secret names, secret refs ───────────────────────────────


def test_render_vectors_reproduce_through_controls_functions() -> None:
    for case in _VECTORS["render_vectors"]:
        again = builder._render_case(case["name"], case["params"], case["app_image"])
        assert again == case, case["name"]


def test_render_golden_bytes_and_bytewise_app_image_ordering() -> None:
    workers = next(c for c in _VECTORS["render_vectors"] if c["name"] == "workers")
    assert workers["render_utf8"] == (
        "APP_IMAGE=127.0.0.1:5000/team/app@sha256:" + "1" * 64 + "\nWORKERS=2\n"
    )
    ordered = next(
        c for c in _VECTORS["render_vectors"] if c["name"].startswith("app_image sorts")
    )
    names = [line.split("=")[0] for line in ordered["render_utf8"].splitlines()]
    assert names == ["ALPHA", "APP", "APP_IMAGE", "APP_IMAGE_X", "A_B", "ZED"]
    assert names == sorted(names, key=lambda n: n.encode())
    assert ordered["digest"] == params_env_digest(ordered["render_utf8"].encode())
    refusals = {
        c["name"]: c["refused"] for c in _VECTORS["render_vectors"] if "refused" in c
    }
    assert refusals["a secret-named material may not carry a value"] == (
        "secret_named_material"
    )
    assert refusals["APP_IMAGE is reserved"] == "claimed_twice"


def test_value_vectors_reproduce() -> None:
    accepted = refused = 0
    for case in _VECTORS["value_vectors"]:
        value = "".join(case["value_parts"])
        spec = ParamSpec(name="p", type="string")
        if case["accept"]:
            accepted += 1
            assert validate_param_value(spec, value) == value
        else:
            refused += 1
            with pytest.raises(ParamRefusedError):
                validate_param_value(spec, value)
    assert accepted >= 3
    assert refused >= 10


def test_secret_named_material_vectors() -> None:
    for case in _VECTORS["secret_name_vectors"]:
        text = (
            'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
            'spec = "deploy/product.toml"\n'
            f'[params.p]\ntype = "{case["type"]}"\nmaterial = "{case["material"]}"\n'
        )
        if case["accept"]:
            assert parse_deploy_unit(text).params["p"].material == case["material"]
        else:
            with pytest.raises(DeployUnitError, match="secret-named"):
                parse_deploy_unit(text)
    by = {
        (c["material"], c["type"]): c["accept"] for c in _VECTORS["secret_name_vectors"]
    }
    assert by[("DB_PASSWORD", "string")] is False
    assert by[("DB_PASSWORD", "path")] is True
    assert by[("SECRETS_DIR_APP", "path")] is True
    assert (
        by[("PUBLIC_HOST", "string")] is True
    )  # R3-L5: the wider rule. `*_KEY`, PASS, PWD, DSN, SALT and COOKIE names are
    # file-only too; false positives (BYPASS_CACHE) fail closed.
    for name in (
        "DB_PASS",
        "DB_PWD",
        "SIGNING_KEY",
        "JWT_KEY",
        "KEY",
        "DATABASE_DSN",
        "PASSWORD_SALT",
        "SESSION_COOKIE",
        "BYPASS_CACHE",
    ):
        assert by[(name, "string")] is False, name
    assert by[("DATABASE_DSN", "path")] is True
    # Names that merely CONTAIN the letters stay ordinary.
    for name in ("MONKEY_X", "KEYBOARD_LAYOUT", "KEY_ID"):
        assert by[(name, "string")] is (name != "KEY_ID"), name
    # The existing descriptors' materials are all still accepted.
    for name, kind in (
        ("PLATFORM_ROOT_DOMAIN", "hostname"),
        ("TRUSTED_HOSTS", "string"),
        ("SEED_ON_STARTUP", "bool"),
    ):
        assert by[(name, kind)] is True, name


def test_secret_ref_vectors_and_derivation() -> None:
    vectors = _VECTORS["secret_ref_vectors"]
    for case in vectors["ok"]:
        ref = derive_secret_ref(
            case["environment"], case["product"], case["role"], case["name"]
        )
        assert ref == case["secret_ref"]
        assert ref.endswith("/" + case["name"].lower())
    assert vectors["ok"][0]["secret_ref"] == (
        "bao://production/dotmac-erp-v2/kv/app/db_password"
    )
    for case in vectors["refused"]:
        with pytest.raises(DeployUnitError):
            derive_secret_ref(
                case["environment"], case["product"], case["role"], case["name"]
            )


def test_a_unit_derives_its_active_binding_refs_and_never_stores_them() -> None:
    text = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
        '[[bindings]]\nname = "DB_PASSWORD"\nkind = "key"\nroles = ["app", "migrate"]\n'
        'writer = "ceremony"\nrotation = "copy_only"\n'
        '[[bindings]]\nname = "JWT_SECRET"\nstate = "pre_staged"\nkind = "key"\n'
        'roles = ["app"]\nwriter = "ceremony"\nrotation = "copy_only"\n'
    )
    unit = parse_deploy_unit(text)
    assert unit.secret_refs("production") == {
        ("app", "DB_PASSWORD"): "bao://production/dotmac-erp-v2/kv/app/db_password",
        (
            "migrate",
            "DB_PASSWORD",
        ): "bao://production/dotmac-erp-v2/kv/migrate/db_password",
    }
    assert "secret_ref" not in text


def test_the_render_function_agrees_with_the_vector_file_directly() -> None:
    unit = parse_deploy_unit(
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
        '[params.workers]\ntype = "int"\nmaterial = "WORKERS"\n'
    )
    image = "127.0.0.1:5000/team/app@sha256:" + "1" * 64
    render = canonical_render(
        unit, {"workers": "2"}, app_image=image, environment="production"
    )
    workers = next(c for c in _VECTORS["render_vectors"] if c["name"] == "workers")
    assert render.decode() == workers["render_utf8"]
    assert params_env_digest(render) == workers["digest"]


# ── R3-M1: the one request check ────────────────────────────────────────────


def _check(inputs: dict) -> api.RequestCoordinates:  # type: ignore[type-arg]
    return api.check_request(
        method=inputs["method"],
        raw_path=inputs["raw_path"],
        query_string=inputs["query_string"],
        headers=inputs["headers"],
        body=inputs["body_utf8"].encode(),
        store_now=inputs["store_now"],
        credential_target_ref=inputs["credential_target_ref"],
    )


def test_check_request_vectors_reproduce() -> None:
    vectors = _VECTORS["request_check"]
    for case in vectors["ok"]:
        found = _check(case["inputs"])
        expected = case["coordinates"]
        assert found.target_ref == expected["target_ref"]
        if "signed_message_utf8" in expected:
            assert found.signed_message.decode() == expected["signed_message_utf8"]
            assert found.route == expected["route"]
            assert found.dispatch_id == expected["dispatch_id"]
            assert found.nonce_ledger_key == expected["nonce_ledger_key"]
    refusals = {}
    for case in vectors["refused"]:
        with pytest.raises(api.TargetApiError) as info:
            _check(case["inputs"])
        assert info.value.code == case["code"], case["name"]
        refusals[case["name"]] = case["code"]
    # Each coordinate the review named has its own negative vector.
    assert refusals["header target differs from the path"] == (
        "target_mismatch_header_path"
    )
    assert refusals["the credential is bound to another target"] == (
        "target_mismatch_credential"
    )
    assert refusals["wrong verb for the route"] == "wrong_verb"
    assert refusals["a query string"] == "query_string"
    assert refusals["a percent-encoded path"] == "bad_path"
    assert refusals["an unknown route"] == "bad_path"
    assert {c for n, c in refusals.items() if n.startswith("missing header")} == {
        "missing_header"
    }
    assert len([n for n in refusals if n.startswith("missing header")]) == 5
    assert refusals["outside the skew"] == "skew"
    assert refusals["a 63-byte signature"] == "bad_signature_encoding"
    assert refusals["a non-canonical signature spelling"] == "bad_signature_encoding"


def test_a_valid_signature_cannot_be_replayed_against_another_target() -> None:
    """The confused-deputy case: a verifying signature is not authorisation."""
    case = _VECTORS["request_check"]["ok"][0]["inputs"]
    other = "dotmac-erp-v2/production/host-b"
    with pytest.raises(api.TargetApiError) as info:
        _check({**case, "credential_target_ref": other})
    assert info.value.code == "target_mismatch_credential"


def test_audit_router_source_requires_check_request_and_no_local_builder() -> None:
    good = (
        "from dotmac_deployment_control.target_api import check_request\n"
        "def route(req):\n"
        "    return check_request(method=req.m, raw_path=req.p, query_string='',\n"
        "        headers=req.h, body=req.b, store_now=now(),\n"
        "        credential_target_ref=cred.target)\n"
    )
    assert api.audit_router_source(good) == []
    assert api.audit_router_source("def route(req):\n    return 1\n") == [
        "the router never calls check_request"
    ]
    no_target = good.replace("credential_target_ref=cred.target", "x=1")
    assert api.audit_router_source(no_target) == [
        "check_request is never given the credential's target"
    ]
    local = good + '\nMSG = "dotmac.target_request.v1" + "\\n"\n'
    assert any("local message purpose" in p for p in api.audit_router_source(local))
    local_response = good + '\nR = "cp-target-response.v1"\n'
    assert any(
        "local message purpose" in p for p in api.audit_router_source(local_response)
    )


# ── R3-L1: nonce ledger and retry idempotency; unique nonces ───────────────


def test_the_nonce_ledger_scope_key_and_retention_are_specified() -> None:
    ledger = _VECTORS["nonce_ledger"]
    assert ledger["scope"] == "deployment.target_request_nonce.v1"
    assert ledger["key_fields"] == ["credential_id", "nonce"]
    assert ledger["retention"] == "permanent"
    first = _VECTORS["request_vectors"][0]
    assert ledger["example_key"] == api.nonce_ledger_key(
        first["credential_id"], first["nonce"]
    )
    with pytest.raises(api.TargetApiError):
        api.nonce_ledger_key("bad/id", first["nonce"])
    with pytest.raises(api.TargetApiError):
        api.nonce_ledger_key(first["credential_id"], "short")


def test_every_route_states_its_retry_idempotency() -> None:
    table = _VECTORS["retry_idempotency"]
    assert set(table) == {route for _verb, route, _caller in api.ENDPOINTS}
    assert "409" in table["consume"]


def test_every_vector_request_has_its_own_nonce() -> None:
    nonces = [c["nonce"] for c in _VECTORS["request_vectors"]]
    nonces += [c["request_nonce"] for c in _VECTORS["response_vectors"]]
    assert len(nonces) == len(set(nonces))


# ── R3-L9: duplicate JSON keys ──────────────────────────────────────────────


def test_json_body_vectors() -> None:
    bodies = _VECTORS["json_bodies"]
    for case in bodies["ok"]:
        assert api.parse_json_body(case["body_utf8"].encode()) == case["parsed"]
    for case in bodies["refused"]:
        with pytest.raises(api.TargetApiError) as info:
            api.parse_json_body(bytes.fromhex(case["body_hex"]))
        assert info.value.code == case["code"]
    codes = {c["code"] for c in bodies["refused"]}
    assert "duplicate_key" in codes
    # First-wins and last-wins parsers would disagree on a duplicate; neither runs.
    assert json.loads('{"a":1,"a":2}') == {"a": 2}
    with pytest.raises(api.TargetApiError):
        api.parse_json_body(b'{"a":1,"a":2}')


def test_noncanonical_base64url_is_refused() -> None:
    assert "AB" in _VECTORS["encoding"]["base64url"]["refused"]
    assert api.b64u_decode("AA") == b"\x00"
    with pytest.raises(api.TargetApiError, match="trailing bits"):
        api.b64u_decode("AB")
