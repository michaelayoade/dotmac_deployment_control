"""Builds `contract/target_api_v1.json`: the shared vectors, deterministically.

The file is the contract's test oracle. Control's own functions must reproduce
every vector; Platform CP replays them through its real router; the deploy agent
vendors the file byte-for-byte and pins its sha256 (recorded in the CHANGELOG).

Determinism: sorted keys, two-space indent, ASCII only, one trailing newline, no
timestamps, no randomness (fixed seeds, fixed nonces). Regenerate with

    python -m tests.unit.target_api_vectors --write

Test keys are derived from fixed, public, non-secret seeds and carry no
authority anywhere. Values that LOOK like secrets are stored as `value_parts`
(joined by the consumer), so no credential-shaped literal sits in the file.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any

from dotmac_deployment_control import target_api as api
from dotmac_deployment_control.deploy_unit import (
    DeployUnitError,
    canonical_render,
    derive_secret_ref,
    params_env_digest,
    parse_deploy_unit,
    validate_param_value,
)
from tests.unit import ed25519_reference as ed

VECTOR_PATH = (
    Path(__file__).resolve().parents[2]
    / "src"
    / "dotmac_deployment_control"
    / "contract"
    / "target_api_v1.json"
)

_REQUEST_SEED = bytes(range(32))
_RESPONSE_SEED = bytes(range(32, 64))
_ISSUED = "2026-11-22T10:00:00Z"
_NONCE_A = "00112233445566778899aabbccddeeff"
_NONCE_B = "ffeeddccbbaa99887766554433221100"


def _nonce(index: int) -> str:
    """A distinct, deterministic nonce per vector (no two requests share one)."""
    return format(0xA5A5A5A5 + index, "032x")


_REF = "dotmac-erp-v2/production/host-a"
_CRED = "cred-0001"
_D1 = "sha256:" + "1" * 64


def _text(raw: bytes) -> str:
    return raw.decode("utf-8")


def _sign(seed: bytes, message: bytes) -> str:
    return api.b64u_encode(ed.sign(seed, message))


def _request_vectors() -> list[dict[str, Any]]:
    cases = [
        ("GET", api.target_path(_REF, "materials"), b"", _nonce(1)),
        ("POST", api.target_path(_REF, "observations"), b'{"report":1}', _nonce(2)),
        ("POST", api.target_path(_REF, "lease/acquire"), b'{"ttl":900}', _nonce(3)),
        (
            "GET",
            api.target_path(_REF, "committed", dispatch_id="dispatch-0001"),
            b"",
            _nonce(4),
        ),
    ]
    out = []
    for method, path, body, nonce in cases:
        message = api.request_message(
            method=method,
            path=path,
            body=body,
            credential_id=_CRED,
            target_ref=_REF,
            issued_at=_ISSUED,
            nonce=nonce,
        )
        signature = _sign(_REQUEST_SEED, message)
        out.append(
            {
                "method": method,
                "path": path,
                "body_utf8": _text(body),
                "credential_id": _CRED,
                "target_ref": _REF,
                "issued_at": _ISSUED,
                "nonce": nonce,
                "message_utf8": _text(message),
                "signature_b64u": signature,
                "headers": api.request_headers(
                    credential_id=_CRED,
                    target_ref=_REF,
                    issued_at=_ISSUED,
                    nonce=nonce,
                    signature_b64u=signature,
                ),
            }
        )
    return out


def _response_vectors() -> list[dict[str, Any]]:
    cases = [
        ("GET", api.target_path(_REF, "materials"), _nonce(11), 200, b'{"ok":true}'),
        ("POST", api.target_path(_REF, "consume"), _nonce(12), 409, b'{"error":"x"}'),
        ("POST", api.target_path(_REF, "resolve"), _nonce(13), 200, b""),
    ]
    out = []
    for method, path, nonce, status, body in cases:
        message = api.response_message(
            method=method, path=path, request_nonce=nonce, status=status, body=body
        )
        out.append(
            {
                "method": method,
                "path": path,
                "request_nonce": nonce,
                "status": status,
                "body_utf8": _text(body),
                "message_utf8": _text(message),
                "signature_b64u": _sign(_RESPONSE_SEED, message),
            }
        )
    return out


def _path_vectors() -> dict[str, Any]:
    ok = [
        {"target_ref": _REF, "route": "materials"},
        {"target_ref": _REF, "route": "lease/standing"},
        {"target_ref": _REF, "route": "committed", "dispatch_id": "dispatch-0001"},
        {"target_ref": "a/b/c", "route": "consume"},
    ]
    for case in ok:
        case["path"] = api.target_path(
            case["target_ref"], case["route"], dispatch_id=case.get("dispatch_id")
        )
    base = f"{api.BASE_PATH}/targets"
    refused = [
        {"path": f"{base}/dotmac-erp-v2%2Fproduction%2Fhost-a/materials"},
        {"path": f"{base}/{_REF}/materials?x=1"},
        {"path": f"{base}/{_REF}/materials/"},
        {"path": f"{base}/dotmac-erp-v2/production/materials"},
        {"path": f"{base}/Dotmac/production/host-a/materials"},
        {"path": f"{base}/{_REF}/unknown"},
        {"path": f"{base}//production/host-a/materials"},
        {"path": f"{base}/{_REF}/committed"},
        {"path": f"{base}/{_REF}/committed/a/b"},
    ]
    for case in refused:
        try:
            api.parse_target_path(case["path"])
        except api.TargetApiError:
            case["refused"] = True
        else:  # pragma: no cover - a refusal vector must refuse
            raise AssertionError(case["path"])
    return {
        "base": api.BASE_PATH,
        "ok": ok,
        "refused": refused,
        "routes": [
            {"method": verb, "route": route, "caller": caller}
            for verb, route, caller in api.ENDPOINTS
        ],
        "wrong_verbs": [
            {"method": "POST", "route": "materials"},
            {"method": "GET", "route": "consume"},
        ],
    }


def _encoding_vectors() -> dict[str, Any]:
    raws = [b"", b"\x00", b"\xfb\xff", b"hello world", bytes(range(32))]
    return {
        "base64url": {
            "ok": [{"hex": r.hex(), "text": api.b64u_encode(r)} for r in raws],
            # `AB` decodes to the same byte as `AA`: non-zero trailing bits.
            "refused": ["AA==", "ab+/", "A", "ab cd", "ab\n", "éé", "AB"],
        },
        "stamps": {
            "ok": [_ISSUED, "2026-12-31T23:59:59Z"],
            "refused": [
                "2026-11-22 10:00:00Z",
                "2026-11-22T10:00:00",
                "2026-11-22T10:00:00+00:00",
                "2026-13-22T10:00:00Z",
            ],
        },
        "nonces": {
            "ok": [_NONCE_A, _NONCE_B],
            "refused": ["", "ABCDEF", _NONCE_A.upper(), _NONCE_A[:-1], _NONCE_A + "0"],
        },
        "skew": [
            {
                "issued_at": "2026-11-22T10:00:00Z",
                "store_now": "2026-11-22T10:01:00Z",
                "ok": True,
            },
            {
                "issued_at": "2026-11-22T10:01:00Z",
                "store_now": "2026-11-22T10:00:00Z",
                "ok": True,
            },
            {
                "issued_at": "2026-11-22T10:00:00Z",
                "store_now": "2026-11-22T10:01:01Z",
                "ok": False,
            },
            {
                "issued_at": "2026-11-22T10:01:01Z",
                "store_now": "2026-11-22T10:00:00Z",
                "ok": False,
            },
        ],
        "unsigned_status": {
            str(status): api.classify_unsigned_response(status)
            for status in (401, 403, 404, 413, 429, 500, 502, 503)
        },
    }


def _noncanonical(signature: str) -> str:
    """The same 64 bytes spelled with non-zero trailing bits (last char + 1)."""
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    last = alphabet.index(signature[-1])
    return signature[:-1] + alphabet[(last + 1) % 64]


def _check_inputs(case: dict[str, Any], **overrides: Any) -> dict[str, Any]:
    base = {
        "method": case["method"],
        "raw_path": case["path"],
        "query_string": "",
        "headers": dict(case["headers"]),
        "body_utf8": case["body_utf8"],
        "store_now": case["issued_at"],
        "credential_target_ref": case["target_ref"],
    }
    base.update(overrides)
    return base


def _run_check(inputs: dict[str, Any]) -> api.RequestCoordinates:
    return api.check_request(
        method=inputs["method"],
        raw_path=inputs["raw_path"],
        query_string=inputs["query_string"],
        headers=inputs["headers"],
        body=inputs["body_utf8"].encode(),
        store_now=inputs["store_now"],
        credential_target_ref=inputs["credential_target_ref"],
    )


def _request_check_vectors() -> dict[str, Any]:
    requests = _request_vectors()
    get, post = requests[0], requests[1]
    ok = []
    for case in (get, post, requests[3]):
        inputs = _check_inputs(case)
        found = _run_check(inputs)
        ok.append(
            {
                "inputs": inputs,
                "coordinates": {
                    "target_ref": found.target_ref,
                    "route": found.route,
                    "dispatch_id": found.dispatch_id,
                    "credential_id": found.credential_id,
                    "nonce_ledger_key": found.nonce_ledger_key,
                    "signed_message_utf8": _text(found.signed_message),
                },
            }
        )
    lowered = _check_inputs(get)
    lowered["headers"] = {k.lower(): v for k, v in lowered["headers"].items()}
    found = _run_check(lowered)
    ok.append({"inputs": lowered, "coordinates": {"target_ref": found.target_ref}})
    other = "dotmac-erp-v2/production/host-b"
    refused: list[dict[str, Any]] = []

    def refuse(name: str, inputs: dict[str, Any]) -> None:
        try:
            _run_check(inputs)
        except api.TargetApiError as exc:
            refused.append({"name": name, "inputs": inputs, "code": exc.code})
        else:  # pragma: no cover
            raise AssertionError(name)

    mismatched = _check_inputs(get)
    mismatched["headers"][api.H_TARGET] = other
    refuse("header target differs from the path", mismatched)
    refuse(
        "the credential is bound to another target",
        _check_inputs(get, credential_target_ref=other),
    )
    refuse("wrong verb for the route", _check_inputs(get, method="POST"))
    refuse("a query string", _check_inputs(get, query_string="x=1"))
    refuse(
        "an unknown route",
        _check_inputs(get, raw_path=f"{api.BASE_PATH}/targets/{_REF}/nonsense"),
    )
    for header in (
        api.H_CREDENTIAL,
        api.H_TARGET,
        api.H_ISSUED_AT,
        api.H_NONCE,
        api.H_SIGNATURE,
    ):
        broken = _check_inputs(get)
        del broken["headers"][header]
        refuse(f"missing header {header}", broken)
    empty = _check_inputs(get)
    empty["headers"][api.H_NONCE] = ""
    refuse("an empty header", empty)
    bad_nonce = _check_inputs(get)
    bad_nonce["headers"][api.H_NONCE] = "NOT-HEX"
    refuse("a malformed nonce", bad_nonce)
    bad_stamp = _check_inputs(get)
    bad_stamp["headers"][api.H_ISSUED_AT] = "2026-11-22 10:00:00"
    refuse("a malformed timestamp", bad_stamp)
    refuse("outside the skew", _check_inputs(get, store_now="2026-11-22T10:05:00Z"))
    short = _check_inputs(get)
    short["headers"][api.H_SIGNATURE] = api.b64u_encode(bytes(63))
    refuse("a 63-byte signature", short)
    spelled = _check_inputs(get)
    spelled["headers"][api.H_SIGNATURE] = _noncanonical(get["signature_b64u"])
    refuse("a non-canonical signature spelling", spelled)
    encoded = f"{api.BASE_PATH}/targets/dotmac-erp-v2%2Fproduction%2Fhost-a/materials"
    refuse("a percent-encoded path", _check_inputs(get, raw_path=encoded))
    return {"ok": ok, "refused": refused}


def _json_vectors() -> dict[str, Any]:
    ok = [b"{}", b'{"a":1,"b":[1,2,{"c":null}]}', b"[]", b'"text"']
    refused = [
        b'{"a":1,"a":2}',
        b'{"a":{"b":1,"b":2}}',
        b'[{"x":1,"x":1}]',
        b'{"a":NaN}',
        b'{"a":Infinity}',
        b"\xff\xfe",
        b"not json",
    ]
    out_ok = [
        {"body_utf8": _text(body), "parsed": api.parse_json_body(body)} for body in ok
    ]
    out_refused = []
    for body in refused:
        try:
            api.parse_json_body(body)
        except api.TargetApiError as exc:
            out_refused.append({"body_hex": body.hex(), "code": exc.code})
        else:  # pragma: no cover
            raise AssertionError(body)
    return {"ok": out_ok, "refused": out_refused}


def _snapshot() -> dict[str, Any]:
    return {
        "plan_purpose": "foundation_execution",
        "target_ref": _REF,
        "product_code": "dotmac-erp-v2",
        "environment": "production",
        "deploy_binding": {
            "deploy_unit_digest": "sha256:" + "5" * 64,
            "product_toml_sha256": "sha256:" + "8" * 64,
            "params_env_digest": "sha256:" + "3" * 64,
            "lease_ttl_seconds": 900,
            "active_binding_names": [],
            "primary_service": "dotmac-erp-v2",
            "roles": [
                {"role": "app", "single_use": False},
                {"role": "backup", "single_use": False},
                {"role": "migrate", "single_use": True},
            ],
            "companion_order": None,
            "legacy": {
                "policy_version": 1,
                "sha256": "sha256:" + "a" * 64,
                "names": ["API_SECRET", "DB_PASSWORD"],
                "expires_at": "2026-12-31T23:59:59Z",
            },
            "images": [
                {
                    "service": "dotmac-erp-v2",
                    "source": "transfer",
                    "release_repository": "registry.example.test/team/app",
                    "release_digest": _D1,
                    "planned_repository": "127.0.0.1:5000/team/app",
                    "planned_digest": _D1,
                }
            ],
        },
    }


def _materials_vectors() -> dict[str, Any]:
    snapshot = _snapshot()
    plan_digest = api.plan_snapshot_digest(snapshot)
    document = {
        "schema": api.MATERIALS_SCHEMA,
        "pending": True,
        "store_now": _ISSUED,
        "dispatch_id": "dispatch-0001",
        "target_ref": _REF,
        "params": [
            {"name": "workers", "material": "WORKERS", "type": "int", "value": "2"}
        ],
        "app_image": api.expected_app_image(snapshot),
        "dispatch_envelope": {
            "statement": {
                "dispatch_id": "dispatch-0001",
                "target_ref": _REF,
                "product_code": "dotmac-erp-v2",
                "environment": "production",
                "plan_digest": plan_digest,
            },
            "signature": "signed-by-control-and-verified-by-the-agent",
        },
        "plan_snapshot": snapshot,
    }
    api.check_materials_shape(document)
    idle = {
        "schema": api.MATERIALS_SCHEMA,
        "pending": False,
        "store_now": _ISSUED,
        "target_ref": _REF,
    }
    api.check_materials_shape(idle)
    refusals = []

    def copy(doc: dict[str, Any]) -> dict[str, Any]:
        return json.loads(json.dumps(doc))

    def refuse(reason: str, bad: dict[str, Any]) -> None:
        try:
            api.check_materials_shape(bad)
        except api.TargetApiError:
            refusals.append({"reason": reason, "document": bad})
        else:  # pragma: no cover
            raise AssertionError(reason)

    simple = {
        "removed key params_env_digest": {"params_env_digest": "x"},
        "removed key images": {"images": []},
        "removed key bindings": {"bindings": []},
        "removed key roles (they come from the signed plan)": {"roles": []},
        "removed key previous_app_image": {"previous_app_image": None},
        "unknown key": {"surprise": 1},
        "wrong schema": {"schema": "dotmac.deploy_target_materials/2"},
        "app_image is not the planned image": {
            "app_image": "127.0.0.1:5000/team/other@" + _D1
        },
        "pending is not a bool": {"pending": "yes"},
        "dispatch_id differs from the signed statement": {"dispatch_id": "dispatch-9"},
        "target_ref differs from the signed statement": {
            "target_ref": "dotmac-erp-v2/production/host-b"
        },
        "a malformed store_now": {"store_now": "yesterday"},
    }
    for reason, change in simple.items():
        bad = copy(document)
        bad.update(change)
        refuse(reason, bad)
    for key in (
        "dispatch_envelope",
        "plan_snapshot",
        "params",
        "dispatch_id",
        "store_now",
    ):
        bad = copy(document)
        del bad[key]
        refuse(f"missing {key}", bad)
    bad = copy(document)
    bad["dispatch_envelope"]["statement"]["plan_digest"] = "sha256:" + "0" * 64
    refuse("the signed plan digest is not the snapshot's", bad)
    bad = copy(document)
    bad["dispatch_envelope"]["statement"]["product_code"] = "dotmac-sub"
    refuse("the signed product differs from the target", bad)
    bad = copy(document)
    del bad["dispatch_envelope"]["statement"]
    refuse("the envelope carries no statement", bad)
    bad = copy(document)
    bad["plan_snapshot"]["deploy_binding"]["primary_service"] = "unknown"
    bad["dispatch_envelope"]["statement"]["plan_digest"] = api.plan_snapshot_digest(
        bad["plan_snapshot"]
    )
    refuse("the binding names a primary service that is not an image", bad)
    bad = copy(document)
    del bad["plan_snapshot"]["deploy_binding"]["primary_service"]
    bad["dispatch_envelope"]["statement"]["plan_digest"] = api.plan_snapshot_digest(
        bad["plan_snapshot"]
    )
    refuse("the binding names no primary service (no single-image fallback)", bad)
    bad = copy(document)
    bad["plan_snapshot"]["deploy_binding"]["roles"] = [
        {"role": "migrate", "single_use": True},
        {"role": "app", "single_use": False},
    ]
    bad["dispatch_envelope"]["statement"]["plan_digest"] = api.plan_snapshot_digest(
        bad["plan_snapshot"]
    )
    refuse("plan roles are not sorted", bad)
    bad = copy(idle)
    bad["dispatch_id"] = "dispatch-0001"
    refuse("nothing pending but dispatch fields present", bad)
    bad = copy(idle)
    del bad["store_now"]
    refuse("an idle document without store_now", bad)
    return {
        "schema": api.MATERIALS_SCHEMA,
        "always_keys": sorted(api.MATERIALS_ALWAYS),
        "pending_keys": sorted(api.MATERIALS_PENDING),
        "removed_keys": sorted(api.MATERIALS_FORBIDDEN_KEYS),
        "statement_keys": sorted(api.STATEMENT_KEYS),
        "pending_meaning": (
            "true: a dispatch is pending and the document carries it; false: "
            "nothing is pending, the document is exactly the always keys"
        ),
        "ok": document,
        "idle": idle,
        "plan_digest": plan_digest,
        "expected_app_image": api.expected_app_image(snapshot),
        "plan_roles": [list(r) for r in api.plan_roles(snapshot)],
        "refused": refusals,
        "archive_names": [
            {
                "service": "dotmac-erp-v2",
                "digest": _D1,
                "name": api.archive_name("dotmac-erp-v2", _D1),
            }
        ],
    }


def _join(parts: list[str]) -> str:
    return "".join(parts)


_SECRETISH = [
    ["ghp_", "Ab1" * 12],
    ["-----BEGIN ", "PRIVATE KEY-----"],
    ["hvs.", "Zz9" * 8],
    ["eyJ", "a" * 12, ".", "b" * 12, ".", "c" * 12],
    ["AKIA", "ABCDEFGHIJKLMNOP"],
    ["postgres://user:", "hunter2", "@db.example.test/app"],
]
_VALUES: list[tuple[list[str], str]] = [
    (["release-2026.11"], "ok"),
    (["erp.example.test"], "ok"),
    (["a b c"], "ok"),
    ([""], "empty"),
    (["line", "\n", "break"], "alterable"),
    (["carriage", "\r", "return"], "alterable"),
    (["nul", "\x00", "byte"], "alterable"),
    ([" leading"], "alterable"),
    (["trailing "], "alterable"),
    (['"quoted"'], "alterable"),
    (["'quoted'"], "alterable"),
    *[(parts, "secret_shaped") for parts in _SECRETISH],
]


def _value_outcome(parts: list[str]) -> dict[str, Any]:
    from dotmac_deployment_control.deploy_unit import ParamRefusedError, ParamSpec

    value = _join(parts)
    try:
        validate_param_value(ParamSpec(name="p", type="string"), value)
    except ParamRefusedError as exc:
        text = str(exc)
        reason = (
            "secret_shaped"
            if "secret" in text
            else "empty"
            if "empty" in text
            else "alterable"
        )
        return {"accept": False, "reason": reason}
    return {"accept": True, "reason": "ok"}


def _descriptor(params: list[dict[str, Any]]) -> str:
    out = (
        'schema = "dotmac.deploy_unit/1"\nproduct = "dotmac-erp-v2"\n'
        'spec = "deploy/product.toml"\n'
    )
    for param in params:
        out += f'[params.{param["name"]}]\ntype = "{param["type"]}"\n'
        if param["material"] is not None:
            out += f'material = "{param["material"]}"\n'
    return out


def _render_case(name: str, params: list[dict[str, Any]], app_image: str) -> dict:
    case: dict[str, Any] = {"name": name, "params": params, "app_image": app_image}
    try:
        unit = parse_deploy_unit(_descriptor(params))
        values = {p["name"]: _join(p["value_parts"]) for p in params}
        render = canonical_render(
            unit, values, app_image=app_image, environment="production"
        )
    except DeployUnitError as exc:
        text = str(exc)
        case["refused"] = (
            "secret_named_material"
            if "secret-named" in text
            else "secret_shaped"
            if "secret" in text
            else "claimed_twice"
            if "claimed twice" in text or "same material" in text or "reserved" in text
            else "value_invalid"
        )
        return case
    case["render_utf8"] = _text(render)
    case["digest"] = params_env_digest(render)
    return case


def _p(name: str, material: str | None, kind: str, *value: str) -> dict[str, Any]:
    return {
        "name": name,
        "material": material,
        "type": kind,
        "value_parts": list(value),
    }


def _render_vectors() -> list[dict[str, Any]]:
    image = "127.0.0.1:5000/team/app@" + _D1
    return [
        _render_case("workers", [_p("workers", "WORKERS", "int", "2")], image),
        _render_case("no params", [], image),
        _render_case(
            "app_image sorts with the other lines (bytewise)",
            [
                _p("zed", "ZED", "string", "z"),
                _p("alpha", "ALPHA", "string", "a"),
                _p("app", "APP", "string", "p"),
                _p("a_b", "A_B", "string", "u"),
                _p("app_image_x", "APP_IMAGE_X", "string", "x"),
                _p("no_material", None, "string", "ignored"),
            ],
            image,
        ),
        _render_case(
            "a secret-named material may point at a path",
            [_p("secrets_dir", "SECRETS_DIR_APP", "path", "/run/dotmac/x/secrets/app")],
            image,
        ),
        _render_case(
            "a secret-named material may not carry a value",
            [_p("db_password", "DB_PASSWORD", "string", "plain")],
            image,
        ),
        _render_case(
            "token-named string refused",
            [_p("api_token", "API_TOKEN", "string", "plain")],
            image,
        ),
        _render_case(
            "APP_IMAGE is reserved",
            [_p("img", "APP_IMAGE", "string", "x")],
            image,
        ),
        _render_case(
            "one material twice",
            [_p("a", "SAME", "string", "1"), _p("b", "SAME", "string", "2")],
            image,
        ),
        _render_case(
            "a secret-shaped value is refused",
            [_p("note", "NOTE", "string", *_SECRETISH[0])],
            image,
        ),
        _render_case(
            "a quoted value is refused",
            [_p("note", "NOTE", "string", '"x"')],
            image,
        ),
    ]


def _secret_vectors() -> dict[str, Any]:
    ok = [
        ("production", "dotmac-erp-v2", "app", "DB_PASSWORD"),
        ("staging", "dotmac-integrator-companion", "migrate", "MIGRATION_DATABASE_URL"),
    ]
    refused = [
        ("Production", "dotmac-erp-v2", "app", "DB_PASSWORD"),
        ("production", "dotmac erp", "app", "DB_PASSWORD"),
        ("production", "dotmac-erp-v2", "App", "DB_PASSWORD"),
        ("production", "dotmac-erp-v2", "app", "db_password"),
        ("production", "dotmac-erp-v2", "app/x", "DB_PASSWORD"),
    ]
    out_ok = [
        {
            "environment": e,
            "product": p,
            "role": r,
            "name": n,
            "secret_ref": derive_secret_ref(e, p, r, n),
        }
        for e, p, r, n in ok
    ]
    out_refused = []
    for e, p, r, n in refused:
        try:
            derive_secret_ref(e, p, r, n)
        except DeployUnitError:
            out_refused.append(
                {"environment": e, "product": p, "role": r, "name": n, "refused": True}
            )
        else:  # pragma: no cover
            raise AssertionError((e, p, r, n))
    return {"ok": out_ok, "refused": out_refused}


def _secret_name_vectors() -> list[dict[str, Any]]:
    cases = [
        ("DB_PASSWORD", "string"),
        ("DB_PASSWORD", "path"),
        ("JWT_SECRET", "string"),
        ("SECRETS_DIR_APP", "path"),
        ("SECRETS_DIR_APP", "string"),
        ("API_TOKEN", "string"),
        ("API_KEY", "string"),
        ("TLS_PRIVATE_KEY", "path"),
        ("DB_PASS", "string"),
        ("DB_PWD", "string"),
        ("SIGNING_KEY", "string"),
        ("JWT_KEY", "string"),
        ("KEY", "string"),
        ("KEY_ID", "string"),
        ("DATABASE_DSN", "string"),
        ("DATABASE_DSN", "path"),
        ("PASSWORD_SALT", "string"),
        ("SESSION_COOKIE", "string"),
        ("BYPASS_CACHE", "string"),
        ("MONKEY_X", "string"),
        ("KEYBOARD_LAYOUT", "string"),
        ("PUBLIC_HOST", "string"),
        ("PLATFORM_ROOT_DOMAIN", "hostname"),
        ("TRUSTED_HOSTS", "string"),
        ("SEED_ON_STARTUP", "bool"),
        ("WORKERS", "int"),
    ]
    out = []
    for material, kind in cases:
        try:
            parse_deploy_unit(
                _descriptor([{"name": "p", "type": kind, "material": material}])
            )
        except DeployUnitError:
            accept = False
        else:
            accept = True
        out.append({"material": material, "type": kind, "accept": accept})
    return out


def build_vectors() -> dict[str, Any]:
    return {
        "contract": api.CONTRACT_NAME,
        "file": "target_api_v1.json",
        "note": (
            "Test keys come from fixed public seeds and carry no authority. "
            "`value_parts` are joined by the consumer so no secret-shaped "
            "literal sits in this file."
        ),
        "constants": {
            "request_purpose": api.REQUEST_PURPOSE,
            "response_purpose": api.RESPONSE_PURPOSE,
            "base_path": api.BASE_PATH,
            "max_skew_seconds": api.MAX_SKEW_SECONDS,
            "key_encoding": "base64url-unpadded",
            "headers": {
                "credential_id": api.H_CREDENTIAL,
                "target_ref": api.H_TARGET,
                "issued_at": api.H_ISSUED_AT,
                "nonce": api.H_NONCE,
                "signature": api.H_SIGNATURE,
                "response_signature": api.H_RESPONSE_SIGNATURE,
            },
            "bindings_env_names": list(api.BINDINGS_ENV_NAMES),
            "deploy_env_names": list(api.DEPLOY_ENV_NAMES),
        },
        "keys": {
            "request": {
                "seed_b64u": api.b64u_encode(_REQUEST_SEED),
                "public_b64u": api.b64u_encode(ed.public_key(_REQUEST_SEED)),
            },
            "response": {
                "seed_b64u": api.b64u_encode(_RESPONSE_SEED),
                "public_b64u": api.b64u_encode(ed.public_key(_RESPONSE_SEED)),
            },
        },
        "request_vectors": _request_vectors(),
        "request_check": _request_check_vectors(),
        "nonce_ledger": {
            "scope": api.NONCE_LEDGER_SCOPE,
            "key_fields": list(api.NONCE_LEDGER_KEY_FIELDS),
            "retention": api.NONCE_RETENTION,
            "example_key": api.nonce_ledger_key(_CRED, _nonce(1)),
            "duplicate": "refused; a retried POST carries a NEW nonce",
        },
        "retry_idempotency": dict(api.RETRY_IDEMPOTENCY),
        "json_bodies": _json_vectors(),
        "response_vectors": _response_vectors(),
        "paths": _path_vectors(),
        "encoding": _encoding_vectors(),
        "materials": _materials_vectors(),
        "render_vectors": _render_vectors(),
        "value_vectors": [
            {"value_parts": parts, **_value_outcome(parts)} for parts, _ in _VALUES
        ],
        "secret_name_vectors": _secret_name_vectors(),
        "secret_ref_vectors": _secret_vectors(),
        "stamp_vectors": [
            {
                "input": "2026-12-31T23:59:59+00:00",
                "expected": "2026-12-31T23:59:59Z",
            },
            {
                "input": "2026-12-31T23:59:59+01:00",
                "expected": "2026-12-31T22:59:59Z",
            },
        ],
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
