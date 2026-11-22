"""The target-API contract: ONE definition, owned by Deployment Control.

The deploy agent (a target-side client) and Platform CP (the server and the
bindings) both speak this wire. Neither may define these bytes itself: they call
the functions here, and replay the shared vectors in
`contract/target_api_v1.json`, which is package data of this distribution. A
change to anything below is a new contract file (`target_api_v2.json`) and a new
Control release; the CP pin and the agent's vendored copy move in one train.

Pure: no I/O, no clock, no cryptography. Signing and verification are the
callers' (the kernel verifies on the CP side, the agent signs with its PoP key);
this module fixes the BYTES that are signed.

## What is fixed

* **Request message**: the LF-joined lines `dotmac.target_request.v1`, METHOD,
  the raw path, `sha256hex(raw body)`, credential id, target ref, `issued_at`,
  nonce. A GET signs the empty body. The server hashes the RAW received bytes
  and never re-canonicalises.
* **Response message**: `cp-target-response.v1`, METHOD, path, the REQUEST's
  nonce, the status, `sha256hex(body)`. Error bodies are signed too.
* **Headers**: `X-Dotmac-{Credential-Id,Target-Ref,Issued-At,Nonce,Signature,
  Response-Signature}`.
* **Encoding**: keys and signatures are UNPADDED base64url.
* **`issued_at`**: `YYYY-MM-DDTHH:MM:SSZ`; the nonce is 32 lowercase hex; the
  request must be within 60 s of the server's signed `store_now`.
* **Path**: `/platform/deploy/target/v1/targets/<product>/<environment>/
  <host_alias>/<route>`: the target ref as THREE path segments, never
  percent-encoded, never a query string (an ASGI server decodes `%2F` before
  routing, which would make the signed path and the routed path differ).
* **Endpoints and verbs** are the closed table `ENDPOINTS`.
* **Materials** `dotmac.deploy_target_materials/1`: the agent acts only on a
  Control-signed, plan-bound dispatch, so the document carries the dispatch
  envelope and the plan snapshot, and every value the plan binds is read from
  `plan_snapshot.deploy_binding`.
"""

from __future__ import annotations

import base64
import re
from collections.abc import Mapping
from datetime import UTC, datetime
from importlib import resources
from typing import Any, Final

from dotmac_deployment_control.digests import (
    PlanDigestV1,
    RequestBodyDigestV1,
    canonical_json,
    is_canonical_digest,
)

CONTRACT_NAME: Final = "dotmac.target_api/1"

REQUEST_PURPOSE: Final = "dotmac.target_request.v1"
RESPONSE_PURPOSE: Final = "cp-target-response.v1"
BASE_PATH: Final = "/platform/deploy/target/v1"
MAX_SKEW_SECONDS: Final = 60

H_CREDENTIAL: Final = "X-Dotmac-Credential-Id"
H_TARGET: Final = "X-Dotmac-Target-Ref"
H_ISSUED_AT: Final = "X-Dotmac-Issued-At"
H_NONCE: Final = "X-Dotmac-Nonce"
H_SIGNATURE: Final = "X-Dotmac-Signature"
H_RESPONSE_SIGNATURE: Final = "X-Dotmac-Response-Signature"

#: (verb, route, caller). `committed/<dispatch_id>` is the one parametrised
#: route. "agent" calls are the deploy agent's; "bindings" are the CP
#: bindings running inside Foundation on the target.
ENDPOINTS: Final = (
    ("GET", "materials", "agent"),
    ("POST", "observations", "agent"),
    ("POST", "lease/acquire", "agent"),
    ("POST", "lease/covers", "agent"),
    ("POST", "lease/release", "agent"),
    ("GET", "lease/standing", "agent"),
    ("POST", "resolve", "bindings"),
    ("POST", "consume", "bindings"),
    ("GET", "committed/<dispatch_id>", "bindings"),
)
_VERBS: Final = {route: verb for verb, route, _ in ENDPOINTS}

MATERIALS_SCHEMA: Final = "dotmac.deploy_target_materials/1"
#: Exactly these top-level keys (the first four are required in every document).
MATERIALS_KEYS: Final = frozenset(
    {
        "schema",
        "pending",
        "store_now",
        "dispatch_id",
        "target_ref",
        "params",
        "app_image",
        "previous_app_image",
        "roles",
        "dispatch_envelope",
        "plan_snapshot",
    }
)
#: Removed from the first draft. They are READ from the plan snapshot instead,
#: so a CP-supplied copy could only ever disagree with what Control signed.
MATERIALS_FORBIDDEN_KEYS: Final = frozenset(
    {"params_env_digest", "images", "legacy", "lease_ttl_seconds", "bindings"}
)
ROLE_KEYS: Final = frozenset({"role", "single_use"})

#: Names the bindings already read, plus the runner env the agent sets. The
#: agent passes nothing else, and never a database DSN.
BINDINGS_ENV_NAMES: Final = (
    "HOST_ADMISSION_MATERIALS",
    "EXECUTION_CONTEXT_MATERIALS",
    "AUTHORIZATION_VERIFICATION_IDENTITY",
    "DISPATCH_VERIFICATION_IDENTITY",
    "RELEASE_EVIDENCE_VERIFICATION_IDENTITY",
    "RELEASE_EVIDENCE_REPOSITORY",
    "DISPATCH_CLOCK_SKEW_LIMIT_SECONDS",
)
DEPLOY_ENV_NAMES: Final = (
    "DOTMAC_DEPLOY_DISPATCH_ID",
    "DOTMAC_DEPLOY_TARGET_REF",
    "DOTMAC_DEPLOY_PRODUCT",
    "DOTMAC_DEPLOY_PARAMS_ENV",
    "DOTMAC_DEPLOY_LEGACY_ENV",
    "DOTMAC_DEPLOY_LEASE_ID",
    "DOTMAC_DEPLOY_PLAN_DIGEST",
    "DOTMAC_DEPLOY_AGENT_CONFIG",
    "CREDENTIALS_DIRECTORY",
)

_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DISPATCH_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_NONCE = re.compile(r"[0-9a-f]{32}")
_STAMP = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z")
_B64URL = re.compile(r"[A-Za-z0-9_-]*")
_FORBIDDEN_PATH_CHARS = frozenset("%?#\\ \t\r\n\x00")


class TargetApiError(ValueError):
    """A value violates the target-API contract. The message names the rule."""


# ── The shared vectors (package data) ───────────────────────────────────────

VECTORS_RESOURCE: Final = "contract/target_api_v1.json"


def vector_bytes() -> bytes:
    """The exact bytes of `contract/target_api_v1.json`, as shipped.

    The deploy agent vendors these bytes and pins their sha256, which the
    CHANGELOG records; CP replays every vector through its real router.
    """
    return (
        resources.files("dotmac_deployment_control")
        .joinpath(VECTORS_RESOURCE)
        .read_bytes()
    )


# ── Encoding ────────────────────────────────────────────────────────────────


def b64u_encode(raw: bytes) -> str:
    """UNPADDED base64url."""
    return base64.urlsafe_b64encode(raw).decode("ascii").rstrip("=")


def b64u_decode(text: str) -> bytes:
    """Strict: no padding, no standard alphabet, no whitespace."""
    if not isinstance(text, str) or not _B64URL.fullmatch(text) or len(text) % 4 == 1:
        raise TargetApiError("not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise TargetApiError("not unpadded base64url") from None


# ── Time and nonce ──────────────────────────────────────────────────────────


def format_stamp(moment: datetime) -> str:
    return moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def parse_stamp(value: str) -> datetime:
    if not isinstance(value, str) or not _STAMP.fullmatch(value):
        raise TargetApiError("a timestamp is YYYY-MM-DDTHH:MM:SSZ")
    try:
        return datetime.strptime(value, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=UTC)
    except ValueError:
        raise TargetApiError("a timestamp is YYYY-MM-DDTHH:MM:SSZ") from None


def check_nonce(value: str) -> str:
    if not isinstance(value, str) or not _NONCE.fullmatch(value):
        raise TargetApiError("a nonce is 32 lowercase hex characters")
    return value


def check_skew(issued_at: str, store_now: str) -> None:
    """Refuse a request more than 60 s from the server's signed `store_now`."""
    delta = abs((parse_stamp(issued_at) - parse_stamp(store_now)).total_seconds())
    if delta > MAX_SKEW_SECONDS:
        raise TargetApiError(f"issued_at is {delta:.0f}s from store_now (max 60)")


# ── Paths ───────────────────────────────────────────────────────────────────


def _check_target_ref(target_ref: str) -> tuple[str, str, str]:
    parts = target_ref.split("/") if isinstance(target_ref, str) else []
    if len(parts) != 3 or not all(_SEGMENT.fullmatch(p) for p in parts):
        raise TargetApiError(
            "a target ref is <product>/<environment>/<host_alias>, lowercase"
        )
    return parts[0], parts[1], parts[2]


def target_path(target_ref: str, route: str, *, dispatch_id: str | None = None) -> str:
    """The route, as signed: no percent-encoding, no query string."""
    product, environment, host = _check_target_ref(target_ref)
    if route == "committed":
        route = "committed/<dispatch_id>"
    if route not in _VERBS:
        raise TargetApiError(f"unknown route {route!r}")
    if route == "committed/<dispatch_id>":
        if dispatch_id is None or not _DISPATCH_ID.fullmatch(dispatch_id):
            raise TargetApiError("committed needs a well-formed dispatch id")
        route = f"committed/{dispatch_id}"
    elif dispatch_id is not None:
        raise TargetApiError("only committed takes a dispatch id")
    return f"{BASE_PATH}/targets/{product}/{environment}/{host}/{route}"


def parse_target_path(path: str) -> tuple[str, str, str | None]:
    """Inverse of `target_path`: `(target_ref, route, dispatch_id | None)`."""
    prefix = f"{BASE_PATH}/targets/"
    if (
        not isinstance(path, str)
        or not path.startswith(prefix)
        or _FORBIDDEN_PATH_CHARS & set(path)
        or path.endswith("/")
        or "//" in path
    ):
        raise TargetApiError("not a target-API path")
    rest = path[len(prefix) :].split("/")
    if len(rest) < 4:
        raise TargetApiError("not a target-API path")
    target_ref = "/".join(rest[:3])
    _check_target_ref(target_ref)
    route = "/".join(rest[3:])
    if route.startswith("committed/") and route.count("/") == 1:
        dispatch_id = route.split("/", 1)[1]
        if not _DISPATCH_ID.fullmatch(dispatch_id):
            raise TargetApiError("committed needs a well-formed dispatch id")
        return target_ref, "committed/<dispatch_id>", dispatch_id
    if route not in _VERBS or route == "committed/<dispatch_id>":
        raise TargetApiError(f"unknown route {route!r}")
    return target_ref, route, None


def check_route(method: str, route: str) -> None:
    """The verb for an route is fixed; any other verb is refused."""
    if _VERBS.get(route) != method:
        raise TargetApiError(f"{route} is {_VERBS.get(route)}, not {method}")


# ── Signed messages ─────────────────────────────────────────────────────────


def _line(value: str) -> str:
    if not isinstance(value, str) or any(c in value for c in "\n\r\x00"):
        raise TargetApiError("a signed field has a line break or NUL")
    return value


def _sha256_hex(body: bytes) -> str:
    # Through the typed digest authority: this package computes digests in one
    # module only (`digests.py`).
    return RequestBodyDigestV1.over_bytes(body).digest.hex()


def request_message(
    *,
    method: str,
    path: str,
    body: bytes,
    credential_id: str,
    target_ref: str,
    issued_at: str,
    nonce: str,
) -> bytes:
    parse_stamp(issued_at)
    check_nonce(nonce)
    parts = [
        REQUEST_PURPOSE,
        method.upper(),
        path,
        _sha256_hex(body),
        credential_id,
        target_ref,
        issued_at,
        nonce,
    ]
    return "\n".join(_line(part) for part in parts).encode("utf-8")


def response_message(
    *, method: str, path: str, request_nonce: str, status: int, body: bytes
) -> bytes:
    """Bound to the REQUEST's nonce: a captured response answers nothing else."""
    check_nonce(request_nonce)
    parts = [
        RESPONSE_PURPOSE,
        method.upper(),
        path,
        request_nonce,
        str(status),
        _sha256_hex(body),
    ]
    return "\n".join(_line(part) for part in parts).encode("utf-8")


def request_headers(
    *,
    credential_id: str,
    target_ref: str,
    issued_at: str,
    nonce: str,
    signature_b64u: str,
) -> dict[str, str]:
    b64u_decode(signature_b64u)
    return {
        H_CREDENTIAL: credential_id,
        H_TARGET: target_ref,
        H_ISSUED_AT: issued_at,
        H_NONCE: check_nonce(nonce),
        H_SIGNATURE: signature_b64u,
    }


def classify_unsigned_response(status: int) -> str:
    """An UNSIGNED 429/413/5xx is a retryable transport fault, not a forgery."""
    if status in (413, 429) or 500 <= status <= 599:
        return "cp_unreachable"
    return "response_signature_invalid"


# ── Materials ───────────────────────────────────────────────────────────────


def plan_snapshot_digest(plan_snapshot: Mapping[str, Any]) -> str:
    """`sha256(canonical_json(plan_snapshot))`, as `sha256:<hex>`."""
    return PlanDigestV1.over_json(plan_snapshot).canonical


def primary_image(plan_snapshot: Mapping[str, Any]) -> Mapping[str, Any]:
    """The primary service's image: the one named for the product."""
    binding = plan_snapshot.get("deploy_binding")
    images = (binding or {}).get("images") or []
    product = plan_snapshot.get("product_code")
    chosen = [i for i in images if i.get("service") == product] or (
        images if len(images) == 1 else []
    )
    if len(chosen) != 1:
        raise TargetApiError("the plan snapshot has no single primary image")
    return chosen[0]


def expected_app_image(plan_snapshot: Mapping[str, Any]) -> str:
    """`app_image` must equal the primary service's `planned_repository@digest`."""
    image = primary_image(plan_snapshot)
    return f"{image['planned_repository']}@{image['planned_digest']}"


def archive_name(service: str, digest: str) -> str:
    """The transfer archive, derived: `<service>-<digest hex>.oci.tar`."""
    if not _SEGMENT.fullmatch(service) or not is_canonical_digest(digest):
        raise TargetApiError("an archive name needs a service and a sha256 digest")
    return f"{service}-{digest.split(':', 1)[1]}.oci.tar"


def check_materials_shape(document: Mapping[str, Any]) -> None:
    """The structural contract of the materials document (not its signatures).

    The agent separately verifies the dispatch envelope under the
    enrolment-pinned identity and that `sha256(canonical_json(plan_snapshot))`
    equals the plan digest; this fixes what the document may contain.
    """
    if not isinstance(document, Mapping):
        raise TargetApiError("materials are a mapping")
    forbidden = sorted(set(document) & MATERIALS_FORBIDDEN_KEYS)
    if forbidden:
        raise TargetApiError(f"materials carry removed keys: {', '.join(forbidden)}")
    if not set(document) <= MATERIALS_KEYS:
        raise TargetApiError("materials carry an unknown key")
    if document.get("schema") != MATERIALS_SCHEMA:
        raise TargetApiError(f"materials schema is {MATERIALS_SCHEMA}")
    for key in ("dispatch_envelope", "plan_snapshot"):
        if not isinstance(document.get(key), Mapping):
            raise TargetApiError(f"materials need {key}")
    roles = document.get("roles")
    if not isinstance(roles, list):
        raise TargetApiError("materials need roles")
    seen: set[str] = set()
    for row in roles:
        if not isinstance(row, Mapping) or set(row) != ROLE_KEYS:
            raise TargetApiError("a role is exactly {role, single_use}")
        if (
            not isinstance(row["role"], str)
            or not _SEGMENT.fullmatch(row["role"])
            or row["role"] in seen
            or type(row["single_use"]) is not bool
        ):
            raise TargetApiError("a role has a bad name or single_use")
        seen.add(row["role"])
    snapshot = document["plan_snapshot"]
    if document.get("app_image") != expected_app_image(snapshot):
        raise TargetApiError(
            "app_image is not the primary service's planned_repository@planned_digest"
        )


__all__ = [
    "BASE_PATH",
    "BINDINGS_ENV_NAMES",
    "CONTRACT_NAME",
    "DEPLOY_ENV_NAMES",
    "ENDPOINTS",
    "H_CREDENTIAL",
    "H_ISSUED_AT",
    "H_NONCE",
    "H_RESPONSE_SIGNATURE",
    "H_SIGNATURE",
    "H_TARGET",
    "MATERIALS_FORBIDDEN_KEYS",
    "MATERIALS_KEYS",
    "MATERIALS_SCHEMA",
    "MAX_SKEW_SECONDS",
    "REQUEST_PURPOSE",
    "RESPONSE_PURPOSE",
    "VECTORS_RESOURCE",
    "TargetApiError",
    "archive_name",
    "b64u_decode",
    "b64u_encode",
    "canonical_json",
    "check_materials_shape",
    "check_nonce",
    "check_route",
    "check_skew",
    "classify_unsigned_response",
    "expected_app_image",
    "format_stamp",
    "parse_stamp",
    "parse_target_path",
    "plan_snapshot_digest",
    "primary_image",
    "request_headers",
    "request_message",
    "response_message",
    "target_path",
    "vector_bytes",
]
