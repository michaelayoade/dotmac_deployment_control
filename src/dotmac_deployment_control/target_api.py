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

import ast
import base64
import json
import re
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
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
#: The four keys every document carries. `pending` is a bool: True means a
#: dispatch is pending for this target and the document carries it (the signed
#: envelope and the plan snapshot it binds); False means NOTHING is pending, the
#: document is exactly these four keys, and the agent does nothing.
MATERIALS_ALWAYS: Final = frozenset({"schema", "pending", "store_now", "target_ref"})
#: Present exactly when `pending` is True.
MATERIALS_PENDING: Final = frozenset(
    {"dispatch_id", "params", "app_image", "dispatch_envelope", "plan_snapshot"}
)
MATERIALS_KEYS: Final = MATERIALS_ALWAYS | MATERIALS_PENDING
#: Removed from the first draft. Everything the plan binds (params digest,
#: images, legacy part, lease TTL, ROLES, the primary service) is READ from
#: `plan_snapshot.deploy_binding`, so a CP-supplied copy could only ever
#: disagree with what Control signed. `previous_app_image` is unsigned and
#: widened post-run classification, so it is gone too.
MATERIALS_FORBIDDEN_KEYS: Final = frozenset(
    {
        "params_env_digest",
        "images",
        "legacy",
        "lease_ttl_seconds",
        "bindings",
        "roles",
        "previous_app_image",
    }
)
STATEMENT_KEYS: Final = frozenset(
    {"dispatch_id", "target_ref", "product_code", "environment", "plan_digest"}
)

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
    """A value violates the target-API contract. The message names the rule.

    `code` is a closed, machine-readable reason where the contract defines one
    (the `check_request` refusals); it is what the negative vectors pin.
    """

    def __init__(self, message: str, code: str = "contract_violation") -> None:
        super().__init__(message)
        self.code = code


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
        raw = base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        raise TargetApiError("not unpadded base64url") from None
    # Non-zero trailing bits decode to the same bytes (`AB` == `AA`), which
    # would give one signature several spellings. Require the round trip.
    if b64u_encode(raw) != text:
        raise TargetApiError("base64url has non-zero trailing bits")
    return raw


# ── Keys that must never be trusted ─────────────────────────────────────────

#: The vector file publishes two Ed25519 PRIVATE seeds (so anyone can reproduce
#: its signatures). Their public keys therefore authenticate nobody: enrolment
#: refuses them here, and CP and the agent refuse them as a pinned response key.
DENIED_PUBLIC_KEYS_B64U: Final = frozenset(
    {
        "A6EHv_POEL4dcN0Y50vAmWfk1jCbpQ1fHdyGZBJVMbg",
        "Kay64UG8yvCyLhqU000LxzYeUm0L_hLIl5S8kyKWbdc",
    }
)


def _key_bytes(text: str) -> bytes | None:
    for decode in (b64u_decode, lambda t: base64.b64decode(t, validate=True)):
        try:
            return decode(text)
        except (TargetApiError, ValueError):
            continue
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError:
        return None


_DENIED_RAW: Final = frozenset(b64u_decode(k) for k in DENIED_PUBLIC_KEYS_B64U)


def is_denied_public_key(text: str) -> bool:
    """True for a published test key, in unpadded base64url or standard base64."""
    raw = _key_bytes(text) if isinstance(text, str) else None
    return raw in _DENIED_RAW


def check_public_key_admissible(text: str) -> None:
    if is_denied_public_key(text):
        raise TargetApiError(
            "this public key belongs to a published test seed", "denied_public_key"
        )


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


# ── Replay: the nonce ledger, and retry idempotency ────────────────────────

#: Every accepted request inserts `(credential_id, nonce)` into the kernel's
#: insert-only ledger under this scope BEFORE it is acted on, in the same
#: transaction as its effect. Retention is PERMANENT per credential: the skew
#: window only bounds how old a request may be, and a bounded ledger would let a
#: captured request replay once its entry aged out. A duplicate key is refused.
NONCE_LEDGER_SCOPE: Final = "deployment.target_request_nonce.v1"
NONCE_LEDGER_KEY_FIELDS: Final = ("credential_id", "nonce")
NONCE_RETENTION: Final = "permanent"

#: A RETRY of a POST carries a NEW nonce (the first one is spent), so retry
#: safety comes from the business key, never from the nonce.
RETRY_IDEMPOTENCY: Final = {
    "materials": "read: repeatable",
    "observations": "dispatch id plus kind: a repeat returns the stored receipt",
    "lease/acquire": "dispatch run: re-acquiring by the same run returns its lease",
    "lease/covers": "read: repeatable",
    "lease/release": "dispatch run: a second release is a replay, not an error",
    "lease/standing": "read: repeatable",
    "resolve": "read: repeatable",
    "consume": "dispatch id: a replay is 409 with the existing signed committed marker",
    "committed/<dispatch_id>": "read: repeatable",
}


def nonce_ledger_key(credential_id: str, nonce: str) -> str:
    """The ledger key. `/` cannot occur in a credential id, so it is unambiguous."""
    _check_credential_id(credential_id)
    return f"{credential_id}/{check_nonce(nonce)}"


def _check_credential_id(credential_id: str) -> str:
    if not isinstance(credential_id, str) or not _DISPATCH_ID.fullmatch(credential_id):
        raise TargetApiError("a credential id is well formed", "bad_credential_id")
    return credential_id


# ── Request bodies ──────────────────────────────────────────────────────────


def parse_json_body(body: bytes) -> Any:
    """Parse a request or response body. Refuses duplicate keys.

    A parser that keeps the last duplicate and one that keeps the first would
    read different requests from the same signed bytes; refusing them removes
    the difference. NaN and Infinity are refused too, and the bytes must be
    UTF-8.
    """

    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        seen: dict[str, Any] = {}
        for key, value in items:
            if key in seen:
                raise TargetApiError(f"duplicate JSON key {key!r}", "duplicate_key")
            seen[key] = value
        return seen

    def constant(name: str) -> Any:
        raise TargetApiError(f"{name} is not valid JSON", "bad_json")

    try:
        return json.loads(
            body.decode("utf-8"), object_pairs_hook=pairs, parse_constant=constant
        )
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise TargetApiError("the body is not UTF-8 JSON", "bad_json") from None


# ── Paths ───────────────────────────────────────────────────────────────────


#: The environment names Control targets are registered with, mapped to the
#: OpenBao namespace-env of the approved `<env>/<product>` layout. Registration
#: accepts either CP spelling (`production` or `prod`) and never assumes one; an
#: environment not listed here needs an EXPLICIT namespace-env at registration.
SECRETS_ENVIRONMENT_DEFAULTS: Final = {
    "production": "prod",
    "prod": "prod",
    "staging": "staging",
}


def default_secrets_environment(environment: str) -> str | None:
    return SECRETS_ENVIRONMENT_DEFAULTS.get(environment)


def check_secrets_value(value: object, what: str) -> str:
    """A secrets namespace or namespace-env is a lowercase path segment."""
    if not isinstance(value, str) or not _SEGMENT.fullmatch(value):
        raise TargetApiError(f"{what} is a lowercase segment", "bad_secrets_name")
    return value


def openbao_namespace(secrets_namespace: str, secrets_environment: str) -> str:
    """The OpenBao namespace `<env>/<product>`, e.g. `prod/erp`."""
    env = check_secrets_value(secrets_environment, "the namespace env")
    product = check_secrets_value(secrets_namespace, "the secrets namespace")
    return f"{env}/{product}"


def approle_name(secrets_namespace: str, secrets_environment: str, role: str) -> str:
    """The AppRole name `<secrets_namespace>-<ns_env>-<role>`, e.g. `erp-prod-app`."""
    check_secrets_value(role, "a role")
    openbao_namespace(secrets_namespace, secrets_environment)
    return f"{secrets_namespace}-{secrets_environment}-{role}"


@dataclass(frozen=True, slots=True)
class TargetBinding:
    host: str
    namespace: str


def check_target_binding(
    target_ref: str,
    product_code: str,
    environment: str,
    *,
    secrets_namespace: str,
    secrets_environment: str,
) -> TargetBinding:
    """A descriptor-backed target's identities, tied together.

    The ref is `<product_code>/<environment>/<host>` (Control's identities, what
    the API signs and routes on). The OpenBao names are NOT those identities:
    they follow the approved `<env>/<product>` layout, from the descriptor's
    `secrets_namespace` and the namespace-env fixed on the target at
    registration. Both are validated here; neither is ever sent in a dispatch.
    """
    product, env, host = _check_target_ref(target_ref)
    if (product, env) != (product_code, environment):
        raise TargetApiError(
            f"target ref {target_ref!r} is not {product_code}/{environment}/<host>",
            "target_ref_mismatch",
        )
    return TargetBinding(
        host=host, namespace=openbao_namespace(secrets_namespace, secrets_environment)
    )


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


# ── The one request check ───────────────────────────────────────────────────

_REQUEST_HEADERS: Final = (H_CREDENTIAL, H_TARGET, H_ISSUED_AT, H_NONCE, H_SIGNATURE)

HeaderInput = Mapping[str, str] | Sequence[tuple[str, str]]


def _single_header(headers: HeaderInput, name: str) -> str:
    """The ONE value of a header: absent or repeated (any case) is refused.

    A framework lookup returns the first of a repeated header and a dict keeps
    the last; refusing repetition removes the difference.
    """
    items = headers.items() if isinstance(headers, Mapping) else headers
    values = [v for k, v in items if str(k).lower() == name.lower()]
    if not values or not isinstance(values[0], str) or not values[0]:
        raise TargetApiError(f"header {name} is missing", "missing_header")
    if len(values) > 1:
        raise TargetApiError(f"header {name} is repeated", "duplicate_header")
    return values[0]


def request_credential_id(headers: HeaderInput) -> str:
    """The credential id to look the credential up by. Use THIS, nothing else.

    Refuses an absent or duplicated header. `check_request` requires the id it
    finds to equal the one the server looked the credential up with
    (`looked_up_credential_id`), so the key that verifies the signature and the
    id the audit trail and nonce ledger record cannot differ.
    """
    return _check_credential_id(_single_header(headers, H_CREDENTIAL))


SIGNATURE_BYTES: Final = 64


@dataclass(frozen=True, slots=True)
class RequestCoordinates:
    """What `check_request` established. The server authorises on THESE."""

    method: str
    path: str
    target_ref: str
    route: str
    dispatch_id: str | None
    credential_id: str
    issued_at: str
    nonce: str
    signature_b64u: str
    signed_message: bytes
    nonce_ledger_key: str


def check_request(
    *,
    method: str,
    raw_path: str,
    query_string: str,
    headers: HeaderInput,
    body: bytes,
    store_now: str,
    credential_target_ref: str,
    looked_up_credential_id: str,
) -> RequestCoordinates:
    """EVERY server-side coordinate check, in one place, before any signature.

    The signature covers the header target ref AND the path, so a signature that
    verifies proves nothing about whether they AGREE, or whether the credential
    belongs to either. This function requires all three to be the same target:
    the path's, the header's and the credential's. It also requires the verb
    the route is fixed to, an empty query string, all five request headers, a
    well-formed nonce and timestamp within the skew, and a 64-byte signature.

    Platform CP calls this and nothing else to establish a request's
    coordinates (an architecture test enforces it, see `audit_router_source`),
    then verifies `signed_message` under the credential's key and inserts
    `nonce_ledger_key` under `NONCE_LEDGER_SCOPE`.
    """
    try:
        target_ref, route, dispatch_id = parse_target_path(raw_path)
    except TargetApiError as exc:
        raise TargetApiError(str(exc), "bad_path") from None
    if _VERBS.get(route) != method:
        raise TargetApiError(
            f"{route} is {_VERBS.get(route)}, not {method}", "wrong_verb"
        )
    if query_string:
        raise TargetApiError("a target-API request has no query string", "query_string")
    found: dict[str, str] = {
        name: _single_header(headers, name) for name in _REQUEST_HEADERS
    }
    if found[H_TARGET] != target_ref:
        raise TargetApiError(
            "the header target ref differs from the path's",
            "target_mismatch_header_path",
        )
    if credential_target_ref != target_ref:
        raise TargetApiError(
            "the credential is bound to a different target than the path",
            "target_mismatch_credential",
        )
    credential_id = _check_credential_id(found[H_CREDENTIAL])
    if credential_id != looked_up_credential_id:
        raise TargetApiError(
            "the credential looked up is not the one the request names",
            "credential_lookup_mismatch",
        )
    try:
        nonce = check_nonce(found[H_NONCE])
    except TargetApiError:
        raise TargetApiError("the nonce is malformed", "bad_nonce") from None
    try:
        parse_stamp(found[H_ISSUED_AT])
    except TargetApiError:
        raise TargetApiError("issued_at is malformed", "bad_timestamp") from None
    try:
        check_skew(found[H_ISSUED_AT], store_now)
    except TargetApiError as exc:
        raise TargetApiError(str(exc), "skew") from None
    signature = found[H_SIGNATURE]
    try:
        decoded = b64u_decode(signature)
    except TargetApiError:
        raise TargetApiError(
            "the signature is not canonical base64url", "bad_signature_encoding"
        ) from None
    if len(decoded) != SIGNATURE_BYTES:
        raise TargetApiError(
            "an Ed25519 signature is 64 bytes", "bad_signature_encoding"
        )
    return RequestCoordinates(
        method=method,
        path=raw_path,
        target_ref=target_ref,
        route=route,
        dispatch_id=dispatch_id,
        credential_id=credential_id,
        issued_at=found[H_ISSUED_AT],
        nonce=nonce,
        signature_b64u=signature,
        signed_message=request_message(
            method=method,
            path=raw_path,
            body=body,
            credential_id=credential_id,
            target_ref=target_ref,
            issued_at=found[H_ISSUED_AT],
            nonce=nonce,
        ),
        nonce_ledger_key=nonce_ledger_key(credential_id, nonce),
    )


@dataclass(frozen=True, slots=True)
class ResponseCheck:
    """What a client verifies: `signature` over `message` under the pinned key."""

    message: bytes
    signature: bytes


def check_response(
    *,
    method: str,
    path: str,
    request_nonce: str,
    status: int,
    body: bytes,
    headers: HeaderInput,
) -> ResponseCheck:
    """The CLIENT half: everything about a response before its signature check.

    Requires a well-formed path and request nonce and exactly one canonical
    64-byte `X-Dotmac-Response-Signature`. An UNSIGNED 413, 429 or 5xx is a
    retryable transport fault (`cp_unreachable`); any other unsigned or
    malformed response is `response_signature_invalid`. The caller then verifies
    `signature` over `message` under the pinned CP response key (never a denied
    key) and maps a failure to `response_signature_invalid`.
    """
    try:
        parse_target_path(path)
        check_nonce(request_nonce)
    except TargetApiError as exc:
        raise TargetApiError(str(exc), "response_binding_invalid") from None
    unsigned = classify_unsigned_response(status)
    try:
        text = _single_header(headers, H_RESPONSE_SIGNATURE)
    except TargetApiError:
        raise TargetApiError("the response is not signed", unsigned) from None
    try:
        signature = b64u_decode(text)
    except TargetApiError:
        signature = b""
    if len(signature) != SIGNATURE_BYTES:
        raise TargetApiError(
            "the response signature is not a canonical 64-byte value",
            "response_signature_invalid",
        )
    return ResponseCheck(
        message=response_message(
            method=method,
            path=path,
            request_nonce=request_nonce,
            status=status,
            body=body,
        ),
        signature=signature,
    )


def audit_router_source(source: str) -> list[str]:
    """Architecture-test helper for a consumer's router (Platform CP).

    Returns the violations in `source`: no call to `check_request` that passes
    `credential_target_ref`; no use of `.signed_message` (verification) or
    `.nonce_ledger_key` (the replay ledger); a string constant that is a signed
    message purpose (a local message builder); or a literal `X-Dotmac-` header
    name. This is a LINT, not enforcement: CP's HTTP replay of every vector and
    a composed-route test that every target route carries the auth dependency
    are the enforcement. CP asserts the list is empty for its router module.
    """
    problems: list[str] = []
    tree = ast.parse(source)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and (
            (isinstance(node.func, ast.Name) and node.func.id == "check_request")
            or (
                isinstance(node.func, ast.Attribute)
                and node.func.attr == "check_request"
            )
        )
    ]
    if not calls:
        problems.append("the router never calls check_request")
    else:
        for kwarg, why in (
            (
                "credential_target_ref",
                "check_request is never given the credential's target",
            ),
            (
                "looked_up_credential_id",
                "check_request is never given the looked-up credential id",
            ),
        ):
            if not any(any(kw.arg == kwarg for kw in c.keywords) for c in calls):
                problems.append(why)
    attributes = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
        n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
    }
    for needed, why in (
        (
            "request_credential_id",
            "the credential is not looked up by request_credential_id",
        ),
        ("signed_message", "the signature is never verified over signed_message"),
        ("nonce_ledger_key", "nonce_ledger_key is never inserted"),
    ):
        if needed not in attributes:
            problems.append(why)
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Constant) and isinstance(node.value, str)):
            continue
        if REQUEST_PURPOSE in node.value or RESPONSE_PURPOSE in node.value:
            problems.append(
                f"line {node.lineno}: a local message purpose (use request_message)"
            )
        if "x-dotmac-" in node.value.lower():
            problems.append(
                f"line {node.lineno}: a literal X-Dotmac- header name "
                "(use the H_* constants and request_credential_id)"
            )
    return problems


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
    """The primary service's image: the one the plan binding NAMES.

    The binding carries `primary_service`; there is no fallback to "the only
    image", so a snapshot that names nothing (or an unknown service) is refused.
    """
    binding = plan_snapshot.get("deploy_binding")
    if not isinstance(binding, Mapping):
        raise TargetApiError("the plan snapshot has no deploy binding")
    service = binding.get("primary_service")
    chosen = [
        image
        for image in (binding.get("images") or [])
        if isinstance(service, str) and service and image.get("service") == service
    ]
    if len(chosen) != 1:
        raise TargetApiError("the plan binding names no single primary image")
    return chosen[0]


def plan_roles(plan_snapshot: Mapping[str, Any]) -> list[tuple[str, bool]]:
    """`(role, single_use)` for secret_id minting, from the SIGNED plan only."""
    binding = plan_snapshot.get("deploy_binding")
    rows = binding.get("roles") if isinstance(binding, Mapping) else None
    if not isinstance(rows, list):
        raise TargetApiError("the plan binding carries no roles")
    out: list[tuple[str, bool]] = []
    for row in rows:
        if (
            not isinstance(row, Mapping)
            or set(row) != {"role", "single_use"}
            or not isinstance(row["role"], str)
            or not _SEGMENT.fullmatch(row["role"])
            or type(row["single_use"]) is not bool
        ):
            raise TargetApiError("a plan role is exactly {role, single_use}")
        out.append((row["role"], row["single_use"]))
    if [r for r, _ in out] != sorted({r for r, _ in out}):
        raise TargetApiError("plan roles are unique and sorted")
    return out


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
    enrolment-pinned identity; this fixes what the document may contain and
    cross-checks every unsigned field against the signed statement and the plan
    snapshot, so no CP-supplied value can differ from what Control signed.
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
    missing = sorted(MATERIALS_ALWAYS - set(document))
    if missing:
        raise TargetApiError(f"materials need {', '.join(missing)}")
    target_ref = document["target_ref"]
    product, environment, _host = _check_target_ref(target_ref)
    parse_stamp(document["store_now"])
    pending = document["pending"]
    if type(pending) is not bool:
        raise TargetApiError("pending is a boolean")
    present = set(document) & MATERIALS_PENDING
    if not pending:
        if present:
            raise TargetApiError("nothing is pending: no dispatch fields may appear")
        return
    if present != MATERIALS_PENDING:
        raise TargetApiError("a pending document carries the whole dispatch")
    envelope, snapshot = document["dispatch_envelope"], document["plan_snapshot"]
    if not isinstance(envelope, Mapping) or not isinstance(snapshot, Mapping):
        raise TargetApiError("the envelope and the snapshot are mappings")
    statement = envelope.get("statement")
    if not isinstance(statement, Mapping) or not STATEMENT_KEYS <= set(statement):
        raise TargetApiError("the envelope carries no signed statement")
    if not isinstance(document["dispatch_id"], str) or not _DISPATCH_ID.fullmatch(
        document["dispatch_id"]
    ):
        raise TargetApiError("dispatch_id is well formed")
    for key, expected in (
        ("dispatch_id", document["dispatch_id"]),
        ("target_ref", target_ref),
        ("product_code", product),
        ("environment", environment),
        ("plan_digest", plan_snapshot_digest(snapshot)),
    ):
        if statement.get(key) != expected:
            raise TargetApiError(f"the signed statement's {key} differs")
    for key, expected in (
        ("target_ref", target_ref),
        ("product_code", product),
        ("environment", environment),
    ):
        if snapshot.get(key) != expected:
            raise TargetApiError(f"the plan snapshot's {key} differs")
    params = document["params"]
    if not isinstance(params, list) or any(
        not isinstance(row, Mapping)
        or set(row) != {"name", "material", "type", "value"}
        for row in params
    ):
        raise TargetApiError("params are a list of {name, material, type, value}")
    plan_roles(snapshot)
    if document["app_image"] != expected_app_image(snapshot):
        raise TargetApiError(
            "app_image is not the primary service's planned_repository@planned_digest"
        )


__all__ = [
    "BASE_PATH",
    "BINDINGS_ENV_NAMES",
    "CONTRACT_NAME",
    "DENIED_PUBLIC_KEYS_B64U",
    "DEPLOY_ENV_NAMES",
    "ENDPOINTS",
    "H_CREDENTIAL",
    "H_ISSUED_AT",
    "H_NONCE",
    "H_RESPONSE_SIGNATURE",
    "H_SIGNATURE",
    "H_TARGET",
    "MATERIALS_ALWAYS",
    "MATERIALS_FORBIDDEN_KEYS",
    "MATERIALS_KEYS",
    "MATERIALS_PENDING",
    "MATERIALS_SCHEMA",
    "MAX_SKEW_SECONDS",
    "NONCE_LEDGER_KEY_FIELDS",
    "NONCE_LEDGER_SCOPE",
    "NONCE_RETENTION",
    "REQUEST_PURPOSE",
    "RESPONSE_PURPOSE",
    "RETRY_IDEMPOTENCY",
    "SECRETS_ENVIRONMENT_DEFAULTS",
    "SIGNATURE_BYTES",
    "STATEMENT_KEYS",
    "VECTORS_RESOURCE",
    "HeaderInput",
    "RequestCoordinates",
    "ResponseCheck",
    "TargetApiError",
    "TargetBinding",
    "approle_name",
    "archive_name",
    "audit_router_source",
    "b64u_decode",
    "b64u_encode",
    "canonical_json",
    "check_materials_shape",
    "check_nonce",
    "check_public_key_admissible",
    "check_request",
    "check_response",
    "check_route",
    "check_secrets_value",
    "check_skew",
    "check_target_binding",
    "classify_unsigned_response",
    "default_secrets_environment",
    "expected_app_image",
    "format_stamp",
    "is_denied_public_key",
    "nonce_ledger_key",
    "openbao_namespace",
    "parse_json_body",
    "parse_stamp",
    "parse_target_path",
    "plan_roles",
    "plan_snapshot_digest",
    "primary_image",
    "request_credential_id",
    "request_headers",
    "request_message",
    "response_message",
    "target_path",
    "vector_bytes",
]
