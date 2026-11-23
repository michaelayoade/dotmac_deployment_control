"""The deploy-unit descriptor and the typed params it validates.

A product repository carries `deploy/deploy-unit.toml`, schema
`dotmac.deploy_unit/1`, beside its Foundation `product.toml`. This module is the
ONE parser and validator Control applies to it. It is a pure value layer: no
I/O, no database, no clock. Persistence and commands are layered on top of it
later; nothing here is reachable from an existing code path, so it is additive
and inert until a caller opts in.

## What the value grammar refuses, and why

The Foundation reads values only from env files, and its parser strips
whitespace and one pair of matching outer quotes from every value (F1). A value
that the parser would alter is a value Control would plan one way and the
Foundation would run another way. So the grammar refuses, at plan time and
rather than repairing: a newline or carriage return, NUL, leading or trailing
whitespace, and a matching outer quote pair. It also refuses a value that is
shaped like a secret (PEM armour, token prefixes, a high-entropy run, URL
userinfo): a secret is a `secret_ref` pointer to OpenBao and never a param.

## `secret_ref`

`bao://<env>/<product>/kv/<role>/<binding>`: a pointer. It is parsed
structurally and carries no value.

## What is NOT here

`[legacy_env_file]` policy decisions (sha, expiry, ceiling) live in
:mod:`dotmac_deployment_control.legacy_policy`. This module only parses the
descriptor's `names` and `path_param`, and refuses the table unless the product
is on `legacy_env_file_allowed_targets` (default-deny) and the descriptor is
not under `deploy/companion/`.
"""

from __future__ import annotations

import ipaddress
import math
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, replace
from typing import Any, Final

from dotmac_deployment_control.digests import (
    DeployUnitDigestV1,
    ParamsEnvDigestV1,
    is_canonical_digest,
)

DESCRIPTOR_SCHEMA: Final = "dotmac.deploy_unit/1"

PARAM_TYPES: Final = frozenset(
    {
        "string",
        "int",
        "bool",
        "enum",
        "hostname",
        "cidr",
        "url",
        "duration_seconds",
        "path",
        "image_digest",
        "image_repository",
    }
)

IMAGE_SOURCES: Final = frozenset({"transfer", "pull"})
DEFAULT_IMAGE_SOURCE: Final = "transfer"

#: The reserved material the plan adds itself. A param material of this name, or
#: a legacy name equal to it, would let a value override the planned image.
APP_IMAGE_MATERIAL: Final = "APP_IMAGE"

#: DEFAULT-DENY, keyed by TARGET. `[legacy_env_file]` is accepted only for a
#: target on the Control setting `legacy_env_file_allowed_targets` (empty by
#: default). A product code would be the wrong key: it would admit every target
#: and every descriptor of that product. Adding a target is a visible, attended
#: setting change. A descriptor under `deploy/companion/` is ALWAYS refused,
#: whatever the setting says.
COMPANION_DESCRIPTOR_PREFIX: Final = "deploy/companion/"
DEFAULT_DESCRIPTOR_PATH: Final = "deploy/deploy-unit.toml"


def _normal_parts(path: str) -> list[str]:
    parts = path.replace("\\", "/").split("/")
    if ".." in parts or path.startswith("/"):
        raise DeployUnitError("a descriptor path must be repository-relative")
    return [p for p in parts if p not in ("", ".")]


def is_companion_descriptor_path(path: str) -> bool:
    """True for any descriptor located under `deploy/companion/`."""
    parts = path.replace("\\", "/").split("/")
    if ".." in parts or path.startswith("/"):
        raise DeployUnitError("a descriptor path must be repository-relative")
    return "/".join(p for p in parts if p not in ("", ".")).startswith(
        COMPANION_DESCRIPTOR_PREFIX
    )


_MATERIAL = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PRODUCT = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?")
_REPO_COMPONENT = re.compile(r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*")
_REPO_HOST = re.compile(
    r"(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*(?::[0-9]{1,5})?"
)
_INT = re.compile(r"-?[0-9]{1,18}")
_URL = re.compile(
    r"(?P<scheme>https?)://(?P<host>[A-Za-z0-9.-]+|\[[0-9A-Fa-f:]+\])"
    r"(?::(?P<port>[0-9]{1,5}))?(?P<rest>[/?][^\s#@]*)?"
)

_SECRET_SHAPES: Final = (
    re.compile(r"-----BEGIN [A-Z ]*-----"),
    re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\."),
    re.compile(r"\bhv[sbr]\.[A-Za-z0-9_-]{8,}"),
    re.compile(r"\bs\.[A-Za-z0-9]{24}\b"),
    re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}"),
    re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}"),
    re.compile(r"\bAKIA[0-9A-Z]{16}\b"),
    re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}"),
    re.compile(r"\bsk-[A-Za-z0-9]{20,}"),
    re.compile(r"://[^/\s:@]*:[^/\s@]+@"),
)
#: Credentials that belong to a DISPATCHED job and to nothing else: never a
#: `[legacy_env_file]` name, never a material of the serving app (an unscoped
#: param). They reach a job only through its role's OpenBao mint, never through
#: a boot, sealed or legacy fallback.
JOB_ONLY_MATERIALS: Final = frozenset({"MIGRATION_DATABASE_URL", "LEGACY_DATABASE_URL"})

#: A material whose NAME says it is a secret may only point at a FILE (a `path`
#: param), never carry a value. Enforced here, at descriptor parse (so product
#: CI refuses it) and again, as a vector-pinned duplicate, by the agent.
SECRET_NAMED_MATERIAL: Final = re.compile(
    r"PASS|PWD|SECRET|TOKEN|CREDENTIAL|DSN|SALT|COOKIE|PRIVATE_KEY|API_KEY"
    r"|(?:^|_)KEY(?:$|_)"
)
_HIGH_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+_=-]{32,}")

BINDING_ACTIVE: Final = "active"
BINDING_PRE_STAGED: Final = "pre_staged"
BINDING_STATES: Final = frozenset({BINDING_ACTIVE, BINDING_PRE_STAGED})
#: `copy_only`: the value is copied from its source and never rotated by the
#: deploy; `manual`: an operator rotates it. A new mode is a schema revision.
BINDING_ROTATIONS: Final = frozenset({"copy_only", "manual"})
#: The gates a runner can be asked to pass, in the order a descriptor lists them.
HEALTH_GATES: Final = frozenset(
    {
        "migrate",
        "grant_mirror",
        "heads",
        "live",
        "ready",
        "composition_equals_pins",
        "runtime_policy_digest",
        "census_zero_enabled",
    }
)
JOB_TRIGGERS: Final = frozenset({"operator"})
HOLD_MEMBERS: Final = frozenset({"primary", "companion"})
HOLD_BEFORE: Final = frozenset({"migrate", "start", "switch"})
HOLD_ON_TIMEOUT: Final = frozenset({"abandon_member_record_deviation"})
HOLD_RELEASED_BY: Final = frozenset({"operator"})
_PATTERN_TYPES: Final = frozenset({"string", "hostname", "url", "path"})
_MAX_PATTERN_LENGTH = 256
_DEFAULT_MAX_LENGTH = 512
_MAX_PATH_LENGTH = 1024
_MAX_DURATION_SECONDS = 31_536_000


class DeployUnitError(ValueError):
    """A descriptor or a param value was refused. The message names the cause."""


class ParamRefusedError(DeployUnitError):
    """A param value (or the set of values) was refused by the grammar."""


# ── Descriptor model ────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class ParamSpec:
    name: str
    type: str
    material: str | None = None
    #: Environments in which the param must be supplied.
    required_in: frozenset[str] = frozenset()
    minimum: int | None = None
    maximum: int | None = None
    min_length: int | None = None
    max_length: int | None = None
    #: Canonical renderings ("true"/"false", decimal ints, strings).
    choices: tuple[str, ...] = ()
    #: Canonical rendering, validated at parse; used when no value is supplied.
    default: str | None = None
    #: A full-match regular expression (string, hostname, url and path only).
    pattern: str | None = None
    #: Jobs this param is SCOPED to. A scoped param is rendered only into those
    #: jobs' env, never into the serving app's params.env; the scope is bound
    #: into the plan digest through the plan binding's `jobs`.
    jobs: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BindingSpec:
    name: str
    kind: str
    roles: tuple[str, ...]
    writer: str
    rotation: str
    single_use: bool
    #: `active` is a delivery source; `pre_staged` is declared and reviewable
    #: but delivers nothing (the exit from the legacy bridge, staged early).
    state: str = BINDING_ACTIVE


@dataclass(frozen=True, slots=True)
class JobSpec:
    """An operator-triggered one-shot. Its arguments come from the runbook."""

    name: str
    command: tuple[str, ...]
    trigger: str
    materials: tuple[str, ...]
    runbook: str
    #: The OpenBao role a DISPATCHED job logs in as (e.g. `import`). Its secret_id
    #: is minted only when the job is dispatched, never for the serving app.
    role: str | None = None


@dataclass(frozen=True, slots=True)
class HoldPointSpec:
    """A bounded wait: the agent holds at `before` until released or timed out."""

    name: str
    member: str
    before: str
    timeout_param: str
    on_timeout: str
    released_by: str


@dataclass(frozen=True, slots=True)
class CompanionSpec:
    product: str
    descriptor: str
    order: str
    required_at_switch: bool
    host: str


@dataclass(frozen=True, slots=True)
class LegacyEnvFileSpec:
    names: tuple[str, ...]
    path_param: str


@dataclass(frozen=True, slots=True)
class DeployUnit:
    product: str
    spec: str
    #: The `<product>` segment of the OpenBao layout `<env>/<product>`
    #: (`erp`, `erp-integrator`, ...). Owned by the product repo and checked by
    #: its CI against the authored OpenBao config; it is NOT the product code.
    secrets_namespace: str
    #: Computed by Control over the descriptor bytes; never self-declared.
    digest: str
    params: Mapping[str, ParamSpec]
    bindings: tuple[BindingSpec, ...]
    companions: tuple[CompanionSpec, ...]
    #: `transfer` unless the descriptor says otherwise AND Control later allows
    #: it (see `image_policy`). Absence of `[image]` is `transfer`.
    image_source: str
    health_gates: tuple[str, ...]
    jobs: tuple[JobSpec, ...]
    hold_points: tuple[HoldPointSpec, ...]
    legacy_env_file: LegacyEnvFileSpec | None

    def job_roles(self) -> frozenset[str]:
        """Roles claimed by a dispatched job: minted for that job only."""
        return frozenset(job.role for job in self.jobs if job.role)

    def role_bindings(self) -> tuple[tuple[str, bool], ...]:
        """`(role, single_use)` for every role of an ACTIVE binding, sorted.

        Derived from the verified descriptor and bound into the plan; the agent
        mints one secret_id per role from THIS, never from a CP-supplied list.
        A role has ONE secret_id, so one mode. Parse REFUSES a role whose bindings
        disagree (no coercion either way): split the binding instead.
        """
        found: dict[str, bool] = {}
        for binding in self.bindings:
            if binding.state != BINDING_ACTIVE:
                continue
            for role in binding.roles:
                found[role] = binding.single_use
        return tuple(sorted(found.items()))

    def deploy_role_bindings(self) -> tuple[tuple[str, bool], ...]:
        """The roles minted for the SERVING deploy: job roles are excluded."""
        job_roles = self.job_roles()
        return tuple((r, s) for r, s in self.role_bindings() if r not in job_roles)

    def job_role_single_use(self, job: JobSpec) -> bool | None:
        """Whether the job's role secret_id is single-use (None: no role)."""
        if job.role is None:
            return None
        return dict(self.role_bindings()).get(job.role)

    def secret_refs(self, secrets_environment: str) -> dict[tuple[str, str], str]:
        """`(role, binding name) -> secret_ref` for every ACTIVE binding.

        `secrets_environment` is the target's namespace-env (`prod`), fixed at
        registration; the product segment is this descriptor's own
        `secrets_namespace`.
        """
        return {
            (role, binding.name): derive_secret_ref(
                secrets_environment, self.secrets_namespace, role, binding.name
            )
            for binding in self.bindings
            if binding.state == BINDING_ACTIVE
            for role in binding.roles
        }

    def active_binding_names(self) -> tuple[str, ...]:
        """Names of bindings that are real delivery sources (not pre-staged)."""
        return tuple(sorted(b.name for b in self.bindings if b.state == BINDING_ACTIVE))


@dataclass(frozen=True, slots=True)
class SecretRef:
    environment: str
    product: str
    role: str
    binding: str

    def render(self) -> str:
        return f"bao://{self.environment}/{self.product}/kv/{self.role}/{self.binding}"


# ── secret_ref ──────────────────────────────────────────────────────────────


def derive_secret_ref(
    secrets_environment: str, secrets_namespace: str, role: str, name: str
) -> str:
    """The secret_ref of a binding: DERIVED, never stored or entered.

    `bao://<ns_env>/<secrets_namespace>/kv/<role>/<lower(name)>`, following the
    approved `<env>/<product>` OpenBao layout (`prod/erp`): the namespace env
    (`prod`) is the target's, the product segment (`erp`) is the descriptor's
    `secrets_namespace`. The binding name is the uppercase file name (K1); its
    path segment is lowercase.
    """
    ref = SecretRef(secrets_environment, secrets_namespace, role, name.lower())
    for label, segment in (
        ("env", ref.environment),
        ("product", ref.product),
        ("role", ref.role),
        ("binding", ref.binding),
    ):
        if not _SEGMENT.fullmatch(segment):
            raise DeployUnitError(f"a secret_ref {label} segment is not well formed")
    if not _MATERIAL.fullmatch(name):
        raise DeployUnitError("a binding name is an uppercase file name")
    return ref.render()


def parse_secret_ref(value: object) -> SecretRef:
    """Parse `bao://<env>/<product>/kv/<role>/<binding>`; refuse anything else."""
    if not isinstance(value, str) or not value.startswith("bao://"):
        raise DeployUnitError("a secret_ref must be a bao:// pointer")
    parts = value[len("bao://") :].split("/")
    if len(parts) != 5 or parts[2] != "kv":
        raise DeployUnitError(
            "a secret_ref has the form bao://<env>/<product>/kv/<role>/<binding>"
        )
    environment, product, _kv, role, binding = parts
    for label, segment in (
        ("env", environment),
        ("product", product),
        ("role", role),
        ("binding", binding),
    ):
        if not _SEGMENT.fullmatch(segment):
            raise DeployUnitError(f"a secret_ref {label} segment is not well formed")
    return SecretRef(environment, product, role, binding)


# ── Value grammar ───────────────────────────────────────────────────────────


def _refuse(name: str, reason: str) -> ParamRefusedError:
    return ParamRefusedError(f"param {name!r} refused: {reason}")


def _check_alterable(name: str, value: str) -> None:
    """Refuse what Foundation's env-file parser would alter (F1)."""
    if "\n" in value or "\r" in value:
        raise _refuse(name, "contains a line break")
    if "\x00" in value:
        raise _refuse(name, "contains NUL")
    if value != value.strip():
        raise _refuse(name, "has leading or trailing whitespace")
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "'\"":
        raise _refuse(name, "is wrapped in matching quotes")


def _entropy(text: str) -> float:
    counts: dict[str, int] = {}
    for char in text:
        counts[char] = counts.get(char, 0) + 1
    total = len(text)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def looks_secret_shaped(value: str) -> bool:
    """True for a value a secret would look like. Conservative by design."""
    if any(shape.search(value) for shape in _SECRET_SHAPES):
        return True
    for run in _HIGH_ENTROPY_RUN.findall(value):
        has_digit = any(c.isdigit() for c in run)
        has_alpha = any(c.isalpha() for c in run)
        if has_digit and has_alpha and _entropy(run) >= 4.0:
            return True
    return False


def valid_repository(value: str) -> bool:
    """`host[:port]/path` with lowercase components, no tag, no digest."""
    if "@" in value or value != value.strip():
        return False
    host, slash, path = value.partition("/")
    if not slash or not path or not _REPO_HOST.fullmatch(host):
        return False
    if ":" in host and not (1 <= int(host.rsplit(":", 1)[1]) <= 65535):
        return False
    return all(_REPO_COMPONENT.fullmatch(part) for part in path.split("/"))


def _validate_hostname(name: str, value: str) -> None:
    if len(value) > 253 or value.endswith("."):
        raise _refuse(name, "is not a hostname")
    if not all(_LABEL.fullmatch(label) for label in value.split(".")):
        raise _refuse(name, "is not a hostname")


def _validate_url(name: str, value: str) -> None:
    match = _URL.fullmatch(value)
    if match is None:
        raise _refuse(name, "is not an http(s) URL without userinfo or fragment")
    port = match.group("port")
    if port is not None and not 1 <= int(port) <= 65535:
        raise _refuse(name, "has an out-of-range port")


def _validate_path(name: str, value: str) -> None:
    if (
        not value.startswith("/")
        or len(value) > _MAX_PATH_LENGTH
        or "//" in value
        or (len(value) > 1 and value.endswith("/"))
        or any(part in ("..", ".") for part in value.split("/"))
    ):
        raise _refuse(name, "is not a normalised absolute path")


def _int_value(name: str, value: object) -> int:
    if isinstance(value, bool):
        raise _refuse(name, "is a boolean, not an integer")
    if isinstance(value, int):
        return value
    if isinstance(value, str) and _INT.fullmatch(value):
        return int(value)
    raise _refuse(name, "is not an integer")


def validate_param_value(spec: ParamSpec, value: object) -> str:
    """Validate one value against its spec and return its CANONICAL rendering.

    The rendering is what lands in params.env and what the digest covers.
    """
    rendered = _validate_typed(spec, value)
    if spec.choices and rendered not in spec.choices:
        raise _refuse(spec.name, "is not one of the declared choices")
    if spec.pattern is not None and not re.fullmatch(spec.pattern, rendered):
        raise _refuse(spec.name, "does not match its declared pattern")
    return rendered


def _validate_typed(spec: ParamSpec, value: object) -> str:
    name = spec.name
    kind = spec.type
    if kind == "bool":
        if isinstance(value, bool):
            return "true" if value else "false"
        if value in ("true", "false"):
            return str(value)
        raise _refuse(name, "is not a boolean")
    if kind in ("int", "duration_seconds"):
        number = _int_value(name, value)
        low = spec.minimum if spec.minimum is not None else 0 if kind != "int" else None
        high = spec.maximum
        if kind == "duration_seconds" and high is None:
            high = _MAX_DURATION_SECONDS
        if low is not None and number < low:
            raise _refuse(name, f"is below the minimum {low}")
        if high is not None and number > high:
            raise _refuse(name, f"is above the maximum {high}")
        return str(number)
    if not isinstance(value, str):
        raise _refuse(name, "is not a string")
    _check_alterable(name, value)
    if value == "":
        raise _refuse(name, "is empty")
    if kind == "string":
        limit = spec.max_length if spec.max_length is not None else _DEFAULT_MAX_LENGTH
        if len(value) > limit:
            raise _refuse(name, f"is longer than {limit}")
        if spec.min_length is not None and len(value) < spec.min_length:
            raise _refuse(name, f"is shorter than {spec.min_length}")
    elif kind == "enum":
        pass  # membership is checked against `choices` by the caller
    elif kind == "hostname":
        _validate_hostname(name, value)
    elif kind == "cidr":
        try:
            ipaddress.ip_network(value, strict=True)
        except ValueError:
            raise _refuse(name, "is not a canonical CIDR") from None
    elif kind == "url":
        _validate_url(name, value)
    elif kind == "path":
        _validate_path(name, value)
    elif kind == "image_digest":
        if not is_canonical_digest(value):
            raise _refuse(name, "is not sha256:<64 lowercase hex>")
        return value
    elif kind == "image_repository":
        if not valid_repository(value):
            raise _refuse(name, "is not a repository without tag or digest")
    else:  # pragma: no cover - unreachable, specs are validated at parse
        raise _refuse(name, "has an unknown type")
    if looks_secret_shaped(value):
        raise _refuse(name, "looks like a secret; use a secret_ref binding")
    return value


def validate_params(
    unit: DeployUnit, values: Mapping[str, object], *, environment: str
) -> dict[str, str]:
    """Validate a whole value set against the descriptor.

    Refuses an unknown name, a missing required one, and any grammar breach.
    Returns the canonical renderings by param name.
    """
    unknown = sorted(set(values) - set(unit.params))
    if unknown:
        raise ParamRefusedError(f"unknown param(s): {', '.join(unknown)}")
    rendered: dict[str, str] = {}
    for name, spec in unit.params.items():
        if name not in values:
            if spec.default is not None:
                rendered[name] = spec.default
                continue
            if environment in spec.required_in:
                raise ParamRefusedError(
                    f"param {name!r} is required in {environment!r}"
                )
            continue
        rendered[name] = validate_param_value(spec, values[name])
    return rendered


# ── params.env: canonical render and digest (design §2.5) ───────────────────


def canonical_render(
    unit: DeployUnit, values: Mapping[str, object], *, app_image: str, environment: str
) -> bytes:
    """LF-terminated `MATERIAL=value` lines, sorted by material name.

    Covers every param with a `material` (including each path param that names a
    secrets directory) plus `APP_IMAGE=<the exact planned image reference>`.
    """
    rendered = validate_params(unit, values, environment=environment)
    _check_alterable(APP_IMAGE_MATERIAL, app_image)
    if not app_image:
        raise _refuse(APP_IMAGE_MATERIAL, "is empty")
    lines: dict[str, str] = {}
    for name, text in rendered.items():
        material = unit.params[name].material
        if material is None or unit.params[name].jobs:
            continue  # job-scoped params never reach the serving app's env
        if material in lines or material == APP_IMAGE_MATERIAL:
            raise ParamRefusedError(f"material {material!r} is claimed twice")
        lines[material] = text
    lines[APP_IMAGE_MATERIAL] = app_image
    return "".join(f"{key}={lines[key]}\n" for key in sorted(lines)).encode()


def scoped_param_names(unit: DeployUnit, job_name: str) -> tuple[str, ...]:
    """Names of the params scoped to `job_name` that carry a material, sorted."""
    return tuple(
        sorted(
            name
            for name, spec in unit.params.items()
            if job_name in spec.jobs and spec.material is not None
        )
    )


def canonical_job_render(
    unit: DeployUnit, values: Mapping[str, object], *, job_name: str, environment: str
) -> bytes:
    """`MATERIAL=value` lines for ONE job's scoped params, sorted (no APP_IMAGE)."""
    rendered = validate_params(unit, values, environment=environment)
    lines: dict[str, str] = {}
    for name in scoped_param_names(unit, job_name):
        if name in rendered:
            lines[str(unit.params[name].material)] = rendered[name]
    return "".join(f"{key}={lines[key]}\n" for key in sorted(lines)).encode()


def params_env_digest(render: bytes) -> str:
    """`sha256:<hex>` over the canonical render, as bound into the plan."""
    return ParamsEnvDigestV1.over_bytes(render).canonical


# ── Parsing ─────────────────────────────────────────────────────────────────

_TOP_KEYS = frozenset(
    {
        "schema",
        "product",
        "spec",
        "secrets_namespace",
        "params",
        "bindings",
        "companions",
        "image",
        "health",
        "jobs",
        "hold_points",
        "legacy_env_file",
    }
)
_PARAM_KEYS = frozenset(
    {
        "type",
        "required_in",
        "material",
        "min",
        "max",
        "min_length",
        "max_length",
        "choices",
        "default",
        "pattern",
        "jobs",
    }
)
_BINDING_KEYS = frozenset(
    {"name", "kind", "roles", "writer", "rotation", "single_use", "state"}
)
_JOB_KEYS = frozenset({"name", "command", "trigger", "materials", "runbook", "role"})
_HOLD_KEYS = frozenset(
    {"name", "member", "before", "timeout_param", "on_timeout", "released_by"}
)
_HOST = re.compile(r"[a-z0-9][a-z0-9_.-]{0,62}")
_COMPANION_KEYS = frozenset(
    {"product", "descriptor", "order", "required_at_switch", "host"}
)


def _only_keys(where: str, table: Mapping[str, Any], allowed: frozenset[str]) -> None:
    extra = sorted(set(table) - allowed)
    if extra:
        raise DeployUnitError(f"{where}: unknown key(s) {', '.join(extra)}")


def _opt_int(where: str, table: Mapping[str, Any], key: str) -> int | None:
    value = table.get(key)
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int):
        raise DeployUnitError(f"{where}.{key} must be an integer")
    return value


def _string_list(where: str, value: object) -> tuple[str, ...]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise DeployUnitError(f"{where} must be a list of strings")
    return tuple(value)


def _parse_param(name: str, table: object) -> ParamSpec:
    where = f"params.{name}"
    if not _NAME.fullmatch(name):
        raise DeployUnitError(f"{where}: the param name is not well formed")
    if not isinstance(table, dict):
        raise DeployUnitError(f"{where} must be a table")
    _only_keys(where, table, _PARAM_KEYS)
    kind = table.get("type")
    if kind not in PARAM_TYPES:
        raise DeployUnitError(f"{where}.type is not a known param type")
    material = table.get("material")
    if material is not None and (
        not isinstance(material, str) or not _MATERIAL.fullmatch(material)
    ):
        raise DeployUnitError(f"{where}.material is not a valid material name")
    if (
        material is not None
        and SECRET_NAMED_MATERIAL.search(material)
        and kind != "path"
    ):
        raise DeployUnitError(
            f"{where}: a secret-named material ({material}) may only point at "
            "a file (type path), never carry a value"
        )
    raw_choices = table.get("choices", [])
    if not isinstance(raw_choices, list):
        raise DeployUnitError(f"{where}.choices must be a list")
    if kind == "enum" and not raw_choices:
        raise DeployUnitError(f"{where}: an enum declares its choices")
    if raw_choices and kind not in ("enum", "bool", "int", "string"):
        raise DeployUnitError(f"{where}: choices apply to enum, bool, int, string")
    required_in = frozenset(
        _string_list(f"{where}.required_in", table.get("required_in", []))
    )
    minimum = _opt_int(where, table, "min")
    maximum = _opt_int(where, table, "max")
    if minimum is not None and maximum is not None and minimum > maximum:
        raise DeployUnitError(f"{where}: min exceeds max")
    if (minimum is not None or maximum is not None) and kind not in (
        "int",
        "duration_seconds",
    ):
        raise DeployUnitError(f"{where}: min and max apply to int types only")
    pattern = table.get("pattern")
    if pattern is not None:
        if kind not in _PATTERN_TYPES:
            raise DeployUnitError(
                f"{where}: pattern applies to {sorted(_PATTERN_TYPES)}"
            )
        if not isinstance(pattern, str) or not 0 < len(pattern) <= _MAX_PATTERN_LENGTH:
            raise DeployUnitError(f"{where}.pattern is empty or too long")
        try:
            re.compile(pattern)
        except re.error:
            raise DeployUnitError(
                f"{where}.pattern is not a valid expression"
            ) from None
    base = ParamSpec(
        name=name,
        type=str(kind),
        material=material,
        required_in=required_in,
        minimum=minimum,
        maximum=maximum,
        min_length=_opt_int(where, table, "min_length"),
        max_length=_opt_int(where, table, "max_length"),
        pattern=pattern,
        jobs=_string_list(f"{where}.jobs", table.get("jobs", [])),
    )
    if len(set(base.jobs)) != len(base.jobs):
        raise DeployUnitError(f"{where}.jobs lists a job twice")
    try:
        choices = tuple(_validate_typed(base, c) for c in raw_choices)
        spec = replace(base, choices=choices)
        default = table.get("default")
        rendered_default = (
            None if default is None else validate_param_value(spec, default)
        )
    except ParamRefusedError as exc:
        raise DeployUnitError(f"{where}: {exc}") from None
    return replace(spec, default=rendered_default)


def _parse_binding(index: int, table: object, product: str) -> BindingSpec:
    where = f"bindings[{index}]"
    if not isinstance(table, dict):
        raise DeployUnitError(f"{where} must be a table")
    _only_keys(where, table, _BINDING_KEYS)
    name = table.get("name")
    if not isinstance(name, str) or not _MATERIAL.fullmatch(name):
        raise DeployUnitError(f"{where}.name is not a valid binding name")
    for key in ("kind", "writer", "rotation"):
        if not isinstance(table.get(key), str) or not table.get(key):
            raise DeployUnitError(f"{where}.{key} is required")
    if table["rotation"] not in BINDING_ROTATIONS:
        raise DeployUnitError(
            f"{where}.rotation must be one of {sorted(BINDING_ROTATIONS)}"
        )
    state = table.get("state", BINDING_ACTIVE)
    if state not in BINDING_STATES:
        raise DeployUnitError(f"{where}.state must be active or pre_staged")
    single_use = table.get("single_use", False)
    if not isinstance(single_use, bool):
        raise DeployUnitError(f"{where}.single_use must be a boolean")
    roles = _string_list(f"{where}.roles", table.get("roles", []))
    if not roles:
        raise DeployUnitError(f"{where}.roles must not be empty")
    for key in table:
        if key in ("secret_ref", "value"):  # pragma: no cover - keys are closed
            raise DeployUnitError(f"{where} carries a value")
    return BindingSpec(
        name=name,
        kind=str(table["kind"]),
        roles=roles,
        writer=str(table["writer"]),
        rotation=str(table["rotation"]),
        single_use=single_use,
        state=str(state),
    )


def _parse_job(index: int, table: object) -> JobSpec:
    where = f"jobs[{index}]"
    if not isinstance(table, dict):
        raise DeployUnitError(f"{where} must be a table")
    _only_keys(where, table, _JOB_KEYS)
    name = table.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name.replace("-", "_")):
        raise DeployUnitError(f"{where}.name is not well formed")
    command = _string_list(f"{where}.command", table.get("command"))
    if not command or any(not part or "\x00" in part for part in command):
        raise DeployUnitError(f"{where}.command must be a non-empty argument list")
    if table.get("trigger") not in JOB_TRIGGERS:
        raise DeployUnitError(f"{where}.trigger must be one of {sorted(JOB_TRIGGERS)}")
    materials = _string_list(f"{where}.materials", table.get("materials", []))
    if not all(_MATERIAL.fullmatch(m) for m in materials):
        raise DeployUnitError(f"{where}.materials must be material names")
    runbook = table.get("runbook")
    if (
        not isinstance(runbook, str)
        or not runbook
        or runbook.startswith("/")
        or ".." in runbook.split("/")
    ):
        raise DeployUnitError(f"{where}.runbook must be a repository-relative path")
    role = table.get("role")
    if role is not None and (not isinstance(role, str) or not _SEGMENT.fullmatch(role)):
        raise DeployUnitError(f"{where}.role is a lowercase segment")
    return JobSpec(
        name=name,
        command=command,
        trigger=str(table["trigger"]),
        materials=materials,
        runbook=runbook,
        role=role,
    )


def _parse_hold_point(index: int, table: object) -> HoldPointSpec:
    where = f"hold_points[{index}]"
    if not isinstance(table, dict):
        raise DeployUnitError(f"{where} must be a table")
    _only_keys(where, table, _HOLD_KEYS)
    name = table.get("name")
    if not isinstance(name, str) or not _NAME.fullmatch(name.replace("-", "_")):
        raise DeployUnitError(f"{where}.name is not well formed")
    for key, allowed in (
        ("member", HOLD_MEMBERS),
        ("before", HOLD_BEFORE),
        ("on_timeout", HOLD_ON_TIMEOUT),
        ("released_by", HOLD_RELEASED_BY),
    ):
        if table.get(key) not in allowed:
            raise DeployUnitError(f"{where}.{key} must be one of {sorted(allowed)}")
    timeout_param = table.get("timeout_param")
    if not isinstance(timeout_param, str):
        raise DeployUnitError(f"{where}.timeout_param is required")
    return HoldPointSpec(
        name=name,
        member=str(table["member"]),
        before=str(table["before"]),
        timeout_param=timeout_param,
        on_timeout=str(table["on_timeout"]),
        released_by=str(table["released_by"]),
    )


def _parse_companion(index: int, table: object) -> CompanionSpec:
    where = f"companions[{index}]"
    if not isinstance(table, dict):
        raise DeployUnitError(f"{where} must be a table")
    _only_keys(where, table, _COMPANION_KEYS)
    for key in ("product", "descriptor", "host"):
        if not isinstance(table.get(key), str) or not table.get(key):
            raise DeployUnitError(f"{where}.{key} is required")
    order = table.get("order", "after_primary_ready")
    if order != "after_primary_ready":
        raise DeployUnitError(f"{where}.order must be after_primary_ready")
    required = table.get("required_at_switch", False)
    if not isinstance(required, bool):
        raise DeployUnitError(f"{where}.required_at_switch must be a boolean")
    if not _HOST.fullmatch(str(table["host"])):
        raise DeployUnitError(f"{where}.host is `same` or a host alias")
    return CompanionSpec(
        product=str(table["product"]),
        descriptor=str(table["descriptor"]),
        order=order,
        required_at_switch=required,
        host=str(table["host"]),
    )


def parse_deploy_unit(
    text: str,
    *,
    descriptor_path: str = DEFAULT_DESCRIPTOR_PATH,
    legacy_allowed: bool = False,
) -> DeployUnit:
    """Parse and structurally validate a `deploy-unit.toml`.

    `descriptor_path` is where the descriptor lives in its repository; a path
    under `deploy/companion/` always refuses `[legacy_env_file]`. `legacy_allowed`
    is True only for a target on the setting `legacy_env_file_allowed_targets`.
    Refusals are `DeployUnitError`.
    """
    try:
        document = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise DeployUnitError(f"the descriptor is not valid TOML: {exc}") from None
    _only_keys("descriptor", document, _TOP_KEYS)
    if document.get("schema") != DESCRIPTOR_SCHEMA:
        raise DeployUnitError(f"the descriptor schema must be {DESCRIPTOR_SCHEMA}")
    product = document.get("product")
    if not isinstance(product, str) or not _PRODUCT.fullmatch(product):
        raise DeployUnitError("the descriptor product is not well formed")
    namespace = document.get("secrets_namespace")
    if not isinstance(namespace, str) or not _SEGMENT.fullmatch(namespace):
        raise DeployUnitError(
            "secrets_namespace is required: the lowercase <product> segment of "
            "the OpenBao layout <env>/<product> (for example erp)"
        )
    spec = document.get("spec")
    sibling = "/".join([*_normal_parts(descriptor_path)[:-1], "product.toml"])
    if spec != sibling:
        raise DeployUnitError(f"spec must be {sibling}, the product.toml beside it")

    raw_params = document.get("params", {})
    if not isinstance(raw_params, dict):
        raise DeployUnitError("params must be a table of tables")
    params = {name: _parse_param(name, t) for name, t in raw_params.items()}
    materials = [p.material for p in params.values() if p.material is not None]
    if len(set(materials)) != len(materials):
        raise DeployUnitError("two params claim the same material")
    if APP_IMAGE_MATERIAL in materials:
        raise DeployUnitError(f"{APP_IMAGE_MATERIAL} is reserved for the plan")

    raw_bindings = document.get("bindings", [])
    if not isinstance(raw_bindings, list):
        raise DeployUnitError("bindings must be an array of tables")
    bindings = tuple(_parse_binding(i, t, product) for i, t in enumerate(raw_bindings))
    if len({b.name for b in bindings}) != len(bindings):
        raise DeployUnitError("two bindings share a name")
    role_modes: dict[str, bool] = {}
    for binding in bindings:
        for role in binding.roles:
            if not _SEGMENT.fullmatch(role):
                raise DeployUnitError(f"role {role!r} is not a lowercase segment")
            if role_modes.setdefault(role, binding.single_use) != binding.single_use:
                raise DeployUnitError(
                    f"role {role!r} mixes single-use and reusable bindings; a "
                    "role has one secret_id and so one mode (split the binding)"
                )

    raw_companions = document.get("companions", [])
    if not isinstance(raw_companions, list):
        raise DeployUnitError("companions must be an array of tables")
    companions = tuple(_parse_companion(i, t) for i, t in enumerate(raw_companions))

    image = document.get("image", {})
    if not isinstance(image, dict):
        raise DeployUnitError("image must be a table")
    _only_keys("image", image, frozenset({"source"}))
    source = image.get("source", DEFAULT_IMAGE_SOURCE)
    if source not in IMAGE_SOURCES:
        raise DeployUnitError("image.source must be transfer or pull")

    health = document.get("health", {})
    if not isinstance(health, dict):
        raise DeployUnitError("health must be a table")
    _only_keys("health", health, frozenset({"gates"}))
    gates = _string_list("health.gates", health.get("gates", []))
    if len(set(gates)) != len(gates) or not set(gates) <= HEALTH_GATES:
        raise DeployUnitError(
            f"health.gates must be unique members of {sorted(HEALTH_GATES)}"
        )

    raw_jobs = document.get("jobs", [])
    if not isinstance(raw_jobs, list):
        raise DeployUnitError("jobs must be an array of tables")
    jobs = tuple(_parse_job(i, t) for i, t in enumerate(raw_jobs))
    if len({j.name for j in jobs}) != len(jobs):
        raise DeployUnitError("two jobs share a name")
    job_names = {j.name for j in jobs}
    for pname, pspec in params.items():
        unknown_jobs = sorted(set(pspec.jobs) - job_names)
        if unknown_jobs:
            raise DeployUnitError(
                f"params.{pname}.jobs names unknown jobs: {', '.join(unknown_jobs)}"
            )
        if pspec.jobs and pspec.material is None:
            raise DeployUnitError(
                f"params.{pname} is job-scoped and needs a material to render"
            )
        if pspec.material in JOB_ONLY_MATERIALS and not pspec.jobs:
            raise DeployUnitError(
                f"params.{pname}: {pspec.material} belongs to a dispatched job "
                "and may not be an app material; scope the param to its job"
            )
    binding_roles = {role for b in bindings for role in b.roles}
    for job in jobs:
        if job.role is not None and job.role not in binding_roles:
            raise DeployUnitError(
                f"job {job.name!r} logs in as role {job.role!r}, which no binding has"
            )
    known = {p.material for p in params.values() if p.material} | {
        b.name for b in bindings
    }
    for job in jobs:
        unknown_materials = sorted(set(job.materials) - known)
        if unknown_materials:
            raise DeployUnitError(
                f"job {job.name!r} names unknown materials: "
                f"{', '.join(unknown_materials)}"
            )

    raw_holds = document.get("hold_points", [])
    if not isinstance(raw_holds, list):
        raise DeployUnitError("hold_points must be an array of tables")
    hold_points = tuple(_parse_hold_point(i, t) for i, t in enumerate(raw_holds))
    if len({h.name for h in hold_points}) != len(hold_points):
        raise DeployUnitError("two hold points share a name")
    for hold in hold_points:
        timeout = params.get(hold.timeout_param)
        if timeout is None or timeout.type != "duration_seconds":
            raise DeployUnitError(
                f"hold point {hold.name!r}: timeout_param must name a "
                "duration_seconds param"
            )
        if timeout.maximum is None:
            raise DeployUnitError(
                f"hold point {hold.name!r}: the timeout param needs a max, so the "
                "wait is bounded"
            )

    legacy = _parse_legacy(
        document.get("legacy_env_file"),
        product=product,
        companion=is_companion_descriptor_path(descriptor_path),
        legacy_allowed=legacy_allowed,
        params=params,
        bindings=bindings,
    )
    return DeployUnit(
        product=product,
        spec=str(spec),
        secrets_namespace=namespace,
        digest=DeployUnitDigestV1.over_bytes(text.encode()).canonical,
        params=params,
        bindings=bindings,
        companions=companions,
        image_source=str(source),
        health_gates=gates,
        jobs=jobs,
        hold_points=hold_points,
        legacy_env_file=legacy,
    )


def _parse_legacy(
    table: object,
    *,
    product: str,
    companion: bool,
    legacy_allowed: bool,
    params: Mapping[str, ParamSpec],
    bindings: Sequence[BindingSpec],
) -> LegacyEnvFileSpec | None:
    if table is None:
        return None
    if companion:
        raise DeployUnitError(
            "[legacy_env_file] is always refused for a deploy/companion/ descriptor"
        )
    if not legacy_allowed:
        raise DeployUnitError(
            "[legacy_env_file] is refused: this target is not on "
            "legacy_env_file_allowed_targets (default-deny)"
        )
    if not isinstance(table, dict):
        raise DeployUnitError("legacy_env_file must be a table")
    _only_keys("legacy_env_file", table, frozenset({"names", "path_param"}))
    names = _string_list("legacy_env_file.names", table.get("names"))
    if not names or len(set(names)) != len(names):
        raise DeployUnitError("legacy_env_file.names must be non-empty and unique")
    for name in names:
        if not _MATERIAL.fullmatch(name):
            raise DeployUnitError("a legacy_env_file name is not a material name")
    path_param = table.get("path_param")
    if not isinstance(path_param, str) or path_param not in params:
        raise DeployUnitError("legacy_env_file.path_param must name a declared param")
    if params[path_param].type != "path":
        raise DeployUnitError("legacy_env_file.path_param must be a path param")
    # L2: a collision is refused only with an ACTIVE binding. A pre-staged
    # binding may reuse a legacy name; activating it later is refused by
    # `legacy_policy` until the name is retired from the policy.
    taken = {p.material for p in params.values() if p.material} | {
        b.name for b in bindings if b.state == BINDING_ACTIVE
    }
    taken.add(APP_IMAGE_MATERIAL)
    job_only = sorted(set(names) & JOB_ONLY_MATERIALS)
    if job_only:
        raise DeployUnitError(
            "legacy_env_file names may never include a dispatched job's "
            f"credentials: {', '.join(job_only)}"
        )
    collisions = sorted(set(names) & taken)
    if collisions:
        raise DeployUnitError(
            "legacy_env_file names collide with a param material, an active binding or "
            f"APP_IMAGE: {', '.join(collisions)}"
        )
    return LegacyEnvFileSpec(names=tuple(sorted(names)), path_param=path_param)
