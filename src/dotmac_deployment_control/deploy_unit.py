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
descriptor's `names` and `path_param`, and refuses the table for a product on
the `legacy_never` list.
"""

from __future__ import annotations

import hashlib
import ipaddress
import math
import re
import tomllib
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

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

#: Products on which `[legacy_env_file]` is refused at parse. `sub_thin` is a new
#: build, and every `deploy/companion/` descriptor is new by construction. The
#: set is a Control setting in the fleet; this is its default.
LEGACY_NEVER_DEFAULT: Final = frozenset({"sub_thin"})

_MATERIAL = re.compile(r"[A-Z][A-Z0-9_]{0,127}")
_NAME = re.compile(r"[a-z][a-z0-9_]{0,63}")
_PRODUCT = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
_SEGMENT = re.compile(r"[a-z0-9][a-z0-9._-]{0,63}")
_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
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
_HIGH_ENTROPY_RUN = re.compile(r"[A-Za-z0-9+_=-]{32,}")

_DEFAULT_MAX_LENGTH = 512
_MAX_PATH_LENGTH = 1024
_MAX_DURATION_SECONDS = 31_536_000


class DeployUnitError(ValueError):
    """A descriptor or a param value was refused. The message names the cause."""


class ParamRefusedError(DeployUnitError):
    """A param value (or the set of values) was refused by the grammar."""


def _sha256_digest(payload: bytes) -> str:
    return "sha256:" + hashlib.sha256(payload).hexdigest()


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
    choices: tuple[str, ...] = ()


@dataclass(frozen=True, slots=True)
class BindingSpec:
    name: str
    kind: str
    roles: tuple[str, ...]
    writer: str
    rotation: str
    single_use: bool


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
    spec_digest: str | None
    params: Mapping[str, ParamSpec]
    bindings: tuple[BindingSpec, ...]
    companions: tuple[CompanionSpec, ...]
    #: `transfer` unless the descriptor says otherwise AND Control later allows
    #: it (see `image_policy`). Absence of `[image]` is `transfer`.
    image_source: str
    health: Mapping[str, Any]
    legacy_env_file: LegacyEnvFileSpec | None


@dataclass(frozen=True, slots=True)
class SecretRef:
    environment: str
    product: str
    role: str
    binding: str

    def render(self) -> str:
        return f"bao://{self.environment}/{self.product}/kv/{self.role}/{self.binding}"


# ── secret_ref ──────────────────────────────────────────────────────────────


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
        if value not in spec.choices:
            raise _refuse(name, "is not one of the declared choices")
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
        if not _DIGEST.fullmatch(value):
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
        if material is None:
            continue
        if material in lines or material == APP_IMAGE_MATERIAL:
            raise ParamRefusedError(f"material {material!r} is claimed twice")
        lines[material] = text
    lines[APP_IMAGE_MATERIAL] = app_image
    return "".join(f"{key}={lines[key]}\n" for key in sorted(lines)).encode()


def params_env_digest(render: bytes) -> str:
    """`sha256:<hex>` over the canonical render, as bound into the plan."""
    return _sha256_digest(render)


# ── Parsing ─────────────────────────────────────────────────────────────────

_TOP_KEYS = frozenset(
    {
        "schema",
        "product",
        "spec",
        "spec_digest",
        "params",
        "bindings",
        "companions",
        "image",
        "health",
        "legacy_env_file",
    }
)
_PARAM_KEYS = frozenset(
    {
        "type",
        "required_in",
        "material",
        "minimum",
        "maximum",
        "min_length",
        "max_length",
        "choices",
    }
)
_BINDING_KEYS = frozenset({"name", "kind", "roles", "writer", "rotation", "single_use"})
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
    choices = _string_list(f"{where}.choices", table.get("choices", []))
    if kind == "enum" and not choices:
        raise DeployUnitError(f"{where}: an enum declares its choices")
    if kind != "enum" and choices:
        raise DeployUnitError(f"{where}: only an enum declares choices")
    required_in = frozenset(
        _string_list(f"{where}.required_in", table.get("required_in", []))
    )
    minimum = _opt_int(where, table, "minimum")
    maximum = _opt_int(where, table, "maximum")
    if minimum is not None and maximum is not None and minimum > maximum:
        raise DeployUnitError(f"{where}: minimum exceeds maximum")
    return ParamSpec(
        name=name,
        type=str(kind),
        material=material,
        required_in=required_in,
        minimum=minimum,
        maximum=maximum,
        min_length=_opt_int(where, table, "min_length"),
        max_length=_opt_int(where, table, "max_length"),
        choices=choices,
    )


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
    companion: bool = False,
    legacy_never: frozenset[str] = LEGACY_NEVER_DEFAULT,
) -> DeployUnit:
    """Parse and structurally validate a `deploy-unit.toml`.

    `companion` is true for a `deploy/companion/` descriptor: it is on the
    `legacy_never` list by construction. Refusals are `DeployUnitError`.
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
    spec = document.get("spec")
    if spec != "deploy/product.toml":
        raise DeployUnitError("spec must be deploy/product.toml")
    spec_digest = document.get("spec_digest")
    if spec_digest is not None and not (
        isinstance(spec_digest, str) and _DIGEST.fullmatch(spec_digest)
    ):
        raise DeployUnitError("spec_digest must be sha256:<64 lowercase hex>")

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

    legacy = _parse_legacy(
        document.get("legacy_env_file"),
        product=product,
        companion=companion,
        legacy_never=legacy_never,
        params=params,
        bindings=bindings,
    )
    return DeployUnit(
        product=product,
        spec=str(spec),
        spec_digest=spec_digest,
        params=params,
        bindings=bindings,
        companions=companions,
        image_source=str(source),
        health=health,
        legacy_env_file=legacy,
    )


def _parse_legacy(
    table: object,
    *,
    product: str,
    companion: bool,
    legacy_never: frozenset[str],
    params: Mapping[str, ParamSpec],
    bindings: Sequence[BindingSpec],
) -> LegacyEnvFileSpec | None:
    if table is None:
        return None
    if companion or product in legacy_never:
        raise DeployUnitError(
            "[legacy_env_file] is refused for this product: it is on the "
            "legacy_never list (new builds and companions never use the bridge)"
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
    taken = {p.material for p in params.values() if p.material} | {
        b.name for b in bindings
    }
    taken.add(APP_IMAGE_MATERIAL)
    collisions = sorted(set(names) & taken)
    if collisions:
        raise DeployUnitError(
            "legacy_env_file names collide with a param material, a binding or "
            f"APP_IMAGE: {', '.join(collisions)}"
        )
    return LegacyEnvFileSpec(names=tuple(sorted(names)), path_param=path_param)
