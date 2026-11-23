"""The agent observation envelope (target_api v2): one ingestion path, owned here.

The deploy agent reports what it did (a deploy, a reconcile, a role job) as a
statement signed by the target's PoP key, in an envelope Control parses with its
own strict parser. `record_observation` ingests it exactly as it ingests the v1
execution observation: every arrival becomes an attempt, the signature is
verified against the ENROLLED credential Control selects by `key_id`, and the
statement's `target_ref` must equal the credential's target.

Domain separation: the signed bytes are the canonical JSON of the statement and
begin `{"details"` after key sorting; the schema string inside them is
`dotmac.agent-observation/2`. A target REQUEST is signed over LF-joined text that
begins `dotmac.target_request.v1`, so the two byte domains never parse as each
other (a test pins both directions). The same Ed25519 key signs both.

Pure: no I/O. The cryptographic primitive is the injected
`ExecutionObservationVerifier` (kernel-backed in the composing control plane).
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any, Final

from dotmac_deployment_control.digests import canonical_json
from dotmac_deployment_control.execution_observation import (
    EXECUTION_OBSERVATION_PURPOSE,
    ExecutionObservationRefusalCode,
    ExecutionObservationRefusedError,
    ExecutionObservationVerificationKey,
    ExecutionObservationVerifier,
    _bounded_text,
    _exact_mapping,
    _mapping_without_duplicate_keys,
    _refuse_non_json_number,
    _refused,
    _text,
)

AGENT_OBSERVATION_SCHEMA: Final = "dotmac.agent-observation/2"
MAX_AGENT_OBSERVATION_BYTES: Final = 65_536
MAX_DETAILS_BYTES: Final = 16_384
MAX_DETAILS_DEPTH: Final = 4
#: `kind -> the outcomes it may report`. A deploy and a job report the same three;
#: a reconcile reports how the expired, unreleased lease was settled.
KIND_OUTCOMES: Final = {
    "deploy": ("succeeded", "failed", "refused"),
    "job": ("succeeded", "failed", "refused"),
    "reconcile": ("reconciled", "failed", "not_needed"),
}
_STATEMENT_KEYS: Final = frozenset(
    {
        "schema",
        "kind",
        "dispatch_id",
        "target_ref",
        "key_id",
        "outcome",
        "reason",
        "details",
        "observed_at",
    }
)
_STAMP: Final = re.compile(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z")


def _stamp(value: datetime) -> str:
    if value.tzinfo is None:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED, "observed_at needs a timezone"
        )
    return value.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _json_safe(value: object, depth: int) -> None:
    if depth > MAX_DETAILS_DEPTH:
        raise _refused(
            ExecutionObservationRefusalCode.MALFORMED,
            f"details nest deeper than {MAX_DETAILS_DEPTH}",
        )
    if value is None or isinstance(value, bool | int | str):
        return
    if isinstance(value, list):
        for item in value:
            _json_safe(item, depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise _refused(
                    ExecutionObservationRefusalCode.MALFORMED,
                    "details keys are strings",
                )
            _json_safe(item, depth + 1)
        return
    raise _refused(
        ExecutionObservationRefusalCode.MALFORMED,
        "details hold JSON values only (no floats, no other types)",
    )


@dataclass(frozen=True, slots=True)
class AgentObservationStatementV2:
    kind: str
    dispatch_id: str
    target_ref: str
    key_id: str
    outcome: str
    reason: str
    details: Mapping[str, Any]
    observed_at: str

    def __post_init__(self) -> None:
        if self.kind not in KIND_OUTCOMES:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"kind is one of {sorted(KIND_OUTCOMES)}",
            )
        for field in ("dispatch_id", "target_ref", "key_id"):
            _bounded_text(getattr(self, field), field=field, maximum=200)
        if self.outcome not in KIND_OUTCOMES[self.kind]:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"a {self.kind} observation reports "
                f"{list(KIND_OUTCOMES[self.kind])}, not {self.outcome!r}",
            )
        if (
            not isinstance(self.reason, str)
            or len(self.reason) > 512
            or self.reason != self.reason.strip()
        ):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "reason is a whitespace-exact string of at most 512 characters",
            )
        if not isinstance(self.details, dict):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED, "details is an object"
            )
        _json_safe(self.details, 1)
        if len(canonical_json(self.details)) > MAX_DETAILS_BYTES:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"details exceed {MAX_DETAILS_BYTES} bytes",
            )
        if not isinstance(self.observed_at, str) or not _STAMP.fullmatch(
            self.observed_at
        ):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "observed_at is canonical UTC YYYY-MM-DDTHH:MM:SSZ",
            )

    @property
    def report_id(self) -> str:
        """The ledger business key: one report per dispatch and kind."""
        return f"agent:{self.kind}:{self.dispatch_id}"

    def as_mapping(self) -> dict[str, Any]:
        return {
            "schema": AGENT_OBSERVATION_SCHEMA,
            "kind": self.kind,
            "dispatch_id": self.dispatch_id,
            "target_ref": self.target_ref,
            "key_id": self.key_id,
            "outcome": self.outcome,
            "reason": self.reason,
            "details": dict(self.details),
            "observed_at": self.observed_at,
        }

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())


@dataclass(frozen=True, slots=True)
class AgentObservationEnvelopeV2:
    statement: AgentObservationStatementV2
    signature: str

    def __post_init__(self) -> None:
        _bounded_text(self.signature, field="signature", maximum=1024)

    def as_mapping(self) -> dict[str, Any]:
        return {"statement": self.statement.as_mapping(), "signature": self.signature}

    @property
    def canonical_bytes(self) -> bytes:
        return canonical_json(self.as_mapping())

    @classmethod
    def parse(cls, value: object) -> AgentObservationEnvelopeV2:
        row = _exact_mapping(value, {"statement", "signature"}, where="envelope")
        signature = row["signature"]
        if not isinstance(signature, str) or not signature:
            raise _refused(
                ExecutionObservationRefusalCode.UNSIGNED,
                "the agent observation carries no signature",
            )
        body = _exact_mapping(row["statement"], set(_STATEMENT_KEYS), where="statement")
        if body["schema"] != AGENT_OBSERVATION_SCHEMA:
            raise _refused(
                ExecutionObservationRefusalCode.UNSUPPORTED_VERSION,
                f"schema is {AGENT_OBSERVATION_SCHEMA}",
            )
        details = body["details"]
        if not isinstance(details, dict):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED, "details is an object"
            )
        statement = AgentObservationStatementV2(
            kind=_text(body, "kind"),
            dispatch_id=_text(body, "dispatch_id"),
            target_ref=_text(body, "target_ref"),
            key_id=_text(body, "key_id"),
            outcome=_text(body, "outcome"),
            reason=_text(body, "reason"),
            details=details,
            observed_at=_text(body, "observed_at"),
        )
        return cls(statement=statement, signature=signature)

    @classmethod
    def parse_bytes(cls, value: bytes) -> AgentObservationEnvelopeV2:
        """Parse the exact bounded wire bytes, refusing ambiguous JSON."""
        if not isinstance(value, bytes):
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED, "the wire value is bytes"
            )
        if len(value) > MAX_AGENT_OBSERVATION_BYTES:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                f"the agent observation exceeds {MAX_AGENT_OBSERVATION_BYTES} bytes",
            )
        try:
            decoded = json.loads(
                value.decode("utf-8"),
                object_pairs_hook=_mapping_without_duplicate_keys,
                parse_constant=_refuse_non_json_number,
                parse_float=_refuse_float,
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise _refused(
                ExecutionObservationRefusalCode.MALFORMED,
                "the agent observation is not UTF-8 JSON",
            ) from exc
        return cls.parse(decoded)


def _refuse_float(text: str) -> Any:
    raise _refused(
        ExecutionObservationRefusalCode.MALFORMED,
        f"the agent observation carries a float ({text!r}); there are none",
    )


def issue_agent_observation_envelope(
    fields: Mapping[str, Any], *, sign: Callable[[bytes], str]
) -> AgentObservationEnvelopeV2:
    """Build and sign one envelope (the agent's side; used by the vectors)."""
    values = dict(fields)
    if isinstance(values.get("observed_at"), datetime):
        values["observed_at"] = _stamp(values["observed_at"])
    statement = AgentObservationStatementV2(**values)
    signature = sign(statement.canonical_bytes)
    return AgentObservationEnvelopeV2(statement=statement, signature=signature)


def verify_agent_observation_envelope(
    value: object,
    *,
    verifier: ExecutionObservationVerifier,
    verification_key: ExecutionObservationVerificationKey,
) -> AgentObservationEnvelopeV2:
    """The signed key id must be the enrolled one, and the signature must verify
    over the statement's canonical bytes under the enrolled public key."""
    if not isinstance(verifier, ExecutionObservationVerifier):
        raise _refused(
            ExecutionObservationRefusalCode.PURPOSE_MISMATCH,
            "the injected verifier is not an observation verifier",
        )
    envelope = (
        value
        if isinstance(value, AgentObservationEnvelopeV2)
        else AgentObservationEnvelopeV2.parse(value)
    )
    statement = envelope.statement
    if (
        statement.key_id != verification_key.key_id
        or verification_key.purpose != EXECUTION_OBSERVATION_PURPOSE
    ):
        raise _refused(
            ExecutionObservationRefusalCode.SIGNATURE_INVALID,
            "the signed key id is not the enrolled verification identity",
        )
    if not verifier.verify_execution_observation(
        key_id=verification_key.key_id,
        algorithm=verification_key.algorithm,
        purpose=verification_key.purpose,
        public_key_b64=verification_key.public_key_b64,
        public_key_fingerprint=verification_key.public_key_fingerprint,
        canonical_bytes=statement.canonical_bytes,
        signature=envelope.signature,
    ):
        raise _refused(
            ExecutionObservationRefusalCode.SIGNATURE_INVALID,
            "the injected verifier refused the signature",
        )
    return envelope


__all__ = [
    "AGENT_OBSERVATION_SCHEMA",
    "KIND_OUTCOMES",
    "AgentObservationEnvelopeV2",
    "AgentObservationStatementV2",
    "ExecutionObservationRefusedError",
    "issue_agent_observation_envelope",
    "verify_agent_observation_envelope",
]
