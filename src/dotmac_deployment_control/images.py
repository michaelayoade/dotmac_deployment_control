"""The AUTHORIZED IMAGE SET — what an approval says may run, as a value.

## The defect this module exists to remove

Deployment Control's plan record carried no image field. The images a
deployment would run sat inside `desired_spec`, which this module declares
OPAQUE and never interprets — correctly, because interpreting a product's
deployment shape would make Control a second authority on what a deployment IS
(ADR-0003).

The consequence was measured by the Observability lane rather than guessed at.
Its promotion receipt requires `images` to equal the approved plan's image set;
with no image field to read, `authorized_images` was supplied by the promotion
CALLER, and the comparison proved only that the caller agreed with itself. A
receipt could say "what ran is what was approved" while nothing had checked
what was approved.

So an authorized image set becomes a FIRST-CLASS, TYPED, Control-owned term.
Note what did NOT change: `spec` is still opaque and Control still interprets
nothing inside it. This is a separate, declared field with a shape Control
defines and validates, which is precisely the difference between "the images
are in there somewhere" and "these are the images this plan authorizes".

## Inside the digest, never beside it

`service.plan_snapshot` puts the frozen set INSIDE the document `PlanDigestV1`
is taken over. That placement is the whole property, and the alternative is
worth naming because it is the tidier-looking one: a sibling
`deployment_plans.authorized_images` column would be a value an `UPDATE` can
move without the plan digest moving. An approval binds to the digest, so an
image set beside the digest is an image set the approval does not cover, and
"approved" would stop meaning what it says while every screen kept reading
correctly.

There is therefore no image column on `deployment_plans`. The frozen snapshot
is the record, and `tests/unit/test_authorized_image_set.py` plants an image
change and requires the digest to move.

## Order is canonicalized here, because a SET has no order

Two callers declaring the same three images in different orders must get the
same plan digest, or one approved image set has two identities — the a4 defect
in another costume. `authorized_image_set` sorts by
`(service, repository, digest)`.

This is not Control normalizing somebody else's value. The snapshot is
Control's own document, built from Control's own state, and ordering it is the
same act as `sort_keys=True` in `canonical_json`. Contrast
`ExecutionPlanDigestV1`, which Control refuses rather than reshapes precisely
because that value belongs to the Foundation.

## One digest per (service, repository), and duplicates are refused

Two entries naming the same service and repository make "which digest is
authorized here?" a question with two answers. Dedup would be an inference
about which one was meant, so it is refused instead — including an exact
duplicate, because a caller that sent one is not describing a set it has
thought about.

## Empty is a declaration; absent is not

`()` means *this plan authorizes no images*, and a receipt recording any image
contradicts it. NULL on the target means *no image set was ever declared*, and
a consumer must not read that as an empty set. `service.find_approved_plan`
refuses the second case rather than answering it, so the distinction cannot be
lost by a caller writing `or ()`.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from typing import Any

from dotmac_deployment_control.digests import ImageDigestV1
from dotmac_deployment_control.ports import DigestEncodingError, ImageSetRefusedError

#: Bounded like every other opaque reference on this plane. Not a registry
#: rule — Control does not own image naming — just a refusal to freeze an
#: unbounded string into a document an approval binds to.
MAX_NAME_LENGTH = 200

__all__ = [
    "MAX_NAME_LENGTH",
    "AuthorizedImage",
    "authorized_image_set",
    "image_set_from_payload",
    "image_set_payload",
]


def _require_name(value: object, *, field: str, where: str) -> str:
    if not isinstance(value, str):
        raise ImageSetRefusedError(
            f"{where}: an authorized image's {field} must be a string and this "
            f"is a {type(value).__name__}. An image set is frozen into the "
            "document a plan digest is taken over, so a value that cannot be "
            "written down cannot be authorized."
        )
    if not value:
        raise ImageSetRefusedError(
            f"{where}: an authorized image's {field} is empty. An image nobody "
            "can name is an image nobody can check a receipt against."
        )
    if value != value.strip():
        raise ImageSetRefusedError(
            f"{where}: an authorized image's {field} ({value!r}) carries "
            "leading or trailing whitespace. Stripping it here would make this "
            "module tolerant of a caller corrupting the value upstream, and "
            "one image name with two spellings is one image with two "
            "identities."
        )
    if len(value) > MAX_NAME_LENGTH:
        raise ImageSetRefusedError(
            f"{where}: an authorized image's {field} is {len(value)} "
            f"characters and the bound is {MAX_NAME_LENGTH}."
        )
    return value


@dataclass(frozen=True, slots=True)
class AuthorizedImage:
    """ONE image an approved plan authorizes: which service, from where, pinned.

    Three terms and not one string, because the Observability receipt compares
    exactly these three (`service`, `repository`, `digest`) and a single
    `repo@sha256:...` string would make Control's authorization and the
    consumer's comparison two different parsers of one format.

    `service` is the logical role the image fills in a deployment — the name an
    operator uses when asking what is running. `repository` is where the image
    came from. `digest` is `ImageDigestV1`, which is a digest and never a tag:
    a tag-pinned authorization authorizes whatever the tag points at later,
    under an approval nobody re-ran.

    Ordering is done by `authorized_image_set` over an explicit key rather
    than by `order=True` on this class. A generated ordering would compare the
    digest VALUE when two images shared a service and repository — a
    comparison whose answer is meaningless, and one that only never happens
    because the duplicate check runs first. An ordering that is correct by
    accident of another check's ordering is not an ordering.
    """

    service: str
    repository: str
    digest: ImageDigestV1

    @classmethod
    def parse(cls, value: object, *, where: str) -> AuthorizedImage:
        """Read one image from a mapping, refusing anything it cannot read.

        Refuses an unknown key rather than ignoring it. A caller that sent
        `sha256` where this expects `digest` has described an image this module
        did not freeze, and silently dropping the key would authorize the
        remaining two terms as though the third had been checked.
        """
        if isinstance(value, AuthorizedImage):
            return value
        if not isinstance(value, Mapping):
            raise ImageSetRefusedError(
                f"{where}: an authorized image must be a mapping with "
                f"'service', 'repository' and 'digest', and this is a "
                f"{type(value).__name__}."
            )
        unknown = sorted(set(map(str, value)) - {"service", "repository", "digest"})
        if unknown:
            raise ImageSetRefusedError(
                f"{where}: an authorized image carries unknown key(s) "
                f"{unknown}. Ignoring them would freeze a set that says less "
                "than the caller wrote, and the approval would cover the "
                "shorter one."
            )
        missing = sorted({"service", "repository", "digest"} - set(map(str, value)))
        if missing:
            raise ImageSetRefusedError(
                f"{where}: an authorized image is missing {missing}. There is "
                "no default for any of the three: an image set is what an "
                "approval authorizes, and an authorization is never inferred."
            )
        return cls(
            service=_require_name(value["service"], field="service", where=where),
            repository=_require_name(
                value["repository"], field="repository", where=where
            ),
            digest=_parse_digest(value["digest"], where=where),
        )

    def as_mapping(self) -> dict[str, str]:
        """The exact JSON shape frozen into the plan snapshot.

        The digest is rendered CANONICALLY (`sha256:<64 lowercase hex>`), which
        is the only text `ImageDigestV1.parse` accepts — so what is written is
        byte-identical to what can be read back, and a round trip through the
        snapshot cannot change a plan digest.
        """
        return {
            "service": self.service,
            "repository": self.repository,
            "digest": self.digest.canonical,
        }

    @property
    def reference(self) -> str:
        """`<repository>@<sha256:...>` — for an operator to read, never to parse.

        A rendering, not an identity. Nothing in this module compares two of
        these: the identity is the three typed terms.
        """
        return f"{self.repository}@{self.digest.canonical}"


def _parse_digest(value: object, *, where: str) -> ImageDigestV1:
    """A digest, refused rather than reshaped — including a tag.

    The refusal names the tag case explicitly, because it is the mistake a
    caller actually makes and "not 64 lowercase hex characters" would send them
    looking for a typo instead of at their pinning strategy.
    """
    try:
        return ImageDigestV1.parse(value)
    except DigestEncodingError as exc:
        raise ImageSetRefusedError(
            f"{where}: an authorized image must be pinned by DIGEST, as "
            f"canonical `sha256:<64 lowercase hex>`, and {value!r} is not one "
            f"({exc}). A tag is a mutable pointer: an image set pinned by tag "
            "authorizes whatever that tag names later, under an approval "
            "nobody re-ran and a plan digest that never moved."
        ) from exc


def authorized_image_set(
    values: Iterable[object] | None, *, where: str
) -> tuple[AuthorizedImage, ...] | None:
    """The canonical, ordered, duplicate-free image set — or `None` for absent.

    `None` in, `None` out, and that round trip is load-bearing: *no image set
    was declared* is a different fact from *this plan authorizes no images*,
    and a function that turned the first into `()` would delete the difference
    at the one boundary where it matters.
    """
    if values is None:
        return None
    if isinstance(values, str | bytes | Mapping):
        raise ImageSetRefusedError(
            f"{where}: an authorized image set is a sequence of images and "
            f"this is a {type(values).__name__}."
        )
    parsed = [AuthorizedImage.parse(value, where=where) for value in values]

    seen: dict[tuple[str, str], AuthorizedImage] = {}
    for image in parsed:
        key = (image.service, image.repository)
        previous = seen.get(key)
        if previous is not None:
            if previous.digest == image.digest:
                raise ImageSetRefusedError(
                    f"{where}: service {image.service!r} from repository "
                    f"{image.repository!r} appears twice with the same digest. "
                    "Collapsing it would be tidying a set the caller has not "
                    "checked, and a set with a repeated member is not a set."
                )
            raise ImageSetRefusedError(
                f"{where}: service {image.service!r} from repository "
                f"{image.repository!r} appears twice, pinned to "
                f"{previous.digest.canonical} and {image.digest.canonical}. "
                "Which one is authorized has two answers, and choosing either "
                "here would be this module inferring an authorization. Declare "
                "one digest per service and repository."
            )
        seen[key] = image
    # An EXPLICIT key — see `AuthorizedImage` on why this is not `order=True`.
    return tuple(
        sorted(parsed, key=lambda i: (i.service, i.repository, i.digest.canonical))
    )


def image_set_payload(
    images: Sequence[AuthorizedImage] | None,
) -> list[dict[str, str]] | None:
    """The JSON the snapshot and the target column hold. `None` stays `None`."""
    if images is None:
        return None
    return [image.as_mapping() for image in images]


def image_set_from_payload(
    payload: Any, *, where: str
) -> tuple[AuthorizedImage, ...] | None:
    """Read a stored set back, refusing a stored value this module cannot read.

    A data fault rather than a caller error, and it says so — the same
    three-way split `service._frozen_plan_digest` makes. Nothing in this
    package can write an unreadable set, so one found here is a corruption of
    the document an approval binds to, and answering a lookup against it would
    be worse than failing loudly.
    """
    if payload is None:
        return None
    try:
        return authorized_image_set(payload, where=where)
    except ImageSetRefusedError as exc:
        raise ImageSetRefusedError(
            f"{where} holds an authorized image set this module cannot read: "
            f"{exc} This is a data fault in a frozen plan, not a caller error. "
            "The set is inside the document the plan digest is taken over, so "
            "it cannot be repaired in place without invalidating the approval "
            "— investigate the row."
        ) from exc
