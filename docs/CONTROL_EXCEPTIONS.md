# Control exceptions

Controls this repository claims, where the claim is narrower than it sounds.
Each entry states what is enforced, what is NOT, and by whom — so that a reader
does not infer coverage that does not exist.

## Publisher scope cannot be restricted to one package name

**Status:** open, and structural rather than a configuration gap.

Forgejo packages belong to the **owner**, not to a repository. Write authority
is owner-scoped and repository linkage does not narrow it
(https://forgejo.org/docs/latest/user/packages/). A credential able to publish
`dotmac-deployment-control` under the `dotmac` owner is therefore able to
publish **any** package under that owner.

**Enforced elsewhere, deliberately.** `scripts/release_guard.py` refuses any
distribution but this one and any version at or below the inherited floor, and
the release workflow will be structurally restricted to this package, a version
strictly greater than a2, an exact protected-main SHA, immutable conflict
refusal, and a registry read-back before tagging.

**Not enforced by Forgejo.** All of the above is workflow-side. A credential
used outside this workflow is bounded only by the packages-write-only team it
belongs to. Compensating controls are: `write:package` scope only — no
repository, user, issue or administration scope; a dedicated principal with no
repository permissions; and storage in a protected `registry-release`
environment.

**Preferred replacement.** Authorized Integrations
(https://forgejo.org/docs/latest/user/api/authorized-integrations/) would issue
short-lived OIDC/JWT bound to this repository, workflow and protected ref. The
capability endpoint is scope-blocked from the tokens available, so an
administrator must confirm availability on the instance.

## The publisher's identity cannot be asserted with a `write:package`-only token

**Status:** open, and it is a genuine conflict between two requirements rather
than an oversight.

The release preflight is supposed to authenticate and compare the publisher's
**identity** — presence is not the property (`AGENTS.md` rule 39), and a token
that is valid but belongs to the Starter's publisher is exactly the case worth
catching, because it silently recreates the two-writer hazard the extraction
removed.

Measured against the live registry with an existing `read:package` token:

| Endpoint | Result |
| --- | --- |
| `/api/packages/dotmac/pypi/simple/dotmac-kernel/` | 200 |
| `/api/v1/packages/dotmac?type=pypi` | 200 |
| `/api/v1/version` | 200 (11.0.16+gitea-1.22.0) |
| `/api/v1/user` | 403 |
| `/api/v1/user/orgs` | 403 |
| `/api/v1/user/applications/oauth2` | 403 |

The 200s are the control: the token authenticates and reaches the registry, so
the 403s are **scope** refusals rather than authentication failures. A
`write:package`-only credential therefore cannot call `/api/v1/user`, and the
identity assertion the preflight needs cannot be made with the credential the
scope rule requires.

**This is recorded rather than worked around.** Weakening the preflight to "a
token exists and can reach the registry" would be the existence-not-identity
check rule 39 forbids, and the exact failure the design exists to prevent. Until
an identity assertion is available — an Authorized Integration, or a narrowly
added read scope accepted as a deliberate widening — step 7 of the publisher
design is **unimplementable as specified**, and this exception is the honest
record of that rather than a softer check pretending otherwise.

## The copied evidence vocabulary is pinned, not shared

**Status:** controlled.

`tests/architecture/adoption_evidence.py` belongs to `dotmac_starter_mt` and is
copied here because the dossier gate cannot run without it. Rule 24 permits a
one-time extraction and forbids a permanent fork. The control is a git blob-id
pin against a named source commit
(`tests/architecture/test_vocabulary_is_not_a_fork.py`), which fails if the copy
drifts and names the two legitimate repairs. What is NOT controlled: the Starter
changing its own copy. Nothing here watches that; the pin detects divergence
only when someone re-extracts.
