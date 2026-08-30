# Control exceptions

Controls this repository claims, where the claim is narrower than it sounds.
Each entry states what is enforced, what is NOT, and by whom — so that a reader
does not infer coverage that does not exist.

## 0.1.0a3 is published, immutable, and must never be pinned

**Status:** permanent. Not a gap to close — a fact to keep visible.

`0.1.0a3` was published by release run `33295149495`, which was **cancelled
during its own verify job**. The upload succeeded; the authenticated read-back,
the consumer proof and the tag never ran. Verify run `33296262948` returned
**UNPROVABLE**.

Both artifacts were subsequently confirmed byte-correct out of band — wheel
45,911 bytes and sdist 42,256 bytes, each sha256-matching what the release run
built. **The bytes are sound. The evidence chain is not**, and it cannot be
repaired after the fact: the proofs that were skipped were meant to run against
that publication, in that order, before the tag asserted them.

Michael ruled on 2026-08-30: do not tag, adopt, overwrite or delete it. An index
cannot un-publish, so a3 exists permanently and the only available control is to
make it unpinnable. `docs/published-versions.json` records it with
`pinnable: false`, `scripts/release_guard.py` refuses it by name with a distinct
message, and the release floor moves through it — a floor that skipped a3 would
let a later release collide with bytes that are permanently there.

**What is NOT enforced:** nothing stops a consumer outside this repository
pinning `==0.1.0a3` from the index. The refusal is a publish-side control, and
no server-side mechanism exists to withdraw a version. The compensating control
is the record itself.

## The publisher's identity IS asserted — resolved 2026-08-30

**Status:** closed. Recorded rather than deleted, because the reasoning that
looked like a dead end is the reasoning a future reader will repeat.

The earlier entry said this was unimplementable as specified: a
`write:package`-only token returned 403 from `/api/v1/user`, so the preflight
could not compare an identity, and the honest outcome was to record that rather
than soften the check into "a token exists and can reach the registry".

**What was actually wrong was the diagnosis, not the requirement.** Scopes and
package reach turned out to be two different mechanisms:

- `read:package` was **normalised away** by Forgejo, implied by `write:package`,
  and the token still 401'd on the index. The scope string was a red herring.
- Package access is granted by **org team membership**. A team carrying only
  unit type 9 (packages) at write made the index read succeed immediately, while
  every repository endpoint stayed 403.
- The account is **not** `restricted`. That flag was set initially, broke index
  reads, and removing it changed no refusal — so it never provided containment
  and must not be cited as though it did.

So the preflight asserts **behaviour, never a scope string**: `/api/v1/user`
returns exactly `dotmac-deployment-control-publisher`, and a package-namespace
read returns 200. It additionally re-proves that the credential cannot reach
repositories, because a publish token that can read source has a different blast
radius than the one recorded here.

**The general lesson, which outlives this entry:** a permission system can have
two independent mechanisms where the documented one is the more visible. Asserting
on configuration would have passed with the token that did not work and would
pass again with a token whose team membership was later removed.

## Publisher scope cannot be restricted to one package NAME

**Status:** open, structural, and now the only remaining gap.

Forgejo packages belong to the **owner**. Registry permission is
owner/package-namespace scoped, so a credential that may publish
`dotmac-deployment-control` under `dotmac` may publish **any** package under
that owner. Repository linkage does not narrow it, and the packages-only team
above stops repository access without touching package-name reach.

**The protected workflow is the boundary, and nothing on the Forgejo side is.**
`.github/workflows/release.yml` refuses a foreign distribution before any build
or upload, refuses a version at or below the inherited floor, requires the exact
protected-main SHA, refuses a conflicting re-upload, reads the published version
back as the publisher before tagging, and carries an unconditional identity
preflight. `tests/architecture/test_release_workflow_structure.py` is the sixth
layer: it exists because the first five are each removable by one line, and each
removal leaves a workflow that still runs and still goes green.

Compensating controls: a dedicated principal with no repository permissions;
`write:package` only; a packages-only team; and the credential held in the
protected `registry-release` environment with
`deployment_branch_policy.protected_branches = true`, so a job using it must
declare that environment and can only run from a protected branch.

**Preferred replacement.** Authorized Integrations would issue short-lived
OIDC/JWT bound to this repository, workflow and protected ref. The capability
endpoint is scope-blocked from the tokens available, so an administrator must
confirm availability on Forgejo `11.0.16`.

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
