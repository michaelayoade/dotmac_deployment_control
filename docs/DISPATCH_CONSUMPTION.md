# Dispatch-consumption boundary

This document is the source of truth for Control's single-use dispatch
authority. It does not define an executor transport or launch adapter.

`_stage_dispatch_consumption` is an internal service seam. It accepts only a
Control attempt identifier and an independently resolved expected target
coordinate after trusted composition has authenticated a presenter. The
coordinate's `target_id` must come from the Control-stored credential selected
by that authentication, and its `target_ref` from the corresponding target row;
neither may come from the presented envelope. The coordinate is compared to the
locked target; it is not itself authentication. No production caller exists. It
does not accept an envelope, verifier or standing assertion from an untrusted
caller.

Within one caller-owned transaction, Control locks target, plan, rollout and
attempt in the same order as approval revocation; parses and compares the exact
stored authorization/dispatch coordinate; checks target liveness, rollout and
attempt state, authorization lifetime, and current approval standing; then calls
Kernel `execute_once_platform`. Its key is the stored signed dispatch id, its
scope is `deployment.consume_dispatch_challenge.v1`, its fingerprint is the
bare 64-hex form of the typed dispatch-envelope digest, and `expires_at` is
always `NULL`.

The service flushes but never commits. Its private staged result is not a launch
grant. An adapter may launch only after the transaction owner observes commit;
no such adapter is present in this distribution today. The marker and the
launch must never be reset or expired. If approval revocation commits first,
consumption refuses even though dispatch history stays immutable. If consumption
commits first, that is the final authorization cut-off; recovery requires a new
signed dispatch attempt. This is distinct from at-most-once external delivery,
which stays with Integrator/outbox.
