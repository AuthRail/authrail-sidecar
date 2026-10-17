# Architecture

The sidecar runs beside an application or agent. AuthRail supplies the Rails
for a deployment; an adapter brings protected actions to the sidecar; the
customer's executor performs actions that are permitted. The agent does not
need access to provider credentials.

```text
AuthRail ── signed Rails ──▶ Sidecar ◀── actions ── Adapter ◀── Application
                              │
                              └── local decision
```

## Configuration

The current code owns the AuthRail-to-sidecar connection. It authenticates one
deployment, downloads its active Rail bundle, checks the signing key and
signature, and confirms that the bundle belongs to the right organisation and
deployment. It also checks when the bundle becomes active and expires.

The sidecar saves the latest activation sequence in a private state file. This
prevents an older bundle from replacing a newer one after a restart. A
revocation clears the active bundle. If AuthRail is temporarily unreachable,
the sidecar can retain a previously verified Observe bundle until it expires.
An invalid state file stops startup instead of resetting this protection.

`/health` reports configuration status. It does not expose the bundle or the
deployment credential.

## Decision boundary

A local adapter can send a tool call or result to `/evaluate` with the exact
Operation Version, a request ID, opaque principal and session references, an
optional resource reference, and the action fields. These references are
attributed to the adapter; they do not establish verified principal identity.
A separate adapter
secret protects this loopback endpoint. A caller-supplied action key travels
in the `Idempotency-Key` header. The deployment credential authenticates both
configuration sync and the sidecar's report to AuthRail.

The sidecar checks the current signed bundle and evaluates its Guard and Policy
rules for that Operation. A Guard can deny or clear its boundary; only a Policy
can allow the business action. Missing trusted facts, identity, or trajectory
state remain unresolved. An unselected Operation is reported as uncovered.
Every response says `mode: observe` and `enforced: false`; the adapter must not
treat it as permission or a block. The protected executor owns provider
credentials and performs the operation.

For a covered call or result, the sidecar sends the evaluated outcome, exact
bundle and rule references, and a digest of canonicalized input to AuthRail.
Raw action fields and tool results stay local. The AuthRail server retains an
idempotent Action and signs a certificate explicitly marked as a
deployment-reported Observe result. Before upload, the sidecar saves the bounded
metadata-only report in a private queue beside its state file. It retries queued
reports after restart and periodically while running. A failed upload leaves
the local response marked `recordingStatus: queued`; a failed queue write is
`unavailable`. Neither is presented as centrally retained. The first Go SDK is a separate repository. `/health` still
reports configuration coverage; it does not claim that calls are intercepted.
