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
optional resource reference, and the action fields. The protected executor
signs a short-lived assertion that binds these references to the deployment,
action key, phase, and canonical input digest. The sidecar verifies the
configured Ed25519 public key before evaluating or retaining a report. The
protected application must authenticate its own principal and resolve its
resource before signing. This proof establishes that its key asserted the
references; it does not independently authenticate the person or prove execution.
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
bundle and rule references, a digest of canonicalized input, and the signed
executor assertion to AuthRail. The assertion contains references and digests,
not the tool input or result. AuthRail verifies it against the public key
registered for that deployment before recording a verified signature claim.
Raw action fields and tool results stay local. The AuthRail server retains an
idempotent Action and signs a certificate explicitly marked as a
deployment-reported Observe result. Signature verification does not independently
authenticate a person, resolve a resource, or prove execution. Before upload,
the sidecar saves the bounded
metadata-only report in a private queue beside its state file. It retries queued
reports after restart and periodically while running. A failed upload leaves
the local response marked `recordingStatus: queued`; a failed queue write is
`unavailable`. Neither is presented as centrally retained. The first Go SDK is a separate repository. `/health` still
reports configuration coverage; it does not claim that calls are intercepted.
During application key rotation, the sidecar verifies assertions with the new
key and optional previous key, then reports the matching key fingerprint for
server verification. The server accepts the previous key only during its bounded
overlap. Once closed, a new report under it receives a specific permanent
response. The queue retains that metadata-only report with a blocked reason,
excludes it from retries, and exposes the count in `/health`. Each instance
owns its queue; the server does not infer that all instances have drained.
