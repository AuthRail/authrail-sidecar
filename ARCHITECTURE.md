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

The decision path will use one Runtime protocol across adapters. The sidecar
will evaluate the active Rails; the adapter will apply the response at the
tool or workflow boundary. The protected executor keeps provider credentials
and performs the operation. AuthRail retains deployment management, approval,
and decision history.

This branch does not yet expose a decision endpoint or evaluate actions. Its
health response reports `configuration_only` coverage.
