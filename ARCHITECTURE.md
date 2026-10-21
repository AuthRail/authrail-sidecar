# Sidecar Architecture

The sidecar is the customer-side Runtime decision process for one AuthRail
deployment. It verifies the deployment's signed Rails and evaluates checks
sent by a local adapter. It does not execute the customer's tool or hold the
tool's provider credentials.

```text
AuthRail ── signed deployment bundle ──▶ sidecar ◀── signed call/result ── application
   ▲                                      │                                  │
   └──── bounded reports and health ─────┘                                  └── protected tool
```

## Ownership and trust

| Owner | Responsibility |
| --- | --- |
| Protected application | Authenticate the caller, resolve the target, read trusted context, keep provider credentials, and execute the function. |
| Local adapter | Bind the reviewed Operation Version and stable action key to call/result hooks; sign the application's claims. |
| Sidecar | Authenticate the adapter, verify the application signature and active Rails, evaluate locally, queue bounded decision reports, and forward signed execution receipts. |
| AuthRail server | Authenticate the deployment, retain accepted Action/certificate/Activity records, and expose customer history. |

The application key proves that the application asserted principal, session,
resource, and context references. It does **not** independently prove the
person, resource, provider read, execution, or that every action passed through
the adapter. A signed execution receipt establishes what the registered
application reported, while the provider's record remains external. A bypass
path remains advisory. Predecision responses in both
modes report `enforced: false` because the sidecar cannot verify that the
adapter applied them. Neither sidecar health nor a decision is execution proof.
The sidecar reports both the full decision input digest and the canonical
business arguments digest. The latter stays fixed across a reconciled no-effect
retry while facts and trajectory are evaluated afresh; each execution receipt
still binds its own full call digest.

## Bundle synchronization

The sidecar authenticates one deployment to AuthRail and downloads its active
Rail bundle. Before use, it verifies the configured signing-key fingerprint,
signature, organisation and deployment IDs, activation time, expiry, and
sequence. A newer removal clears the active bundle. An older sequence cannot
replace a newer one after restart.

The latest accepted sequence lives in a private state file. An invalid file
stops startup rather than resetting rollback protection. If AuthRail becomes
unreachable, a previously verified bundle may remain usable only
until its expiry. A missing or invalid bundle makes coverage unavailable,
not allowed.

`/health` exposes configuration and queue status without exposing the bundle
or deployment credential. A bounded authenticated health signal also reaches
AuthRail. Neither signal establishes that every tool was intercepted.

## Local check

The adapter calls loopback `/evaluate` with a separate adapter Bearer token,
a stable `Idempotency-Key`, the exact Operation Version, phase, request ID,
bounded action fields, and an application-signed assertion. The assertion
binds the deployment, action key, phase, canonical input digest, and principal,
session, and optional resource references. The sidecar verifies the configured
Ed25519 public key and short validity window before evaluation or reporting.

The application must resolve a required resource from the reviewed Operation
argument. A missing, different, or untrusted identity leaves coverage
unavailable and produces no covered central certificate. Only signed
principal and resource IDs are available to local Rail conditions; other
attributes must come from reviewed, trusted context.

The active Data Rails project bounded values from exact reviewed source
versions. Account, lookup, record key, type, and freshness must match. A Data
Rail supplies context; it never authorizes the business action. Guard Rails
may deny or clear their boundary. Policy Rails may allow, deny, or require
approval. Missing trusted facts or incomplete context remain unresolved.
An unselected Operation is uncovered. The sidecar does not invoke a provider
or model to invent missing context.

## Session context

For a prior-read Guard, the application may sign an ordered snapshot of
successful read Operation Versions from the same authenticated session. The
sidecar keeps a private, restart-safe ledger of matching signed call and
successful result hooks. It checks the snapshot against that ledger and the
active bundle's result-hook coverage. Cross-session, duplicate, changed,
missing, or incomplete history cannot clear a Guard. An exact earlier read
may deny even when a Policy would allow.

The ledger is bounded to 128 sessions and 256 read hooks per session. A full
or lost ledger makes the decision unavailable; do not clear it to recover an
existing instance. Small typed session values are usable only when listed in
the reviewed Operation. Tool results do not establish prior business effects;
those need authenticated execution receipts.

For AI-assisted Data facts, the protected application supplies one typed
resolution and bounded extraction provenance from a reviewed source. The
sidecar checks source, account, model settings, instructions version, document
digest and location, size, time, type, and uncertainty. It does not call the
model or treat its answer as an authorization decision. Raw documents and
fact values stay local.

## Reporting and recovery

For a covered call or result, the sidecar sends the outcome, exact bundle and
rule references, fact status and bounded provenance, canonical input digest,
and signed application assertion to AuthRail. It never uploads raw tool
arguments, results, fact values, or lookup keys. The server verifies the
registered application key and retains an idempotent Action and a certificate
marked as deployment-reported, not independently verified as enforced or
executed. The Node Enforce adapter requires retained call and result
reports before proceeding at each phase.

Before upload, the sidecar writes metadata to a private queue beside its
state file. It retries after restart and while running. The queue holds at
most 512 reports and has a 40 MiB file bound. A failed upload remains `queued`;
a failed or full queue is `unavailable`. Recording failure never blocks an Observe
function. Each sidecar instance owns its own queue.

During application-key rotation, the configured new and previous public keys
may verify assertions within the bounded overlap. The server can permanently
reject a report signed by a closed key. Such a report stays in the queue as
`blocked`, not silently certified or retried forever. A separate operator
token protects local gap inspection and acknowledgement. The operator reviews
blocked metadata against independent application records and writes a reason;
the sidecar durably records that acknowledgement before removing the queue
entry. A full or inaccessible review history leaves the report blocked.
Acknowledgement does not create a central Action or certificate.

Keep the state file and its report queue, gap history, and trajectory ledger
together on private storage through restart and rollback. Never share a state
path between instances or reset these files as a recovery shortcut.
