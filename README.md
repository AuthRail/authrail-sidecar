# AuthRail Sidecar

AuthRail Sidecar runs beside your AI application. It receives the Rails you
activate in AuthRail and provides a local place for your application to check
protected actions. Your tools and provider accounts stay in your environment.

An AuthRail adapter connects your application to the sidecar. The adapter
identifies the action; the sidecar evaluates the active Rails; your application
receives the decision. In Observe mode, the decision is advisory and your
application continues its normal flow.

## Run from source

This repository uses Go 1.26 or later. Build the sidecar with:

```bash
go build -o authrail-sidecar ./cmd/authrail-sidecar
```

Give the process its AuthRail API address, deployment credential, organisation
and deployment IDs, trusted signing-key fingerprint, and a durable state path:

| Environment variable | Value |
| --- | --- |
| `AUTHRAIL_CONTROL_PLANE_URL` | AuthRail API address |
| `AUTHRAIL_DEPLOYMENT_TOKEN` | Credential for this deployment |
| `AUTHRAIL_ORGANISATION_ID` | Organisation ID |
| `AUTHRAIL_DEPLOYMENT_ID` | Deployment ID |
| `AUTHRAIL_TRUSTED_KEY_SHA256` | Trusted signing-key fingerprint |
| `AUTHRAIL_STATE_FILE` | File path for local state |
| `AUTHRAIL_ADAPTER_TOKEN` | Separate secret shared with your local adapter to enable Observe checks |
| `AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE` | PEM Ed25519 public key for assertions signed by your protected application |
| `AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE` | Optional previous public key while changing the application key |
| `AUTHRAIL_OPERATOR_TOKEN` | Separate secret for reviewing local recording gaps; at least 32 characters |

The short-lived AI system discovery setup key belongs only to the protected
application's SDK setup request. Never put it in the sidecar environment; it
cannot replace the deployment credential or authorize an action.

Keep the credential away from the agent and its tools. Keep the state file and
its adjacent `.observations` retry, `.observation-gaps` review, and `.trajectory`
session-history files on private storage that survives
restarts. The containing directory must be private to the sidecar process.
Give each sidecar instance its own state path; do not share one file between
processes.
Obtain the signing-key fingerprint through a
trusted setup channel; do not take it from the bundle being verified.

The health endpoint is available at `http://127.0.0.1:7078/health`. Set
`AUTHRAIL_ADAPTER_TOKEN` to a random value of at least 32 characters to enable
`POST http://127.0.0.1:7078/evaluate` for an adapter on the same host. Send it
as a Bearer token, along with a stable `Idempotency-Key` for the action. Keep it
separate from the deployment credential. The key is checked for a valid shape;
AuthRail uses it to recognize a retry of the same action. The
sidecar checks for updated Rails every five seconds. `AUTHRAIL_HEALTH_ADDR`
and `AUTHRAIL_SYNC_INTERVAL` change those defaults; the listener must stay on
loopback.

Create an Ed25519 key pair for the protected application. Give the sidecar only
the PEM public key; keep the private key in the application, outside the agent's
reach. Register that public key on the deployment page in AuthRail before
sending signed reports, and use the same key in the sidecar. When
`AUTHRAIL_ADAPTER_TOKEN` enables `/evaluate`, the public key file is
required. Each check carries a short-lived signature over the organisation and
deployment IDs, Operation Version, action key, phase, input digest, and the
principal, session, and resource references. The sidecar rejects missing,
expired, or changed assertions before checking Rails. Derive those references
from your application's authenticated session and resource lookup. A signature
shows which application key asserted them; it does not authenticate the person
on its own.
The signed attribution also carries `principalSource` as
`application_session` or `service_identity`. Set `resourceSource` to
`application_lookup` with the target ID from the reviewed Operation argument,
or `not_applicable` with no target when the Operation has no resource identity.
Missing claims or a target that differs from the argument leave coverage
unavailable. Such a check is not uploaded as a covered decision.
The local `/health` response shows `executorKeySha256s`; compare them with the
fingerprints on the deployment page. This is configuration evidence, not proof
of interception. To change keys, add the new public key on that page, switch
the application to its new private key, and set the new public key as
`AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE`. Keep the old public key as
`AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE` while old reports drain. The old
key is accepted for at most 24 hours. Check `pendingReports: 0` and
`blockedReports: 0` on every sidecar before retiring it. If a key is
compromised, revoke it immediately on the deployment page; queued reports
signed by that key become recording gaps that require review.

To review those gaps, set `AUTHRAIL_OPERATOR_TOKEN` to a secret that is different
from the deployment and adapter tokens. Give it only to the operator. The
loopback endpoint `GET /observations/gaps` lists each blocked action key, phase,
input digest, and application key fingerprint. It does not expose tool input or
result. After comparing a gap with your application logs, send its exact action
key, phase, and input digest with a reason to
`POST /observations/gaps/acknowledgements`. The sidecar writes the review to its
private `.observation-gaps` file before freeing queue space. Acknowledging a
gap does not create an AuthRail Action or certificate, and it cannot turn a
revoked-key report into verified evidence. `GET /observations/gaps/history`
shows the latest 100 local acknowledgements. All three endpoints require the
operator token as a Bearer token. Check every sidecar instance separately.

The local endpoint evaluates calls and results against the
active signed Rails in Observe mode. It reports what the Rails would decide,
including missing context and uncovered Operations. For a covered action, the
sidecar sends the decision and a digest of the checked input to AuthRail. It
never sends the input or result itself. Your adapter supplies opaque principal,
session, and optional resource references. The local response says whether the
report was retained, queued for retry, or unavailable. A retained response has
the Action and certificate IDs. `/health` shows the number of pending reports.
Reports rejected after a key closes remain in the private queue with a blocked
reason and appear in `blockedReports`; they are not silently deleted or certified.
For earlier-read rules, a signed complete snapshot starts with `start: true`
and an empty read list on the task's first checked call. Later checks must
present the exact ordered list of covered reads for that principal and session.
The sidecar records matching signed read call and successful result hooks under
the same active Rail bundle in
its private `.trajectory` file. A missing start, changed replay, mismatched
history, full ledger, or lost file makes the local decision unavailable; it
does not create a central Action or certificate. Keep this file with the state
file for restart and rollback. History is capped at 128 sessions and 256 read
hooks per session. Never clear the ledger to recover an existing instance.
AuthRail cannot detect a read that bypasses the adapter; check actual hook
coverage before relying on a prior-read rule. Session values remain signed
application claims, not independently verified model output.
Earlier business effects are not inferred from a tool result or this ledger.
They require a separate authenticated execution receipt before they can be
used as prior-effect decision context.
For AI-assisted Data Rails, the protected application sends only a typed fact
and bounded extraction provenance from the exact reviewed Context Source.
The sidecar checks the source and account, model/settings and instructions
versions, document digest and location, size, time, type, and uncertainty before
the deterministic Rails use that fact. An uncertain or mismatched reading is
untrusted, never an allow from the model. The application keeps the document
and model credentials away from the agent; the sidecar does not call the model
or independently verify its answer. Covered reports retain provenance but not
the document or extracted value.
The queue holds at most 512 reports or 16 MiB and rejects new reports when full.
Its private review history is also bounded; if it fills or becomes inaccessible,
the blocked report remains in the queue. Recording failure does not stop the
customer's action. No published binary or container image is included yet.

For implementation details, see [Architecture](ARCHITECTURE.md). To work on
the project, see [Contributing](CONTRIBUTING.md).
