# AuthRail Sidecar

Run AuthRail checks beside your AI application, without sending tool inputs or
provider credentials to AuthRail. The sidecar receives signed Rails for one
deployment, evaluates action calls and results on the same host, and reports
bounded decision records back to AuthRail.

Your application still owns the workflow and the protected function. In
**Observe** mode, checks show what the Rails would decide; they do not block
the function or prove it executed.

## How it fits

```text
AuthRail ── signed Rails ──▶ sidecar ◀── local adapter ◀── protected application
                               │                                 │
                               └── decision report ──▶ AuthRail   └── tool/provider
```

The sidecar and an adapter work together: the sidecar owns local decisions and
report delivery; the adapter places checks at the application's actual action
boundary. Choose the [Node SDK](https://github.com/AuthRail/authrail-sdk-node)
or [Go SDK](https://github.com/AuthRail/authrail-sdk-go), or implement the same
local decision protocol. The sidecar is not a hosted decision endpoint or a
shared service for unrelated deployments.

## Before you start

1. In AuthRail, review the action and its Rails, create an Observe deployment,
   and obtain its deployment credential and trusted signing-key fingerprint.
2. Generate an Ed25519 key pair for the protected application. Register the
   public key on the deployment page. Give the sidecar only that public key;
   keep the private key in the application.
3. Create a separate random adapter token of at least 32 characters. It lets
   the application call the sidecar locally; it is not the deployment credential.
4. Choose a private, persistent state path for each sidecar instance. Its
   adjacent report queue, recording-gap history, and trajectory ledger must
   survive restarts.

Do not give deployment, adapter, operator, or provider credentials to the
agent. If it can bypass the protected executor, treat the deployment as
advisory even when the sidecar is healthy.

## Build and run

Go 1.26 or newer is required to build from source:

```bash
go build -o authrail-sidecar ./cmd/authrail-sidecar
```

Configure the process before starting it:

| Variable | Purpose |
| --- | --- |
| `AUTHRAIL_CONTROL_PLANE_URL` | AuthRail API address. |
| `AUTHRAIL_DEPLOYMENT_TOKEN` | Credential for this exact deployment. |
| `AUTHRAIL_ORGANISATION_ID` | Organisation ID. |
| `AUTHRAIL_DEPLOYMENT_ID` | Deployment ID. |
| `AUTHRAIL_TRUSTED_KEY_SHA256` | Trusted signing-key fingerprint obtained through setup, not from a downloaded bundle. |
| `AUTHRAIL_STATE_FILE` | Private persistent state-file path, unique per instance. |
| `AUTHRAIL_ADAPTER_TOKEN` | Separate local adapter token for `/evaluate`. |
| `AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE` | PEM public key of the protected application. |
| `AUTHRAIL_OPERATOR_TOKEN` | Optional separate token to enable local recording-gap review. |

`AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE` accepts the previous application
public key during a bounded rotation overlap. `AUTHRAIL_HEALTH_ADDR` changes
the loopback listener from `127.0.0.1:7078`; `AUTHRAIL_SYNC_INTERVAL` changes
the five-second Rail sync interval. Keep the listener on loopback.

The sidecar checks the signed bundle's organisation, deployment, sequence,
activation time, expiry, and signature before using it. An invalid private
state file stops startup rather than resetting rollback protection.

## Connect your application

Use an AuthRail adapter at the protected function boundary. It sends a signed
`tool_call` before the function and a signed `tool_result` after a successful
result. Both phases carry the same stable action key. The local endpoint is
`POST http://127.0.0.1:7078/evaluate`; use the adapter token as its Bearer
credential. The [Node SDK](https://github.com/AuthRail/authrail-sdk-node) and
[Go SDK](https://github.com/AuthRail/authrail-sdk-go) handle signing and the
request format; install one in the protected application, not in the sidecar.

The application must authenticate the caller and resolve any target resource
before signing. A signature proves that its key asserted those references;
it does not independently prove the person, resource, or business execution.
The sidecar does not fetch provider facts or invoke a model. It evaluates
reviewed, bounded context supplied by the protected application.

## Check health and recording

`GET http://127.0.0.1:7078/health` shows signed-bundle status, application-key
fingerprints, and queued or blocked report counts. The sidecar sends a bounded
deployment signal to AuthRail at startup and every 30 seconds. Fresh health
does not prove every action was intercepted.

For a covered check, `recordingStatus` distinguishes:

- `retained`: AuthRail saved the report and returned Action/certificate IDs.
- `queued`: the private sidecar queue saved it for retry; AuthRail has not
  retained it.
- `unavailable`: neither retention nor local queue durability is established.

An upload outage leaves a report queued when local storage works. A full or
unwritable queue leaves a recording gap; it never turns Observe into a block.
Monitor the customer deployment's health and logs as well as local `/health`.

## Recover recording gaps

During application-key rotation, keep the old public key available only while
old reports drain. Check `pendingReports: 0` and `blockedReports: 0` on each
instance before retiring it. A revoked key cannot be used to certify queued
reports. An operator may inspect blocked metadata through the token-protected
`/observations/gaps` endpoint and acknowledge an independently reviewed gap
with a reason. That acknowledgement is local; it does not create an Action or
certificate. Never clear the queue or trajectory ledger to make health appear
good.

## Project guides

- [Architecture](ARCHITECTURE.md): trust boundaries, decision protocol, local
  state, queue, and recovery invariants.
- [Contributing](CONTRIBUTING.md): build and test conventions.
