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

Keep the credential away from the agent and its tools. Keep the state file and
its adjacent `.observations` retry file on private storage that survives
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

**Current build:** the local endpoint evaluates calls and results against the
active signed Rails in Observe mode. It reports what the Rails would decide,
including missing context and uncovered Operations. For a covered action, the
sidecar sends the decision and a digest of the checked input to AuthRail. It
never sends the input or result itself. Your adapter supplies opaque principal,
session, and optional resource references. The local response says whether the
report was retained, queued for retry, or unavailable. A retained response has
the Action and certificate IDs. `/health` shows the number of pending reports.
The queue holds at most 512 reports or 16 MiB, rejects new reports when full,
and never drops old ones automatically. Recording failure does not stop the action. No published binary or container
image is included yet.

For implementation details, see [Architecture](ARCHITECTURE.md). To work on
the project, see [Contributing](CONTRIBUTING.md).
