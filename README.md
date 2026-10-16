# AuthRail Sidecar

AuthRail Sidecar runs beside your AI application. It receives the Rails you
activate in AuthRail and provides a local place for your application to check
protected actions. Your tools and provider accounts stay in your environment.

An AuthRail adapter connects your application to the sidecar. The adapter
identifies the action; the sidecar applies the active Rails; your application
carries out an allowed action. You can start a deployment in Observe mode to
see decisions before enabling enforcement.

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

Keep the credential away from the agent and its tools. Keep the state file on
storage that survives restarts. Obtain the signing-key fingerprint through a
trusted setup channel; do not take it from the bundle being verified.

The health endpoint is available at `http://127.0.0.1:7078/health`. The sidecar
checks for updated Rails every five seconds. `AUTHRAIL_HEALTH_ADDR` and
`AUTHRAIL_SYNC_INTERVAL` change those defaults.

**Current build:** configuration sync and health are available. The action
decision interface is not yet available, so this build cannot authorize or
block an action. There is no published binary or container image yet.

For implementation details, see [Architecture](ARCHITECTURE.md). To work on
the project, see [Contributing](CONTRIBUTING.md).
