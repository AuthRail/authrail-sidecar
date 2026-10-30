<p align="center">
  <img src="assets/authrail-logo.png" alt="AuthRail" width="120" />
</p>

# AuthRail Sidecar

AuthRail helps teams govern how AI is used: organise their compliance work,
set rules for AI actions, review requests that need a person, and understand
what happened afterwards. Its Runtime connects those rules to the tools an AI
application can actually call.

The **sidecar** is the part of Runtime you run beside your application. Think of
it as a local rule checker: before a protected tool runs, your application asks
"is this request allowed?" The sidecar checks the exact rules published for
that deployment in AuthRail and returns an answer. Your application also checks
the tool's result before returning it to the agent. In AuthRail, these published
rules are called **Rails**; a **deployment** is one configured installation of
your AI application with its selected Rails and identity.

For example, if an agent asks to refund a payment, your application keeps the
Stripe credential and performs the refund. The sidecar decides whether that
specific call is allowed under the active Rails; it does not hold the Stripe
key or issue the refund. It reports bounded decision records to AuthRail while
the action inputs, provider credentials, and business workflow stay with your
application.

In **Observe**, the decision is advisory and the application may still run the
function. In **Enforce**, the protected adapter must stop unless a covered call
is explicitly allowed, then check the result before releasing it. The
sidecar returns decisions; only an adapter at the real execution boundary can
apply them.

## How it fits

```text
AuthRail ── signed Rails ──▶ sidecar ◀── local adapter ◀── protected application
                               │                                 │
                               └── decision report ──▶ AuthRail   └── tool/provider
```

The sidecar and an adapter work together: the sidecar owns local decisions and
report delivery; the adapter places checks at the application's actual action
boundary. Choose the [Node SDK](https://github.com/AuthRail/authrail-sdk-node),
the [Go SDK](https://github.com/AuthRail/authrail-sdk-go), or the
[Python SDK](https://github.com/AuthRail/authrail-sdk-python) to connect your
application through the supported adapters. Published SDK **0.1.1** is available
on [npm](https://www.npmjs.com/package/@authrail/sdk-node),
[PyPI](https://pypi.org/project/authrail/) and
[Go package documentation](https://pkg.go.dev/github.com/AuthRail/authrail-sdk-go). The sidecar is not a hosted decision endpoint or a
shared service for unrelated deployments.
The Node, Go and Python SDKs have Enforce wrappers. Their Observe wrappers remain
advisory. Review the installed adapter and bypass paths before switching modes.

## Before you start

1. Sign in to an AuthRail workspace, or ask its administrator to help with
   setup. You need permission to manage the AI system and its Runtime deployment.
   Confirm the AI system in **AI Inventory**, register/review the action your
   application will perform, publish its Rails, and select them for an **Observe**
   deployment. Copy the organisation/deployment IDs, deployment credential and
   trusted signing-key fingerprint from that setup. A local build alone cannot
   supply these values or create a connected AuthRail deployment.
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

### Prepare the application key and local credentials

For a new installation, create a private directory outside the checkout and
an application signing key pair. The following examples use a POSIX shell
(macOS/Linux, or an appropriate shell on Windows):

```sh
umask 077
mkdir -p "$HOME/.local/share/authrail/my-deployment"
chmod 700 "$HOME/.local/share/authrail/my-deployment"
openssl genpkey -algorithm Ed25519 -out "$HOME/.local/share/authrail/my-deployment/executor-private.pem"
openssl pkey -in "$HOME/.local/share/authrail/my-deployment/executor-private.pem" -pubout -out "$HOME/.local/share/authrail/my-deployment/executor-public.pem"
openssl rand -hex 32 > "$HOME/.local/share/authrail/my-deployment/adapter-token"
```

Run key generation once for a new deployment; if you already registered a key,
reuse that key pair rather than overwriting it. Register `executor-public.pem`
in AuthRail. Use a private editor or your operator's secret-provisioning tool
to save the deployment credential from AuthRail as `deployment-token` in the
same private directory. Keep those paths for the setup below. The SDK uses
`executor-private.pem` and the same adapter token; the sidecar uses the public
PEM, adapter token and deployment credential. Never mount the private signing
key or provider credentials into the sidecar.

## Choose how to run it

You run one sidecar process using **either Docker or a native binary**. Both
run the same decision service; the SDK still belongs in your application.

| Choose | What you need | What you run |
| --- | --- | --- |
| Docker (recommended) | Git, Docker Engine/Desktop and Compose | Build a local image, then start its container. Go compilation happens inside Docker. |
| Native download | The archive for your operating system/CPU | Unpack the executable, supply deployment settings, then run it in a terminal or service manager. No Go installation is needed. |
| Native source build | Git and Go 1.26+ | Compile the executable yourself, then use the same native run settings. |

Native sidecar **0.1.0** archives and checksums are available from
[GitHub Releases](https://github.com/AuthRail/authrail-sidecar/releases/tag/v0.1.0)
for macOS and Linux on amd64 and arm64. For Docker, use the source-build steps
below. You do **not** build a native binary first and put it into Docker: its
Dockerfile compiles and packages the program for you.

## Install with Docker (recommended)

With Docker running, get the source and build your local image:

```sh
git clone https://github.com/AuthRail/authrail-sidecar.git
cd authrail-sidecar
docker build -t authrail-sidecar:development .
```

That command creates an image on your computer; it does not start the sidecar,
connect to AuthRail or publish anything to a registry. You do not need a local
Go installation for this route. Then use the [Docker setup steps](docker/README.md)
to put the deployment and adapter tokens in private files, point Compose at
those files, and start it:

```sh
# After completing the guide's deployment settings and private file setup:
docker compose -p authrail-runtime -f docker/compose.yaml up -d
docker compose -p authrail-runtime -f docker/compose.yaml exec sidecar /usr/local/bin/authrail-container health
```

A successful health command exits with status 0 and no output after the sidecar
loads a valid signed bundle. A running container without a valid bundle is not
ready. The guide explains how your protected application joins the sidecar's
local network namespace. A host application cannot reach the Docker container
through the host's own `127.0.0.1:7078`; use the documented topology or choose
native for a host-native application. Never publish the decision port.

## Download and run natively

Choose native when your protected application runs directly on the same host.
Download the **0.1.0** archive and its matching `.sha256` file from
[the release](https://github.com/AuthRail/authrail-sidecar/releases/tag/v0.1.0).
Choose `darwin` for macOS or `linux` for Linux, then `arm64` or `amd64` for your
CPU. `uname -m` reports `arm64`/`aarch64` for arm64 or `x86_64` for amd64.

For example, on an Apple silicon Mac, download and unpack in a new directory:

```sh
mkdir authrail-sidecar-download &&
cd authrail-sidecar-download &&
curl --fail --location --remote-name https://github.com/AuthRail/authrail-sidecar/releases/download/v0.1.0/authrail-sidecar-0.1.0-darwin-arm64.tar.gz &&
curl --fail --location --remote-name https://github.com/AuthRail/authrail-sidecar/releases/download/v0.1.0/authrail-sidecar-0.1.0-darwin-arm64.tar.gz.sha256 &&
shasum -a 256 -c authrail-sidecar-0.1.0-darwin-arm64.tar.gz.sha256 &&
tar -xzf authrail-sidecar-0.1.0-darwin-arm64.tar.gz &&
cd authrail-sidecar-0.1.0-darwin-arm64 &&
./authrail-sidecar --version
```

The checksum should report `OK`; do not unpack a failed download. The version
command prints build identity and exits without connecting to AuthRail. The
archive includes the executable, `manifest.json`, guides, protocol examples
and the OpenShell example. Downloading it does not configure or start a service.
On Linux, `sha256sum -c` can verify the matching checksum file instead.

<details>
<summary>Build the native executable from source instead</summary>

Install Git and Go 1.26 or newer, then run:

```sh
git clone https://github.com/AuthRail/authrail-sidecar.git
cd authrail-sidecar
go build -o authrail-sidecar ./cmd/authrail-sidecar
```

This creates `./authrail-sidecar` in the checkout. It has not started it.
Choose a reviewed source commit for a repeatable build, then use the same
settings and run command below.

</details>

### Supply settings and start it

Finish the AuthRail setup above and have your deployment-token file,
adapter-token file and registered executor public PEM ready in a private
operator-owned directory. The application keeps the matching private key.
Replace every `YOUR_...` and `/absolute/...` placeholder before running:

```sh
export AUTHRAIL_CONTROL_PLANE_URL=https://YOUR_AUTHRAIL_API_HOST
export AUTHRAIL_ORGANISATION_ID=YOUR_ORGANISATION_UUID
export AUTHRAIL_DEPLOYMENT_ID=YOUR_DEPLOYMENT_UUID
export AUTHRAIL_TRUSTED_KEY_SHA256=YOUR_VERIFIED_SIGNING_KEY_FINGERPRINT
export AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE=/absolute/private/runtime/executor-public.pem
export AUTHRAIL_DEPLOYMENT_TOKEN="$(cat /absolute/private/runtime/deployment-token)"
export AUTHRAIL_ADAPTER_TOKEN="$(cat /absolute/private/runtime/adapter-token)"
umask 077
mkdir -p "$HOME/.local/state/authrail/my-deployment"
chmod 700 "$HOME/.local/state/authrail/my-deployment"
export AUTHRAIL_STATE_FILE="$HOME/.local/state/authrail/my-deployment/state.json"
./authrail-sidecar
```

These are process launch settings, including credentials loaded from private
files; do not commit them or put secret values in documentation. The native
process reads the token values directly. The Docker launcher additionally
supports mounted token-file settings. Use a separate state directory per
instance and preserve the whole directory across restarts.

The terminal stays attached while the sidecar runs. In another terminal, check:

```sh
curl --fail --silent --show-error http://127.0.0.1:7078/health
```

Look for `bundleValid: true` and the expected bundle sequence. This endpoint can
respond while configuration is missing, so an HTTP 200 alone does not establish
readiness. Leave the sidecar running, then connect your application using the
Node, Go or Python SDK at `http://127.0.0.1:7078`. Stop the foreground process with
Ctrl+C; restart with the same settings and state directory.

If you want to distribute your own native build to another machine of the same
platform, `sh scripts/package.sh YOUR_VERSION /absolute/output-directory`
creates an archive with the binary, guides, protocol examples and a SHA-256
checksum. This is optional packaging, not a required step before running the
binary. Verify the checksum before unpacking. It does not publish an official
release. Pin compatible source revisions and validate the exact deployment
before switching to Enforce; formatVersion 1 alone is not a compatibility test.

## Configuration reference

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
| `AUTHRAIL_OTLP_ENDPOINT` | Optional OTLP/HTTP Collector base URL, for example `http://127.0.0.1:4318`. Use HTTPS for a remote Collector; omit it to disable export. |

`AUTHRAIL_PREVIOUS_EXECUTOR_PUBLIC_KEY_FILE` accepts the previous application
public key during a bounded rotation overlap. `AUTHRAIL_HEALTH_ADDR` changes
the loopback listener from `127.0.0.1:7078`; `AUTHRAIL_SYNC_INTERVAL` changes
the five-second Rail sync interval. Keep the listener on loopback.

The sidecar checks the signed bundle's organisation, deployment, sequence,
activation time, expiry, and signature before using it. An invalid private
state file stops startup rather than resetting rollback protection.

For an upgrade, stop only the instance being upgraded under your own change
process, preserve `AUTHRAIL_STATE_FILE` and its adjacent `.observations`,
recording-gap, and trajectory files as one private set, and install the new
binary at the pinned revision. Use the same deployment ID, trusted key pins,
adapter token, and public executor key. Check `/health` for the expected
sequence, bundle validity, queue counts, and key fingerprints before routing
protected calls. For rollback, restore the previous binary while keeping the
newer state set; never restore an older state snapshot that would lower the
accepted bundle sequence or erase queued reports. A binary unable to read
that state must fail closed for Enforce and be resolved operationally, not
started with a blank file. An isolated package smoke test unpacks the sidecar,
starts it with a fresh private state path, restarts it, and rejects a lower
configuration sequence. A packaged process restart on a real deployment
remains a separate acceptance check.

## Connect your application

Use an AuthRail adapter at the protected function boundary. It sends a signed
`tool_call` before the function and a signed `tool_result` after a successful
result. Both phases carry the same stable action key. The local endpoint is
`POST http://127.0.0.1:7078/evaluate`; use the adapter token as its Bearer
credential. The [Node SDK](https://github.com/AuthRail/authrail-sdk-node),
[Go SDK](https://github.com/AuthRail/authrail-sdk-go) and
[Python SDK](https://github.com/AuthRail/authrail-sdk-python) handle signing and the
request format; install one in the protected application, not in the sidecar.

The application must authenticate the caller and resolve any target resource
before signing. A signature proves that its key asserted those references;
it does not independently prove the person, resource, or business execution.
The sidecar does not fetch provider facts or invoke a model. It evaluates
reviewed, bounded context supplied by the protected application.

## Follow local logs

The sidecar writes structured JSON events to stderr, including startup and
service-error events. No Collector is required. A native foreground process
shows them in its terminal; for the Docker setup, run:

```sh
docker compose -p authrail-runtime -f docker/compose.yaml logs --tail 50 --follow sidecar
```

`decision` records the call/result phase, mode, outcome and recording status.
`check_unavailable` identifies a request whose required history could not be
trusted, with the actual deployment mode and phase.
`execution_report` describes an application-reported attempt and whether its
report was retained or queued. `report_delivered` confirms later delivery of a
queued report; it does not resume a held action. `request_completed` records a fixed SDK operation,
HTTP status and elapsed time; HTTP success is not business permission.
Validated request, Action and attempt IDs help you find the related AuthRail
record. Arguments, source text, credentials and provider bodies are omitted.
An executor-reported success is not independent verification of an effect.

Logs are bounded, best-effort diagnostics. Slow or failed output can drop lines;
`logDrops` in local health counts these losses. They do not replace durable
Actions, receipts or report queues. Your operator owns output capture, rotation
and retention. Optional OTLP exports traces and metrics to your Collector,
independently of these process logs.

## Check health and recording

`GET http://127.0.0.1:7078/health` shows signed-bundle status, application-key
fingerprints, queued or blocked report counts, and a process-local cumulative
`telemetryFailures` count. That count includes dropped spans and failed OTLP
exports; it does not prove Collector retention or adapter coverage. OTLP export
uses bounded memory and a short deadline and cannot change a decision. An
invalid exporter configuration disables export without stopping decisions.
The sidecar sends a bounded deployment signal to AuthRail at startup and every
30 seconds. Fresh health
does not prove every action was intercepted.

For a covered check, `recordingStatus` distinguishes:

- `retained`: AuthRail saved the report and returned Action/certificate IDs.
- `queued`: the private sidecar queue saved it for retry; AuthRail has not
  retained it.
- `unavailable`: neither retention nor local queue durability is established.

An upload outage leaves a report queued when local storage works. A full or
unwritable queue leaves a recording gap; it never turns Observe into a block.
The Node Enforce adapter requires `retained` before proceeding, so an outage
stops its protected path. A result-phase stop cannot undo a tool effect.
Monitor the customer deployment's health and logs as well as local `/health`.

For a retained approval wait, the protected adapter can send a fresh signed
bounded `reviewSummary` on its Enforce call. The sidecar verifies its digest
as part of the executor signature and forwards the summary for named human
reviewers; it does not upload raw call arguments or results. Missing or invalid
review context leaves the request unavailable. The protected adapter can send a
fresh signed claim to local `POST /approval-permits/claim` with its adapter token. The
sidecar forwards that claim with its deployment credential; the agent never
receives that credential. The server consumes an approved request once and
returns a short-lived permit. The sidecar never retries a claim after an
uncertain response. A permit says the call may proceed; it does not prove the
protected function ran.
An authenticated adapter can send the same fresh signed claim to
`POST /approval-permits/recover` to read a still-valid existing permit after
a lost claim response. Recovery cannot create a permit or resume an already
started attempt.

The protected adapter sends a signed `started` receipt to local
`POST /execution-receipts` before invoking the provider. The sidecar forwards
it with the deployment credential and returns only a centrally retained
acknowledgement. Completion and reconciliation use the same endpoint. The
sidecar does not execute the operation, infer a provider result, or retry a
business effect. If a completion report is lost, the application must check
the provider with the original idempotency reference and reconcile the Action.
Only an authenticated no-effect reconciliation permits a fresh signed call
decision and another attempt under that Action. The protected adapter reuses
the provider idempotency key and business arguments; facts and trajectory can
be refreshed for the new decision. Any new approval is separate.
The sidecar forwards the executor's assertion and cannot verify the provider.

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
- [Local protocol](PROTOCOL.md): raw HTTP shape, signed phases, effect receipts,
  conformance, and coverage review.
- [Compatibility](COMPATIBILITY.md): published component versions, protocol and
  state requirements, verification evidence and deployment coverage checks.
- [Contributing](CONTRIBUTING.md): build and test conventions.
- [OpenShell protected executor](integrations/openshell/README.md): customer-owned
  placement and source integration, with separate containment validation requirements.

## Build identity and CI

The sidecar has its own version, separate from the SDK versions. Check a packaged
binary with `./authrail-sidecar --version`, or an image with
`docker run --rm YOUR_IMAGE --version`. The JSON shows its version, source commit,
and configuration, protocol and state format numbers. This command needs no
credentials and does not start the service. A direct `go build` reports
`development` and `unknown`; `scripts/package.sh` and Docker's `VERSION` and
`REVISION` build arguments supply distribution identity.

Sidecar CI checks native builds on Linux and macOS, race tests, signed protocol
compatibility with pinned Node/Go/Python SDKs, and the Docker image. Disposable
container checks cover private networking, restart state and protected SDK
callbacks. These checks use local fixtures, not customer deployments or provider
credentials. The separate Release workflow publishes versioned native archives and images
when its publication option is selected. Image upload alone does not establish
anonymous registry access; use the Docker source build above.

Maintainers: see [Releasing](RELEASING.md) for checked artifacts and publication setup.
