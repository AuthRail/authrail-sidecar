# Operator-managed Docker installation

For a new application, use the [released guided Docker setup](https://docs.authrail.io/docs/docker).
It downloads a pinned prebuilt image, saves credentials privately and checks the
selected deployment without a source build or host Go compiler.

Use this recipe when your team builds a source revision or maintains its own
Compose installation. The sidecar runs beside the protected application, while
AuthRail supplies its Rails and stores the reports. Before continuing,
[prepare the deployment](../README.md#prepare-one-action) and obtain its API
address from the installation administrator. Your application will also need
the SDK wrapper and a review of other routes to its tools and credentials.

If you prefer a published image, the `0.2.0` image is
`ghcr.io/authrail/authrail-sidecar@sha256:5ca550de03a591c42d490374229bca57980b3e000b7b86bb3366174b317b48b4`
for Linux amd64/arm64. Released setup executable 0.2.0 instead pins the earlier
Runtime image `sha256:cb6e60475146ead55bcec56d5da14fcc75e2bf7e776b584b01ace5426a5356f4`
(internal version 0.1.0). The setup executable and running Runtime have
separate versions. Check [compatibility](https://docs.authrail.io/docs/compatibility)
before choosing one, especially if the Rails you want to use require newer
SDK or Runtime features.

The main recipe below builds **a local image from source**, then starts its
container. Docker compiles Go inside a temporary build stage; you do not run
`go build` on the host or copy a native binary into the image. A local build
is not a published artifact.

## 1. Get the source and build the image

Install Git and Docker with the Compose plugin. On macOS/Windows, start Docker
Desktop; on Linux, ensure Docker Engine is running. Then:

```sh
git clone https://github.com/AuthRail/authrail-sidecar.git
cd authrail-sidecar
docker build -t authrail-sidecar:development .
```

Run the remaining commands from this repository directory. The trailing `.`
tells Docker which files to build. Docker downloads its Go builder image and
modules, then creates the local image `authrail-sidecar:development`. You will
start that image in step 3. Select the source commit under your team’s change
process so the build can be reproduced later.
For a host application, use the [native installation guide](https://docs.authrail.io/docs/native).

The image contains the decision binary, a small credential/health launcher and
public CA certificates. It runs as UID/GID `10001:10001` without a shell. The
launcher replaces itself with the sidecar so SIGTERM reaches the process directly.
The Compose configuration uses a read-only root filesystem, no capabilities,
and a 15-second stop grace period (the process allows five seconds for shutdown).

## 2. Prepare your AuthRail settings and private files

Use an existing Observe deployment and copy its organisation ID, deployment
ID and AuthRail signing-key fingerprint from the authenticated workspace. The
sidecar needs that deployment’s credential and the public key registered for
the application. The application keeps its private key and business-provider
credentials. The [identity guide](https://docs.authrail.io/docs/identity) explains
manual provisioning and the purpose of each credential.

If you already used guided setup, plan a migration before replacing it with
this Compose project. It has its own state and credentials, which need to be
preserved through that change.

Your operator prepares three private files outside the checkout: the deployment
token, a separate random adapter token of at least 32 characters, and the
application’s public PEM key. Use absolute paths so Compose mounts the intended
files. The application’s private key stays with the application.

The sidecar user, UID 10001, must be able to read its mounted files. On Linux,
use ownership `10001:10001`, mode `0400` and a protected parent directory.
Compose mounts file secrets but does not repair host ownership. Docker Desktop
can map permissions differently; check readability without printing secrets.
Keep access limited to the required user rather than making files world-readable,
and keep credentials out of build arguments and image layers.

Set these shell variables to the paths and non-secret setup values. Replace
all placeholders; the API origin comes from your AuthRail installation, and
the IDs/fingerprint come from its deployment setup:

```sh
export AUTHRAIL_CONTROL_PLANE_URL=https://your-authrail-api.example.com
export AUTHRAIL_ORGANISATION_ID=YOUR_ORGANISATION_ID
export AUTHRAIL_DEPLOYMENT_ID=YOUR_DEPLOYMENT_ID
export AUTHRAIL_TRUSTED_KEY_SHA256=YOUR_VERIFIED_SIGNING_KEY_FINGERPRINT
export AUTHRAIL_DEPLOYMENT_TOKEN_PATH=/private/runtime/deployment-token
export AUTHRAIL_ADAPTER_TOKEN_PATH=/private/runtime/adapter-token
export AUTHRAIL_EXECUTOR_PUBLIC_KEY_PATH=/private/runtime/executor-public.pem
```

## 3. Start the container and check readiness

With the image built and the settings above exported in the same terminal:

```sh
docker compose -p authrail-runtime -f docker/compose.yaml up -d
docker compose -p authrail-runtime -f docker/compose.yaml ps
docker compose -p authrail-runtime -f docker/compose.yaml exec sidecar /usr/local/bin/authrail-container health
```

`up -d` starts the local image in the background and creates the named state
volume on first use. The last command produces no output and exits 0 when a
valid signed bundle is loaded. If it exits 1 or Compose reports `unhealthy`,
check the API address, selected Rails, credential files and signing-key pin.
Inspect startup messages with:

```sh
docker compose -p authrail-runtime -f docker/compose.yaml logs --tail 50 sidecar
```

Keep credentials out of copied logs. To stop and later resume the same instance:

```sh
docker compose -p authrail-runtime -f docker/compose.yaml stop sidecar
docker compose -p authrail-runtime -f docker/compose.yaml start sidecar
```

Keep the same project name and volume; never add `-v` to a removal command.
To rebuild changed source and recreate the container deliberately, use
`docker compose -p authrail-runtime -f docker/compose.yaml up -d --build`, then
recreate any executor sharing its network namespace as explained below.

Run these commands from the repository root. The placeholders must be replaced
with actual setup values. The default image tag for this source recipe is
`authrail-sidecar:development`. To use a reviewed published image instead of building,
set an immutable digest and explicitly skip the Compose build:

```sh
export AUTHRAIL_SIDECAR_IMAGE=ghcr.io/authrail/authrail-sidecar@sha256:5ca550de03a591c42d490374229bca57980b3e000b7b86bb3366174b317b48b4
docker pull "$AUTHRAIL_SIDECAR_IMAGE"
docker compose -p authrail-runtime -f docker/compose.yaml up -d --no-build
```

Keep the selected image compatible with your SDK, API and required Rails. Do not
apply a source-only requirement to an older image. To build a labelled source
image separately:

```sh
docker build --build-arg VERSION=YOUR_VERSION --build-arg REVISION=YOUR_REVISION -t authrail-sidecar:YOUR_VERSION .
```

Run `python3 scripts/docker-smoke.py` after building to verify the image using
disposable `authrail-package-*` containers and a volume. The check requires the
`node:22-slim` fixture image, removes only its own resources, and covers private
state, namespace connectivity, readiness, graceful shutdown, sequence rollback
protection and offline restart. It uses an isolated protocol fixture, so a
separate connected server/SDK/protected-executor check is still required.

`GO_IMAGE` can pin the Go builder to a reviewed digest. Native target architecture
is selected by Docker; use Buildx `--platform linux/amd64,linux/arm64` with an
appropriate builder to produce a multi-platform release. No registry publication
is performed by this repository's Docker build.

The health command exits zero only when `/health` responds with a valid signed
bundle. A fresh deployment with no selected bundle stays unhealthy. A cached
unexpired bundle can remain healthy during a control-plane outage; this is not
proof of central recording, adapter coverage or executor availability. Docker's
health status does not restart an unhealthy running process. Review full health
metadata with a trusted HTTP client in the shared network namespace: sequence,
mode, coverage, sync status, expiry, public-key fingerprints and pending/blocked
report counts all matter before Enforce. Health returns no token or private key.

The container-only launcher supports `AUTHRAIL_DEPLOYMENT_TOKEN_FILE`,
`AUTHRAIL_ADAPTER_TOKEN_FILE`, and optional `AUTHRAIL_OPERATOR_TOKEN_FILE`.
It rejects a direct variable and corresponding file variable set together. A
single trailing line ending is accepted. Mount optional operator-token and
previous-executor-public-key files separately if needed; never put the operator
credential in the agent or ordinary executor. Other configuration variables
are described in the root README. Export `AUTHRAIL_OTLP_ENDPOINT` to an OTLP/HTTP
Collector reachable from this container; telemetry failure cannot grant a call.

## 4. Connect your protected application

The sidecar deliberately binds **loopback only**, including in Docker. Publishing
7078 or addressing `http://sidecar:7078` cannot make a separate container work.
Add your protected application service to this Compose project with:

```yaml
services:
  executor:
    image: your-protected-application:reviewed-version
    network_mode: service:sidecar
    depends_on:
      sidecar:
        condition: service_healthy
```

Your application image should include the Node.js, Go or Python SDK around
the function that performs the work. Configure it to use `http://127.0.0.1:7078`
and mount its adapter token, private signing key and provider credentials where
the application expects them. Only that application container needs the private
key and provider credentials. Follow the SDK guide for caller authentication,
request checks, provider idempotency and result handling.

Both containers share a network namespace, not a filesystem. They cannot use the
same listening ports. Publish only your application's necessary ingress ports
on the **sidecar** service, whose namespace owns them; never publish 7078. When
the sidecar container is recreated, recreate the executor too so it joins the
new namespace. Do not place the untrusted agent in this namespace: it must not
reach the sidecar directly or read executor secrets. SDK wrapping and namespace
placement alone do not prove all provider/credential bypass paths are closed.

For a host-native executor on Linux, a reviewed alternative is Docker host
networking; it shares host loopback and reduces isolation. Docker Desktop 4.34+
requires explicitly enabling host networking. Do not silently enable it, publish
the decision port, or change the listener to `0.0.0.0`. See Docker's official
[host networking](https://docs.docker.com/engine/network/drivers/host/) and
[Compose network mode](https://docs.docker.com/reference/compose-file/services/#network_mode)
contracts. With ordinary bridge networking, host `127.0.0.1` refers to this
container. A local development API therefore needs reviewed same-namespace
placement or HTTPS routing; `http://host.docker.internal` is deliberately
rejected by the current control-plane URL security rule. A Collector may use
its private Compose DNS address. No provider credentials belong in the sidecar.

## Restart, offline recovery and upgrades

The named volume stores the **entire** `/var/lib/authrail` directory, including
`state.json`, rollback sequence floor, lock, observation queue, trajectory ledger
and recording-gap archives. The same volume and credentials must accompany a
restart. File secrets remain in their protected host locations, mounted read-only.
Never use `docker compose down -v`, anonymous replacement volumes, a blank state
file, or a copied older state snapshot as a recovery technique.

On a fresh named volume, Docker copies the image's directory ownership and mode
0700 for UID 10001. An existing bind mount must be provisioned by its owner with
equivalent private ownership; the image never runs a root permission-repair step.
Use one state volume per instance and keep the Compose project name stable.
Changing the project name creates a different volume and therefore a fresh
instance; it is not an upgrade.

Before an upgrade, quiesce protected requests and stop this executor/sidecar
pair under your change procedure. Back up the entire stopped volume with its
private permissions and host secret files. Build/pin a reviewed compatible
image, recreate the pair against the same volume, then check health, exact
bundle sequence, public-key fingerprints, queued reports and SDK conformance
before routing calls. Rollback replaces the binary image and retains the latest
state, never an older queue or lower sequence. If that binary cannot read the
state, leave Enforce stopped and resolve compatibility rather than resetting it.

During an outage, reports can remain queued on disk. Enforce still waits for
AuthRail to save permission and the execution-start report, even if the sidecar
has cached rules. Observe continues running the function. After service returns,
inspect pending and blocked reports and investigate any recording gaps.

If a completion report was lost, the application needs to check the provider
and reconcile the outcome before considering another attempt. Restarting the
sidecar resumes report delivery, not the business operation; the provider’s
record remains the place to establish its effect independently.
