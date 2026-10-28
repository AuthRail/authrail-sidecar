# Run the sidecar with Docker

Docker is the recommended installation for a customer-operated sidecar. Build
the image from a pinned, reviewed source revision; there is no published image
or release compatibility matrix yet. Native archives remain supported through
`scripts/package.sh` and the root README.

The image contains the decision binary, a small credential/health launcher and
public CA certificates. It runs as UID/GID `10001:10001` without a shell. The
launcher replaces itself with the sidecar so SIGTERM reaches the process directly.
The Compose configuration uses a read-only root filesystem, no capabilities,
and a 15-second stop grace period (the process allows five seconds for shutdown).

## Prepare one deployment

Use an existing reviewed Observe deployment, its exact deployment credential,
organisation/deployment IDs, independently verified signing-key fingerprint and
the protected executor's registered Ed25519 public key. Keep the executor's
private key and provider credentials exclusively in the protected application.

Place the deployment token, a separate random adapter token of at least 32
characters, and executor public PEM in three private files outside the checkout.
Files must be readable by UID 10001 in the container. On Linux, provision the
files with ownership `10001:10001` and mode `0400`, and protect their parent
directory; Compose file secrets do not automatically fix host permissions.
Do not make credentials world-readable to solve a mount-permission failure.
Docker Desktop file sharing may map permissions differently; verify readability
without printing the files. Never put credentials in build arguments or image layers.

Set these shell variables to the paths and non-secret setup values:

```sh
export AUTHRAIL_CONTROL_PLANE_URL=https://your-authrail-api.example.com
export AUTHRAIL_ORGANISATION_ID=YOUR_ORGANISATION_ID
export AUTHRAIL_DEPLOYMENT_ID=YOUR_DEPLOYMENT_ID
export AUTHRAIL_TRUSTED_KEY_SHA256=YOUR_VERIFIED_SIGNING_KEY_FINGERPRINT
export AUTHRAIL_DEPLOYMENT_TOKEN_PATH=/private/runtime/deployment-token
export AUTHRAIL_ADAPTER_TOKEN_PATH=/private/runtime/adapter-token
export AUTHRAIL_EXECUTOR_PUBLIC_KEY_PATH=/private/runtime/executor-public.pem
docker compose -p authrail-runtime -f docker/compose.yaml up -d --build
docker compose -p authrail-runtime -f docker/compose.yaml exec sidecar /usr/local/bin/authrail-container health
```

Run these commands from the repository root. The placeholders must be replaced
with actual setup values. The default image tag is `authrail-sidecar:development`;
set `AUTHRAIL_SIDECAR_IMAGE` to a reviewed immutable release tag/digest when one
is available. To build separately:

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

## Put the protected application beside it

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

The Node/Go adapter in that executor uses `http://127.0.0.1:7078` and its own
mounted copy of the adapter token. Mount its Ed25519 private key and provider
credentials only into the executor. This example intentionally does not invent
an executor image or its application-specific secret configuration. Its real
authentication, tool interception, effect idempotency and result checks must
be implemented using the reviewed SDK/HTTP protocol.

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

An outage can leave bounded reports queued on disk. Enforce SDKs require central
retention for protected decisions and a retained started receipt before an
effect, so a cached bundle does not guarantee continued execution. Observe
remains advisory. A lost completion report requires the protected application's
provider lookup and reconciliation; restarting the sidecar never retries the
business operation. Inspect pending/blocked reports and recording gaps after
recovery. A healthy container never proves that a provider effect occurred.
