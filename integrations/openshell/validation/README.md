# Real OpenShell validation harness

Run this harness on a development machine with permission to create disposable
Docker resources. It needs Docker-daemon authority to let the real gateway
create sandboxes. Do not run it against a production Docker daemon.

The connected qualification was run on Apple Silicon macOS with Docker Desktop.
These helper scripts currently use `/private/tmp` and macOS-specific private
directory checks; they are not a qualified Linux harness. The Docker socket
defaults to a local Unix `DOCKER_HOST`, then the current user's Desktop socket
when present, then `unix:///var/run/docker.sock`. An explicit
`--docker-socket unix:///absolute/socket/path` is supported. Remote Docker
daemons and other socket protocols are refused. No Docker configuration or
credential files are read. A Linux run needs the private-directory assumptions
adapted and the full containment checks repeated before claiming support.

`gateway.py` creates a unique private directory under `/private/tmp`, pulls the
requested pinned gateway and supervisor images, generates disposable mTLS
credentials, and starts one loopback-published gateway. It isolates OpenShell's
XDG config and state; it does not read your normal OpenShell or Docker config.
Pass immutable image digests to reproduce a reviewed run.

```sh
python3 integrations/openshell/validation/gateway.py \
  --cli /absolute/path/to/openshell \
  --gateway-image ghcr.io/nvidia/openshell/gateway@sha256:REVIEWED_DIGEST \
  --supervisor-image ghcr.io/nvidia/openshell/supervisor@sha256:REVIEWED_DIGEST
```

The printed directory contains a manifest identifying that gateway. It also
contains private disposable keys: keep it private and never commit it. A
successful authenticated gateway check is only setup, not containment proof.

Copy `validation/Dockerfile` into a private build directory alongside only the
isolated executor's public CA certificate named `executor-ca.crt`, then build
it as a uniquely named local probe image. Its marker
under `/protected` is deliberately synthetic. Prepare a copy of the reviewed
OpenShell policy with the exact isolated executor hostname, port and curl
binary. The executor's private key stays outside the sandbox and build context.

OpenShell's trusted supervisor verifies upstream HTTPS separately from the
workload. A private executor CA installed only in the workload is insufficient.
For this isolated validation, `Dockerfile.supervisor` overlays a public CA
bundle onto the exact upstream supervisor image while retaining its binary.
Prepare `supervisor-ca-bundle.crt` from its original public trust roots plus the
disposable executor's public CA. This extends trust for every destination in
that isolated supervisor; never add an unreviewed CA to a customer deployment.
`reconfigure.py` replaces only the manifest's disposable gateway and sandbox
with the reviewed validation supervisor image and bridge networking. Existing
private PKI and isolated gateway registration remain in that private directory.

```sh
python3 integrations/openshell/validation/probe.py PRINTED_DIRECTORY \
  --policy /absolute/path/to/reviewed-policy.yaml \
  --image UNIQUE_LOCAL_PROBE_IMAGE \
  --executor https://EXACT_EXECUTOR_HOST:PORT
```

The probe first requires the allowed POST route to reach the real protected
executor's authentication boundary. It then records sandbox identity, effective
policy, and filesystem/network/method/path failures. Inspect the retained
failures and gateway logs to distinguish an actual policy denial from missing
files, DNS failure, TLS failure or an unreachable destination. Failed commands
alone do not prove containment. Also run authenticated AuthRail allow/deny,
effect-count, replay, active-policy inspector and stale-policy checks before
accepting the integration.

`inspect.mjs PRINTED_DIRECTORY` records the actual sandbox and effective policy
without rounding large revision numbers, and checks the existing containment
inspector against those pins. Its automatically discovered pins are for this
controlled validation only. Operators must review production pins themselves.

The opt-in Go integration fixture can select `verify-sandbox.mjs` using
`AUTHRAIL_OPENSHELL_GATEWAY_MANIFEST`. That script expects the prepared sandbox,
reviewed pins and policy, and isolated executor TLS files in the private
directory. It checks the real sandbox -> HTTPS executor -> Node SDK -> sidecar
path. Its control-plane retention is an isolated Go fixture, not PostgreSQL.
It also renames only the disposable sandbox's network rule, preserving the
same host, port, method and path, and verifies
that the old pins block further execution. Do not reuse those old pins after
the run.

The connected check has passed with OpenShell CLI, gateway and supervisor
version 0.1.6 on Apple Silicon Docker Desktop. The gateway used immutable image
`sha256:f0b36dba21d282c52e498c25289658cfd6cd4f343b0069fde5609e25b002cdea`.
The validation supervisor retained the binary from upstream image
`sha256:ce859a7d77ee515d3fe0b3c7dc61286516f402eb1d25c761d806d9ae5ed96c0b`,
with the reviewed public CA overlay described above and bridge networking.
Gateway authentication used mTLS; executor HTTPS verification and required
Landlock stayed enabled.

That check demonstrated one isolated allowed effect, business denial, replay
blocking, withdrawal of operator approval, and blocking after an actual policy
revision made the old pins stale. A positively checked live sidecar probe
received only its host control request; the sandbox could not reach it.
OpenShell's retained denial events identified the unapproved hostname, wrong
HTTP method and path, and unreviewed Node binary. The synthetic protected-file
read was denied, and wrong routes never reached the executor. These results
cover the reviewed test image, policy and network topology; they are not
production release acceptance or proof of every customer bypass boundary.

Remove only the exact sandbox in `manifest.json`'s `sandboxName` using the isolated CLI
config, then remove only the exact gateway container in `manifest.json`. Do not
run unscoped Docker cleanup. Delete the private directory after reviewing the
evidence and confirming no validation resource still uses it.
