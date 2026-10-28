# OpenShell protected-executor integration

An OpenShell sandbox limits the files, processes and network destinations an
agent can reach. AuthRail checks whether a particular business action is allowed.
Use them together by putting the credential-owning executor **outside** the agent
sandbox, with the Node SDK and one customer-side AuthRail sidecar beside it.

```text
OpenShell agent sandbox
  POST /execute over HTTPS, sandbox request credential
        ↓
Protected application: fixed sandbox → principal + deployment + Operation Version
  Node SDK → loopback sidecar → signed call decision and retained started receipt
        ↓
Protected tool → completion receipt → result check → result released to sandbox
```

This directory supplies the HTTPS handler, a live containment inspector, a
restrictive policy template and an isolated SQLite sample executor. It does not
wrap arbitrary shell commands or give OpenShell a second policy engine. The
sample records a simulated amount locally; it never moves money or calls a
provider. Your actual business executor replaces that callback and keeps its
own provider idempotency and reconciliation contracts.

## What is checked so far

The reviewed upstream is NVIDIA OpenShell **v0.1.6**, released October 27, 2026.
The official CLI archive SHA-256 for Apple silicon is
`334e9cf24994a5bfd34691e9835920da15f5ef224cc96be0d4751eadfa279897`.
Other platforms require their own verified official release artifact.
The released CLI's version and policy/sandbox inspection flags were checked.

The protocol check runs the real Node SDK against sidecar HTTP handlers and
signed Rail evaluation. A separate real OpenShell run used an authenticated mTLS
gateway, a hard-required Landlock sandbox, this HTTPS executor and the real SDK.
It allowed one isolated effect, blocked an oversized request and a replay, and
blocked execution after the exact sandbox policy changed. File access, direct
sidecar access, other destinations, unreviewed executables and disallowed HTTP
methods/paths were probed; OpenShell's retained network events identified the
denials. The executor's forced 30-second shutdown deadline was also checked.

That OpenShell run uses an isolated control-plane retention fixture, not central
PostgreSQL or a real provider. The Docker/server smoke check separately verifies
Node/Go call/result retention against authenticated AuthRail services and
PostgreSQL, including queued reports across an offline restart. These checks
establish the tested integration boundaries; they do not establish universal
tool interception or acceptance of a customer's deployment. Repeat the relevant
probes against your own exact image, policy, credentials and protected tool.

## Prepare the protected application

Use Node 22.13 or newer for this example's built-in SQLite support. The SDK
itself retains its separately documented Node support. Check out the reviewed
`authrail-sdk-node` next to `authrail-sidecar`, build the SDK and install the
example's local dependency:

```sh
npm --prefix ../authrail-sdk-node ci
npm --prefix ../authrail-sdk-node run build
cd integrations/openshell
npm ci
cp operator-settings.example.json operator-settings.json
```

The commands start from the sidecar repository root. Edit the ignored settings
file with this exact deployment's organisation, registered executor identity,
reviewed Operation Version and private file paths. Do not copy it into a
sandbox or publish its contents. `npm ci` links the sibling SDK source; it
does not imply an npm release has been published. Pin both repository revisions
together. Native sidecar setup is in the root README; Docker is recommended
and described in [the Docker guide](../../docker/README.md).

Register an Operation with one numeric `amount` argument, an object result with
boolean `accepted`, no resource identity and both call/result coverage. Select
reviewed Rails that allow an ordinary amount and deny an oversized amount.
Use your AuthRail administrator to confirm the AI Inventory identity and
deployment, select exact published Rail Versions, register the executor public
key and explicitly select Enforce. This example always requires Enforce; use
the SDK's Observe path separately to study advisory behavior.

Provision a private state directory owned by the executor process with mode
`0700`. Provision separate files for the adapter token, executor private key,
sandbox request credential, TLS certificate/key and a random 32-byte journal
key encoded as 64 hex characters. Generate the journal key with a trusted
operator tool such as `openssl rand -hex 32`; retain it with the encrypted
recovery journal. The sample encrypts recovery events using AES-256-GCM with
the deployment ID as authenticated context. Its sample-effect ledger contains
only the simulated amount and provider idempotency reference. The journal is
application recovery storage, not an AuthRail audit record or Evidence.

The sandbox request credential authorizes access to this one executor route.
It never grants direct provider access and is not the adapter token, deployment
credential or executor signing key. Give each sandbox a separate request
credential and immutable binding. `protectedExecutor` rejects caller-supplied
identity fields. Trusted application code fixes the principal, session,
deployment and Operation Version; `prepare` resolves resource identity and
facts behind that boundary. Do not turn an unverified sandbox name or an agent
request into a tenant-confirmed workload identity.

## Create and inspect containment

Have the customer operate a pinned OpenShell gateway and sandbox image using
the [official installation and gateway documentation](https://docs.nvidia.com/openshell/latest/).
This integration does not install or restart a customer's gateway. Review
`policy.yaml`: replace `executor.example.com` and `/usr/bin/curl` with the
actual HTTPS executor origin and executable in your reviewed sandbox image.
Do not add provider endpoints, sidecar access, host sockets or private credential
directories. Add model inference destinations only through a separate reviewed
provider configuration; the template intentionally allows only the executor.

The OpenShell network supervisor must trust the executor's HTTPS certificate,
separately from the workload's trust store. A private CA installed only in the
workload is insufficient for REST inspection. Use your reviewed supervisor
trust configuration and keep verification enabled. The isolated validation
harness appends its disposable public CA to a supervisor derived from the
pinned upstream image; no private key enters either image. Docker Desktop
validation used the Docker driver's explicit bridge networking. Review the
actual gateway configuration and callback hostname/certificate SANs rather
than silently enabling host networking or disabling TLS.

Create a **new** sandbox with your reviewed policy using the official CLI:

```sh
openshell sandbox create --name customer-agent --policy policy.yaml
openshell sandbox get customer-agent -o json
openshell policy get customer-agent --full -o json
openshell policy get customer-agent --rev 1 -o json
```

Use explicit gateway and workspace selection when several exist. The inspector
always supplies both. Obtain the immutable sandbox ID from `sandbox get`, not
from an agent's request. Check the actual loaded revision; `effective` desired
configuration alone does not establish that it loaded in a sandbox. Review all
provider-composed effective rules and global settings. The current inspector
rejects a global policy override rather than treating an unreviewed replacement
as equivalent to the reviewed sandbox policy.

Save the effective-policy JSON output privately, review its `policy` field,
and calculate its canonical digest:

```sh
node --input-type=module -e 'import {readFileSync} from "node:fs"; import {effectivePolicyDigest} from "./containment.mjs"; console.log(effectivePolicyDigest(JSON.parse(readFileSync(process.argv[1],"utf8")).policy))' /private/effective-policy.json
```

Put that digest, exact revision, immutable sandbox ID, sandbox name, gateway
name, workspace and absolute pinned CLI path in the settings. The inspector
requires OpenShell 0.1.6, the exact policy and sandbox, `hard_requirement`
Landlock, a `loaded` active revision and a `Ready` sandbox. It reads effective
configuration before and after inspection and rejects changes between them.
It removes inherited OpenShell endpoint/TLS-override variables before invoking
the CLI. Keep the CLI registration, settings, filesystem and operator account
outside sandbox control; this is upstream-reported state, not independent kernel
attestation. There is still a time-of-check boundary: revoke executor ingress
when containment changes or trust is lost.

## Run and call the executor

Configure a trusted TLS chain valid for the exact hostname the sandbox uses.
Never bypass certificate validation. The default example listener is host
loopback, so explicitly configure private ingress or a trusted HTTPS reverse
proxy that the sandbox can reach. In Docker, the executor shares the sidecar's
network namespace; publish only the HTTPS application ingress, never port7078.
The sandbox belongs in a separate namespace with no executor filesystem mounts.

```sh
node start.mjs ./example-config.mjs
```

Inside the sandbox, send only a stable request key and arguments to the reviewed
executor URL. Reuse the same key for retries of the same business request.
The body is exactly:

```json
{"requestKey":"sample-invoice-001","arguments":{"amount":80}}
```

Send it as `POST /execute`, `Content-Type: application/json`, with
`Authorization: Bearer <sandbox request credential>`. Use your application's
protected request-credential mechanism; do not paste credentials into shell
history or commit them in examples. The handler derives a deployment-scoped
Action key from the fixed sandbox ID and this request key. Changing the key
means a new business request; it cannot serve as provider reconciliation.

An allowed request returns HTTP200 with `status: allowed`, an Action ID and
the checked result. It means call and result checks passed and the executor
reported completion. It is not independent provider proof. HTTP409 `blocked`
runs no new effect; a duplicate is blocked, not re-executed or silently served
from an invented cached result. `approval_required` preserves an encrypted
continuation for protected application recovery. `result_withheld` means an
effect may already have occurred. `outcome_unknown` requires reconciliation
with the original provider idempotency key before any retry. HTTP503 indicates
missing containment, protected context or recovery storage. Inspect protected
recovery state instead of changing the request key to force a retry.

Approvals are handled outside the agent route. Load the original protected
event using the example's operator-only `loadEvent(id)`, verify ownership and
human review, then pass that event to `protectedApprovalRecovery(config)` from `executor.mjs`.
It checks the saved sandbox/deployment/Operation/principal/session binding and
live containment before claiming permission and immediately before the effect.
A lost claim response uses the same function with `{ recoverExistingPermit: true }`
to recover only an existing valid permit. It retains the same durable started
write and provider idempotency behavior. There is
no sandbox-accessible resume/reconcile endpoint in this example. Never accept
an approval continuation or claimed provider outcome from the agent.

## Lifecycle and bypass review

Record live containment reports with the protected application journal. Missing,
stopped, changed, incompatible or unreachable containment blocks new calls.
`start.mjs` drains in-flight requests on SIGTERM for up to30 seconds. A process
crash after an attempted effect leaves recovery work; restart never reruns an
effect automatically. Preserve the journal encryption key, SQLite database/WAL,
deployment identity, sandbox binding, session and complete sidecar state on
upgrades. Recreating a sandbox changes its identity and requires reviewed binding,
not a silent name-based substitution. Review new upstream versions and rerun
the checks before updating the pinned CLI.

Before claiming Enforce protection, run from the actual sandbox: one allowed
request, one denied request with zero ledger effect, a duplicate request, a
direct provider request, a sidecar request, credential-file reads, disallowed
binary/network requests, stopped containment, policy replacement and executor
unavailability. Verify the exact loaded policy and relevant OpenShell lifecycle
and OCSF events. Review inference grants, provider-composed rules, executable
replacement, mounts, subprocesses, subagents, host services and alternate
credential paths. An upstream policy report cannot replace those probes.

Run the existing AuthRail protocol-boundary verification from the sidecar root:

```sh
AUTHRAIL_OPENSHELL_INTEGRATION=1 go test ./sidecar -run TestOpenShellProtectedExecutorWithNodeAndRealSidecar -v
```

It builds on the sibling Node SDK's existing `dist` build. Keep its result
separate from actual OpenShell containment acceptance and real-server retention.
See the pinned upstream [policy schema](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/docs/how-it-works/policies/schema.mdx)
and [supervisor middleware boundary](https://github.com/NVIDIA/OpenShell/blob/v0.1.6/docs/extensibility/supervisor-middleware/index.mdx).
