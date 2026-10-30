# Runtime compatibility and coverage

Use this reference to choose the sidecar and SDK versions for an application,
understand the checks behind them, and review the paths your deployment
protects. A compatible protocol is necessary; it does not automatically place
checks around every tool or prove an external business effect.

## Published components

| Component | Version | Install or download |
| --- | --- | --- |
| AuthRail sidecar | `0.1.0` | [Native archives and checksums](https://github.com/AuthRail/authrail-sidecar/releases/tag/v0.1.0) for macOS/Linux, amd64/arm64. For Docker, [build from source](docker/README.md). |
| Node SDK | `0.1.1` | [@authrail/sdk-node on npm](https://www.npmjs.com/package/@authrail/sdk-node): `npm install @authrail/sdk-node@0.1.1` |
| Python SDK | `0.1.1` | [authrail on PyPI](https://pypi.org/project/authrail/): `python -m pip install authrail==0.1.1` |
| Go SDK | `v0.1.1` | [Module documentation](https://pkg.go.dev/github.com/AuthRail/authrail-sdk-go): `go get github.com/AuthRail/authrail-sdk-go@v0.1.1` |

The SDK `0.1.1` tags have the same Runtime implementation as their respective
`0.1.0` tags. Their changes are documentation, publication workflow and package
version metadata. Node `src/`, Python `src/authrail/`, and Go Runtime sources and
module dependencies have no differences between those tags. These are separate
SDK and sidecar version numbers; they do not need to match numerically.

Native archive checksums and `--version` identify the downloaded sidecar build.
For a locally built Docker image, retain its source revision and image digest.
The source-build instructions do not require public container-registry access.
An uploaded registry image must not be treated as anonymously available until
its access has been checked.

## Verification evidence and its limits

Node and Go have connected checks of call/result decisions, retained execution
reports and approval/recovery transitions against AuthRail services and
PostgreSQL. Python's installed `0.1.0` wheel also passed allow, deny/no effect,
approval wait/no effect, named review, encrypted continuation and fresh-client
resume, and consumed-approval blocking against a packaged sidecar and actual
server services with disposable PostgreSQL. The unchanged Runtime sources in
SDK `0.1.1` preserve that implementation; package installation/import checks
also cover the published versions.

These checks use isolated business effects. They do not establish a real
provider payment, independent provider verification, or coverage of all routes
in a customer's application. Source-level evidence does not mean every
released image/platform combination has repeated the entire connected journey.
The release pipeline's build and package checks remain distinct from that
journey and from customer acceptance.

<details>
<summary>Earlier source-level evidence and scope</summary>

**Earlier connected source check — October 21, 2026**

| Component | Source revision | Connected evidence |
| --- | --- | --- |
| Server | `9e69d3f`, disposable database through `0226` | HTTP controllers persisted one-use approval, duplicate-safe receipts, unknown outcome, and reconciliation; signed-bundle evaluation retained two SDK Enforce Actions and their call/result certificates. |
| Sidecar | `1fea940` | The checksummed local Linux archive checked the signed Enforce bundle and forwarded decisions, claims, and receipts. Isolated install and restart checks also passed. |
| Node SDK | `756e223` | The extracted npm package protected a tool callback through the sidecar/server Enforce path; two receipts and two certificates were retained. Connected Observe and 23 local tests also passed. |
| Go SDK | `5fdc3cb` | Protected HTTP handler reached the same sidecar/server Enforce path; two receipts and two certificates were retained. Connected Observe and local tests also passed. |

The connected test used mock business effects in the protected callbacks and
a seeded approved Action for the raw HTTP approval/recovery path. It proves the
wire and persistence transitions, not a real provider effect or an independent
provider outcome lookup. The separate Observe test rolls back its Actions.
These checks establish a source combination for development, not release
artifacts or a customer deployment coverage review.

**Coverage demonstrated by that check**

| Adapter path | Intercepted here | Outside this fixture's claim |
| --- | --- | --- |
| Node tool callback | One call, its mock provider effect, start/success receipts, and result | Other tools, direct provider access, local files, shell, egress, and subagents. The fixed test principal must be replaced by authenticated application context. |
| Go HTTP handler | One `POST /payments` request, its mock provider effect, start/success receipts, and result | Other routes, direct provider access, files, shell, egress, and subagents. The fixed test principal must be replaced by authenticated middleware context. |
| Raw HTTP approval/effects | Signed permit claim, duplicate start, unknown outcome, and reconciled failure on a seeded approved Action | Human review UI, independent provider lookup, and automatic callback recovery. |

An Enforce claim for a customer deployment requires a separate inventory of all
paths to each provider and its credentials. Any path that bypasses the protected
executor makes that deployment advisory, even when these tests pass.


</details>

## Protocol and state requirements

| Component | Contract | Required check |
| --- | --- | --- |
| Signed Rail bundle | Manifest `formatVersion: 1`; exact organisation and deployment, trusted signing key, sequence, activation and expiry. | Local health shows the valid expected bundle and sequence. |
| Local decisions | Evaluation `formatVersion: 1`, Ed25519 executor proof, stable Action key, call and result checks. | Shared `conformance/v1` examples check canonical encoding, signed requests, decisions and failures. |
| Approval and execution reports | One-use permit claim and signed receipts binding the Action, attempt and event. | Check saved approval/resume and execution recovery against the deployed server's contract. |
| Node adapter | Observe and Enforce; Observe remains advisory. | `npm test`, package-content checks and the application's protected callback. |
| Python adapter | Asyncio Observe and Enforce, callable from a script through `asyncio.run`; Observe remains advisory. | Python package checks and the application's protected callback, including saved approval continuation/recovery. |
| Go adapter | Observe and Enforce; Observe remains advisory. | `go test ./...`, signed sidecar checks and the application's protected function or handler. |
| Private sidecar state | Disk format 1, accepted sequence protection, report queue and saved session history. | Preserve the entire private state set through restarts and upgrades. |

## Verify the application's coverage

Before enabling Enforce, exercise an allowed request, a denied request and an
approval-required request using the actual protected function. Check that a
denial has no effect, that approval resumes the same saved call, and that an
uncertain response is reconciled without duplicating the operation. A call
report only saved in a local queue cannot start Enforce execution.

Review every route to the same provider and its credentials: other tools,
HTTP routes, shell commands, files, network access and subagents. A route that
bypasses the protected executor makes that path advisory, even with a healthy
sidecar. Keep those gaps visible instead of inferring coverage from a passing
protocol test.

Before changing versions, preserve state, keys, pending approvals and
application recovery records. Test the intended combination in a safe
installation. A format number names a message or disk shape; it does not prove
business idempotency, complete interception or acceptance of the deployment.
