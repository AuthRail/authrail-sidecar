# Runtime compatibility, current development contract

These are protocol requirements for the current source trees. They are not a
published release matrix or a guarantee that independently installed package
versions have passed connected acceptance. Pin all components to versions
verified together before enabling Enforce.

## Locally checked source combination, October 21, 2026

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

### Coverage demonstrated by this fixture

| Adapter path | Intercepted here | Outside this fixture's claim |
| --- | --- | --- |
| Node tool callback | One call, its mock provider effect, start/success receipts, and result | Other tools, direct provider access, local files, shell, egress, and subagents. The fixed test principal must be replaced by authenticated application context. |
| Go HTTP handler | One `POST /payments` request, its mock provider effect, start/success receipts, and result | Other routes, direct provider access, files, shell, egress, and subagents. The fixed test principal must be replaced by authenticated middleware context. |
| Raw HTTP approval/effects | Signed permit claim, duplicate start, unknown outcome, and reconciled failure on a seeded approved Action | Human review UI, independent provider lookup, and automatic callback recovery. |

An Enforce claim for a customer deployment requires a separate inventory of all
paths to each provider and its credentials. Any path that bypasses the protected
executor makes that deployment advisory, even when these tests pass.

| Component | Current contract | Required check |
| --- | --- | --- |
| Signed Rail bundle | Manifest `formatVersion: 1`; exact tenant and deployment audience, key pin, sequence, activation, and expiry | Sidecar `/health` shows the expected valid bundle and sequence. |
| Local decision HTTP | Evaluation `formatVersion: 1`, Ed25519 executor proof, stable `Idempotency-Key`, call and result phases | Run the packaged `conformance/v1` canonical, decision, failure, and signed request vectors. |
| Approval and effect HTTP | One-use permit claim and authenticated receipt endpoints; receipt event key binds Action, attempt, and event | Verify server persistence through the current Runtime receipt contract and migration 0226 or later. |
| Node adapter | Current source exports Observe and Enforce; Observe always remains advisory | `npm test` and package-content check for `dist/enforce/client.js`. |
| Go adapter | Current source exports Observe and Enforce; Observe always remains advisory | `go test ./...`; the deterministic Go proof must pass the real sidecar handler. |
| Private sidecar state | Disk format 1 with sequence floor, adjacent report queue and trajectory ledger | Preserve the whole private set on upgrade and rollback; pass isolated archive restart check. |

The format number only names a wire or disk shape. It does not prove that an
adapter intercepts every path, that a provider effect is idempotent, or that a
specific build has passed customer acceptance. A deployment's actual tool
calls, results, subagents, shell, files, egress, and credential paths need a
separate coverage and bypass review. The current compatibility claim is
limited to the validated source trees and isolated tests. A versioned release
table requires immutable artifacts and connected checks against those exact
artifacts.
