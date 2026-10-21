# Runtime compatibility, current development contract

These are protocol requirements for the current source trees. They are not a
published release matrix or a guarantee that independently installed package
versions have passed connected acceptance. Pin all components to versions
verified together before enabling Enforce.

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
