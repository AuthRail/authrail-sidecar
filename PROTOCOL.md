# Local Runtime adapter protocol, format 1

The local sidecar is bound to one deployment. A protected application calls it
on loopback with a separate adapter Bearer token. The deployment credential
stays in the sidecar; provider and signing credentials stay in the protected
application. The application authenticates its caller, resolves the resource,
and reviews every path by which the agent could reach the provider. An
unprotected equivalent path is bypass exposure, regardless of a healthy
sidecar or a passing conformance test.

## Call and result checks

`POST /evaluate` requires `Authorization: Bearer <adapter token>`, a stable
business `Idempotency-Key`, `Content-Type: application/json`, and this JSON
shape:

```json
{
  "formatVersion": 1,
  "requestId": "00000000-0000-4000-8000-000000000001",
  "operationVersionId": "00000000-0000-4000-8000-000000000002",
  "phase": "tool_call",
  "arguments": { "invoiceId": "invoice_123" },
  "attribution": {
    "principalId": "staff_123",
    "sessionId": "task_123",
    "resourceId": "invoice_123",
    "principalSource": "application_session",
    "resourceSource": "application_lookup"
  },
  "identityProof": {
    "issuedAt": 0,
    "expiresAt": 0,
    "signature": "base64url Ed25519 signature from the protected application"
  }
}
```

The displayed times and signature are placeholders for the field shape, not a
usable request. The live proof has a short validity window. The signed
statement is `authrail.observe.executor.v1` and binds organisation and
deployment, request ID, stable action key, exact Operation Version, phase,
SHA-256 of the canonical input, attribution, optional human review summary
digest, and issue/expiry times. The canonical input is a JSON object in this
order: `arguments`, optional `result` for `tool_result`, optional
`factResolutions`, optional `trajectory`. Object keys within arguments and
values are sorted by UTF-8 bytes, matching Go `encoding/json`. Use the Node or
Go SDK source and the signed proof tests as executable examples. A customer
adapter must reproduce those bytes exactly; an imported OpenAPI operation or
agent-supplied argument is not a reviewed executor contract.

For `tool_result`, reuse the same request ID, action key, exact Operation,
attribution, facts, and trajectory; add a bounded JSON object `result` and
sign a new phase proof. A call decision never proves that the tool ran. In
Observe, both decisions are advisory. In Enforce, the adapter may invoke its
protected executor only after a fresh covered `allow` with
`recordingStatus: retained` and `reportReplayed: false`. Missing, queued,
uncovered, unavailable, replayed, denied, or mismatched responses stop that
path. The result must be checked before exposing it. A result denial can
withhold output but cannot reverse an earlier external effect.

An `approval_required` decision is a durable wait, not permission to run. A
named human reviews the bound call; the protected executor then sends a fresh
signed `POST /approval-permits/claim`. A successful one-use permit binds the
same Action and input. An uncertain claim cannot be retried blindly. The
Policy may return `approval_required` again for the result because it evaluates
the same business arguments. An adapter may release that retained result only
with a previously claimed permit for the same Action; a denied, missing,
replayed, or different-Action result still blocks exposure.
signed `POST /approval-permits/recover` reads only an existing unexpired permit
for the same Action, input, and executor before any start receipt. It never
issues a second permit. An unavailable read cannot authorize a callback. The
protected executor sends signed `POST /execution-receipts` events for
`started`, `succeeded`, or `unknown`, with `Idempotency-Key` equal to
`<Action ID>:<attempt ID>:<event>`. The attempt ID is the checked call request
ID. The provider idempotency key is `ar-<Action ID>` and remains stable across
attempts. The sidecar forwards signed executor assertions; it never executes
the business operation or verifies the provider result. For an uncertain
outcome, the executor checks the provider by the original key and reports
`reconciled_succeeded` or `reconciled_failed` with a provider reference. Only
an authenticated no-effect reconciliation can permit a fresh attempt.

The optional W3C `traceparent` header is validated and forwarded with checks,
claims, receipts, and queued Observe reports. It is correlation only. Do not
put sensitive payloads in trace fields or use them as identity or proof.

## Guard processing requirements

Guard format 3 may attach `obligations` to a condition rule. Each obligation
contains `kind` (`sanitize`, `transform`, or `isolate`), `handlerId`, an exact
64-character lowercase SHA-256 `handlerVersion`, and `target` with `root`
(`arguments` at tool call or `result` at tool result) and a reviewed field
`path`. Processing is required for that phase regardless of whether the
condition later matches. Conditions are evaluated against the processed value.
Sanitization and transformation target string fields. They cannot change the
Operation's resource identity. Isolation is a required protected boundary,
not a Boolean supplied by an agent; adapters without a supported isolation
handler must stop.

`GET /guard-requirements?operationVersionId=<UUID>&phase=tool_call|tool_result`
uses the local adapter Bearer token. It returns `formatVersion: 1`, the exact
Operation and phase, `bundleId`, `sequence`, `coverage`, and `requirements`.
Each requirement includes its `railVersionId`, `ruleId`, and the obligation
fields above. This read does not authorize a call, update trajectory, create
an Action, or retain a Decision Certificate. Unavailable or uncovered lookup
cannot authorize processing or execution. The final evaluation rechecks the
current signed bundle; a stale plan cannot fulfil a new requirement.

The protected adapter runs only an application-registered handler whose ID,
version and kind match. It passes that handler a copy of the target string,
changes only that exact field, and computes SHA-256 over the canonical JSON
string before and after processing. It sends optional `guardEvidence` in the
signed evaluation input, after `trajectory`: an ordered array of
`{phase,bundleId,kind,handlerId,handlerVersion,target,inputSha256,outputSha256}`.
Object keys inside this array use canonical JSON ordering. The evidence is
part of the signed input digest. Only call-phase evidence enters the stable
effect digest, so checking a result does not change the effect identity. Result checks keep call-phase evidence as well as their own.
The sidecar checks the exact bundle, handler, phase, field, and output digest
before applying the conditions. Different handlers for overlapping targets
conflict; identical requirements are fulfilled once. Evidence never grants
business permission or overrides a deny, missing fact, or approval.

`evaluation.obligations` records the exact requirements with `status` set to
`fulfilled`, `missing`, or `conflict`, and bounded before/after digests when
fulfilled. Missing or conflicting requirements cannot return allow or a
claimable approval. Observe remains advisory and does not transform the
customer's tool inputs or results. Application signatures identify the
executor's assertions; they do not independently verify handler code, content
classification, or sandbox containment. Unsupported isolation remains blocked
until a concrete supported adapter establishes its protected boundary.

## Conformance and coverage

`conformance/v1` is the source fixture corpus mirrored in the Node and Go SDK
repositories. Both SDK test suites execute decision, canonical input, and
failure cases. A deterministic Go SDK proof is also verified by the real
sidecar handler. Source and mirrors must be byte-identical when changed.
Existing sidecar handler tests cover request authentication,
signature verification, report retention, approval forwarding, and receipt
forwarding. A customer-built adapter should run the same cases plus exact
canonicalization, malformed input, timeout, retry, and result-hook tests
against its own host. Passing these fixtures proves translation behavior,
not complete interception. Inventory the agent's tool calls, tool results,
subagents, local files, shell, network egress, provider credentials, and
unknown tools; disclose uncovered or bypass paths in the deployment review.

## Execution outcomes in Observe

Observe does not authorize execution, but the protected executor can report
what actually happened. This uses the existing execution receipt lifecycle,
with no permit and no blocking start step. Only the executor may classify
`succeeded`, `failed`, `unknown`, `reconciled_succeeded`, or `reconciled_failed`.
A tool exception alone does not prove no effect happened.

`POST /execution/observed-receipts` uses the adapter Bearer token and
`Idempotency-Key: operationVersionId:actionKey:attemptId:event`. Its exact body
is `{operationVersionId,actionKey,attemptId,event,inputSha256,
providerIdempotencyKey,providerReference,keySha256,proof}`. IDs, references, and
digests use the existing protocol bounds. The input digest is the original
canonical tool-call input, including its facts and trajectory. `attemptId` is
the original prepared call request ID; it must not be regenerated for reporting.
No raw input or result is sent.

The Ed25519 statement has this exact key order:
`{type,organisationId,deploymentId,operationVersionId,actionKey,attemptId,event,
inputSha256,providerIdempotencyKey,providerReference,keySha256,issuedAt,expiresAt}`
with `type: authrail.execution.receipt.observe.v1`. Proof spans at most 30
seconds. Delayed, signed outcome evidence remains historical evidence after
that window; it never grants permission. Final intake requires the current
registered executor key to match the independently verified original Observe
call and its exact input and attempt. Observe completion can accompany an
advisory deny without changing that decision.

The sidecar verifies and durably queues evidence in its existing private report
state, sharing the 512-entry and 40 MiB bounds with decision reports. Decision
reports flush before outcomes; unavailable matching calls remain queued.
`202 {recordingStatus: queued}` means local persistence only.
`201 {recordingStatus: retained,receiptId,actionId,state,replayed}` means central
retention. Report delivery failure must never rerun the business operation.
Unresolved effects remain unknown until explicit provider reconciliation.

Central receipt retention stores the exact signed statement, signature, and
public-key snapshot. Older receipts without that retained assertion must remain
identifiable as older evidence; never synthesize a signature for them.
