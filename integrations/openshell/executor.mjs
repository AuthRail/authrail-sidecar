import { createHash, timingSafeEqual } from 'node:crypto';

const digest = (value) => createHash('sha256').update(value).digest();
const object = (value) => value !== null && typeof value === 'object' && !Array.isArray(value);
const key = (value) => typeof value === 'string' && /^[A-Za-z0-9_-]{1,96}$/.test(value);

/**
 * Place this handler outside the sandbox, behind authenticated HTTPS. One handler
 * binds one sandbox to one deployment and one exact reviewed Operation Version.
 * The request credential grants access to this boundary, never to the provider.
 * `prepare` authenticates resource context and resolves facts in protected code.
 * `record` must durably retain recovery/approval state before acknowledging it.
 */
export function protectedExecutor({ client, binding, prepare, execute, record, containment }) {
  if (!client || typeof client.enforce !== 'function' || !object(binding) ||
      typeof binding.token !== 'string' || binding.token.length < 32 ||
      !key(binding.sandboxId) || !key(binding.sessionId) || !binding.principalId ||
      !binding.operationVersionId || !binding.deploymentId ||
      ![prepare, execute, record, containment].every((fn) => typeof fn === 'function')) {
    throw new Error('Protected executor configuration is incomplete');
  }
  // Copy identity once; a later mutation must not move this handler to another tenant.
  const identity = Object.freeze({ ...binding });
  const credential = digest(`Bearer ${identity.token}`);
  return async (request, response) => {
    const send = (status, body) => {
      if (response.destroyed || response.writableEnded) return;
      response.writeHead(status, { 'content-type': 'application/json',
        'cache-control': 'no-store', 'x-content-type-options': 'nosniff' });
      response.end(JSON.stringify(body));
    };
    if (!timingSafeEqual(credential, digest(request.headers.authorization ?? ''))) {
      request.resume();
      send(401, { status: 'unauthorized' });
      return;
    }
    if (request.method !== 'POST' || request.url !== '/execute') {
      request.resume();
      send(404, { status: 'not_found' });
      return;
    }
    let body;
    try {
      if (request.headers['content-type']?.split(';')[0].trim() !== 'application/json') {
        request.resume();
        send(415, { status: 'invalid_content_type' });
        return;
      }
      let bytes = 0;
      const chunks = [];
      for await (const chunk of request) {
        bytes += chunk.length;
        if (bytes > 64 * 1024) {
          send(413, { status: 'input_too_large' });
          request.resume();
          return;
        }
        chunks.push(chunk);
      }
      body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      if (!object(body) || Object.keys(body).sort().join(',') !== 'arguments,requestKey' ||
          !key(body.requestKey) || !object(body.arguments)) throw new Error('Invalid request');
    } catch {
      send(400, { status: 'invalid_request' });
      return;
    }
    const actionKey = `os-${digest(`${identity.sandboxId}:${body.requestKey}`).toString('hex')}`;
    const correlation = { sandboxId: identity.sandboxId, deploymentId: identity.deploymentId,
      operationVersionId: identity.operationVersionId, actionKey };
    let effectStarted = false;
    try {
      // Operator-owned, live containment review. An agent-supplied policy claim
      // must never satisfy this check. Missing/stale/error signals block Enforce.
      if (await containment(correlation) !== true) {
        send(503, { status: 'containment_unavailable' });
        return;
      }
      const context = await prepare(body.arguments, correlation);
      if (!object(context) || !['application_lookup', 'not_applicable'].includes(context.resourceSource)) {
        throw new Error('Protected resource context is missing');
      }
      const operation = { ...context, operationVersionId: identity.operationVersionId,
        actionKey, principalId: identity.principalId, principalSource: 'service_identity',
        sessionId: identity.sessionId };
      const checked = await client.enforce(operation, body.arguments, async (input, recovery) => {
        // SDK retained a fresh started receipt. Persist provider recovery identity
        // before attempting the effect; a failed write never executes the tool.
        await record({ ...correlation, type: 'started', recovery });
        effectStarted = true;
        return execute(input, recovery, correlation);
      });
      await record({ ...correlation, type: 'completed', actionId: checked.callDecision.actionId });
      send(200, { status: 'allowed', actionId: checked.callDecision.actionId, result: checked.result });
    } catch (error) {
      // Errors and raw provider payloads never cross the agent boundary.
      if (error?.name === 'EnforceOutcomeUnknownError') {
        try { await record({ ...correlation, type: 'unknown', recovery: error.recovery }); } catch { /* started state remains authoritative */ }
        send(409, { status: 'outcome_unknown' });
      } else if (error?.name === 'EnforceBlockedError') {
        if (error.approvalContinuation) {
          try {
            await record({ ...correlation, type: 'approval_required', continuation: error.approvalContinuation });
          } catch {
            send(503, { status: 'recovery_storage_unavailable' });
            return;
          }
        }
        const status = error.effectMayHaveOccurred ? 'result_withheld' :
          error.approvalContinuation ? 'approval_required' : 'blocked';
        send(409, { status, actionId: error.decision?.actionId });
      } else {
        send(effectStarted ? 409 : 503, { status: effectStarted ? 'result_withheld' : 'executor_unavailable' });
      }
    }
  };
}

/**
 * Resume only an operator-loaded, protected approval event for this exact sandbox.
 * Containment is checked before permit recovery and again before the effect.
 * Never expose this function or the encrypted continuation through sandbox ingress.
 */
export function protectedApprovalRecovery({ client, binding, execute, record, containment }) {
  if (!client || !object(binding) || !key(binding.sandboxId) || !key(binding.sessionId) ||
      !binding.principalId || !binding.deploymentId || !binding.operationVersionId ||
      ![client.resumeApprovalFrom, client.recoverApprovalFrom, execute, record, containment]
        .every((value) => typeof value === 'function')) {
    throw new Error('Protected approval recovery configuration is incomplete');
  }
  const identity = Object.freeze({ ...binding });
  return async (savedEvent, { recoverExistingPermit = false } = {}) => {
    if (typeof recoverExistingPermit !== 'boolean') throw new Error('Explicit recovery mode required');
    // Snapshot protected storage before asynchronous checks so callers cannot
    // swap the approved input or its binding while containment is inspected.
    const serialized = JSON.stringify(savedEvent);
    if (typeof serialized !== 'string' || Buffer.byteLength(serialized) > 256 * 1024) {
      throw new Error('Protected approval event is invalid');
    }
    const event = JSON.parse(serialized);
    const call = event?.continuation?.call;
    const decision = event?.continuation?.decision;
    if (event.type !== 'approval_required' || event.sandboxId !== identity.sandboxId ||
        event.deploymentId !== identity.deploymentId || event.operationVersionId !== identity.operationVersionId ||
        typeof event.actionKey !== 'string' || !/^os-[a-f0-9]{64}$/.test(event.actionKey) ||
        !object(call) || call.actionKey !== event.actionKey ||
        call.operationVersionId !== identity.operationVersionId ||
        call.principalId !== identity.principalId || call.sessionId !== identity.sessionId ||
        call.principalSource !== 'service_identity' || !object(decision) ||
        decision.mode !== 'enforce' || decision.outcome !== 'approval_required' ||
        decision.recordingStatus !== 'retained' || typeof decision.actionId !== 'string') {
      throw new Error('Protected approval event does not match this sandbox binding');
    }
    const correlation = { sandboxId: identity.sandboxId, deploymentId: identity.deploymentId,
      operationVersionId: identity.operationVersionId, actionKey: event.actionKey };
    if (await containment(correlation) !== true) throw new Error('Containment unavailable for approval recovery');
    const callback = async (input, recovery) => {
      await record({ ...correlation, type: 'started', recovery });
      if (await containment(correlation) !== true) throw new Error('Containment unavailable before approved effect');
      return execute(input, recovery, correlation);
    };
    const result = recoverExistingPermit
      ? await client.recoverApprovalFrom(event.continuation, callback)
      : await client.resumeApprovalFrom(event.continuation, callback);
    await record({ ...correlation, type: 'completed', actionId: decision.actionId });
    return result;
  };
}
