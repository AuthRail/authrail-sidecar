import assert from 'node:assert/strict';
import { resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { protectedApprovalRecovery } from './executor.mjs';

// These stubs exercise only the wrapper's containment and recovery-storage gate.
// Actual permit issuance, consumption and SDK recovery have separate connected checks.
function fixture({ containment = [true, true], storageFails = false } = {}) {
  const binding = { sandboxId: 'sandbox-one', sessionId: 'session-one', principalId: 'service-one',
    deploymentId: 'deployment-one', operationVersionId: 'operation-one' };
  const actionKey = `os-${'a'.repeat(64)}`;
  const event = { type: 'approval_required', sandboxId: binding.sandboxId,
    deploymentId: binding.deploymentId, operationVersionId: binding.operationVersionId, actionKey,
    continuation: { call: { actionKey, operationVersionId: binding.operationVersionId,
      principalId: binding.principalId, sessionId: binding.sessionId,
      principalSource: 'service_identity', arguments: { amount: 80 } },
    decision: { mode: 'enforce', outcome: 'approval_required', recordingStatus: 'retained', actionId: 'action-one' } } };
  const order = [];
  let checks = 0;
  let effects = 0;
  const sdk = async (kind, continuation, callback) => {
    order.push(kind);
    const result = await callback(continuation.call.arguments, { providerIdempotencyKey: 'provider-one' });
    return { result, permitId: 'permit-one' };
  };
  const recover = protectedApprovalRecovery({ binding,
    client: { resumeApprovalFrom: (continuation, callback) => sdk('claim', continuation, callback),
      recoverApprovalFrom: (continuation, callback) => sdk('recover', continuation, callback) },
    containment: async () => { order.push(`containment-${++checks}`); return containment[checks - 1] ?? false; },
    record: async (record) => {
      order.push(`record-${record.type}`);
      assert.equal(record.sandboxId, binding.sandboxId);
      assert.equal(record.actionKey, actionKey);
      if (storageFails) throw new Error('Storage unavailable');
    },
    execute: async (input, recovery, correlation) => {
      order.push('effect');
      effects++;
      assert.deepEqual(input, { amount: 80 });
      assert.equal(recovery.providerIdempotencyKey, 'provider-one');
      assert.equal(correlation.deploymentId, binding.deploymentId);
      return { accepted: true };
    },
  });
  return { recover, event, order, effects: () => effects };
}

/** Verify the wrapper blocks delayed approvals after containment or binding changes. */
export async function verifyProtectedApprovalRecovery() {
  const stale = fixture({ containment: [false] });
  await assert.rejects(stale.recover(stale.event), /Containment unavailable/);
  assert.deepEqual(stale.order, ['containment-1']);
  assert.equal(stale.effects(), 0);

  for (const change of [
    (event) => { event.sandboxId = 'different-sandbox'; },
    (event) => { event.deploymentId = 'different-deployment'; },
    (event) => { event.operationVersionId = 'different-operation'; },
    (event) => { event.continuation.call.principalId = 'different-principal'; },
    (event) => { event.continuation.call.sessionId = 'different-session'; },
    (event) => { event.continuation.call.actionKey = `os-${'b'.repeat(64)}`; },
  ]) {
    const changed = fixture();
    change(changed.event);
    await assert.rejects(changed.recover(changed.event), /does not match/);
    assert.deepEqual(changed.order, []);
    assert.equal(changed.effects(), 0);
  }

  const lost = fixture({ containment: [true, false] });
  await assert.rejects(lost.recover(lost.event), /Containment unavailable before approved effect/);
  assert.deepEqual(lost.order, ['containment-1', 'claim', 'record-started', 'containment-2']);
  assert.equal(lost.effects(), 0);

  const disk = fixture({ storageFails: true });
  await assert.rejects(disk.recover(disk.event), /Storage unavailable/);
  assert.deepEqual(disk.order, ['containment-1', 'claim', 'record-started']);
  assert.equal(disk.effects(), 0);

  for (const recoverExistingPermit of [false, true]) {
    const valid = fixture();
    const result = await valid.recover(valid.event, { recoverExistingPermit });
    assert.deepEqual(result.result, { accepted: true });
    assert.equal(valid.effects(), 1);
    assert.deepEqual(valid.order, ['containment-1', recoverExistingPermit ? 'recover' : 'claim',
      'record-started', 'containment-2', 'effect', 'record-completed']);
  }
  console.log('Approval wrapper: changed binding, unavailable/lost containment and failed durable start block effects; claim and existing-permit paths preserve ordering. SDK/server permit semantics are not simulated evidence.');
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await verifyProtectedApprovalRecovery();
}
