// Run through TestOpenShellProtectedExecutorWithNodeAndRealSidecar, not directly.
import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { EnforceClient } from '../../../authrail-sdk-node/dist/index.js';
import { protectedExecutor } from './executor.mjs';

Date.now = () => Date.parse(process.env.AUTHRAIL_FIXTURE_NOW);
const config = JSON.parse(process.env.AUTHRAIL_FIXTURE_CONFIG);
let effects = 0;
let contained = true;
let storage = true;
const events = [];
const handler = protectedExecutor({ client: new EnforceClient(config),
  binding: { token: 'sandbox-only-abcdefghijklmnopqrstuvwxyz', sandboxId: 'sandbox_1',
    sessionId: 'sandbox_session_1', principalId: 'sandbox_1', deploymentId: config.deploymentId,
    operationVersionId: '00000000-0000-4000-8000-000000000008' },
  containment: async () => contained,
  prepare: async () => ({ resourceId: null, resourceSource: 'not_applicable' }),
  record: async (event) => { if (!storage) throw new Error('Disk unavailable'); events.push(event); },
  execute: async (input, recovery) => {
    assert.equal(input.amount, 10);
    assert.ok(recovery.providerIdempotencyKey.startsWith('ar-'));
    assert.equal(events.at(-1).type, 'started');
    effects++;
    return { accepted: true };
  } });
const server = createServer(handler);
await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
try {
  const url = `http://127.0.0.1:${server.address().port}/execute`;
  const invoke = async (requestKey, amount, extra = {}, token = 'sandbox-only-abcdefghijklmnopqrstuvwxyz') => {
    const response = await fetch(url, { method: 'POST',
      headers: { authorization: `Bearer ${token}`, 'content-type': 'application/json' },
      body: JSON.stringify({ requestKey, arguments: { amount }, ...extra }) });
    return { code: response.status, body: await response.json() };
  };
  assert.equal((await invoke('auth', 10, {}, 'wrong')).code, 401);
  assert.equal((await invoke('identity', 10, { principalId: 'other' })).code, 400);
  assert.equal((await invoke('allowed', 10)).body.status, 'allowed');
  assert.equal(effects, 1);
  assert.equal((await invoke('allowed', 10)).body.status, 'blocked');
  assert.equal((await invoke('denied', 1000)).body.status, 'blocked');
  contained = false;
  assert.equal((await invoke('stale', 10)).body.status, 'containment_unavailable');
  contained = true;
  storage = false;
  assert.equal((await invoke('disk', 10)).body.status, 'outcome_unknown');
  storage = true;
  await fetch(config.sidecarUrl + '/fixture/offline', {method:'POST'});
  assert.equal((await invoke('offline', 10)).body.status, 'blocked');
  assert.equal(effects, 1);
  console.log('Real SDK/sidecar: authenticated fixed identity, allow, replay, deny, stale containment, recovery-write failure and offline retention passed; exactly one isolated effect.');
} finally {
  await new Promise((resolve) => server.close(resolve));
}
