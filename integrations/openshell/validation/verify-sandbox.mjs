// Run through the opt-in Go sidecar fixture, with an existing real sandbox.
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { createServer } from 'node:https';
import { dirname, resolve } from 'node:path';
import { promisify } from 'node:util';
import { EnforceClient } from '../../../../authrail-sdk-node/dist/index.js';
import { protectedExecutor } from '../executor.mjs';
import { containmentInspector } from '../containment.mjs';

const manifestPath = process.env.AUTHRAIL_OPENSHELL_GATEWAY_MANIFEST;
assert.ok(manifestPath?.startsWith('/private/tmp/authrail-openshell-validation-'));
const directory = dirname(resolve(manifestPath));
const manifest = JSON.parse(await readFile(`${directory}/manifest.json`, 'utf8'));
const pins = JSON.parse(await readFile(`${directory}/review-pins.json`, 'utf8'));
assert.ok(manifest.gateway.startsWith('authrail-openshell-validation-'));
assert.ok(manifest.sandboxName.startsWith('ar-check-'));
assert.equal(pins.sandboxName, manifest.sandboxName);
assert.equal(pins.gateway, manifest.gateway);
const host = manifest.executorHost;
const port = Number(manifest.executorPort);
assert.ok(host && /^[a-z0-9.-]+$/.test(host));
assert.ok(Number.isSafeInteger(port) && port > 1024 && port < 65536);
process.env.XDG_CONFIG_HOME = `${directory}/config`;
process.env.XDG_STATE_HOME = `${directory}/state`;
Date.now = () => Date.parse(process.env.AUTHRAIL_FIXTURE_NOW);
const config = JSON.parse(process.env.AUTHRAIL_FIXTURE_CONFIG);
const inspect = containmentInspector(pins);
assert.equal((await inspect()).ready, true, 'Real sandbox must satisfy reviewed containment pins');
let effects = 0;
let unreviewedRequests = 0;
let reviewed = true;
const events = [];
const token = 'sandbox-only-abcdefghijklmnopqrstuvwxyz';
const handler = protectedExecutor({ client: new EnforceClient(config),
  binding: { token, sandboxId: pins.sandboxId, sessionId: 'sandbox_session_1',
    principalId: pins.sandboxId, deploymentId: config.deploymentId,
    operationVersionId: '00000000-0000-4000-8000-000000000008' },
  containment: async () => reviewed && (await inspect()).ready,
  prepare: async () => ({ resourceId: null, resourceSource: 'not_applicable' }),
  record: async (event) => { events.push(event); },
  execute: async (input, recovery) => {
    assert.equal(input.amount, 10);
    assert.ok(recovery.providerIdempotencyKey.startsWith('ar-'));
    assert.equal(events.at(-1).type, 'started');
    effects++;
    return { accepted: true };
  } });
const server = createServer({
  cert: await readFile(`${directory}/executor/server.crt`),
  key: await readFile(`${directory}/executor/server.key`),
}, (request, response) => {
  if (request.method !== 'POST' || request.url !== '/execute' ||
      request.headers['x-authrail-probe-binary'] === 'node') unreviewedRequests++;
  return handler(request, response);
});
await new Promise((accept, reject) => {
  server.once('error', reject);
  server.listen(port, '0.0.0.0', accept);
});
const run = promisify(execFile);
const sandboxCommand = async (arguments_) => {
  const { stdout } = await run(manifest.cli, ['sandbox', 'exec', manifest.sandboxName,
    '--no-login-shell', '--timeout', '30', '--gateway', manifest.gateway,
    '--workspace', 'default', '--color', 'never', '--', ...arguments_],
  { timeout: 40_000, maxBuffer: 1024 * 1024 });
  return stdout;
};
const invoke = async (requestKey, amount) => {
  const stdout = await sandboxCommand(['/usr/bin/curl', '--silent', '--show-error',
    '--max-time', '20', '-X', 'POST', `https://${host}:${port}/execute`,
    '-H', `Authorization: Bearer ${token}`, '-H', 'Content-Type: application/json',
    '--data-binary', JSON.stringify({ requestKey, arguments: { amount } })]);
  return JSON.parse(stdout);
};
try {
  const unauthenticated = await sandboxCommand(['/usr/bin/curl', '--silent', '--show-error',
    '--max-time', '20', '-X', 'POST', `https://${host}:${port}/execute`]);
  assert.deepEqual(JSON.parse(unauthenticated), { status: 'unauthorized' });
  const sidecarControl = await fetch(`${config.sidecarUrl}/fixture/bypass-check`);
  assert.deepEqual(await sidecarControl.json(), { sidecarProbeAlive: true });
  let sidecarBypassFailed = false;
  try {
    const stdout = await sandboxCommand(['/usr/bin/curl', '--fail', '--max-time', '3',
      `http://${host}:${new URL(config.sidecarUrl).port}/fixture/bypass-check`]);
    await writeFile(`${directory}/sidecar-denial.json`, JSON.stringify({ stdout }));
  } catch (error) {
    sidecarBypassFailed = true;
    await writeFile(`${directory}/sidecar-denial.json`, JSON.stringify({ stdout: error.stdout ?? '',
      stderr: error.stderr ?? '', exitCode: error.code }));
  }
  assert.equal(sidecarBypassFailed, true, 'Sandbox must not reach the positively checked sidecar route');
  assert.equal((await invoke('actual-sandbox-allow', 10)).status, 'allowed');
  assert.equal(effects, 1);
  const { stdout: bypassOutput } = await run('python3',
    [resolve(import.meta.dirname, 'probe.py'), directory, '--existing-sandbox',
      '--policy', `${directory}/reviewed-policy.yaml`, '--image', 'already-running',
      '--executor', `https://${host}:${port}`], { timeout: 180_000, maxBuffer: 1024 * 1024 });
  console.log(bypassOutput.trim());
  assert.equal(unreviewedRequests, 0, 'Unreviewed method/path must be blocked before the executor');
  assert.match((await sandboxCommand(['/usr/local/bin/node', '-p', 'process.version'])).trim(), /^v22\./);
  const nodeProbe = `const https=require('node:https');const request=https.request(${JSON.stringify(`https://${host}:${port}/execute`)},{method:'POST',rejectUnauthorized:false,headers:{'x-authrail-probe-binary':'node'}},response=>{console.log('HTTP '+response.statusCode);response.resume();});request.on('error',error=>{console.error(error.code);process.exitCode=1;});request.setTimeout(5000,()=>request.destroy(new Error('timeout')));request.end();`;
  // Certificate verification is disabled only in this deliberate bypass probe,
  // eliminating an untrusted test CA as the explanation for binary rejection.
  try {
    const output = await sandboxCommand(['/usr/local/bin/node', '-e', nodeProbe]);
    await writeFile(`${directory}/unreviewed-binary.json`, JSON.stringify({ stdout: output }));
  } catch (error) {
    await writeFile(`${directory}/unreviewed-binary.json`, JSON.stringify({
      stdout: error.stdout ?? '', stderr: error.stderr ?? '', exitCode: error.code }));
  }
  assert.equal(unreviewedRequests, 0, 'Unreviewed Node binary must not reach the executor');
  const { stdout: networkLogs, stderr: networkLogDiagnostics } = await run(manifest.cli,
    ['logs', manifest.sandboxName, '--source', 'sandbox', '--since', '5m', '-n', '500',
      '--gateway', manifest.gateway, '--workspace', 'default', '--color', 'never'],
    { timeout: 15_000, maxBuffer: 5 * 1024 * 1024 });
  await writeFile(`${directory}/sandbox-network-logs.txt`, networkLogs + networkLogDiagnostics);
  assert.equal((await invoke('actual-sandbox-allow', 10)).status, 'blocked');
  assert.equal((await invoke('actual-sandbox-deny', 1000)).status, 'blocked');
  reviewed = false;
  assert.equal((await invoke('actual-sandbox-withdrawn', 10)).status, 'containment_unavailable');
  reviewed = true;
  // Change only this disposable sandbox's policy. The old review pins must stop
  // matching even though its HTTPS executor route remains reachable.
  const policyPath = `${directory}/reviewed-policy.yaml`;
  const policySource = await readFile(policyPath, 'utf8');
  const changedPolicy = policySource.replace('authrail-protected-executor', 'authrail-reviewed-executor');
  assert.notEqual(changedPolicy, policySource, 'Expected the reviewed probe network rule name');
  const stalePath = `${directory}/stale-policy.yaml`;
  await writeFile(stalePath, changedPolicy);
  await run(manifest.cli, ['policy', 'set', manifest.sandboxName, '--policy', stalePath,
    '--wait', '--timeout', '30', '--gateway', manifest.gateway,
    '--workspace', 'default', '--color', 'never'], { timeout: 40_000 });
  assert.equal((await inspect()).ready, false, 'Actual policy publication must invalidate old pins');
  assert.equal((await invoke('actual-sandbox-stale-policy', 10)).status, 'containment_unavailable');
  assert.equal(effects, 1);
  const result = { sandboxId: pins.sandboxId, policyVersion: pins.policyVersion,
    allowed: true, replayBlocked: true, businessDenied: true, operatorReviewWithdrawn: true,
    actualPolicyChangeBlocked: true,
    effectCount: effects, retention: 'isolated Go control-plane fixture, not PostgreSQL' };
  await writeFile(`${directory}/protected-executor-result.json`, `${JSON.stringify(result, null, 2)}\n`);
  console.log(JSON.stringify(result));
} finally {
  server.closeAllConnections();
  await new Promise((accept) => server.close(accept));
}
