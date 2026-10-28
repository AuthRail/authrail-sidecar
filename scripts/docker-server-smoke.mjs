import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { ObserveClient } from '/workspace/authrail-sdk-node/dist/index.js';

const client = new ObserveClient({
  sidecarUrl: process.env.AUTHRAIL_SIDECAR_URL,
  adapterToken: process.env.AUTHRAIL_ADAPTER_TOKEN,
  organisationId: process.env.AUTHRAIL_ORGANISATION_ID,
  deploymentId: process.env.AUTHRAIL_DEPLOYMENT_ID,
  executorPrivateKey: readFileSync(process.env.AUTHRAIL_EXECUTOR_PRIVATE_KEY_FILE),
});
const attempt = client.observe({
  operationVersionId: process.env.AUTHRAIL_OPERATION_VERSION_ID,
  actionKey: process.env.AUTHRAIL_SMOKE_ACTION_KEY ?? 'node-slice5-observe', principalId: 'isolated-staff',
  sessionId: 'isolated-session', principalSource: 'application_session',
  resourceSource: 'not_applicable',
}, { amount: 80 }, () => ({ accepted: true }));
assert.deepEqual(await attempt.result, { accepted: true });
const observation = await attempt.observation;
assert.equal(observation.callError, null);
assert.equal(observation.resultError, null);
const recording = process.env.AUTHRAIL_SMOKE_RECORDING_STATUS ?? 'retained';
assert.ok(['retained', 'queued'].includes(recording));
assert.equal(observation.callDecision?.recordingStatus, recording);
assert.equal(observation.resultDecision?.recordingStatus, recording);
if (recording === 'queued') {
  assert.equal(observation.callDecision?.actionId, undefined);
  assert.equal(observation.resultDecision?.actionId, undefined);
}
