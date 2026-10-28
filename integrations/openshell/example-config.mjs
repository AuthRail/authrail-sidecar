import { readFileSync, statSync } from 'node:fs';
import { resolve } from 'node:path';
import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, randomBytes } from 'node:crypto';
import { EnforceClient } from '@authrail/sdk-node';
import { containmentInspector } from './containment.mjs';

// This example owns an isolated sample ledger, never a real payment provider.
// Keep settings and the whole state directory outside the sandbox's filesystem.
process.umask(0o077);
const settings = JSON.parse(readFileSync(new URL('./operator-settings.json', import.meta.url), 'utf8'));
const state = resolve(settings.stateDirectory);
const metadata = statSync(state);
if (!metadata.isDirectory() || (metadata.mode & 0o077) !== 0 || metadata.uid !== process.getuid()) {
  throw new Error('State directory must be private and owned by the executor user');
}
const secret = (path) => readFileSync(path, 'utf8').trimEnd();
const journalKeyHex = secret(settings.journalKeyFile);
if (!/^[a-fA-F0-9]{64}$/.test(journalKeyHex)) throw new Error('Private 32-byte journal key required');
const journalKey = Buffer.from(journalKeyHex, 'hex');
const client = new EnforceClient({ sidecarUrl: 'http://127.0.0.1:7078',
  adapterToken: secret(settings.adapterTokenFile), organisationId: settings.organisationId,
  deploymentId: settings.deploymentId, executorPrivateKey: secret(settings.executorPrivateKeyFile) });
const db = new DatabaseSync(resolve(state, 'executor.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA synchronous=FULL;
  CREATE TABLE IF NOT EXISTS recovery_events (id INTEGER PRIMARY KEY, body TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sample_effects (provider_key TEXT PRIMARY KEY, amount REAL NOT NULL);`);
const save = db.prepare('INSERT INTO recovery_events(body) VALUES (?)');
const record = async (event) => {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', journalKey, iv);
  cipher.setAAD(Buffer.from(settings.deploymentId));
  const encrypted = Buffer.concat([cipher.update(JSON.stringify(event), 'utf8'), cipher.final()]);
  save.run(JSON.stringify({ iv: iv.toString('base64'), data: encrypted.toString('base64'),
    tag: cipher.getAuthTag().toString('base64') }));
};

/** Operator-only recovery reader; never expose this function as a sandbox route. */
export function loadEvent(id) {
  const row = db.prepare('SELECT body FROM recovery_events WHERE id=?').get(id);
  if (!row) throw new Error('Recovery event not found');
  const stored = JSON.parse(row.body);
  const decipher = createDecipheriv('aes-256-gcm', journalKey, Buffer.from(stored.iv, 'base64'));
  decipher.setAAD(Buffer.from(settings.deploymentId));
  decipher.setAuthTag(Buffer.from(stored.tag, 'base64'));
  return JSON.parse(Buffer.concat([decipher.update(Buffer.from(stored.data, 'base64')),
    decipher.final()]).toString('utf8'));
}
const inspect = containmentInspector(settings.containment);

export default {
  client, host: settings.host, port: settings.port,
  tlsKeyFile: settings.tlsKeyFile, tlsCertFile: settings.tlsCertFile,
  binding: { token: secret(settings.sandboxRequestTokenFile),
    sandboxId: settings.containment.sandboxId, sessionId: settings.sessionId,
    principalId: settings.principalId, deploymentId: settings.deploymentId,
    operationVersionId: settings.operationVersionId },
  containment: async () => {
    const report = await inspect();
    await record({ type: 'containment', ...report });
    return report.ready;
  },
  prepare: async () => ({ resourceId: null, resourceSource: 'not_applicable' }),
  execute: async (input, recovery) => {
    // This independent cap limits this sample executor even if its Rails change.
    if (Object.keys(input).length !== 1 || typeof input.amount !== 'number' ||
        !Number.isFinite(input.amount) || input.amount <= 0 || input.amount > 1000) {
      throw new Error('Sample amount is outside the executor boundary');
    }
    db.prepare('INSERT INTO sample_effects(provider_key,amount) VALUES (?,?) ON CONFLICT DO NOTHING')
      .run(recovery.providerIdempotencyKey, input.amount);
    const retained = db.prepare('SELECT amount FROM sample_effects WHERE provider_key=?')
      .get(recovery.providerIdempotencyKey);
    if (retained.amount !== input.amount) throw new Error('Sample effect identity conflict');
    return { accepted: true };
  },
  record,
};
