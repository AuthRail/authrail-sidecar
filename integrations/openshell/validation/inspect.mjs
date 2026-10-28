#!/usr/bin/env node
import { execFile } from 'node:child_process';
import { readFile, writeFile } from 'node:fs/promises';
import { resolve } from 'node:path';
import { promisify } from 'node:util';
import { containmentInspector, effectivePolicyDigest } from '../containment.mjs';

const directory = resolve(process.argv[2] ?? '');
const manifest = JSON.parse(await readFile(`${directory}/manifest.json`, 'utf8'));
if (!manifest.gateway?.startsWith('authrail-openshell-validation-') ||
    !manifest.sandboxName?.startsWith('ar-check-')) {
  throw new Error('An existing isolated validation manifest is required');
}
process.env.XDG_CONFIG_HOME = `${directory}/config`;
process.env.XDG_STATE_HOME = `${directory}/state`;
const run = promisify(execFile);
const read = async (arguments_) => {
  const { stdout } = await run(manifest.cli, [...arguments_, '--gateway', manifest.gateway,
    '--workspace', 'default', '--color', 'never'], { timeout: 10_000 });
  return { value: JSON.parse(stdout), raw: stdout };
};
const sandboxRead = await read(['sandbox', 'get', manifest.sandboxName, '-o', 'json']);
const policyRead = await read(['policy', 'get', manifest.sandboxName, '--full', '-o', 'json']);
const sandbox = sandboxRead.value;
const policy = policyRead.value;
await writeFile(`${directory}/sandbox.json`, sandboxRead.raw);
await writeFile(`${directory}/effective-policy.json`, policyRead.raw);
const pins = { cli: manifest.cli, gateway: manifest.gateway, workspace: 'default',
  sandboxName: manifest.sandboxName, sandboxId: sandbox.id, policyVersion: policy.active_version,
  policySha256: effectivePolicyDigest(policy.policy) };
await writeFile(`${directory}/review-pins.json`, `${JSON.stringify(pins, null, 2)}\n`);
// These pins are generated only for this controlled validation. Production pins
// require operator review; discovery alone must never grant containment approval.
const result = await containmentInspector(pins)();
await writeFile(`${directory}/inspector-result.json`, `${JSON.stringify(result, null, 2)}\n`);
console.log(JSON.stringify(result));
if (!result.ready) process.exitCode = 1;
