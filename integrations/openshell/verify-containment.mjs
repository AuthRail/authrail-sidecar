import assert from 'node:assert/strict';
import { chmod, mkdtemp, readFile, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { containmentInspector, effectivePolicyDigest } from './containment.mjs';

/** Exercise fail-closed inspector parsing with a subprocess CLI fixture, not OpenShell. */
export async function verifyContainmentParsing() {
  const directory = await mkdtemp(join(tmpdir(), 'authrail-containment-fixture-'));
  const cli = join(directory, 'fixture-cli');
  const beforeFile = join(directory, 'before.json');
  const afterFile = join(directory, 'after.json');
  const markerFile = join(directory, 'full-read');
  const traceFile = join(directory, 'invocations.txt');
  const loadedFile = join(directory, 'loaded.json');
  const policy = { version: 1, landlock: { compatibility: 'hard_requirement' } };
  const hash = 'a'.repeat(64);
  const unsafeRevision = '8660680612572748555';
  const adjacentRevision = '8660680612572748556';
  const effective = { scope: 'sandbox', sandbox: 'fixture-sandbox', policy_source: 'sandbox',
    status: 'effective', version: 1, active_version: 1, hash, policy };
  // Emit a JSON number's original decimal bytes without passing through Number.
  const full = (value, revision) => revision === undefined ? JSON.stringify(value)
    : JSON.stringify({ ...value, config_revision: '__REVISION__' }).replace('"__REVISION__"', revision);
  const quote = (value) => `'${value.replaceAll("'", "'\\''")}'`;
  try {
    // A Node-backed fake CLI can exceed the inspector's one-second version
    // deadline during cold startup. Shell built-ins keep this a parsing check.
    await writeFile(cli, `#!/bin/sh
set -eu
printf '%s\\n' "$*" >> ${quote(traceFile)}
if [ "$1" = '--version' ]; then
  printf '%s\\n' 'openshell 0.1.6'
else
  case " $* " in *' --gateway fixture-gateway --workspace fixture-workspace '*) ;; *) exit 1 ;; esac
  case "$1" in
    status) printf '%s\\n' '{"gateway":"fixture-gateway","server":"https://gateway.example.test","authentication":{"status":"authenticated"}}' ;;
    sandbox) printf '%s\\n' '{"id":"fixture-id","name":"fixture-sandbox","workspace":"fixture-workspace","phase":"Ready","current_policy_version":1}' ;;
    policy)
      case " $* " in
        *' --full '*)
          if [ -f ${quote(markerFile)} ]; then /bin/cat ${quote(afterFile)}
          else : > ${quote(markerFile)}; /bin/cat ${quote(beforeFile)}; fi ;;
        *' --rev 1 '*) /bin/cat ${quote(loadedFile)} ;;
        *) exit 1 ;;
      esac ;;
    *) exit 1 ;;
  esac
fi
`, { mode: 0o700 });
    await chmod(cli, 0o700);
    await writeFile(loadedFile, JSON.stringify({ scope: 'sandbox', sandbox: 'fixture-sandbox',
      status: 'loaded', version: 1, active_version: 1, hash }), { mode: 0o600 });
    const inspect = containmentInspector({ cli, gateway: 'fixture-gateway', workspace: 'fixture-workspace',
      sandboxName: 'fixture-sandbox', sandboxId: 'fixture-id', policyVersion: 1,
      policySha256: effectivePolicyDigest(policy) });
    const check = async (before, after, ready) => {
      await rm(markerFile, { force: true });
      await writeFile(traceFile, '', { mode: 0o600 });
      await writeFile(beforeFile, before, { mode: 0o600 });
      await writeFile(afterFile, after, { mode: 0o600 });
      const report = await inspect();
      const diagnostic = `Fixture result: ${report.status}; invocations: ${await readFile(traceFile, 'utf8')}`;
      assert.equal(report.ready, ready, diagnostic);
      assert.equal(report.status, ready ? 'upstream_reported_ready' : 'review_required', diagnostic);
    };

    await check(full(effective, unsafeRevision), full(effective, unsafeRevision), true);
    const withoutHash = { ...effective };
    delete withoutHash.hash;
    await check(full(withoutHash, unsafeRevision), full(withoutHash, unsafeRevision), false);
    await check(full(effective), full(effective), false);

    // This pair compares equal after Number rounding; original decimal text must differ.
    assert.equal(Number(unsafeRevision), Number(adjacentRevision));
    await check(full(effective, unsafeRevision), full(effective, adjacentRevision), false);
    await check(full(effective, '1'), full(effective, '2'), false);
    await check(full(effective, unsafeRevision), full({ ...effective, hash: 'b'.repeat(64) }, unsafeRevision), false);
    await check(full(effective, unsafeRevision), full({ ...effective,
      policy: { ...policy, version: 2 } }, unsafeRevision), false);
    console.log('CLI fixture: exact uint64 revision accepted; missing hash/revision, adjacent rounded revisions and changed policy/hash/revision rejected. This is parsing evidence, not actual OpenShell containment acceptance.');
  } finally {
    await rm(directory, { recursive: true, force: true });
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(resolve(process.argv[1])).href) {
  await verifyContainmentParsing();
}
