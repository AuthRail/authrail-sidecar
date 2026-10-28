import { execFile } from 'node:child_process';
import { createHash } from 'node:crypto';
import { promisify } from 'node:util';

const run = promisify(execFile);
const canonical = (value) => {
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (value && typeof value === 'object') return `{${Object.keys(value).sort()
    .map((key) => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
  return JSON.stringify(value);
};

/** Hash a reviewed effective JSON policy, including provider-composed rules. */
export const effectivePolicyDigest = (policy) => createHash('sha256').update(canonical(policy)).digest('hex');

/**
 * Query the operator's pinned OpenShell 0.1.6 CLI and authenticated gateway.
 * This is live upstream-reported state, not independent proof of kernel isolation
 * or credential/network bypass tests. Keep the CLI and its config outside sandbox mounts.
 * Changing policy/sandbox/source requires explicit operator review and new pins.
 */
export function containmentInspector({ cli, gateway, workspace, sandboxName, sandboxId,
  policyVersion, policySha256 }) {
  if (typeof cli !== 'string' || !cli.startsWith('/') ||
      ![gateway, workspace, sandboxName, sandboxId].every((value) =>
        typeof value === 'string' && /^[A-Za-z0-9_.-]{1,128}$/.test(value)) ||
      !Number.isSafeInteger(policyVersion) || policyVersion < 1 ||
      !/^[a-f0-9]{64}$/.test(policySha256)) throw new Error('Reviewed containment pins required');
  const invoke = async (args) => {
    const { stdout } = await run(cli, [...args, '--gateway', gateway, '--workspace', workspace,
      '--color', 'never'], { timeout: 2000, maxBuffer: 5 * 1024 * 1024,
      // Do not inherit a caller's TLS-disable flag, alternate endpoint or gateway.
      env: Object.fromEntries(Object.entries(process.env).filter(([name]) => !name.startsWith('OPENSHELL_'))) });
    // OpenShell revisions are uint64 and can exceed JavaScript's exact integer
    // range. Compare the original decimal bytes, never rounded Number values.
    return JSON.parse(stdout, (name, value, context) => name === 'config_revision' && typeof value === 'number'
      ? context && /^(0|[1-9][0-9]{0,19})$/.test(context.source) ? context.source : null
      : value);
  };
  return async () => {
    const checkedAt = new Date().toISOString();
    try {
      const { stdout } = await run(cli, ['--version'], { timeout: 1000, maxBuffer: 1024 });
      if (stdout.trim() !== 'openshell 0.1.6') return { ready: false, status: 'incompatible', checkedAt };
      const gatewayStatus = await invoke(['status', '-o', 'json']);
      if (gatewayStatus.gateway !== gateway || gatewayStatus.authentication?.status !== 'authenticated' ||
          typeof gatewayStatus.server !== 'string' || new URL(gatewayStatus.server).protocol !== 'https:') {
        return { ready: false, status: 'gateway_unverified', checkedAt, sandboxId };
      }
      const before = await invoke(['policy', 'get', sandboxName, '--full', '-o', 'json']);
      const revision = await invoke(['policy', 'get', sandboxName, '--rev', String(policyVersion), '-o', 'json']);
      const sandbox = await invoke(['sandbox', 'get', sandboxName, '-o', 'json']);
      const after = await invoke(['policy', 'get', sandboxName, '--full', '-o', 'json']);
      const matches = (value) => value.scope === 'sandbox' && value.sandbox === sandboxName &&
        value.policy_source === 'sandbox' && value.status === 'effective' &&
        value.active_version === policyVersion && value.version === policyVersion &&
        typeof value.hash === 'string' && /^[a-f0-9]{64}$/.test(value.hash) &&
        typeof value.config_revision === 'string' && /^(0|[1-9][0-9]{0,19})$/.test(value.config_revision) &&
        value.policy?.landlock?.compatibility === 'hard_requirement' &&
        effectivePolicyDigest(value.policy) === policySha256;
      const ready = matches(before) && matches(after) && before.hash === after.hash &&
        before.config_revision === after.config_revision && revision.scope === 'sandbox' &&
        revision.sandbox === sandboxName && revision.status === 'loaded' &&
        revision.version === policyVersion && revision.active_version === policyVersion &&
        revision.hash === after.hash && sandbox.id === sandboxId && sandbox.name === sandboxName &&
        sandbox.workspace === workspace && sandbox.phase === 'Ready' &&
        sandbox.current_policy_version === policyVersion;
      return { ready, status: ready ? 'upstream_reported_ready' : 'review_required', checkedAt,
        sandboxId, policyVersion, policySha256 };
    } catch {
      // Suppress subprocess stderr; it may contain gateway or provider diagnostics.
      return { ready: false, status: 'unavailable', checkedAt, sandboxId };
    }
  };
}
