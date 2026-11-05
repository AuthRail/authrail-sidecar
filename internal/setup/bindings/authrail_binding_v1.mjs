import { readFile, lstat } from 'node:fs/promises';
import { join } from 'node:path';
import { ObserveClient, EnforceClient } from '@authrail/sdk-node';

// Keep this binding in the credential-owning application, outside agent access.
// The selected action list is setup guidance; the sidecar still checks permission.
export async function connectAuthRail(directory, sidecarUrl) {
  const directoryInfo = await lstat(directory);
  if (!directoryInfo.isDirectory() || (directoryInfo.mode & 0o077)) throw new Error('Private AuthRail directory required');
  async function read(name) {
    const path = join(directory, name);
    const info = await lstat(path);
    if (!info.isFile() || (info.mode & 0o077) || info.size > 65536) throw new Error('Private AuthRail file required');
    return readFile(path, 'utf8');
  }
  const connection = JSON.parse(await read('connection.json'));
  const selected = JSON.parse(await read('integration.json'));
  if (connection.formatVersion !== 1 || selected.formatVersion !== 1 ||
      connection.organisationId !== selected.organisationId || connection.deploymentId !== selected.deploymentId) {
    throw new Error('AuthRail setup files belong to different deployments');
  }
  const configuration = { sidecarUrl, organisationId: connection.organisationId,
    deploymentId: connection.deploymentId, adapterToken: (await read('adapter-token')).trim(),
    executorPrivateKey: await read('executor-private.pem') };
  const operations = selected.integration?.operations ?? [];
  return {
    observe: new ObserveClient(configuration), enforce: new EnforceClient(configuration), operations,
    // Supply context from authenticated application state, never agent arguments.
    operation(operationVersionId, trustedContext) {
      if (!operations.some(value => value.operationVersionId === operationVersionId)) {
        throw new Error('Select published Rails for this action and rerun setup');
      }
      return { ...trustedContext, operationVersionId };
    },
  };
}
