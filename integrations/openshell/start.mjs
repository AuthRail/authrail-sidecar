import { createServer } from 'node:https';
import { readFile } from 'node:fs/promises';
import { pathToFileURL } from 'node:url';
import { resolve } from 'node:path';
import { protectedExecutor } from './executor.mjs';

// Configuration is operator code outside sandbox mounts, not agent-provided JSON.
// It constructs the pinned Node SDK and the application's durable recovery hooks.
if (!process.argv[2]) throw new Error('Usage: node start.mjs /private/operator-config.mjs');
const { default: config } = await import(pathToFileURL(resolve(process.argv[2])).href);
if (!config || !Number.isInteger(config.port) || config.port < 1 || config.port > 65535 ||
    typeof config.host !== 'string') throw new Error('Explicit HTTPS listener required');
const handler = protectedExecutor(config);
const server = createServer({ key: await readFile(config.tlsKeyFile),
  cert: await readFile(config.tlsCertFile), minVersion: 'TLSv1.2' }, (request, response) => {
  void handler(request, response).catch(() => {
    if (!response.headersSent) response.writeHead(503);
    response.end();
  });
});
server.requestTimeout = 15_000;
server.headersTimeout = 10_000;
server.maxHeadersCount = 32;
server.listen(config.port, config.host);
let stopping = false;
for (const signal of ['SIGINT', 'SIGTERM']) process.on(signal, () => {
  if (stopping) return;
  stopping = true;
  // Drain in-flight checks/effects. An interrupted effect remains unknown and
  // must be reconciled by the executor using the persisted original identity.
  server.close();
  const deadline = setTimeout(() => { server.closeAllConnections(); process.exit(1); }, 30_000);
  deadline.unref();
});
