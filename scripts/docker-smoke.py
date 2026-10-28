#!/usr/bin/env python3
"""Verify container isolation/persistence with disposable local protocol fixtures.

This does not prove a connected AuthRail deployment or a protected business effect.
Requires Docker, the locally built sidecar image, and node:22-slim.
"""
import json
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid

image = sys.argv[1] if len(sys.argv) > 1 else "authrail-sidecar:development"
prefix = "authrail-package-" + uuid.uuid4().hex[:12]
peer, sidecar, volume = prefix + "-peer", prefix + "-sidecar", prefix + "-state"


def docker(*args, check=True):
    return subprocess.run(["docker", *args], check=check, text=True, capture_output=True)


fixture = r"""
const http = require('http'); let sequence = 1;
const server = http.createServer((req,res) => {
  if (req.url === '/lower') { sequence = 0; res.end(); return; }
  if (req.url === '/offline') { res.end(); server.closeAllConnections(); server.close(); return; }
  if (req.url === '/runtime/deployment/configuration') {
    if (req.headers.authorization !== 'Bearer isolated-packaging-credential') {
      res.writeHead(401); res.end(); return;
    }
    res.setHeader('content-type','application/json');
    res.end(JSON.stringify({deployment:{
      organisationId:'11111111-1111-4111-8111-111111111111',
      deploymentId:'22222222-2222-4222-8222-222222222222',
      inventoryItemId:'33333333-3333-4333-8333-333333333333',
      inventoryRevisionId:'44444444-4444-4444-8444-444444444444',
      mode:'observe',sequence,activeBundleId:null}})); return;
  }
  res.writeHead(204); res.end();
}).listen(7079,'127.0.0.1');
setInterval(()=>{},1000); // Preserve the namespace while the fixture is offline.
"""


def request(port, path):
    return docker("exec", peer, "node", "-e",
                  f"fetch('http://127.0.0.1:{port}{path}').then(r=>r.text()).then(console.log).catch(()=>process.exit(1))").stdout


def await_sequence(status=None):
    for _ in range(60):
        try:
            health = json.loads(request(7078, "/health"))
            if health["sequence"] == 1 and (status is None or health["syncStatus"] == status):
                return health
        except (subprocess.CalledProcessError, json.JSONDecodeError):
            pass
        time.sleep(0.1)
    raise AssertionError("container never exposed retained sequence 1")


try:
    with tempfile.TemporaryDirectory(prefix=prefix) as directory:
        token = pathlib.Path(directory) / "deployment-token"
        token.write_text("isolated-packaging-credential\n")
        # This disposable fixture has no live credential. Host directory is private.
        token.chmod(0o444)
        docker("volume", "create", volume)
        docker("run", "-d", "--name", peer, "node:22-slim", "node", "-e", fixture)
        docker("run", "-d", "--name", sidecar, "--network", "container:" + peer,
               "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--mount", "type=volume,src=" + volume + ",dst=/var/lib/authrail",
               "--mount", "type=bind,src=" + str(token) + ",dst=/run/secrets/token,readonly",
               "-e", "AUTHRAIL_DEPLOYMENT_TOKEN_FILE=/run/secrets/token",
               "-e", "AUTHRAIL_CONTROL_PLANE_URL=http://127.0.0.1:7079",
               "-e", "AUTHRAIL_ORGANISATION_ID=11111111-1111-4111-8111-111111111111",
               "-e", "AUTHRAIL_DEPLOYMENT_ID=22222222-2222-4222-8222-222222222222",
               "-e", "AUTHRAIL_TRUSTED_KEY_SHA256=" + "a" * 64,
               "-e", "AUTHRAIL_SYNC_INTERVAL=1s", image)
        await_sequence()
        config = json.loads(docker("inspect", sidecar).stdout)[0]
        assert config["Config"]["User"] == "10001:10001"
        assert not config["NetworkSettings"]["Ports"], "decision port must not be published"
        # A process with no signed bundle must fail readiness, even though HTTP lives.
        assert docker("exec", sidecar, "/usr/local/bin/authrail-container", "health", check=False).returncode == 1
        docker("stop", "--time", "10", sidecar)
        assert json.loads(docker("inspect", sidecar).stdout)[0]["State"]["ExitCode"] == 0
        verify = """const fs=require('fs');const s=fs.statSync('/state/state.json');
if(s.uid!==10001||(s.mode&511)!==384)process.exit(1);
if(JSON.parse(fs.readFileSync('/state/state.json')).floor!==1)process.exit(2);"""
        docker("run", "--rm", "--user", "10001:10001", "--mount",
               "type=volume,src=" + volume + ",dst=/state,readonly", "node:22-slim", "node", "-e", verify)
        request(7079, "/lower")
        docker("start", sidecar)
        await_sequence()
        # Losing the fixture entirely must not erase the persisted floor on restart.
        request(7079, "/offline")
        docker("restart", "--time", "10", sidecar)
        await_sequence("unreachable")
        print("PASS: non-root private state, local namespace, no published port, invalid-bundle readiness, graceful stop, rollback floor and offline restart")
except (subprocess.CalledProcessError, AssertionError) as error:
    print("Docker packaging smoke failed:", error, file=sys.stderr)
    logs = docker("logs", sidecar, check=False)
    print(logs.stdout + logs.stderr, file=sys.stderr)
    sys.exit(1)
finally:
    docker("rm", "-f", sidecar, peer, check=False)
    docker("volume", "rm", volume, check=False)
