#!/usr/bin/env python3
"""Replace only this harness's gateway with a reviewed supervisor trust image."""
import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import time

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--supervisor-image", required=True)
args = parser.parse_args()
root = args.directory.resolve()
manifest = json.loads((root / "manifest.json").read_text())
name = manifest["gateway"]
if root.parent != Path("/private/tmp") or root.name != name or not name.startswith("authrail-openshell-validation-"):
    raise SystemExit("Only an exact isolated harness directory is accepted")
sandbox = manifest.get("sandboxName")
if sandbox != "ar-check-" + name.rsplit("-", 1)[-1]:
    raise SystemExit("Expected the manifest's bounded disposable sandbox")
if not args.supervisor_image.startswith("authrail-openshell-supervisor:"):
    raise SystemExit("Use a uniquely named authrail-openshell-supervisor validation image")
environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENSHELL_")}
environment.update(XDG_CONFIG_HOME=str(root / "config"), XDG_STATE_HOME=str(root / "state"))
docker_binary = shutil.which("docker")
docker = [docker_binary, "--config", str(root / "docker-config"), "-H", manifest["dockerSocket"]]

def run(arguments, docker_command=False, timeout=60):
    process_environment = dict(environment)
    if docker_command:
        process_environment["PATH"] = "/usr/bin:/bin"
    result = subprocess.run(arguments, env=process_environment, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout

metadata = json.loads(run(docker + ["inspect", name], docker_command=True))[0]
if metadata["Name"] != "/" + name or metadata["Config"]["Image"] != manifest["gatewayImage"]:
    raise SystemExit("Gateway name/image no longer matches this harness")
bindings = metadata["HostConfig"].get("Binds") or []
for binding in bindings:
    source = binding.split(":", 1)[0]
    if source != "/var/run/docker.sock" and not source.startswith(str(root) + "/"):
        raise SystemExit("Refusing to recreate a gateway with a non-harness mount")
port = manifest["port"]
config = root / "gateway.toml"
config.write_text('[openshell]\nversion = 2\n\n[openshell.drivers.docker]\n'
    + 'supervisor_network_mode = "bridge"\n'
    + f'supervisor_image = {json.dumps(args.supervisor_image)}\n'
    + f'grpc_endpoint = "https://host.openshell.internal:{port}"\n')
image = json.loads(run(docker + ["image", "inspect", args.supervisor_image], docker_command=True))[0]
manifest["supervisorImage"] = args.supervisor_image
manifest["supervisorImageId"] = image["Id"]
manifest["supervisorNetworkMode"] = "bridge"
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Deleting only disposable sandbox {sandbox}", flush=True)
run([manifest["cli"], "sandbox", "delete", sandbox, "--gateway", name, "--workspace", "default"])
print(f"Replacing only isolated gateway {name}", flush=True)
run(docker + ["stop", "--time", "15", name], docker_command=True)
run(docker + ["rm", name], docker_command=True)
launch = docker + ["run", "-d", "--name", name]
user = metadata["Config"].get("User")
if user:
    launch += ["--user", user]
for container_port, ports in metadata["HostConfig"]["PortBindings"].items():
    for published in ports:
        if published["HostIp"] != "127.0.0.1":
            raise SystemExit("Only loopback gateway publications are permitted")
        launch += ["-p", f"127.0.0.1:{published['HostPort']}:{container_port}"]
for binding in bindings:
    if binding.split(":", 1)[0] != str(config):
        launch += ["-v", binding]
launch += ["-v", f"{config}:/authrail-validation/gateway.toml:ro"]
for value in metadata["Config"].get("Env") or []:
    if not value.startswith("OPENSHELL_GATEWAY_CONFIG="):
        launch += ["-e", value]
launch += ["-e", "OPENSHELL_GATEWAY_CONFIG=/authrail-validation/gateway.toml",
           manifest["gatewayImage"], *(metadata["Config"].get("Cmd") or [])]
run(launch, docker_command=True)
deadline = time.monotonic() + 60
while True:
    try:
        status = run([manifest["cli"], "status", "--gateway", name, "-o", "json"], timeout=5)
        value = json.loads(status)
        if value.get("status") != "connected" or value.get("authentication", {}).get("status") != "authenticated":
            raise RuntimeError("Gateway not yet authenticated")
        (root / "gateway-status.json").write_text(status)
        print(status, flush=True)
        break
    except (RuntimeError, subprocess.TimeoutExpired):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)
