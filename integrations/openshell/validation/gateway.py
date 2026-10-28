#!/usr/bin/env python3
"""Create an isolated, pinned mTLS gateway for operator-run containment checks.

This is a development harness. A healthy gateway alone does not prove sandbox
containment or an AuthRail-protected effect. Retain the output directory until
the sandbox probes finish; it contains private disposable credentials.
"""
import argparse
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time
from urllib.parse import urlsplit

def default_docker_socket():
    configured = os.environ.get("DOCKER_HOST")
    if configured:
        return configured
    desktop_socket = Path.home() / ".docker/run/docker.sock"
    if desktop_socket.exists():
        return "unix://" + str(desktop_socket)
    return "unix:///var/run/docker.sock"

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--cli", required=True, type=Path)
parser.add_argument("--docker-socket", default=default_docker_socket())
parser.add_argument("--gateway-image", default="ghcr.io/nvidia/openshell/gateway@sha256:f0b36dba21d282c52e498c25289658cfd6cd4f343b0069fde5609e25b002cdea")
parser.add_argument("--supervisor-image", default="ghcr.io/nvidia/openshell/supervisor@sha256:ce859a7d77ee515d3fe0b3c7dc61286516f402eb1d25c761d806d9ae5ed96c0b")
parser.add_argument("--supervisor-network-mode", choices=("host", "bridge"), default="bridge")
args = parser.parse_args()
socket_url = urlsplit(args.docker_socket)
if socket_url.scheme != "unix" or socket_url.netloc not in ("", "localhost") or not socket_url.path.startswith("/") or socket_url.query or socket_url.fragment:
    parser.error("--docker-socket and DOCKER_HOST must identify an absolute local Unix socket; remote daemons are unsupported")
args.docker_socket = "unix://" + socket_url.path
root = Path(tempfile.mkdtemp(prefix="authrail-openshell-validation-", dir="/private/tmp"))
root.chmod(0o700)
name = root.name
config = root / "config"
state = root / "state"
supervisor = root / "openshell-sandbox"
for directory in (config, state, root / "docker-config"):
    directory.mkdir(mode=0o700)
environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENSHELL_")}
environment.update(XDG_CONFIG_HOME=str(config), XDG_STATE_HOME=str(state))
docker_binary = shutil.which("docker")
if not docker_binary:
    raise SystemExit("Docker is required")
docker = [docker_binary, "--config", str(root / "docker-config"), "-H", args.docker_socket]

def command(arguments, timeout=120, docker_command=False):
    # Exclude credential helpers for public pulls; never inspect owner Docker config.
    process_environment = dict(environment)
    if docker_command:
        process_environment["PATH"] = "/usr/bin:/bin"
    result = subprocess.run(arguments, env=process_environment, text=True,
                            capture_output=True, timeout=timeout)
    if result.returncode:
        raise RuntimeError(result.stderr.strip() or result.stdout.strip())
    return result.stdout

manifest = {"directory": str(root), "gateway": name, "cli": str(args.cli),
            "dockerSocket": args.docker_socket, "gatewayImage": args.gateway_image,
            "supervisorImage": args.supervisor_image}
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
print(f"Validation directory: {root}", flush=True)
if command([str(args.cli), "--version"]).strip() != "openshell 0.1.6":
    raise SystemExit("Exactly OpenShell 0.1.6 is required")
for image in (args.gateway_image, args.supervisor_image):
    print(f"Pulling {image}", flush=True)
    command(docker + ["pull", image], timeout=300, docker_command=True)
temporary = name + "-extract"
supervisor_config = json.loads(command(docker + ["image", "inspect", args.supervisor_image], docker_command=True))[0]["Config"]
entrypoint = supervisor_config.get("Entrypoint") or []
supervisor_source = entrypoint[0] if entrypoint and entrypoint[0].startswith("/") else "/openshell-sandbox"
try:
    command(docker + ["create", "--name", temporary, args.supervisor_image], docker_command=True)
    command(docker + ["cp", temporary + ":" + supervisor_source, str(supervisor)], docker_command=True)
finally:
    subprocess.run(docker + ["rm", "-f", temporary], capture_output=True)
supervisor.chmod(0o755)
print("Generating isolated mTLS credentials", flush=True)
command(docker + ["run", "--rm", "--user", "0:0", "-v",
    f"{state}:/home/openshell/.local/state/openshell", "-v",
    f"{config}:/home/openshell/.config", args.gateway_image,
    "generate-certs", "--output-dir", "/home/openshell/.local/state/openshell/tls",
    "--server-san", "host.openshell.internal", "--server-san", "127.0.0.1"], docker_command=True)
mtls = config / "openshell" / "gateways" / name / "mtls"
mtls.mkdir(parents=True, mode=0o700)
for source, target in ((state / "tls/ca.crt", "ca.crt"),
                       (state / "tls/client/tls.crt", "tls.crt"),
                       (state / "tls/client/tls.key", "tls.key")):
    shutil.copyfile(source, mtls / target)
    (mtls / target).chmod(0o600)
with socket.socket() as listener:
    listener.bind(("127.0.0.1", 0))
    port = listener.getsockname()[1]
manifest["port"] = port
manifest["supervisorNetworkMode"] = args.supervisor_network_mode
(root / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
gateway_config = root / "gateway.toml"
gateway_config.write_text('[openshell]\nversion = 2\n\n[openshell.drivers.docker]\n'
    + f'supervisor_network_mode = {json.dumps(args.supervisor_network_mode)}\n'
    + f'supervisor_image = {json.dumps(args.supervisor_image)}\n'
    + f'grpc_endpoint = "https://host.openshell.internal:{port}"\n')
gateway_environment = {
    "OPENSHELL_GATEWAY_CONFIG": "/authrail-validation/gateway.toml",
    "OPENSHELL_COMPUTE_DRIVER": "docker",
    "OPENSHELL_GRPC_ENDPOINT": f"https://host.openshell.internal:{port}",
    "OPENSHELL_DOCKER_SUPERVISOR_BIN": str(supervisor),
    "OPENSHELL_DB_URL": "sqlite:/home/openshell/.local/state/openshell/openshell.db",
    "OPENSHELL_LOCAL_TLS_DIR": "/home/openshell/.local/state/openshell/tls",
    "OPENSHELL_TLS_CERT": "/home/openshell/.local/state/openshell/tls/server/tls.crt",
    "OPENSHELL_TLS_KEY": "/home/openshell/.local/state/openshell/tls/server/tls.key",
    "OPENSHELL_TLS_CLIENT_CA": "/home/openshell/.local/state/openshell/tls/ca.crt",
    "OPENSHELL_ENABLE_MTLS_AUTH": "true",
    "OPENSHELL_DOCKER_TLS_CA": "/home/openshell/.local/state/openshell/tls/ca.crt",
    "OPENSHELL_DOCKER_TLS_CERT": "/home/openshell/.local/state/openshell/tls/client/tls.crt",
    "OPENSHELL_DOCKER_TLS_KEY": "/home/openshell/.local/state/openshell/tls/client/tls.key",
}
launch = docker + ["run", "-d", "--name", name, "--user", "0:0",
    "-p", f"127.0.0.1:{port}:{port}", "-v",
    f"{gateway_config}:/authrail-validation/gateway.toml:ro", "-v",
    f"{state}:/home/openshell/.local/state/openshell", "-v",
    "/var/run/docker.sock:/var/run/docker.sock", "-v", f"{supervisor}:{supervisor}:ro"]
for key, value in gateway_environment.items():
    launch += ["-e", f"{key}={value}"]
launch += [args.gateway_image, "--bind-address", "0.0.0.0", "--port", str(port)]
command(launch, docker_command=True)
print(f"Started disposable gateway {name}", flush=True)
command([str(args.cli), "gateway", "add", f"https://127.0.0.1:{port}",
         "--local", "--name", name])
deadline = time.monotonic() + 60
while True:
    try:
        status = command([str(args.cli), "status", "--gateway", name, "-o", "json"], timeout=5)
        status_value = json.loads(status)
        if status_value.get("authentication", {}).get("status") != "authenticated" or status_value.get("status") != "connected":
            raise RuntimeError("Gateway has not authenticated")
        break
    except (RuntimeError, subprocess.TimeoutExpired):
        if time.monotonic() >= deadline:
            raise
        time.sleep(1)
(root / "gateway-status.json").write_text(status)
print(status, flush=True)
print("Gateway only: sandbox policy and bypass probes still required.", flush=True)
