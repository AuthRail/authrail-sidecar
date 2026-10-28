#!/usr/bin/env python3
"""Run Node and Go protected callbacks against the actual sidecar Docker image.

All keys, signed Rails, control-plane acknowledgements and effects are isolated
fixtures. This proves the image/SDK boundary, not real-server persistence or a
provider effect. Existing services and deployment state are never accessed.
"""
import json
import os
import pathlib
import subprocess
import sys
import tempfile
import time
import uuid

repository = pathlib.Path(__file__).resolve().parents[1]
node_sdk = repository.parent / "authrail-sdk-node"
go_sdk = repository.parent / "authrail-sdk-go"
image = sys.argv[1] if len(sys.argv) > 1 else "authrail-sidecar:development"
prefix = "authrail-sdk-image-" + uuid.uuid4().hex[:12]
runner, sidecar, volume = prefix + "-runner", prefix + "-sidecar", prefix + "-state"


def docker(*args, check=True, timeout=90):
    return subprocess.run(["docker", *args], check=check, timeout=timeout,
                          capture_output=True, text=True)


try:
    if not (node_sdk / "dist/index.js").is_file():
        raise RuntimeError("Build authrail-sdk-node with npm run build first")
    if not (node_sdk / "scripts/sidecar-check.mjs").is_file():
        raise RuntimeError("Node SDK sidecar-check fixture is required")
    architecture = docker("image", "inspect", "node:22-slim", "--format", "{{.Architecture}}").stdout.strip()
    image_architecture = docker("image", "inspect", image, "--format", "{{.Architecture}}").stdout.strip()
    if architecture != image_architecture:
        raise RuntimeError("Sidecar and node:22-slim fixture image architectures must match")
    with tempfile.TemporaryDirectory(prefix=prefix) as scratch:
        directory = pathlib.Path(scratch)
        work = directory / "go.work"
        work.write_text("go 1.26.0\nuse (\n" + json.dumps(str(go_sdk)) + "\n" + json.dumps(str(repository)) + "\n)\n")
        environment = dict(os.environ, GOWORK=str(work), CGO_ENABLED="0", GOOS="linux", GOARCH=architecture)
        subprocess.run(["go", "build", "-trimpath", "-o", str(directory / "check"),
                        str(repository / "scripts/docker-sdk-smoke.go")], env=environment, check=True)
        docker("volume", "create", volume)
        docker("run", "-d", "--name", runner, "--read-only", "--cap-drop", "ALL",
               "--security-opt", "no-new-privileges:true",
               "--mount", "type=bind,src=" + scratch + ",dst=/fixture",
               "--mount", "type=bind,src=" + str(node_sdk) + ",dst=/workspace/authrail-sdk-node,readonly",
               "--mount", "type=bind,src=" + str(go_sdk) + ",dst=/workspace/authrail-sdk-go,readonly",
               "-w", "/workspace/authrail-sdk-go", "-e", "AUTHRAIL_DOCKER_FIXTURE_DIR=/fixture",
               "node:22-slim", "/fixture/check")
        ready = directory / "ready.json"
        for _ in range(100):
            if ready.is_file():
                break
            if docker("inspect", runner, "--format", "{{.State.Running}}").stdout.strip() != "true":
                raise RuntimeError("SDK fixture exited before its control plane was ready")
            time.sleep(0.1)
        if not ready.is_file():
            raise RuntimeError("SDK fixture did not start its isolated control plane")
        configuration = json.loads(ready.read_text())
        docker("run", "-d", "--name", sidecar, "--network", "container:" + runner,
               "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--mount", "type=volume,src=" + volume + ",dst=/var/lib/authrail",
               "--mount", "type=bind,src=" + str(directory / "executor-public.pem") + ",dst=/run/executor-public.pem,readonly",
               "-e", "AUTHRAIL_CONTROL_PLANE_URL=" + configuration["controlPlaneUrl"],
               "-e", "AUTHRAIL_TRUSTED_KEY_SHA256=" + configuration["pin"],
               "-e", "AUTHRAIL_DEPLOYMENT_TOKEN=isolated-deployment-token",
               "-e", "AUTHRAIL_ADAPTER_TOKEN=isolated-adapter-token-01234567890123456789",
               "-e", "AUTHRAIL_EXECUTOR_PUBLIC_KEY_FILE=/run/executor-public.pem",
               "-e", "AUTHRAIL_ORGANISATION_ID=00000000-0000-4000-8000-000000000001",
               "-e", "AUTHRAIL_DEPLOYMENT_ID=00000000-0000-4000-8000-000000000002", image)
        status = docker("wait", runner).stdout.strip()
        logs = docker("logs", runner)
        print(logs.stdout, end="")
        if status != "0":
            print(logs.stderr, file=sys.stderr)
            raise RuntimeError("SDK fixture exited " + status)
        config = json.loads(docker("inspect", sidecar).stdout)[0]
        assert config["Config"]["User"] == "10001:10001"
        assert not config["NetworkSettings"]["Ports"]
        print("PASS: actual Docker image daemon + Go and Node SDK signed call/result, denial/no effect, approval continuation recovery, and duplicate-start blocking; no decision port published")
except (subprocess.SubprocessError, RuntimeError, AssertionError) as error:
    print("Docker SDK smoke failed:", error, file=sys.stderr)
    for container in (runner, sidecar):
        logs = docker("logs", container, check=False)
        print(logs.stdout + logs.stderr, file=sys.stderr)
    sys.exit(1)
finally:
    docker("rm", "-f", sidecar, runner, check=False)
    docker("volume", "rm", volume, check=False)
