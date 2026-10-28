#!/usr/bin/env python3
"""Run real sandbox probes after gateway.py; no policy changes or approvals.

Supply the reviewed sandbox policy and an isolated executor URL. The policy
must allow its POST /execute path and must deny GET, other paths and hosts.
The protected executor remains a separate host process, never inside the image.
"""
import argparse
import json
import os
from pathlib import Path
import subprocess

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("directory", type=Path)
parser.add_argument("--policy", required=True, type=Path)
parser.add_argument("--image", required=True)
parser.add_argument("--executor", required=True)
parser.add_argument("--existing-sandbox", action="store_true")
args = parser.parse_args()
manifest = json.loads((args.directory / "manifest.json").read_text())
name = manifest["gateway"]
if not name.startswith("authrail-openshell-validation-"):
    raise SystemExit("Expected this harness's isolated gateway")
environment = {key: value for key, value in os.environ.items() if not key.startswith("OPENSHELL_")}
environment.update(XDG_CONFIG_HOME=str(args.directory / "config"),
                   XDG_STATE_HOME=str(args.directory / "state"))
cli = [manifest["cli"], "--gateway", name, "--workspace", "default", "--color", "never"]

def run(arguments, expected_success=True, timeout=120, evidence=None):
    result = subprocess.run(cli + arguments, env=environment, text=True,
                            capture_output=True, timeout=timeout)
    if evidence:
        (args.directory / evidence).write_text(json.dumps({"exitCode": result.returncode,
            "stdout": result.stdout, "stderr": result.stderr}, indent=2) + "\n")
    if (result.returncode == 0) != expected_success:
        raise RuntimeError(f"Unexpected command status {result.returncode}: {result.stdout} {result.stderr}")
    return result.stdout

sandbox = "ar-check-" + name.rsplit("-", 1)[-1]
if len(sandbox) > 19:
    raise SystemExit("Sandbox name must fit OpenShell's 19-character limit")
manifest["sandboxName"] = sandbox
(args.directory / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
if not args.existing_sandbox:
    print("Creating actual sandbox with hard-required Landlock", flush=True)
    run(["sandbox", "create", "--name", sandbox, "--from", args.image,
         "--policy", str(args.policy.resolve()), "--no-auto-providers", "--detach",
         "--", "sleep", "infinity"])
for filename, arguments in (("sandbox.json", ["sandbox", "get", sandbox, "-o", "json"]),
                            ("effective-policy.json", ["policy", "get", sandbox, "--full", "-o", "json"])):
    (args.directory / filename).write_text(run(arguments))
exec_command = ["sandbox", "exec", sandbox, "--no-login-shell", "--timeout", "15", "--"]
control = run(exec_command + ["curl", "--silent", "--show-error", "--max-time", "5",
    "-X", "POST", args.executor + "/execute"], evidence="executor-positive-control.json")
if json.loads(control) != {"status": "unauthorized"}:
    raise RuntimeError("Allowed route did not reach the real protected executor's authentication boundary")
run(exec_command + ["cat", "/protected/provider-marker"], expected_success=False,
    evidence="filesystem-denial.json")
run(exec_command + ["sh", "-c", "test ! -S /var/run/docker.sock"])
run(exec_command + ["curl", "--fail", "--max-time", "5", "https://example.com"], expected_success=False,
    evidence="network-denial.json")
run(exec_command + ["curl", "--fail", "--max-time", "5", args.executor + "/execute"], expected_success=False,
    evidence="method-denial.json")
run(exec_command + ["curl", "--fail", "--max-time", "5", "-X", "POST", args.executor + "/unreviewed"], expected_success=False,
    evidence="path-denial.json")
print("Positive executor-route control passed. Inspect retained failures and gateway logs to establish policy denial causes.", flush=True)
print("Business allow/deny and active inspector checks remain separate required checks.", flush=True)
