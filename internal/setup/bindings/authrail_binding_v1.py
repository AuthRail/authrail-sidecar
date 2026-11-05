"""Read a private setup installation from the protected Python application."""

import json
import stat
from pathlib import Path
from authrail import AsyncObserveClient, AsyncEnforceClient, Operation


def connect_authrail(directory, sidecar_url):
    """Return clients and selected action guidance; callers close both async clients."""
    directory = Path(directory)
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_mode & 0o077:
        raise ValueError("Private AuthRail directory required")

    def read(name):
        path = directory / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_mode & 0o077 or info.st_size > 65536:
            raise ValueError("Private AuthRail file required")
        return path.read_bytes()

    connection = json.loads(read("connection.json"))
    selected = json.loads(read("integration.json"))
    if (connection.get("formatVersion") != 1 or selected.get("formatVersion") != 1
            or connection["organisationId"] != selected["organisationId"]
            or connection["deploymentId"] != selected["deploymentId"]):
        raise ValueError("AuthRail setup files belong to different deployments")
    config = dict(sidecar_url=sidecar_url, organisation_id=connection["organisationId"],
                  deployment_id=connection["deploymentId"],
                  adapter_token=read("adapter-token").decode().strip(),
                  executor_private_key=read("executor-private.pem"))
    operations = (selected.get("integration") or {}).get("operations", [])

    def operation(version_id, **trusted_context):
        # Caller/resource/history come from authenticated application state.
        if not any(item["operationVersionId"] == version_id for item in operations):
            raise ValueError("Select published Rails for this action and rerun setup")
        return Operation(version_id=version_id, **trusted_context)

    return AsyncObserveClient(**config), AsyncEnforceClient(**config), operations, operation
