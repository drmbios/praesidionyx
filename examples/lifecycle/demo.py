#!/usr/bin/env python3
"""Run from the repository root after docker compose up --build -d --wait."""
import json
import subprocess
import sys
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from praesidionyx import AgentClient


def compose(*args):
    return subprocess.check_output(["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", *args], text=True)


# Validate the endpoint before sending any bootstrap secret; avoid local proxy env.
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
address = subprocess.check_output(["docker", "compose", "port", "praesidionyxd", "8080"], text=True).strip()
if not address.startswith("127.0.0.1:"):
    raise RuntimeError("Expected a loopback-only published agent port")
base_url = "http://" + address
with opener.open(base_url + "/healthz", timeout=5) as response:
    health = json.load(response)
assert health["status"] == "ok" and health["milestone"] == 7
client = AgentClient(compose("cat", "/var/lib/praesidionyx/bootstrap.key").strip(), base_url)
issued = json.loads(compose("praesidionyx", "caps", "issue"))
spawned = client.spawn(issued["capability"], prompt="Return a deterministic mock response")
agent = spawned["agent"]
print("Spawned:", agent["agent_id"], agent["state"], agent["mock_response"])
listed = json.loads(compose("praesidionyx", "list-agents"))
assert any(a["agent_id"] == agent["agent_id"] and a["state"] == "running" for a in listed["agents"])
finished = client.exit(agent["agent_id"], spawned["session_token"], spawned["exit_capability"])
assert finished["state"] == "finished" and finished["exit_status"] == 0
print("Exited:", finished["agent_id"], finished["state"])
print("PASS: HTTP spawn/exit and gRPC supervisor listing")

cli_spawned = json.loads(compose("praesidionyx", "spawn", "--name", "cli-demo"))
cli_finished = json.loads(subprocess.check_output(
    ["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", "praesidionyx", "exit",
     cli_spawned["agent"]["agent_id"], "--credentials-file", "/dev/stdin"],
    input=json.dumps(cli_spawned), text=True,
))
assert cli_finished["state"] == "finished" and cli_finished["exit_status"] == 0
print("PASS: CLI spawn/exit over Unix-socket gRPC")

verified = json.loads(compose("praesidionyx", "audit", "verify"))
assert verified["records"] > 0
print("PASS: signed audit verification (", verified["records"], "records)")
