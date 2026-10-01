#!/usr/bin/env python3
"""Offline web injection, real MCP HTTP, and supervisor CLI denial."""
import json
import subprocess
import sys
import urllib.error
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from praesidionyx import AgentClient


def compose(*args):
    return subprocess.check_output(["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", *args], text=True)

address = subprocess.check_output(["docker", "compose", "port", "praesidionyxd", "8080"], text=True).strip()
client = AgentClient(compose("cat", "/var/lib/praesidionyx/bootstrap.key").strip(), "http://" + address)
a = client.spawn(json.loads(compose("praesidionyx", "caps", "issue"))["capability"], name="injection-demo")
id = a["agent"]["agent_id"]
def grant(tool, resource):
    return json.loads(compose("praesidionyx", "caps", "issue-tool", id, tool, resource))["capability"]
url = "http://fixtures.praesidionyx.invalid/injection"
page = client.invoke(id, a["session_token"], "http.get", {"url":url}, grant("http.get", url))
assert "UNTRUSTED INSTRUCTION" in page["result"]["output"]["body"]
assert page["label"] == "untrusted"
print("Read web fixture with hidden fs.write instruction; context is untrusted.")
# Deterministic adversarial mock: attempt exactly the instruction from that page.
cap = grant("fs.write", "owned.txt")
args = {"path":"owned.txt", "content":"injected"}
blocked = client.invoke(id, a["session_token"], "fs.write", args, cap)
assert blocked["outcome"] == "needs_approval", blocked
print("PASS: hidden instruction gets needs_approval before any write")
assert json.loads(compose("praesidionyx", "deny", blocked["request_id"]))["status"] == "denied"
try:
    client.invoke(id, a["session_token"], "fs.write", args, cap, blocked["request_id"])
except urllib.error.HTTPError as error:
    assert error.code == 403
else:
    raise AssertionError("denied approval executed")
check = client.invoke(id, a["session_token"], "fs.read", {"path":"owned.txt"}, grant("fs.read", "owned.txt"))
assert check["result"]["is_error"], check
client.exit(id, a["session_token"], a["exit_capability"])
print("PASS: CLI denial blocks retry; target file was never created")
