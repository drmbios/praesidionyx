#!/usr/bin/env python3
"""Real HTTP/gRPC tool path, positive confinement and negative authorization checks."""
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from praesidionyx import AgentClient


def compose(*args, input=None):
    return subprocess.check_output(["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", *args], input=input, text=True)


def expect_error(code, call):
    try:
        call()
    except urllib.error.HTTPError as error:
        assert error.code == code, (error.code, error.read().decode())
    else:
        raise AssertionError("request unexpectedly succeeded")


address = subprocess.check_output(["docker", "compose", "port", "praesidionyxd", "8080"], text=True).strip()
assert address.startswith("127.0.0.1:")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open("http://" + address + "/healthz", timeout=5) as response:
    assert json.load(response)["tool_execution_enabled"], "mandatory confinement unavailable"
client = AgentClient(compose("cat", "/var/lib/praesidionyx/bootstrap.key").strip(), "http://" + address)
a = client.spawn(json.loads(compose("praesidionyx", "caps", "issue"))["capability"], name="sandbox-demo")
b = client.spawn(json.loads(compose("praesidionyx", "caps", "issue"))["capability"], name="isolated-neighbor")
agent_id = a["agent"]["agent_id"]


def grant(tool, resource, calls=1):
    return json.loads(compose("praesidionyx", "caps", "issue-tool", agent_id, tool, resource, "--max-calls", str(calls)))["capability"]


def invoke(tool, args, capability="", session=None, target=None):
    return client.invoke(target or agent_id, session or a["session_token"], tool, args, capability)


for tool, args in [("fs.read", {"path": "note.txt"}), ("http.get", {"url": "https://example.com/"})]:
    expect_error(403, lambda: invoke(tool, args))
write = grant("fs.write", "note.txt")
expect_error(401, lambda: invoke("fs.write", {"path": "note.txt", "content": "hello"}, write, b["session_token"]))
expect_error(403, lambda: invoke("fs.write", {"path": "note.txt", "content": "hello"}, write, b["session_token"], b["agent"]["agent_id"]))
expect_error(403, lambda: invoke("fs.write", {"path": "other.txt", "content": "hello"}, write))
expect_error(400, lambda: invoke("fs.write", {"path": "../audit.key", "content": "hello"}, write))
result = invoke("fs.write", {"path": "note.txt", "content": "Hello from an isolated MCP worker."}, write)
assert result["label"] == "untrusted" and not result["result"]["is_error"], result
expect_error(403, lambda: invoke("fs.write", {"path": "note.txt", "content": "replay"}, write))
read = invoke("fs.read", {"path": "note.txt"}, grant("fs.read", "note.txt"))
assert read["result"]["output"]["content"] == "Hello from an isolated MCP worker.", read
proof = read["result"]["sandbox"]
assert proof["landlock"] == "fully_enforced_v3" and proof["seccomp"] == "allowlist"
assert len(proof["namespaces"]) == 7
print("PASS: MCP file write/read; Landlock, seccomp, seven separate namespaces and cgroup limits")
print("PASS: missing capability, wrong session/agent/path, traversal and quota replay denied")
# A network capability still cannot access the daemon, host, metadata or private networks.
private_cap = grant("http.get", "http://127.0.0.1/")
pending = invoke("http.get", {"url": "http://127.0.0.1/"}, private_cap)
assert pending["outcome"] == "needs_approval"
compose("praesidionyx", "approve", pending["request_id"])
expect_error(503, lambda: client.invoke(agent_id, a["session_token"], "http.get", {"url":"http://127.0.0.1/"}, private_cap, pending["request_id"]))
print("PASS: private-network HTTP rejected even with a signed URL capability")
# gRPC Invoke is exercised through the CLI, while HTTP Invoke was exercised above.
credentials = json.dumps(a)
# Store only the capability in a private short-lived file inside the container.
cap_file = compose("mktemp", "/tmp/praesidionyx-tool-cap.XXXXXX").strip()
try:
    compose("sh", "-c", 'cat > "$1"', "sh", cap_file, input=grant("fs.read", "note.txt"))
    rpc = json.loads(compose("praesidionyx", "invoke", "fs.read", "--credentials-file", "/dev/stdin", "--capability-file", cap_file, "--args", '{"path":"note.txt"}', input=credentials))
    assert json.loads(rpc["result_json"])["output"]["content"] == read["result"]["output"]["content"]
finally:
    compose("rm", "-f", cap_file)
for spawned in (a, b):
    client.exit(spawned["agent"]["agent_id"], spawned["session_token"], spawned["exit_capability"])
json.loads(compose("praesidionyx", "audit", "verify"))
print("PASS: Unix gRPC Invoke, lifecycle cleanup and signed audit verification")
