#!/usr/bin/env python3
"""Exercise capability limits, then tamper with an exported COPY of the audit log."""
import json
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "sdk" / "python"))
from praesidionyx import AgentClient


def compose(*args, input=None):
    return subprocess.check_output(["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", *args], input=input, text=True)


def denied(call):
    try:
        call()
    except urllib.error.HTTPError as error:
        assert error.code == 403, error.code
    else:
        raise AssertionError("operation unexpectedly authorized")


address = subprocess.check_output(["docker", "compose", "port", "praesidionyxd", "8080"], text=True).strip()
assert address.startswith("127.0.0.1:")
opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
with opener.open("http://" + address + "/healthz", timeout=5) as response:
    assert json.load(response)["milestone"] == 7
client = AgentClient(compose("cat", "/var/lib/praesidionyx/bootstrap.key").strip(), "http://" + address)
denied(lambda: client.spawn(""))
issued = json.loads(compose("praesidionyx", "caps", "issue", "--max-calls", "2"))
child = compose("praesidionyx", "caps", "attenuate", "--token-file", "/dev/stdin", "--max-calls", "1", input=json.dumps(issued)).strip()
first = client.spawn(child, name="attenuated")
denied(lambda: client.spawn(child))
second = client.spawn(issued["capability"], name="parent-remaining-call")
denied(lambda: client.spawn(issued["capability"]))
for spawned in (first, second):
    client.exit(spawned["agent"]["agent_id"], spawned["session_token"], spawned["exit_capability"])
print("PASS: missing capabilities denied; parent and attenuated tokens share call quota")

# These files contain signed metadata and a PUBLIC key, never secret signing keys.
# No further API calls during export: capture a consistent local snapshot.
with tempfile.TemporaryDirectory(prefix="praesidionyx-audit-demo-") as temp:
    root = Path(temp)
    root.chmod(0o755)
    for name in ("audit.jsonl", "audit.head", "audit.pub"):
        (root / name).write_text(compose("cat", "/var/lib/praesidionyx/" + name))
        (root / name).chmod(0o644)
    image = subprocess.check_output(["docker", "compose", "images", "-q", "praesidionyxd"], text=True).strip()
    command = ["docker", "run", "--rm", "--network", "none", "--read-only",
               "--cap-drop", "ALL", "--security-opt", "no-new-privileges:true",
               "--mount", "type=bind,source=" + temp + ",target=/proof,readonly",
               "--entrypoint", "praesidionyx", image, "audit", "verify",
               "--file", "/proof/audit.jsonl", "--public-key-file", "/proof/audit.pub",
               "--checkpoint", "/proof/audit.head"]
    pristine = subprocess.run(command, capture_output=True, text=True)
    assert pristine.returncode == 0, pristine.stderr
    path = root / "audit.jsonl"
    data = bytearray(path.read_bytes())
    data[data.index(b"kernel.start")] = ord("K")
    path.write_bytes(data)
    tampered = subprocess.run(command, capture_output=True, text=True)
    assert tampered.returncode != 0 and "audit hash mismatch" in tampered.stderr, tampered.stderr
print("PASS: one changed byte makes the offline audit CLI exit nonzero")
json.loads(compose("praesidionyx", "audit", "verify"))
print("PASS: live audit log still verifies")
