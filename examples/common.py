"""Private credential handling shared by offline demonstrations."""
import json
import subprocess
import sys
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sdk" / "python"))
from praesidionyx import AgentClient


def compose(*args, input=None):
    return subprocess.check_output(
        ["docker", "compose", "exec", "-T", "--user", "10001:10001", "praesidionyxd", *args],
        input=input, text=True,
    )


def client():
    address = subprocess.check_output(["docker", "compose", "port", "praesidionyxd", "8080"], text=True).strip()
    assert address.startswith("127.0.0.1:"), "refusing to send credentials off loopback"
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
    with opener.open("http://" + address + "/healthz", timeout=5) as response:
        assert json.load(response)["milestone"] == 7
    return AgentClient(compose("cat", "/var/lib/praesidionyx/bootstrap.key").strip(), "http://" + address)


def spawn(api, name, **kwargs):
    return api.spawn(json.loads(compose("praesidionyx", "caps", "issue"))["capability"], name=name, **kwargs)


def grant(credentials, tool, resource, calls=1):
    return json.loads(compose("praesidionyx", "caps", "issue-tool", credentials["agent"]["agent_id"], tool, resource, "--max-calls", str(calls)))["capability"]


def expect_error(code, call):
    try:
        call()
    except urllib.error.HTTPError as error:
        assert error.code in (code if isinstance(code, tuple) else (code,)), (error.code, error.read().decode())
    else:
        raise AssertionError("request unexpectedly succeeded")


def finish(api, credentials):
    api.exit(credentials["agent"]["agent_id"], credentials["session_token"], credentials["exit_capability"])
