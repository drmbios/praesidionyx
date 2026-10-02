#!/usr/bin/env python3
"""Child attenuation, typed messages, supervisor preemption and budget termination."""
import json
import sys
import time
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import client, compose, expect_error, grant, spawn

api = client()
parent = spawn(api, "parent-demo")
pid = parent["agent"]["agent_id"]
delegated = api.spawn_child(parent,
    {"name":"child-demo", "provider":"mock", "model":"mock-v1", "prompt":"read notes", "context_window":256},
    {"tokens":512, "wall_time_ms":120000, "tool_calls":2, "cost_microusd":0},
    "fs.read", "notes.txt", grant(parent, "fs.read", "notes.txt", calls=3))
assert delegated["outcome"] == "completed"
child = delegated["child"]
cid = child["agent"]["agent_id"]
assert child["agent"]["parent_id"] == pid
cap = delegated["delegated_capability"]
expect_error(403, lambda: api.invoke(cid, child["session_token"], "fs.write", {"path":"notes.txt", "content":"escape"}, cap))
expect_error(403, lambda: api.invoke(cid, child["session_token"], "fs.read", {"path":"other.txt"}, cap))
print("PASS: parent spawns child; delegated read token cannot write or change resource")
api.memory(parent, "remember", content="web-derived task", label="untrusted")
api.message(parent, "send", target_id=cid, kind="task", content="read the permitted notes")
received = api.message(child, "receive")["message"]
assert received["kind"] == "task" and received["label"] == "untrusted"
assert api.memory(child, "context")["label"] == "untrusted"
assert api.message(parent, "yield")["yielded"]
for action, state in (("pause", "paused"), ("resume", "running")):
    assert json.loads(compose("praesidionyx", action, pid))["state"] == state
assert json.loads(compose("praesidionyx", "kill", pid))["state"] == "killed"
assert next(a for a in json.loads(compose("praesidionyx", "list-agents"))["agents"] if a["agent_id"] == cid)["state"] == "killed"
print("PASS: typed messages propagate taint; pause/resume and parent kill cascade work")
limited = spawn(api, "one-tool-budget", budget={"tokens":4096, "wall_time_ms":60000, "tool_calls":1, "cost_microusd":0})
lid = limited["agent"]["agent_id"]
result = api.invoke(lid, limited["session_token"], "fs.read", {"path":"missing.txt"}, grant(limited, "fs.read", "missing.txt"))
assert result["result"]["is_error"]
deadline = time.monotonic() + 2
while True:
    state = next(a for a in json.loads(compose("praesidionyx", "list-agents"))["agents"] if a["agent_id"] == lid)["state"]
    if state == "killed":
        break
    assert time.monotonic() < deadline, "scheduler failed to terminate exhausted agent"
    time.sleep(.05)
print("PASS: final tool call completes; scheduler kills the exhausted agent")
