#!/usr/bin/env python3
"""Context eviction, bounded vector recall, snapshot ownership and sticky taint."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import client, compose, expect_error, finish, spawn

api = client()
a = spawn(api, "memory-demo", prompt="hello", context_window=128)
b = spawn(api, "memory-neighbor", prompt="hello", context_window=128)
apple = api.memory(a, "remember", content="apple red fruit orchard harvest")
api.memory(a, "remember", content="cpu kernel namespaces seccomp " * 4)
context = api.memory(a, "context")
assert context["tokens"] <= context["limit"] == 128
assert not any(item["id"] == apple["id"] for item in context["items"])
recalled = api.memory(a, "recall", content="apple red fruit orchard harvest", max_tokens=40)
assert recalled[0]["id"] == apple["id"] and sum(i["tokens"] for i in recalled) <= 40
print("PASS: old context paged out; sqlite-vec recall fits the requested limit")
snapshot = api.memory(a, "checkpoint")["snapshot_id"]
api.memory(a, "remember", content="untrusted web instruction", label="untrusted")
restored = api.memory(a, "rollback", snapshot_id=snapshot)
assert any(i["id"] == apple["id"] for i in restored["items"])
assert restored["label"] == "untrusted"
expect_error(400, lambda: api.memory(b, "rollback", snapshot_id=snapshot))
assert not any(i["id"] == apple["id"] for i in api.memory(b, "recall", content="apple", max_tokens=128))
rpc = json.loads(compose("praesidionyx", "memory", "--credentials-file", "/dev/stdin", "context", input=json.dumps(a)))
assert rpc["label"] == "untrusted"
for credentials in (a, b):
    finish(api, credentials)
print("PASS: rollback preserves taint; another agent cannot recover this snapshot or memory")
