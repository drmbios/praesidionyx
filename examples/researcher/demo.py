#!/usr/bin/env python3
"""Offline research: a real sandboxed HTTP read, derived summary, approved write."""
import json
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from common import client, compose, finish, grant, spawn

api = client()
a = spawn(api, "researcher")
id = a["agent"]["agent_id"]
url = "http://fixtures.praesidionyx.invalid/research"
page = api.invoke(id, a["session_token"], "http.get", {"url": url}, grant(a, "http.get", url))
assert "context" in page["result"]["output"]["body"].lower(), page
# The offline mock harness supplies a deterministic summary, not an LLM quality test.
summary = "Praesidionyx pages context into SQLite, recalls relevant items, and requires approval for writes derived from untrusted pages."
stored = api.memory(a, "remember", content=summary, label="trusted")
assert stored["label"] == "untrusted", "derived summary laundered provenance"
cap = grant(a, "fs.write", "summary.txt")
args = {"path": "summary.txt", "content": summary}
pending = api.invoke(id, a["session_token"], "fs.write", args, cap)
assert pending["outcome"] == "needs_approval"
print("PASS: fetched page and derived summary retain untrusted provenance")
assert json.loads(compose("praesidionyx", "approve", pending["request_id"]))["status"] == "approved"
written = api.invoke(id, a["session_token"], "fs.write", args, cap, pending["request_id"])
assert not written["result"]["is_error"], written
read = api.invoke(id, a["session_token"], "fs.read", {"path": "summary.txt"}, grant(a, "fs.read", "summary.txt"))
assert read["result"]["output"]["content"] == summary
finish(api, a)
print("PASS: supervisor CLI approval permits exactly the requested summary write")
