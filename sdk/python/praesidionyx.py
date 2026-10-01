"""Dependency-free Praesidionyx HTTP client. Keep returned credentials private."""
import json
import urllib.request


class AgentClient:
    def __init__(self, bootstrap_key, base_url="http://127.0.0.1:18080", timeout=65):
        self.bootstrap_key = bootstrap_key
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def _post(self, path, payload, token):
        request = urllib.request.Request(
            self.base_url + path,
            json.dumps(payload).encode(),
            {"Content-Type": "application/json", "Authorization": "Bearer " + token},
            method="POST",
        )
        with self.opener.open(request, timeout=self.timeout) as response:
            return json.load(response)

    def spawn(self, capability, name="demo", prompt="Hello, Praesidionyx", provider="mock",
              model="mock-v1", context_window=4096, budget=None):
        return self._post("/v1/agents", {
            "spec": {"name": name, "provider": provider, "model": model,
                     "prompt": prompt, "context_window": context_window},
            "budget": budget if budget is not None else {"tokens": 4096, "wall_time_ms": 60000,
                       "tool_calls": 16, "cost_microusd": 0},
            "capability": capability,
        }, self.bootstrap_key)

    def exit(self, agent_id, session_token, capability, status=0):
        return self._post("/v1/agents/" + agent_id + "/exit",
                          {"status": status, "capability": capability}, session_token)

    def invoke(self, agent_id, session_token, tool, args, capability, approval_id=""):
        response = self._post("/v1/invoke", {
            "agent_id": agent_id, "tool": tool,
            "args_json": json.dumps(args), "capability": capability, "approval_id": approval_id,
        }, session_token)
        response["result"] = json.loads(response.pop("result_json"))
        return response

    def memory(self, credentials, operation, content="", label="user", max_tokens=1024, snapshot_id=""):
        response = self._post("/v1/memory", {
            "agent_id": credentials["agent"]["agent_id"], "capability": credentials["local_capability"],
            "operation": operation, "content": content, "label": label,
            "max_tokens": max_tokens, "snapshot_id": snapshot_id,
        }, credentials["session_token"])
        return json.loads(response["result_json"])

    def message(self, credentials, operation, target_id="", kind="text", content=""):
        result = self._post("/v1/message", {"agent_id":credentials["agent"]["agent_id"], "capability":credentials["local_capability"], "operation":operation, "target_id":target_id, "kind":kind, "content":content}, credentials["session_token"])
        return json.loads(result["result_json"])

    def spawn_child(self, credentials, spec, budget, tool, resource, delegated_capability, approval_id=""):
        return self._post("/v1/children", {"agent_id":credentials["agent"]["agent_id"], "capability":credentials["local_capability"], "spec":spec, "budget":budget, "tool":tool, "resource":resource, "delegated_capability":delegated_capability, "approval_id":approval_id}, credentials["session_token"])
