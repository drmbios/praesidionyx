#!/usr/bin/env python3
"""Record the fixed credential-safe demo to asciicast v2 plus plain text."""
import json
import os
import subprocess
import time
from pathlib import Path

root = Path(__file__).resolve().parents[1]
os.chdir(root)
started = time.monotonic()
header = {"version": 2, "width": 120, "height": 32, "timestamp": int(time.time()),
          "title": "Praesidionyx: capabilities, confinement, approvals, memory and scheduling",
          "env": {"TERM": "xterm-256color"}}
# Record only the fixed demo program. Never record a shell, env, or credential files.
with (root / "docs/demo.cast").open("w") as cast, (root / "docs/demo-transcript.txt").open("w") as transcript:
    cast.write(json.dumps(header) + "\n")
    process = subprocess.Popen(["sh", "scripts/demo.sh"], stdout=subprocess.PIPE,
                               stderr=subprocess.STDOUT, text=True, bufsize=1)
    for line in process.stdout:
        transcript.write(line)
        cast.write(json.dumps([round(time.monotonic() - started, 3), "o", line.replace("\n", "\r\n")]) + "\n")
        print(line, end="", flush=True)
    code = process.wait()
    if code:
        raise SystemExit(code)
print("Saved docs/demo.cast and docs/demo-transcript.txt.")
