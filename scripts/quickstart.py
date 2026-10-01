#!/usr/bin/env python3
"""Build, boot and demonstrate the mock MVP; report actual elapsed time."""
import os
import subprocess
import time
from pathlib import Path

os.chdir(Path(__file__).resolve().parents[1])
started = time.monotonic()
# Override a local provider selection for this explicitly offline demonstration.
environment = dict(os.environ, PRAESIDIONYX_PROVIDER="mock", ANTHROPIC_API_KEY="")
subprocess.run(["docker", "compose", "up", "--build", "-d", "--wait"], env=environment, check=True)
subprocess.run(["sh", "scripts/demo.sh"], env=environment, check=True)
elapsed = time.monotonic() - started
print(f"Quickstart completed in {elapsed:.1f}s (under 5 minutes: {elapsed < 300}).")
