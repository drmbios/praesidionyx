# Researcher demo

Run `python3 examples/researcher/demo.py` after Compose boot with mock. It reads the
immutable offline research page via a real confined HTTP worker, derives a fixed summary,
proves that asking for a trusted memory label does not clear taint, requests a write,
approves the exact request through the supervisor CLI, retries, and reads back the file.
This demonstrates policy and confinement, not live-model summary quality.
