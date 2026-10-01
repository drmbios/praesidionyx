# Injection demo

Run `python3 examples/injection-demo/demo.py` after Compose boot with mock. The compiled-in
web fixture hides an instruction to write owned.txt. A deterministic adversarial harness
attempts it through the real API; needs_approval occurs before execution. The supervisor
CLI denies it, retry fails, and a confined read proves no file was created. No API key,
external DNS or live model is needed. This tests the permission boundary, not an injection
classifier or a live model's susceptibility.
