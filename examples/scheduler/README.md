# Scheduler and delegation demo

Run `python3 examples/scheduler/demo.py` after Compose boot with mock. A parent delegates
an exact read token to a child; attempted write/scope widening fails. Typed messages
propagate taint. Pause/resume and parent-kill cascade are exercised. A one-tool budget
allows the final read to finish, then the scheduler kills the exhausted agent. Unit tests
separately assert termination in one tick for all budgets and cancellation during inference.
