# Memory demo

Run `python3 examples/memory/demo.py` after Compose boot with mock. It proves paging,
bounded sqlite-vec recall, resident-page rollback, sticky taint, cross-owner snapshot
rejection and isolation, through HTTP and Unix gRPC. Byte counts estimate context tokens;
embeddings are deterministic hashed word vectors, with no remote service.
