# L-KR1Z1S drop_tails release-order race — CI guard

Self-contained AddressSanitizer stand-in for the SIGSEGV drop_tails race
(share-tracker prune vs concurrent IO). It seals the crash SHAPE; it does **not**
link `NodeImpl` / `main_ltc`. It follows the #759 stand-in pattern.

One ASan binary, three modes (see `kr1z1s_droptail_guard.sh`):

| MODE     | models                         | expected |
|----------|--------------------------------|----------|
| green    | fixed discipline under prune   | PASS (exit 0, io_ops>0) |
| deadcode | caller holds tracker mutex exclusive across notify (main_ltc.cpp:5011 shape) | RED (io_ops==0) |
| uaf      | node deref after lock release (node.cpp:1038 shape) | RED (ASan heap-use-after-free) |

Run standalone: `CXX=g++ bash kr1z1s_droptail_guard.sh`
Run via ctest:  `ctest -R LtcKr1z1sDropTailGuard`

`evidence/` holds a captured run of each mode; `evidence/PROVENANCE.txt` records
the compiler, flags, and the deterministic `source_sha256` anchor.
