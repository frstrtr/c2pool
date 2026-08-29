Embedded DigiByte Core daemon slice (M3). Forked from upstream DigiByte Core
(github.com/DigiByte-Core/digibyte). Vendoring policy: NO in-tree vendor;
reference clone built siblingly, artifacts into worktree only (M1 §1).
Scope: SPV + P2P + mempool + template builder, Scrypt-algo lane only
(project_embedded_coin_daemons_primary). Confirm DigiByte Core commit/tag at
vendoring. Non-Scrypt algo lanes (SHA256d/Skein/Qubit/Odocrypt) are NOT driven
in V36. Stub placeholder at M2.
