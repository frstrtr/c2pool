Embedded BCHN daemon slice. Forked from Bitcoin Cash Node, lowest divergence
from Bitcoin Core (same root as c2pool-btc embedded daemon). Vendoring policy:
NO in-tree vendor of BCHN; reference clone built siblingly, artifacts into
worktree only (M1 §1.1). Scope: SPV + P2P + mempool + template builder.

The embedded daemon body now lives under src/impl/bch/coin/. Owner entrypoint
is EmbeddedDaemon<Config> (coin/embedded_daemon.hpp), which binds HeaderChain,
Mempool, EmbeddedCoinNode, coin::Node and AblaRuntime in order and runs them.
AblaRuntime (coin/abla_runtime.hpp) closes the ABLA loop full_block -> feed ->
tracker -> getwork budget. EMBEDDED-PRIMARY / EXTERNAL-FALLBACK holds: the
external BCHN RPC path (coin/rpc.*) is retained as fallback, never removed.
