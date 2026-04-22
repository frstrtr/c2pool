# Dashcore vendored sources

Authoritative dashcore algorithms ported here as a build-time vendor. The
upstream license is MIT, the same as c2pool, so the files live in-tree.

## Files

- `blockencodings.hpp` / `.cpp` — BIP 152 compact-block wire types and
  reassembly logic. Verbatim port of `dashcore/src/blockencodings.{h,cpp}`
  with four well-contained adaptations:
    1. Dashcore primitives (`CBlockHeader`, `CBlock`, `CTransactionRef`,
       `CTxMemPool`) replaced by Dash's own types via the typedefs in
       `shim.hpp`.
    2. Dashcore's `SERIALIZE_METHODS(Class, obj) { READWRITE(...) }`
       idiom is already provided by `btclibs/serialize.h`; we reuse it
       directly instead of porting it.
    3. `CheckBlock` removed from `FillBlock` — c2pool-dash validates
       merkle roots at higher layers (header-chain + submit path); the
       compact-block reassembly only needs to re-emit bytes peers sent us.
    4. `LogPrint(BCLog::CMPCTBLOCK, ...)` rewritten as `LOG_DEBUG_COIND`
       to land in c2pool's existing log stream.

No other changes. If dashcore updates `blockencodings`, diff against the
pinned upstream tag (currently dashcore master @ TBD — see
`project_dash_spv_embedded.md`) and re-apply the four adaptations.

## Shim (`shim.hpp`)

- `CTransactionRef` — `std::shared_ptr<const dash::coin::MutableTransaction>`.
- `MempoolShortIdProvider` — lightweight callback replacing the
  `CTxMemPool*` direct pointer. Phase M wires the real mempool;
  pre-Phase-M it's null and every cmpctblock falls straight through to
  `getblocktxn`.
- `DifferenceFormatter` — vendored verbatim from dashcore (no further
  dependencies).
