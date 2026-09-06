# ─────────────────────────────────────────────────────────────────────────────
# Family B (XMR / RandomX lane) — monerod adapter static library  (WBS X2, W2)
#
# `xmr_node` is the daemon-ful monerod adapter: the RPC/ZMQ decoders plus the
# mainchain index. The header-only pieces (xmr_node_types, monerod_transport,
# minijson, mainchain_index, monero_node_adapter) need no translation unit — only
# the RPC and ZMQ JSON decoders carry .cpp bodies, so those are the library's two
# sources. All daemon I/O is behind the mockable IMonerodTransport seam
# (monerod_transport.hpp); NO RandomX, NO libzmq, NO async HTTP client is linked
# here — production supplies the real HTTP/libzmq backing in a later engine leg.
#
# Primitive-reuse (no drift): mainchain_index.hpp #includes
# impl/xmr/coin/xmr_seedheight.hpp and calls ::xmr::coin::rx_seedheight(); the
# 2112-block SEED_REACH_MIN is DERIVED from ::xmr::coin::SEEDHASH_EPOCH_BLOCKS +
# SEEDHASH_EPOCH_LAG, so the node and coin legs can never disagree on the seed
# schedule. The src/ include root below makes that impl/xmr/coin/... include
# resolve; this library re-vendors nothing.
#
# Like xmr_coin, defining this library costs a plain `--target c2pool` build
# nothing: nothing in the base target links it yet, so its TUs compile only when
# a dependent target (the X2 node KAT in ../test, or the W3 wire / W5 coinbase
# legs later) is actually built.
# ─────────────────────────────────────────────────────────────────────────────

add_library(xmr_node STATIC
    monero_rpc.cpp   # JSON-RPC request bodies + typed get_miner_data/fee/submit parsers
    monero_zmq.cpp   # ZMQ json-full/json-minimal topic decoders (miner_data/txpool/chain_main)
)

# PUBLIC src/ root: consumers reach node + coin headers as
# "impl/xmr/node/…" / "impl/xmr/coin/xmr_seedheight.hpp".
target_include_directories(xmr_node PUBLIC ${CMAKE_SOURCE_DIR}/src)
target_compile_features(xmr_node PUBLIC cxx_std_20)

# Header-only dependence on the X1 coin leg (seed-height primitive) resolves via
# the include root above; no link edge is required. A later wave that pulls a
# compiled coin symbol into the node path can add:
#   target_link_libraries(xmr_node PUBLIC xmr_coin)
