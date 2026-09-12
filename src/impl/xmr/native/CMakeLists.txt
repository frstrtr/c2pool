# ─────────────────────────────────────────────────────────────────────────────
# Native-minimal Monero embedded node -- Waves 0 and 1.
#
# There is no library here on purpose. Wave 0 is the pinned CONTRACTS family
# (contracts/, header-only, STL plus the existing lane value types), a compiling
# fake per interface (contracts/fakes/), and the four shared consensus
# primitives every wave-1 component would otherwise have re-implemented
# (consensus/: the blob reader, consensus transaction weight, the hard-fork
# table and its fence, and the RandomX seed epoch).
#
# Wave 1 adds one directory per component:
#   * p2p/ (components C1a and C1b): C1a is the levin bucket-header codec, the
#     epee portable-storage codec and the typed P2P messages -- pure codec, no
#     socket and no connection state. C1b adds the TRANSPORT on top of it: the
#     asio LevinSocket (framed read loop, single-composed-write FIFO queue,
#     owner lifetime guard), the per-connection FIFO reply matcher (levin has
#     no request id), the HANDSHAKE state machine and the LevinLink that drives
#     the 1001 handshake and the 60-second 1002 TIMED_SYNC liveness beat.
#     RandomX never runs on the io thread; C1 hands blobs to C2, which owns the
#     verify thread.
#   * consensus/ and chain/ (component C2a): the block parse and identity,
#     medians, weights, reward, difficulty, timestamps and the R-HFFUSE
#     hard-fork policy, plus the consensus state, the wire-to-state evaluation
#     seam and the real IChainView.
#   * rct/ + txpool/ (component C3): the relayed transaction pool and the
#     non-input consensus it admits on. This is the ONE part of the native node
#     that is not header-only, and the reason is below.
#   * relay/ (component C5): the dual-arm found-block relay -- the self-contained
#     NOTIFY_NEW_FLUFFY_BLOCK (2008) push over C1c's IBroadcastPort, the
#     on-demand monerod submit_block backup arm, the 2009 responder with its
#     retained-block book, and the c2pool-side redundant-broadcast carrier with
#     its cheap-to-heavy admission ladder. Header-only. The RandomX gate is an
#     injected closure, fail-closed, so the component builds and is tested with
#     RandomX compiled out.
#   * template/ (component C4): the IMinerDataSource seam the option-B
#     settlement template provider is rebound through, with its two arms -- the
#     existing get_miner_data path, wrapped, and the native one built from the
#     C2c chain index plus the C3 txpool -- and the resolver that decides which
#     serves and which shadows. Header-only, derives no consensus value of its
#     own, and adds only the readiness gate, the epoch/rebuild rule and the
#     template-layer guards. The assembler above it is not modified at all.
#   * parity/ (component C6): the monerod-parity oracle, which is the M4 gate.
#     It runs beside a real daemon and judges three seams -- tip, template,
#     submit -- against it, keeping a revocable, hard-keyed graduation ledger.
#     Its one structural rule is that VOID IS NOT AGREEMENT: a comparison that
#     did not happen can never satisfy a coverage floor, so a probe that quietly
#     stopped firing blocks the gate instead of reading as calm. Header-only;
#     see parity/README.md.
#
# Everything else here is still header-only: nothing is compiled until a target
# includes it, and the KATs in test/ are those targets. Two of the C2a KATs link
# `xmr_coin` for the keccak, tree hash and vendored difficulty oracle that
# already exist in this repository, and the two C1b KATs link boost::asio
# (header-only in the pinned Boost 1.90) plus a thread library -- see
# test/CMakeLists.txt.
#
# SCOPE FENCE: this tree is a WORK SOURCE for the pool. It is not part of the
# v37 share-chain record, it activates no consensus, and it does not touch
# src/sharechain/v37.
# ─────────────────────────────────────────────────────────────────────────────

# ─────────────────────────────────────────────────────────────────────────────
# C3: the relayed txpool + non-input consensus (`xmr_native_txpool`)
#
# WHY A LIBRARY, when the rest of native/ is header-only: ruling R-VAL admits a
# relayed transaction on Structural | NonInputConsensus evidence, and the
# NonInputConsensus half is Bulletproof+ range-proof verification -- a thousand
# lines of elliptic-curve arithmetic with a 2048-entry generator table that must
# be built exactly once per process. That is a translation unit with state, not
# a header.
#
# It links `xmr_coin`, which already carries the byte-for-byte vendored monero
# ed25519 group operations (vendor/crypto-ops.c) and Keccak (vendor/keccak.c).
# Nothing under rct/ re-vendors either: see rct/PROVENANCE.md for what IS
# derived from upstream there and why it is a port rather than a copy.
#
# Cost discipline, same rule as xmr_coin and xmr_node: this library is declared
# unconditionally but its translation units compile ONLY when a target that
# links it is built (the two C3 KATs today, the native node later). A plain
# `--target c2pool` build pays nothing for it.
# ─────────────────────────────────────────────────────────────────────────────
add_library(xmr_native_txpool STATIC
    rct/xmr_rct_ops.cpp             # scalars, points, hashes over vendored ge_*/sc_*
    rct/xmr_multiexp.cpp            # Straus multi-scalar multiplication
    rct/xmr_bulletproofs_plus.cpp   # the Bulletproof+ VERIFIER (no prover)
    rct/xmr_rct_verify.cpp          # balance + range proofs + key-image domain
    txpool/xmr_tx_decode.cpp        # relay-side transaction decoder + identity
    txpool/xmr_relayed_txpool.cpp   # the pool itself
)

# Consumers include "impl/xmr/native/...", which is rooted at src/.
target_include_directories(xmr_native_txpool PUBLIC ${CMAKE_SOURCE_DIR}/src)

# PUBLIC: the rct headers include <vendor/crypto-ops.h>, which xmr_coin puts on
# the include path, so anything including them needs that path too.
target_link_libraries(xmr_native_txpool PUBLIC xmr_coin)

target_compile_features(xmr_native_txpool PUBLIC cxx_std_20)

# ─────────────────────────────────────────────────────────────────────────────
# C5 live proof (relay/tools/): the one thing a KAT cannot check -- whether a
# REAL monerod accepts the 2008 frame we build. BUILT here so it cannot bit-rot
# (it is in both build.yml --target lists) and RUN by nobody in CI: it needs a
# daemon, and CI must not depend on one. It registers no ctest test, so the
# #1539 Not-Run rule does not apply to it.
#
# UNIX only (POSIX sockets, no asio) and deliberately so: it is a harness, not a
# component, and keeping it dependency-free keeps it honest about what the relay
# itself needs. relay/tools/README.md carries the two-node regtest recipe and
# the run this component was landed on.
# ─────────────────────────────────────────────────────────────────────────────
if (BUILD_TESTING AND UNIX)
    add_executable(xmr_c5_regtest_push relay/tools/xmr_c5_regtest_push.cpp)
    target_include_directories(xmr_c5_regtest_push PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_c5_regtest_push PRIVATE xmr_coin)
    target_compile_features(xmr_c5_regtest_push PRIVATE cxx_std_20)
endif()

# ─────────────────────────────────────────────────────────────────────────────
# M0 (node/): THE ASSEMBLY. The wave-1 components are header-only and each one
# states a threading contract it does not itself provide; node/ builds the
# threads, the boot, the sync schedule and the status surface that turn them
# into a running node, and node/tools/ is the entrypoint that runs it.
#
# Same discipline as xmr_c5_regtest_push above: BUILT in both build.yml
# --target lists so it cannot bit-rot, RUN by nobody in CI (it needs a daemon
# and a network), and registering no ctest test -- so the #1539 Not-Run rule
# does not apply to it. What IS registered is test/xmr_native_node_kat, which
# covers the parts of the assembly that can be judged without a daemon: the
# queue adapters, the io-thread fence, the boot's derivation of the genesis
# row, and the sync driver's schedule.
#
# Links boost::asio (header-only in the pinned Boost 1.90), a thread library,
# and xmr_native_txpool (which brings xmr_coin for keccak, the tree hash and
# the vendored difficulty retarget). It links `randomx` when
# XMR_BUILD_RANDOMX is on, and defines XMR_NATIVE_NODE_HAVE_RANDOMX so the
# node compiles the real LightVerifier in; without it the binary still builds
# (the sanitizer leg has no RandomX) and refuses to call any block verified.
# ─────────────────────────────────────────────────────────────────────────────
if (BUILD_TESTING AND UNIX)
    add_executable(xmr_native_node node/tools/xmr_native_node_main.cpp)
    target_include_directories(xmr_native_node PRIVATE ${CMAKE_SOURCE_DIR}/src)
    # xmr_node carries the PRODUCTION get_miner_data parser
    # (MoneroDaemonRpc::body_get_miner_data / parse_miner_data). It became a
    # link dependency at M4 rather than earlier because nothing in this binary
    # had ever POLLED the daemon template arm: the M4 soak drives P-TPL, which
    # means calling MonerodMinerDataSource::poll(), which instantiates that
    # parse. The alternative -- a second decode path for the daemon arm -- would
    # make "we match the daemon" a claim about a re-typed struct, which is
    # exactly what the C4/C6 targets link xmr_node to avoid.
    target_link_libraries(xmr_native_node PRIVATE xmr_native_txpool xmr_node)
    target_compile_features(xmr_native_node PRIVATE cxx_std_20)
    if (TARGET Boost::headers)
        target_link_libraries(xmr_native_node PRIVATE Boost::headers)
    elseif (TARGET Boost::boost)
        target_link_libraries(xmr_native_node PRIVATE Boost::boost)
    elseif (DEFINED Boost_INCLUDE_DIRS)
        target_include_directories(xmr_native_node PRIVATE ${Boost_INCLUDE_DIRS})
    endif()
    if (TARGET Threads::Threads)
        target_link_libraries(xmr_native_node PRIVATE Threads::Threads)
    endif()
    if (TARGET randomx)
        target_link_libraries(xmr_native_node PRIVATE randomx)
        target_compile_definitions(xmr_native_node PRIVATE XMR_NATIVE_NODE_HAVE_RANDOMX=1)
    endif()
endif()

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
