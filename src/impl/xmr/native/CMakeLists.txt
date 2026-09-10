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
#   * template/ (component C4): the IMinerDataSource seam the option-B
#     settlement template provider is rebound through, with its two arms -- the
#     existing get_miner_data path, wrapped, and the native one built from the
#     C2c chain index plus the C3 txpool -- and the resolver that decides which
#     serves and which shadows. Header-only, derives no consensus value of its
#     own, and adds only the readiness gate, the epoch/rebuild rule and the
#     template-layer guards. The assembler above it is not modified at all.
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

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
