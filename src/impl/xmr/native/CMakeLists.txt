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
#   * p2p/ (component C1a): the levin bucket-header codec, the epee
#     portable-storage codec and the typed P2P messages -- pure codec, no
#     socket and no connection state.
#   * consensus/ and chain/ (component C2a): the block parse and identity,
#     medians, weights, reward, difficulty, timestamps and the R-HFFUSE
#     hard-fork policy, plus the consensus state, the wire-to-state evaluation
#     seam and the real IChainView.
#
# Still header-only: nothing here is compiled until a target includes it, and
# the KATs in test/ are those targets. Two of the C2a KATs link `xmr_coin` for
# the keccak, tree hash and vendored difficulty oracle that already exist in
# this repository -- see test/CMakeLists.txt.
#
# SCOPE FENCE: this tree is a WORK SOURCE for the pool. It is not part of the
# v37 share-chain record, it activates no consensus, and it does not touch
# src/sharechain/v37.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
