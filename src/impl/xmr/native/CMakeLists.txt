# ─────────────────────────────────────────────────────────────────────────────
# Native-minimal Monero embedded node -- Wave 0.
#
# There is no library here on purpose. Wave 0 is the pinned CONTRACTS family
# (contracts/, header-only, STL plus the existing lane value types), a compiling
# fake per interface (contracts/fakes/), and the four shared consensus
# primitives every wave-1 component would otherwise have re-implemented
# (consensus/: the blob reader, consensus transaction weight, the hard-fork
# table and its fence, and the RandomX seed epoch).
#
# All of it is header-only, so nothing is compiled until a target includes it.
# The three Wave 0 KATs in test/ are those targets.
#
# SCOPE FENCE: this tree is a WORK SOURCE for the pool. It is not part of the
# v37 share-chain record, it activates no consensus, and it does not touch
# src/sharechain/v37.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
