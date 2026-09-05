# ─────────────────────────────────────────────────────────────────────────────
# Family B: Monero / RandomX settlement lane  (v37 Work-Receipts, Track X)
#
# FOUNDATION scaffold. This is a NEW per-coin tree (src/impl/xmr/) with ~0%
# reuse below the sharechain seam and ~100% above it. It does NOT touch
# src/sharechain/v37 consensus-digest code.
#
# What is intentionally NOT wired into the coin build here:
#   * the RandomX verifier (needs the tevador/RandomX submodule -> librandomx.a);
#   * the ed25519 crypto-ops path (needs libsodium at link time);
#   * the monerod RPC/ZMQ adapter (needs an async HTTP client + cppzmq);
#   * the whole-block template builder, stratum front-end, W3 wire, W5 coinbase.
# Those land in later Track-X PRs (WBS X1–X9, see docs/xmr-lane/). Building them
# now would drag heavy external deps onto OOM-pressured CI hosts before the lane
# is ready. The FOUNDATION only compiles the self-contained, dependency-free
# self-checks (STL + the vendored Monero C crypto) under test/.
#
# The coinbase-output-derivation surface (settle/, template/) is fenced
# PRE-CARROT, pinned per Monero hard-fork major_version (<= 16). See
# docs/xmr-lane/w5-xmr-coinbase-rule.md §6 and xmr_pow_select.hpp.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
