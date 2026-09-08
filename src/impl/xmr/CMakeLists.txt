# ─────────────────────────────────────────────────────────────────────────────
# Family B: Monero / RandomX settlement lane  (v37 Work-Receipts, Track X)
#
# FOUNDATION scaffold. This is a NEW per-coin tree (src/impl/xmr/) with ~0%
# reuse below the sharechain seam and ~100% above it. It does NOT touch
# src/sharechain/v37 consensus-digest code.
#
# What is intentionally NOT wired into the coin build here:
#   * the RandomX verifier (needs the tevador/RandomX submodule -> librandomx.a);
#   * the monerod RPC/ZMQ adapter (needs an async HTTP client + cppzmq);
#   * the whole-block template builder, stratum front-end, W3 wire, W5 coinbase.
# Those land in later Track-X PRs (WBS X1–X9, see docs/xmr-lane/). Building them
# now would drag heavy external deps onto OOM-pressured CI hosts before the lane
# is ready.
#
# WBS X1 (this change): the `coin/` subtree is now a light static library
# (`xmr_coin`) — vendored Monero C crypto + ed25519 derivation + the difficulty
# oracle. Defining it costs a plain `--target c2pool` build nothing (nothing in
# the base target links it yet); its TUs compile only when an X1 KAT that links
# it is built. The ed25519 path builds WITHOUT libsodium via the authored
# coin/compat/sodium/crypto_verify_32.h shim.
#
# The coinbase-output-derivation surface (settle/, template/) is fenced
# PRE-CARROT, pinned per Monero hard-fork major_version (<= 16). See
# docs/xmr-lane/w5-xmr-coinbase-rule.md §6 and xmr_pow_select.hpp.
# ─────────────────────────────────────────────────────────────────────────────

# X1: light coin-primitives library (unconditional — it is lane production code
# consumed by later waves; compiles only when a dependent target is built).
add_subdirectory(coin)

# X2 (W2): daemon-ful monerod adapter library (xmr_node). Unconditional like
# coin — production lane code; its TUs compile only when a dependent target (the
# X2 node KAT in test/, or later W3 wire / W5 coinbase legs) is built.
add_subdirectory(node)

# X8 / O-2: librandomx from the VENDORED tevador/RandomX tree (consensus pin
# 12f2c2ff, third_party/randomx). OFF by default — 2 x 256 MiB light caches +
# a JIT are OOM-hostile on a laptop and do not survive -fsanitize — and turned
# ON by the non-sanitizer CI leg (-DXMR_BUILD_RANDOMX=ON). Declared HERE (not
# only in test/) so the c2pool-v37-xmr daemon can link `randomx` for its
# runtime submit-path verify without BUILD_TESTING; test/ re-declares the same
# option (idempotent) and guards its own add_subdirectory with NOT TARGET.
option(XMR_BUILD_RANDOMX
    "Build librandomx (tevador/RandomX pin 12f2c2ff) for the runtime verify + KAT" OFF)
if (XMR_BUILD_RANDOMX AND NOT TARGET randomx
    AND EXISTS ${CMAKE_CURRENT_SOURCE_DIR}/third_party/randomx/CMakeLists.txt)
    add_subdirectory(third_party/randomx ${CMAKE_CURRENT_BINARY_DIR}/randomx_build)
endif()

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
