# ─────────────────────────────────────────────────────────────────────────────
# Family B (XMR / RandomX lane) — coin primitives static library  (WBS X1)
#
# `xmr_coin` bundles the LIGHT, dependency-lean consensus primitives the lane
# needs below the sharechain seam: the vendored monero-project C crypto
# (Keccak/cn_fast_hash, tree-hash, ed25519 group-ops), the extracted CryptoNote
# stealth-address derivation, the block hashing-blob assembler, and the vendored
# difficulty reference oracle. It links NO RandomX (that is the heavy CI-only
# path, wired in test/CMakeLists.txt behind XMR_BUILD_RANDOMX) and NO libsodium
# (see the crypto_verify_32 note below).
#
# Consumers: the X1 KAT targets in ../test now; the W3 receipt verifier, W5
# coinbase executor and monerod-adapter in later waves. Because nothing in the
# base `c2pool` target links it yet, defining this library adds ZERO cost to a
# plain `--target c2pool` build — the TUs here compile only when a target that
# links `xmr_coin` (i.e. a KAT) is actually built.
#
# Vendored C/C++ under vendor/ is compiled BYTE-FOR-BYTE unmodified (LIC-1);
# every build-time gap upstream fills with an external dep is filled instead by
# an authored, dependency-free shim under compat/ placed on the include path:
#   * compat/warnings.h                 (epee diagnostics)            [foundation]
#   * compat/sodium/crypto_verify_32.h  (the ONE libsodium symbol crypto-ops.c
#                                        uses; the repo carries no libsodium)   [X1]
#   * compat/crypto/hash.h              (crypto::hash for difficulty.cpp)       [X1]
#   * compat/cryptonote_config.h        (difficulty-window constants)           [X1]
# ─────────────────────────────────────────────────────────────────────────────

add_library(xmr_coin STATIC
    # --- vendored monero-project C crypto (BSD-3, byte-identical) -------------
    vendor/keccak.c            # Keccak-1600 permutation + incremental CTX
    vendor/hash.c              # cn_fast_hash (== Keccak-256, 32-B digest)
    vendor/tree-hash.c         # CryptoNote tx merkle tree_hash / tree_branch
    vendor/crypto-ops.c        # ed25519 ge_*/sc_* (uses crypto_verify_32 shim)
    vendor/crypto-ops-data.c   # ed25519 precomputed base tables
    vendor/difficulty.cpp      # cryptonote::check_hash reference oracle (boost)
    # --- authored c2pool lane code (AGPL-3) -----------------------------------
    xmr_blob.cpp               # hashing-blob / tx-hash / tree_root / branch verify
    xmr_derivation.cpp         # generate_key_derivation / derive_public_key / ...
)

# Public: consumers include coin-relative ("xmr_blob.hpp", "vendor/varint.h",
# "xmr_check_hash.hpp") and reach the vendored headers + compat shims through
# these dirs. compat is FIRST so <sodium/crypto_verify_32.h>, "crypto/hash.h",
# "cryptonote_config.h" and "warnings.h" resolve to the authored stand-ins.
target_include_directories(xmr_coin PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/compat
    ${CMAKE_CURRENT_SOURCE_DIR}
    ${CMAKE_CURRENT_SOURCE_DIR}/vendor)

# int-util.h needs _GNU_SOURCE for BYTE_ORDER/mul128; harmless for the C++ TUs.
target_compile_definitions(xmr_coin PRIVATE _GNU_SOURCE)
target_compile_features(xmr_coin PRIVATE c_std_11 cxx_std_20)

# difficulty.cpp is the ONLY TU that pulls boost::multiprecision (uint128/256/512).
# Header-only, so this contributes includes, not a link. Root CMakeLists already
# `find_package(Boost REQUIRED ...)`, so a boost target exists repo-wide.
if (TARGET Boost::headers)
    target_link_libraries(xmr_coin PRIVATE Boost::headers)
elseif (TARGET Boost::boost)
    target_link_libraries(xmr_coin PRIVATE Boost::boost)
elseif (DEFINED Boost_INCLUDE_DIRS)
    target_include_directories(xmr_coin PRIVATE ${Boost_INCLUDE_DIRS})
endif()

# NOTE (fan-in): the foundation's xmr_primitives_selfcheck / xmr_stratum_selftest
# still compile the vendored .c/.cpp directly (self-contained, pre-lib). That is
# a benign duplicate COMPILE, not a symbol clash (separate executables). A later
# cleanup MAY migrate those two targets to `target_link_libraries(... xmr_coin)`
# and drop their inline vendored sources; it is intentionally NOT done here to
# keep the proven foundation targets untouched.
