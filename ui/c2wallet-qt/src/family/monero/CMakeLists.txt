# ═══════════════════════════════════════════════════════════════════════════
# c2wallet-qt Family B (Monero) seed/key/address core  (design §2.3 / §3.2)
#
# Deliberately Qt-FREE: this defines a plain C++17 static library plus a ctest
# executable, so the money-correctness KATs build and run WITHOUT the Qt signer
# app (and without Qt6 installed). It links c2pool's ALREADY-VENDORED Monero
# curve engine (design §2.4) by compiling the leaf TUs directly -- the same
# byte-identical BSD-3 crypto-ops/keccak the node uses -- rather than
# reimplementing any curve or hash math. It links NO libsodium (the compat/
# crypto_verify_32 shim covers the one symbol crypto-ops.c needs) and NO boost
# (difficulty.cpp is not pulled in here).
#
# Standalone (Qt-free) build of just these KATs:
#   cmake -S ui/c2wallet-qt/src/family/monero -B /tmp/mxbuild
#   cmake --build /tmp/mxbuild --target c2wallet-monero-seed-test
#   ctest --test-dir /tmp/mxbuild --output-on-failure
#
# Or, from the c2wallet-qt tree, with -DC2WALLET_QT_BUILD_TESTS=ON.
# ═══════════════════════════════════════════════════════════════════════════
cmake_minimum_required(VERSION 3.21)

# Allow standalone configuration (Qt-free) as well as add_subdirectory() use.
if (CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
    project(c2wallet_monero LANGUAGES C CXX)
    enable_testing()
endif()

# The vendored Monero crypto is C. The c2wallet-qt parent project declares only
# LANGUAGES CXX, so enable C here (a no-op if the parent already enabled it) --
# otherwise the .c files are silently dropped and sc_reduce32 et al. never link.
enable_language(C)

# This module is deliberately Qt-free: no moc pass on any of its targets, even
# when built as a subdirectory of a project that sets AUTOMOC globally.
set(CMAKE_AUTOMOC OFF)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_C_STANDARD 11)

# Locate the c2pool node source root (repo/src) relative to this module dir:
#   ui/c2wallet-qt/src/family/monero  ->  ../../../../../src
get_filename_component(C2WALLET_MONERO_NODE_SRC
    "${CMAKE_CURRENT_SOURCE_DIR}/../../../../../src" ABSOLUTE)
set(XMR_COIN "${C2WALLET_MONERO_NODE_SRC}/impl/xmr/coin")
set(XMR_RCT  "${C2WALLET_MONERO_NODE_SRC}/impl/xmr/native/rct")

if (NOT EXISTS "${XMR_COIN}/vendor/crypto-ops.c")
    message(FATAL_ERROR
        "c2wallet-monero: cannot find the vendored Monero crypto at ${XMR_COIN}. "
        "Set C2WALLET_MONERO_NODE_SRC to the c2pool src/ directory.")
endif()

# ── vendored Monero crypto (BSD-3, byte-identical, compiled directly) ────────
# The minimal leaf set the seed/key/address core needs: ed25519 group/scalar
# ops, precomputed tables, Keccak, and cn_fast_hash. crypto_verify_32 resolves
# to the authored compat shim (compat/ first on the include path).
add_library(c2wallet_monero_xmrvendor STATIC
    ${XMR_COIN}/vendor/keccak.c
    ${XMR_COIN}/vendor/hash.c
    ${XMR_COIN}/vendor/crypto-ops.c
    ${XMR_COIN}/vendor/crypto-ops-data.c
    ${XMR_COIN}/xmr_derivation.cpp        # extracted CryptoNote derivation subset
    ${XMR_RCT}/xmr_rct_ops.cpp            # M3-X: RingCT scalar/point helpers (CLSAG deps)
    ${XMR_RCT}/xmr_multiexp.cpp           # M4-X: Straus multi-scalar mult (BP+ prover + verifier)
    ${XMR_RCT}/xmr_bulletproofs_plus.cpp  # M4-X: in-tree BP+ VERIFIER (the construct->verify oracle)
)
target_include_directories(c2wallet_monero_xmrvendor PUBLIC
    ${XMR_COIN}/compat      # MUST be first: <sodium/crypto_verify_32.h>, warnings.h
    ${XMR_COIN}
    ${XMR_COIN}/vendor
    ${XMR_RCT}              # M3-X: for "xmr_rct_ops.hpp"
)
# int-util.h wants _GNU_SOURCE for BYTE_ORDER/mul128 (harmless for the C++ TU).
target_compile_definitions(c2wallet_monero_xmrvendor PRIVATE _GNU_SOURCE)

# ── the authored Family B core (AGPL-3, Qt-free) ─────────────────────────────
add_library(c2wallet_monero STATIC
    MoneroCrypto.cpp
    seed/MoneroWordlist.cpp
    seed/MoneroMnemonic.cpp
    addr/MoneroBase58.cpp
    addr/MoneroAddress.cpp
    MoneroKey.cpp
    scan/MoneroScanOps.cpp
    scan/MoneroScanner.cpp
    prover/MoneroProverRng.cpp            # M3-X: wallet-local CSPRNG scalar for the prover (money-safety)
    prover/MoneroClsag.cpp                # M3-X: CLSAG signer + verifier (ported)
    prover/MoneroKeyImage.cpp             # M3-X: key-image export {I, ring-sig}
    prover/MoneroBulletproofsPlus.cpp     # M4-X: Bulletproofs+ range-proof PROVER (ported)
    prover/MoneroRingctBuilder.cpp        # M4-X: full RingCT tx assembly + offline self-verify
    artifact/MoneroArtifact.cpp        # M5-X: cold-sign artifact marshaling (verbatim monero layouts)
    ${CMAKE_CURRENT_SOURCE_DIR}/../../secure/SecureString.cpp
)
target_include_directories(c2wallet_monero PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../..     # ui/c2wallet-qt/src  (for "family/..","secure/..")
)
target_link_libraries(c2wallet_monero PUBLIC c2wallet_monero_xmrvendor)

# ── the KAT executable + ctest registration ─────────────────────────────────
add_executable(c2wallet-monero-seed-test
    test/monero_seed_test.cpp
)
target_link_libraries(c2wallet-monero-seed-test PRIVATE c2wallet_monero)

add_test(NAME c2wallet_monero_seed_kat COMMAND c2wallet-monero-seed-test)

# ── Family B (Monero) output-scanning KATs (M2-X) ────────────────────────────
# Read-only wallet scan: ownership test, amount decrypt, subaddress table, the
# view-only/full-wallet key-image split. Same Qt-free lib, a second ctest.
add_executable(c2wallet-monero-scan-test
    scan/test/monero_scan_test.cpp
)
target_link_libraries(c2wallet-monero-scan-test PRIVATE c2wallet_monero)

add_test(NAME c2wallet_monero_scan_kat COMMAND c2wallet-monero-scan-test)

# ── Family B (Monero) prover KATs (M3-X): key image + CLSAG signer ───────────
# Money-path: key-image export {I, ring-sig} and the ported CLSAG signer, gated
# by a construct->verify round-trip against the ported verifier (there is no
# in-tree CLSAG verifier) plus tamper-rejection and the view-only split.
add_executable(c2wallet-monero-prover-test
    prover/test/monero_prover_test.cpp
)
target_link_libraries(c2wallet-monero-prover-test PRIVATE c2wallet_monero)

add_test(NAME c2wallet_monero_prover_kat COMMAND c2wallet-monero-prover-test)

# ── Family B (Monero) M4-X KATs: Bulletproofs+ prover + full RingCT assembly ──
# HIGH money-path: the range-proof PROVER gated by construct -> INDEPENDENT
# in-tree BP+ verify (a separate construct, stronger than CLSAG's), full RingCT
# transaction assembly (commitments, balanced masks, ecdh, CLSAG per input, key
# images, fee, tx_extra, blob + tx_hash), and the offline self-verify-before-emit
# that refuses an unbalanced or non-verifying tx.
add_executable(c2wallet-monero-ringct-test
    prover/test/monero_ringct_test.cpp
)
target_link_libraries(c2wallet-monero-ringct-test PRIVATE c2wallet_monero)

add_test(NAME c2wallet_monero_ringct_kat COMMAND c2wallet-monero-ringct-test)

# -- Family B (Monero) M5-X KATs: cold-sign artifact marshaling ---------------
# The four public artifacts that cross the air gap (design 5.4; Decision 9 =
# verbatim monero layouts): outputs export, key-image export, unsigned_txset,
# signed_txset. Round-trip each; an unsigned_txset carrying a frozen ring drives
# the M4-X assembler to a SELF-VERIFYING signed_txset; the online-facing exports
# carry no spend secret (byte scan); a flipped byte is detected at parse.
add_executable(c2wallet-monero-artifact-test
    artifact/test/monero_artifact_test.cpp
)
target_link_libraries(c2wallet-monero-artifact-test PRIVATE c2wallet_monero)

add_test(NAME c2wallet_monero_artifact_kat COMMAND c2wallet-monero-artifact-test)
