# c2pool-dash coin module (V36 / PR-0 foundation decomposition).
#
# S2 scope (project_v36 consensus stage): X11 PoW hashing primitive ONLY.
# DGW v3 retarget is DEFERRED to S3 (header-chain slice); pay/replay to S4/S5.
# No coin binary or daemon slice is wired here yet -- this registers the single
# additive dash_x11 target so its KAT ctest runs on every Linux build. The diff
# is confined to src/impl/dash/* and is SAFE-ADDITIVE: no existing target links
# dash_x11, so ltc/btc/doge/dgb build + ctest surfaces are untouched.
add_subdirectory(crypto)

# S8 stratum work-source module (dash::stratum::DASHWorkSource, the concrete
# core::stratum::IWorkSource). OBJECT lib compiled here; linked by c2pool-dash +
# the test_dash_stratum_work_source KAT only. SAFE-ADDITIVE, src/impl/dash only.
add_subdirectory(stratum)

# S5 block-replay slice (PR-0 foundation decomposition): compact-block
# reconstruction primitives (BIP-152 short-tx-id / PartiallyDownloadedBlock),
# vendored from dashcore with the C2POOL_SERIALIZE_METHODS idiom. SAFE-ADDITIVE:
# additive static lib; no existing target links dash_block_replay, so the
# ltc/btc/doge/dgb build + ctest surfaces are untouched. Block deserialization
# is TX_WITH_WITNESS-gated via bitcoin_family::coin (read-only TxParams const --
# no bitcoin_family/ touch). Replay ctest (test_dash_block_replay) wires in test/.
add_library(dash_block_replay STATIC coin/vendor/blockencodings.cpp)
target_include_directories(dash_block_replay PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(dash_block_replay PRIVATE core nlohmann_json::nlohmann_json ${Boost_LIBRARIES})

# Launcher slice-3 external-dashd-RPC client (won-block dual-path broadcaster,
# RPC leg). coin/rpc.cpp is a real boost::beast + jsonrpccxx HTTP JSON-RPC
# client to an external dashd, mirroring src/impl/dgb/coin/rpc.cpp conformed to
# DASH (X11, no segwit -> plain getblocktemplate body, NO algo param; rich
# DashWorkData getwork(); DASH genesis identity probe; submit_block_hex dashd
# submitblock fallback). The embedded-P2P relay leg of the broadcaster is still
# DEFERRED. SAFE-ADDITIVE: additive static lib; the ONLY existing target that
# links it is c2pool-dash (this slice), so the ltc/btc/doge/dgb build + ctest
# surfaces are untouched. Per-coin isolation held: src/impl/dash only, no
# shared-base/core SOURCE edit, dashd RPC fallback preserved.
# E1 Phase-L / E-SUPERBLOCK: BLS verify (coin/vendor/bls_verify.cpp). Provides
# BOTH the type-6 quorum-commitment aggregate verify (Phase-L) AND the single-
# signature governance-vote operator-key verify (R3 daemonless superblock
# serving — verify_govvote_operator_sig). Compiled UNCONDITIONALLY so the seam
# symbols always resolve; the dashbls backend is linked + the C2POOL_DASH_BLS
# define is set (PUBLIC, so the sole consumer c2pool-dash inherits it) ONLY when
# the library was found. Without it the verify functions are fail-closed stubs
# and NO dashbls dependency enters the build — keeping the Windows main_ltc
# launcher (shared core only) clean. SAFE-ADDITIVE: the only executable linking
# dash_bls_verify is c2pool-dash (plus its KAT test_dash_govvote_bls).
add_library(dash_bls_verify STATIC coin/vendor/bls_verify.cpp)
target_include_directories(dash_bls_verify PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash_bls_verify PRIVATE core ${Boost_LIBRARIES})
if(C2POOL_DASH_BLS_AVAILABLE)
    target_compile_definitions(dash_bls_verify PUBLIC C2POOL_DASH_BLS)
    target_include_directories(dash_bls_verify PUBLIC ${DASHBLS_INCLUDE_DIR})
    target_link_libraries(dash_bls_verify PUBLIC ${DASHBLS_LIBRARIES})
endif()

add_library(dash_rpc STATIC coin/rpc.cpp coin/zmq_tip_notify.cpp)
target_include_directories(dash_rpc PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash_rpc PRIVATE core nlohmann_json::nlohmann_json ${Boost_LIBRARIES})

# dashd ZMQ `hashblock` instant tip-notify (coin/zmq_tip_notify.cpp). libzmq is
# OPTIONAL: when available, compile the subscriber (C2POOL_ZMQ) and link libzmq.
# The define + link are PUBLIC so the ONLY consumer (c2pool-dash / main_dash.cpp)
# inherits them — one wiring point. When libzmq is absent only the pure hex
# helper compiles and c2pool-dash is byte-identical to the poll-only path.
if(C2POOL_ZMQ_AVAILABLE)
    target_compile_definitions(dash_rpc PUBLIC C2POOL_ZMQ)
    target_link_libraries(dash_rpc PUBLIC ${C2POOL_ZMQ_TARGET})
endif()

# S8 sharechain-p2p dispatch layer (slice S8-p2p.2). Mirrors the dgb pool OBJECT
# lib (src/impl/dgb/CMakeLists.txt add_library(dgb OBJECT ...)): compiles the
# Legacy/Actual established-peer protocol handlers so the 12-message dispatch
# surface is a real compiled TU. node.cpp (the NodeImpl reception/think TU) landed
# with slice .4 (#656/#657: processing_shares()/handle_get_share() bodies), so this
# OBJECT lib is now fully linkable and slice .3 LINKS it into c2pool-dash to bind a
# real sharechain P2P listener (src/c2pool/main_dash.cpp run_node). SAFE-ADDITIVE:
# the ONLY executable linking `dash` is c2pool-dash, so ltc/btc/doge/dgb build +
# ctest surfaces are untouched. Per-coin isolation held: src/impl/dash only.
add_library(dash OBJECT
    node.hpp
    peer.hpp
    messages.hpp
    share.hpp
    protocol_actual.cpp protocol_legacy.cpp node.cpp
)
target_include_directories(dash PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash core pool sharechain c2pool_storage dash_x11 btclibs nlohmann_json::nlohmann_json ${Boost_LIBRARIES} ${SECP256K1_LIBRARIES})

# ── PR-C4 (dashd-cut, tx-serving reward-safety) ──────────────────────────────
# Consensus-exact CheckInputScripts over the C1 fold view. dash_scriptcheck is
# dashcore's OWN script interpreter (src/script/interpreter.cpp + script.cpp +
# pubkey.cpp + primitives/transaction.cpp + the crypto/uint256/util leaves it
# needs), vendored byte-for-byte under coin/vendor/dashscript/ and compiled as a
# HIDDEN-VISIBILITY SHARED OBJECT that exports ONLY the pure-C c2pool_dash_*
# entry points (c2pool_scriptcheck.h). Building it as a .so with
# -fvisibility=hidden keeps every bitcoin-derived symbol (uint256, CScript,
# CSHA256, ...) internal to the object, so it can never ODR-collide with
# c2pool's own btclibs copies of the same names at the c2pool-dash final link.
# Links the system libsecp256k1 c2pool already depends on (ECDSA CHECKSIG). The
# ONLY consumers are c2pool-dash (via the --embedded-fold-checkscripts lambda in
# main_dash.cpp, default-OFF) and the test_dash_mempool KAT; the shared LTC
# launcher never links it. SAFE-ADDITIVE, src/impl/dash only.
set(_dash_scriptcheck_root ${CMAKE_CURRENT_SOURCE_DIR}/coin/vendor/dashscript)
add_library(dash_scriptcheck SHARED
    ${_dash_scriptcheck_root}/c2pool_scriptcheck.cpp
    ${_dash_scriptcheck_root}/script/interpreter.cpp
    ${_dash_scriptcheck_root}/script/script.cpp
    ${_dash_scriptcheck_root}/script/script_error.cpp
    ${_dash_scriptcheck_root}/script/bitcoinconsensus.cpp
    ${_dash_scriptcheck_root}/pubkey.cpp
    ${_dash_scriptcheck_root}/primitives/transaction.cpp
    ${_dash_scriptcheck_root}/uint256.cpp
    ${_dash_scriptcheck_root}/hash.cpp
    ${_dash_scriptcheck_root}/util/strencodings.cpp
    ${_dash_scriptcheck_root}/util/string.cpp
    ${_dash_scriptcheck_root}/support/cleanse.cpp
    ${_dash_scriptcheck_root}/crypto/sha256.cpp
    ${_dash_scriptcheck_root}/crypto/sha512.cpp
    ${_dash_scriptcheck_root}/crypto/ripemd160.cpp
    ${_dash_scriptcheck_root}/crypto/sha1.cpp
    ${_dash_scriptcheck_root}/crypto/hmac_sha256.cpp
    ${_dash_scriptcheck_root}/crypto/hmac_sha512.cpp
)
# Isolated include root (BEFORE) so the vendored files resolve dashcore's own
# <script/script.h>, <uint256.h>, <crypto/*>, <primitives/*> — NOT c2pool's
# btclibs (which this target deliberately does not link). Boost include dirs are
# added only to satisfy the directory-level force-included boost_asio_compat
# shim; no Boost library is linked into this crypto object.
target_include_directories(dash_scriptcheck BEFORE PRIVATE
    ${_dash_scriptcheck_root}
    ${Boost_INCLUDE_DIRS})
target_compile_definitions(dash_scriptcheck PRIVATE
    BUILD_BITCOIN_INTERNAL DISABLE_OPTIMIZED_SHA256 HAVE_CONFIG_H)
set_target_properties(dash_scriptcheck PROPERTIES
    CXX_VISIBILITY_PRESET hidden
    VISIBILITY_INLINES_HIDDEN ON
    POSITION_INDEPENDENT_CODE ON)
target_link_libraries(dash_scriptcheck PRIVATE ${SECP256K1_LIBRARIES})
