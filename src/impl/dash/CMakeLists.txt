# c2pool-dash coin module (V36 / PR-0 foundation decomposition).
#
# S2 scope (project_v36 consensus stage): X11 PoW hashing primitive ONLY.
# DGW v3 retarget is DEFERRED to S3 (header-chain slice); pay/replay to S4/S5.
# No coin binary or daemon slice is wired here yet -- this registers the single
# additive dash_x11 target so its KAT ctest runs on every Linux build. The diff
# is confined to src/impl/dash/* and is SAFE-ADDITIVE: no existing target links
# dash_x11, so ltc/btc/doge/dgb build + ctest surfaces are untouched.
add_subdirectory(crypto)

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
add_library(dash_rpc STATIC coin/rpc.cpp)
target_include_directories(dash_rpc PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash_rpc PRIVATE core nlohmann_json::nlohmann_json ${Boost_LIBRARIES})

# S8 sharechain-p2p dispatch layer (slice S8-p2p.2). Mirrors the dgb pool OBJECT
# lib (src/impl/dgb/CMakeLists.txt add_library(dgb OBJECT ...)): compiles the
# Legacy/Actual established-peer protocol handlers so the 12-message dispatch
# surface is a real compiled TU. node.cpp (the NodeImpl reception/think TU) is
# slice .4 and does NOT exist yet, so this OBJECT lib is intentionally NOT linked
# into any executable here -- processing_shares()/handle_get_share() are declared
# in node.hpp and their definitions are link-deferred to slice .4. Object-compile
# only; SAFE-ADDITIVE (no existing target links `dash`, so ltc/btc/doge/dgb build
# + ctest surfaces are untouched). Per-coin isolation held: src/impl/dash only.
add_library(dash OBJECT
    node.hpp
    peer.hpp
    messages.hpp
    share.hpp
    protocol_actual.cpp protocol_legacy.cpp
)
target_include_directories(dash PRIVATE
    ${CMAKE_SOURCE_DIR}/src
    ${CMAKE_SOURCE_DIR}/src/btclibs
    ${CMAKE_SOURCE_DIR}/include)
target_link_libraries(dash core pool sharechain c2pool_storage dash_x11 btclibs nlohmann_json::nlohmann_json ${Boost_LIBRARIES} ${SECP256K1_LIBRARIES})
