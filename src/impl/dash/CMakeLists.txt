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
