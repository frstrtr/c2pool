# c2pool-dgb coin module (V36). Mirrors src/impl/btc/CMakeLists.txt.
# Per-coin binary scheme: project_v36_per_coin_binary_v37_unified_process.
# Impl plan: c2pool-dgb-embedded-impl-plan.md (frstrtr/the docs/v36, 8ef8d2d).
#
# SCOPE (M1 / project_v36_dgb_scrypt_only): V36 validates SCRYPT blocks only.
# Other 4 DGB algos (SHA256d, Skein, Qubit, Odocrypt) = accept-by-continuity
# or ignored. Full 5-algo validation is DEFERRED TO V37.
#
# -DAUX_DOGE opt-in (DGB-as-DOGE-parent, the dual-parent stretch): the build-flag
# seam is wired below (phase DA, post-#82). It only compiles the INERT aux seam in
# coin/node.hpp; the shared DOGE-aux surface (ltc-doge owns) is CONSUMED at M3/DB,
# not here. Default OFF -> standalone Scrypt-only parent.
#
# LIB GATING (mirrors btc/ltc): the dgb_coin (coin-layer), dgb_stratum
# (miner-facing IWorkSource) and dgb (pool-layer) OBJECT libs are defined
# UNCONDITIONALLY — the c2pool-dgb executable links them, and the coin-matrix
# CI builds that exe WITHOUT -DCOIN_DGB, so the targets MUST exist regardless
# of the flag (gating them behind COIN_DGB makes the linker fall back to raw
# -ldgb/-ldgb_coin/-ldgb_stratum and fail). Only the test subtree stays behind
# COIN_DGB; build.yml sets -DCOIN_DGB=ON and builds those targets.
# -DAUX_DOGE=ON: DGB-as-DOGE-parent dual-parent merged-mining STRETCH opt-in
# (phase DA). Defines the AUX_DOGE compile macro across the dgb subtree so the
# inert aux seam in coin/node.hpp compiles (forward-decl + AuxChainBackend type
# alias + bind_aux_doge_parsers() declaration -- no body, never ODR-used). The
# shared src/impl/doge aux module is CONSUMED only at M3/DB, when the real
# <impl/doge/coin/aux_chain_embedded.hpp> include and the bind body land
# (ltc-doge owns and is the sole modifier of that surface). Default OFF keeps the
# standalone Scrypt-only parent build with zero DOGE coupling.
option(AUX_DOGE "DGB-as-DOGE-parent dual-parent merged-mining stretch (consumes shared src/impl/doge aux module at M3)" OFF)
if(AUX_DOGE)
  message(STATUS "c2pool-dgb: AUX_DOGE dual-parent stretch ENABLED (DGB-as-DOGE-parent)")
  add_compile_definitions(AUX_DOGE)
endif()

add_subdirectory(coin)
add_subdirectory(stratum)   # dgb_stratum: IWorkSource (#82 miner-facing path)
# add_subdirectory(daemon)

# dgb -- DGB Scrypt pool-layer OBJECT lib. Mirrors the ltc/btc OBJECT lib:
# compiles the real NodeImpl translation unit (node.cpp + protocol handlers)
# so share_tracker.hpp / share_check.hpp are pulled into a compiled TU. Links
# the shared core / pool / sharechain base plus dgb_coin (embedded P2P+mempool)
# and c2pool_storage (LevelDB sharechain).
add_library(dgb OBJECT
    config_coin.hpp config_coin.cpp config_pool.hpp config_pool.cpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    messages.hpp
    share_types.hpp share.hpp
)
target_link_libraries(dgb core pool sharechain dgb_coin btclibs c2pool_storage ${SECP256K1_LIBRARIES})

if(COIN_DGB)
  message(STATUS "c2pool: DGB Scrypt-only coin module enabled")
  add_subdirectory(test)
endif()
