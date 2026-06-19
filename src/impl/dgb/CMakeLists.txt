# c2pool-dgb coin module (V36). Built when -DCOIN_DGB=ON.
# Mirrors src/impl/btc/CMakeLists.txt; emits the c2pool-dgb binary.
# Per-coin binary scheme: project_v36_per_coin_binary_v37_unified_process.
# Impl plan: c2pool-dgb-embedded-impl-plan.md (frstrtr/the docs/v36, 8ef8d2d).
#
# SCOPE (M1 / project_v36_dgb_scrypt_only): V36 validates SCRYPT blocks only.
# Other 4 DGB algos (SHA256d, Skein, Qubit, Odocrypt) = accept-by-continuity
# or ignored. Full 5-algo validation is DEFERRED TO V37.
#
# -DAUX_DOGE opt-in (DGB-as-DOGE-parent, the dual-parent stretch) is NOT wired
# in this module yet: parked behind the Phase 5.8 settle (ltc-doge owns the
# shared DOGE-aux surface). Do not add AUX_DOGE plumbing here at M2.
#
# TODO(M3): add_library(impl_dgb ...) sources as an OBJECT lib (ci-steward
# PR-CMake-object-library convention; impl_dgb = 1 of 5 per-coin OBJECT libs),
# link bitcoin_family/Scrypt shared base, wire embedded DigiByte Core daemon
# slice under daemon/. Top-level add_subdirectory(src/impl/dgb) registration
# follows the OBJECT-lib convention PR; held ~2-3 heartbeats, not raced here.
if(COIN_DGB)
  message(STATUS "c2pool: DGB Scrypt-only coin module enabled")
  add_subdirectory(coin)
  add_subdirectory(stratum)   # dgb_stratum: IWorkSource (#82 miner-facing path)
  # add_subdirectory(daemon)
  add_subdirectory(test)

  # dgb -- DGB Scrypt pool-layer OBJECT lib. Mirrors the ltc OBJECT lib
  # (src/impl/ltc/CMakeLists.txt): compiles the real NodeImpl translation unit
  # (node.cpp + protocol handlers) so share_tracker.hpp / share_check.hpp are
  # pulled into a compiled TU. Links the shared core / pool / sharechain base
  # plus dgb_coin (embedded P2P+mempool) and c2pool_storage (LevelDB sharechain).
  add_library(dgb OBJECT
      config_coin.hpp config_coin.cpp config_pool.hpp config_pool.cpp
      node.hpp node.cpp
      peer.hpp
      protocol_actual.cpp protocol_legacy.cpp
      messages.hpp
      share_types.hpp share.hpp
  )
  target_link_libraries(dgb core pool sharechain dgb_coin btclibs c2pool_storage ${SECP256K1_LIBRARIES})
endif()
