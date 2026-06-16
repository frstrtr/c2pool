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
# TODO(Phase B): pool/share-layer OBJECT lib. Scaffolding stubs landed on
# branch dgb/pool-pillars-port (ported from src/impl/ltc, Scrypt-only):
#   share_types.hpp share.hpp share_tracker.hpp share_check.hpp
#   redistribute.hpp peer.hpp messages.hpp
#   auto_ratchet.hpp        -- PILLAR 1, GATED on F10 fence (version-acceptance)
#   donation_consensus.hpp  -- PILLAR 4, GATED on farsider350-vs-LTC reconcile
#   config_pool.cpp node.cpp protocol_actual.cpp protocol_legacy.cpp (TBD)
# Files are listed for tracking but NOT yet compiled -- the add_library(impl_dgb
# ...) OBJECT-lib registration follows the same ci-steward convention PR as the
# coin lib (held, not raced). Pillars 1 and 4 stay stubbed behind their gates.
if(COIN_DGB)
  message(STATUS "c2pool: DGB Scrypt-only coin module enabled (skeleton)")
  add_subdirectory(coin)

  # impl_dgb pool/share-layer OBJECT lib (Phase B / B1). Mirrors the ltc OBJECT
  # lib (dgb was ported verbatim from src/impl/ltc, Scrypt parent) per the
  # ci-steward OBJECT-lib direct-naming convention (#22/#39). B1 is header-only,
  # so b1_smoke.cpp is the sole compile unit giving the surface a whole-target
  # build gate; real TUs (config_pool.cpp/node.cpp/protocol_actual.cpp/
  # protocol_legacy.cpp) replace it as dgb-scrypt-steward lands them.
  add_library(dgb OBJECT
      b1_smoke.cpp
      share_types.hpp share.hpp
      share_tracker.hpp share_check.hpp share_messages.hpp
      redistribute.hpp
      config_coin.hpp config_pool.hpp
      messages.hpp node.hpp peer.hpp
      # auto_ratchet.hpp / donation_consensus.hpp: PILLAR 1/4, gated -- not compiled here
  )

  target_link_libraries(dgb core pool sharechain dgb_coin btclibs c2pool_storage ${SECP256K1_LIBRARIES})

  # add_subdirectory(daemon)  # M3
  # add_subdirectory(test)    # B-later: share_test references LTC types
endif()
