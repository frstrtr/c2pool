# c2pool-bch coin module (V36). Built when -DCOIN_BCH=ON.
# Mirrors src/impl/btc/CMakeLists.txt; emits the c2pool-bch binary.
# Per-coin binary scheme: project_v36_per_coin_binary_v37_unified_process.
#
# TODO(M3): add_library(impl_bch ...) sources, link bitcoin_family shared base,
# wire embedded BCHN daemon slice under daemon/. Stub only at M2.
if(COIN_BCH)
  message(STATUS "c2pool: BCH coin module enabled (skeleton)")
  # add_subdirectory(coin)
  # add_subdirectory(daemon)
  # add_subdirectory(test)
endif()
