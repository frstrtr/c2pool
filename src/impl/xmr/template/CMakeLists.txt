# ─────────────────────────────────────────────────────────────────────────────
# Family B (XMR / RandomX lane) — whole-block template builder library (X9 opt-B)
#
# `xmr_template` = the p2pool-derived XmrBlockTemplate TU (GPL-3.0-only source,
# combined under AGPLv3 §13; see the PROVENANCE block atop
# xmr_block_template.cpp and xmr_provenance.hpp) + the AUTHORED bodies for the
# consumer-side primitive seam it consumes (xmr_coin_primitives.cpp, AGPL-3),
# which forward to the X1 `xmr_coin` library (vendored monero-project keccak.c,
# vendored tools::write_varint) so the template's varints / Keccak / midstate
# are the SAME bytes xmr_blob.hpp emits.
#
# Until this wave the template TU was compiled by NO target. Like xmr_coin it
# costs a plain `--target c2pool` build nothing: its TUs compile only when a
# target links it (the xmr_template_primitives_kat in ../test, and — behind the
# --settlement-coinbase opt-in — c2pool-v37-xmr once the option-B provider is
# wired in src/c2pool/CMakeLists.txt).
#
# Hook (one line, in ../CMakeLists.txt next to add_subdirectory(coin)/(node)):
#     add_subdirectory(template)
# No add_executable here, so the tools/ci/check_test_target_allowlist.py
# drift-guard (which audits test/ trees) is unaffected.
# ─────────────────────────────────────────────────────────────────────────────

if (NOT TARGET Threads::Threads)
    find_package(Threads REQUIRED)
endif()

add_library(xmr_template STATIC
    xmr_block_template.cpp        # p2pool block_template.cpp port (GPL-3, AGPLv3 §13)
    xmr_coin_primitives.cpp       # authored seam bodies over xmr_coin (AGPL-3)
)

# Consumers include "xmr_block_template.hpp" / "xmr_coin_primitives.hpp" /
# "xmr_coin_adapters.hpp" relative to this dir; xmr_coin's PUBLIC include dirs
# (coin/, coin/vendor, coin/compat) propagate through the PUBLIC link below.
target_include_directories(xmr_template PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})
target_link_libraries(xmr_template PUBLIC xmr_coin Threads::Threads)
target_compile_features(xmr_template PUBLIC cxx_std_20)
