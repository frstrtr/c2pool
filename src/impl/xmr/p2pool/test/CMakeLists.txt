# ─────────────────────────────────────────────────────────────────────────────
# The P2Pool KATs. Two registered targets, split along the only line that
# matters here: what the PARSER does with bytes off a hostile wire, and what the
# DISPLAY does with numbers out of the read model.
#
#   xmr_p2pool_parse_kat    the component's risk surface -- a parser fed by an
#                           unauthenticated peer -- pinned against two real
#                           captured frames. One translation unit that compiles
#                           every header together, which is also the collision
#                           fence.
#   xmr_p2pool_monitor_kat  the monitor's frame, pinned against a golden
#                           rendered from three fixed read models, plus the
#                           emitted message-id set re-asserted for the second
#                           live binary. It includes NO socket header, so the
#                           layout is checked without a network stack -- and
#                           nothing about a dashboard can drift unseen.
#
# BOTH ARE OFFLINE. The parser goldens are real frames captured from a live mini
# session and embedded as hex; the monitor golden is the frame its own fixture
# produces (regenerate with `xmr_p2pool_monitor_kat --emit-golden`). Neither
# needs a network, a daemon, a fixture file or a terminal: they run identically
# on a laptop, on the sanitizer leg and on a machine with no route out.
#
# Both link xmr_coin for keccak and the tree hash. No RandomX, no boost, no
# libsodium, no ncurses: a LIGHT link, same tier as the C2a KATs.
#
# DRIFT-GUARD: this directory is outside the coin-test allowlist glob, so both
# targets below are also in BOTH `--target` lists in .github/workflows/build.yml.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    add_executable(xmr_p2pool_parse_kat p2pool_parse_kat.cpp)
    target_include_directories(xmr_p2pool_parse_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_p2pool_parse_kat PRIVATE xmr_coin)
    target_compile_features(xmr_p2pool_parse_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_p2pool_parse_kat COMMAND xmr_p2pool_parse_kat)

    add_executable(xmr_p2pool_monitor_kat p2pool_monitor_kat.cpp)
    target_include_directories(xmr_p2pool_monitor_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_p2pool_monitor_kat PRIVATE xmr_coin)
    target_compile_features(xmr_p2pool_monitor_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_p2pool_monitor_kat COMMAND xmr_p2pool_monitor_kat)
endif()
