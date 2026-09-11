# ─────────────────────────────────────────────────────────────────────────────
# The P2Pool observer KAT.
#
# ONE registered target, deliberately: the component's whole risk surface is a
# parser fed by an unauthenticated peer, and a single translation unit that
# compiles every header together is also the collision fence.
#
# It is OFFLINE. The two goldens are real frames captured from a live mini
# sidechain session and embedded as hex in p2pool_golden_frames.hpp, so the KAT
# needs no network, no daemon and no fixture file -- it runs identically on a
# laptop, on the sanitizer leg and on a machine with no route to the internet.
#
# Links xmr_coin for keccak and the tree hash (through both the sidechain id
# recomputation and the native lane's Monero block identity). No RandomX, no
# boost, no libsodium: a LIGHT link, same tier as the C2a KATs.
#
# DRIFT-GUARD: this directory is outside the coin-test allowlist glob, so the
# target below is also in BOTH `--target` lists in .github/workflows/build.yml.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING)
    add_executable(xmr_p2pool_parse_kat p2pool_parse_kat.cpp)
    target_include_directories(xmr_p2pool_parse_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_p2pool_parse_kat PRIVATE xmr_coin)
    target_compile_features(xmr_p2pool_parse_kat PRIVATE cxx_std_20)
    add_test(NAME xmr_p2pool_parse_kat COMMAND xmr_p2pool_parse_kat)
endif()
