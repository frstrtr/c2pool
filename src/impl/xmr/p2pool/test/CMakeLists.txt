# ─────────────────────────────────────────────────────────────────────────────
# The P2Pool KATs. Three registered targets, split along the two lines that
# matter here: what the PARSER does with bytes off a hostile wire, what the
# DISPLAY does with numbers out of the read model, and what the DISK does with
# the display's numbers when the process is killed.
#
#   xmr_p2pool_parse_kat    the component's risk surface -- a parser fed by an
#                           unauthenticated peer -- pinned against two real
#                           captured frames. One translation unit that compiles
#                           every header together, which is also the collision
#                           fence.
#   xmr_p2pool_monitor_kat  the monitor's frame, pinned against a golden
#                           rendered from three fixed read models, plus the
#                           emitted message-id set re-asserted for the second
#                           live binary, plus the absence-vs-zero rules (a dead
#                           chain renders `--`, never a zero), the seven-state
#                           liveness ladder, and the state-file codec round trip.
#                           It includes NO socket header and makes no syscall, so
#                           the layout is checked without a network stack -- and
#                           nothing about a dashboard can drift unseen.
#   xmr_p2pool_persist_kat  the durability claim, which is operational and cannot
#                           be made by a string round trip: it FORKS a child,
#                           has it save a state, kills it with SIGKILL, and
#                           reads every number back in the parent. Plus the
#                           lock (a second monitor must not clobber the live
#                           writer's file), the no-HOME refusal, and the journal
#                           rotation. UNIX-gated; writes only inside a mkdtemp()
#                           directory it removes again.
#
# ALL THREE ARE OFFLINE. The parser goldens are real frames captured from a live
# mini session and embedded as hex; the monitor golden is the frame its own
# fixture produces (regenerate with `xmr_p2pool_monitor_kat --emit-golden`).
# None of them needs a network, a daemon, a fixture file or a terminal: they run
# identically on a laptop, on the sanitizer leg and on a machine with no route
# out.
#
# All three link xmr_coin for keccak and the tree hash. No RandomX, no boost, no
# libsodium, no ncurses: a LIGHT link, same tier as the C2a KATs. The state file
# is JSON written by about forty lines of string building and read back through
# the repository's existing header-only minijson -- deliberately not a new
# dependency.
#
# DRIFT-GUARD: this directory is outside the coin-test allowlist glob, so all
# three targets below are also in BOTH `--target` lists in
# .github/workflows/build.yml. A target registered with add_test but never built
# reports "***Not Run" and exits non-zero -- the #1539 lesson.
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

    # The durability half. UNIX-gated because it is the one KAT here that is
    # about syscalls: mkdir / rename / flock / fork / SIGKILL.
    if (UNIX)
        add_executable(xmr_p2pool_persist_kat p2pool_persist_kat.cpp)
        target_include_directories(xmr_p2pool_persist_kat PRIVATE ${CMAKE_SOURCE_DIR}/src)
        target_link_libraries(xmr_p2pool_persist_kat PRIVATE xmr_coin)
        target_compile_features(xmr_p2pool_persist_kat PRIVATE cxx_std_20)
        add_test(NAME xmr_p2pool_persist_kat COMMAND xmr_p2pool_persist_kat)
    endif()
endif()
