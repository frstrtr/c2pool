# ─────────────────────────────────────────────────────────────────────────────
# P2Pool SIDECHAIN OBSERVER -- strictly read-only.
#
# A client for a FOREIGN network. P2Pool (SChernykh/p2pool) runs its own p2p
# sidechain over TCP, unrelated to Monero levin and unrelated to c2pool's own
# sharechain, and this tree reads it: handshake, peer-list exchange, sidechain
# block messages, and the full PoolBlock parse including the embedded Monero
# block template and the PPLNS share set.
#
# READ-ONLY IS STRUCTURAL, not a flag. p2pool_wire.hpp declares a four-value
# ControlMessage enum and one encoder over it (handshake challenge, handshake
# solution, block request, peer-list request); there is no serialiser for a
# PoolBlock anywhere under p2pool/, no LISTEN_PORT encoder, and therefore no
# code path that can publish, announce or submit. See that file's header for
# why LISTEN_PORT in particular is absent and what it costs.
#
# NOTHING HERE IS A LIBRARY. Every component is header-only STL over two things
# the repository already has: xmr_coin (the vendored Monero keccak and tree
# hash) and the native lane's consensus headers (the bounds-checked BlobReader,
# the Monero block parse and the block identity). The embedded Monero block in
# a sidechain blob is handed to THOSE parsers rather than to a second copy
# written here -- which is the whole reason this component is stacked on M3.
#
# Five targets, all under BUILD_TESTING:
#
#   xmr_p2pool_parse_kat    the deterministic parser KAT over two real captured
#                           frames. REGISTERED with add_test and run in both CI
#                           legs. Offline: the goldens are in the header.
#   xmr_p2pool_monitor_kat  the deterministic RENDER KAT: three fixed read
#                           models drawn to a golden frame in BOTH panel states
#                           (expanded and collapsed), every ASCII widget pinned
#                           on its own, plus the emitted message-id pin
#                           re-asserted for the monitor, the absence-vs-zero
#                           rules and the state-file codec. Also REGISTERED,
#                           also offline -- it includes no socket header, makes
#                           no syscall and needs no terminal.
#   xmr_p2pool_persist_kat  the DURABILITY KAT: forks a child, has it save a
#                           state, kills it with SIGKILL and reads every number
#                           back; plus the directory lock, the no-HOME refusal
#                           and journal rotation. REGISTERED, offline, and the
#                           only KAT here that touches a filesystem.
#   xmr_p2pool_observer     the live single-chain harness. BUILT by CI so it
#                           cannot bit-rot, RUN by nobody in CI, because running
#                           it dials a public network. Registers no ctest test,
#                           so the #1539 Not-Run rule does not apply to it.
#   xmr_p2pool_monitor      the live all-in-one monitor: all three sidechains in
#                           ONE poll() loop behind a fullscreen ANSI/termios
#                           TUI. Same rule as the observer -- BUILT by CI, never
#                           RUN by it (it dials three public networks and the
#                           fullscreen mode wants a tty), and it registers no
#                           ctest test either. What CI runs is the render KAT.
#
# THE TUI HAS NO DEPENDENCIES. It is ANSI escapes plus POSIX termios: no
# ncurses, no boost, no asio, no threads. The renderer itself
# (p2pool_tui.hpp) is pure STL and deliberately POSIX-free, which is what lets
# the KAT pin a whole frame without linking a socket layer.
#
# DRIFT-GUARD: tools/ci/check_test_target_allowlist.py audits
# src/impl/<coin>/test/CMakeLists.txt; this tree sits one level deeper
# (src/impl/xmr/p2pool/test/) and is outside that glob, so ALL FIVE targets are
# added to BOTH `--target` lists in .github/workflows/build.yml by hand. A
# target registered with add_test but never built reports "***Not Run" and
# exits non-zero -- the #1539 lesson.
#
# SCOPE FENCE: everything under src/impl/xmr/. Zero files under src/sharechain/.
# ─────────────────────────────────────────────────────────────────────────────

if (BUILD_TESTING AND UNIX)
    # The live harnesses. POSIX sockets only: no asio, no threads, no boost,
    # and for the monitor's full-screen mode, no ncurses either.
    add_executable(xmr_p2pool_observer tools/p2pool_observer_main.cpp)
    target_include_directories(xmr_p2pool_observer PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_p2pool_observer PRIVATE xmr_coin)
    target_compile_features(xmr_p2pool_observer PRIVATE cxx_std_20)

    add_executable(xmr_p2pool_monitor tools/p2pool_monitor_main.cpp)
    target_include_directories(xmr_p2pool_monitor PRIVATE ${CMAKE_SOURCE_DIR}/src)
    target_link_libraries(xmr_p2pool_monitor PRIVATE xmr_coin)
    target_compile_features(xmr_p2pool_monitor PRIVATE cxx_std_20)
endif()

if (BUILD_TESTING)
    add_subdirectory(test)
endif()
