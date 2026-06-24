# Enhanced C2Pool Components

# Hashrate Tracker Library
add_library(c2pool_hashrate OBJECT
    hashrate/tracker.cpp
)
target_include_directories(c2pool_hashrate PUBLIC .)
target_link_libraries(c2pool_hashrate
    yaml-cpp::yaml-cpp
    btclibs
    nlohmann_json::nlohmann_json
    # lib does not link core (SCC break); carry Boost.Log explicitly so ld64 resolves
    # it on AppleClang arm64 (same carry pattern as c2pool_storage/c2pool_payout, #22/#39).
    Boost::log
    Boost::log_setup
)
target_include_directories(c2pool_hashrate PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Difficulty Adjustment Engine Library  
add_library(c2pool_difficulty
    difficulty/adjustment_engine.cpp
)
target_include_directories(c2pool_difficulty PUBLIC .)
target_link_libraries(c2pool_difficulty
    yaml-cpp::yaml-cpp
    btclibs
    nlohmann_json::nlohmann_json
    # lib does not link core (SCC break); carry Boost.Log explicitly so ld64 resolves
    # it on AppleClang arm64 (same carry pattern as c2pool_storage/c2pool_payout, #22/#39).
    Boost::log
    Boost::log_setup
)
# Stays STATIC (one-way into core, outside the SCC); drop the core link edge so its
# archive does not absorb core OBJECT files (would duplicate at the final link).
target_include_directories(c2pool_difficulty PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Storage Manager Library
add_library(c2pool_storage OBJECT
    storage/sharechain_storage.cpp
)
target_include_directories(c2pool_storage PUBLIC .)
target_link_libraries(c2pool_storage
    yaml-cpp::yaml-cpp
    btclibs
    # storage/sharechain_storage.cpp pulls core/leveldb_store.hpp -> <leveldb/db.h>.
    # This OBJECT lib deliberately does not link core (SCC break), so it must carry
    # the leveldb usage requirement itself. On Conan/MSVC the include dir propagates
    # only via the leveldb::leveldb imported target; without this, Windows fails
    # C1083 leveldb/db.h (Linux happens to find it on the default system path).
    ${LEVELDB_LIBRARIES}
    # sharechain_storage.cpp uses <core/log.hpp> (LOG_* -> Boost.Log trivial). OBJECT
    # lib does not link core (SCC break); carry Boost.Log explicitly so ld64 resolves
    # it on AppleClang arm64 (same carry pattern as c2pool_payout/c2pool_merged_mining,
    # #22/#39).
    Boost::log
    Boost::log_setup
)
target_include_directories(c2pool_storage PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Merged Mining Manager Library (integrated mm-adapter)
add_library(c2pool_merged_mining OBJECT
    merged/merged_mining.cpp
)
target_include_directories(c2pool_merged_mining PUBLIC .)
target_link_libraries(c2pool_merged_mining
    yaml-cpp::yaml-cpp
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    # merged_mining.cpp uses <core/log.hpp> (LOG_* -> Boost.Log trivial). OBJECT lib
    # does not link core (SCC break); carry Boost.Log explicitly so ld64 resolves it
    # on AppleClang arm64 (same fix class as c2pool_storage/leveldb, #22/#39).
    Boost::log
    Boost::log_setup
)
target_include_directories(c2pool_merged_mining PRIVATE ${CMAKE_SOURCE_DIR}/src)

# Enhanced Node Library (header-only template after M6 decoupling).
# Coin-agnostic; callers that use the LTC alias (enhanced_node.hpp) must link
# `ltc` themselves. Dash callers include impl/dash/enhanced_node.hpp.
add_library(c2pool_node_enhanced INTERFACE)
target_include_directories(c2pool_node_enhanced INTERFACE .)
target_link_libraries(c2pool_node_enhanced INTERFACE
    core
    c2pool_hashrate
    c2pool_difficulty
    c2pool_storage
    nlohmann_json::nlohmann_json
)

# Inject version from git at build time
execute_process(
    COMMAND git describe --tags --always
    WORKING_DIRECTORY ${CMAKE_SOURCE_DIR}
    OUTPUT_VARIABLE C2POOL_GIT_VERSION
    OUTPUT_STRIP_TRAILING_WHITESPACE
    ERROR_QUIET
)
if(NOT C2POOL_GIT_VERSION)
    set(C2POOL_GIT_VERSION "0.1.0-alpha")
endif()
# Strip leading 'v'
string(REGEX REPLACE "^v" "" C2POOL_GIT_VERSION "${C2POOL_GIT_VERSION}")

# Main C2Pool Enhanced Application (refactored with mining_shares/p2p_shares separation)
add_executable(c2pool c2pool_refactored.cpp)
target_compile_definitions(c2pool PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
target_link_libraries(c2pool
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    # OBJECT sets reachable only transitively via ltc (itself OBJECT) do not
    # propagate their objects into the exe link; name them directly (#22/#39).
    c2pool_storage
    ltc_coin
    nmc_coin   # NMC coin-layer: out-of-line Transaction/MutableTransaction ctors for embedded merged-mining (2b-ii)
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
target_link_libraries(c2pool c2pool_hashrate pool)  # OBJECT-lib SCC direct-naming (#22/#39)

# Enhanced version with explicit name (for backward compatibility)
add_executable(c2pool_enhanced c2pool_refactored.cpp)
target_link_libraries(c2pool_enhanced
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    c2pool_storage
    ltc_coin
    nmc_coin   # NMC coin-layer: out-of-line Transaction/MutableTransaction ctors for embedded merged-mining (2b-ii)
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
target_link_libraries(c2pool_enhanced c2pool_hashrate pool)  # OBJECT-lib SCC direct-naming (#22/#39)

# c2pool-btc: BTC SPV embedded p2pool — Phase B0 scaffold (stub entry).
# Library `btc` is a clone of `ltc` with namespace renamed and CMake targets
# adjusted; real entry-point port is in later B-phases.
# Links `ltc` transitively because core/web_server.cpp references LTC symbols
# (see comment at the bottom of this file). Untangling that is out of B0 scope.
add_executable(c2pool-btc main_btc.cpp)
target_compile_definitions(c2pool-btc PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
target_link_libraries(c2pool-btc
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    ltc_coin  # ltc OBJECT lib pulls in protocol handlers needing ltc::coin::{Mutable,}Transaction ctors
    btc
    btc_stratum
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# c2pool-dgb: DigiByte Scrypt-only (V36) — slice #4 minimal COMPILING SKELETON.
# Mirrors the c2pool-btc add_executable shape, pruned to a stub entry. The body
# (embedded daemon + pool pillars) is M3/Phase B; this target only proves the
# binary builds + links off master. It compiles impl/dgb/node.cpp directly
# rather than linking a dgb / dgb_coin / impl_dgb lib on purpose: the top-level
# OBJECT-lib registration of src/impl/dgb is ci-steward's convention PR and is
# intentionally NOT raced here. The skeleton reads only header constexpr
# constants from impl/dgb/config_{coin,pool}.hpp; those headers #include
# core/netaddress.hpp, which #includes <yaml-cpp/yaml.h>. So the target needs
# yaml-cpp's INCLUDE DIR to compile — but NOT core's symbols: it never
# instantiates the Fileconfig-derived configs nor calls any core function.
# Linking the `core` library instead would drag in core/web_server.o +
# stratum_server.o, which reference merged/payout/hashrate/ltc symbols (the
# self-link tangle that forces c2pool-btc to drag in ltc/payout/merged) and
# would pull Phase B forward. We therefore add ONLY yaml-cpp (header path).
# EXE-WIRE slice: main_dgb.cpp drives the LIVE header-only chain-score path
# (dgb::ShareTracker::score, #132/#134) + make_coin_params; it never constructs
# the abstract dgb::NodeImpl, so node.cpp (the run-loop TU that references core
# web_server/stratum -> payout/merged/hashrate/ltc, i.e. the Phase B self-link
# tangle AND merged-mining = DOGE aux, which is NOT in the V36 default DGB
# build) is intentionally NOT compiled in. core is an OBJECT lib (links ALL its
# objects unconditionally, incl. web_server/stratum), so linking it forces that
# whole tangle; we therefore do NOT link core. We compile ONLY core/uint256.cpp
# directly (base_uint symbols the header-only ScoreT/hashrate-hex path needs) -
# additive, no other target touched - and link nothing beyond yaml-cpp(header)/
# json/Boost. Per-coin isolation held. The embedded run-loop (NodeBridge over
# digibyted P2P + Stratum) and its pool-runtime link land in a later Phase B
# slice.
# RUN-LOOP slice (#82): main_dgb.cpp --run now constructs dgb::Config + the
# dgb::Node sharechain peer (pool::NodeBridge<NodeImpl,...>) and binds its P2P
# listener, so the exe must link the real dgb pool runtime — not just the
# header-only score path. We link the `dgb` OBJECT lib (node.cpp + protocol
# handlers) and the shared core/pool/sharechain/storage base it sits on,
# mirroring the c2pool-btc link set. c2pool_merged_mining is pulled for SYMBOL
# RESOLUTION of the core web_server/stratum tangle ONLY (same reason c2pool-btc
# links it) — it does NOT enable -DAUX_DOGE; DGB default build stays standalone
# (no DOGE aux). core provides core/uint256.cpp, so the explicit source is
# dropped to avoid a duplicate-symbol link. Per-coin isolation holds: only the
# c2pool-dgb target stanza changes.
add_executable(c2pool-dgb main_dgb.cpp)
target_compile_definitions(c2pool-dgb PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
target_link_libraries(c2pool-dgb
    c2pool_payout
    c2pool_merged_mining  # symbol resolution for core web_server tangle (NOT -DAUX_DOGE)
    c2pool_hashrate
    core
    dgb        # DGB pool-layer OBJECT lib: node.cpp NodeImpl + protocol handlers
    dgb_coin   # DGB coin-layer: embedded P2P + mempool + transaction ctors
    dgb_stratum  # DGB miner-facing IWorkSource (DGBWorkSource) — #82 stratum standup
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
# c2pool-bch: Bitcoin Cash (SHA256d standalone parent, V36) — EXE-WIRE slice.
# Closes the "no runnable c2pool-bch entrypoint" gap (integrator 2026-06-18):
# the M5 lane was pure state-machine + ctest with no main_bch.cpp. Mirrors the
# c2pool-dgb add_executable shape but is even leaner: main_bch.cpp drives the
# LIVE header-only ABLA template-budget path (impl/bch/coin/abla.hpp, 1:1 BCHN
# consensus/abla.cpp port). abla.hpp is std-only (no core/yaml/uint256/leveldb),
# so this target links NOTHING beyond the standard runtime — it never drags in
# the core OBJECT-lib web_server/stratum tangle that forces c2pool-btc to pull
# ltc/payout/merged. The global src/ include path resolves <impl/bch/...>. The
# P2P IBD run-loop (coin/p2p_node.cpp read-only sync vs VM300 .110:8333) and its
# live numbers are the NEXT --ibd slice; kept separate so this lands additive.
# Per-coin isolation held: src/impl/bch only, no shared-base/core edits.
add_executable(c2pool-bch
    main_bch.cpp
    # BCH coin impl TUs (M3 deferred impl_bch reg, now forced by --ibd harness
    # needing to LINK bch:: symbols). Compiled directly into the target, exactly
    # as the bch tests add coin/transaction.cpp; per-coin isolation holds.
    ${CMAKE_SOURCE_DIR}/src/impl/bch/config_coin.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/config_pool.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/transaction.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_connection.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/p2p_node.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/coin_node.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/coin/rpc.cpp
)
target_compile_definitions(c2pool-bch PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
# --ibd RUN-LOOP slice (integrator 2026-06-18): the read-only headers-first IBD
# harness stands up EmbeddedDaemon over its P2P front-end (NodeP2P/HeaderChain/
# Timer), which pulls the core OBJECT-lib + Boost.Asio. Adding ONLY these link
# deps (core + btclibs + yaml-cpp + json + Boost), matching the c2pool-dgb tier,
# is SAFE-ADDITIVE on this target (integrator explicitly cleared it): no shared-
# base/core SOURCE edit, src/impl/bch headers only, per-coin isolation held. The
# --selftest path remains the std-only ABLA budget driver. core is an OBJECT lib
# so it links all its objects (incl. web_server/stratum) — those symbols already
# resolve in the full c2pool target; we depend on the same set here.
target_link_libraries(c2pool-bch
    # OBJECT-lib SCC direct-naming (#22/#39): core is monolithic; its stratum_server/
    # web_server objects reference the whole pool/payout/merged/hashrate/storage/
    # difficulty SCC, so every core consumer names the full set. Identical to the
    # bch test link set; merged is the shared core SCC (BCH never invokes it), NOT
    # BCH-specific merged-mining logic -> per-coin isolation holds.
    core pool sharechain
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# c2pool-dash: DASH (X11 standalone parent, older-than-v35 -> V36) — EXE-WIRE
# slice 2 (integrator 2026-06-23, stacked on launcher slice 1 #387). Closes the
# "DASH is impl-files-only, not runnable" gap: slice 1 registered DASH in the
# unified dispatch; this gives DASH its own executable driving the REAL header-
# only consensus path (make_coin_params + X11 PoW + subsidy). Mirrors the
# c2pool-bch --selftest tier: main_dash.cpp + the dash_x11 sph lib; params/
# subsidy/utxo_adapter are header-only. Block submission (won-block dual-path
# broadcaster: dashd-RPC submitblock + embedded P2P relay) is DEFERRED to the
# next stacked slice and is an explicit, labelled --run stub (NOT silent). The
# core OBJECT-lib link set matches c2pool-bch/the dash tests (core monolith SCC
# direct-naming, #22/#39); per-coin isolation held: src/impl/dash only, no
# shared-base/core SOURCE edit, dashd RPC fallback untouched.
add_executable(c2pool-dash main_dash.cpp)
target_compile_definitions(c2pool-dash PRIVATE C2POOL_VERSION="${C2POOL_GIT_VERSION}")
target_link_libraries(c2pool-dash
    core pool sharechain
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    dash_x11   # DASH X11 PoW sph reference (BLAKE->...->ECHO), additive static lib
    dash_rpc   # launcher slice-3: external-dashd-RPC client (submitblock fallback)
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# Windows: Boost.Asio requires Winsock libraries; /bigobj for large translation units
if(WIN32)
    target_link_libraries(c2pool ws2_32 mswsock bcrypt dbghelp)
    target_link_libraries(c2pool_enhanced ws2_32 mswsock bcrypt dbghelp)
endif()
if(MSVC)
    target_compile_options(c2pool PRIVATE /bigobj)
    target_compile_options(c2pool_enhanced PRIVATE /bigobj)
    # Match Linux 8MB stack (MSVC default is 1MB — deep share validation can overflow)
    target_link_options(c2pool PRIVATE /STACK:8388608)
    target_link_options(c2pool_enhanced PRIVATE /STACK:8388608)
endif()

# Test applications
add_executable(test_ltc_node test_ltc_node.cpp)
target_link_libraries(test_ltc_node core ltc)
target_link_libraries(test_ltc_node c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
target_link_libraries(test_ltc_node nlohmann_json::nlohmann_json)

# Legacy applications have been archived to ../../archive/
# - c2pool_legacy.cpp (original c2pool.cpp)
# - c2pool_node_legacy.cpp (original c2pool_node.cpp)
# - c2pool_temp_legacy.cpp (original c2pool_temp.cpp)

add_subdirectory(ltc)
add_subdirectory(payout)

# core/web_server.cpp references symbols from c2pool_payout, c2pool_hashrate and
# c2pool_merged_mining. With OBJECT libraries every consumer pools ALL of core's
# objects (including web_server.o), so those symbols must reach every core consumer.
# Propagate them as INTERFACE deps (consumers pool their objects) with NO back-edge
# into core: the payout/hashrate/merged OBJECT libs no longer link core (header-only
# access via the global src/ include path), keeping the target graph ACYCLIC so CMake
# accepts the non-STATIC SCC. secp256k1 (external) likewise propagated via INTERFACE.
# Source-level dissolution of these core->c2pool deps is deferred to V37.
target_link_libraries(core INTERFACE c2pool_payout c2pool_hashrate c2pool_merged_mining ${SECP256K1_LIBRARIES})