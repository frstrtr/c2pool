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

# Inject version from git at BUILD time (was configure time). --dirty so a
# tag-exact but locally-modified rebuild does not share a version string with
# the clean tag build (the embedded oracle-shadow ledger keys its clean streak
# on this — a dirty dev build must not inherit a tag-exact binary's graduation
# streak).
#
# The old execute_process() ran `git describe` only when CMake reconfigured, so
# an incremental rebuild in a build dir configured at an older commit baked that
# stale hash into the binary (deployed dgb/bch reported de025c6f while built
# from ff3707c0 sources). Instead an always-out-of-date custom target regenerates
# a header on every build; copy_if_different keeps its mtime stable when the
# version is unchanged, so a no-op rebuild does not relink. Each c2pool-* target
# depends on this target and gets the generated header on its include path; the
# five mains + bch/pool_entrypoint.hpp include it under an __has_include guard,
# so their existing `#ifdef C2POOL_VERSION` blocks work unchanged.
set(C2POOL_VERSION_HEADER_DIR ${CMAKE_CURRENT_BINARY_DIR}/generated)
add_custom_target(c2pool_version_header
    COMMAND ${CMAKE_COMMAND}
            -DSRC_DIR=${CMAKE_SOURCE_DIR}
            -DOUT_FILE=${C2POOL_VERSION_HEADER_DIR}/c2pool_build_version.h
            -P ${CMAKE_SOURCE_DIR}/cmake/GenerateVersionHeader.cmake
    BYPRODUCTS ${C2POOL_VERSION_HEADER_DIR}/c2pool_build_version.h
    COMMENT "Generating c2pool_build_version.h (git describe, build-time)"
    VERBATIM
)
# Helper: wire a c2pool-* executable to the build-time version header.
function(c2pool_wire_version _tgt)
    add_dependencies(${_tgt} c2pool_version_header)
    target_include_directories(${_tgt} PRIVATE ${C2POOL_VERSION_HEADER_DIR})
endfunction()

# Main C2Pool Enhanced Application (refactored with mining_shares/p2p_shares separation)
add_executable(c2pool main_ltc.cpp)
c2pool_wire_version(c2pool)
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
add_executable(c2pool_enhanced main_ltc.cpp)
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

# c2pool-ltc: LTC (+ embedded DOGE aux merged-mining) reference entrypoint.
# The coin-matrix / release presence gate keys on src/c2pool/main_ltc.cpp
# (see PR #66); this target packages the LTC binary as c2pool-ltc. LTC is the
# reference coin, so this mirrors the c2pool_enhanced link set exactly (c2pool
# and c2pool_enhanced already build the same LTC-native main). DOGE aux rides
# via c2pool_merged_mining -- always compiled in, NO -DAUX_DOGE flag.
add_executable(c2pool-ltc main_ltc.cpp)
c2pool_wire_version(c2pool-ltc)
target_link_libraries(c2pool-ltc
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
target_link_libraries(c2pool-ltc c2pool_hashrate pool)  # OBJECT-lib SCC direct-naming (#22/#39)

# c2pool-btc: BTC SPV embedded p2pool — Phase B0 scaffold (stub entry).
# Library `btc` is a clone of `ltc` with namespace renamed and CMake targets
# adjusted; real entry-point port is in later B-phases.
# Links `ltc` transitively because core/web_server.cpp references LTC symbols
# (see comment at the bottom of this file). Untangling that is out of B0 scope.
add_executable(c2pool-btc main_btc.cpp)
c2pool_wire_version(c2pool-btc)
target_link_libraries(c2pool-btc
    c2pool_node_enhanced
    c2pool_payout
    c2pool_merged_mining
    core
    ltc
    ltc_coin  # ltc OBJECT lib pulls in protocol handlers needing ltc::coin::{Mutable,}Transaction ctors
    btc
    btc_stratum
    nmc_coin   # NMC coin-layer: embedded merged-mining (2b-ii) — supplies nmc::coin Transaction/MutableTransaction ctors for the aux commitment path wired into main_btc
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
c2pool_wire_version(c2pool-dgb)
# ── SLICE 2: arm --merged DOGE (DGB-as-DOGE-parent embedded merged mining) ──────
# AUX_DOGE ON for THIS TARGET ONLY (target_compile_definitions, not the global
# option() which would leak the macro across every coin lane and break per-coin
# isolation). It compiles in main_dgb.cpp's #ifdef AUX_DOGE arm — the embedded
# DOGE aux backend standup (mm_manager + doge::coin::AuxChainEmbedded PRIMARY +
# CoinBroadcaster header sync) that feeds the #1413 DGBWorkSource coinbase-commit
# seams. The dgb OBJECT libs stay compiled without the macro (main_dgb never
# ODR-uses node.hpp::bind_aux_doge_parsers), so only this TU changes. ltc_coin is
# added because the shared src/impl/doge aux module (header-only) is templated on
# ltc::coin types (Mempool/Transaction/BlockHeaderType/parse_doge_*) whose
# out-of-line defs live there; CoinBroadcaster/MergedMiningManager/AuxChainRPC
# already resolve via c2pool_merged_mining (linked above). No shared-base edit;
# only the c2pool-dgb stanza changes.
target_compile_definitions(c2pool-dgb PRIVATE AUX_DOGE)
target_link_libraries(c2pool-dgb
    c2pool_payout
    c2pool_merged_mining  # MergedMiningManager / CoinBroadcaster / AuxChainRPC (+ core web_server tangle)
    c2pool_hashrate
    core
    dgb        # DGB pool-layer OBJECT lib: node.cpp NodeImpl + protocol handlers
    dgb_coin   # DGB coin-layer: embedded P2P + mempool + transaction ctors
    dgb_stratum  # DGB miner-facing IWorkSource (DGBWorkSource) — #82 stratum standup
    ltc_coin   # SLICE 2: DOGE aux backend reuses ltc::coin Mempool/Transaction/parse (embedded DOGE-on-DGB)
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
    # M5 pool-node body TUs: NodeImpl out-of-line methods (node.cpp) + the two
    # p2pool p2p protocol dispatchers (Legacy/Actual handle_message_* family) +
    # the stratum work source. These define the previously-undefined NodeImpl::
    # and protocol symbols so the --pool path LINKS. Per-coin isolation holds
    # (src/impl/bch only); compiled directly into the target like the coin TUs.
    ${CMAKE_SOURCE_DIR}/src/impl/bch/node.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/protocol_actual.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/protocol_legacy.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bch/stratum/work_source.cpp
)
c2pool_wire_version(c2pool-bch)
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
c2pool_wire_version(c2pool-dash)
target_link_libraries(c2pool-dash
    core pool sharechain
    c2pool_node_enhanced  # dash-dashboard: header-only EnhancedC2PoolNodeT (impl/dash/enhanced_node.hpp)
                          # -> the core::IMiningNode core::WebServer takes. INTERFACE lib; its deps
                          # (core / c2pool_hashrate / c2pool_difficulty / c2pool_storage) are already listed.
    dash       # S8-p2p: sharechain pool-node OBJECT lib (NodeImpl + Legacy/Actual dispatch, node.cpp)
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    dash_x11   # DASH X11 PoW sph reference (BLAKE->...->ECHO), additive static lib
    dash_rpc   # launcher slice-3: external-dashd-RPC client (submitblock fallback)
    dash_stratum  # S8: DASHWorkSource IWorkSource bodies (stratum accept-loop caller)
    dash_block_replay  # E1: coin/vendor/blockencodings.cpp — the coin-network P2P Handler
                       # (cmpctblock codec) the opt-in CoinClient instantiates ODR-uses
                       # CBlockHeaderAndShortTxIDs::FillShortTxIDSelector()
    dash_bls_verify    # E1 Phase-L: real type-6 quorum-commitment BLS verify
                       # (make_commitment_bls_verifier -> set_bls_verify_fn seam).
                       # R3: also verify_govvote_operator_sig (governance-vote BLS
                       # operator-key verify, daemonless superblock serving).
                       # Carries the C2POOL_DASH_BLS define + dashbls libs PUBLIC
                       # when the backend was found; fail-closed stub otherwise.
    dash_scriptcheck   # PR-C4: consensus-exact CheckInputScripts over the C1 fold
                       # view (dashcore interpreter vendored as a hidden-visibility
                       # .so exporting only the c2pool_dash_* C API;
                       # --embedded-fold-checkscripts, default-OFF => dormant).
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)

# c2pool-bip110: Bitcoin Knots BLAKE2b hard fork (BIP-110) — M1 EMBEDDED lane.
# BIP-110 swaps Bitcoin's SHA256d PoW for the BLAKE2b commitment pipeline
# (src/impl/bip110/pow.hpp) at Blake2bHeight=961640 and caps block weight (RDTS).
# M1 is the daemonless SPV header-follower: main_bip110.cpp --run --coin-p2p-
# discover dials NODE_BLAKE2B (bit 28) peers, downloads v2 headers, and follows
# the BLAKE2b fork chain past 961640 (NO Knots/bitcoind daemon), exactly as
# btc.voidbind runs embedded today. --selftest keeps the live BLAKE2b KAT arm.
# It links the bip110_coin SPV lane (cloned from btc/coin) on top of the shared
# core/pool/sharechain base — the same core OBJECT-lib web_server/stratum symbol
# tangle that forces c2pool-btc to pull ltc/payout/merged is resolved by
# mirroring that link set (documented risk; isolation is held by the per-binary
# __C2POOL_COIN_BIP110__ define, NOT the link closure). blake2b.c is compiled
# into the exe (pow.hpp inline callers resolve bip110_blake2b at final link);
# core provides uint256.cpp so it is NOT compiled a second time here. No shared-
# base/core SOURCE edit; no other lane touched; per-coin isolation holds. Mining
# (164-byte template assembly / Knots-GBT backend) is M2+, untouched here.
add_executable(c2pool-bip110
    main_bip110.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/stratum/work_source.cpp
    # M3 sharechain MINT lane (behind --bip110-sharechain; default OFF): the
    # namespace-copied sharechain node + single-protocol v36-genesis bridge +
    # c2pool protocol handler. main_bip110 references bip110::pool::Node (ctor,
    # listen, broadcast_share, notify_local_share, register_template_txs,
    # start_outbound_connections) which are DEFINED in these TUs — same set the
    # bip110_pool_node_compile KAT links. Dormant unless the flag is passed.
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/pool/node.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/pool/protocol_actual.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
)
c2pool_wire_version(c2pool-bip110)
target_compile_definitions(c2pool-bip110 PRIVATE
    __C2POOL_COIN_BIP110__=1
)
target_link_libraries(c2pool-bip110
    bip110_coin
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    core
    ltc
    ltc_coin
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
    ${SECP256K1_LIBRARIES}
    Threads::Threads
)

# Dashboard assets: the shared coin-generic WebServer serves the web-static/
# frontend from a CWD-relative "web-static" dir (core::WebServer::set_dashboard_dir,
# same convention btc/dgb/dash use — no lane compiles it into the binary). On the
# fleet the DEPLOY pairs a web-static copied from this commit next to the binary;
# for LOCAL runs / curl verification, mirror the repo's web-static next to the
# built c2pool-bip110 so "/" resolves to the HTML dashboard from the build dir.
# c2pool-bip110-scoped, additive, build-only — touches no other lane.
add_custom_command(TARGET c2pool-bip110 POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E copy_directory
        ${CMAKE_SOURCE_DIR}/web-static
        $<TARGET_FILE_DIR:c2pool-bip110>/web-static
    COMMENT "c2pool-bip110: staging web-static dashboard assets next to the binary"
)

# bip110_blake2b_kat: the KILLER known-answer test for the BIP-110 lane.
#   (A) BLAKE2b primitive vs the RFC 7693 vector; (B) the full BIP-110 block-
#   hash pipeline reproduces the CANONICAL block hash of two REAL BIP-110 chain
#   blocks (961640, 963396) byte-for-byte and 961640 satisfies its nBits.
# Same lean, isolated link set as c2pool-bip110.
add_executable(bip110_blake2b_kat
    bip110_blake2b_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
    ${CMAKE_SOURCE_DIR}/src/core/uint256.cpp
)
target_compile_definitions(bip110_blake2b_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_blake2b_kat
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME bip110_blake2b_kat COMMAND bip110_blake2b_kat)

# bip110_m2_workshape_kat: the KILLER KAT for BIP-110 M2 mining.
#   (A) the Stratum-v1 BLAKE2b work-shape (pseudoheader.hpp SSOT) reproduces the
#       CANONICAL block hash of live fork block 961640 via the 80-byte profile-0
#       buffer (wire coinb1 h2 + extranonce); (B) a coinbase-only job is built,
#       CPU-ground to a trivial local target, submitted, and the reassembled
#       164-byte v2 header || varint || coinbase re-hashes to the SAME PoW ==
#       byte-exact serialization (the submit-roundtrip proof; R2 nonce split +
#       R10 zero-flags pinned). Same lean, isolated link set as the M1 KAT.
add_executable(bip110_m2_workshape_kat
    bip110_m2_workshape_kat.cpp
    ${CMAKE_SOURCE_DIR}/src/impl/bip110/crypto/blake2b.c
    ${CMAKE_SOURCE_DIR}/src/core/uint256.cpp
)
target_compile_definitions(bip110_m2_workshape_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_m2_workshape_kat
    btclibs
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME bip110_m2_workshape_kat COMMAND bip110_m2_workshape_kat)

# bip110_m3_serving_kat: the KILLER KAT for BIP-110 M3 daemonless mempool
# tx-serving. Network-free reward-safety proof over block_assembler.hpp +
# template_builder.hpp: CPFP package selection with topological parent-before-
# child ordering, fail-closed exclusion of an unpriced-parent child and an
# over-weight tx, coinbasevalue == subsidy + Σ(fees) to the satoshi, and the
# txid-merkle / witness-commitment SSOT. A failure is a money-path defect.
add_executable(bip110_m3_serving_kat
    bip110_m3_serving_kat.cpp
)
target_compile_definitions(bip110_m3_serving_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_m3_serving_kat
    bip110_coin
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    core
    ltc
    ltc_coin
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME bip110_m3_serving_kat COMMAND bip110_m3_serving_kat)

# bip110_broadcaster_kat: M3 PR-C2 addrman-backed FOUND-BLOCK fan-out. Network-
# free red/green over coin/broadcaster.hpp + broadcaster_full.hpp: discover
# dedupe/cap/primary-exclude, prune_dead + backoff, submit_block_raw_all fans to
# every live slot, and the dual-arm on_block_found verdict (ARM A embedded fan-
# out + ARM B primary relay; reached_network iff >=1 arm placed the block). The
# money property: a won block reaches the whole reachable NODE_BLAKE2B set, not a
# single submit, and never silently drops when both arms fail.
add_executable(bip110_broadcaster_kat
    bip110_broadcaster_kat.cpp
)
target_compile_definitions(bip110_broadcaster_kat PRIVATE __C2POOL_COIN_BIP110__=1)
target_link_libraries(bip110_broadcaster_kat
    bip110_coin
    c2pool_payout
    c2pool_merged_mining
    c2pool_hashrate
    core
    pool
    sharechain
    c2pool_storage
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME bip110_broadcaster_kat COMMAND bip110_broadcaster_kat)

# KAT: pre-anchor header-backfill PARALLEL GETHEADERS WINDOW (extends #1263 /
# task #151; base PR #1278). Drives the real BulkFetchLane header lane against a
# scripted peer set: RED (window=1, no disconnect) serializes/wedges on a silent
# peer; GREEN (window=N + event refill + disconnect-and-redial) completes. Links
# the same DASH library set as c2pool-dash (header lane pulls block_producer /
# header_chain / x11 / block-replay; BLS carried for the shared object graph).
add_executable(dash_hdr_backfill_window_kat dash_hdr_backfill_window_kat.cpp)
target_link_libraries(dash_hdr_backfill_window_kat
    core pool sharechain
    c2pool_node_enhanced
    dash
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    dash_x11
    dash_rpc
    dash_stratum
    dash_block_replay
    dash_bls_verify
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME dash_hdr_backfill_window_kat COMMAND dash_hdr_backfill_window_kat)

# #154 daemonless bulk-fetch dashd-parity KAT (LEVER 1 protected-local primary
# stays bulk-eligible; LEVER 2 throughput-weighted per-peer inflight) is NOT a
# standalone target here: it was folded into the already-allowlisted
# test/test_dash_p2p_node gtest target as test_dash_bulk_local_primary_kat.cpp
# so CI's "Build tests" --target list actually compiles+runs it. A standalone
# executable was never in the allowlist and became a NOT_BUILT/"Not Run" CTest
# sentinel that red the suite (the #769 unregistered-KAT class).
# KAT: DASHD-FREE self-validated own-set tx serving (successor to #1318). Pure
# red/green over two header-only units with NO node and NO daemon: the
# mempool-validity classifier (Window-1 dashd-ahead propagation -> demoted to
# measurement, does not reset the clean run) and the serve-time internal-
# consistency referee (own-state self-validation: coinbase fee-exact, no
# intra-set double-spend, fee_fold_proven) that decides own-set serving with
# ZERO dashd calls. Links the same DASH library set as c2pool-dash.
add_executable(dash_tx_serve_self_validation_kat dash_tx_serve_self_validation_kat.cpp)
target_link_libraries(dash_tx_serve_self_validation_kat
    core pool sharechain
    c2pool_node_enhanced
    dash
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    dash_x11
    dash_rpc
    dash_stratum
    dash_block_replay
    dash_bls_verify
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME dash_tx_serve_self_validation_kat COMMAND dash_tx_serve_self_validation_kat)

# dash_explorer_json_kat — KAT for the read-only /api/explorer getblock body
# decode (dash::coin::block_to_explorer_json): DIP4 CbTx type/extraPayload +
# masternode-payee X-address + txid. Decode-only, no node/network.
add_executable(dash_explorer_json_kat dash_explorer_json_kat.cpp)
target_link_libraries(dash_explorer_json_kat
    core pool sharechain
    c2pool_node_enhanced
    dash
    c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage c2pool_difficulty
    dash_x11
    dash_rpc
    dash_stratum
    dash_block_replay
    dash_bls_verify
    btclibs
    yaml-cpp::yaml-cpp
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
add_test(NAME dash_explorer_json_kat COMMAND dash_explorer_json_kat)

# ---- Control-plane M0: money-gate KAT (Qt-free sibling of test_reward_safe_launch)
# The settings-file loader + param catalog are self-contained (stdlib only), so
# this test compiles them directly rather than dragging the full core object lib
# (and its boost/zmq/leveldb deps) into a config-only unit test.
add_executable(test_reward_safe_file
    test_reward_safe_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/settings_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/param_catalog.cpp)
target_include_directories(test_reward_safe_file PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/../core)
add_test(NAME test_reward_safe_file COMMAND test_reward_safe_file)

# ---- Control-plane M0b: catalog-driven CLI scanner unit test. Same config-only
# link shape as test_reward_safe_file (core settings TUs compiled directly, no
# boost/zmq/leveldb). Kills the tracker-under-mark precedence risk mechanically:
# iterates every catalog alias of every binary and asserts scan_cli marks it.
add_executable(test_settings_cli_scan
    test_settings_cli_scan.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/settings_cli.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/settings_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/param_catalog.cpp)
target_include_directories(test_settings_cli_scan PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/..)
add_test(NAME test_settings_cli_scan COMMAND test_settings_cli_scan)

# ---- Control-plane M1 (SAFE half): config-endpoint KAT. Same config-only link
# shape (settings + catalog + config_endpoint TUs compiled directly, only
# nlohmann_json added for the JSON serializers). Exercises resolved_config_json,
# catalog_schema_json, and the DORMANT validate_apply_batch oracle, plus the
# cross-check that the core referee invariant agrees with the DASH
# resolve_good_citizen_tx_serve resolver (pure/inline header -> no impl link).
add_executable(test_config_endpoint
    test_config_endpoint.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/config_endpoint.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/settings_file.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/../core/param_catalog.cpp)
target_include_directories(test_config_endpoint PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/.. ${CMAKE_CURRENT_SOURCE_DIR}/../core)
target_link_libraries(test_config_endpoint PRIVATE nlohmann_json::nlohmann_json)
add_test(NAME test_config_endpoint COMMAND test_config_endpoint)

# ---- Control-plane M0b: GOLDEN no-file==today resolved-config gate + the
# unknown-flag and money-gate end-to-end negatives, run against the built
# coin binaries.
#
# The gate is meaningful ONLY where the 5 coin binaries are actually built. The
# sanitizer lane builds the test suite but NOT the coin binaries, so it would
# fail-close here ("no coin binaries -- instrument-validity floor"). Gate the
# ctest REGISTRATION on a build-configuration option instead of on a runtime
# "if file missing then skip": the sanitizer lane configures with
# -DC2POOL_GOLDEN_RESOLVED_CONFIG_GATE=OFF, so the test is cleanly ABSENT there
# (not a fail-close, not a fake pass). Everywhere else it defaults ON, is
# PRESENT, and -- because ci/golden_resolved_config.sh requires ALL 5 coin
# binaries in verify mode -- FAILS if any coin binary is missing or a vector
# diverges. This encodes the leg distinction on target/build presence, never on
# a per-file skip that could vacuously green the release leg.
option(C2POOL_GOLDEN_RESOLVED_CONFIG_GATE
       "Register the golden resolved-config ctest (requires the 5 coin binaries to be built)" ON)
if(UNIX AND C2POOL_GOLDEN_RESOLVED_CONFIG_GATE)
    add_test(NAME golden_resolved_config
             COMMAND ${CMAKE_COMMAND} -E env bash
                     ${CMAKE_SOURCE_DIR}/ci/golden_resolved_config.sh
                     $<TARGET_FILE_DIR:c2pool-dash>)
endif()

# ---- Control-plane M0: catalog-completeness tripwire (anti-drift, runs offline)
# Also wired as a GitHub Actions step so it runs on every PR without a build.
find_package(Python3 COMPONENTS Interpreter QUIET)
if(Python3_Interpreter_FOUND)
    add_test(NAME param_catalog_completeness
             COMMAND ${Python3_EXECUTABLE}
                     ${CMAKE_SOURCE_DIR}/ci/check_param_catalog.py)
endif()

# Windows: Boost.Asio requires Winsock libraries; /bigobj for large translation units
if(WIN32)
    target_link_libraries(c2pool ws2_32 mswsock bcrypt dbghelp)
    target_link_libraries(c2pool_enhanced ws2_32 mswsock bcrypt dbghelp)
    target_link_libraries(c2pool-ltc ws2_32 mswsock bcrypt dbghelp)
endif()
if(MSVC)
    target_compile_options(c2pool PRIVATE /bigobj)
    target_compile_options(c2pool_enhanced PRIVATE /bigobj)
    target_compile_options(c2pool-ltc PRIVATE /bigobj)
    # Match Linux 8MB stack (MSVC default is 1MB — deep share validation can overflow)
    target_link_options(c2pool PRIVATE /STACK:8388608)
    target_link_options(c2pool_enhanced PRIVATE /STACK:8388608)
    target_link_options(c2pool-ltc PRIVATE /STACK:8388608)
endif()

# Test applications
add_executable(test_ltc_node test_ltc_node.cpp)
target_link_libraries(test_ltc_node core ltc)
target_link_libraries(test_ltc_node c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)  # OBJECT-lib SCC direct-naming (#22/#39)
target_link_libraries(test_ltc_node nlohmann_json::nlohmann_json)

# ── KAT: emergency fallback re-arm (docs/coin-peer-manager-rearm.md) ──
add_executable(coin_peer_rearm_kat coin_peer_rearm_kat.cpp)
target_link_libraries(coin_peer_rearm_kat core ltc)
target_link_libraries(coin_peer_rearm_kat c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)
target_link_libraries(coin_peer_rearm_kat nlohmann_json::nlohmann_json)
add_test(NAME coin_peer_rearm_kat COMMAND coin_peer_rearm_kat)

# ── KAT: PR-0 ARRIVAL INSTRUMENTATION schema (dashd-cut coin-P2P foundation) ──
# Locks the OffEmbeddedWindow arrival/fold split invariant
# (arrival_ms + fold_ms == window_ms) and the per-peer per-datum-class
# DeliveryLatencyEwma update. arrival_timing.hpp is pure policy (header-only, no
# node, no daemon, standard library only), so this target links NOTHING and
# still exercises the schema the stacked coin-P2P PRs consume. Built under
# -DC2POOL_DASH_BLS=ON like the rest of the dash suite; it carries no BLS symbols.
add_executable(dash_arrival_instrumentation_kat dash_arrival_instrumentation_kat.cpp)
add_test(NAME dash_arrival_instrumentation_kat COMMAND dash_arrival_instrumentation_kat)

# -- KAT: PR-1 LATENCY-AWARE PEER SCORING (dashd-cut coin-P2P stack) --
# Exercises the REAL dash::coin::DashPeerInfo::compute_score(): flag OFF is
# byte-identical to master (latency term == 0), flag ON adds a bounded/clamped
# tie-breaker so the faster deliverer ranks up. coin_peer_manager.hpp is a
# header-only dash coin leaf; it needs the core lib for NetService + the JSON
# header it includes. Built under -DC2POOL_DASH_BLS=ON; carries no BLS symbols.
add_executable(dash_latency_scoring_kat dash_latency_scoring_kat.cpp)
target_link_libraries(dash_latency_scoring_kat core ltc c2pool_payout c2pool_merged_mining c2pool_hashrate c2pool_storage ltc_coin pool)
target_link_libraries(dash_latency_scoring_kat nlohmann_json::nlohmann_json)
add_test(NAME dash_latency_scoring_kat COMMAND dash_latency_scoring_kat)
# ── KAT: PR-2 RACE THE FRESHEST DATUM (dashd-cut coin-P2P stack) ──
# Locks (1) select_race_targets() naming the K fastest-scored CanServeBlocks
# peers in DISTINCT netgroups (width<=1 == single carrier == today), and
# (2) FreshDatumRaceInflight first-VALID-wins + single-flight dedup: the fold
# self-check is licensed EXACTLY ONCE, duplicate racer copies are dropped, an
# invalid copy with a sibling outstanding keeps racing, and the last racer
# failing is fail-closed. fresh_datum_race.hpp is pure policy (header-only, no
# node, no daemon, standard library only), so this target links NOTHING and
# still exercises the reward-safety contract the wiring depends on. Built under
# -DC2POOL_DASH_BLS=ON like the rest of the dash suite; carries no BLS symbols.
add_executable(dash_fresh_datum_race_kat dash_fresh_datum_race_kat.cpp)
add_test(NAME dash_fresh_datum_race_kat COMMAND dash_fresh_datum_race_kat)
# ── KAT: PR-3 PROACTIVE PEER ROTATION policy (dashd-cut coin-P2P foundation) ──
# Locks the proactive-rotation decision invariants — primary/protected-local
# NEVER retired (#147), retirement picks the SLOWEST measured CanServeBlocks
# server (#148), and the cadence is bounded (default-OFF => never). Runs over the
# pure header proactive_rotation_policy.hpp (header-only, no node, no daemon,
# standard library only), the EXACT logic the shipped maybe_proactive_rotate
# calls, so this target links NOTHING and still exercises the real path. Built
# under -DC2POOL_DASH_BLS=ON like the rest of the dash suite; no BLS symbols.
add_executable(dash_proactive_rotation_kat dash_proactive_rotation_kat.cpp)
add_test(NAME dash_proactive_rotation_kat COMMAND dash_proactive_rotation_kat)
# ── KAT: PR-4 ASN / GEO DIVERSITY (dashd-cut coin-P2P racing tier) ──
# Locks the bundled ASN-prefix group assignment (peer_asn/peer_asn_group) and
# the race-set diversity objective (enforce_asn_diversity: top-N span >= 2 ASNs).
# asn_diversity.hpp is pure policy (header-only, no node, no daemon, boost::asio
# address parsing only), so this target links NOTHING and still exercises the
# schema --embedded-asn-diversity consumes. Built under -DC2POOL_DASH_BLS=ON like
# the rest of the dash suite; it carries no BLS symbols.
add_executable(dash_asn_diversity_kat dash_asn_diversity_kat.cpp)
add_test(NAME dash_asn_diversity_kat COMMAND dash_asn_diversity_kat)

# ── KAT: EMBEDDED getmnlistd SLOT TRACKER (dashd-cut coin-P2P stack, #154) ──
# Locks the five gates the wiring depends on: (1) the <=K in-flight invariant
# across a simulated rotation with fixed 10s per-slot timers (no backoff), (2)
# late/duplicate reply => first content-addressed match wins, rest dropped, NO
# strike, (3) expiry at 100s (10x) => ESCALATE not repeat, applied folds
# untouched, (4) capability filter => an incapable old-proto peer never gets a
# slot, (5) OFF-equivalence => flag default-OFF, tracker never consulted.
# getmnlistd_tracker.hpp is pure policy (header-only, no node, no daemon,
# standard library only), so this target links NOTHING and still exercises the
# reward-safety contract the wiring depends on. Built under -DC2POOL_DASH_BLS=ON
# like the rest of the dash suite; carries no BLS symbols.
add_executable(dash_getmnlistd_tracker_kat dash_getmnlistd_tracker_kat.cpp)
add_test(NAME dash_getmnlistd_tracker_kat COMMAND dash_getmnlistd_tracker_kat)

# ── Track A2 / W0: the v37 node scaffold ─────────────────────────────────────
# c2pool-v37: the node shell the v37 executor (PR #1467, the O1 single-writer
# lane executor) plugs into. W0 stands an >= 8-process single-host loopback
# simnet that meshes and idles EXCHANGING NOTHING (the receipt wire schema is
# W2/W3). MINIMAL link graph by design (the W0 spec §5.1) and by necessity
# (memory-pressured CI host): the v37 consensus module is header-only and
# self-contained, and the W0 loopback mesh uses plain POSIX sockets, so this
# target links only Threads — NOT core/pool/Boost/coin/payout/storage. The
# donor coin mains (main_btc.cpp / main_dash.cpp) are left untouched.
add_executable(c2pool-v37 v37/main_v37.cpp)
c2pool_wire_version(c2pool-v37)
target_include_directories(c2pool-v37 PRIVATE ${CMAKE_SOURCE_DIR}/src)
target_link_libraries(c2pool-v37 Threads::Threads)

# W0 HAND-WIRES its consumer-side test dir explicitly. Test wiring in this repo
# is hand-listed add_subdirectory/add_test — there is no file(GLOB) over
# */test — and the test-floor-guard only floors lanes already present in
# test-floors.json, so a test dir that is never added is a silent hollow-green.
# This add_subdirectory is that mitigation (spec §5.2). The linux-lane floor
# raise for the new v37 scaffold test is deferred to A1's CI-lane PR (a floor is
# raised only AFTER capturing a green-baseline junit).
add_subdirectory(v37/test)

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