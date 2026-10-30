# file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")

set(legacy_sources legacy/packv1.hpp legacy/pack_typesv1.hpp math.hpp math.cpp)

set(network_sources message_macro.hpp message.hpp socket.cpp socket.hpp factory.hpp)

set(btclib_sources hash.hpp hash.cpp uint256.hpp uint256.cpp)

set(source 
    fileconfig.hpp
    settings.hpp settings.cpp
    config.hpp
    # ${configs_source}
    log.hpp log.cpp
    events.hpp
    timer.hpp
    filesystem.hpp
    pack.hpp pack_types.hpp
    ${btclib_sources}
    reply_matcher.hpp 
    events.hpp 
    disposable.hpp
    ${legacy_sources}
    common.hpp common.cpp
    ${network_sources}
    macro.hpp
    netaddress.hpp netaddress.cpp
    opscript.hpp
    random.hpp random.cpp
    os_random.hpp os_random.cpp
    addr_store.hpp addr_store.cpp
    p2p_message_stats.hpp
    web_server.hpp web_server.cpp
    graph_history.hpp graph_history.cpp
    http_session.cpp
    ip_mask.hpp ip_mask.cpp
    stratum_server.hpp stratum_server.cpp
    stratum_types.hpp
    stratum_work_source.hpp
    address_utils.hpp address_utils.cpp
    leveldb_store.hpp leveldb_store.cpp
    address_validator.hpp address_validator.cpp
    # Control-plane settings foundation (M0): declarative param catalog +
    # monolithic settings-file loader with per-key source, tri-state, money gate.
    param_catalog.hpp param_catalog.cpp param_catalog.inc
    settings_file.hpp settings_file.cpp
    settings_cli.hpp settings_cli.cpp
    # Control-plane M1 (SAFE half): READ-ONLY /api/config[/schema] serializers +
    # DORMANT (unwired) apply-batch validator. See config_endpoint.hpp.
    config_endpoint.hpp config_endpoint.cpp
    boost_throw_exception.cpp
)

find_package(yaml-cpp REQUIRED)

# core_util: link-dependency-free leaf carrying core::timestamp(), split out
# to break the core <-> {pool,ltc,c2pool} static-link SCC (V36 gate). Source
# half landed in 07165699; this wires the leaf library into the build.
add_library(core_util STATIC core_util.cpp)
# Boost::headers is an INTERFACE (include-dirs-only) target, so this adds NO
# link edge and does NOT reintroduce the SCC the split was made to break. It
# is required because the top-level -include core/boost_asio_compat.hpp force-
# include (CMakeLists.txt) injects <boost/version.hpp> into EVERY CXX TU,
# including this one. Self-hosted runners masked the gap with a system libboost
# on the default include path; the github-hosted live-bootstrap gate has boost
# only as conan target-scoped includes, so the leaf must carry the header path.
target_link_libraries(core_util PUBLIC Boost::headers)

add_library(core OBJECT ${source})
target_link_libraries(core PUBLIC core_util btclibs)

target_link_libraries(core PUBLIC Boost::headers Boost::exception Boost::log Boost::log_setup Boost::thread Boost::filesystem yaml-cpp nlohmann_json::nlohmann_json ${LEVELDB_LIBRARIES})

# Add LevelDB include directories
target_include_directories(core PUBLIC ${LEVELDB_INCLUDE_DIRS})

# UTXO snapshots (DASH full UTXO set, PR S1): MuHash3072 + ChaCha20 and the
# compressor / Coin codec ported from Dash Core v23.1.7 (crypto/VENDOR.md),
# the dumptxoutset reader / writer / pin / import / dump, and the set hashes
# over a UTXOViewDB. Its own OBJECT library: only the targets that name it
# link it (core_test, c2pool-utxo), so no node binary changes in this PR.
add_library(core_utxo OBJECT
    crypto/chacha20.hpp crypto/chacha20.cpp
    crypto/muhash.hpp crypto/muhash.cpp
    coin/coin_compressor.hpp coin/coin_compressor.cpp
    coin/utxo_set_hash.hpp coin/utxo_set_hash.cpp
    coin/utxo_snapshot.hpp coin/utxo_snapshot.cpp
)
target_link_libraries(core_utxo core ${SECP256K1_LIBRARIES})

add_subdirectory(test)
