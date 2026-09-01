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
    addr_store.hpp addr_store.cpp
    p2p_message_stats.hpp
    web_server.hpp web_server.cpp
    graph_history.hpp graph_history.cpp
    http_session.cpp
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

add_subdirectory(test)
