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
    nlohmann_json::nlohmann_json
    ${Boost_LIBRARIES}
)
target_link_libraries(c2pool_enhanced c2pool_hashrate pool)  # OBJECT-lib SCC direct-naming (#22/#39)

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