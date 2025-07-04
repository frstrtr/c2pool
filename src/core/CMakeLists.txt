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
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source})
target_link_libraries(core btclibs)
target_link_libraries(core Boost::headers Boost::log Boost::log_setup Boost::thread Boost::filesystem yaml-cpp nlohmann_json::nlohmann_json)

add_subdirectory(test)
