# file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")

set(legacy_sources legacy/packv1.hpp legacy/pack_typesv1.hpp math.hpp math.cpp events.hpp disposable.hpp)

set(network_sources message.hpp socket.cpp socket.hpp factory.hpp)

set(btclib_sources hash.hpp hash.cpp uint256.hpp uint256.cpp)

set(source 
    fileconfig.hpp
    settings.hpp settings.cpp
    config.hpp
    # ${configs_source}
    log.hpp log.cpp
    timer.hpp
    filesystem.hpp
    pack.hpp pack_types.hpp
    ${btclib_sources}
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
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp nlohmann_json::nlohmann_json)

add_subdirectory(test)
