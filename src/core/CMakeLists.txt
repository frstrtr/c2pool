file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")
file(GLOB chain_source "chain/*.hpp" "chain/*.cpp")

set(legacy_sources legacy/packv1.hpp legacy/pack_typesv1.hpp math.hpp math.cpp events.hpp disposable.hpp)

set(source 
    fileconfig.hpp
    settings.hpp settings.cpp
    config.hpp config.cpp
    ${configs_source}
    log.hpp log.cpp
    filesystem.hpp
    pack.hpp pack_types.hpp
    ${legacy_sources}
    common.hpp common.cpp
    macro.hpp
    netaddress.hpp netaddress.cpp
    opscript.hpp
    ${chain_source}
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source})
target_link_libraries(core btclibs)
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp)

add_subdirectory(test)
