file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")

set(legacy_sources legacy/packv1.hpp legacy/pack_typesv1.hpp math.hpp math.cpp)

set(source 
    fileconfig.hpp
    settings.hpp settings.cpp
    config.hpp config.cpp
    ${configs_source}
    log.hpp log.cpp
    filesystem.hpp
    pack.hpp pack_types.hpp
    ${legacy_sources}
    common.hpp
    macro.hpp
    netaddress.hpp netaddress.cpp
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source})
target_link_libraries(core btclibs)
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp)
