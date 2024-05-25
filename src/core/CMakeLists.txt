file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")

set(legacy_sources pack.hpp pack_types.hpp math.hpp math.cpp)

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
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source})
target_link_libraries(core btclibs)
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp)
