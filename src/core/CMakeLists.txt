file(GLOB configs_source "configs/*.hpp" "configs/*.cpp")

set(source 
    fileconfig.hpp
    settings.hpp settings.cpp
    config.hpp config.cpp
    ${configs_source}
    log.hpp log.cpp
    filesystem.hpp
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source} )
target_link_libraries(core btclibs)
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp)
