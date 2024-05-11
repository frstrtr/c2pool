set(source 
    config.hpp config.cpp 
    settings.hpp settings.cpp
    log.hpp log.cpp
    filesystem.hpp
)

find_package(yaml-cpp REQUIRED)

add_library(core STATIC ${source} )
target_link_libraries(core boost::boost yaml-cpp::yaml-cpp)
