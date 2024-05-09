set(source 
    pool_config.hpp pool_config.cpp 
    network_config.hpp network_config.cpp
    log.hpp log.cpp
    filesystem.hpp filesystem.cpp
    )

add_library(core STATIC ${source})
target_link_libraries(core boost::boost)
