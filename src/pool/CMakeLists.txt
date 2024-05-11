set(pool_source
    config.hpp config.cpp
)

add_library(pool ${pool_source})
target_link_libraries(pool STATIC core)