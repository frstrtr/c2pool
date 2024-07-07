set(pool_source
    factory.hpp factory.cpp
    node.hpp
    peer.hpp
)

add_library(pool STATIC ${pool_source})
target_link_libraries(pool core)