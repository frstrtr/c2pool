set(pool_source
    node.cpp node.hpp 
    peer.hpp
    protocol.hpp
)

add_library(pool STATIC ${pool_source})
target_link_libraries(pool core)