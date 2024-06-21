set(pool_source
    api.hpp
    node.hpp
    protocol.hpp
    handshake.hpp
)

add_library(pool STATIC ${pool_source})
target_link_libraries(pool core)