set(pool_source
    factory.hpp factory.cpp
    api.hpp
    node.hpp
    protocol.hpp
    handshake.hpp
)

add_library(pool STATIC ${pool_source})
target_link_libraries(pool core)