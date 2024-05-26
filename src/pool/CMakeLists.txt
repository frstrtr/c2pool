set(pool_source
    api.hpp
    node.hpp
    protocol.hpp
    handler.hpp
    message.hpp
)

add_library(pool ${pool_source})
target_link_libraries(pool core)