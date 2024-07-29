add_library(pool_ltc 
    config.hpp config.cpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    transaction.hpp transaction.cpp
    types.hpp
    messages.hpp
    share_types.hpp share.hpp
)

target_link_libraries(pool_ltc core pool sharechain)

add_subdirectory(test)