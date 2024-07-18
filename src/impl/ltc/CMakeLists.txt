add_library(pool_ltc 
    node.hpp node.cpp
    peer.hpp
    protocol.hpp protocol_actual.cpp protocol_legacy.cpp
)

target_link_libraries(pool_ltc core pool sharechain)