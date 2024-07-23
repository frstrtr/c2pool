add_library(pool_ltc 
    config.hpp config.cpp
    node.hpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    transaction.hpp transaction.cpp
    types.hpp
    messages.hpp
    share.hpp
)

target_link_libraries(pool_ltc core pool sharechain)