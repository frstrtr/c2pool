add_subdirectory(coin)

add_library(ltc_impl 
    config.hpp config.cpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    transaction.hpp transaction.cpp
    types.hpp
    messages.hpp
    share_types.hpp share.hpp
)

target_link_libraries(ltc_impl core pool sharechain)

add_subdirectory(test)