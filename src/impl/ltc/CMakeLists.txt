add_subdirectory(coin)

add_library(ltc
    config.hpp config.cpp
    node.hpp node.cpp
    peer.hpp
    protocol_actual.cpp protocol_legacy.cpp
    messages.hpp
    share_types.hpp share.hpp
)

target_link_libraries(ltc core pool sharechain ltc_coin)

add_subdirectory(test)