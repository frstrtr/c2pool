set(libnet2_sources
        pool_node.cpp pool_node.h
        pool_socket.cpp pool_socket.h
        pool_protocol.cpp pool_protocol.h
        pool_handshake.cpp pool_handshake.h
        pool_protocol_data.h
        pool_messages.h pool_messages.cpp

        coind_node.h coind_node.cpp
        )

add_library(libnet2 ${libnet2_sources})

target_link_libraries(libnet2 libp2p libp2ppreset libcoind sharechains)
#target_link_libraries(libnet2 univalue networks libdevcore sharechains libcoind)