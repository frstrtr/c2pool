set(libnet2_sources
        p2p_node.cpp p2p_node.h
        p2p_socket.cpp p2p_socket.h
        p2p_protocol.cpp p2p_protocol.h
        p2p_handshake.cpp p2p_handshake.h
        p2p_node_interface.h p2p_protocol_data.h
        p2p_messages.h p2p_messages.cpp
        )

add_library(libnet2 ${libnet2_sources})

target_link_libraries(libnet2 libp2p libp2ppreset libcoind sharechains)
#target_link_libraries(libnet2 univalue networks libdevcore sharechains libcoind)