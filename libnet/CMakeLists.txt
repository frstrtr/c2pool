set(libnet_sources
        pool_interface.h 
        pool_network.h pool_network.cpp
        pool_node.cpp pool_node.h
        pool_socket.cpp pool_socket.h
        pool_protocol.h
        pool_handshake.h
        pool_protocol_data.h
        pool_messages.h
        pool_node_data.h pool_node_data.cpp

        worker.h worker.cpp
        
        coind_messages.h
        coind_socket.h coind_socket.cpp
        coind_interface.h coind_network.h
        coind_protocol.h coind_protocol_data.h
        coind_node.h coind_node.cpp
        coind_node_data.h coind_node_data.cpp
        )

add_library(libnet STATIC ${libnet_sources})

target_link_libraries(libnet libp2p libcoind sharechains)