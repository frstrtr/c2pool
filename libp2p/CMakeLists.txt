set(libp2p_source
        socket.h
        socket_data.h
        message.h protocol.h handler.h handshake.h protocol.cpp protocol_events.h node.h node.cpp)

set(libp2ppreset_source
        preset/p2p_socket_data.h
        preset/p2p_node_interface.h
)

# TODO: library to interface
add_library(libp2p STATIC ${libp2p_source} ${libp2ppreset_source})
target_link_libraries(libp2p libdevcore)



#add_library(libp2ppreset STATIC ${libp2ppreset_source})
#target_link_libraries(libp2ppreset libp2p libcoind)

#target_link_libraries(libp2p univalue networks libdevcore sharechains libcoind)