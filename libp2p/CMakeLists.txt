set(libp2p_source
        socket.h
        socket_components.h
        socket_data.h
        net_supervisor.h        
        message.h 
        protocol.h 
        handler.h 
        handshake.h 
        protocol_components.h node.h)

set(libp2ppreset_source
        preset/p2p_socket_data.h
        preset/p2p_node_interface.h
)

# TODO: library to interface
add_library(libp2p STATIC ${libp2p_source} ${libp2ppreset_source})
target_link_libraries(libp2p libdevcore)