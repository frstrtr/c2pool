set(libp2p_source
        net_errors.h
        socket.h
        socket_components.h
        socket_packet.h
        message.h 
        protocol.h 
        handler.h 
        handshake.h 
        protocol_components.h 
        node.h
)

set(workflow_source workflow_tree.h workflow_thread.h workflow_task.h workflow_process.h workflow_node.h)

# TODO: library to interface
add_library(libp2p STATIC ${libp2p_source} ${libp2ppreset_source} ${workflow_source})
target_link_libraries(libp2p libdevcore)