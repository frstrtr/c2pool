set(libnet_sources coind_node.h
    coind_node.cpp
    messages.h
    messages.cpp
    node_manager.h
    node_manager.cpp
    p2p_node.h
    p2p_node.cpp
    p2p_protocol.h
    p2p_protocol.cpp
    p2p_socket.h
    p2p_socket.cpp
    worker.h
    worker.cpp
    )

add_library(libnet ${libnet_sources})

target_link_libraries(libnet univalue networks devcore sharechains coind_jsonrpc coind_p2p)