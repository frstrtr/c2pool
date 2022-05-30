set(libp2p_source
        socket.h
        socket.cpp
        socket_data.h
        message.h protocol.h handler.h handshake.h protocol.cpp)

# TODO: library to interface
add_library(libp2p ${libp2p_source})

target_link_libraries(libp2p libdevcore)
#target_link_libraries(libp2p univalue networks libdevcore sharechains libcoind)