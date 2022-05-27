set(libnet2_sources
        p2p_socket.h
        p2p_socket.cpp
        p2p_socket_data.h)

add_library(libnet2 ${libnet2_sources})

target_link_libraries(libnet2 libp2p libcoind)
#target_link_libraries(libnet2 univalue networks libdevcore sharechains libcoind)