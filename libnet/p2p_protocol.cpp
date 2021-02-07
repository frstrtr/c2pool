#include "p2p_protocol.h"
#include "p2p_socket.h"

namespace c2pool::p2p{
    Protocol::Protocol(P2PSocket socket) : _socket(std::move(socket)){

    }
}