#pragma once
#include "p2p_socket.h"

namespace c2pool::p2p
{
    class Protocol
    {
        public:
            Protocol(P2PSocket socket);
        private:
            P2PSocket _socket;
    };
} // namespace c2pool::p2p