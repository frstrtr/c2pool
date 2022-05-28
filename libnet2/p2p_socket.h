#pragma once

#include <memory>

#include <libp2p/socket.h>

#include <boost/asio.hpp>

class P2PSocket : public Socket, public FundamentalSocketObject<std::shared_ptr<boost::asio::ip::tcp::socket>>
{
    P2PSocket() :
            Socket(),
            FundamentalSocketObject<std::shared_ptr<boost::asio::ip::tcp::socket>>()
    {

    }
};