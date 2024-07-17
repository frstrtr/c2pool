#include "node.hpp"

namespace pool
{

std::string parse_net_error(const boost::system::error_code& ec)
{
    switch (ec.value())
    {
    case boost::asio::error::eof:
        return "EOF, socket disconnected";
    default:
        return "???";
    }
}

} // namespace pool