#include "p2p_node.hpp"

namespace ltc
{
namespace coin
{

namespace p2p
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

} // p2p

} // namespace coin

} // namespace ltc