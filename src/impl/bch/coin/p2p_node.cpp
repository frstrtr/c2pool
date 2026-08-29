// SPDX-License-Identifier: AGPL-3.0-or-later
#include "p2p_node.hpp"

namespace bch
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
        return ec.message();
    }
}

} // p2p

} // namespace coin

} // namespace bch