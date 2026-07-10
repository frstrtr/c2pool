// SPDX-License-Identifier: AGPL-3.0-or-later
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
        return ec.message();
    }
}

} // namespace pool