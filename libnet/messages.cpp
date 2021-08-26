#include "messages.h"
#include "p2p_socket.h"

#include <devcore/logger.h>
#include <devcore/str.h>
#include <util/pystruct.h>

namespace c2pool::libnet::messages
{
    const char *string_commands(commands cmd)
    {
        try
        {
            return _string_commands.at(cmd);
        }
        catch (const std::out_of_range &e)
        {
            LOG_WARNING << (int)cmd << " out of range in string_commands";
            return "error";
        }
    }

    commands reverse_string_commands(const char *key)
    {
        try
        {
            return _reverse_string_commands.at(key);
        }
        catch (const std::out_of_range &e)
        {
            LOG_WARNING << key << " out of range in reverse_string_commands";
            return commands::cmd_error;
        }
    }

} // namespace c2pool::libnet::messages