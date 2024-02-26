#pragma once
#include <string>
#include <libdevcore/types.h>

namespace libp2p
{
    enum errcode
    {
        BAD_PEER
    };

    class error
    {
    public:
        libp2p::errcode errc;
        std::string reason;
        NetAddress addr;

        error(libp2p::errcode errc_, std::string reason_, NetAddress addr_)
            : errc(errc_), reason(reason_), addr(addr_)
        {

        }

        error(libp2p::errcode errc_, const char* reason_, NetAddress addr_)
            : errc(errc_), reason(reason_), addr(addr_)
        {
            
        }
    };
}