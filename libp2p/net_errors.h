#pragma once

#include <string>
#include <stdexcept>

#include <libdevcore/types.h>
#include "workflow_node.h"

namespace libp2p
{
    enum errcode
    {
        BAD_PEER,
        PING_TIMEOUT,
        SYSTEM_ERROR,
        ASIO_ERROR
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

    class node_exception : public std::runtime_error
    {
        WorkflowNode* node;
    public:
        node_exception(const std::string& reason, WorkflowNode* node_)
            : std::runtime_error(reason), node(node_)
        {
        }

        WorkflowNode* get_node() const
        {
            return node;
        }
    };
}