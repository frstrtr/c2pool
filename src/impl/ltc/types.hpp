#pragma once

#include <core/pack_types.hpp>
#include <core/netaddress.hpp>

namespace ltc
{

struct addr_type
{
    uint64_t m_services;
    NetService m_endpoint;

    SERIALIZE_METHODS(ltc::addr_type) { READWRITE(obj.m_services, obj.m_endpoint); }
};

} // namespace ltc