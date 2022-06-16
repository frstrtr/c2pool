#pragma once
#include <cstdint>
#include <optional>

struct PoolProtocolData
{
    const int version;

    std::optional<uint32_t> other_version;
    std::string other_sub_version;
    uint64_t other_services;
    uint64_t nonce;

    PoolProtocolData(auto _version) : version(_version) {}
};