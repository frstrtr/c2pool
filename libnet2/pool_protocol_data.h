#pragma once
#include <cstdint>
#include <optional>

#include <libdevcore/deferred.h>
#include <sharechains/share_types.h>

struct PoolProtocolData
{
    const int version;

    std::optional<uint32_t> other_version;
    std::string other_sub_version;
    uint64_t other_services;
    uint64_t nonce;

	c2pool::deferred::QueryDeferrer<std::vector<PackedShareData>, uint256, std::vector<uint256>, uint64_t, std::vector<uint256>> get_shares;

    PoolProtocolData(auto _version, auto _get_shares) : version(_version), get_shares(std::move(_get_shares))
	{

	}
};