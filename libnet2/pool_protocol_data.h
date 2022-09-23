#pragma once
#include <cstdint>
#include <optional>

#include <libdevcore/deferred.h>
#include <sharechains/share_types.h>
#include <sharechains/share.h>

struct PoolProtocolData
{
    const int version;

    std::optional<uint32_t> other_version;
    std::string other_sub_version;
    uint64_t other_services;
    uint64_t nonce;

    std::set<uint256> remote_tx_hashes;
    int32_t remote_remembered_txs_size = 0;

    std::map<uint256, coind::data::stream::TransactionType_stream> remembered_txs;
    int32_t remembered_txs_size;
    const int32_t max_remembered_txs_size = 25000000;
    std::vector<std::map<uint256, coind::data::tx_type>> known_txs_cache;

	c2pool::deferred::QueryDeferrer<std::vector<ShareType>, std::vector<uint256>, uint64_t, std::vector<uint256>> get_shares;

    PoolProtocolData(auto _version, auto _get_shares) : version(_version), get_shares(std::move(_get_shares))
	{

	}
};