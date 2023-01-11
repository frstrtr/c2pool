#pragma once

#include <string>
#include <map>
#include <vector>
#include <tuple>

#include <boost/function.hpp>

#include <btclibs/uint256.h>
#include <networks/network.h>
#include <libcoind/transaction.h>
#include "share_types.h"
#include "share.h"

class ShareTracker;

namespace shares
{
	bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net);

	uint256 check_hash_link(shared_ptr<::HashLinkType> hash_link, std::vector<unsigned char> data, std::vector<unsigned char> const_ending = {});

    shared_ptr<::HashLinkType> prefix_to_hash_link(std::vector<unsigned char> prefix, std::vector<unsigned char> const_ending = {});

    PackStream get_ref_hash(std::shared_ptr<c2pool::Network> net, types::ShareData &share_data, types::ShareInfo &share_info, coind::data::MerkleLink ref_merkle_link, std::optional<types::SegwitData> segwit_data = nullopt);
}