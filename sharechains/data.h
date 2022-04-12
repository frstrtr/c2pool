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

using std::string;

class ShareTracker;

namespace shares
{
	bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net);

	uint256 check_hash_link(shared_ptr<HashLinkType> hash_link, std::vector<unsigned char> data, string const_ending = "");

    shared_ptr<shares::types::HashLinkType> prefix_to_hash_link(std::vector<unsigned char> prefix, std::vector<unsigned char> const_ending = {});

    PackStream get_ref_hash(std::shared_ptr<c2pool::Network> net, types::ShareInfo &share_info, coind::data::MerkleLink ref_merkle_link);
}

//GenerateShareTransaction
namespace shares
{
    typedef boost::function<ShareType(shares::types::BlockHeaderType, uint64_t)> get_share_method;

	struct GeneratedShareTransactionResult
	{
		std::unique_ptr<shares::types::ShareInfo> share_info;
        coind::data::tx_type gentx;
		std::vector<uint256> other_transaction_hashes;
		get_share_method get_share;

        GeneratedShareTransactionResult(std::unique_ptr<shares::types::ShareInfo> _share_info, coind::data::tx_type _gentx, std::vector<uint256> _other_transaction_hashes, get_share_method &_get_share);
	};

#define type_desired_other_transaction_hashes_and_fees std::vector<std::tuple<uint256,boost::optional<int32_t>>>
#define type_known_txs std::map<uint256, coind::data::tx_type>

#define SetProperty(type, name)          \
    type _##name;                        \
                                         \
    void set_##name(const type &_value){ \
        _##name = _value;                \
    }

	class GenerateShareTransaction
	{
	public:
		std::shared_ptr<ShareTracker> tracker;
		std::shared_ptr<c2pool::Network> net;

		GenerateShareTransaction(std::shared_ptr<ShareTracker> _tracker);

	public:
		SetProperty(types::ShareData, share_data);
		SetProperty(uint256, block_target);
		SetProperty(uint32_t, desired_timestamp);
		SetProperty(uint256, desired_target);
		SetProperty(coind::data::MerkleLink, ref_merkle_link);
		SetProperty(type_desired_other_transaction_hashes_and_fees, desired_other_transaction_hashes_and_fees);
		SetProperty(type_known_txs, known_txs);
		SetProperty(unsigned long long, last_txout_nonce);
		SetProperty(long long, base_subsidy);

		std::optional<shares::types::SegwitData> _segwit_data;

		void set_segwit_data(const shares::types::SegwitData &_value)
		{
			_segwit_data = _value;
		}

	public:
		GeneratedShareTransactionResult operator()(uint64_t version);
	};

#undef SetProperty
#undef type_desired_other_transaction_hashes_and_fees
#undef type_known_txs
}