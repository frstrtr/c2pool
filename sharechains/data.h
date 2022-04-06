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
	typedef boost::function<ShareType(int)> get_share_method;//TODO: args

	bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net);

	uint256 check_hash_link(shared_ptr<HashLinkType> hash_link, PackStream &data, string const_ending = "");
}

//GenerateShareTransaction
namespace shares
{
	struct GeneratedShare
	{
		ShareInfo share_info;
		coind::data::TransactionType gentx;
		vector<uint256> other_transaction_hashes;
		get_share_method get_share;
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
		SetProperty(int32_t, desired_timestamp);
		SetProperty(uint256, desired_target);
		SetProperty(shares::types::MerkleLink, ref_merkle_link);
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
		GeneratedShare operator()(uint64_t version);
	};

#undef SetProperty
#undef type_desired_other_transaction_hashes_and_fees
#undef type_known_txs
}