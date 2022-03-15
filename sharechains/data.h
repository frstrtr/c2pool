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

namespace shares
{
	typedef boost::function<ShareType(int)> get_share_method;//TODO: args

	bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net);

	uint256 check_hash_link(HashLinkType hash_link, unsigned char *data, string const_ending = "");

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
		SetProperty(ShareData, share_data);
		SetProperty(uint256, block_target);
		SetProperty(int32_t, desired_timestamp);
		SetProperty(uint256, desired_target);
		SetProperty(shares::MerkleLink, ref_merkle_link);
		SetProperty(type_desired_other_transaction_hashes_and_fees, desired_other_transaction_hashes_and_fees);
		SetProperty(type_known_txs, known_txs);
		SetProperty(unsigned long long, last_txout_nonce);
		SetProperty(long long, base_subsidy);
		SetProperty(shares::SegwitData, segwit_data);
	public:
		GeneratedShare operator()()
		{
			//TODO:
		}
	};

#undef SetProperty
#undef type_desired_other_transaction_hashes_and_fees
#undef type_known_txs
}