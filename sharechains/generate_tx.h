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

//GenerateShareTransaction
namespace shares
{
    typedef boost::function<ShareType(coind::data::types::BlockHeaderType, uint64_t)> get_share_method;

    struct GeneratedShareTransactionResult
    {
        std::shared_ptr<shares::types::ShareInfo> share_info;
        types::ShareData share_data;
        coind::data::tx_type gentx;
        std::vector<uint256> other_transaction_hashes;
        get_share_method get_share;

        GeneratedShareTransactionResult(std::shared_ptr<shares::types::ShareInfo> _share_info, types::ShareData _share_data, coind::data::tx_type _gentx, std::vector<uint256> _other_transaction_hashes, get_share_method _get_share);
    };

#define type_desired_other_transaction_hashes_and_fees std::vector<std::tuple<uint256, std::optional<int32_t>>>
#define type_known_txs std::map<uint256, coind::data::tx_type>

#define SetProperty(type, name)          \
    type _##name{};                      \
                                         \
    GenerateShareTransaction &set_##name(const type &_value){ \
        _##name = _value;                \
		return *this; \
    }

    class GenerateShareTransaction : public std::enable_shared_from_this<GenerateShareTransaction>
    {
    private:
        struct bits_calc
        {
            FloatingInteger max_bits;
            FloatingInteger bits;
        };

        struct weight_amount
        {
            std::vector<unsigned char> address;
            uint288 weight;
        };

        struct new_tx_data
        {
            vector<uint256> new_transaction_hashes;
            vector<tx_hash_refs> transaction_hash_refs;
            vector<uint256> other_transaction_hashes;
        };

    public:
        ShareTracker* tracker;
        c2pool::Network* net;

        GenerateShareTransaction(ShareTracker* _tracker);

    public:
        SetProperty(types::ShareData, share_data);
        SetProperty(uint256, block_target);
        SetProperty(uint32_t, desired_timestamp);
        SetProperty(uint256, desired_target);
        SetProperty(coind::data::MerkleLink, ref_merkle_link);
        SetProperty(type_desired_other_transaction_hashes_and_fees, desired_other_transaction_hashes_and_fees);
        SetProperty(unsigned long long, last_txout_nonce);

        std::optional<unsigned long long> _base_subsidy;
        GenerateShareTransaction &set_base_subsidy(const unsigned long long &_value)
        {
            _base_subsidy = _value;
            return *this;
        }

        std::optional<type_known_txs> _known_txs;
        GenerateShareTransaction &set_known_txs(const type_known_txs &_value)
        {
            _known_txs = _value;
            return *this;
        }

        std::optional<shares::types::SegwitData> _segwit_data;
        GenerateShareTransaction &set_segwit_data(const shares::types::SegwitData &_value)
        {
            _segwit_data = _value;
            return *this;
        }

        std::optional<shares::types::ShareTxInfo> _share_tx_info;
        GenerateShareTransaction &set_share_tx_info(const shares::types::ShareTxInfo &_value)
        {
            _share_tx_info = _value;
            return *this;
        }

    public:
        std::shared_ptr<GeneratedShareTransactionResult> operator()(uint64_t version);

        uint256 pre_target_calculate(ShareType previous_share, const int32_t &height);
        bits_calc bits_calculate(const uint256 &pre_target);
        new_tx_data new_tx_hashes_calculate(uint64_t version, uint256 prev_share_hash, int32_t height);
        std::vector<weight_amount> weight_amount_calculate(uint256 prev_share_hash, int32_t height, const std::string& this_address);
        void make_segwit_data(const std::vector<uint256>& other_transaction_hashes);
        std::shared_ptr<shares::types::ShareInfo> share_info_generate(int32_t height, uint256 last, ShareType previous_share, uint64_t version, FloatingInteger max_bits, FloatingInteger bits, bool segwit_activated);
        coind::data::tx_type gentx_generate(uint64_t version, bool segwit_activated, uint256 witness_commitment_hash, std::vector<weight_amount> amounts, std::shared_ptr<shares::types::ShareInfo> &share_info, const char* witness_reserved_value_str);
        get_share_method get_share_func(uint64_t version, coind::data::tx_type gentx, vector<uint256> other_transaction_hashes, std::shared_ptr<shares::types::ShareInfo> share_info);
    private:
        // for debug
        c2pool::dev::debug_timestamp t0, t1, t2, t3, t4, t5;
    };

#undef SetProperty
#undef type_desired_other_transaction_hashes_and_fees
#undef type_known_txs
}