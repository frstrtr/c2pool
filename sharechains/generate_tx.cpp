#include "generate_tx.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "share_tracker.h"
#include "data.h"
#include "share_adapters.h"
#include "share_builder.h"
#include <libdevcore/logger.h>
#include <networks/network.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

namespace shares
{

    GeneratedShareTransactionResult::GeneratedShareTransactionResult(std::shared_ptr<shares::types::ShareInfo> _share_info, types::ShareData _share_data, coind::data::tx_type _gentx, std::vector<uint256> _other_transaction_hashes, get_share_method _get_share)
    {
        share_info = std::move(_share_info);
        share_data = std::move(_share_data);
        gentx = std::move(_gentx);
        other_transaction_hashes = std::move(_other_transaction_hashes);
        get_share = std::move(_get_share);
    }

    GenerateShareTransaction::GenerateShareTransaction(std::shared_ptr<ShareTracker> _tracker) : tracker(_tracker), net(_tracker->net)
    {

    }

    std::shared_ptr<GeneratedShareTransactionResult> GenerateShareTransaction::operator()(uint64_t version)
    {
        t0 = c2pool::dev::debug_timestamp();
        ShareType previous_share = tracker->get(_share_data.previous_share_hash);
        uint256 prev_share_hash = previous_share ? previous_share->hash : uint256::ZERO;

        //height, last
        auto [height, last] = tracker->get_height_and_last(_share_data.previous_share_hash);
        LOG_TRACE << "height: " << height << ", last: " << last.IsNull() << "/" << last.GetHex();
        LOG_TRACE << tracker->exist(last) << " " << tracker->exist(_share_data.previous_share_hash);
        assert((height >= net->REAL_CHAIN_LENGTH) || last.IsNull());//!tracker->exists(last));//last.IsNull());

        auto pre_target = pre_target_calculate(previous_share, height);
        auto [max_bits, bits] = bits_calculate(pre_target);

        auto [new_transaction_hashes, transaction_hash_refs, other_transaction_hashes] = new_tx_hashes_calculate(version, prev_share_hash, height);

        auto t11 = c2pool::dev::debug_timestamp();;
        set<uint256> included_transactions = set<uint256>(other_transaction_hashes.begin(),
                                                          other_transaction_hashes.end());

        vector<std::optional<int32_t>> removed_fee;
        int32_t removed_fee_sum = 0;
        int32_t definite_fees = 0;
        bool fees_none_contains = false;
        for (auto [tx_hash, fee]: _desired_other_transaction_hashes_and_fees)
        {
            if (included_transactions.find(tx_hash) == included_transactions.end())
            {
                removed_fee.push_back(fee);
                if (fee.has_value())
                    removed_fee_sum += *fee;
                else
                    fees_none_contains = true;
            } else
            {
                if (fee.has_value())
                    definite_fees += *fee;
                else
                    definite_fees += 0;
            }
        }
        auto t12 = c2pool::dev::debug_timestamp();

        if (!fees_none_contains)
        {
            _share_data.subsidy -= removed_fee_sum;
        } else
        {
            assert(_base_subsidy.has_value());
            _share_data.subsidy = _base_subsidy.value() + definite_fees;
        }

        // This address calculate
        std::string this_address;
        switch (_share_data.addr.get_type())
        {
            case shares::types::ShareAddrType::Type::pubkey_hash_type:
            {
                this_address = coind::data::pubkey_hash_to_address(*_share_data.addr.pubkey_hash,
                                                                         net->parent->ADDRESS_VERSION, -1, net);
                break;
            }
            case shares::types::ShareAddrType::Type::address_type:
            {
                this_address = *_share_data.addr.address;
                break;
            }
            case shares::types::ShareAddrType::Type::none:
                throw std::runtime_error("Empty ShareAddrType for this_address");
        }
        if (version < 34 && !_share_data.addr.pubkey_hash)
        {
            auto _pubkey = coind::data::address_to_pubkey_hash(this_address, net);
            _share_data.addr.pubkey_hash = new uint160(std::get<0>(_pubkey));
            delete _share_data.addr.address;
            _share_data.addr.address = nullptr;
        }
        auto t13 = c2pool::dev::debug_timestamp();

        // Weight Amount Calculate
        auto amounts = weight_amount_calculate(prev_share_hash.IsNull() ? uint256::ZERO : (*previous_share->share_data)->previous_share_hash, height, this_address);

        auto t14 = c2pool::dev::debug_timestamp();
        bool segwit_activated = is_segwit_activated(version, net);
        if (!_segwit_data.has_value() && !_known_txs.has_value())
        {
            segwit_activated = false;
        }

        if (!(segwit_activated || !_known_txs.has_value()))
        {
            for (auto _tx_hash: other_transaction_hashes)
            {
                if (coind::data::is_segwit_tx(_known_txs.value()[_tx_hash]))
                    throw std::runtime_error("segwit transaction included before activation");
            }
        }

        if (segwit_activated && _known_txs.has_value())
        {
            make_segwit_data(other_transaction_hashes);
        }
        auto t15 = c2pool::dev::debug_timestamp();
//      witness_reserved_value_str = '[P2Pool]'*4
//		witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
//		witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
        const char* witness_reserved_value_str = "[P2Pool][P2Pool][P2Pool][P2Pool]";
        uint256 witness_commitment_hash;
        if (segwit_activated && _segwit_data.has_value())
        {
            PackStream stream(witness_reserved_value_str, strlen(witness_reserved_value_str));
            IntType(256) witness_reserved_stream;
            stream >> witness_reserved_stream;

            uint256 witness_reserved_value = witness_reserved_stream.get();

            witness_commitment_hash = coind::data::get_witness_commitment_hash(_segwit_data.value().wtxid_merkle_root, witness_reserved_value);
        }
        auto t16 = c2pool::dev::debug_timestamp();


        if (version < 34)
            set_share_tx_info(shares::types::ShareTxInfo{new_transaction_hashes, transaction_hash_refs});

        std::shared_ptr<shares::types::ShareInfo> share_info = share_info_generate(height, last, previous_share, version, max_bits, bits, segwit_activated);
        auto t17 = c2pool::dev::debug_timestamp();

        auto gentx = gentx_generate(version, segwit_activated, witness_commitment_hash, amounts, share_info, witness_reserved_value_str);
        auto t18 = c2pool::dev::debug_timestamp();

        get_share_method get_share_F = get_share_func(version, gentx, other_transaction_hashes, share_info);
        auto t19 = c2pool::dev::debug_timestamp();

        t5 = c2pool::dev::debug_timestamp();
        // TODO: log_info -> log_debug
        LOG_INFO << t5-t0 << " for generate_transaction(). Parts: " << t1-t0 << " " << t2-t1 << " " << t3-t2 << " " << t4-t3 << " " << t5-t4;
        LOG_INFO << "other parts: " << t12-t11 << " " << t13-t12 << " " << t14-t13 << " " << t15-t14 << " " << t16-t15 << " " << t17-t16 << " " << t18-t17 << " " << t19-t18;
//		if p2pool.BENCH: print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
//			(t5-t0)*1000.,
//			(t1-t0)*1000.,
//			(t2-t1)*1000.,
//			(t3-t2)*1000.,
//			(t4-t3)*1000.,
//			(t5-t4)*1000.)
//	    */
//
        return std::make_shared<GeneratedShareTransactionResult>(share_info, _share_data, gentx, other_transaction_hashes, std::move(get_share_F));
    }

    uint256 GenerateShareTransaction::pre_target_calculate(ShareType previous_share, const int32_t &height)
    {
        uint288 _pre_target3;
        if (height < net->TARGET_LOOKBEHIND)
        {
            _pre_target3 = convert_uint<uint288>(net->MAX_TARGET);
        } else
        {
            auto attempts_per_second = tracker->get_pool_attempts_per_second(_share_data.previous_share_hash, net->TARGET_LOOKBEHIND, true);

            uint288 pre_target("10000000000000000000000000000000000000000000000000000000000000000");
            if (!attempts_per_second.IsNull())
            {
                //equal: 2**256/(net.SHARE_PERIOD*attempts_per_second) - 1
                pre_target /= attempts_per_second * net->SHARE_PERIOD;
                pre_target -= 1;
            } else
            {
                pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            }

            uint288 pre_target2;
            {
                uint288 _max_target_div10 = convert_uint<uint288>(previous_share->max_target) / 10;
                uint288 _min_clip = _max_target_div10*9;
                uint288 _max_clip = _max_target_div10*11;
                pre_target2 = math::clip(pre_target, _min_clip, _max_clip);
            }

            _pre_target3 = math::clip(pre_target2, convert_uint<uint288>(net->MIN_TARGET), convert_uint<uint288>(net->MAX_TARGET));
        }
        return convert_uint<uint256>(_pre_target3);
    }

    GenerateShareTransaction::bits_calc GenerateShareTransaction::bits_calculate(const uint256 &pre_target)
    {
        FloatingInteger max_bits = FloatingInteger::from_target_upper_bound(pre_target);
        FloatingInteger bits;
        {
            LOG_DEBUG_STRATUM << "DESIRED TARGET: " << _desired_target.GetHex();

            uint256 _pre_target3_div30 = pre_target/30;
            bits = FloatingInteger::from_target_upper_bound(
                    math::clip(_desired_target, _pre_target3_div30, pre_target)
            );

            LOG_DEBUG_STRATUM << "_pre_target3_div30: " << _pre_target3_div30.GetHex();
            LOG_DEBUG_STRATUM << "pre_target: " << pre_target.GetHex();
            LOG_DEBUG_STRATUM << "math::clip(__desired_target, _pre_target3_div30, pre_target): " << math::clip(_desired_target, _pre_target3_div30, pre_target).GetHex();
            LOG_DEBUG_STRATUM << "BITS: " << bits.value.value;
        }

        return {max_bits, bits};
    }

    GenerateShareTransaction::new_tx_data GenerateShareTransaction::new_tx_hashes_calculate(uint64_t version, uint256 prev_share_hash, int32_t height)
    {
        t1 = c2pool::dev::debug_timestamp();
        vector<uint256> new_transaction_hashes;
        int32_t all_transaction_stripped_size = 0;
        int32_t new_transaction_weight = 0;
        int32_t all_transaction_weight = 0;
        vector<tx_hash_refs> transaction_hash_refs;
        vector<uint256> other_transaction_hashes;

        auto past_shares_generator = tracker->get_chain(prev_share_hash, std::min(height, 100));
        map<uint256, tx_hash_refs> tx_hash_to_this;

        if (version < 34)
        {
            uint256 _hash;
            int32_t i = 0;
            while (past_shares_generator(_hash))
            {
                auto _share = tracker->get(_hash);
                for (int j = 0; j < _share->new_transaction_hashes->size(); j++)
                {
                    auto tx_hash = (*_share->new_transaction_hashes)[j];
                    if (tx_hash_to_this.find(tx_hash) == tx_hash_to_this.end())
                    {
                        tx_hash_to_this[tx_hash] = {1 + i, j};
                    }
                }
                i += 1;
            }
        }

        t2 = c2pool::dev::debug_timestamp();
        for (auto [tx_hash, fee]: _desired_other_transaction_hashes_and_fees)
        {
            int32_t this_stripped_size = 0;
            int32_t this_real_size = 0;
            int32_t this_weight = 0;
            if (_known_txs.has_value())
            {
                for (auto _vs : _known_txs.value())
                    LOG_TRACE << _vs.first;
                LOG_TRACE << "tx_hash = " << tx_hash;
                auto _tx = _known_txs.value()[tx_hash];
                // this_stripped_size
                {
                    PackStream temp_txid;
                    auto stream_txid = coind::data::stream::TxIDType_stream(_tx->version,_tx->tx_ins, _tx->tx_outs, _tx->lock_time);
                    temp_txid << stream_txid;
                    this_stripped_size = temp_txid.size();
                }
                // this_real_size
                {
                    PackStream temp_tx;
                    auto stream_tx = coind::data::stream::TransactionType_stream(_tx);
                    temp_tx << stream_tx;
                    this_real_size = temp_tx.size();
                }
                this_weight = this_real_size + 3 * this_stripped_size;
            }

            if (all_transaction_stripped_size + this_stripped_size + 80 + Share::gentx_size + 500 > net->BLOCK_MAX_SIZE)
                break;
            if (all_transaction_weight + this_weight + 4 * 80 + Share::gentx_size + 2000 >
                net->BLOCK_MAX_WEIGHT)
                break;

            tx_hash_refs _this{};
            if (_known_txs.has_value())
            {
                all_transaction_stripped_size += this_stripped_size;
                //all_transaction_real_size += this_real_size;
                all_transaction_weight += this_weight;
            }
            if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
            {
                _this = tx_hash_to_this[tx_hash];
            } else
            {
                //new_transaction_size += this_real_size;
                if (_known_txs.has_value())
                {
                    new_transaction_weight += this_weight;
                }

                new_transaction_hashes.push_back(tx_hash);
                _this = {0, (int)new_transaction_hashes.size() - 1};
            }
            transaction_hash_refs.emplace_back(_this);
            other_transaction_hashes.push_back(tx_hash);
        }

        t3 = c2pool::dev::debug_timestamp();

        // Тут в питон-коде проводятся махинации с упаковкой в типы C, для оптимизации памяти. Нам, по идее, это не нужно.
        // if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
        //     transaction_hash_refs = array.array('H', transaction_hash_refs)
        // elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
        //     transaction_hash_refs = array.array('L', transaction_hash_refs)

        t4 = c2pool::dev::debug_timestamp();

        // if all_transaction_stripped_size:
        //     print "Generating a share with %i bytes, %i WU (new: %i B, %i WU) in %i tx (%i new), plus est gentx of %i bytes/%i WU" % (
        //         all_transaction_real_size,
        //         all_transaction_weight,
        //         new_transaction_size,
        //         new_transaction_weight,
        //         len(other_transaction_hashes),
        //         len(new_transaction_hashes),
        //         cls.gentx_size,
        //         cls.gentx_weight)
        //     print "Total block stripped size=%i B, full size=%i B,  weight: %i WU" % (
        //         80+all_transaction_stripped_size+cls.gentx_size,
        //         80+all_transaction_real_size+cls.gentx_size,
        //         3*80+all_transaction_weight+cls.gentx_weight)

        return {new_transaction_hashes, transaction_hash_refs, other_transaction_hashes};
    }

    std::vector<GenerateShareTransaction::weight_amount> GenerateShareTransaction::weight_amount_calculate(uint256 prev_share_hash, int32_t height, const std::string &_this_address)
    {
        auto tw1 = c2pool::dev::debug_timestamp();
        uint256 start_hash = prev_share_hash;
        int32_t max_shares = max(0, min(height, net->REAL_CHAIN_LENGTH) - 1);

        auto tw2 = c2pool::dev::debug_timestamp();
        auto _block_target_attempts = coind::data::target_to_average_attempts(_block_target);
        auto desired_weight = _block_target_attempts * 65535 * net->SPREAD;
        auto [weights, total_weight, donation_weight] = tracker->get_cumulative_weights(start_hash, max_shares, desired_weight);
        auto tw3 = c2pool::dev::debug_timestamp();
        //assert
        {
            uint288 sum_weights;
            sum_weights.SetHex("0");
            for (const auto& v : weights)
            {
                sum_weights += v.second;
            }

//            LOG_INFO << "GCW RESULT: total_weight = " << total_weight.ToString() << "; sum_weights = " << sum_weights.ToString() << "; donation_weight = " << donation_weight.ToString() << "; sum = " << (sum_weights + donation_weight).ToString() << "; equal?: " << (total_weight == (sum_weights + donation_weight));
            assert(total_weight == (sum_weights + donation_weight));
        }
        auto tw4 = c2pool::dev::debug_timestamp();

        // 99.5% goes according to weights prior to this share
        std::vector<GenerateShareTransaction::weight_amount> amounts;
        for (const auto& v : weights)
        {
            amounts.push_back({v.first, v.second*199*_share_data.subsidy/(200*total_weight)});
        }

        // 0.5% goes to block finder
        {
//            std::vector<unsigned char> this_script = coind::data::pubkey_hash_to_script2(_share_data.pubkey_hash, net->parent->ADDRESS_VERSION, -1, net).data;
            std::vector<unsigned char> this_address{_this_address.begin(), _this_address.end()};

            auto _this_amount = std::find_if(amounts.begin(), amounts.end(), [&this_address](const GenerateShareTransaction::weight_amount& value){
                return value.address == this_address;
            });

            if (_this_amount == amounts.end())
                amounts.push_back({this_address, _share_data.subsidy/200});
            else
                _this_amount->weight += _share_data.subsidy/200;
        }

        auto tw5 = c2pool::dev::debug_timestamp();
        //all that's left over is the donation weight and some extra satoshis due to rounding
        {
            auto _donation_address = coind::data::donation_script_to_address(net);
            std::vector<unsigned char> donation_address{_donation_address.begin(), _donation_address.end()};

            auto _donation_amount = std::find_if(amounts.begin(), amounts.end(), [&](const GenerateShareTransaction::weight_amount& value){
                return value.address == donation_address;
            });

            uint288 sum_amounts{};
            for (const auto& v: amounts)
                sum_amounts += v.weight;

            if (_donation_amount == amounts.end())
                amounts.push_back({donation_address, _share_data.subsidy - sum_amounts});
            else
                _donation_amount->weight += _share_data.subsidy - sum_amounts;
        }

        auto tw6 = c2pool::dev::debug_timestamp();
        if (std::accumulate(amounts.begin(), amounts.end(), uint288{}, [&](uint288 v, const GenerateShareTransaction::weight_amount &p ){
            return v + p.weight;
        }) != _share_data.subsidy)
            throw std::invalid_argument("Invalid subsidy!");

        auto tw7 = c2pool::dev::debug_timestamp();

        LOG_INFO << "weight_amount_calculate time: " << tw2-tw1 << " " << tw3-tw2 << " " << tw4-tw3 << " " << tw5-tw4 << " " << tw6-tw5 << " " << tw7-tw6;
        return amounts;
    }

    coind::data::tx_type GenerateShareTransaction::gentx_generate(uint64_t version, bool segwit_activated, uint256 witness_commitment_hash, std::vector<GenerateShareTransaction::weight_amount> amounts, std::shared_ptr<shares::types::ShareInfo> &share_info, const char* witness_reserved_value_str)
    {
        coind::data::tx_type gentx;

        std::map<std::vector<unsigned char>, uint288> _amounts;
        for (const auto& v : amounts)
        {
            _amounts[v.address] = v.weight;
        }

        std::vector<std::vector<unsigned char>> dests;
//        LOG_TRACE.stream() << "amounts: ";
//        for (auto [k, v] : amounts)
//        {
//            LOG_TRACE.stream() << "\t\t" << k << "; " << v.GetHex();
//        }

        for (const auto& v: amounts)
            dests.push_back(v.address);

        auto dests_pre_end = std::partition(dests.begin(), dests.end() - 1, [&](auto elem) {
            return elem < dests.back();
        });

        std::sort(dests.begin(), dests_pre_end, [&](std::vector<unsigned char> a, std::vector<unsigned char> b)
        {
//            if (a == net->DONATION_SCRIPT)
//                return false;

            return _amounts[a] != _amounts[b] ? _amounts[a] < _amounts[b] : a < b;
        });

        //TX_IN
        vector<coind::data::TxInType> tx_ins;
        tx_ins.emplace_back(coind::data::PreviousOutput(), _share_data.coinbase, 4294967295);

        //TX_OUT
        vector<coind::data::TxOutType> tx_outs;
        // tx1 [+]
        {
            if (segwit_activated)
            {
                auto script = std::vector<unsigned char>{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
                auto packed_witness_commitment_hash = pack<IntType(256)>(witness_commitment_hash);
                script.insert(script.end(), packed_witness_commitment_hash.begin(),
                              packed_witness_commitment_hash.end());
                tx_outs.emplace_back(0, script);
            }
        }
        // tx2 [+]
        auto _donation_address = coind::data::donation_script_to_address(net);
        const std::vector<unsigned char> donation_address{_donation_address.begin(), _donation_address.end()};
        for (const auto& addr: dests)
        {
            if (!_amounts[addr].IsNull() && addr != donation_address)
            {
                tx_outs.emplace_back(_amounts[addr].GetLow64(), coind::data::address_to_script2(std::string{addr.begin(), addr.end()}, net).data); //value, script
            }
        }
        tx_outs.emplace_back(_amounts[donation_address].GetLow64(), net->DONATION_SCRIPT);

        // tx3 [+]
        {
            // script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce)
            auto script = std::vector<unsigned char>{0x6a, 0x28};

            auto _get_ref_hash = get_ref_hash(version, net, _share_data, *share_info, _ref_merkle_link, _segwit_data);
            script.insert(script.end(), _get_ref_hash.data.begin(), _get_ref_hash.data.end());

            std::vector<unsigned char> packed_last_txout_nonce = pack<IntType(64)>(_last_txout_nonce);
            script.insert(script.end(), packed_last_txout_nonce.begin(), packed_last_txout_nonce.end());

            tx_outs.emplace_back(0, script);
        }

        // DEBUG tx_outs
//        int _i = 0;
//        LOG_DEBUG_SHARETRACKER << "DEBUG_TX_OUTS";
//        for (const auto& _tx : tx_outs)
//        {
//            coind::data::stream::TxOutType_stream packed_tx_out(_tx);
//            auto data = pack<coind::data::stream::TxOutType_stream>(packed_tx_out);
//            LOG_DEBUG_SHARETRACKER << _i << "(" << _tx.value << "/" << coind::data::script2_to_address(PackStream(_tx.script), net->parent->ADDRESS_VERSION, -1, net) << "): [" << data << "].";
//            _i += 1;
//        }

        // MAKE GENTX
        gentx = std::make_shared<coind::data::TransactionType>(1, tx_ins, tx_outs, 0);

        if (segwit_activated)
        {
            std::vector<std::vector<std::string>> _witness;
            _witness.push_back(std::vector<string>{std::string(witness_reserved_value_str)});
            gentx->wdata = std::make_optional<coind::data::WitnessTransactionData>(0, 1, _witness);
        }

        return gentx;
    }

    std::shared_ptr<shares::types::ShareInfo>
    GenerateShareTransaction::share_info_generate(int32_t height, uint256 last, ShareType previous_share,
                                                  uint64_t version, FloatingInteger max_bits, FloatingInteger bits,
                                                  bool segwit_activated)
    {
        std::shared_ptr<shares::types::ShareInfo> share_info;

        uint256 far_share_hash;
        if (last.IsNull() && height < 99)
            far_share_hash.SetNull();

        else
            far_share_hash = tracker->get_nth_parent_key(_share_data.previous_share_hash, 99);

        uint32_t timestamp;

        if (previous_share != nullptr)
        {
            if (version < 32)
                timestamp = std::clamp(_desired_timestamp, *previous_share->timestamp + 1,
                                       *previous_share->timestamp + net->SHARE_PERIOD * 2 - 1);
            else
                timestamp = std::max(_desired_timestamp, *previous_share->timestamp + 1);
        } else
        {
            timestamp = _desired_timestamp;
        }

        auto _absheight = ((previous_share ? *previous_share->absheight : 0) + 1) % 0x100000000; // % 2^32


        uint128 _abswork;
        {
            uint288 _temp;
            if (previous_share)
            {
                _temp.SetHex(previous_share->abswork->GetHex());
            }
            auto _temp_avg = coind::data::target_to_average_attempts(bits.target());

            _temp = _temp + _temp_avg;
            uint288 pow2_128("100000000000000000000000000000000"); // 2^128

            _temp = _temp >= pow2_128 ? _temp - pow2_128 : _temp; // _temp % pow2_128;
            _abswork.SetHex(_temp.GetHex());
        }
        //((previous_share.abswork if previous_share is not None else 0) + bitcoin_data.target_to_average_attempts(bits.target)) % 2**128

        share_info = std::make_shared<shares::types::ShareInfo>(far_share_hash, max_bits.get(),
                                                                bits.get(), timestamp, _absheight, _abswork
        );

        if (_share_tx_info.has_value())
            share_info->share_tx_info = _share_tx_info;

        if (previous_share)
        {
            if (_desired_timestamp > (*previous_share->timestamp + 180))
            {
                LOG_WARNING << (boost::format("Warning: Previous share's timestamp is %1% seconds old.\n" \
                            "Make sure your system clock is accurate, and ensure that you're connected to decent peers.\n" \
                            "If your clock is more than 300 seconds behind, it can result in orphaned shares.\n" \
                            "(It's also possible that this share is just taking a long time to mine.)") %
                                (_desired_timestamp - *previous_share->timestamp))
                        .str();
            }

            if (*previous_share->timestamp > (c2pool::dev::timestamp() + 3))
            {
                LOG_WARNING << (boost::format("WARNING! Previous share's timestamp is %1% seconds in the future. This is not normal.\n" \
                                              "Make sure your system clock is accurate.Errors beyond 300 sec result in orphaned shares.") %
                                (*previous_share->timestamp - c2pool::dev::timestamp()))
                        .str();
//                LOG_TRACE << "PreviousShare.timestamp = " << *previous_share->timestamp << ", timestamp = " << c2pool::dev::timestamp() << "(" << (c2pool::dev::timestamp() + 3) << ")";
            }
        }

        if (segwit_activated)
            share_info->segwit_data = _segwit_data;

        return share_info;
    }

    get_share_method GenerateShareTransaction::get_share_func(uint64_t version, coind::data::tx_type gentx, vector<uint256> other_transaction_hashes, std::shared_ptr<shares::types::ShareInfo> share_info)
    {
        return [=, gentx_data = shared_from_this()](const coind::data::types::BlockHeaderType& header, uint64_t last_txout_nonce)
        {
            coind::data::types::SmallBlockHeaderType min_header{header.version, header.previous_block, header.timestamp, header.bits, header.nonce};
            std::shared_ptr<ShareObjectBuilder> builder = std::make_shared<ShareObjectBuilder>(net);

            shared_ptr<::HashLinkType> pref_to_hash_link;
            {
                coind::data::stream::TxIDType_stream txid(gentx->version,gentx->tx_ins, gentx->tx_outs, gentx->lock_time);
//                LOG_TRACE.stream() << "generate_tx: pref_to_hash_link(gentx): " << *gentx;
                PackStream txid_packed;
                txid_packed << txid;
//                LOG_TRACE.stream() << "\tgenerate_tx: pref_to_hash_link(txid_packed): " << txid_packed;

                std::vector<unsigned char> prefix;
                prefix.insert(prefix.begin(), txid_packed.begin(), txid_packed.end()-32-8-4);
//                LOG_TRACE.stream() << "generate_tx: pref_to_hash_link(prefix): " << prefix;

                pref_to_hash_link = prefix_to_hash_link(prefix, net->gentx_before_refhash);
            }

            auto tx_hashes = other_transaction_hashes;
            tx_hashes.insert(tx_hashes.begin(),uint256());

            builder->create(version, {});

            builder
                    ->min_header(min_header)
                    ->share_data(_share_data)
                    ->share_info(*share_info)
                    ->ref_merkle_link(coind::data::MerkleLink())
                    ->last_txout_nonce(last_txout_nonce)
                    ->hash_link(*pref_to_hash_link->get())
                    ->merkle_link(coind::data::calculate_merkle_link(tx_hashes, 0));

            if (_segwit_data.has_value())
                builder->segwit_data(_segwit_data.value());

            if (_share_tx_info.has_value())
                builder->share_tx_info(_share_tx_info.value());

            ShareType share = builder->GetShare();
            assert(*share->header.get() == header);
            return share;
        };
    }

    void GenerateShareTransaction::make_segwit_data(const std::vector<uint256>& other_transaction_hashes)
    {
        struct __share_tx{
            std::shared_ptr<coind::data::TransactionType> tx;
            uint256 txid;
            uint256 h; //hash

            __share_tx() = default;
            __share_tx(std::shared_ptr<coind::data::TransactionType> _tx, uint256 _txid, uint256 _h)
            {
                tx = _tx;
                txid = _txid;
                h = _h;
            }
        };
        std::vector<__share_tx> share_txs;
        for (auto h : other_transaction_hashes)
        {
            share_txs.emplace_back(_known_txs.value()[h], coind::data::get_txid(_known_txs.value()[h]), h);
        }

        std::vector<uint256> _txids{uint256()};
        std::vector<uint256> _wtxids{uint256()};
        for (const auto& v : share_txs)
        {
            _txids.push_back(v.txid);
            _wtxids.push_back(coind::data::get_wtxid(v.tx, v.txid, v.h));
        }

        _segwit_data = std::make_optional<types::SegwitData>(coind::data::calculate_merkle_link(_txids, 0),
                                                             coind::data::merkle_hash(_wtxids));
    }


}