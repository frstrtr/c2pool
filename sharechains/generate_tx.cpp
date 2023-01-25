#include "generate_tx.h"

#include <algorithm>
#include <string>
#include <utility>
#include <vector>

#include "tracker.h"
#include "data.h"
#include "share_adapters.h"
#include "share_builder.h"
#include <libdevcore/logger.h>
#include <networks/network.h>
#include <libdevcore/stream.h>
#include <libdevcore/stream_types.h>

namespace shares
{

    GeneratedShareTransactionResult::GeneratedShareTransactionResult(std::shared_ptr<shares::types::ShareInfo> _share_info, types::ShareData _share_data, coind::data::tx_type _gentx, std::vector<uint256> _other_transaction_hashes, get_share_method &_get_share)
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

    //TODO: Test
    std::shared_ptr<GeneratedShareTransactionResult> GenerateShareTransaction::operator()(uint64_t version)
    {
        //t0
        ShareType previous_share = tracker->get(_share_data.previous_share_hash);
        uint256 prev_share_hash = previous_share ? previous_share->hash : uint256::ZERO;

        //height, last
        auto [height, last] = tracker->get_height_and_last(_share_data.previous_share_hash);
        LOG_TRACE << "height: " << height << ", last: " << last.IsNull() << "/" << last.GetHex();
        LOG_TRACE << tracker->exists(last) << " " << tracker->exists(_share_data.previous_share_hash);
        assert((height >= net->REAL_CHAIN_LENGTH) || last.IsNull());//!tracker->exists(last));//last.IsNull());

        auto pre_target = pre_target_calculate(previous_share, height);
        auto [max_bits, bits] = bits_calculate(pre_target);

        auto [new_transaction_hashes, transaction_hash_refs, other_transaction_hashes] = new_tx_hashes_calculate(prev_share_hash, height);

        set<uint256> included_transactions = set<uint256>(other_transaction_hashes.begin(),
                                                          other_transaction_hashes.end());

        vector<std::optional<int32_t>> removed_fee;
        int32_t removed_fee_sum = 0;
        int32_t definite_fees = 0;
        bool fees_none_contains = false;
        for (auto item: _desired_other_transaction_hashes_and_fees)
        {
            auto tx_hash = std::get<0>(item);
            auto fee = std::get<1>(item);
            LOG_TRACE << "from desired_other_transaction_hashes_and_fees: " << tx_hash << "; " << (fee.has_value() ? fee.value() : -1);
            if (!fee.has_value())
                fees_none_contains = true;

            if (included_transactions.find(tx_hash) == included_transactions.end())
            {
                removed_fee.push_back(fee);
                if (fee.has_value())
                    removed_fee_sum += *fee;
            } else
            {
                if (fee.has_value())
                    definite_fees += *fee;
                else
                    definite_fees += 0;
            }
        }

        LOG_TRACE << "fees_none_contains = " << fees_none_contains;
        LOG_TRACE << "_share_data.subsidy = " << _share_data.subsidy;
        LOG_TRACE << "_base_subsidy = " << _base_subsidy;
        LOG_TRACE << "definite_fees = " << definite_fees;
        if (!fees_none_contains)//TODO:
        {
            _share_data.subsidy += removed_fee_sum;
        } else
        {
            _share_data.subsidy = _base_subsidy + definite_fees;
        }

        auto [amounts] = weight_amount_calculate((*previous_share->share_data)->previous_share_hash, height);

        bool segwit_activated = is_segwit_activated(version, net);
        if (!_segwit_data.has_value() && !_known_txs.has_value())
        {
            LOG_TRACE << "!_segwit_data.has_value(): " << !_segwit_data.has_value();
            LOG_TRACE << "_known_txs.empty(): " << !_known_txs.has_value();
            LOG_TRACE << "segwit_activated -> false";
            segwit_activated = false;
        }

        bool segwit_tx = false;
        for (auto _tx_hash: other_transaction_hashes)
        {
            if (coind::data::is_segwit_tx(_known_txs.value()[_tx_hash]))
                segwit_tx = true;
        }
        if (!(segwit_activated || !_known_txs.has_value()) && segwit_tx)
        {
            throw "segwit transaction included before activation";
        }

        if (segwit_activated && _known_txs.has_value())
        {
            make_segwit_data(other_transaction_hashes);
        }

//      witness_reserved_value_str = '[P2Pool]'*4
//		witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
//		witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
        const char* witness_reserved_value_str = "[C2Pool][C2Pool][C2Pool][C2Pool]";
        uint256 witness_commitment_hash;
        if (segwit_activated && _segwit_data.has_value())
        {
            PackStream stream(witness_reserved_value_str, strlen(witness_reserved_value_str));
            LOG_TRACE << "witness_reserved_stream: " << stream;
            IntType(256) witness_reserved_stream;
            stream >> witness_reserved_stream;

            uint256 witness_reserved_value = witness_reserved_stream.get();
            LOG_TRACE << "witness_reserved_value = " << witness_reserved_value.GetHex();

            witness_commitment_hash = coind::data::get_witness_commitment_hash(_segwit_data.value().wtxid_merkle_root, witness_reserved_value);
            LOG_TRACE << "witness_commitment_hash = " << witness_commitment_hash.GetHex();
        }

        std::shared_ptr<shares::types::ShareInfo> share_info = share_info_generate(height, last, previous_share, version, max_bits, bits, new_transaction_hashes, transaction_hash_refs, segwit_activated);

        auto gentx = gentx_generate(segwit_activated, witness_commitment_hash, amounts, share_info, witness_reserved_value_str);

        get_share_method get_share_F = get_share_func(version, gentx, other_transaction_hashes, share_info);

//		t5 = time.time()
//		if p2pool.BENCH: print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
//			(t5-t0)*1000.,
//			(t1-t0)*1000.,
//			(t2-t1)*1000.,
//			(t3-t2)*1000.,
//			(t4-t3)*1000.,
//			(t5-t4)*1000.)
//	    */
//
        return std::make_shared<GeneratedShareTransactionResult>(share_info, _share_data, gentx, other_transaction_hashes, get_share_F);
    }

    arith_uint256 GenerateShareTransaction::pre_target_calculate(ShareType previous_share, const int32_t &height)
    {
        LOG_TRACE << "pre_target_calculate called";
        arith_uint256 _pre_target3;
        if (height < net->TARGET_LOOKBEHIND)
        {
            _pre_target3 = net->MAX_TARGET;
        } else
        {
            auto attempts_per_second = tracker->get_pool_attempts_per_second(_share_data.previous_share_hash, net->TARGET_LOOKBEHIND, true);
            LOG_TRACE << "attempts_per_second = " << attempts_per_second.GetHex();

            arith_uint288 pre_target;
            pre_target.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
            if (!attempts_per_second.IsNull())
            {
                //equal: 2**256/(net.SHARE_PERIOD*attempts_per_second) - 1
                pre_target /= attempts_per_second * net->SHARE_PERIOD;
                pre_target -= 1;
            } else
            {
                pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            }

            arith_uint256 pre_target2;
            {
                arith_uint256 _max_target_div10 = UintToArith256(previous_share->max_target)/10;
                arith_uint256 _min_clip = _max_target_div10*9;
                arith_uint256 _max_clip = _max_target_div10*11;
                pre_target2 = math::clip(Arith288ToArith256(pre_target), _min_clip, _max_clip);
            }

            _pre_target3 = math::clip(pre_target2, UintToArith256(net->MIN_TARGET), UintToArith256(net->MAX_TARGET));
        }
        uint256 pre_target3 = ArithToUint256(_pre_target3);
        LOG_TRACE << "pre_target3 = " << pre_target3.GetHex();

        return _pre_target3;
    }

    std::tuple<FloatingInteger, FloatingInteger> GenerateShareTransaction::bits_calculate(const arith_uint256 &pre_target)
    {
        LOG_TRACE << "bits_calculate called";

        FloatingInteger max_bits = FloatingInteger::from_target_upper_bound(ArithToUint256(pre_target));
        LOG_TRACE << "max_bits.target = " << max_bits.target().GetHex() << ", max_bits.value = " << max_bits.get();
        FloatingInteger bits;
        {
            arith_uint256 __desired_target = UintToArith256(_desired_target);
            arith_uint256 _pre_target3_div30 = pre_target/30;
            bits = FloatingInteger::from_target_upper_bound(
                    ArithToUint256(math::clip(__desired_target, _pre_target3_div30, pre_target))
            );
        }

        return std::make_tuple(max_bits, bits);
    }

    std::tuple<vector<uint256>, vector<tuple<uint64_t, uint64_t>>, vector<uint256>> GenerateShareTransaction::new_tx_hashes_calculate(uint256 prev_share_hash, int32_t height)
    {
        LOG_TRACE << "new_tx_hashes_calculate called";

        vector<uint256> new_transaction_hashes;
        int32_t all_transaction_stripped_size = 0;
        int32_t new_transaction_weight = 0;
        int32_t all_transaction_weight = 0;
        vector<tuple<uint64_t, uint64_t>> transaction_hash_refs;
        vector<uint256> other_transaction_hashes;

        //t1

        auto past_shares_generator = tracker->get_chain(prev_share_hash, std::min(height, 100));
        map<uint256, tuple<int, int>> tx_hash_to_this;

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
                        tx_hash_to_this[tx_hash] = std::make_tuple(1 + i, j);
                    }
                }
                i += 1;
            }
        }

        //t2
        //TODO: test
        for (auto item: _desired_other_transaction_hashes_and_fees)
        {
            auto tx_hash = std::get<0>(item);
            auto fee = std::get<1>(item);

            int32_t this_stripped_size = 0;
            int32_t this_real_size = 0;
            int32_t this_weight = 0;
            if (_known_txs.has_value())
            {
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

            if (all_transaction_stripped_size + this_stripped_size + 80 + Share::gentx_size + 500 >
                net->BLOCK_MAX_SIZE)
                break;
            if (all_transaction_weight + this_weight + 4 * 80 + Share::gentx_size + 2000 >
                net->BLOCK_MAX_WEIGHT)
                break;

            tuple<int, int> _this;
            all_transaction_stripped_size += this_stripped_size;
            //all_transaction_real_size += this_real_size;
            all_transaction_weight += this_weight;
            if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
            {
                _this = tx_hash_to_this[tx_hash];
            } else
            {
                //new_transaction_size += this_real_size;
                new_transaction_weight += this_weight;

                new_transaction_hashes.push_back(tx_hash);
                _this = std::make_tuple(0, new_transaction_hashes.size() - 1);
            }
            transaction_hash_refs.push_back(_this);
            other_transaction_hashes.push_back(tx_hash);
        }

        //t3

        // Тут в питон-коде проводятся махинации с упаковкой в типы C, для оптимизации памяти. Нам, по идее, это не нужно.
        // if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
        //     transaction_hash_refs = array.array('H', transaction_hash_refs)
        // elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
        //     transaction_hash_refs = array.array('L', transaction_hash_refs)

        //t4

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

        return std::make_tuple(new_transaction_hashes, transaction_hash_refs, other_transaction_hashes);
    }

    std::tuple<std::map<std::vector<unsigned char>, arith_uint288>> GenerateShareTransaction::weight_amount_calculate(uint256 prev_share_hash, int32_t height)
    {
        LOG_TRACE << "weight_amount_calculate called";

        std::map<std::vector<unsigned char>, arith_uint288> weights;
        arith_uint288 total_weight;
        arith_uint288 donation_weight;
        {
            uint256 start_hash = prev_share_hash;

            int32_t max_shares = max(0, min(height, net->REAL_CHAIN_LENGTH) - 1);

            LOG_TRACE << "block_target: " << _block_target.GetHex();
            auto _block_target_attempts = coind::data::target_to_average_attempts(_block_target);
            LOG_TRACE << "_block_target_attempts: " << _block_target_attempts.GetHex();

            auto desired_weight = _block_target_attempts * 65535 * net->SPREAD;

            LOG_TRACE << "For get_cumulative_weights: " << start_hash.GetHex() << " " << max_shares << " " << desired_weight.GetHex();
            auto weights_result = tracker->get_cumulative_weights(start_hash, max_shares, desired_weight);
            weights = std::get<0>(weights_result);
            total_weight = std::get<1>(weights_result);
            donation_weight = std::get<2>(weights_result);
            LOG_TRACE << "weights.size = " << weights.size() << ", total_weight = " << total_weight.GetHex() << ", donation_weight = " << donation_weight.GetHex();
        }

        //assert
        {
            arith_uint288 sum_weights;
            sum_weights.SetHex("0");
            for (auto v : weights)
            {
                sum_weights += v.second;
            }

            assert(total_weight == (sum_weights + donation_weight));
        }

        // 99.5% goes according to weights prior to this share
        std::map<std::vector<unsigned char>, arith_uint288> amounts;
        for (auto v : weights)
        {
            amounts[v.first] = v.second*199*_share_data.subsidy/(200*total_weight);
        }

        //this script reward; 0.5% goes to block finder
        {
            std::vector<unsigned char> this_script = coind::data::pubkey_hash_to_script2(_share_data.pubkey_hash).data;
            auto _this_amount = amounts.find(this_script);
            if (_this_amount == amounts.end())
                amounts[this_script] = 0;
            amounts[this_script] += _share_data.subsidy/200;
        }

        //all that's left over is the donation weight and some extra satoshis due to rounding
        {
            auto _donation_amount = amounts.find(net->DONATION_SCRIPT);
            if (_donation_amount == amounts.end())
                amounts[net->DONATION_SCRIPT] = 0;

            arith_uint288 sum_amounts;
            sum_amounts.SetHex("0");
            for (auto v: amounts)
            {
                sum_amounts += v.second;
            }

            amounts[net->DONATION_SCRIPT] += _share_data.subsidy - sum_amounts;
        }
//TODO: check
//		if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
//			raise ValueError()

        return std::make_tuple(amounts);
    }

    coind::data::tx_type GenerateShareTransaction::gentx_generate(bool segwit_activated, uint256 witness_commitment_hash, std::map<std::vector<unsigned char>, arith_uint288> amounts, std::shared_ptr<shares::types::ShareInfo> &share_info, const char* witness_reserved_value_str)
    {
        LOG_TRACE << "gentx_generate called";

        coind::data::tx_type gentx;

        //		dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit
        std::vector<std::vector<unsigned char>> dests;
        for (auto v: amounts)
            dests.push_back(v.first);

        std::sort(dests.begin(), dests.end(), [&](std::vector<unsigned char> a, std::vector<unsigned char> b)
        {
            if (a == net->DONATION_SCRIPT)
                return false;

            return amounts[a] != amounts[b] ? amounts[a] < amounts[b] : a < b;
        });


        //TX_IN
        vector<coind::data::TxInType> tx_ins;
        tx_ins.emplace_back(coind::data::PreviousOutput(uint256::ZERO, 0), _share_data.coinbase,
                            0); // TODO: check + debug

        //TX_OUT
        vector<coind::data::TxOutType> tx_outs;
        // tx1 [+]
        {
            if (segwit_activated)
            {
                auto script = std::vector<unsigned char>{0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
                auto packed_witness_commitment_hash = pack<IntType(256)>(witness_commitment_hash); // TODO: witness_commitment_hash
                script.insert(script.end(), packed_witness_commitment_hash.begin(),
                              packed_witness_commitment_hash.end());
                tx_outs.emplace_back(0, script);
            }
        }
        // tx2 [+]
        for (const auto& script: dests)
        {
            if (!ArithToUint256(amounts[script]).IsNull() || script == net->DONATION_SCRIPT)
            {
                tx_outs.emplace_back(amounts[script].GetLow64(), script); //value, script
            }
        }
        // tx3 [-]
        {
            // script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce)
            auto script = std::vector<unsigned char>{0x6a, 0x28};

            auto _get_ref_hash = get_ref_hash(net, _share_data, *share_info, _ref_merkle_link, _segwit_data); //TODO:
            script.insert(script.end(), _get_ref_hash.data.begin(), _get_ref_hash.data.end());

            std::vector<unsigned char> packed_last_txout_nonce = pack<IntType(64)>(_last_txout_nonce);
            LOG_TRACE.stream() << packed_last_txout_nonce;
            script.insert(script.end(), packed_last_txout_nonce.begin(), packed_last_txout_nonce.end());

            tx_outs.emplace_back(0, script);
        }

        // MAKE GENTX
        gentx = std::make_shared<coind::data::TransactionType>(1, tx_ins, tx_outs, 0);

        if (segwit_activated)
        {
            std::vector<std::vector<std::string>> _witness;
            _witness.push_back(std::vector<string>{std::string(witness_reserved_value_str)});
            gentx->wdata = std::make_optional<coind::data::WitnessTransactionData>(0, 1, _witness);
        }

        LOG_TRACE << "GENTX: " << gentx;

        return gentx;
    }

    std::shared_ptr<shares::types::ShareInfo>
    GenerateShareTransaction::share_info_generate(int32_t height, uint256 last, ShareType previous_share,
                                                  uint64_t version, FloatingInteger max_bits, FloatingInteger bits,
                                                  vector<uint256> new_transaction_hashes,
                                                  vector<tuple<uint64_t, uint64_t>> transaction_hash_refs, bool segwit_activated)
    {
        LOG_TRACE << "share_info_generate called";

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
            arith_uint288 _temp;
            if (previous_share)
            {
                _temp.SetHex(previous_share->abswork->GetHex());
            }
            LOG_TRACE << "_temp = " << _temp.GetHex();
            LOG_TRACE << "bits = " << bits.value.value;
            LOG_TRACE << "bits.target = " << bits.target().GetHex();
            auto _temp_avg = coind::data::target_to_average_attempts(bits.target());
            LOG_TRACE << "_temp_avg = " << _temp_avg.GetHex();

            _temp = _temp + _temp_avg;
            arith_uint288 pow2_128; // 2^128
            pow2_128.SetHex("100000000000000000000000000000000");

            _temp = _temp >= pow2_128 ? _temp - pow2_128 : _temp; // _temp % pow2_128;
            _abswork.SetHex(_temp.GetHex());
            LOG_TRACE << "abswork = " << _abswork.GetHex();
        }
        //((previous_share.abswork if previous_share is not None else 0) + bitcoin_data.target_to_average_attempts(bits.target)) % 2**128

        share_info = std::make_shared<shares::types::ShareInfo>(far_share_hash, max_bits.get(),
                                                                bits.get(), timestamp, new_transaction_hashes,
                                                                transaction_hash_refs,
                                                                _absheight, _abswork
        );

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
            }
        }

        if (segwit_activated)
            share_info->segwit_data = _segwit_data;

        return share_info;
    }

    get_share_method GenerateShareTransaction::get_share_func(uint64_t version, coind::data::tx_type gentx, vector<uint256> other_transaction_hashes, std::shared_ptr<shares::types::ShareInfo> share_info)
    {
        LOG_TRACE << "get_share_func called";

        return [=](coind::data::types::BlockHeaderType header, uint64_t last_txout_nonce)
        {
            coind::data::types::SmallBlockHeaderType min_header{header.version, header.previous_block, header.timestamp, header.bits, header.nonce};

            ShareType share;
            std::shared_ptr<ShareObjectBuilder> builder = std::make_shared<ShareObjectBuilder>(net);

            shared_ptr<::HashLinkType> pref_to_hash_link;
            {
                coind::data::stream::TxIDType_stream txid(gentx->version,gentx->tx_ins, gentx->tx_outs, gentx->lock_time);

                PackStream txid_packed;
                txid_packed << txid;

                std::vector<unsigned char> prefix;
                prefix.insert(prefix.begin(), prefix.end()-32-8-4, prefix.end());

                pref_to_hash_link = prefix_to_hash_link(prefix, net->gentx_before_refhash);
            }

            auto tx_hashes = other_transaction_hashes;
            tx_hashes.insert(tx_hashes.begin(),uint256());

            builder->create(version, {});

            builder
                    ->min_header(min_header)
                    ->share_info(*share_info)
                    ->ref_merkle_link(coind::data::MerkleLink())
                    ->last_txout_nonce(last_txout_nonce)
                    ->hash_link(*pref_to_hash_link->get())
                    ->merkle_link(coind::data::calculate_merkle_link(tx_hashes, 0));



            share = builder->GetShare();
            //TODO: assert(share->header == header);
            return share;
        };
    }

    void GenerateShareTransaction::make_segwit_data(const std::vector<uint256>& other_transaction_hashes)
    {
        LOG_TRACE << "make_segwit_data called";

        //	share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
        //  segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))

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
        share_txs.resize(other_transaction_hashes.size());
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