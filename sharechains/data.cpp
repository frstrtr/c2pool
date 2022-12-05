#include "data.h"

#include <algorithm>
#include <string>
#include <vector>

#include "tracker.h"
#include "share_adapters.h"
#include "share_builder.h"
#include <networks/network.h>
#include <libdevcore/stream_types.h>
#include <libdevcore/str.h>

namespace shares
{
    bool is_segwit_activated(int version, shared_ptr<c2pool::Network> net)
    {
        return version >= net->SEGWIT_ACTIVATION_VERSION;
    }

    uint256 check_hash_link(shared_ptr<::HashLinkType> hash_link, std::vector<unsigned char> data, std::vector<unsigned char> const_ending)
    {
        uint64_t extra_length = (*hash_link)->length % (512 / 8);
        assert((*hash_link)->extra_data.size() == max((int64_t)extra_length - (int64_t)const_ending.size(), (int64_t) 0));

        auto extra = (*hash_link)->extra_data;
        extra.insert(extra.end(), const_ending.begin(), const_ending.end());
        {
            int32_t len = (*hash_link)->extra_data.size() + const_ending.size() - extra_length;
            extra.erase(extra.begin(), extra.begin() + len);
        }
        assert(extra.size() == extra_length);

        IntType(256) result;

        uint32_t init_state[8]{
            ReadBE32((*hash_link)->state.data() + 0),
            ReadBE32((*hash_link)->state.data() + 4),
            ReadBE32((*hash_link)->state.data() + 8),
            ReadBE32((*hash_link)->state.data() + 12),
            ReadBE32((*hash_link)->state.data() + 16),
            ReadBE32((*hash_link)->state.data() + 20),
            ReadBE32((*hash_link)->state.data() + 24),
            ReadBE32((*hash_link)->state.data() + 28),
        };

        auto result2 = coind::data::hash256_from_hash_link(init_state, data, extra, hash_link->get()->length);
        return result2;
    }

    shared_ptr<::HashLinkType> prefix_to_hash_link(std::vector<unsigned char> prefix, std::vector<unsigned char> const_ending)
    {
        //TODO: assert prefix.endswith(const_ending), (prefix, const_ending)
        shared_ptr<::HashLinkType> result = std::make_shared<::HashLinkType>();

//        uint32_t _init[8] {0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05644c, 0x1f83d9ab, 0x5be0cd12};
        auto sha = CSHA256().Write(prefix.data(), prefix.size());

        std::vector<unsigned char> state;
        state.resize(CSHA256::OUTPUT_SIZE);

        WriteBE32(&state[0], sha.s[0]);
        WriteBE32(&state[0+4], sha.s[1]);
        WriteBE32(&state[0+8], sha.s[2]);
        WriteBE32(&state[0+12], sha.s[3]);
        WriteBE32(&state[0+16], sha.s[4]);
        WriteBE32(&state[0+20], sha.s[5]);
        WriteBE32(&state[0+24], sha.s[6]);
        WriteBE32(&state[0+28], sha.s[7]);


        std::vector<unsigned char> extra_data;
        extra_data.insert(extra_data.end(), sha.buf, sha.buf + sha.bytes%64-const_ending.size());

        (*result)->state = state;
        (*result)->extra_data = extra_data;
        (*result)->length = sha.bytes;

        return result;
    }

    PackStream get_ref_hash(std::shared_ptr<c2pool::Network> net, types::ShareData &share_data, types::ShareInfo &share_info, coind::data::MerkleLink ref_merkle_link, std::optional<types::SegwitData> segwit_data)
    {
        RefType ref_type(std::vector<unsigned char>(net->IDENTIFIER, net->IDENTIFIER+net->IDENTIFIER_LENGHT), share_data, share_info, segwit_data);

        PackStream ref_type_packed;
        ref_type_packed << ref_type;

        auto hash_ref_type = coind::data::hash256(ref_type_packed, true);
        IntType(256) _check_merkle_link(coind::data::check_merkle_link(hash_ref_type, ref_merkle_link));

        PackStream result;
        result << _check_merkle_link;

        return result;
    }
}

namespace shares
{

    GeneratedShareTransactionResult::GeneratedShareTransactionResult(std::unique_ptr<shares::types::ShareInfo> _share_info, coind::data::tx_type _gentx, std::vector<uint256> _other_transaction_hashes, get_share_method &_get_share)
    {
        share_info = std::move(_share_info);
        gentx = std::move(_gentx);
        other_transaction_hashes = _other_transaction_hashes;
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
        assert((height >= net->REAL_CHAIN_LENGTH) || last.IsNull());

		arith_uint256 _pre_target3;
		if (height < net->TARGET_LOOKBEHIND)
		{
			_pre_target3 = net->MAX_TARGET;
		} else
		{
			auto attempts_per_second = tracker->get_pool_attempts_per_second(_share_data.previous_share_hash, net->TARGET_LOOKBEHIND, true);

            arith_uint256 pre_target;
            pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            if (attempts_per_second != 0)
            {
                //equal: 2**256/(net.SHARE_PERIOD*attempts_per_second) - 1
                pre_target -= attempts_per_second*net->SHARE_PERIOD;
                pre_target /= attempts_per_second*net->SHARE_PERIOD;
            }

            arith_uint256 pre_target2;
            {
                arith_uint256 _max_target_div10 = UintToArith256(previous_share->max_target)/10;
                arith_uint256 _min_clip = _max_target_div10*9;
                arith_uint256 _max_clip = _max_target_div10*11;
                pre_target2 = math::clip(pre_target, _min_clip, _max_clip);
            }

            _pre_target3 = math::clip(pre_target2, UintToArith256(net->MIN_TARGET), UintToArith256(net->MAX_TARGET));
		}
        uint256 pre_target3 = ArithToUint256(_pre_target3);

        FloatingInteger max_bits = FloatingInteger::from_target_upper_bound(pre_target3);
        FloatingInteger bits;
        {
            arith_uint256 __desired_target = UintToArith256(_desired_target);
            arith_uint256 _pre_target3_div30 = _pre_target3/30;
            bits = FloatingInteger::from_target_upper_bound(
                    ArithToUint256(math::clip(__desired_target, _pre_target3_div30, _pre_target3))
            );
        }

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
			if (!_known_txs.empty())
			{
                auto _tx = _known_txs[tx_hash];
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

		set<uint256> included_transactions = set<uint256>(other_transaction_hashes.begin(),
														  other_transaction_hashes.end());

		vector<std::optional<int32_t>> removed_fee;
		int32_t removed_fee_sum;
		int32_t definite_fees;
		bool fees_none_contains = false;
		for (auto item: _desired_other_transaction_hashes_and_fees)
		{
			auto tx_hash = std::get<0>(item);
			auto fee = std::get<1>(item);
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

		if (!fees_none_contains)
		{
			_share_data.subsidy += removed_fee_sum;
		} else
		{
			_share_data.subsidy = _base_subsidy + definite_fees;
		}


		std::map<std::vector<unsigned char>, arith_uint256> weights;
		arith_uint256 total_weight;
		arith_uint256 donation_weight;
		{
			uint256 start_hash;
			if (previous_share)
				start_hash = *previous_share->previous_hash;
			else
				start_hash.SetNull();

			int32_t max_shares = max(0, min(height, net->REAL_CHAIN_LENGTH) - 1);

			arith_uint256 desired_weight =
					UintToArith256(coind::data::target_to_average_attempts(_block_target)) * 65535 * net->SPREAD;

			auto weights_result = tracker->get_cumulative_weights(start_hash, max_shares, desired_weight);
			weights = std::get<0>(weights_result);
			total_weight = std::get<1>(weights_result);
			donation_weight = std::get<2>(weights_result);
		}

		//assert
		{
			arith_uint256 sum_weights;
			sum_weights.SetHex("0");
			for (auto v : weights)
			{
				sum_weights += v.second;
			}

			assert(total_weight == (sum_weights + donation_weight));
		}

		// 99.5% goes according to weights prior to this share
		std::map<std::vector<unsigned char>, arith_uint256> amounts;
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

			arith_uint256 sum_amounts;
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

//		dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit
		std::vector<std::vector<unsigned char>> dests;
        for (auto v : amounts)
            dests.push_back(v.first);

		std::sort(dests.begin(), dests.end(), [&](std::vector<unsigned char> a, std::vector<unsigned char> b){
			if (a == net->DONATION_SCRIPT)
				return false;

			return amounts[a] != amounts[b] ? amounts[a] < amounts[b] : a < b;
		});

		bool segwit_activated = is_segwit_activated(version, net);
    	if (!_segwit_data.has_value() && _known_txs.empty())
		{
			segwit_activated = false;
		}

		bool segwit_tx = false;
		for (auto _tx_hash: other_transaction_hashes)
		{
			if (coind::data::is_segwit_tx(_known_txs[_tx_hash]))
				segwit_tx = true;
		}
		if (!(segwit_activated || _known_txs.empty()) && segwit_tx)
		{
			throw "segwit transaction included before activation";
		}

		//	share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
		//  segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
		if (segwit_activated && !_known_txs.empty())
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
			std::vector<uint256> txids;
			for (auto h : other_transaction_hashes)
			{
				auto txid = coind::data::get_txid(_known_txs[h]);
				share_txs.emplace_back(_known_txs[h], txid, h);
				txids.push_back(txid);
			}

            {
                std::vector<uint256> txids{uint256()};
                std::vector<uint256> wtxids{uint256()};
                for (auto v : share_txs)
                {
                    txids.push_back(v.txid);
                    wtxids.push_back(coind::data::get_wtxid(v.tx, v.txid, v.h));
                }

                _segwit_data = std::make_optional<types::SegwitData>(coind::data::calculate_merkle_link(txids, 0),
                                                                     coind::data::merkle_hash(wtxids));
            }
		}

//      witness_reserved_value_str = '[P2Pool]'*4
//		witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
//		witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
        char* witness_reserved_value_str = "[C2Pool][CPool][C2Pool][C2Pool]";
        uint256 witness_commitment_hash;
        if (segwit_activated && _segwit_data.has_value())
        {
            //TODO: TEST
            PackStream stream(witness_reserved_value_str, strlen(witness_reserved_value_str));
            IntType(256) witness_reserved_stream;
            stream >> witness_reserved_stream;

            uint256 witness_reserved_value = witness_reserved_stream.get();

            witness_commitment_hash = coind::data::get_witness_commitment_hash(_segwit_data.value().wtxid_merkle_root, witness_reserved_value);
        }

        unique_ptr<shares::types::ShareInfo> share_info;
        {
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
                arith_uint256 _temp;
                if (previous_share)
                {
                    auto _share_abswork = *previous_share->abswork;
                    _temp.SetHex(_share_abswork.GetHex());
                }

                _temp = _temp + coind::data::target_to_average_attempts(bits.target());
                arith_uint256 pow2_128; // 2^128
                pow2_128.SetHex("100000000000000000000000000000000");

                _temp = _temp >= pow2_128 ? _temp-pow2_128 : _temp; // _temp % pow2_128;
                _abswork.SetHex(_temp.GetHex());
            }
            //((previous_share.abswork if previous_share is not None else 0) + bitcoin_data.target_to_average_attempts(bits.target)) % 2**128

            share_info = std::make_unique<shares::types::ShareInfo>(far_share_hash, max_bits.get(),
                                                                    bits.get(), timestamp, new_transaction_hashes, transaction_hash_refs,
                                                                    _absheight, _abswork
                                                                    );
        }

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

        coind::data::tx_type gentx;
        {
            //TX_IN
            vector<coind::data::TxInType> tx_ins;
            tx_ins.emplace_back(coind::data::PreviousOutput(uint256::ZERO, 0), _share_data.coinbase, 0); // TODO: check + debug

            //TX_OUT
            vector<coind::data::TxOutType> tx_outs;
            {
                auto script = std::vector<unsigned char> {0x6a, 0x24, 0xaa, 0x21, 0xa9, 0xed};
                if (segwit_activated)
                {
                    auto packed_witness_commitment_hash = pack<IntType(256)>(witness_commitment_hash);
                    script.insert(script.end(), packed_witness_commitment_hash.begin(), packed_witness_commitment_hash.end());
                }
                tx_outs.emplace_back(0, script);
            }

            for (auto script : dests)
            {
                if (!ArithToUint256(amounts[script]).IsNull() || script == net->DONATION_SCRIPT)
                {
                    tx_outs.emplace_back(amounts[script].GetLow64(), script);
                }
            }
            {
                // script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce)
                auto script = std::vector<unsigned char> {0x6a, 0x28};

                auto _get_ref_hash = get_ref_hash(net, _share_data, *share_info, _ref_merkle_link, _segwit_data);
                script.insert(script.end(), _get_ref_hash.data.begin(), _get_ref_hash.data.end());


                //ERROR HERE!
                auto packed_last_txout_nonce = pack<IntType(64)>(_last_txout_nonce);
                script.insert(script.end(), packed_last_txout_nonce.begin(), packed_last_txout_nonce.end());

                tx_outs.emplace_back(0, script);
            }

            // MAKE GENTX
            gentx = std::make_shared<coind::data::TransactionType>(1, tx_ins, tx_outs, 0);

            if(segwit_activated)
            {
                std::vector<std::vector<std::string>> _witness;
                _witness.push_back(std::vector<string>{std::string(witness_reserved_value_str)});
                gentx->wdata = std::make_optional<coind::data::WitnessTransactionData>(0, 1, _witness);
            }
        }

        get_share_method get_share_F([=, &share_info](coind::data::types::BlockHeaderType header, uint64_t last_txout_nonce)
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
        });

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
        return std::make_shared<GeneratedShareTransactionResult>(std::move(share_info),gentx, other_transaction_hashes,get_share_F);
    }
}