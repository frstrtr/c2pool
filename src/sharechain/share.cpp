#include <share.h>
#include <config.h>
#include <other.h>
#include <shareTracker.h>
#include <shareTypes.h>
#include <other.h>
#include <uint256.h>
#include <arith_uint256.h>
#include <data.h>
#include <console.h>
#include <univalue.h>

#include <memory>
#include <sstream>
#include <iomanip>
#include <string>
#include <vector>
#include <algorithm>
#include <map>

using std::map, std::vector, std::string;

namespace c2pool::shares
{
    bool is_segwit_activated(int version, int segwit_activation_version)
    {
        return (segwit_activation_version > 0) && (version >= segwit_activation_version);
    }

    int BaseShare::gentxSize = 50000;
    int BaseShare::gentxWeight = 200000;

    BaseShare::BaseShare(shared_ptr<c2pool::config::Network> _net, std::tuple<std::string, std::string> _peer_addr, ShareType _contents, ShareVersion _TYPE)
    {
        net = _net;
        peer_addr = _peer_addr;
        contents = _contents;

        min_header = contents.min_header;
        share_info = contents.share_info;
        hash_link = contents.hash_link;
        merkle_link = contents.merkle_link;

        TYPE = _TYPE;
        
        //TODO:
        // # save some memory if we can
        // txrefs = self.share_info['transaction_hash_refs']
        // if txrefs and max(txrefs) < 2**16:
        //     self.share_info['transaction_hash_refs'] = array.array('H', txrefs)
        // elif txrefs and max(txrefs) < 2**32: # in case we see blocks with more than 65536 tx in the future
        //     self.share_info['transaction_hash_refs'] = array.array('L', txrefs)

        bool segwit_activated = is_segwit_activated(VERSION, net->SEGWIT_ACTIVATION_VERSION);

        //TODO:
        // if not (2 <= len(self.share_info['share_data']['coinbase']) <= 100):
        //     raise ValueError('''bad coinbase size! %i bytes''' % (len(self.share_info['share_data']['coinbase']),))

        // if len(self.merkle_link['branch']) > 16 or (segwit_activated and len(self.share_info['segwit_data']['txid_merkle_link']['branch']) > 16):
        //     raise ValueError('merkle branch too long!')

        //TODO: assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])


        share_data = share_info->share_data;

        std::stringstream ss;
        std::string str_value;

        ss << std::hex << share_info->max_bits;
        ss >> str_value;
        
        max_target.SetHex(str_value);
        // max_target = share_info->max_//bits; //TODO: .target [data.py, 381]

        ss << std::hex << share_info->bits;
        ss >> str_value;
        target.SetHex(str_value);
        // target = share_info->bits;         //TODO: .target [data.py, 382]


        timestamp = share_info->timestamp;
        previous_hash = share_data->previous_share_hash;
        //TODO: new_script = bitcoin_data.pubkey_hash_to_script2(self.share_data['pubkey_hash'])
        desired_version = share_data->desired_version;
        absheight = share_info->absheigth;
        abswork = share_info->abswork;

        if (/*TODO:[add NAME in net] (net->NAME == "bitocin") &&*/ absheight > 3927800 && desired_version == 16)
        {
            //TODO: raise ValueError("This is not a hardfork-supporting share!")
        }

        //TODO: check for tx?
        // n = set()
        // for share_count, tx_count in self.iter_transaction_hash_refs():
        //     assert share_count < 110
        //     if share_count == 0:
        //         n.add(tx_count)
        // assert n == set(range(len(self.share_info['new_transaction_hashes'])))

        //TODO: create check_hash_link
        // gentx_hash = check_hash_link(
        //     self.hash_link,
        //     self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
        //     self.gentx_before_refhash, );

        //TODO:
        // merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
        // self.header = dict(self.min_header, merkle_root=merkle_root)

        //TODO: self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
        //TODO: self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))

        //TODO: add MAX_TARGET in net
        if (target.Compare(net->MAX_TARGET) > 0) //target > net->MAX_TARGET)
        {
            //TODO: raise p2p.PeerMisbehavingError('share target invalid')
        }

        if (pow_hash.Compare(target) > 0) //pow_hash > target)
        {
            //TODO: raise p2p.PeerMisbehavingError('share PoW invalid')
        }

        new_transaction_hashes = share_info->new_transaction_hashes;

        time_seen = c2pool::time::timestamp();
    }

    //TODO: write debug logs
    //TODO: return type
    template <int Version>
    GeneratedTransaction BaseShare::generate_transaction(c2pool::shares::tracker::OkayTracker _tracker, shared_ptr<ShareData> _share_data,
                                                         uint256 _block_target, unsigned int _desired_timestamp,
                                                         uint256 _desired_target, MerkleLink _ref_merkle_link,
                                                         vector<tuple<uint256, int>> desired_other_transaction_hashes_and_fees,
                                                         shared_ptr<c2pool::config::Network> _net, map<uint256, bitcoind::data::TransactionType> known_txs, /*TODO:  <type> last_txout_nonce=0,*/
                                                         long long base_subsidy, shared_ptr<SegwitData> _segwit_data)
    {
        auto t0 = c2pool::time::timestamp();
        BaseShare previous_share; //TODO: tracker BaseShare -> shared_ptr<BaseShare>
        if (_share_data->previous_share_hash.IsNull())
        {
            previous_share = _tracker.items[_share_data->previous_share_hash];
        }
        else
        {
            previous_share.TYPE = NoneVersion;
        }

        auto height_last = _tracker.get_height_and_last(_share_data->previous_share_hash);
        auto height = std::get<0>(height_last);
        auto last = std::get<1>(height_last);
        //TODO ASSERT: assert height >= net.REAL_CHAIN_LENGTH or last is None

        uint256 pre_target3;

        if (height < _net->TARGET_LOOKBEHIND)
        {
            pre_target3 = _net->MAX_TARGET;
        }
        else
        {
            //get_pool_attempts_per_second вместо 0 возвращает Null
            uint256 attempts_per_second; //TODO:= get_pool_attempts_per_second(tracker, share_data['previous_share_hash'], net.TARGET_LOOKBEHIND, min_work=True, integer=True)

            arith_uint256 pre_target;
            if (!attempts_per_second.IsNull())
            {
                pre_target.SetHex("10000000000000000000000000000000000000000000000000000000000000000");
                
                pre_target = (pre_target / UintToArith256(attempts_per_second) * _net->SHARE_PERIOD) - 1;
            }
            else
            {
                pre_target.SetHex("ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
            }

            //TODO: create math.clip for arith_uint256/uint256
            arith_uint256 pre_target2; //TODO: = math.clip(pre_target, (previous_share.max_target*9//10, previous_share.max_target*11//10))
            //TODO: pre_target3 = math.clip(pre_target2, (net.MIN_TARGET, net.MAX_TARGET))
        }

        uint256 max_bits; //TODO: = bitcoin_data.FloatingInteger.from_target_upper_bound(pre_target3)
        uint256 bits;     //TODO: =bitcoin_data.FloatingInteger.from_target_upper_bound(math.clip(desired_target, (pre_target3//30, pre_target3)))

        std::vector<uint256> new_transaction_hashes;
        int new_transaction_size = 0;                //including witnesses
        int all_transaction_stripped_size = 0;       //stripped size
        int all_transaction_real_size = 0;           //including witnesses, for statistics
        int new_transaction_weight = 0;
        int all_transaction_weight = 0;
        vector<tuple<int, int>> transaction_hash_refs;
        vector<uint256> other_transaction_hashes;

        auto t1 = c2pool::time::timestamp();

        //TODO: create get_chain in Tracker
        vector<BaseShare> past_shares = _tracker.get_chain(_share_data->previous_share_hash, std::min(height, 100));

        map<uint256, tuple<int, int>> tx_hash_to_this;

        for (int i = 0; i < past_shares.size(); i++)
        {
            for (int j = 0; j < past_shares[i].new_transaction_hashes.size(); j++)
            {
                if (tx_hash_to_this.find(past_shares[i].new_transaction_hashes[j]) == tx_hash_to_this.end())
                {
                    tx_hash_to_this[past_shares[i].new_transaction_hashes[j]] = std::make_tuple(1 + i, j);
                }
            }
        }

        auto t2 = c2pool::time::timestamp();

        for (auto txhash_fee : desired_other_transaction_hashes_and_fees)
        {
            uint256 tx_hash = std::get<0>(txhash_fee);
            int fee = std::get<1>(txhash_fee);

            int this_stripped_size = 0;
            int this_real_size = 0;
            int this_weight = 0;

            if (known_txs.size() > 0)
            {
                //TODO: packed_size for type
                //this_stripped_size = bitcoin_data.tx_id_type.packed_size(known_txs[tx_hash]);
                //TODO: packed_size for type
                //this_real_size     = bitcoin_data.tx_type.packed_size(known_txs[tx_hash]);
                this_weight = this_real_size + 3 * this_stripped_size;
            }

            //TODO: gentx_size — static/const? method — static?
            if (all_transaction_stripped_size + this_stripped_size + 80 + gentxSize + 500 > _net->BLOCK_MAX_SIZE)
                break;
            if (all_transaction_weight + this_weight + 320 + gentxWeight + 2000 > _net->BLOCK_MAX_WEIGHT)
                break;

            tuple<int, int> _this;
            if (tx_hash_to_this.find(tx_hash) != tx_hash_to_this.end())
            {
                _this = tx_hash_to_this[tx_hash];
                if (known_txs.size() > 0)
                {
                    all_transaction_stripped_size += this_stripped_size;
                    all_transaction_real_size += this_real_size;
                    all_transaction_weight += this_weight;
                }
            }
            else
            {
                if (known_txs.size() > 0)
                {
                    new_transaction_size += this_real_size;
                    all_transaction_stripped_size += this_stripped_size;
                    all_transaction_real_size += this_real_size;
                    new_transaction_weight += this_weight;
                    all_transaction_weight += this_weight;
                }
                new_transaction_hashes.push_back(tx_hash);
                _this = std::make_tuple(0, new_transaction_hashes.size() - 1);
            }
            transaction_hash_refs.push_back(_this);
            other_transaction_hashes.push_back(tx_hash);
        }

        auto t3 = c2pool::time::timestamp();

        /*TODO: Create tx's
        if transaction_hash_refs and max(transaction_hash_refs) < 2**16:
            transaction_hash_refs = array.array('H', transaction_hash_refs)
        elif transaction_hash_refs and max(transaction_hash_refs) < 2**32: # in case we see blocks with more than 65536 tx
            transaction_hash_refs = array.array('L', transaction_hash_refs)
       */

        auto t4 = c2pool::time::timestamp();

        if (all_transaction_stripped_size > 0)
        {
            LOG_INFO << "Generating a share with " << all_transaction_real_size << " bytes, "
                     << all_transaction_weight << " WU (new: " << new_transaction_size
                     << " B, " << new_transaction_weight << " WU) in " << other_transaction_hashes.size()
                     << " tx (" << new_transaction_hashes.size() << " new), plus est gentx of "
                     << gentxSize << " bytes/" << gentxWeight << " WU";

            LOG_INFO << "Total block stripped size=" << 80 + all_transaction_stripped_size + gentxSize
                     << " B, full size=" << 80 + all_transaction_real_size + gentxSize << " B,  weight: "
                     << 240 + all_transaction_weight + gentxWeight << " WU";
        }

        set<uint256> included_transactions(other_transaction_hashes.begin(), other_transaction_hashes.end()); //TODO: test

        vector<int> removed_fees;
        for (auto txhash_fee : desired_other_transaction_hashes_and_fees)
        {
            uint256 tx_hash = std::get<0>(txhash_fee);
            int fee = std::get<1>(txhash_fee);
            if (included_transactions.find(tx_hash) == included_transactions.end()){
                removed_fees.push_back(fee);
            }
        }
        //TODO: definite_fees = sum(0 if fee is None else fee for tx_hash, fee in desired_other_transaction_hashes_and_fees if tx_hash in included_transactions)
        


        /*TODO: Create tx's
        if None not in removed_fees:
            share_data = dict(share_data, subsidy=share_data['subsidy'] - sum(removed_fees))
        else:
            assert base_subsidy is not None
            share_data = dict(share_data, subsidy=base_subsidy + definite_fees)
       */

        uint256 _prev;
        if (previous_share.TYPE != NoneVersion)
        {
            _prev = previous_share.share_data->previous_share_hash;
        }
        else
        {
            _prev.SetNull();
        }
        //TODO: create get_cumulative_weights in tracker
        // auto cumulative_weights = _tracker.get_cumulative_weights(
        //     _prev,
        //     std::max(0, std::min(height, _net->REAL_CHAIN_LENGTH) - 1),
        //     //TODO: 65535*net.SPREAD*bitcoin_data.target_to_average_attempts(block_target)
        // );

        //TODO ASSERT: assert total_weight == sum(weights.itervalues()) + donation_weight, (total_weight, sum(weights.itervalues()) + donation_weight)

        /*TODO:
        amounts = dict((script, share_data['subsidy']*(199*weight)//(200*total_weight)) for script, weight in weights.iteritems()) # 99.5% goes according to weights prior to this share
        this_script = bitcoin_data.pubkey_hash_to_script2(share_data['pubkey_hash'])
        amounts[this_script] = amounts.get(this_script, 0) + share_data['subsidy']//200 # 0.5% goes to block finder
        amounts[DONATION_SCRIPT] = amounts.get(DONATION_SCRIPT, 0) + share_data['subsidy'] - sum(amounts.itervalues()) # all that's left over is the donation weight and some extra satoshis due to rounding
        
        if sum(amounts.itervalues()) != share_data['subsidy'] or any(x < 0 for x in amounts.itervalues()):
            raise ValueError()
        
        dests = sorted(amounts.iterkeys(), key=lambda script: (script == DONATION_SCRIPT, amounts[script], script))[-4000:] # block length limit, unlikely to ever be hit        
        */

        bool segwit_activated = is_segwit_activated(Version, _net->SEGWIT_ACTIVATION_VERSION);

        if (_segwit_data == nullptr && known_txs.size() > 0 )
        {
            segwit_activated = false;
        }

        //TODO: add in if: and any(bitcoin_data.is_segwit_tx(known_txs[h]) for h in other_transaction_hashes):
        if (!(segwit_activated || (known_txs.size() > 0)))
        {
            //TODO RAISE: raise ValueError('segwit transaction included before activation')
        }

        /*TODO:
        if segwit_activated and known_txs is not None:
            share_txs = [(known_txs[h], bitcoin_data.get_txid(known_txs[h]), h) for h in other_transaction_hashes]
            segwit_data = dict(txid_merkle_link=bitcoin_data.calculate_merkle_link([None] + [tx[1] for tx in share_txs], 0), wtxid_merkle_root=bitcoin_data.merkle_hash([0] + [bitcoin_data.get_wtxid(tx[0], tx[1], tx[2]) for tx in share_txs]))
        if segwit_activated and segwit_data is not None:
            witness_reserved_value_str = '[P2Pool]'*4
            witness_reserved_value = pack.IntType(256).unpack(witness_reserved_value_str)
            witness_commitment_hash = bitcoin_data.get_witness_commitment_hash(segwit_data['wtxid_merkle_root'], witness_reserved_value)
        */

        uint256 _far_share_hash;
        if (last.IsNull() && height < 99)
        {
            _far_share_hash.SetNull();
        }
        else
        {
            //TODO: _tracker.get_nth_parent_hash(_share_data->previous_share_hash, 99); //TODO
        }
        auto share_info = std::make_shared<ShareInfoType>(_share_data, new_transaction_hashes, transaction_hash_refs, _far_share_hash, max_bits, bits /*TODO: , timestamp, absheight, abswork*/);

        if (previous_share.TYPE != NoneVersion && _desired_timestamp > previous_share.timestamp + 180)
        {
            LOG_WARNING << "Warning: Previous share's timestamp is " << _desired_timestamp - previous_share.timestamp << " seconds old.\n"
                        << "Make sure your system clock is accurate, and ensure that you're connected to decent peers.\n"
                        << "If your clock is more than 300 seconds behind, it can result in orphaned shares.\n"
                        << "(It's also possible that this share is just taking a long time to mine.)";
        }

        if (previous_share.TYPE != NoneVersion && previous_share.timestamp > c2pool::time::timestamp() + 3)
        {
            LOG_WARNING << "WARNING! Previous share's timestamp is" << previous_share.timestamp - c2pool::time::timestamp() << "seconds in the future. This is not normal.\n"
                        << "Make sure your system clock is accurate. Errors beyond 300 sec result in orphaned shares.";
        }

        if (segwit_activated)
        {
            share_info->segwit_data = _segwit_data;
        }

        /*TODO: create tx's
            gentx = dict(
            version=1,
            tx_ins=[dict(
                previous_output=None,
                sequence=None,
                script=share_data['coinbase'],
            )],
            tx_outs=([dict(value=0, script='\x6a\x24\xaa\x21\xa9\xed' + pack.IntType(256).pack(witness_commitment_hash))] if segwit_activated else []) +
                [dict(value=amounts[script], script=script) for script in dests if amounts[script] or script == DONATION_SCRIPT] +
                [dict(value=0, script='\x6a\x28' + cls.get_ref_hash(net, share_info, ref_merkle_link) + pack.IntType(64).pack(last_txout_nonce))],
            lock_time=0,
        )

        if segwit_activated:
            gentx['marker'] = 0
            gentx['flag'] = 1
            gentx['witness'] = [[witness_reserved_value_str]]
        */

        /*TODO boost::functional:
        def get_share(header, last_txout_nonce=last_txout_nonce):
            min_header = dict(header); del min_header['merkle_root']
            share = cls(net, None, dict(
                min_header=min_header,
                share_info=share_info,
                ref_merkle_link=dict(branch=[], index=0),
                last_txout_nonce=last_txout_nonce,
                hash_link=prefix_to_hash_link(bitcoin_data.tx_id_type.pack(gentx)[:-32-8-4], cls.gentx_before_refhash),
                merkle_link=bitcoin_data.calculate_merkle_link([None] + other_transaction_hashes, 0),
            ))
            assert share.header == header # checks merkle_root
            return share
        t5 = time.time()
        if p2pool.BENCH: print "%8.3f ms for data.py:generate_transaction(). Parts: %8.3f %8.3f %8.3f %8.3f %8.3f " % (
            (t5-t0)*1000.,
            (t1-t0)*1000.,
            (t2-t1)*1000.,
            (t3-t2)*1000.,
            (t4-t3)*1000.,
            (t5-t4)*1000.)
        */

        return GeneratedTransaction(); //TODO: init
    }

    std::string BaseShare::SerializeJSON()
    {
        //TODO:
        UniValue json(UniValue::VOBJ);

        json.pushKV("TYPE", (int)TYPE);
        json.pushKV("contents", contents);

        return json.write();
    }
    void BaseShare::DeserializeJSON(std::string json)
    {
        //TODO:
        UniValue ShareValue(UniValue::VOBJ);
        ShareValue.read(json);


        TYPE = (ShareVersion)ShareValue["TYPE"].get_int();
        LOG_DEBUG << TYPE;
        contents = ShareValue["contents"].get_obj();
    }

} // namespace c2pool::shares