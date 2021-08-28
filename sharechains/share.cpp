#include "share.h"

#include <univalue.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <devcore/addrStore.h>
#include "tracker.h"
#include <stdexcept>
#include <tuple>
#include <set>
using namespace std;

#include <boost/format.hpp>

namespace c2pool::shares
{
    std::string BaseShare::SerializeJSON()
    {
        UniValue json(UniValue::VOBJ);

        //TODO:
        // json.pushKV("TYPE", (int)TYPE);
        // json.pushKV("contents", contents);

        return json.write();
    }
    void BaseShare::DeserializeJSON(std::string json)
    {
        //TODO:
        UniValue ShareValue(UniValue::VOBJ);
        ShareValue.read(json);

        // TYPE = (ShareVersion)ShareValue["TYPE"].get_int();
        // LOG_DEBUG << TYPE;
        // contents = ShareValue["contents"].get_obj();
    }

    bool BaseShare::check(shared_ptr<c2pool::shares::ShareTracker> tracker /*, TODO: other_txs = None???*/)
    {
        if (timestamp > (c2pool::dev::timestamp() + 600))
        {
            throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (timestamp - c2pool::dev::timestamp())).str());
        }

        if (!previous_hash.IsNull()) //TODO: or pack in share_data
        {
            auto previous_share = tracker->get(previous_hash);
            //if (tracker->get_height(previous_hash))
        }
        //TODO:
    }

    void BaseShare::contents_load(UniValue contents)
    {
        min_header = contents["min_header"].get_obj();

        auto share_info = contents["share_info"].get_obj();
        auto share_data = share_info["share_data"].get_obj();

        previous_hash.SetHex(share_data.get_str());
        coinbase = share_data["coinbase"].get_str();
        nonce = share_data["nonce"].get_int();
        pubkey_hash.SetHex(share_data["pubkey_hash"].get_str());
        subsidy = share_data["subsidy"].get_uint64();
        donation = share_data["donation"].get_int();

        int stale_info_temp = share_data["stale_info"].get_int();
        if (stale_info_temp == 253 || stale_info_temp == 254)
        {
            stale_info = (StaleInfo)stale_info_temp;
        }
        else
        {
            stale_info = StaleInfo::unk;
        }

        desired_version = share_data["desired_version"].get_uint64();

        for (auto item : share_info["new_transaction_hashes"].getValues())
        {
            uint256 tx_hash;
            tx_hash.SetHex(item.get_str());
            new_transaction_hashes.push_back(tx_hash);
        }

        for (auto tx_hash_ref : share_info["transaction_hash_refs"].getValues())
        {
            transaction_hash_refs.push_back(std::make_tuple<int, int>(tx_hash_ref[0].get_int(), tx_hash_ref[1].get_int()));
        }

        far_share_hash.SetHex(share_info["far_share_hash"].get_str());
        max_target.SetHex(share_info["max_bits"].get_str());
        target.SetHex(share_info["bits"].get_str());
        timestamp = share_info["timestamp"].get_int();
        absheight = share_info["absheight"].get_int();
        abswork.SetHex(share_info["abswork"].get_str());

        ref_merkle_link = contents["ref_merkle_link"].get_obj();
        last_txout_nonce = contents["last_txout_nonce"].get_uint64();
        hash_link = contents["hash_link"].get_obj();
        merkle_link = contents["merkle_link"].get_obj();
    }



    BaseShare::BaseShare(int VERSION, shared_ptr<Network> _net, tuple<string, string> _peer_addr, UniValue _contents) : SHARE_VERSION(VERSION), net(_net), peer_addr(_peer_addr), contents(_contents)
    {
        contents_load(contents);

        bool segwit_activated = is_segwit_activated();

        if (!(2 <= coinbase.length() && coinbase.length() <= 100))
        {
            throw std::runtime_error((boost::format("bad coinbase size! %1 bytes") % coinbase.length()).str());
        }

        if (merkle_link.branch.size() > 16 && !is_segwit_activated())
        {
            throw std::runtime_error("merkle branch too long!");
        }

        //TODO: need???  assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])

        if (net->net_name == "bitcoin" && absheight > 3927800 && desired_version == 16)
        {
            throw std::runtime_error("This is not a hardfork-supporting share!");
        }

        {
            set<int> n;

            for (auto tx_hash_ref : transaction_hash_refs)
            {
                int share_count = std::get<0>(tx_hash_ref);
                int tx_count = std::get<1>(tx_hash_ref);
                assert(share_count < 110);
                if (share_count == 0)
                {
                    n.insert(tx_count);
                }
            }
            set<int> set_new_tx_hashes;
            for (int i = 0; i < new_transaction_hashes.size(); i++)
            {
                set_new_tx_hashes.insert(i);
            }
            assert(set_new_tx_hashes == n);
        }


        //TODO: 
        // auto _ref_hash = BaseShare::get_ref_hash(net, share_info, contents["ref_merkle_link"]); //TODO: contents remake
        // _ref_hash << IntType(64)(contents.last_txout_nonce) << IntType(32)(0);

        // gentx_hash = check_hash_link(
        //     hash_link,
        //     _ref_hash,
        //     gentx_before_refhash
        // );
        /*
        TODO:
        
        self.gentx_hash = check_hash_link(
            self.hash_link,
            self.get_ref_hash(net, self.share_info, contents['ref_merkle_link']) + pack.IntType(64).pack(self.contents['last_txout_nonce']) + pack.IntType(32).pack(0),
            self.gentx_before_refhash,
        )
        merkle_root = bitcoin_data.check_merkle_link(self.gentx_hash, self.share_info['segwit_data']['txid_merkle_link'] if segwit_activated else self.merkle_link)
        self.header = dict(self.min_header, merkle_root=merkle_root)
        self.pow_hash = net.PARENT.POW_FUNC(bitcoin_data.block_header_type.pack(self.header))
        self.hash = self.header_hash = bitcoin_data.hash256(bitcoin_data.block_header_type.pack(self.header))

        */

        if (target.Compare(net->MAX_TARGET) > 0)
        {
            throw std::runtime_error("share target invalid");
        }

        if (pow_hash.Compare(target) > 0)
        {
            throw std::runtime_error("share PoW invalid");
        }

        time_seen = c2pool::dev::timestamp();
    }

    void Share::contents_load(UniValue contents)
    {
        BaseShare::contents_load(contents);
    }

    void PreSegwitShare::contents_load(UniValue contents)
    {
        BaseShare::contents_load(contents);
        if (is_segwit_activated())
            segwit_data = contents["share_info"]["segwit_data"].get_obj();
    }

#define MAKE_SHARE(CLASS)                                                           \
    share_result = make_shared<CLASS>(net, peer_addr, share["contents"].get_obj()); \
    break;

    shared_ptr<BaseShare> load_share(UniValue share, shared_ptr<Network> net, c2pool::libnet::addr peer_addr)
    {
        shared_ptr<BaseShare> share_result;
        int type_version = 0;
        if (share.exists("type"))
        {
            type_version = share["type"].get_int();
        }
        else
        {
            throw std::runtime_error("share data in load_share() without type!");
        }

        switch (type_version)
        {
        case 17:
            MAKE_SHARE(Share) //TODO: TEST
        case 32:
            MAKE_SHARE(PreSegwitShare) //TODO: TEST
        default:
            if (type_version < 17)
                throw std::runtime_error("sent an obsolete share");
            else
                throw std::runtime_error((boost::format("unkown share type: %1") % type_version).str());
            break;
        }

        return share_result;
    }
    #undef MAKE_SHARE
}