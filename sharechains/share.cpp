#include "share.h"

#include <univalue.h>
#include <devcore/logger.h>
#include <devcore/common.h>
#include <devcore/addrStore.h>
#include "tracker.h"
#include <stdexcept>

#include <boost/format.hpp>

namespace c2pool::shares::share
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

    void BaseShare::check(shared_ptr<c2pool::shares::tracker::ShareTracker> tracker /*, TODO: other_txs = None???*/)
    {
        if (timestamp > (c2pool::dev::timestamp() + 600))
        {
            throw std::invalid_argument((boost::format{"Share timestamp is %1% seconds in the future! Check your system clock."} % (timestamp - c2pool::dev::timestamp())).str());
        }

        if (!previous_hash.IsNull()) //TODO: or pack in share_data
        {
            auto previous_share = tracker->get(previous_hash);
            if (tracker->get_height(share_data.previous_hash))
        }
    }

    void BaseShare::contents_load(UniValue contents)
    {
        min_header = contents["min_header"].get_obj();

        auto share_info = contents["share_info"].get_obj();
        auto share_data = share_info["share_data"].get_obj();
        previous_hash.SetHex(share_data.get_str());
        coinbase = share_data["coinbase"].get_str(); //TODO: script str?
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

        for (auto item : share_info["new_transaction_hashes"].getValues()) {
            uint256 tx_hash;
            tx_hash.SetHex(item.get_str());
            new_transaction_hashes.push_back(tx_hash);
        }

        //TODO: transaction_hahs_refs

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

    BaseShare::BaseShare(int VERSION, shared_ptr<Network> _net, addr _peer_addr, UniValue _contents) : SHARE_VERSION(VERSION), net(_net), peer_addr(_peer_addr), contents(_contents)
    {
        //TODO: remove
        // min_header = contents["min_header"].get_obj();
        // //TODO: share_info ?
        // hash_link = contents["hash_link"].get_obj();
        // merkle_link = contents["merkle_link"].get_obj();

        contents_load(contents);

        bool segwit_activated = is_segwit_activated();

        if (!(2 <= coinbase.length() && coinbase.length() <= 100))
        {
            throw std::runtime_error((boost::format("bad coinbase size! %1 bytes") % coinbase.length()).str());
        }

        if (merkle_link.branch.size() > 16)
        {
            //TODO: or (segwit_activated and len(self.share_info['segwit_data']['txid_merkle_link']['branch']) > 16
            //wanna check for segwit
            throw std::runtime_error("merkle branch too long!");
        }

        //TODO: need???  assert not self.hash_link['extra_data'], repr(self.hash_link['extra_data'])

        if (net->net_name == "bitcoin" && absheight > 3927800 && desired_version == 16)
        {
            throw std::runtime_error("This is not a hardfork-supporting share!");
        }

        if (target.Compare(net->MAX_TARGET) > 0)
        {
            throw std::runtime_error("share target invalid");
        }

        if (pow_hash.Compare(target) > 0)
        {
            throw std::runtime_error("share PoW invalid");
        }

        //TODO: time_seen remove???
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
}