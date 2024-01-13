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
#include "share_builder.h"

class ShareTracker;

namespace shares
{
	bool is_segwit_activated(int version, c2pool::Network* net);

	uint256 check_hash_link(shared_ptr<::HashLinkType> hash_link, std::vector<unsigned char> data, std::vector<unsigned char> const_ending = {});

    shared_ptr<::HashLinkType> prefix_to_hash_link(std::vector<unsigned char> prefix, std::vector<unsigned char> const_ending = {});

    PackStream get_ref_hash(uint64_t version, c2pool::Network* net, types::ShareData &share_data, types::ShareInfo &share_info, coind::data::MerkleLink ref_merkle_link, std::optional<types::SegwitData> segwit_data = nullopt);
}

// pack_share<--->load_share
ShareType inline load_share(PackStream &stream, c2pool::Network* net, const NetAddress& peer_addr)
{
    PackedShareData packed_share;
    try
    {
        stream >> packed_share;
    } catch (packstream_exception &ex)
    {
        throw std::invalid_argument((boost::format("Failed unpack PackedShareData in load_share: [%1%]") % ex.what()).str());// << ex.what();
    }

    PackStream _stream(packed_share.contents.value);

    ShareDirector director(net);
    switch (packed_share.type.value)
    {
        case 17:
//			return director.make_share(packed_share.type.value, peer_addr, _stream);
        case 33:
            return director.make_preSegwitShare(packed_share.type.value, peer_addr, _stream);
        case 34:
        case 35:
            return director.make_segwitMiningShare(packed_share.type.value, peer_addr, _stream);
        default:
            if (packed_share.type.value < 17)
                throw std::runtime_error("sent an obsolete share");
            else
                throw std::runtime_error((boost::format("unkown share type: %1%") % packed_share.type.value).str());
            break;
    }
}