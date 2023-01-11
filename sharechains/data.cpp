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
        RefType ref_type(std::vector<unsigned char>(net->IDENTIFIER, net->IDENTIFIER+net->IDENTIFIER_LENGTH), share_data, share_info, segwit_data);

        PackStream ref_type_packed;
        ref_type_packed << ref_type;

        auto hash_ref_type = coind::data::hash256(ref_type_packed, true);
        IntType(256) _check_merkle_link(coind::data::check_merkle_link(hash_ref_type, ref_merkle_link));

        PackStream result;
        result << _check_merkle_link;

        return result;
    }
}