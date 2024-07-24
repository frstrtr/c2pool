#pragma once

#include <sharechain/sharechain.hpp>
#include <sharechain/share.hpp>
#include <core/netaddress.hpp>
#include <core/uint256.hpp>

namespace ltc
{

template <int64_t Version>
struct BaseShare : chain::BaseShare<uint256, Version>
{
    NetService peer_addr;

    BaseShare() {}
    BaseShare(const uint256& hash, const uint256& prev_hash) : chain::BaseShare<uint256, Version>(hash, prev_hash) {}

// protected:
//     SERIALIZE_METHODS(BaseShare<Version>) { READWRITE(obj.m_hash, obj.m_prev_hash, obj.peer_addr); }
};

struct Share : BaseShare<17>
{
    Share() {}
    Share(const uint256& hash, const uint256& prev_hash) : BaseShare<17>(hash, prev_hash) {}

    SERIALIZE_METHODS(Share) { /*READWRITE(AsBase<BaseShare<17>>(obj));*/READWRITE(obj.m_hash, obj.m_prev_hash, obj.peer_addr); }
};

using ShareType = chain::ShareVariants<Share>;

template <typename StreamType>
inline ShareType load(int64_t version, StreamType& is, NetService peer_addr)
{
    auto share = ShareType::load(version, is);
    share.ACTION({ obj->peer_addr = peer_addr; });
    return share;
}

struct ShareHasher
{
    // this used to call `GetCheapHash()` in uint256, which was later moved; the
    // cheap hash function simply calls ReadLE64() however, so the end result is
    // identical
    size_t operator()(const uint256& hash) const 
    {
        return hash.GetLow64();
    }
};

class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    ShareIndex() : base_index() {}
    template <typename ShareT> ShareIndex(ShareT* share) : base_index(share)
    {

    }

protected:
    void add(ShareIndex* index) override
    {
        // plus
    }

    void sub(ShareIndex* index) override
    {
        // minus
    }
};

struct ShareChain : chain::ShareChain<ShareIndex>
{

};

} // namespace ltc

