#pragma once

#include <sharechain/sharechain.hpp>
#include <sharechain/share.hpp>
#include <btclibs/uint256.h>

namespace ltc
{

template <int64_t Version>
struct BaseShare : c2pool::chain::BaseShare<uint256, Version>
{
    BaseShare() {}
    BaseShare(const uint256& hash, const uint256& prev_hash) : c2pool::chain::BaseShare<uint256, Version>(hash, prev_hash) {}
};

struct Share : BaseShare<17>
{
    Share() {}
    Share(const uint256& hash, const uint256& prev_hash) : BaseShare<17>(hash, prev_hash) {}
};

using ShareType = c2pool::chain::ShareVariants<Share>;

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

class ShareIndex : public c2pool::chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = c2pool::chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

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

struct ShareChain : c2pool::chain::ShareChain<ShareIndex>
{

};

} // namespace ltc

