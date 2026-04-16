#pragma once

// Dash share chain types: ShareType variant, ShareIndex, ShareChain.
// Uses the generic sharechain infrastructure from c2pool/sharechain/.
// Only v16 shares exist for Dash.

#include "share.hpp"
#include "share_types.hpp"

#include <sharechain/share.hpp>
#include <sharechain/sharechain.hpp>
#include <core/target_utils.hpp>

#include <chrono>

namespace dash
{

// ── Formatter for v16 share serialization ────────────────────────────────────

struct DashFormatter
{
    // Formatter for v16 share serialization via ShareVariants.
    // Called by ShareVariants::Serialize/Unserialize.
    template <typename StreamType, typename ShareT>
    static void Write(StreamType& os, const ShareT* share)
    {
        // TODO: implement full v16 wire serialization
        // For now, serialize key fields
        os << share->m_min_header;
    }

    template <typename StreamType, typename ShareT>
    static void Read(StreamType& is, ShareT* share)
    {
        // TODO: implement full v16 wire deserialization
        // For now, deserialize key fields
        is >> share->m_min_header;
    }
};

// ── ShareType: variant containing only v16 ───────────────────────────────────
// For Dash, there's only one share version (v16).

using ShareType = chain::ShareVariants<DashFormatter, DashShare>;

// ── Load share from wire format ──────────────────────────────────────────────

inline ShareType load_share(chain::RawShare& rshare, NetService peer_addr)
{
    auto stream = rshare.contents.as_stream();
    auto share = ShareType::load(rshare.type, stream);
    // TODO: set peer_addr on the share
    return share;
}

// ── ShareHasher ──────────────────────────────────────────────────────────────

struct ShareHasher
{
    size_t operator()(const uint256& hash) const
    {
        return hash.GetLow64();
    }
};

// ── ShareIndex: per-share metadata in the chain ──────────────────────────────

class ShareIndex : public chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>
{
    using base_index = chain::ShareIndex<uint256, ShareType, ShareHasher, ShareIndex>;

public:
    uint288 work;
    uint288 min_work;
    int64_t time_seen{0};

    ShareIndex() : base_index(), work(0), min_work(0) {}

    template <typename ShareT> ShareIndex(ShareT* share) : base_index(share)
    {
        work = chain::target_to_average_attempts(chain::bits_to_target(share->m_bits));
        min_work = chain::target_to_average_attempts(chain::bits_to_target(share->m_max_bits));
        time_seen = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
    }
};

// ── ShareChain ───────────────────────────────────────────────────────────────

struct ShareChain : chain::ShareChain<ShareIndex>
{
};

} // namespace dash
