#pragma once
// V37 MRR roundabout — the multichain container (§3, §6.3, §7).
// Lanes are independent; the only cross-lane state is the global miner
// intern table (normalized PayoutDescriptor identity -> dense u32 id) and
// the directory. Adding/removing a lane never restructures another lane.

#include <cstdint>
#include <map>
#include <memory>
#include <stdexcept>
#include <vector>

#include "v37_descriptor.hpp"
#include "v37_lane.hpp"

namespace v37 {

using ChainId = std::uint32_t;

class MinerIntern {
public:
    // Identity = SHA256d of the identity preimage (exact (kind,payload) of
    // `pay`, §6.3 rule 3 / S-1). Returns a dense id, stable for the session.
    MinerId intern(const PayoutDescriptor& d) {
        auto key = d.identity_preimage();
        auto it = m_ids.find(key);
        if (it != m_ids.end()) return it->second;
        MinerId id = static_cast<MinerId>(m_refs.size());
        m_ids.emplace(std::move(key), id);
        m_refs.push_back(d.pay);
        m_keys.push_back(d.identity_key());
        return id;
    }
    const ScriptRef& pay_ref(MinerId id) const { return m_refs.at(id); }
    // Canonical identity key (S-3): the consensus-stable name of a miner.
    // Intern ids are node-local and MUST NOT appear in any consensus bytes.
    const bytes32& key(MinerId id) const { return m_keys.at(id); }
    std::size_t size() const { return m_refs.size(); }

private:
    std::map<std::vector<std::uint8_t>, MinerId> m_ids;
    std::vector<ScriptRef> m_refs;
    std::vector<bytes32> m_keys;
};

class Roundabout {
public:
    // O(1) directory append; no other lane is touched (§7).
    Lane& add_lane(ChainId chain, const LaneParams& p) {
        auto [it, fresh] = m_lanes.emplace(chain, nullptr);
        if (!fresh) throw std::invalid_argument("v37: lane already exists");
        it->second = std::make_unique<Lane>(p);
        return *it->second;
    }
    void remove_lane(ChainId chain) { m_lanes.erase(chain); }
    Lane* lane(ChainId chain) {
        auto it = m_lanes.find(chain);
        return it == m_lanes.end() ? nullptr : it->second.get();
    }
    const Lane* lane(ChainId chain) const {
        auto it = m_lanes.find(chain);
        return it == m_lanes.end() ? nullptr : it->second.get();
    }
    std::size_t lane_count() const { return m_lanes.size(); }
    MinerIntern& miners() { return m_miners; }

    // Push a share: validates the descriptor under V37.0 rules (attribution
    // MUST be absent), interns identity, forwards to the lane.
    MinerId push(ChainId chain, const PayoutDescriptor& d, u64 w_raw,
                 std::uint32_t flags) {
        if (!d.valid(false))
            throw std::invalid_argument("v37: invalid descriptor (V37.0 rules)");
        Lane* l = lane(chain);
        if (!l) throw std::invalid_argument("v37: unknown chain");
        MinerId id = m_miners.intern(d);
        l->push(id, w_raw, flags);
        return id;
    }

    // Lane digest with the canonical identity resolver (the only correct way
    // to produce the consensus-committed digest; Lane::digest is generic so
    // tests can inject resolvers, but production goes through here).
    bytes32 lane_digest(ChainId chain) const {
        const Lane* l = lane(chain);
        if (!l) throw std::invalid_argument("v37: unknown chain");
        return l->digest([this](MinerId m) { return m_miners.key(m); });
    }

    // Cross-lane per-miner aggregate of decayed weights: integer-keyed merge
    // (§7). Display/aggregation only — never consensus (OQ-8: normalization
    // happens at serialization, not here; values stay chain-local units).
    std::map<MinerId, U256> aggregate_decayed() const {
        std::map<MinerId, U256> out;
        for (const auto& [c, l] : m_lanes)
            for (const auto& [m, w] : l->payout_map()) out[m] += w;
        return out;
    }

private:
    std::map<ChainId, std::unique_ptr<Lane>> m_lanes;
    MinerIntern m_miners;
};

} // namespace v37
