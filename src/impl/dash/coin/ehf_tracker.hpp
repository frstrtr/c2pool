// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// EHF signal tracker: which masternode hard-fork signals (special tx type 7)
/// the active chain carries, and from which height we have seen every body.
///
/// Ported from Dash Core v24.0.0 src/evo/mnhftx.cpp:
///   CMNHFManager::ProcessBlock     a block's new signals land at its height
///   CMNHFManager::GetSignalsStage  a signal is dropped ("expired") when the
///                                  median time past of its own block is
///                                  before the start time of a deployment that
///                                  uses the same bit
///   VersionBitsConditionChecker::SignalHeight
///                                  the mined height of the staged signal for
///                                  the bit, INT_MAX if none
/// A block carrying a signal for a bit that is already staged is invalid in
/// Core (bad-mnhf-duplicate), so the chain carries at most one unexpired
/// signal per bit. Signatures are not checked: the tracker only reads blocks
/// Core accepted.
///
/// Coverage. A cold start rescans bodies from a fixed anchor (operator
/// decision O7, DashDeploymentParams::ehf_anchor_height). The tracker keeps
/// the contiguous high-water mark of bodies it has seen from the anchor; the
/// signal height is only exact for a prev block inside that range. Outside
/// it the deployment status (deployment_status.hpp) reasons with bounds or
/// reports UNKNOWN. Reorgs rewind the high-water mark to the fork, found by
/// comparing the recorded hashes with the chain view.
///
/// Persistence: a small text file (ehf_signals.v1) in the coin data dir.

#include <impl/dash/coin/block_producer.hpp>   // block_body_binds_to_header
#include <impl/dash/coin/dash_deployments.hpp>
#include <impl/dash/coin/versionbits.hpp>
#include <impl/dash/coin/vendor/mnhftx.hpp>
#include <impl/dash/crypto/hash_x11.hpp>

#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstdio>
#include <algorithm>
#include <fstream>
#include <functional>
#include <limits>
#include <memory>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct EhfSignal
{
    uint8_t  bit{0};
    uint32_t mined_height{0};
    uint256  block_hash;
    int64_t  block_mtp{0};   ///< median time past of the signal's own block

    bool operator==(const EhfSignal& o) const
    {
        return bit == o.bit && mined_height == o.mined_height && block_hash == o.block_hash
            && block_mtp == o.block_mtp;
    }
};

class EhfSignalTracker
{
public:
    /// Recorded hashes kept for reorg detection (Dash reorgs are shallow:
    /// chainlocks). A fork below this depth rewinds coverage to the anchor.
    static constexpr size_t kHashWindow = 2048;

    EhfSignalTracker(DashNetwork net, VbChainFn chain)
        : EhfSignalTracker(dash_deployment_params(net), std::move(chain))
    {}
    /// `params` must outlive the tracker (the static table does).
    EhfSignalTracker(const DashDeploymentParams& params, VbChainFn chain)
        : m_params(params), m_chain(std::move(chain))
    {}

    DashNetwork network() const { return m_params.network; }
    uint32_t anchor() const { return m_params.ehf_anchor_height; }

    /// Contiguous high-water mark of scanned bodies, or nullopt when nothing
    /// from the anchor on has been scanned.
    std::optional<uint32_t> scanned_to() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_scanned_to;
    }

    /// The next height the cold-start rescan must fetch (anchor first).
    uint32_t next_needed_height() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_scanned_to ? *m_scanned_to + 1 : m_params.ehf_anchor_height;
    }

    /// Every body in [anchor, prev_height] has been scanned on this chain.
    bool covers(int64_t prev_height) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (prev_height < static_cast<int64_t>(m_params.ehf_anchor_height)) return true;
        return m_scanned_to && static_cast<int64_t>(*m_scanned_to) >= prev_height;
    }

    /// The highest height c such that every body in [anchor, c] was scanned
    /// AND is still on the chain view: the deepest recorded hash at or below
    /// the high-water mark that matches the chain (a header-chain switch that
    /// has not yet delivered a body of the new branch cuts it back here, not
    /// only when the next body arrives). anchor - 1 when nothing counts.
    int64_t verified_coverage() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        const int64_t none = static_cast<int64_t>(m_params.ehf_anchor_height) - 1;
        if (!m_scanned_to) return none;
        for (auto it = m_hashes.rbegin(); it != m_hashes.rend(); ++it) {
            auto b = m_chain(it->first);
            if (b && b->hash == it->second) return it->first;
        }
        return none;
    }

    /// Feed one active-chain block body. Returns true when it extended
    /// coverage. Bodies below the anchor and out-of-order bodies (a gap above
    /// the high-water mark) are ignored; a body at or below the mark whose
    /// hash differs from the recorded one rewinds to the fork first.
    bool connect_block(const BlockType& block, uint32_t height, const uint256& hash)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        if (height < m_params.ehf_anchor_height) return false;
        // Only an active-chain body counts: a fork body (or one whose header
        // the chain view does not have) is ignored.
        {
            auto cb = m_chain(height);
            if (!cb || cb->hash != hash) return false;
        }
        if (m_scanned_to && height <= *m_scanned_to) {
            auto it = m_hashes.find(height);
            if (it == m_hashes.end() || it->second == hash) return false;   // already covered
            rewind_locked(static_cast<int64_t>(height) - 1);   // our record is off-chain now
        }
        const uint32_t want = m_scanned_to ? *m_scanned_to + 1 : m_params.ehf_anchor_height;
        if (height != want) return false;
        // Prev-link check against the recorded parent.
        if (m_scanned_to) {
            auto pit = m_hashes.find(*m_scanned_to);
            if (pit != m_hashes.end() && pit->second != block.m_previous_block) {
                rewind_to_chain_locked();
                return false;
            }
        }
        std::vector<uint8_t> bits;
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            if (auto b = extract_ehf_signal(block.m_txs[i])) bits.push_back(*b);
        }
        if (!bits.empty()) {
            const auto mtp = vb_median_time_past(m_chain, height);
            if (!mtp) return false;   // cannot date the signal: do not advance
            for (uint8_t b : bits) {
                EhfSignal s;
                s.bit = b;
                s.mined_height = height;
                s.block_hash = hash;
                s.block_mtp = *mtp;
                m_signals.push_back(s);
            }
            m_dirty = true;
        }
        m_scanned_to = height;
        m_hashes[height] = hash;
        trim_hashes_locked();
        if ((height % 1000) == 0) m_dirty = true;
        return true;
    }

    /// Re-validate the recorded state against the chain view (after a reorg
    /// or a restart): coverage is cut back to the deepest recorded height
    /// whose hash still matches. Returns the new high-water mark.
    std::optional<uint32_t> reconcile_with_chain()
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        rewind_to_chain_locked();
        return m_scanned_to;
    }

    /// SignalHeight for `bit` as of prev_height: the mined height of the
    /// unexpired signal at or below prev_height, kNoSignalHeight if none.
    /// Only exact when covers(prev_height).
    int64_t signal_height(uint8_t bit, int64_t prev_height) const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        int64_t best = kNoSignalHeight;
        for (const auto& s : m_signals) {
            if (s.bit != bit) continue;
            if (static_cast<int64_t>(s.mined_height) > prev_height) continue;
            if (expired(s)) continue;
            if (static_cast<int64_t>(s.mined_height) < best) best = s.mined_height;
        }
        return best;
    }

    std::vector<EhfSignal> signals() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_signals;
    }

    bool dirty() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_dirty;
    }

    // ── persistence (ehf_signals.v1) ────────────────────────────────────
    std::string serialize() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        std::ostringstream o;
        o << "ehf_signals v1 " << static_cast<int>(m_params.network) << "\n";
        o << "anchor " << m_params.ehf_anchor_height << "\n";
        if (m_scanned_to) {
            auto it = m_hashes.find(*m_scanned_to);
            o << "scanned " << *m_scanned_to << " "
              << (it != m_hashes.end() ? it->second.GetHex() : uint256().GetHex()) << "\n";
        }
        for (const auto& s : m_signals)
            o << "signal " << static_cast<int>(s.bit) << " " << s.mined_height << " "
              << s.block_hash.GetHex() << " " << s.block_mtp << "\n";
        return o.str();
    }

    /// Load a serialized state. A file for another network or anchor is
    /// refused (returns false, state unchanged). The loaded state is then
    /// reconciled with the chain view: a stale tip hash or a signal block no
    /// longer on the chain cuts coverage back (see reconcile_with_chain).
    bool deserialize(const std::string& text)
    {
        std::istringstream in(text);
        std::string tag, ver;
        int net = -1;
        if (!(in >> tag >> ver >> net) || tag != "ehf_signals" || ver != "v1") return false;
        if (net != static_cast<int>(m_params.network)) return false;
        std::optional<uint32_t> scanned;
        uint256 scanned_hash;
        std::vector<EhfSignal> sigs;
        std::string key;
        while (in >> key) {
            if (key == "anchor") {
                uint32_t a;
                if (!(in >> a) || a != m_params.ehf_anchor_height) return false;
            } else if (key == "scanned") {
                uint32_t h; std::string hx;
                if (!(in >> h >> hx)) return false;
                scanned = h;
                scanned_hash.SetHex(hx);
            } else if (key == "signal") {
                int bit; uint32_t h; std::string hx; int64_t mtp;
                if (!(in >> bit >> h >> hx >> mtp) || bit < 0 || bit >= kVersionBitsNumBits) return false;
                EhfSignal s;
                s.bit = static_cast<uint8_t>(bit);
                s.mined_height = h;
                s.block_hash.SetHex(hx);
                s.block_mtp = mtp;
                sigs.push_back(s);
            } else {
                return false;
            }
        }
        std::lock_guard<std::mutex> lk(m_mutex);
        m_signals = std::move(sigs);
        m_scanned_to = scanned;
        m_hashes.clear();
        if (scanned) m_hashes[*scanned] = scanned_hash;
        rewind_to_chain_locked();
        m_dirty = false;
        return true;
    }

    bool save(const std::string& path)
    {
        const std::string text = serialize();
        const std::string tmp = path + ".tmp";
        {
            std::ofstream f(tmp, std::ios::trunc);
            if (!f) return false;
            f << text;
            if (!f) return false;
        }
        if (std::rename(tmp.c_str(), path.c_str()) != 0) return false;
        std::lock_guard<std::mutex> lk(m_mutex);
        m_dirty = false;
        return true;
    }

    bool load(const std::string& path)
    {
        std::ifstream f(path);
        if (!f) return false;
        std::ostringstream ss;
        ss << f.rdbuf();
        return deserialize(ss.str());
    }

private:
    void trim_hashes_locked()
    {
        while (m_hashes.size() > kHashWindow) m_hashes.erase(m_hashes.begin());
    }

    bool expired(const EhfSignal& s) const
    {
        // GetSignalsStage: expired when the signal block's MTP is before the
        // start time of ANY deployment using this bit (bit reuse).
        for (const auto& d : m_params.deployments)
            if (d.bit == s.bit && s.block_mtp < d.nStartTime) return true;
        return false;
    }

    void rewind_locked(int64_t to_height)
    {
        if (to_height < static_cast<int64_t>(m_params.ehf_anchor_height)) {
            m_scanned_to.reset();
        } else if (m_scanned_to && static_cast<int64_t>(*m_scanned_to) > to_height) {
            m_scanned_to = static_cast<uint32_t>(to_height);
        }
        std::vector<EhfSignal> keep;
        for (const auto& s : m_signals)
            if (static_cast<int64_t>(s.mined_height) <= to_height) keep.push_back(s);
        if (keep.size() != m_signals.size()) m_dirty = true;
        m_signals.swap(keep);
        for (auto it = m_hashes.begin(); it != m_hashes.end();) {
            if (static_cast<int64_t>(it->first) > to_height) it = m_hashes.erase(it);
            else ++it;
        }
        m_dirty = true;
    }

    /// Cut coverage back to the deepest recorded hash that is still on the
    /// chain view. A recorded signal block that left the chain rewinds below
    /// it. With no matching record at all, coverage restarts at the anchor.
    void rewind_to_chain_locked()
    {
        // Signals first: one whose block is not on the chain any more.
        int64_t limit = m_scanned_to ? static_cast<int64_t>(*m_scanned_to) : -1;
        for (const auto& s : m_signals) {
            auto b = m_chain(s.mined_height);
            if (!b || b->hash != s.block_hash)
                limit = std::min<int64_t>(limit, static_cast<int64_t>(s.mined_height) - 1);
        }
        if (!m_scanned_to) { rewind_locked(limit); return; }
        // The deepest recorded height <= limit whose hash matches the chain
        // (scanned-hash window, then the signal blocks themselves).
        int64_t good = -1;
        for (auto it = m_hashes.rbegin(); it != m_hashes.rend(); ++it) {
            if (static_cast<int64_t>(it->first) > limit) continue;
            auto b = m_chain(it->first);
            if (b && b->hash == it->second) { good = it->first; break; }
        }
        for (const auto& s : m_signals) {
            const int64_t h = s.mined_height;
            if (h > limit || h <= good) continue;
            auto b = m_chain(s.mined_height);
            if (b && b->hash == s.block_hash) good = h;
        }
        if (good < 0) {
            rewind_locked(static_cast<int64_t>(m_params.ehf_anchor_height) - 1);
            return;
        }
        if (good < static_cast<int64_t>(*m_scanned_to)) rewind_locked(good);
    }

    const DashDeploymentParams& m_params;
    VbChainFn                   m_chain;
    mutable std::mutex          m_mutex;
    std::optional<uint32_t>     m_scanned_to;
    std::map<uint32_t, uint256> m_hashes;
    std::vector<EhfSignal>      m_signals;
    bool                        m_dirty{false};
};

/// The binding every rescan body must pass before it can reach the tracker:
/// the X11 hash of its header is the hash we asked for (so the header is the
/// one on our PoW/DGW-validated chain, prev link included) and its merkle
/// root commits to exactly this tx set (block_body_binds_to_header, the same
/// check the live path runs before block_connected, live_feed.hpp). Without
/// it one peer could omit or plant an MNHF signal and so decide the v24
/// state (VERIFY-H0-S0-S1 M1).
inline bool ehf_rescan_body_binds(const uint256& want_hash, const BlockType& block)
{
    if (!block_body_binds_to_header(block)) return false;
    auto packed = ::pack(static_cast<const BlockHeaderType&>(block));
    return dash::crypto::hash_x11(packed.get_span()) == want_hash;
}

/// Cold-start rescan of the EHF tracker from its anchor (operator decision
/// O7), over the coin P2P network (the LAN core node is one of its peers).
///
/// Every body is bound to the header we asked for (ehf_rescan_body_binds)
/// before it is kept; a body that fails is dropped and its height re-asked
/// at the next tick (the request function rotates peers).
///
/// The live feed (block_connected) covers heights from the live floor up: the
/// lowest height the tip-follow path still needs (the payee cursor + 1). The
/// lane fetches only [tracker.next_needed_height(), live_floor - 1], so it
/// never asks for a body the live path wants and may swallow what it asked
/// for (the coin client's body filter). Pure: the coin client, the clock and
/// the chain view are injected, so a KAT drives it with no network.
class EhfRescanLane
{
public:
    static constexpr uint32_t kWindow  = 64;      ///< bodies in flight at most
    static constexpr uint32_t kBatch   = 16;      ///< hashes per getdata
    static constexpr int64_t  kReaskMs = 20'000;  ///< re-ask an unanswered body

    /// Send one getdata for these block hashes; false when no peer took it.
    using RequestFn = std::function<bool(const std::vector<uint256>&)>;
    /// The lowest height the live path still needs (nullopt: not known yet,
    /// the lane stays idle).
    using FloorFn = std::function<std::optional<uint32_t>()>;

    /// Body binding check (tests may inject one; production uses the real
    /// binding, ehf_rescan_body_binds).
    using BodyCheckFn = std::function<bool(const uint256& want_hash, const BlockType&)>;

    EhfRescanLane(std::shared_ptr<EhfSignalTracker> tracker, VbChainFn chain, FloorFn live_floor,
                  RequestFn request, BodyCheckFn check = ehf_rescan_body_binds)
        : m_tracker(std::move(tracker)), m_chain(std::move(chain)),
          m_floor(std::move(live_floor)), m_request(std::move(request)),
          m_check(check ? std::move(check) : BodyCheckFn(ehf_rescan_body_binds))
    {}

    /// Periodic drive (the 3 s service tick): drain what arrived, then keep
    /// the window full. Returns the number of hashes requested.
    size_t tick(int64_t now_ms)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        drain_locked();
        const auto floor = m_floor();
        if (!floor) return 0;
        const uint32_t need = m_tracker->next_needed_height();
        if (need >= *floor) { m_inflight.clear(); m_arrived.clear(); return 0; }
        const uint32_t hi = std::min<uint32_t>(*floor - 1, need + kWindow - 1);
        std::vector<uint256> batch;
        size_t sent = 0;
        auto flush = [&]() {
            if (batch.empty()) return;
            if (m_request(batch)) sent += batch.size();
            batch.clear();
        };
        for (uint32_t h = need; h <= hi; ++h) {
            if (m_arrived.count(h)) continue;
            auto it = m_inflight.find(h);
            if (it != m_inflight.end() && now_ms - it->second.sent_ms < kReaskMs) continue;
            auto b = m_chain(h);
            if (!b) break;
            m_inflight[h] = InFlight{b->hash, now_ms};
            batch.push_back(b->hash);
            if (batch.size() == kBatch) flush();
        }
        flush();
        // Forget asks that fell behind the tracker (the live feed or a
        // reorg moved it).
        for (auto it = m_inflight.begin(); it != m_inflight.end();) {
            if (it->first < need || it->first > hi) it = m_inflight.erase(it);
            else ++it;
        }
        return sent;
    }

    /// The coin client's body filter: true when this lane asked for the body
    /// (it is then consumed here and never reaches the live path). `hash` is
    /// the X11 hash the coin client computed from the received header; the
    /// body is bound to the requested hash again here before it is kept.
    bool on_body(const uint256& hash, const BlockType& block)
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        for (auto it = m_inflight.begin(); it != m_inflight.end(); ++it) {
            if (it->second.hash != hash) continue;
            if (!m_check(it->second.hash, block)) {
                // Forged, mutated or mislabelled: never kept. Re-ask at the
                // next tick (from the next peer of the rotation).
                ++m_rejected;
                if (m_rejected <= 3 || (m_rejected % 100) == 0)
                    LOG_WARNING << "[DASH-V24] EHF rescan body for h=" << it->first << " "
                                << hash.GetHex().substr(0, 16)
                                << " does not bind to its header (merkle root / header hash)"
                                   " -- dropped, re-asking (rejected so far: " << m_rejected << ")";
                it->second.sent_ms = kReaskNow;
                return true;
            }
            m_arrived[it->first] = Arrived{it->second.hash, block};
            m_inflight.erase(it);
            drain_locked();
            return true;
        }
        return false;
    }

    size_t in_flight() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_inflight.size();
    }

    /// Bodies refused by the binding check since start.
    uint64_t rejected() const
    {
        std::lock_guard<std::mutex> lk(m_mutex);
        return m_rejected;
    }

private:
    static constexpr int64_t kReaskNow = std::numeric_limits<int64_t>::min() / 2;

    struct InFlight
    {
        uint256 hash;
        int64_t sent_ms{0};
    };
    struct Arrived
    {
        uint256   hash;    ///< the hash it was requested (and bound) under
        BlockType block;
    };

    void drain_locked()
    {
        for (;;) {
            const uint32_t need = m_tracker->next_needed_height();
            auto it = m_arrived.find(need);
            if (it == m_arrived.end()) break;
            auto b = m_chain(need);
            Arrived a = std::move(it->second);
            m_arrived.erase(it);
            // The chain may have switched since the ask: only a body bound to
            // the block the chain holds at this height counts.
            if (!b || b->hash != a.hash) break;
            if (!m_tracker->connect_block(a.block, need, b->hash)) break;
        }
        const uint32_t need = m_tracker->next_needed_height();
        for (auto it = m_arrived.begin(); it != m_arrived.end();) {
            if (it->first < need) it = m_arrived.erase(it);
            else ++it;
        }
    }

    std::shared_ptr<EhfSignalTracker> m_tracker;
    VbChainFn                         m_chain;
    FloorFn                           m_floor;
    RequestFn                         m_request;
    BodyCheckFn                       m_check;
    mutable std::mutex                m_mutex;
    std::map<uint32_t, InFlight>      m_inflight;
    std::map<uint32_t, Arrived>       m_arrived;
    uint64_t                          m_rejected{0};
};

} // namespace coin
} // namespace dash
