#pragma once
// ─────────────────────────────────────────────────────────────────────────
// W6 · journal-writepath leg · STDLIB-ONLY TEST SHIM (NOT a production file).
//
// This header exists ONLY so the SettlementJournal self-check builds and runs
// single-TU with plain `g++ -std=c++20` on the OOM host, WITHOUT pulling in
// v37_engine.hpp / v37_lane_executor.hpp / leveldb. It reproduces — byte- and
// behaviour-faithfully — the exact W4 surfaces the journal CALLS:
//
//   ::v37::{ChainId,u64,bytes32,sha256d}   (from src/sharechain/v37/*.hpp)
//   c2pool::v37n::settle::SettleHW         (w4_settlement.hpp:258-310, VERBATIM)
//   c2pool::v37n::settle::OwedLedger       (w4_settlement.hpp:352-546, VERBATIM
//                                           mutators + getters used by W6)
//   c2pool::v37n::settle::CutToken         (w4_settlement.hpp:232-246, VERBATIM)
//
// The PRODUCTION w6_journal.hpp includes the REAL <c2pool/v37/w4_settlement.hpp>
// instead of this shim (compile-guard W6_JOURNAL_STDLIB_TEST). The journal code
// is written ONCE against the settle:: names and compiles unchanged against
// either. W6 does NOT edit w4_settlement.hpp — it is fenced (§7.2); this file
// is a private test double that mirrors it, never shipped in place of it.
//
// The ONLY deliberate divergence from W4: sha256d here is a deterministic
// non-cryptographic 32-byte digest (crypto sha256 is not stdlib). Every W6
// self-check claim is an EQUALITY of digests across replay of the SAME ledger,
// so a deterministic mixing digest is sufficient and faithful; the production
// build uses the real ::v37::sha256d.
// ─────────────────────────────────────────────────────────────────────────

#include <algorithm>      // std::sort (owed_digest below); g++-15 no longer
                          // pulls it in transitively via <set>
#include <array>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace v37 {

using u64     = std::uint64_t;
using ChainId = std::uint32_t;                       // v37_roundabout.hpp:18
using bytes32 = std::array<std::uint8_t, 32>;        // v37_hash.hpp:16

// Test stand-in for ::v37::sha256d — deterministic, order-sensitive, 32 bytes.
// (Real build binds the crypto sha256d from v37_hash.hpp.)
inline bytes32 sha256d(const std::vector<std::uint8_t>& v) {
    // A pair of independent 64-bit FNV-1a lanes expanded to 32 bytes; enough
    // for the "same events → same digest" equality the W6 tests assert.
    std::uint64_t a = 1469598103934665603ull;
    std::uint64_t b = 1099511628211ull;
    for (std::size_t i = 0; i < v.size(); ++i) {
        a ^= v[i];          a *= 1099511628211ull;
        b += v[i] + 1u;     b *= 1469598103934665603ull;
        b ^= (b >> 29);
    }
    bytes32 out{};
    for (int i = 0; i < 8; ++i) out[i]      = std::uint8_t((a >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i) out[8 + i]  = std::uint8_t((b >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i) out[16 + i] = std::uint8_t(((a ^ b) >> (8 * i)) & 0xff);
    for (int i = 0; i < 8; ++i) out[24 + i] = std::uint8_t(((a + b) >> (8 * i)) & 0xff);
    return out;
}

// ── MMR double for the owed-event record log ──────────────────────────────
// Mirrors ::v37::PeakSet + the binary-counter append + peak bagging of
// v37_lane.hpp. The PRODUCTION ledger does NOT contain this code: it calls the
// shipped ::v37::Lane statics through c2pool/v37/record_log.hpp. This double
// exists for the same reason sha256d above does — the stdlib self-check builds
// single-TU with plain g++ and must not pull in the consensus tree (and cannot,
// since this file already binds a non-crypto ::v37::sha256d, which would clash
// with the real one). Every W6 claim over it is an EQUALITY across replay of
// the same events, so a faithful structure over a deterministic digest is
// sufficient; the real root is pinned by the production KAT instead.
struct PeakSet {
    std::vector<bytes32> peaks;
    u64 leaf_count = 0;
    bool operator==(const PeakSet&) const = default;
};
inline bytes32 shim_leaf_hash(const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> b;
    b.reserve(payload.size() + 1);
    b.push_back(0x00);
    b.insert(b.end(), payload.begin(), payload.end());
    return sha256d(b);
}
inline bytes32 shim_interior_hash(const bytes32& l, const bytes32& r) {
    std::vector<std::uint8_t> b;
    b.reserve(65);
    b.push_back(0x01);
    b.insert(b.end(), l.begin(), l.end());
    b.insert(b.end(), r.begin(), r.end());
    return sha256d(b);
}
inline void shim_mmr_append(PeakSet& ps, const bytes32& leaf) {
    bytes32 h = leaf;
    u64 n = ps.leaf_count;
    while (n & 1) {
        h = shim_interior_hash(ps.peaks.back(), h);
        ps.peaks.pop_back();
        n >>= 1;
    }
    ps.peaks.push_back(h);
    ps.leaf_count += 1;
}
inline bytes32 shim_mmr_bag(const std::vector<bytes32>& peaks) {
    bytes32 r{};
    if (peaks.empty()) return r;
    r = peaks.back();
    for (std::size_t i = peaks.size() - 1; i-- > 0;)
        r = shim_interior_hash(peaks[i], r);
    return r;
}

} // namespace v37

namespace c2pool::v37n::settle {

using ::v37::u64;
using ::v37::bytes32;

// ── CutToken — VERBATIM from w4_settlement.hpp:232-246 ────────────────────
struct CutToken {
    ::v37::ChainId chain = 0;
    u64  incarnation = 0;
    u64  version = 0;
    u64  next_pos = 0;
    bytes32 spine_digest{};
    u64  ledger_seq = 0;
    bytes32 owed_digest{};
    u64  hw_height = 0;
    bytes32 hw_tip{};
    bool operator==(const CutToken&) const = default;
};

// ── SettleHW — VERBATIM from w4_settlement.hpp:258-310 ────────────────────
struct SettleHW {
    u64     hw_height = 0;
    bytes32 hw_tip{};
    u64     ledger_seq = 0;
    u64     refused = 0;

    bool advance(u64 height, const bytes32& tip) {
        if (height < hw_height) { ++refused; return false; }
        hw_height = height;
        hw_tip = tip;
        return true;
    }
    bool admit_candidate_height(u64 candidate_height) {
        if (candidate_height < hw_height) { ++refused; return false; }
        return true;
    }
    std::string serialize() const {
        std::string s;
        auto put_u64 = [&](u64 x) {
            for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
        };
        put_u64(hw_height);
        s.append(reinterpret_cast<const char*>(hw_tip.data()), hw_tip.size());
        put_u64(ledger_seq);
        put_u64(refused);
        return s;
    }
    static SettleHW deserialize(const std::string& s) {
        SettleHW hw;
        std::size_t o = 0;
        auto get_u64 = [&]() {
            u64 x = 0;
            for (int i = 0; i < 8; ++i)
                x |= u64(std::uint8_t(s[o++])) << (8 * i);
            return x;
        };
        hw.hw_height = get_u64();
        for (std::size_t i = 0; i < hw.hw_tip.size(); ++i)
            hw.hw_tip[i] = std::uint8_t(s[o++]);
        hw.ledger_seq = get_u64();
        hw.refused = get_u64();
        return hw;
    }
};

// ── the owed-event leaf rule, mirroring c2pool/v37/owed_event_log.hpp ─────
// Same tag, same field order, same normalization; the digest underneath is the
// shim's deterministic stand-in (see the note on ::v37::sha256d above).
namespace shimleaf {
using ::v37::bytes32;
using ::v37::u64;
using Amounts = std::map<bytes32, long long>;
enum EvKind : std::uint8_t { EV_FOUND = 1, EV_FINALIZE = 2, EV_ORPHAN = 3 };
inline void put_u32(std::vector<std::uint8_t>& b, std::uint32_t x) {
    for (int i = 0; i < 4; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
inline void put_u64(std::vector<std::uint8_t>& b, u64 x) {
    for (int i = 0; i < 8; ++i) b.push_back(std::uint8_t((x >> (8 * i)) & 0xff));
}
inline void put_amap(std::vector<std::uint8_t>& b, const Amounts& m) {
    std::uint32_t n = 0;
    for (const auto& [k, v] : m) { (void)k; if (v != 0) ++n; }
    put_u32(b, n);
    for (const auto& [k, v] : m) {
        if (v == 0) continue;
        b.insert(b.end(), k.begin(), k.end());
        put_u64(b, static_cast<u64>(v));
    }
}
inline std::vector<std::uint8_t> payload(std::uint8_t evkind, const std::string& bid,
                                         u64 bin_height, const Amounts& credit,
                                         const Amounts& payout, const Amounts& settled) {
    std::vector<std::uint8_t> p;
    const char tag[4] = {'V', '3', '7', 'L'};
    p.insert(p.end(), tag, tag + 4);
    p.push_back(evkind);
    put_u32(p, static_cast<std::uint32_t>(bid.size()));
    p.insert(p.end(), bid.begin(), bid.end());
    put_u64(p, bin_height);
    put_amap(p, credit);
    put_amap(p, payout);
    put_amap(p, settled);
    return p;
}
} // namespace shimleaf

// ── OwedLedger — mutators + getters W6 calls, VERBATIM from :352-546 ──────
class OwedLedger {
public:
    using Amounts = std::map<bytes32, long long>;

    explicit OwedLedger(::v37::ChainId chain) : m_chain(chain) {}

    ::v37::ChainId chain() const { return m_chain; }
    u64 ledger_seq() const { return m_seq; }

    void on_block_found(const std::string& bid, const Amounts& credit,
                        const Amounts& payout) {
        if (m_pending.count(bid) || m_settled.count(bid)) return;
        Pending p;
        for (const auto& [k, v] : credit) if (v != 0) p.credit[k] = v;
        for (const auto& [k, v] : payout) if (v != 0) p.payout[k] = v;
        auto ins = m_pending.emplace(bid, std::move(p));
        bump(shimleaf::payload(shimleaf::EV_FOUND, bid, 0,
                               ins.first->second.credit, ins.first->second.payout, {}));
    }
    void on_block_finalized(const std::string& bid, u64 bin_height) {
        auto it = m_pending.find(bid);
        if (it == m_pending.end()) return;
        for (const auto& [k, v] : it->second.credit) m_finalW[k] += v;
        for (const auto& [k, v] : it->second.payout) m_finalW[k] -= v;
        m_pending.erase(it);
        m_settled.insert(bid);
        rearm_first_eligible(bin_height);
        bump(shimleaf::payload(shimleaf::EV_FINALIZE, bid, bin_height, {}, {}, {}));
    }
    void on_block_orphaned(const std::string& bid, const Amounts& settled_payout) {
        auto it = m_pending.find(bid);
        if (it != m_pending.end()) {
            m_pending.erase(it);
            bump(shimleaf::payload(shimleaf::EV_ORPHAN, bid, 0, {}, {}, {}));
            return;
        }
        if (m_settled.count(bid)) {
            long long residual = 0;
            for (const auto& [k, v] : settled_payout) residual += v;
            if (residual > 0) {
                m_residual += residual;
                m_residual_events.push_back({bid, residual});
            }
            bump(shimleaf::payload(shimleaf::EV_ORPHAN, bid, 0, {}, {}, settled_payout));
        }
    }
    long long effective_owed(const bytes32& k) const {
        long long e = 0;
        auto it = m_finalW.find(k);
        if (it != m_finalW.end()) e = it->second;
        for (const auto& [bid, p] : m_pending) {
            auto pit = p.payout.find(k);
            if (pit != p.payout.end()) e -= pit->second;
        }
        return e;
    }
    Amounts effective_owed_all() const {
        std::set<bytes32> keys;
        for (const auto& [k, v] : m_finalW) { (void)v; keys.insert(k); }
        for (const auto& [bid, p] : m_pending)
            for (const auto& [k, v] : p.payout) { (void)v; keys.insert(k); }
        Amounts out;
        for (const auto& k : keys) out[k] = effective_owed(k);
        return out;
    }
    bytes32 owed_digest() const {
        std::vector<std::pair<bytes32, long long>> rows(m_finalW.begin(),
                                                        m_finalW.end());
        std::sort(rows.begin(), rows.end(),
                  [](const auto& a, const auto& b) { return a.first < b.first; });
        std::vector<std::uint8_t> pre;
        const char tag[4] = {'V', '3', '7', 'O'};
        pre.insert(pre.end(), tag, tag + 4);
        for (const auto& [k, w] : rows) {
            if (w == 0) continue;
            pre.insert(pre.end(), k.begin(), k.end());
            std::uint64_t uw = static_cast<std::uint64_t>(w);
            for (int i = 0; i < 8; ++i) pre.push_back((uw >> (8 * i)) & 0xff);
            u64 fe = 0;
            auto it = m_first_eligible.find(k);
            if (it != m_first_eligible.end()) fe = it->second;
            for (int i = 0; i < 8; ++i) pre.push_back((fe >> (8 * i)) & 0xff);
        }
        return ::v37::sha256d(pre);
    }
    long long residual_total() const { return m_residual; }
    const std::vector<std::pair<std::string, long long>>& residual_events()
        const { return m_residual_events; }
    bool is_settled(const std::string& bid) const {
        return m_settled.count(bid) != 0;
    }
    bool is_pending(const std::string& bid) const {
        return m_pending.count(bid) != 0;
    }
    std::size_t pending_count() const { return m_pending.size(); }
    const Amounts& finalW() const { return m_finalW; }

    // ── owed-event record log surface W6 calls (mirrors the real ledger) ──
    bytes32 owed_event_mmr_root() const { return ::v37::shim_mmr_bag(m_evpeaks.peaks); }
    u64 owed_event_leaf_count() const { return m_evpeaks.leaf_count; }
    const ::v37::PeakSet& owed_event_peaks() const { return m_evpeaks; }
    bool owed_event_log_consistent() const { return m_evpeaks.leaf_count == m_seq; }

private:
    struct Pending { Amounts credit; Amounts payout; };
    // Same shape as the real ledger: the ONLY seq advance, and it cannot
    // advance without minting exactly one record-log leaf.
    void bump(const std::vector<std::uint8_t>& leaf_payload) {
        ::v37::shim_mmr_append(m_evpeaks, ::v37::shim_leaf_hash(leaf_payload));
        ++m_seq;
    }
    void rearm_first_eligible(u64 bin_height) {
        for (const auto& [k, e] : effective_owed_all()) {
            if (e > 0) {
                if (!m_first_eligible.count(k)) m_first_eligible[k] = bin_height;
            } else {
                m_first_eligible.erase(k);
            }
        }
    }
    ::v37::ChainId m_chain;
    u64 m_seq = 0;
    std::map<std::string, Pending> m_pending;
    std::set<std::string> m_settled;
    std::map<bytes32, u64> m_first_eligible;
    Amounts m_finalW;
    long long m_residual = 0;
    std::vector<std::pair<std::string, long long>> m_residual_events;
    ::v37::PeakSet m_evpeaks;                 // owed-event record log (double)
};

} // namespace c2pool::v37n::settle
