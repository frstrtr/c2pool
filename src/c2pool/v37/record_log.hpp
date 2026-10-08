#pragma once
// V37 — GENERIC append-only authenticated RECORD LOG (MMR).
//
// CONSUMER-tree code: it lives here (src/c2pool/v37/), NOT in
// src/sharechain/v37/, which stays the pure header-only consensus module. This
// header adds NO new hash rule and NO second MMR implementation: it CALLS the
// shipped lane MMR statics, so a record log and a lane commit the same bytes
// by construction.
//
// ── WHY IT CALLS THE LANE INSTEAD OF COPYING IT ───────────────────────────
// ::v37::PeakSet is a namespace-level struct (v37_lane.hpp) and
// ::v37::Lane::{mmr_append, mmr_bag, mmr_proof, mmr_verify} + ::v37::Lane::
// MmrProof are PUBLIC statics of the shipped consensus class. So the record
// log holds a ::v37::PeakSet and drives it with the lane's own code:
//   * ONE implementation of the binary-counter append, the peak bagging, the
//     inclusion proof and the stateless verifier — the lane's;
//   * ZERO edits inside src/sharechain/v37 (the consensus wall), so no lane
//     digest, no committed root and no pinned anchor can move because of this
//     header;
//   * a record-log root is byte-for-byte what the same leaves would produce in
//     a lane, because it IS the same code path.
// The ONLY lane routine that is private is Lane::leaf_hash, so the leaf rule
// is mirrored here EXACTLY as w5_coinbase.hpp already mirrors it:
//       leaf     = sha256d(0x00 || payload)
//       interior = sha256d(0x01 || left || right)      <- never re-implemented;
// interiors are hashed only inside Lane::mmr_append / mmr_bag / mmr_proof /
// mmr_verify. KAT-pinned against a hand-computed golden and against the
// w5 StateCommitment mirror.
//
// ── WHAT IT GIVES YOU ─────────────────────────────────────────────────────
//   append(payload)                -> leaf index; peaks advance by the binary
//                                     counter rule
//   root()                         -> the bagged MMR root at the current
//                                     leaf_count (all-zero for an EMPTY log)
//   leaf_count()
//   prove(i) / verify(...)         -> O(log n) inclusion, verified by the
//                                     SHIPPED ::v37::Lane::mmr_verify
//   prove_prefix(n0) / verify_prefix(...)
//                                  -> APPEND-ONLY (consistency) proof: the log
//                                     at leaf_count n1 extends the log that was
//                                     committed at n0, i.e. nothing before n0
//                                     was rewritten. See the note on its shape
//                                     below.
//   serialize() / deserialize()    -> peaks + leaf_count (+ optional retained
//                                     leaf hashes), with a prefix RE-DERIVATION
//                                     check on load: if the leaves are present,
//                                     replaying them must reproduce the stored
//                                     peaks, else the load fails closed.
//
// ── THE EMPTY ROOT ────────────────────────────────────────────────────────
// Lane::mmr_bag({}) is all-zero bytes, so root() of an EMPTY record log is
// 32 zero bytes. That is NOT the empty-owed anchor b4db1ded... (= sha256d(
// "V37O")): owed_digest and the record log are two different commitments over
// two different things, and this header never touches the former.

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include <sharechain/v37/v37_hash.hpp>       // bytes32, sha256d
#include <sharechain/v37/v37_fixed.hpp>      // u64
#include <sharechain/v37/v37_lane.hpp>       // ::v37::PeakSet, ::v37::Lane MMR statics

namespace c2pool::v37n::recordlog {

using ::v37::bytes32;
using ::v37::u64;

// ─────────────────────────────────────────────────────────────────────────
// The CONSENSUS-COMMIT GATE — OFF by default (compile-time, no runtime global).
//
// Computing a record-log root and persisting it are ADDITIVE: they move no
// committed root, so they are always on. COMMITTING that root into a
// consensus-visible structure (the w5 StateCommitment tree) is a FLAG DAY: it
// moves the state root every node commits in its coinbase. So it is gated, and
// the gate is OFF unless the whole tree is compiled with
// -DV37_OWED_EVENT_MMR_COMMIT=1. With the gate OFF every committed root is
// byte-identical to master; the KAT pins both sides.
// ─────────────────────────────────────────────────────────────────────────
#ifndef V37_OWED_EVENT_MMR_COMMIT
#define V37_OWED_EVENT_MMR_COMMIT 0
#endif
inline constexpr bool kCommitOwedEventMmrDefault = (V37_OWED_EVENT_MMR_COMMIT != 0);

// Serialization schema version for RecordLog::serialize().
inline constexpr std::uint8_t RECORD_LOG_SER_VER = 1;

class RecordLog {
public:
    // The lane leaf rule, mirrored (Lane::leaf_hash is private) — identical to
    // the mirror already shipped in w5_coinbase.hpp.
    static bytes32 leaf_hash(const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> b;
        b.reserve(payload.size() + 1);
        b.push_back(0x00);
        b.insert(b.end(), payload.begin(), payload.end());
        return ::v37::sha256d(b);
    }

    RecordLog() = default;
    explicit RecordLog(bool retain_leaves) : m_retain(retain_leaves) {}

    // Retained leaf hashes are what makes inclusion / prefix proofs servable.
    // ON by default: a record log's leaves are events, not shares, so the cost
    // is 32 bytes per ledger mutation. Turning retention OFF keeps root() and
    // leaf_count() exact and only gives up proof SERVICE.
    bool retains_leaves() const { return m_retain; }
    void set_retain_leaves(bool on) {
        if (!on) m_leaves.clear();
        m_retain = on;
    }

    // ── append: the ONLY mutator. Returns the 0-based index of the new leaf.
    u64 append(const std::vector<std::uint8_t>& payload) {
        return append_leaf(leaf_hash(payload));
    }
    u64 append_leaf(const bytes32& leaf) {
        const u64 idx = m_peaks.leaf_count;
        ::v37::Lane::mmr_append(m_peaks, leaf);     // SHIPPED binary-counter rule
        if (m_retain) m_leaves.push_back(leaf);
        return idx;
    }

    // ── reads ────────────────────────────────────────────────────────────
    bytes32 root() const { return ::v37::Lane::mmr_bag(m_peaks.peaks); }
    u64 leaf_count() const { return m_peaks.leaf_count; }
    const ::v37::PeakSet& peaks() const { return m_peaks; }
    const std::vector<bytes32>& leaves() const { return m_leaves; }
    bool empty() const { return m_peaks.leaf_count == 0; }

    // Structural self-check: the peak count must be popcount(leaf_count), and a
    // retaining log must hold exactly leaf_count leaves.
    bool consistent() const {
        if (m_peaks.peaks.size() != popcount(m_peaks.leaf_count)) return false;
        if (m_retain && m_leaves.size() != m_peaks.leaf_count) return false;
        return true;
    }

    // ── inclusion proof (archival side) ──────────────────────────────────
    // Needs the retained leaves. `p` verifies against root() through the
    // SHIPPED ::v37::Lane::mmr_verify.
    bool prove(u64 idx, bytes32& leaf_out, ::v37::Lane::MmrProof& proof_out) const {
        if (!m_retain || idx >= m_peaks.leaf_count) return false;
        if (m_leaves.size() != m_peaks.leaf_count) return false;
        leaf_out = m_leaves[static_cast<std::size_t>(idx)];
        proof_out = ::v37::Lane::mmr_proof(m_leaves, idx);
        return true;
    }
    // Stateless verifier (lite client): the shipped lane verifier, unwrapped.
    static bool verify(const bytes32& committed_root, const bytes32& leaf,
                       const ::v37::Lane::MmrProof& p) {
        return ::v37::Lane::mmr_verify(committed_root, leaf, p);
    }

    // ── prefix (append-only / consistency) proof ─────────────────────────
    // SHAPE, stated honestly: this is the RE-DERIVATION form. The proof
    // carries the peak set the log had at the OLD leaf_count plus the leaf
    // hashes appended since, and the verifier replays the appends. It is
    // O(peaks) + O(appended) rather than O(log n): the compact form (proving
    // each old peak as a node of the new tree) is a deliberate non-goal here,
    // because the consumer of this proof is a node catching up over a small
    // number of new ledger events, not a light client bridging a long gap.
    // What it proves is the property that matters: the old root is a genuine
    // PREFIX of the new one — nothing already committed was rewritten.
    struct PrefixProof {
        ::v37::PeakSet       old_state;   // peaks + leaf_count at the old cut
        std::vector<bytes32> appended;    // leaf hashes [old_leaf_count, new)
        bool operator==(const PrefixProof&) const = default;
    };
    bool prove_prefix(u64 old_leaf_count, PrefixProof& out) const {
        if (!m_retain || old_leaf_count > m_peaks.leaf_count) return false;
        if (m_leaves.size() != m_peaks.leaf_count) return false;
        out = PrefixProof{};
        for (u64 i = 0; i < old_leaf_count; ++i)
            ::v37::Lane::mmr_append(out.old_state, m_leaves[static_cast<std::size_t>(i)]);
        for (u64 i = old_leaf_count; i < m_peaks.leaf_count; ++i)
            out.appended.push_back(m_leaves[static_cast<std::size_t>(i)]);
        return true;
    }
    static bool verify_prefix(const bytes32& old_root, u64 old_leaf_count,
                              const bytes32& new_root, u64 new_leaf_count,
                              const PrefixProof& p) {
        if (p.old_state.leaf_count != old_leaf_count) return false;
        if (p.old_state.peaks.size() != popcount(old_leaf_count)) return false;
        if (old_leaf_count + static_cast<u64>(p.appended.size()) != new_leaf_count)
            return false;
        if (::v37::Lane::mmr_bag(p.old_state.peaks) != old_root) return false;
        ::v37::PeakSet ps = p.old_state;
        for (const bytes32& leaf : p.appended) ::v37::Lane::mmr_append(ps, leaf);
        if (ps.leaf_count != new_leaf_count) return false;
        return ::v37::Lane::mmr_bag(ps.peaks) == new_root;
    }

    // ── serialization ────────────────────────────────────────────────────
    // u8 ver | u8 flags (bit0 = leaves present) | u64 leaf_count
    //   | u32 n_peaks | n_peaks x 32 | [u64 n_leaves | n_leaves x 32]
    // Little-endian, fixed width. The persisted form a node restores from.
    std::string serialize() const {
        std::string s;
        put_u8(s, RECORD_LOG_SER_VER);
        put_u8(s, static_cast<std::uint8_t>(m_retain ? 0x01 : 0x00));
        put_u64(s, m_peaks.leaf_count);
        put_u32(s, static_cast<std::uint32_t>(m_peaks.peaks.size()));
        for (const bytes32& h : m_peaks.peaks) put_b32(s, h);
        if (m_retain) {
            put_u64(s, static_cast<u64>(m_leaves.size()));
            for (const bytes32& h : m_leaves) put_b32(s, h);
        }
        return s;
    }
    // Fail-closed: unknown newer version, truncation, trailing garbage, a peak
    // count that is not popcount(leaf_count), or — when the leaves are present
    // — a REPLAY that does not reproduce the stored peaks, all return nullopt.
    // That last check is the prefix re-derivation guard: a restored log whose
    // leaves and peaks disagree is refused rather than silently trusted.
    static std::optional<RecordLog> deserialize(const std::string& v) {
        std::size_t o = 0;
        std::uint8_t ver = 0, flags = 0;
        if (!get_u8(v, o, ver) || ver > RECORD_LOG_SER_VER) return std::nullopt;
        if (!get_u8(v, o, flags)) return std::nullopt;
        if (flags & ~std::uint8_t(0x01)) return std::nullopt;   // reserved bits must be 0
        RecordLog rl;
        rl.m_retain = (flags & 0x01) != 0;
        if (!get_u64(v, o, rl.m_peaks.leaf_count)) return std::nullopt;
        std::uint32_t np = 0;
        if (!get_u32(v, o, np)) return std::nullopt;
        if (np != popcount(rl.m_peaks.leaf_count)) return std::nullopt;
        rl.m_peaks.peaks.resize(np);
        for (std::uint32_t i = 0; i < np; ++i)
            if (!get_b32(v, o, rl.m_peaks.peaks[i])) return std::nullopt;
        if (rl.m_retain) {
            u64 nl = 0;
            if (!get_u64(v, o, nl)) return std::nullopt;
            if (nl != rl.m_peaks.leaf_count) return std::nullopt;
            if (nl > (v.size() - o) / 32) return std::nullopt;
            rl.m_leaves.resize(static_cast<std::size_t>(nl));
            for (u64 i = 0; i < nl; ++i)
                if (!get_b32(v, o, rl.m_leaves[static_cast<std::size_t>(i)])) return std::nullopt;
            // re-derivation check: replaying the leaves must rebuild the peaks.
            ::v37::PeakSet re;
            for (const bytes32& h : rl.m_leaves) ::v37::Lane::mmr_append(re, h);
            if (!(re == rl.m_peaks)) return std::nullopt;
        }
        if (o != v.size()) return std::nullopt;                 // trailing garbage
        return rl;
    }

private:
    static std::size_t popcount(u64 x) {
        std::size_t n = 0;
        while (x) { n += std::size_t(x & 1); x >>= 1; }
        return n;
    }
    static void put_u8(std::string& s, std::uint8_t x) { s.push_back(char(x)); }
    static void put_u32(std::string& s, std::uint32_t x) {
        for (int i = 0; i < 4; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
    }
    static void put_u64(std::string& s, u64 x) {
        for (int i = 0; i < 8; ++i) s.push_back(char((x >> (8 * i)) & 0xff));
    }
    static void put_b32(std::string& s, const bytes32& h) {
        s.append(reinterpret_cast<const char*>(h.data()), h.size());
    }
    static bool get_u8(const std::string& v, std::size_t& o, std::uint8_t& x) {
        if (o + 1 > v.size()) return false;
        x = std::uint8_t(v[o++]);
        return true;
    }
    static bool get_u32(const std::string& v, std::size_t& o, std::uint32_t& x) {
        if (o + 4 > v.size()) return false;
        x = 0;
        for (int i = 0; i < 4; ++i) x |= std::uint32_t(std::uint8_t(v[o++])) << (8 * i);
        return true;
    }
    static bool get_u64(const std::string& v, std::size_t& o, u64& x) {
        if (o + 8 > v.size()) return false;
        x = 0;
        for (int i = 0; i < 8; ++i) x |= u64(std::uint8_t(v[o++])) << (8 * i);
        return true;
    }
    static bool get_b32(const std::string& v, std::size_t& o, bytes32& h) {
        if (o + 32 > v.size()) return false;
        for (int i = 0; i < 32; ++i) h[i] = std::uint8_t(v[o++]);
        return true;
    }

    ::v37::PeakSet       m_peaks;          // the whole authenticated state
    std::vector<bytes32> m_leaves;         // retained leaf hashes (proof service)
    bool                 m_retain = true;
};

} // namespace c2pool::v37n::recordlog
