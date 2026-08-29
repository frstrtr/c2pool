// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// Phase C-TEMPLATE step 13c: persistent SML + quorum state (the sibling
/// stores credit_pool_db.hpp / mn_state_db.hpp already reference by name).
///
/// The embedded DASH arm's Simplified Masternode List (CSimplifiedMNList,
/// merkleRootMNList source) and active LLMQ quorum set (QuorumManager,
/// merkleRootQuorums source) were IN-MEMORY only: every process restart
/// cold-started a full mnlistdiff(zero, tip) re-sync off the coin-P2P peer.
/// These two stores persist that state so a restart RESUMES incrementally —
/// load the last persisted state, set the getmnlistd base to the persisted
/// tip, and apply only the incremental mnlistdiff from there.
///
/// REUSE, do not hand-roll: both stores wrap core::LevelDBStore exactly like
/// MnStateDb (atomic WriteBatch full-rewrite per accepted mnlistdiff, BEST
/// sentinel for tip tracking, load-on-open). The persistence wire format is
/// INTERNAL-ONLY — never shared on the network — so we serialize the vendored
/// CSimplifiedMNListEntry / CFinalCommitment via pack.hpp directly (the same
/// codec their from-wire parse already round-trips byte-exact).
///
/// FAIL-CLOSED-ON-CORRUPT INVARIANT (the correctness keystone): the store is
/// NEVER trusted blindly. write_*() records the merkle root computed over the
/// state it persists; load_verified() reconstructs the state, RECOMPUTES the
/// root INDEPENDENTLY, and refuses the load unless it matches. A corrupt /
/// stale / partially-written store (bit rot, a torn batch, a downgraded codec)
/// therefore fails closed — the load is rejected and the on-disk store wiped,
/// so the arm falls back to a full mnlistdiff(zero, tip) re-sync rather than
/// ever serving a template built on a WRONG root (which would mine a
/// consensus-invalid block). A self-consistent-but-wrong root cannot be caught
/// by a self-referential check, so on reorg / H-1 heal main_dash also WIPES
/// these stores (see CoinStateMaintainer::set_on_sml_clear) — an orphaned-branch
/// state is self-consistent and would pass the root-verify.
///
/// Schemas
///   SMLDb  ('sml_db/'):
///     'S' + proRegTxHash(32B)       -> pack(CSimplifiedMNListEntry)
///     'B'                            -> best_hash(32B) height(4B LE)
///                                        expected_merkleRootMNList(32B)
///   QuorumDb ('quorum_db/'):
///     'Q' + seq(4B BE)               -> pack(CFinalCommitment) mining_height(4B LE)
///     'L' + seq(4B BE)               -> sig(96B) count(4B LE) count*index(2B LE)
///     'B'                            -> best_hash(32B) height(4B LE)
///                                        expected_merkleRootQuorums(32B)

#include <impl/dash/coin/vendor/simplifiedmns.hpp>  // vendor::CSimplifiedMNList(Entry)
#include <impl/dash/coin/quorum_manager.hpp>        // QuorumManager
#include <impl/dash/coin/quorum_root.hpp>           // compute_merkle_root_quorums

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/pack.hpp>
#include <core/log.hpp>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace dash {
namespace coin {

namespace sml_db_detail {

inline void put_u32_le(std::vector<uint8_t>& out, uint32_t v)
{
    out.push_back(static_cast<uint8_t>( v        & 0xFF));
    out.push_back(static_cast<uint8_t>((v >>  8) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 16) & 0xFF));
    out.push_back(static_cast<uint8_t>((v >> 24) & 0xFF));
}

inline uint32_t get_u32_le(const uint8_t* p)
{
    return uint32_t(p[0]) | (uint32_t(p[1]) << 8)
         | (uint32_t(p[2]) << 16) | (uint32_t(p[3]) << 24);
}

// 4-byte BIG-endian sequence key so list_keys() returns a stable order.
inline std::string make_seq_key(char tag, uint32_t seq)
{
    std::string k;
    k.reserve(5);
    k.push_back(tag);
    k.push_back(static_cast<char>((seq >> 24) & 0xFF));
    k.push_back(static_cast<char>((seq >> 16) & 0xFF));
    k.push_back(static_cast<char>((seq >>  8) & 0xFF));
    k.push_back(static_cast<char>( seq        & 0xFF));
    return k;
}

template <typename T>
inline std::vector<uint8_t> pack_bytes(const T& obj)
{
    auto stream = ::pack(obj);
    auto sp = stream.get_span();
    return std::vector<uint8_t>(
        reinterpret_cast<const uint8_t*>(sp.data()),
        reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

} // namespace sml_db_detail

// ── SMLDb: persist the CSimplifiedMNList (merkleRootMNList source) ─────────
class SMLDb
{
public:
    explicit SMLDb(const std::string& db_path,
                   const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[SML-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const     { return m_best_hash; }
    uint32_t get_best_height() const   { return m_best_height; }
    uint256  get_expected_root() const { return m_expected_root; }

    // Atomic full-rewrite of the SML entry set + BEST sentinel. The sentinel
    // carries the merkleRootMNList computed HERE (the independent verify anchor
    // load_verified re-derives and compares against).
    bool write_sml(const vendor::CSimplifiedMNList& sml,
                   const uint256& best_hash, uint32_t best_height)
    {
        const uint256 expected_root = sml.CalcMerkleRoot();

        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'S'), 500000))
            batch.remove(k);
        for (const auto& e : sml.mnList)
            batch.put(make_entry_key(e.proRegTxHash),
                      sml_db_detail::pack_bytes(e));
        batch.put(make_state_key(),
                  encode_best_state(best_hash, best_height, expected_root));

        if (!batch.commit()) {
            LOG_WARNING << "[SML-DB] write_sml batch commit failed";
            return false;
        }
        m_best_hash     = best_hash;
        m_best_height   = best_height;
        m_expected_root = expected_root;
        return true;
    }

    // FAIL-CLOSED load: reconstruct the SML, recompute merkleRootMNList, and
    // accept ONLY when it equals the persisted root. Any mismatch or parse
    // failure wipes the store and returns false so the caller cold-resyncs.
    // `out` is left EMPTY on any non-warm/failed load.
    bool load_verified(vendor::CSimplifiedMNList& out)
    {
        out.mnList.clear();
        if (m_best_hash.IsNull()) return false;   // no sentinel => cold start

        std::vector<vendor::CSimplifiedMNListEntry> entries;
        for (const auto& key : m_store.list_keys(std::string(1, 'S'), 500000)) {
            if (key.size() != 33 || key[0] != 'S') continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data))
                return fail_closed("entry read failed");
            try {
                vendor::CSimplifiedMNListEntry e;
                ::PackStream ps(data);
                ps >> e;
                entries.push_back(std::move(e));
            } catch (const std::exception& ex) {
                return fail_closed(std::string("entry deserialize: ") + ex.what());
            }
        }

        vendor::CSimplifiedMNList sml(std::move(entries));   // ctor re-sorts
        const uint256 root = sml.CalcMerkleRoot();
        if (root != m_expected_root)
            return fail_closed("merkleRootMNList mismatch persisted="
                               + m_expected_root.GetHex().substr(0, 16)
                               + " recomputed=" + root.GetHex().substr(0, 16));

        out = std::move(sml);
        LOG_INFO << "[SML-DB] loaded+verified " << out.size()
                 << " MNs, merkleRootMNList OK @h=" << m_best_height;
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'S'), 500000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash     = uint256{};
        m_best_height   = 0;
        m_expected_root = uint256{};
        LOG_INFO << "[SML-DB] cleared";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint256              m_expected_root;
    uint32_t             m_best_height{0};

    bool fail_closed(const std::string& why)
    {
        LOG_WARNING << "[SML-DB] FAIL-CLOSED (" << why
                    << ") -> wiping store, cold mnlistdiff(zero,tip) re-sync";
        clear();
        return false;
    }

    static std::string make_entry_key(const uint256& proRegTxHash)
    {
        std::string k;
        k.reserve(33);
        k.push_back('S');
        k.append(reinterpret_cast<const char*>(proRegTxHash.data()), 32);
        return k;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height,
                                                  const uint256& root)
    {
        std::vector<uint8_t> out;
        out.reserve(68);
        out.insert(out.end(), hash.data(), hash.data() + 32);
        sml_db_detail::put_u32_le(out, height);
        out.insert(out.end(), root.data(), root.data() + 32);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 68) return;
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = sml_db_detail::get_u32_le(data.data() + 32);
        std::memcpy(m_expected_root.data(), data.data() + 36, 32);
    }
};

// ── QuorumDb: persist the active LLMQ set (merkleRootQuorums source) ───────
class QuorumDb
{
public:
    explicit QuorumDb(const std::string& db_path,
                      const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[QUO-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const     { return m_best_hash; }
    uint32_t get_best_height() const   { return m_best_height; }
    uint256  get_expected_root() const { return m_expected_root; }

    // Atomic full-rewrite of the active quorum set + cached CL sigs + BEST
    // sentinel (carrying merkleRootQuorums, the independent verify anchor).
    bool write_quorums(const QuorumManager& qmgr,
                       const uint256& best_hash, uint32_t best_height)
    {
        const uint256 expected_root = compute_merkle_root_quorums(qmgr);

        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'Q'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'L'), 500000))
            batch.remove(k);

        uint32_t seq = 0;
        for (const auto& e : qmgr.active_entries()) {
            auto data = sml_db_detail::pack_bytes(e.commitment);
            sml_db_detail::put_u32_le(data, e.mining_height);
            batch.put(sml_db_detail::make_seq_key('Q', seq++), data);
        }
        seq = 0;
        for (const auto& s : qmgr.latest_cl_sigs()) {
            std::vector<uint8_t> v;
            v.insert(v.end(), s.first.begin(), s.first.end());   // 96B BLS sig
            sml_db_detail::put_u32_le(v,
                static_cast<uint32_t>(s.second.size()));
            for (uint16_t idx : s.second) {
                v.push_back(static_cast<uint8_t>( idx       & 0xFF));
                v.push_back(static_cast<uint8_t>((idx >> 8) & 0xFF));
            }
            batch.put(sml_db_detail::make_seq_key('L', seq++), v);
        }
        batch.put(make_state_key(),
                  encode_best_state(best_hash, best_height, expected_root));

        if (!batch.commit()) {
            LOG_WARNING << "[QUO-DB] write_quorums batch commit failed";
            return false;
        }
        m_best_hash     = best_hash;
        m_best_height   = best_height;
        m_expected_root = expected_root;
        return true;
    }

    // FAIL-CLOSED load: warm `out` with the persisted active set + CL sigs,
    // recompute merkleRootQuorums, and accept ONLY when it matches the
    // persisted root. On any mismatch / parse failure the store is wiped, `out`
    // is cleared, and false is returned (cold re-sync).
    bool load_verified(QuorumManager& out)
    {
        out.clear();
        if (m_best_hash.IsNull()) return false;

        std::vector<QuorumManager::Entry> entries;
        for (const auto& key : m_store.list_keys(std::string(1, 'Q'), 500000)) {
            std::vector<uint8_t> data;
            if (!m_store.get(key, data) || data.size() < 4)
                return fail_closed(out, "quorum read failed");
            try {
                QuorumManager::Entry ent;
                ::PackStream ps(data);
                ps >> ent.commitment;
                ent.key = QuorumManager::ActiveKey{
                    ent.commitment.llmqType, ent.commitment.quorumHash};
                ent.mining_height =
                    sml_db_detail::get_u32_le(data.data() + data.size() - 4);
                entries.push_back(std::move(ent));
            } catch (const std::exception& ex) {
                return fail_closed(out,
                    std::string("commitment deserialize: ") + ex.what());
            }
        }

        constexpr size_t SIG = vendor::CFinalCommitment::BLS_SIG_SIZE;
        std::vector<QuorumManager::CLSig> cl_sigs;
        for (const auto& key : m_store.list_keys(std::string(1, 'L'), 500000)) {
            std::vector<uint8_t> data;
            if (!m_store.get(key, data) || data.size() < SIG + 4)
                return fail_closed(out, "clsig read failed");
            QuorumManager::CLSig s;
            std::memcpy(s.first.data(), data.data(), SIG);
            uint32_t n = sml_db_detail::get_u32_le(data.data() + SIG);
            if (data.size() < SIG + 4 + size_t(n) * 2)
                return fail_closed(out, "clsig index underrun");
            s.second.reserve(n);
            for (uint32_t i = 0; i < n; ++i) {
                const uint8_t* p = data.data() + SIG + 4 + size_t(i) * 2;
                s.second.push_back(
                    static_cast<uint16_t>(uint16_t(p[0]) | (uint16_t(p[1]) << 8)));
            }
            cl_sigs.push_back(std::move(s));
        }

        out.replace_state(std::move(entries), std::move(cl_sigs));
        const uint256 root = compute_merkle_root_quorums(out);
        if (root != m_expected_root)
            return fail_closed(out, "merkleRootQuorums mismatch persisted="
                               + m_expected_root.GetHex().substr(0, 16)
                               + " recomputed=" + root.GetHex().substr(0, 16));

        LOG_INFO << "[QUO-DB] loaded+verified " << out.active_count()
                 << " quorums, merkleRootQuorums OK @h=" << m_best_height;
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        for (const auto& k : m_store.list_keys(std::string(1, 'Q'), 500000))
            batch.remove(k);
        for (const auto& k : m_store.list_keys(std::string(1, 'L'), 500000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash     = uint256{};
        m_best_height   = 0;
        m_expected_root = uint256{};
        LOG_INFO << "[QUO-DB] cleared";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint256              m_expected_root;
    uint32_t             m_best_height{0};

    bool fail_closed(QuorumManager& out, const std::string& why)
    {
        LOG_WARNING << "[QUO-DB] FAIL-CLOSED (" << why
                    << ") -> wiping store, cold mnlistdiff(zero,tip) re-sync";
        out.clear();
        clear();
        return false;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height,
                                                  const uint256& root)
    {
        std::vector<uint8_t> out;
        out.reserve(68);
        out.insert(out.end(), hash.data(), hash.data() + 32);
        sml_db_detail::put_u32_le(out, height);
        out.insert(out.end(), root.data(), root.data() + 32);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 68) return;
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = sml_db_detail::get_u32_le(data.data() + 32);
        std::memcpy(m_expected_root.data(), data.data() + 36, 32);
    }
};

} // namespace coin
} // namespace dash
