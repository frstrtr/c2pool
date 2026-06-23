#pragma once

/// Phase C-PAY step 2: per-MN state store.
///
/// Holds the EFFECTIVE state of every masternode we know about, derived
/// by the per-block state machine (Phase C-PAY step 3) from observed
/// ProTx records + coinbase outputs. The `MNState` struct is our pruned
/// internal version of dashcore's `CDeterministicMNState`
/// (evo/dmnstate.h) — same field semantics for the bits we use, but
/// reduced to what GetProjectedMNPayees actually needs:
///
///   - nLastPaidHeight, nPoSeRevivedHeight, nRegisteredHeight
///     → CompareByLastPaid_GetHeight (the sort key)
///   - proRegTxHash → tiebreaker
///   - nType → Regular vs Evo (Evo bonus path)
///   - nConsecutivePayments → Evo "paid 4 in a row" bonus tracking
///   - isValid → eligibility filter
///   - scriptPayout → for "[PAY] match/mismatch" verification
///
/// We persist the FULL state-relevant subset (including keyIDOwner /
/// pubKeyOperator / nOperatorReward / collateralOutpoint / Evo platform
/// fields) so future state-machine work can consume them without a
/// schema migration.
///
/// The store mirrors SMLDb + QuorumDb: open at
/// `~/.c2pool/<coin>/mn_state_db/`, atomic batch full-rewrite per-block
/// state advance, BEST sentinel for tip tracking + cross-check with
/// SMLDb/QuorumDb (divergence → wipe all three).
///
/// Key schema:
///   'M' + proRegTxHash(32B)  →  pack(MNState)
///   'B'                       →  best_hash(32B) + best_height(4B LE)
///
/// Persistence wire format is INTERNAL-ONLY — never shared on the
/// network — so we use pack.hpp's SERIALIZE_METHODS macros directly
/// without worrying about bit-exact match against dashcore's
/// CDeterministicMNState wire layout.

#include <impl/dash/coin/vendor/providertx.hpp>

#include <core/leveldb_store.hpp>
#include <core/uint256.hpp>
#include <core/log.hpp>
#include <core/opscript.hpp>
#include <core/pack.hpp>
#include <core/pack_types.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <array>
#include <cstdint>
#include <cstring>
#include <span>
#include <string>
#include <vector>

namespace dash {
namespace coin {

struct MNState
{
    // From CProRegTx (registration — immutable per MN unless a later
    // ProUpRegTx rewrites them)
    uint16_t                                       nVersion{vendor::ProTxVersion::BASIC_BLS};
    uint8_t                                        nType{vendor::MnType::REGULAR};
    bitcoin_family::coin::TxPrevOut                collateralOutpoint;
    uint160                                        keyIDOwner;
    std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>   pubKeyOperator{};
    uint160                                        keyIDVoting;
    uint16_t                                       nOperatorReward{0};
    OPScript                                       scriptPayout;

    // From CProUpServTx
    vendor::LegacyNetService                       netInfo;
    OPScript                                       scriptOperatorPayout;

    // Per-block state-machine outputs
    uint32_t                                       nRegisteredHeight{0};
    uint32_t                                       nLastPaidHeight{0};
    uint32_t                                       nPoSeRevivedHeight{0};
    uint32_t                                       nPoSeBanHeight{0};
    uint32_t                                       nConsecutivePayments{0};
    uint16_t                                       nRevocationReason{vendor::CProUpRevTx::REASON_NOT_SPECIFIED};
    bool                                           isValid{true};

    // Evo-only platform fields (gated on nType == EVO)
    uint160                                        platformNodeID;
    uint16_t                                       platformP2PPort{0};
    uint16_t                                       platformHTTPPort{0};

    C2POOL_SERIALIZE_METHODS(MNState)
    {
        READWRITE(obj.nVersion,
                  obj.nType,
                  obj.collateralOutpoint,
                  obj.keyIDOwner,
                  Using<vendor::RawBytesFormat<vendor::BLS_PUBKEY_SIZE>>(obj.pubKeyOperator),
                  obj.keyIDVoting,
                  obj.nOperatorReward,
                  obj.scriptPayout,
                  obj.netInfo,
                  obj.scriptOperatorPayout,
                  obj.nRegisteredHeight,
                  obj.nLastPaidHeight,
                  obj.nPoSeRevivedHeight,
                  obj.nPoSeBanHeight,
                  obj.nConsecutivePayments,
                  obj.nRevocationReason,
                  obj.isValid,
                  obj.platformNodeID,
                  obj.platformP2PPort,
                  obj.platformHTTPPort);
    }

    bool operator==(const MNState& r) const
    {
        return nVersion == r.nVersion
            && nType == r.nType
            && nRegisteredHeight == r.nRegisteredHeight
            && nLastPaidHeight == r.nLastPaidHeight
            && nPoSeRevivedHeight == r.nPoSeRevivedHeight
            && nPoSeBanHeight == r.nPoSeBanHeight
            && nConsecutivePayments == r.nConsecutivePayments
            && nRevocationReason == r.nRevocationReason
            && isValid == r.isValid
            && nOperatorReward == r.nOperatorReward
            && keyIDOwner == r.keyIDOwner
            && pubKeyOperator == r.pubKeyOperator
            && keyIDVoting == r.keyIDVoting
            && scriptPayout.m_data == r.scriptPayout.m_data
            && scriptOperatorPayout.m_data == r.scriptOperatorPayout.m_data
            && platformNodeID == r.platformNodeID
            && platformP2PPort == r.platformP2PPort
            && platformHTTPPort == r.platformHTTPPort;
    }
};

class MnStateDb
{
public:
    explicit MnStateDb(const std::string& db_path,
                       const ::core::LevelDBOptions& opts = {})
        : m_store(db_path, opts) {}

    bool open()
    {
        if (!m_store.open()) return false;
        load_best_state();
        LOG_INFO << "[MNS-DB] opened best_height=" << m_best_height
                 << " best_hash=" << m_best_hash.GetHex().substr(0, 16);
        return true;
    }

    void close() { m_store.close(); }
    bool is_open() const { return m_store.is_open(); }

    uint256  get_best_hash() const   { return m_best_hash; }
    uint32_t get_best_height() const { return m_best_height; }

    // Load every persisted MNState into `out` keyed by proRegTxHash.
    // Returns true if at least one entry loaded OR the BEST sentinel
    // exists (warm restart with empty set is technically valid).
    bool load_all(std::vector<std::pair<uint256, MNState>>& out)
    {
        out.clear();
        auto keys = m_store.list_keys(std::string(1, 'M'),
                                      /*limit=*/100000);
        out.reserve(keys.size());
        size_t bad = 0;
        for (const auto& key : keys) {
            if (key.size() != 33 || key[0] != 'M') continue;
            std::vector<uint8_t> data;
            if (!m_store.get(key, data)) { ++bad; continue; }
            try {
                MNState s;
                ::PackStream ps(data);
                ps >> s;
                uint256 h;
                std::memcpy(h.data(), key.data() + 1, 32);
                out.emplace_back(h, std::move(s));
            } catch (const std::exception& ex) {
                ++bad;
                LOG_WARNING << "[MNS-DB] entry deserialize failed: "
                            << ex.what();
            }
        }
        if (bad > 0) {
            LOG_WARNING << "[MNS-DB] " << bad
                        << " entries failed to load (skipped)";
        }
        bool warm = !out.empty() || !m_best_hash.IsNull();
        if (warm) {
            LOG_INFO << "[MNS-DB] loaded " << out.size()
                     << " entries best_height=" << m_best_height;
        }
        return warm;
    }

    // Atomic full-rewrite of the entire MN state set + BEST sentinel.
    // Same pattern as SMLDb::write_sml. ~3000 MNs × ~220 B avg ≈
    // 660 KB per-block rewrite. Fine — LevelDB compaction handles
    // the churn on the same order as SML rewrites.
    bool write_all(const std::vector<std::pair<uint256, MNState>>& entries,
                   const uint256& best_hash,
                   uint32_t best_height)
    {
        // Monotonic-advance: best_height only ever increases. Required so
        // that bootstrap drain (replaying h=snapshot+1 .. tip in chain
        // order, AFTER a tip block at top-of-handler may have already
        // bumped best_height to tip-height) does not roll back the
        // persisted high-watermark. Snapshot ENTRIES still need to be
        // written, so we always persist `entries`; only the best_hash /
        // best_height update is gated.
        const bool advance = (best_height >= m_best_height);

        auto batch = m_store.create_batch();

        auto existing = m_store.list_keys(std::string(1, 'M'),
                                          /*limit=*/100000);
        for (const auto& k : existing) batch.remove(k);

        for (const auto& [hash, state] : entries) {
            auto key = make_entry_key(hash);
            auto stream = ::pack(state);
            auto sp = stream.get_span();
            std::vector<uint8_t> data(
                reinterpret_cast<const uint8_t*>(sp.data()),
                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
            batch.put(key, data);
        }

        if (advance) {
            batch.put(make_state_key(),
                      encode_best_state(best_hash, best_height));
        }

        if (!batch.commit()) {
            LOG_WARNING << "[MNS-DB] write_all batch commit failed";
            return false;
        }
        if (advance) {
            m_best_hash   = best_hash;
            m_best_height = best_height;
        }
        return true;
    }

    bool clear()
    {
        auto batch = m_store.create_batch();
        for (auto& k : m_store.list_keys(std::string(1, 'M'), 100000))
            batch.remove(k);
        batch.remove(make_state_key());
        if (!batch.commit()) return false;
        m_best_hash = uint256{};
        m_best_height = 0;
        LOG_INFO << "[MNS-DB] cleared";
        return true;
    }

private:
    ::core::LevelDBStore m_store;
    uint256              m_best_hash;
    uint32_t             m_best_height{0};

    static std::string make_entry_key(const uint256& proRegTxHash)
    {
        std::string k;
        k.reserve(33);
        k.push_back('M');
        k.append(reinterpret_cast<const char*>(proRegTxHash.data()), 32);
        return k;
    }

    static std::string make_state_key() { return std::string(1, 'B'); }

    static std::vector<uint8_t> encode_best_state(const uint256& hash,
                                                  uint32_t height)
    {
        std::vector<uint8_t> out(36);
        std::memcpy(out.data(), hash.data(), 32);
        out[32] = static_cast<uint8_t>( height        & 0xFF);
        out[33] = static_cast<uint8_t>((height >>  8) & 0xFF);
        out[34] = static_cast<uint8_t>((height >> 16) & 0xFF);
        out[35] = static_cast<uint8_t>((height >> 24) & 0xFF);
        return out;
    }

    void load_best_state()
    {
        std::vector<uint8_t> data;
        if (!m_store.get(make_state_key(), data) || data.size() < 36) {
            return;
        }
        std::memcpy(m_best_hash.data(), data.data(), 32);
        m_best_height = uint32_t(data[32])
                      | (uint32_t(data[33]) <<  8)
                      | (uint32_t(data[34]) << 16)
                      | (uint32_t(data[35]) << 24);
    }
};

} // namespace coin
} // namespace dash
