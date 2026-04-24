#pragma once

/// Phase C-PAY step 4: per-block DMN state machine.
///
/// Mirrors dashcore's evo/specialtxman.cpp::RebuildListFromBlock @ cfad414
/// in the order-of-operations + the field-update semantics. This is the
/// piece that turns the bootstrap state from step 3a/3b into a live,
/// auto-maintained DMN list that step 5 can project payee selections
/// against.
///
/// Apply order (matches dashcore exactly):
///
///   Pass 1 — special-tx records (skip coinbase, walk i=1+):
///     PROVIDER_REGISTER (type 1):  AddMN with proRegTxHash = tx.GetHash()
///         + collateralOutpoint resolution (null hash → tx's own output)
///         + collateral-collision check (replaces an existing MN that
///           shared the same external collateral outpoint)
///     PROVIDER_UPDATE_SERVICE (type 2): netInfo + scriptOperatorPayout
///         + Evo platform fields; PoSe-revive if MN was banned
///     PROVIDER_UPDATE_REGISTRAR (type 3): pubKeyOperator + keyIDVoting
///         + scriptPayout; if pubKeyOperator changed, ResetOperatorFields
///         + BanIfNotBanned (until a ProUpServTx revives)
///     PROVIDER_UPDATE_REVOKE (type 4): ResetOperatorFields + ban +
///         nRevocationReason
///
///   Pass 2 — collateral spends (skip coinbase, walk i=1+):
///     For each vin, check m_collateral_index; if matched, remove the MN.
///     dashcore does this AFTER pass 1 so a brand-new MN registered THIS
///     block can have its collateral spent in a later tx of the same
///     block (rare but consensus-correct). We mirror.
///
///   Pass 3 — payee resolution (coinbase outputs):
///     dashcore computes expected payee from PREV-block list before
///     applying any tx; we OBSERVE actual coinbase outputs and find
///     matches in our current list. Functionally equivalent for nodes
///     processing accepted blocks (every accepted coinbase pays the
///     dashcore-expected MN by definition).
///     For each output that matches an MN's scriptPayout: set
///     nLastPaidHeight = height; for Evo MNs, increment
///     nConsecutivePayments if last payment was at height-1, else reset
///     to 1.
///
/// Things we DELIBERATELY don't model (with consequence notes):
///   - Confirmation pass (dashcore: nMasternodeMinimumConfirmations →
///     confirmedHash). Phase L doesn't use confirmedHash; the SML
///     already sync'd from the network has the correct confirmedHash
///     equivalent baked in. Defer.
///   - DecreaseScores (PoSe penalty decay). We don't track nPoSePenalty
///     beyond storing the field. Phase C-PAY's projection algorithm
///     doesn't read nPoSePenalty (only nPoSeBanHeight via isValid),
///     so this is acceptable.
///   - Quorum commitment processing inside per-block (Phase C-QUO's
///     QuorumManager already handles this via the SML diff path,
///     separately).
///   - Operator-payout tracking (scriptOperatorPayout matches in
///     coinbase). Smaller revenue stream; defer until consumer needs it.
///   - PoSe ban via empty netInfo at registration (dashcore's
///     BanIfNotBanned at line specialtxman.cpp:304). Edge case for
///     newly-registered MNs that haven't yet sent a ProUpServTx; the
///     net effect for projection is the same as nLastPaidHeight=0
///     (they sort to the bottom of the payee queue).
///
/// Reorg story: the state machine is forward-only. On a chain reorg
/// the caller (main_dash tip-changed handler) wipes mn_state_db AND
/// calls load() with the empty vector, then re-bootstraps from the
/// snapshot path; subsequent on_full_block calls re-apply forward
/// from snapshot height.

#include <impl/dash/coin/block.hpp>
#include <impl/dash/coin/mn_state_db.hpp>
#include <impl/dash/coin/vendor/providertx.hpp>
#include <impl/bitcoin_family/coin/base_transaction.hpp>

#include <core/hash.hpp>
#include <core/log.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <cstdint>
#include <cstring>
#include <map>
#include <optional>
#include <span>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

// Strict weak ordering on TxPrevOut (uint256 + uint32) for std::map
// keys. We use uint256 operator< (CompareTo, big-endian-integer
// ordering) — the map is INTERNAL (never compared against dashcore
// wire data), so any consistent ordering works. NOT the memcmp
// ordering Bug A required for the SML merkle leaf sort.
struct TxPrevOutLess {
    bool operator()(const bitcoin_family::coin::TxPrevOut& a,
                    const bitcoin_family::coin::TxPrevOut& b) const
    {
        if (a.hash != b.hash) return a.hash < b.hash;
        return a.index < b.index;
    }
};

class MnStateMachine
{
public:
    struct ApplyResult {
        size_t registered{0};
        size_t updated{0};
        size_t revoked{0};
        size_t spent{0};       // collateral spent → MN removed
        size_t paid{0};        // matched a coinbase output
        size_t total_after{0};
    };

    void load(std::vector<std::pair<uint256, MNState>> entries)
    {
        m_entries.clear();
        m_collateral_index.clear();
        for (auto& [h, st] : entries) {
            m_collateral_index[st.collateralOutpoint] = h;
            m_entries.emplace(h, std::move(st));
        }
    }

    size_t size() const { return m_entries.size(); }

    const std::map<uint256, MNState>& entries() const { return m_entries; }

    std::optional<uint256> find_by_collateral(
        const bitcoin_family::coin::TxPrevOut& outpoint) const
    {
        auto it = m_collateral_index.find(outpoint);
        if (it == m_collateral_index.end()) return std::nullopt;
        return it->second;
    }

    // Linear scan over scriptPayout — used by pass 3 (payee resolution)
    // and by Phase C-PAY step 5 (`[PAY]` log-only verification). At
    // ~3000 active MNs and a typical 10-output coinbase that's ~30k
    // memcmp comparisons per block (microseconds). Acceptable.
    std::optional<uint256> find_by_payout_script(
        const std::vector<unsigned char>& script) const
    {
        if (script.empty()) return std::nullopt;
        for (const auto& [h, st] : m_entries) {
            if (st.scriptPayout.m_data == script) return h;
        }
        return std::nullopt;
    }

    // Walk a block's coinbase outputs and return the FIRST output that
    // matches a known MN's scriptPayout. Used by step 5 to cross-check
    // projection vs observation. Returns nullopt if nothing matched
    // (DMN state empty pre-bootstrap, OR coinbase paid an unknown
    // address — e.g. superblock budget output).
    std::optional<uint256> find_paid_in_block_first(
        const dash::coin::BlockType& block) const
    {
        if (block.m_txs.empty()) return std::nullopt;
        for (const auto& vout : block.m_txs[0].vout) {
            if (auto m = find_by_payout_script(vout.scriptPubKey.m_data)) {
                return m;
            }
        }
        return std::nullopt;
    }

    // Phase C-PAY step 5: vendor of dashcore
    // CDeterministicMNList::GetMNPayee() @ cfad414 (deterministicmns.cpp:184).
    //
    // For Dash mainnet at height > 2,128,896 (MN_RR activation), the
    // Evo 4-in-a-row bonus path is DEAD (`if isv19Active &&
    // !isMNRewardReallocation` evaluates to false). All current and
    // future blocks just use the standard CompareByLastPaid scan.
    // c2pool-dash's header checkpoint is at h=2.4M so we always
    // operate post-MN_RR — we omit the Evo bonus path with a TODO
    // for testnet support pre-1,066,900.
    //
    // CompareByLastPaid_GetHeight (line 158-167):
    //   h = nLastPaidHeight
    //   if nPoSeRevivedHeight > h: h = nPoSeRevivedHeight
    //   else if h == 0: h = nRegisteredHeight
    //
    // CompareByLastPaid (line 169-177):
    //   ah == bh: tiebreak by proTxHash ascending
    //   else:     ah < bh
    //
    // CRITICAL: tiebreaker uses dashcore's uint256 operator< which is
    // memcmp(LE-byte) — NOT c2pool's CompareTo (BE-integer). Same
    // gotcha as Bug A in vendor/simplifiedmns.hpp's sort. We use
    // std::memcmp directly to match dashcore's wire semantics.
    std::optional<uint256> find_expected_payee() const
    {
        std::optional<uint256> best_hash;
        int best_h = 0;
        for (const auto& [hash, st] : m_entries) {
            if (!st.isValid) continue;
            int h = static_cast<int>(st.nLastPaidHeight);
            if (st.nPoSeRevivedHeight != 0
                && static_cast<int>(st.nPoSeRevivedHeight) > h) {
                h = static_cast<int>(st.nPoSeRevivedHeight);
            } else if (h == 0) {
                h = static_cast<int>(st.nRegisteredHeight);
            }
            bool better = !best_hash.has_value()
                       || h < best_h
                       || (h == best_h
                           && std::memcmp(hash.data(),
                                          best_hash->data(), 32) < 0);
            if (better) {
                best_h    = h;
                best_hash = hash;
            }
        }
        return best_hash;
    }

    // Dump entire current state for persistence (mn_state_db.write_all).
    std::vector<std::pair<uint256, MNState>> snapshot() const
    {
        std::vector<std::pair<uint256, MNState>> out;
        out.reserve(m_entries.size());
        for (const auto& [h, st] : m_entries) {
            out.emplace_back(h, st);
        }
        return out;
    }

    // Process a single block. Mutates state per dashcore's
    // RebuildListFromBlock algorithm. Returns counts for logging.
    ApplyResult apply_block(const dash::coin::BlockType& block,
                            uint32_t height)
    {
        ApplyResult r;

        // ── Pass 1: special-tx records ─────────────────────────────
        // Walk all non-coinbase txs (i=1+). The order of types within
        // a block is whatever the miner included; dashcore handles
        // them in tx-list order via the if/else-if chain.
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            if (tx.type < 1 || tx.type > 4) continue;
            if (tx.extra_payload.empty()) continue;
            switch (tx.type) {
              case 1: { // PROVIDER_REGISTER
                vendor::CProRegTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProRegTx parse failed h=" << height;
                    break;
                }
                uint256 proRegTxHash = compute_tx_hash(tx);
                MNState st;
                st.nVersion          = ptx.nVersion;
                st.nType             = ptx.nType;
                st.nRegisteredHeight = height;
                st.nLastPaidHeight   = 0;
                st.isValid           = true;
                // collateralOutpoint resolution: null hash means
                // "this tx's own output at index N is the collateral".
                if (ptx.collateralOutpoint.hash.IsNull()) {
                    st.collateralOutpoint.hash  = proRegTxHash;
                    st.collateralOutpoint.index = ptx.collateralOutpoint.index;
                } else {
                    st.collateralOutpoint = ptx.collateralOutpoint;
                }
                st.keyIDOwner        = ptx.keyIDOwner;
                st.pubKeyOperator    = ptx.pubKeyOperator;
                st.keyIDVoting       = ptx.keyIDVoting;
                st.nOperatorReward   = ptx.nOperatorReward;
                st.scriptPayout.m_data = ptx.scriptPayout.m_data;
                st.netInfo           = ptx.netInfo;
                if (ptx.nType == vendor::MnType::EVO) {
                    st.platformNodeID    = ptx.platformNodeID;
                    st.platformP2PPort   = ptx.platformP2PPort;
                    st.platformHTTPPort  = ptx.platformHTTPPort;
                }
                // Replace any existing MN sharing the same collateral
                // outpoint (external-collateral re-registration case
                // — dashcore specialtxman.cpp:267-279).
                auto coll_it = m_collateral_index.find(st.collateralOutpoint);
                if (coll_it != m_collateral_index.end()) {
                    m_entries.erase(coll_it->second);
                    m_collateral_index.erase(coll_it);
                }
                m_collateral_index[st.collateralOutpoint] = proRegTxHash;
                m_entries.emplace(proRegTxHash, std::move(st));
                ++r.registered;
                break;
              }
              case 2: { // PROVIDER_UPDATE_SERVICE
                vendor::CProUpServTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpServTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) break; // unknown MN
                it->second.netInfo = ptx.netInfo;
                it->second.scriptOperatorPayout.m_data =
                    ptx.scriptOperatorPayout.m_data;
                if (ptx.nType == vendor::MnType::EVO) {
                    it->second.platformNodeID = ptx.platformNodeID;
                    if (ptx.nVersion < vendor::ProTxVersion::EXT_ADDR) {
                        it->second.platformP2PPort  = ptx.platformP2PPort;
                        it->second.platformHTTPPort = ptx.platformHTTPPort;
                    }
                }
                // PoSe revive (dashcore specialtxman.cpp:361-370).
                if (it->second.nPoSeBanHeight != 0) {
                    it->second.nPoSeBanHeight   = 0;
                    it->second.nPoSeRevivedHeight = height;
                    it->second.isValid          = true;
                }
                ++r.updated;
                break;
              }
              case 3: { // PROVIDER_UPDATE_REGISTRAR
                vendor::CProUpRegTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpRegTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) break;
                bool key_changed = (it->second.pubKeyOperator
                                  != ptx.pubKeyOperator);
                it->second.pubKeyOperator   = ptx.pubKeyOperator;
                it->second.keyIDVoting      = ptx.keyIDVoting;
                it->second.scriptPayout.m_data = ptx.scriptPayout.m_data;
                if (key_changed) {
                    // dashcore: ResetOperatorFields + BanIfNotBanned.
                    it->second.nPoSeBanHeight = height;
                    it->second.isValid        = false;
                }
                ++r.updated;
                break;
              }
              case 4: { // PROVIDER_UPDATE_REVOKE
                vendor::CProUpRevTx ptx;
                if (!vendor::parse_protx_payload(tx.extra_payload, ptx)) {
                    LOG_WARNING << "[MNS-SM] CProUpRevTx parse failed h=" << height;
                    break;
                }
                auto it = m_entries.find(ptx.proTxHash);
                if (it == m_entries.end()) break;
                it->second.nPoSeBanHeight   = height;
                it->second.isValid          = false;
                it->second.nRevocationReason = ptx.nReason;
                // Operator key reset (until a future ProUpServTx
                // provides a new operator key + revives).
                it->second.pubKeyOperator.fill(0);
                ++r.revoked;
                break;
              }
            }
        }

        // ── Pass 2: collateral spends ──────────────────────────────
        // Walk all non-coinbase txs again; for each vin, check if it
        // spends a known MN's collateral. dashcore does this AFTER
        // pass 1 — we mirror.
        for (size_t i = 1; i < block.m_txs.size(); ++i) {
            const auto& tx = block.m_txs[i];
            for (const auto& in : tx.vin) {
                auto it = m_collateral_index.find(in.prevout);
                if (it == m_collateral_index.end()) continue;
                m_entries.erase(it->second);
                m_collateral_index.erase(it);
                ++r.spent;
            }
        }

        // ── Pass 3: payee resolution ──────────────────────────────
        if (!block.m_txs.empty()) {
            const auto& cb = block.m_txs[0];
            for (const auto& vout : cb.vout) {
                auto matched = find_by_payout_script(vout.scriptPubKey.m_data);
                if (!matched) continue;
                auto it = m_entries.find(*matched);
                if (it == m_entries.end()) continue;
                bool was_consecutive = (it->second.nLastPaidHeight == height - 1);
                it->second.nLastPaidHeight = height;
                if (it->second.nType == vendor::MnType::EVO) {
                    it->second.nConsecutivePayments =
                        was_consecutive ? it->second.nConsecutivePayments + 1 : 1;
                } else {
                    it->second.nConsecutivePayments = 0;
                }
                ++r.paid;
            }
        }

        r.total_after = m_entries.size();
        return r;
    }

private:
    std::map<uint256, MNState>                                          m_entries;
    std::map<bitcoin_family::coin::TxPrevOut, uint256, TxPrevOutLess>   m_collateral_index;

    // Compute a tx's identifying hash. Mirrors dashcore's
    // CTransaction::GetHash() which is SHA256d(serialized_tx).
    // Dash has no segwit so there's no witness/non-witness distinction.
    static uint256 compute_tx_hash(const MutableTransaction& tx)
    {
        ::PackStream s;
        s << tx;
        auto sp = s.get_span();
        uint256 h;
        CHash256()
            .Write(std::span<const unsigned char>(
                reinterpret_cast<const unsigned char*>(sp.data()), sp.size()))
            .Finalize(std::span<unsigned char>(h.data(), 32));
        return h;
    }
};

} // namespace coin
} // namespace dash
