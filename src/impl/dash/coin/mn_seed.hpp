// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

/// E2c (#738): RPC MN-set seed — dashd `protx list valid true` JSON ->
/// the payout-bearing DMN baseline CoinStateMaintainer::on_mn_list_update()
/// loads at cold start.
///
/// THE GAP THIS CLOSES (proven by E2a): NodeCoinState::populated() needs BOTH
/// a header tip AND a payout-bearing masternode set. The live coin-P2P legs
/// deliver the tip half fast, but the P2P Simplified MN List (mnlistdiff)
/// OMITS scriptPayout + nLastPaidHeight — so leg 4 alone can never assemble a
/// payee-complete set, and building one from block bodies alone needs a full
/// DIP3-height special-tx replay (the heavier E2d follow-up). Until a seed
/// exists, populated() stays false forever on a cold start and get_work()
/// routes to the dashd-RPC fallback arm.
///
/// THE SEED: when a coin-RPC is configured (the mining-hotel posture — dashd
/// present), fetch the full valid deterministic-MN set ONCE at startup via
/// `protx list valid true` and convert it here into the exact
/// vector<pair<proTxHash, MNState>> the maintainer's resync leg takes. That
/// JSON carries everything payee selection needs that the SML does not:
///   - state.payoutAddress   -> MNState.scriptPayout      (the payee itself)
///   - state.lastPaidHeight  -> MNState.nLastPaidHeight   (GetMNPayee order)
///   - state.registeredHeight / PoSeRevivedHeight / PoSeBanHeight
///                           -> CompareByLastPaid_GetHeight inputs
/// `protx diff` (even extended) was rejected as the seed source: it carries
/// payoutAddress but NOT lastPaidHeight/registeredHeight, so a diff-seeded set
/// would rank every MN equal and project the WRONG payee — exactly the
/// bad-cb-payee class the coinbase fix (#746) closed. Never mint payees from
/// payout-incomplete data.
///
/// ADDRESS -> SCRIPT round trip: dashd consensus (CheckService on ProRegTx /
/// ProUpRegTx) only admits P2PKH / P2SH payout scripts, and payoutAddress is
/// EncodeDestination(scriptPayout). Decoding it back through base58check +
/// hash160_to_merged_script reproduces the script BYTE-EXACTLY, and
/// embedded_gbt's script_to_address() re-encodes the identical address dashd's
/// getblocktemplate reports — the byte-faithful payee equality the E2c gate
/// asserts.
///
/// FAIL-CLOSED: if ANY entry's payoutAddress cannot be decoded against the
/// coin's version bytes, the WHOLE seed is aborted (empty return). A partial
/// set could rank a skipped MN's payment slot onto the wrong payee; an empty
/// set is a set-gap that keeps populated() false and get_work() on the dashd
/// fallback — safe by construction.
///
/// STRICTLY single-coin: src/impl/dash/coin/ only. Pure function over
/// nlohmann::json — network-free, KAT-pinned (test_dash_mn_seed.cpp).

#include <impl/dash/coin/mn_state_db.hpp>        // MNState
#include <impl/dash/coin/vendor/providertx.hpp>  // MnType / ProTxVersion / BLS_PUBKEY_SIZE

#include <core/address_utils.hpp>  // base58check_to_hash160 / is_address_for_chain / hash160_to_merged_script
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <cmath>
#include <cstdint>
#include <set>
#include <string>
#include <utility>
#include <vector>

namespace dash {
namespace coin {

/// Observability counters for the seed parse (logged at the call site and
/// pinned by the KAT).
struct MnSeedStats {
    size_t total{0};           // JSON entries walked
    size_t seeded{0};          // entries converted into the returned vector
    size_t evo{0};             // of which Evo (platform) MNs
    size_t payout_decode_failed{0};  // payoutAddress undecodable -> seed ABORTED
    size_t malformed{0};       // entry missing proTxHash/state -> seed ABORTED
};

namespace detail {

// dashd's detailed protx JSON uses -1 as the "never" sentinel for
// lastPaidHeight / PoSeRevivedHeight / PoSeBanHeight. Internally we store 0
// for "never" (see mn_state_machine.hpp find_expected_payee's SENTINEL note —
// storing the raw uint32 wrap of -1 is the exact bug class that produced a
// constant expected-payee and 100% [PAY] MISMATCH). Clamp negatives to 0.
inline uint32_t sane_height_json(const nlohmann::json& j, const char* key)
{
    if (!j.contains(key) || !j[key].is_number()) return 0;
    const int64_t v = j[key].get<int64_t>();
    return v > 0 ? static_cast<uint32_t>(v) : 0u;
}

// Decode a base58check P2PKH/P2SH address into its scriptPubKey using the
// coin's version bytes. Empty return == undecodable (caller fail-closes).
inline std::vector<unsigned char> payout_address_to_script(
    const std::string& addr, uint8_t address_version, uint8_t address_p2sh_version)
{
    if (addr.empty()) return {};
    const char* type = nullptr;
    if (::core::is_address_for_chain(addr, {}, {address_version}))
        type = "p2pkh";
    else if (::core::is_address_for_chain(addr, {}, {address_p2sh_version}))
        type = "p2sh";
    else
        return {};
    const std::string h160 = ::core::base58check_to_hash160(addr);
    if (h160.size() != 40) return {};  // bad checksum / malformed
    return ::core::hash160_to_merged_script(h160, type);
}

// base58check hash160 payload -> uint160 (internal byte order: the payload
// bytes ARE dashcore's CKeyID raw bytes, so build from the byte vector
// directly — SetHex would byte-reverse them).
inline uint160 hash160_hex_to_uint160(const std::string& h160_hex)
{
    if (h160_hex.size() != 40) return uint160();
    std::vector<unsigned char> bytes;
    bytes.reserve(20);
    for (size_t i = 0; i < 40; i += 2)
        bytes.push_back(static_cast<unsigned char>(
            std::stoul(h160_hex.substr(i, 2), nullptr, 16)));
    return uint160(bytes);
}

inline std::array<uint8_t, vendor::BLS_PUBKEY_SIZE>
parse_bls_pubkey_hex(const std::string& hex)
{
    std::array<uint8_t, vendor::BLS_PUBKEY_SIZE> out{};
    if (hex.size() != vendor::BLS_PUBKEY_SIZE * 2) return out;
    for (size_t i = 0; i < vendor::BLS_PUBKEY_SIZE; ++i)
        out[i] = static_cast<uint8_t>(
            std::stoul(hex.substr(i * 2, 2), nullptr, 16));
    return out;
}

// Strict 64-lowercase/uppercase-hex check for RPC hash strings. uint256S is
// TOLERANT of short/garbage input (parses what it can), which would key a
// seeded MN under a wrong/zero hash that later apply_block updates never
// match — a silent drift instead of the contracted fail-closed abort.
inline bool is_hex256(const std::string& s)
{
    if (s.size() != 64) return false;
    for (char c : s)
        if (!((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')
              || (c >= 'A' && c <= 'F')))
            return false;
    return true;
}

} // namespace detail

/// Convert a dashd `protx list valid true` (detailed) JSON array into the
/// (proTxHash -> MNState) vector CoinStateMaintainer::on_mn_list_update()
/// takes. Returns EMPTY on any malformed entry or undecodable payoutAddress
/// (fail-closed: a partial set could project the wrong payee; an empty set is
/// a safe set-gap that keeps the dashd fallback serving).
inline std::vector<std::pair<uint256, MNState>> parse_protx_list_seed(
    const nlohmann::json& list,
    uint8_t address_version,
    uint8_t address_p2sh_version,
    MnSeedStats* stats = nullptr)
{
    MnSeedStats st;
    std::vector<std::pair<uint256, MNState>> out;
    if (!list.is_array()) {
        LOG_WARNING << "[MN-SEED] protx list result is not an array -- seed aborted";
        if (stats) *stats = st;
        return {};
    }
    out.reserve(list.size());

    // Duplicate-collateral guard: MnStateMachine::load() keys a collateral
    // index by outpoint, so two seeded MNs sharing one would silently shadow
    // each other there. Real dashd output cannot contain duplicates (DIP3
    // consensus enforces unique collaterals); seeing one means the input is
    // not a real protx list — fail closed.
    std::set<std::pair<uint256, uint32_t>> seen_collateral;

    for (const auto& e : list) {
        ++st.total;
        bool entry_malformed = false;
        try {
        if (!e.is_object() || !e.contains("proTxHash")
            || !e["proTxHash"].is_string()
            || !detail::is_hex256(e["proTxHash"].get<std::string>())
            || !e.contains("state") || !e["state"].is_object()) {
            entry_malformed = true;
        }
        if (entry_malformed) {
            ++st.malformed;
            LOG_WARNING << "[MN-SEED] malformed protx entry (#" << st.total
                        << ": bad proTxHash/state) -- seed aborted";
            if (stats) *stats = st;
            return {};
        }
        const auto& s = e["state"];

        MNState mn;

        // Identity / registration facets.
        const uint256 proTxHash = uint256S(e["proTxHash"].get<std::string>());
        if (e.contains("collateralHash") && e["collateralHash"].is_string()
            && detail::is_hex256(e["collateralHash"].get<std::string>()))
            mn.collateralOutpoint.hash =
                uint256S(e["collateralHash"].get<std::string>());
        if (e.contains("collateralIndex") && e["collateralIndex"].is_number())
            mn.collateralOutpoint.index = e["collateralIndex"].get<uint32_t>();
        if (!seen_collateral.emplace(mn.collateralOutpoint.hash,
                                     mn.collateralOutpoint.index).second) {
            ++st.malformed;
            LOG_WARNING << "[MN-SEED] duplicate collateral outpoint in protx"
                           " list (proTx " << proTxHash.GetHex().substr(0, 16)
                        << ") -- seed aborted (not a real DIP3 set)";
            if (stats) *stats = st;
            return {};
        }
        // JSON reports operatorReward as a percentage double (dashd ToJson:
        // nOperatorReward / 100.0); recover the internal 0..10000 fixed-point.
        if (e.contains("operatorReward") && e["operatorReward"].is_number())
            mn.nOperatorReward = static_cast<uint16_t>(
                std::llround(e["operatorReward"].get<double>() * 100.0));
        const std::string type_str = e.value("type", "Regular");
        mn.nType = (type_str == "Evo" || type_str == "HighPerformance")
                       ? vendor::MnType::EVO
                       : vendor::MnType::REGULAR;
        if (mn.nType == vendor::MnType::EVO) ++st.evo;

        // Per-block state-machine facets (the GetMNPayee ordering inputs the
        // SML can never provide — the reason protx diff was rejected).
        if (s.contains("version") && s["version"].is_number())
            mn.nVersion = s["version"].get<uint16_t>();
        mn.nRegisteredHeight    = detail::sane_height_json(s, "registeredHeight");
        mn.nLastPaidHeight      = detail::sane_height_json(s, "lastPaidHeight");
        mn.nPoSeRevivedHeight   = detail::sane_height_json(s, "PoSeRevivedHeight");
        mn.nPoSeBanHeight       = detail::sane_height_json(s, "PoSeBanHeight");
        mn.nConsecutivePayments =
            detail::sane_height_json(s, "consecutivePayments");
        if (s.contains("revocationReason") && s["revocationReason"].is_number())
            mn.nRevocationReason = s["revocationReason"].get<uint16_t>();
        // `protx list valid` already filters to non-banned MNs; keep the
        // defensive ban-height projection anyway.
        mn.isValid = (mn.nPoSeBanHeight == 0);

        // THE payee keystone: payoutAddress -> scriptPayout, byte-exact.
        mn.scriptPayout.m_data = detail::payout_address_to_script(
            s.value("payoutAddress", ""), address_version, address_p2sh_version);
        if (mn.scriptPayout.m_data.empty()) {
            ++st.payout_decode_failed;
            LOG_WARNING << "[MN-SEED] undecodable payoutAddress '"
                        << s.value("payoutAddress", "") << "' for proTx "
                        << proTxHash.GetHex().substr(0, 16)
                        << " -- seed aborted (fail-closed: partial sets mint"
                           " wrong payees)";
            if (stats) *stats = st;
            return {};
        }
        // Operator payout (optional, best-effort — not payee-critical today;
        // operator-payout coinbase matching is a documented non-goal of the
        // state machine).
        const std::string op_addr = s.value("operatorPayoutAddress", "");
        if (!op_addr.empty())
            mn.scriptOperatorPayout.m_data = detail::payout_address_to_script(
                op_addr, address_version, address_p2sh_version);

        // Governance keys (best-effort; not consumed by payee projection).
        mn.keyIDOwner  = detail::hash160_hex_to_uint160(
            ::core::base58check_to_hash160(s.value("ownerAddress", "")));
        mn.keyIDVoting = detail::hash160_hex_to_uint160(
            ::core::base58check_to_hash160(s.value("votingAddress", "")));
        mn.pubKeyOperator =
            detail::parse_bls_pubkey_hex(s.value("pubKeyOperator", ""));

        out.emplace_back(proTxHash, std::move(mn));
        ++st.seeded;
        } catch (const nlohmann::json::exception& ex) {
            // Type mismatch anywhere in the entry (numeric proTxHash,
            // non-numeric height, ...): the parser's contract is a FAIL-CLOSED
            // empty return, never an escaping throw.
            ++st.malformed;
            LOG_WARNING << "[MN-SEED] protx entry #" << st.total
                        << " JSON type error (" << ex.what()
                        << ") -- seed aborted";
            if (stats) *stats = st;
            return {};
        }
    }

    if (stats) *stats = st;
    return out;
}

} // namespace coin
} // namespace dash
