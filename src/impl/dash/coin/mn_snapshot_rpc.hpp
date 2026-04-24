#pragma once

/// Phase C-PAY step 3b: build a DmnSnapshot from dashd-RPC.
///
/// Two consumers:
///   1. Maintainer-side dumper (--dump-mn-snapshot OUTPUT_PATH):
///      one-time fetch + write to disk + print SHA256d pin so the
///      maintainer can update mn_snapshot.hpp's known_snapshots[]
///      and re-ship the in-tree snapshot.
///   2. Operator-side bootstrap fallback (step 3b2): if mn_state_db
///      is empty AND no in-tree pin matches AND --dashd-rpc set,
///      fetch fresh state from the operator's own dashd. Same
///      function, different invocation.
///
/// The "RPC stays optional" promise: this code path is only reached
/// when --dashd-rpc is configured. Operators running pure-P2P
/// (--dashd only) will rely on the in-tree snapshot.
///
/// JSON field shape: matches dashcore evo/dmnstate.cpp:39+ ToJson()
/// output (registeredHeight, lastPaidHeight, payoutAddress,
/// pubKeyOperator, ownerAddress, votingAddress, ...). payoutAddress
/// arrives as a base58-encoded P2PKH/P2SH; we reverse-decode via
/// dash::decode_payee_script() (the same helper used in
/// share_check.hpp / coinbase_builder.hpp).

#include <impl/dash/coin/mn_snapshot.hpp>
#include <impl/dash/coin/rpc.hpp>
#include <impl/dash/share_check.hpp>   // decode_payee_script
#include <core/log.hpp>
#include <core/uint256.hpp>

#include <nlohmann/json.hpp>

#include <fstream>
#include <optional>
#include <string>

namespace dash {
namespace coin {

/// Map a single `protx info` JSON object to an MNState. Uses
/// `address_version` / `p2sh_version` to reverse-decode payoutAddress
/// and operatorPayoutAddress to scriptPayout / scriptOperatorPayout
/// bytes (so the byte-level comparison against actual coinbase outputs
/// in step 5 works directly).
inline std::optional<MNState> mn_state_from_protx_info(
    const nlohmann::json& j,
    uint8_t address_version,
    uint8_t p2sh_version)
{
    try {
        // dashd's `protx info` wraps the actual state under "state":
        //   { proTxHash, collateralHash, collateralIndex, state: {...} }
        // We pull from `state` if present, otherwise treat j as the state
        // object directly (some dashd versions / RPC modes vary).
        const auto& s = j.contains("state") ? j["state"] : j;
        MNState m;
        m.nVersion = s.value("version", int(vendor::ProTxVersion::BASIC_BLS));
        // nType: dashd reports "type" as "Regular" or "Evo" (string).
        std::string typeStr = s.value("type", std::string("Regular"));
        m.nType = (typeStr == "Evo")
            ? vendor::MnType::EVO
            : vendor::MnType::REGULAR;
        // dashd reports -1 (signed int) in JSON for "never paid / never
        // revived / never banned" sentinel. Reading via s.value(..., 0)
        // returns int(-1); implicit conversion to uint32_t wraps to
        // UINT32_MAX. Then static_cast<int>(UINT32_MAX) in
        // find_expected_payee → -1, which beats every positive height
        // → that MN always wins the min-find. Result observed live on
        // mainnet: expected payee constant = lowest-hash never-paid MN
        // for all blocks → 100% [PAY] MISMATCH rate against dashd's
        // actual selection. Normalize -1 → 0 here, matching the
        // semantics that drive find_expected_payee's `if (h == 0)
        // h = nRegisteredHeight` fallback.
        auto take_height_or_zero = [&](const char* key) -> uint32_t {
            if (!s.contains(key)) return 0;
            int64_t v = s.value(key, int64_t{0});
            return (v < 0) ? 0u : static_cast<uint32_t>(v);
        };
        m.nRegisteredHeight    = take_height_or_zero("registeredHeight");
        m.nLastPaidHeight      = take_height_or_zero("lastPaidHeight");
        m.nConsecutivePayments = s.value("consecutivePayments", 0);
        m.nPoSeRevivedHeight   = take_height_or_zero("PoSeRevivedHeight");
        m.nPoSeBanHeight       = take_height_or_zero("PoSeBanHeight");
        m.nRevocationReason   = s.value("revocationReason", 0);
        // PoSeBanHeight == -1 in dashcore JSON when not banned; we
        // default to 0. dashd emits int, value() casts cleanly.
        m.isValid = (m.nPoSeBanHeight == 0
                  || m.nPoSeBanHeight == uint32_t(-1));

        // payoutAddress → scriptPayout via decode_payee_script.
        // operatorPayoutAddress is OPTIONAL (only set if Evo or
        // operator has set a script).
        if (s.contains("payoutAddress")) {
            std::string addr = s["payoutAddress"];
            auto bytes = dash::decode_payee_script(
                addr, address_version, p2sh_version);
            m.scriptPayout.m_data.assign(bytes.begin(), bytes.end());
        }
        if (s.contains("operatorPayoutAddress")) {
            std::string addr = s["operatorPayoutAddress"];
            auto bytes = dash::decode_payee_script(
                addr, address_version, p2sh_version);
            m.scriptOperatorPayout.m_data.assign(bytes.begin(), bytes.end());
        }

        // pubKeyOperator: 96-char hex string → 48 bytes.
        if (s.contains("pubKeyOperator")) {
            std::string hex = s["pubKeyOperator"];
            if (hex.size() == 96) {
                for (size_t i = 0; i < 48; ++i) {
                    m.pubKeyOperator[i] = static_cast<uint8_t>(
                        std::stoul(hex.substr(i * 2, 2), nullptr, 16));
                }
            }
        }

        // ownerAddress / votingAddress are base58 P2PKH addresses;
        // reverse to keyIDOwner / keyIDVoting (uint160).
        auto addr_to_keyid = [&](const std::string& addr) -> uint160 {
            std::vector<unsigned char> decoded;
            if (DecodeBase58Check(addr, decoded, 21) && decoded.size() == 21) {
                uint160 k;
                std::memcpy(k.data(), decoded.data() + 1, 20);
                return k;
            }
            return uint160{};
        };
        if (s.contains("ownerAddress")) {
            m.keyIDOwner = addr_to_keyid(s["ownerAddress"]);
        }
        if (s.contains("votingAddress")) {
            m.keyIDVoting = addr_to_keyid(s["votingAddress"]);
        }

        // Evo-only platform fields.
        if (m.nType == vendor::MnType::EVO) {
            if (s.contains("platformNodeID")) {
                std::string hex = s["platformNodeID"];
                if (hex.size() == 40) {
                    for (size_t i = 0; i < 20; ++i) {
                        m.platformNodeID.data()[i] = static_cast<uint8_t>(
                            std::stoul(hex.substr(i * 2, 2), nullptr, 16));
                    }
                }
            }
            m.platformP2PPort  = s.value("platformP2PPort", 0);
            m.platformHTTPPort = s.value("platformHTTPPort", 0);
        }
        return m;
    } catch (const std::exception& ex) {
        LOG_WARNING << "[MNS-RPC] mn_state_from_protx_info parse failed: "
                    << ex.what();
        return std::nullopt;
    }
}

/// Fetch the full active DMN list via dashd-RPC and pack into a
/// DmnSnapshot. Returns std::nullopt on RPC failure or if the list
/// is empty (which indicates either RPC misconfiguration or a fresh
/// regtest with no MNs).
inline std::optional<DmnSnapshot> build_snapshot_via_rpc(
    NodeRPC& rpc,
    uint8_t address_version,
    uint8_t p2sh_version)
{
    if (!rpc.is_connected()) {
        LOG_WARNING << "[MNS-RPC] RPC not connected — cannot dump snapshot";
        return std::nullopt;
    }
    nlohmann::json list;
    nlohmann::json info;
    try {
        // First: where does the snapshot anchor? Use chain tip.
        info = rpc.getblockchaininfo();
    } catch (const std::exception& e) {
        LOG_WARNING << "[MNS-RPC] getblockchaininfo failed: " << e.what();
        return std::nullopt;
    }
    DmnSnapshot snap;
    snap.version = SNAPSHOT_VERSION;
    snap.height  = info.value("blocks", 0);
    std::string tip_hex = info.value("bestblockhash", std::string{});
    if (tip_hex.size() == 64) snap.block_hash.SetHex(tip_hex);

    try {
        list = rpc.protx_list_registered();
    } catch (const std::exception& e) {
        LOG_WARNING << "[MNS-RPC] protx_list_registered failed: " << e.what();
        return std::nullopt;
    }
    if (!list.is_array() || list.empty()) {
        LOG_WARNING << "[MNS-RPC] protx list empty (regtest/testnet "
                       "or stale dashd?) — refusing snapshot";
        return std::nullopt;
    }

    snap.entries.reserve(list.size());
    size_t failed = 0;
    for (const auto& item : list) {
        std::string hex = item.is_string() ? item.get<std::string>() : "";
        if (hex.size() != 64) { ++failed; continue; }
        uint256 pro;
        pro.SetHex(hex);
        try {
            auto info_j = rpc.protx_info(pro);
            auto m = mn_state_from_protx_info(info_j, address_version, p2sh_version);
            if (!m) { ++failed; continue; }
            snap.entries.emplace_back(pro, std::move(*m));
        } catch (const std::exception& e) {
            LOG_WARNING << "[MNS-RPC] protx_info " << hex.substr(0, 16)
                        << "... failed: " << e.what();
            ++failed;
        }
    }
    LOG_INFO << "[MNS-RPC] built snapshot: " << snap.entries.size()
             << " entries (height=" << snap.height
             << " block=" << snap.block_hash.GetHex().substr(0, 16)
             << " failed=" << failed << ")";
    if (snap.entries.empty()) return std::nullopt;
    return snap;
}

/// Write a DmnSnapshot to disk and print the SHA256d pin (which the
/// maintainer copies into known_snapshots[] in mn_snapshot.hpp).
inline bool write_snapshot_file(const DmnSnapshot& snap, const std::string& path)
{
    auto bytes = encode_snapshot(snap);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    if (!f.is_open()) {
        LOG_WARNING << "[MNS-RPC] cannot open " << path << " for writing";
        return false;
    }
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    if (!f) {
        LOG_WARNING << "[MNS-RPC] write to " << path << " failed";
        return false;
    }
    f.close();
    auto pin = sha256d_bytes(std::span<const uint8_t>(bytes.data(), bytes.size()));
    LOG_INFO << "[MNS-RPC] wrote " << bytes.size() << " B to " << path;
    LOG_INFO << "[MNS-RPC] SHA256d pin: " << pin.GetHex();
    LOG_INFO << "[MNS-RPC] paste into mn_snapshot.hpp known_snapshots[]:";
    LOG_INFO << "[MNS-RPC]   { \"" << path << "\", uint256{}.SetHexFromString(\""
             << pin.GetHex() << "\") }";
    return true;
}

} // namespace coin
} // namespace dash
