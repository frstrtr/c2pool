// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Convert.hpp"

#include "../hdkeys/Address.hpp"   // encode_p2pkh / encode_p2sh / encode_segwit_v (M1-A codecs)
#include "../hdkeys/HexUtil.hpp"   // to_hex

#include <core/address_utils.hpp>  // core::classify_address_for_coin (the #961 engine)

#include <array>

namespace c2w::convert {

const char* status_str(Status s)
{
    switch (s) {
        case Status::Ok:                       return "ok";
        case Status::RefuseSourceForeign:      return "refuse: source address is foreign to its claimed coin";
        case Status::RefuseSourceInvalid:      return "refuse: source address unparseable under the source SSOT";
        case Status::RefuseBchNoPrefixSwap:    return "refuse: BCH is never a prefix swap (use the BCH transcode helper)";
        case Status::RefuseTypeAbsentOnTarget: return "refuse: address type is absent on the target coin";
        case Status::RefuseNetworkMismatch:    return "refuse: mainnet<->testnet conversion";
        case Status::RefuseTargetEncodeFailed: return "refuse: target re-encode failed";
        case Status::RefuseRoundTripFailed:    return "refuse: round-trip proof failed (payload changed)";
        case Status::RefuseUnknownCoin:        return "refuse: unknown coin";
    }
    return "refuse: unknown status";
}

const char* addr_type_str(AddrType t)
{
    switch (t) {
        case AddrType::P2PKH:  return "P2PKH";
        case AddrType::P2SH:   return "P2SH";
        case AddrType::P2WPKH: return "P2WPKH";
        case AddrType::P2WSH:  return "P2WSH";
        case AddrType::P2TR:   return "P2TR";
        case AddrType::Unknown:return "Unknown";
    }
    return "Unknown";
}

AddrType classify_script_type(const std::vector<unsigned char>& s)
{
    const size_t n = s.size();
    if (n == 25 && s[0] == 0x76 && s[1] == 0xa9 && s[2] == 0x14 &&
        s[23] == 0x88 && s[24] == 0xac) return AddrType::P2PKH;
    if (n == 23 && s[0] == 0xa9 && s[1] == 0x14 && s[22] == 0x87) return AddrType::P2SH;
    if (n == 22 && s[0] == 0x00 && s[1] == 0x14) return AddrType::P2WPKH;
    if (n == 34 && s[0] == 0x00 && s[1] == 0x20) return AddrType::P2WSH;
    if (n == 34 && s[0] == 0x51 && s[1] == 0x20) return AddrType::P2TR;
    return AddrType::Unknown;
}

// Extract the raw hash160 / witness program from a classified scriptPubKey.
static std::vector<uint8_t> extract_payload(const std::vector<unsigned char>& s, AddrType t)
{
    switch (t) {
        case AddrType::P2PKH:  return {s.begin() + 3, s.begin() + 23};
        case AddrType::P2SH:   return {s.begin() + 2, s.begin() + 22};
        case AddrType::P2WPKH: return {s.begin() + 2, s.begin() + 22};
        case AddrType::P2WSH:  return {s.begin() + 2, s.begin() + 34};
        case AddrType::P2TR:   return {s.begin() + 2, s.begin() + 34};
        default:               return {};
    }
}

std::string payload_hex_of(const std::vector<unsigned char>& s)
{
    auto p = extract_payload(s, classify_script_type(s));
    return c2w::hdkeys::to_hex(p);
}

ConvertResult convert_address(const std::string& address,
                              const ConvertCoin& src,
                              const ConvertCoin& tgt)
{
    ConvertResult r;
    r.source_address = address;

    // #961 guard (a): BCH is never a prefix swap.
    if (src.is_bch || tgt.is_bch) {
        r.status = Status::RefuseBchNoPrefixSwap;
        r.reason = status_str(r.status);
        return r;
    }

    // #961 guard (c): mainnet<->testnet is refused up front.
    if (src.testnet != tgt.testnet) {
        r.status = Status::RefuseNetworkMismatch;
        r.reason = status_str(r.status);
        return r;
    }

    // Step 1 — decode+classify under the SOURCE SSOT. Must be Own (#961 guard d).
    std::vector<unsigned char> script;
    auto m = core::classify_address_for_coin(address, acceptance_of(src), script);
    if (m == core::AddressCoinMatch::Foreign) {
        r.status = Status::RefuseSourceForeign; r.reason = status_str(r.status); return r;
    }
    if (m == core::AddressCoinMatch::Invalid) {
        r.status = Status::RefuseSourceInvalid; r.reason = status_str(r.status); return r;
    }

    // Step 2 — extract {type, payload}.
    r.script = script;
    r.type   = classify_script_type(script);
    if (r.type == AddrType::Unknown) {
        r.status = Status::RefuseSourceInvalid;
        r.reason = "refuse: source scriptPubKey is not a recognised single-type output";
        return r;
    }
    auto payload = extract_payload(script, r.type);
    r.source_payload_hex = c2w::hdkeys::to_hex(payload);

    // Step 3 — capability-gate the TARGET (#961 guard b).
    const bool need_segwit  = (r.type == AddrType::P2WPKH || r.type == AddrType::P2WSH);
    const bool need_taproot = (r.type == AddrType::P2TR);
    if (need_segwit && tgt.segwit_hrp.empty()) {
        r.status = Status::RefuseTypeAbsentOnTarget; r.reason = status_str(r.status); return r;
    }
    if (need_taproot && (!tgt.has_taproot || tgt.segwit_hrp.empty())) {
        r.status = Status::RefuseTypeAbsentOnTarget; r.reason = status_str(r.status); return r;
    }

    // Step 4 — re-encode the SAME payload under the TARGET SSOT. Base58 via the
    // M1-A codecs; segwit v0 as bech32; taproot as bech32m (encode_segwit_v with
    // the BIP-350 constant — the in-tree bech32::encode_segwit hardcodes bech32).
    std::string out;
    switch (r.type) {
        case AddrType::P2PKH: {
            std::array<uint8_t, 20> h{};
            std::copy(payload.begin(), payload.end(), h.begin());
            out = c2w::hdkeys::encode_p2pkh(tgt.p2pkh_version, h);
            break;
        }
        case AddrType::P2SH: {
            std::array<uint8_t, 20> h{};
            std::copy(payload.begin(), payload.end(), h.begin());
            out = c2w::hdkeys::encode_p2sh(tgt.p2sh_version, h);
            break;
        }
        case AddrType::P2WPKH:
        case AddrType::P2WSH:
            out = c2w::hdkeys::encode_segwit_v(tgt.segwit_hrp, 0, payload, /*bech32m=*/false);
            break;
        case AddrType::P2TR:
            out = c2w::hdkeys::encode_segwit_v(tgt.segwit_hrp, 1, payload, /*bech32m=*/true);
            break;
        default:
            break;
    }
    if (out.empty()) {
        r.status = Status::RefuseTargetEncodeFailed; r.reason = status_str(r.status); return r;
    }
    r.target_address = out;

    // Step 5 — MANDATORY round-trip proof (#961). Decode the produced address
    // under the TARGET SSOT and require Own AND a byte-identical scriptPubKey;
    // that proves the hash160/program is unchanged (no fund misdirection).
    std::vector<unsigned char> script2;
    auto m2 = core::classify_address_for_coin(out, acceptance_of(tgt), script2);
    r.target_payload_hex = payload_hex_of(script2);
    if (m2 != core::AddressCoinMatch::Own || script2 != script) {
        r.status = Status::RefuseRoundTripFailed; r.reason = status_str(r.status); return r;
    }

    r.status = Status::Ok;
    r.reason = status_str(r.status);
    return r;
}

ConvertResult convert_address(const std::string& address,
                              const std::string& source_ticker,
                              const std::string& target_ticker)
{
    const ConvertCoin* s = convert_coin(source_ticker);
    const ConvertCoin* t = convert_coin(target_ticker);
    if (!s || !t) {
        ConvertResult r;
        r.source_address = address;
        r.status = Status::RefuseUnknownCoin;
        r.reason = status_str(r.status);
        return r;
    }
    return convert_address(address, *s, *t);
}

} // namespace c2w::convert
