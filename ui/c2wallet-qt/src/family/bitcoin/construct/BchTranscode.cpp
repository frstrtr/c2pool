// SPDX-License-Identifier: AGPL-3.0-or-later
#include "BchTranscode.hpp"

#include "../hdkeys/Address.hpp"   // encode_p2pkh / encode_p2sh
#include "../hdkeys/HexUtil.hpp"   // to_hex

#include <core/address_utils.hpp>       // core::classify_address_for_coin
#include <impl/bch/coin/cashaddr.hpp>   // bch::coin::cashaddr codec (header-only)

#include <array>

namespace c2w::convert {

namespace cash = bch::coin::cashaddr;

TranscodeResult bch_cashaddr_to_base58(const std::string& cashaddr,
                                       const ConvertCoin& tgt,
                                       const std::string& cashaddr_prefix)
{
    TranscodeResult r;
    r.source_address = cashaddr;

    if (tgt.is_bch) { r.reason = "refuse: base58 target must not itself be BCH"; return r; }

    // Decode the CashAddr to {type, hash} under the given network prefix.
    auto content = cash::DecodeCashAddrContent(cashaddr, cashaddr_prefix);
    if (content.IsNull()) { r.reason = "refuse: not a valid CashAddr for this network"; return r; }

    if (content.hash.size() != 20) {
        r.reason = "refuse: only 20-byte P2PKH/P2SH CashAddr transcode to base58 (P2SH32 has no base58 form)";
        return r;
    }

    std::array<uint8_t, 20> h{};
    std::copy(content.hash.begin(), content.hash.end(), h.begin());

    std::string out;
    if (content.type == cash::PUBKEY_TYPE || content.type == cash::TOKEN_PUBKEY_TYPE) {
        r.type = AddrType::P2PKH;
        out = c2w::hdkeys::encode_p2pkh(tgt.p2pkh_version, h);
    } else { // SCRIPT_TYPE / TOKEN_SCRIPT_TYPE, 20-byte
        r.type = AddrType::P2SH;
        out = c2w::hdkeys::encode_p2sh(tgt.p2sh_version, h);
    }
    if (out.empty()) { r.reason = "refuse: base58 re-encode failed"; return r; }

    // Round-trip proof: decode the produced base58 under the target SSOT and
    // require the SAME 20-byte payload (no misdirection).
    std::vector<unsigned char> script2;
    auto m = core::classify_address_for_coin(out, acceptance_of(tgt), script2);
    if (m != core::AddressCoinMatch::Own) { r.reason = "refuse: round-trip decode not Own to target"; return r; }
    // The scriptPubKey embeds the payload at a fixed offset (P2PKH@3, P2SH@2).
    const size_t off = (r.type == AddrType::P2PKH) ? 3 : 2;
    if (script2.size() < off + 20 ||
        !std::equal(content.hash.begin(), content.hash.end(), script2.begin() + off)) {
        r.reason = "refuse: round-trip payload mismatch";
        return r;
    }

    r.target_address = out;
    r.payload_hex    = c2w::hdkeys::to_hex(content.hash);
    r.ok             = true;
    r.reason         = "ok";
    return r;
}

TranscodeResult base58_to_bch_cashaddr(const std::string& address,
                                       const ConvertCoin& src,
                                       const ConvertCoin& bch)
{
    TranscodeResult r;
    r.source_address = address;

    if (src.is_bch) { r.reason = "refuse: base58 source must not itself be BCH"; return r; }
    if (!bch.is_bch || bch.cashaddr_prefix.empty()) { r.reason = "refuse: target is not a BCH network"; return r; }

    // Decode+classify the base58 source under its SSOT — must be Own.
    std::vector<unsigned char> script;
    auto m = core::classify_address_for_coin(address, acceptance_of(src), script);
    if (m != core::AddressCoinMatch::Own) { r.reason = "refuse: source not Own to its claimed base58 coin"; return r; }

    AddrType t = classify_script_type(script);
    cash::CashAddrContent content;
    size_t off = 0;
    if (t == AddrType::P2PKH)      { content.type = cash::PUBKEY_TYPE; off = 3; }
    else if (t == AddrType::P2SH)  { content.type = cash::SCRIPT_TYPE; off = 2; }
    else { r.reason = "refuse: only P2PKH/P2SH base58 addresses transcode to CashAddr"; return r; }
    r.type = t;
    content.hash.assign(script.begin() + off, script.begin() + off + 20);

    std::string out = cash::EncodeCashAddr(bch.cashaddr_prefix, content);
    if (out.empty()) { r.reason = "refuse: CashAddr re-encode failed"; return r; }

    // Round-trip proof: the produced CashAddr must decode back to the SAME
    // scriptPubKey under the BCH codec.
    std::vector<unsigned char> script2 = cash::cashaddr_to_script(out, bch.cashaddr_prefix);
    if (script2 != script) { r.reason = "refuse: round-trip payload mismatch"; return r; }

    r.target_address = out;
    r.payload_hex    = c2w::hdkeys::to_hex(content.hash);
    r.ok             = true;
    r.reason         = "ok";
    return r;
}

} // namespace c2w::convert
