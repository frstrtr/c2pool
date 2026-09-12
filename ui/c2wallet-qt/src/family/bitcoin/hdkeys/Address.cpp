// SPDX-License-Identifier: AGPL-3.0-or-later
#include "Address.hpp"

#include "Bip32.hpp"   // hash160
#include "HexUtil.hpp"
#include "Secp.hpp"

#include <btclibs/base58.h>
#include <btclibs/bech32.h>
#include <btclibs/span.h>

namespace c2w::hdkeys {

std::string encode_p2pkh(uint8_t version, const std::array<uint8_t, 20>& h160)
{
    std::vector<unsigned char> v;
    v.reserve(21);
    v.push_back(version);
    v.insert(v.end(), h160.begin(), h160.end());
    return EncodeBase58Check(Span<const unsigned char>(v.data(), v.size()));
}

std::string encode_p2sh(uint8_t version, const std::array<uint8_t, 20>& h160)
{
    return encode_p2pkh(version, h160);   // identical framing, different version byte
}

// bech32 (v0) / bech32m (v1+) segwit encoder built on the vendored bech32
// detail machinery, parametrising only the BIP-350 checksum constant that the
// in-tree encode_segwit hardcodes to bech32.
std::string encode_segwit_v(const std::string& hrp, int witver,
                            const std::vector<uint8_t>& prog, bool bech32m)
{
    std::vector<uint8_t> data;
    data.push_back(static_cast<uint8_t>(witver));
    if (!bech32::detail::convertbits(prog, 8, 5, /*pad=*/true, data)) return {};

    // create_checksum with the correct constant: bech32 => ^1, bech32m => ^0x2bc830a3.
    const uint32_t xorconst = bech32m ? 0x2bc830a3u : 1u;
    auto values = bech32::detail::hrp_expand(hrp);
    values.insert(values.end(), data.begin(), data.end());
    values.resize(values.size() + 6);
    uint32_t mod = bech32::detail::polymod(values) ^ xorconst;
    for (int i = 0; i < 6; ++i)
        data.push_back(static_cast<uint8_t>((mod >> (5 * (5 - i))) & 31));

    std::string out = hrp + '1';
    for (uint8_t d : data) out += bech32::detail::CHARSET[d];
    return out;
}

static std::string p2pk_script(const std::vector<uint8_t>& pub)
{
    std::vector<uint8_t> s;
    s.push_back(static_cast<uint8_t>(pub.size()));  // 0x21 (33) or 0x41 (65)
    s.insert(s.end(), pub.begin(), pub.end());
    s.push_back(0xac);                              // OP_CHECKSIG
    return to_hex(s);
}

static std::string p2pkh_script(const std::array<uint8_t, 20>& h)
{
    std::vector<uint8_t> s = {0x76, 0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x88);
    s.push_back(0xac);
    return to_hex(s);
}

static std::string p2sh_script(const std::array<uint8_t, 20>& h)
{
    std::vector<uint8_t> s = {0xa9, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    s.push_back(0x87);
    return to_hex(s);
}

static std::string p2wpkh_script(const std::array<uint8_t, 20>& h)
{
    std::vector<uint8_t> s = {0x00, 0x14};
    s.insert(s.end(), h.begin(), h.end());
    return to_hex(s);
}

static std::string p2tr_script(const std::vector<uint8_t>& xonly32)
{
    std::vector<uint8_t> s = {0x51, 0x20};
    s.insert(s.end(), xonly32.begin(), xonly32.end());
    return to_hex(s);
}

std::vector<AddressCandidate> address_candidates(const std::vector<uint8_t>& pubkey,
                                                 const CoinParams& coin)
{
    std::vector<AddressCandidate> out;
    auto& secp = Secp::instance();

    std::vector<uint8_t> comp = pubkey.size() == 33 ? pubkey : secp.pubkey_reserialize(pubkey, true);
    std::vector<uint8_t> uncomp = pubkey.size() == 65 ? pubkey : secp.pubkey_reserialize(pubkey, false);
    if (comp.size() != 33 || uncomp.size() != 65) return out;  // unparseable pubkey

    // P2PK (both encodings) — bare script, no address form.
    out.push_back({ScriptHint::Unknown, "P2PK", "compressed", "", p2pk_script(comp)});
    out.push_back({ScriptHint::Unknown, "P2PK", "uncompressed", "", p2pk_script(uncomp)});

    // P2PKH (both encodings). hash160 differs per encoding => distinct addresses.
    auto hc = hash160(comp.data(), comp.size());
    auto hu = hash160(uncomp.data(), uncomp.size());
    out.push_back({ScriptHint::P2PKH, "P2PKH", "compressed",
                   encode_p2pkh(coin.p2pkh_version, hc), p2pkh_script(hc)});
    out.push_back({ScriptHint::P2PKH, "P2PKH", "uncompressed",
                   encode_p2pkh(coin.p2pkh_version, hu), p2pkh_script(hu)});

    const bool has_segwit = coin.bech32_hrp && coin.bech32_hrp[0] != '\0';
    if (has_segwit) {
        const std::string hrp = coin.bech32_hrp;
        // P2WPKH — segwit requires the compressed key.
        out.push_back({ScriptHint::P2WPKH, "P2WPKH", "compressed",
                       encode_segwit_v(hrp, 0, {hc.begin(), hc.end()}, /*bech32m=*/false),
                       p2wpkh_script(hc)});
        // P2SH-P2WPKH: redeemScript = 0x0014<h160>; scriptPubKey = HASH160(redeem).
        std::vector<uint8_t> redeem = {0x00, 0x14};
        redeem.insert(redeem.end(), hc.begin(), hc.end());
        auto hsh = hash160(redeem.data(), redeem.size());
        out.push_back({ScriptHint::P2SH_P2WPKH, "P2SH-P2WPKH", "compressed",
                       encode_p2sh(coin.p2sh_version, hsh), p2sh_script(hsh)});
        // P2TR key-path: x-only internal key -> taptweak -> output key.
        auto xonly = secp.xonly_serialize(comp);
        if (xonly.size() == 32) {
            auto q = secp.taproot_output_key_from_xonly(xonly.data());
            if (q.size() == 32)
                out.push_back({ScriptHint::P2TR, "P2TR", "x-only",
                               encode_segwit_v(hrp, 1, q, /*bech32m=*/true), p2tr_script(q)});
        }
    }
    return out;
}

std::vector<AddressCandidate> address_candidates_from_seckey(const uint8_t sk[32],
                                                             const CoinParams& coin)
{
    auto& secp = Secp::instance();
    std::vector<uint8_t> comp = secp.pubkey_create(sk, true);
    // P2TR is produced inside address_candidates() via the x-only taptweak; the
    // from-seckey and from-xonly output keys are identical for key-path spends.
    return address_candidates(comp, coin);
}

} // namespace c2w::hdkeys
