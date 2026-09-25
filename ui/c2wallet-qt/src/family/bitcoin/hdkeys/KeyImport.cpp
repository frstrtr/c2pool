// SPDX-License-Identifier: AGPL-3.0-or-later
#include "KeyImport.hpp"

#include "CoinParams.hpp"
#include "HexUtil.hpp"
#include "Secp.hpp"

#include <btclibs/base58.h>

namespace c2w::hdkeys {

WifDecode decode_wif(const std::string& wif)
{
    WifDecode r;
    std::vector<unsigned char> raw;
    if (!DecodeBase58Check(wif, raw, 40)) { r.error = "not valid base58check"; return r; }
    // version(1) + 32 scalar [+ 0x01 compressed flag]
    if (raw.size() != 33 && raw.size() != 34) { r.error = "wrong WIF payload length"; return r; }
    r.version = raw[0];
    if (raw.size() == 34) {
        if (raw[33] != 0x01) { r.error = "bad compressed flag byte"; return r; }
        r.compressed = true;
    } else {
        r.compressed = false;
    }
    // Range-check the scalar.
    if (!Secp::instance().seckey_verify(raw.data() + 1)) {
        r.error = "private key out of range (must be 1 <= k < N)";
        secure::secure_wipe(raw.data(), raw.size());
        return r;
    }
    r.scalar.assign(raw.data() + 1, 32);
    for (const CoinParams* c : coins_by_wif_version(r.version)) r.coin_tickers.push_back(c->ticker);
    secure::secure_wipe(raw.data(), raw.size());
    r.ok = true;
    return r;
}

RawHexDecode decode_raw_hex(const std::string& hex, bool compressed)
{
    RawHexDecode r;
    r.compressed = compressed;
    std::string s = hex;
    // Trim whitespace and an optional 0x prefix.
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.erase(s.begin());
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\n')) s.pop_back();
    if (s.size() >= 2 && s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) s = s.substr(2);
    if (s.size() != 64) { r.error = "raw private key must be 64 hex chars (32 bytes)"; return r; }
    auto bytes = from_hex(s);
    if (!bytes) { r.error = "not valid hex"; return r; }
    if (!Secp::instance().seckey_verify(bytes->data())) {
        r.error = "private key out of range (must be 1 <= k < N)";
        secure::secure_wipe(bytes->data(), bytes->size());
        return r;
    }
    r.scalar.assign(bytes->data(), 32);
    secure::secure_wipe(bytes->data(), bytes->size());
    r.ok = true;
    return r;
}

} // namespace c2w::hdkeys
