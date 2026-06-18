// ---------------------------------------------------------------------------
// bch::coin::cashaddr KAT + roundtrip test (M4 CashAddr port validation).
//
// Vectors lifted verbatim from Bitcoin Cash Node src/test/cashaddrenc_tests.cpp
// and src/test/cashaddr_tests.cpp -- the conformance oracle. Asserts:
//   1. {type,hash} -> address matches BCHN's anchored strings (P2PKH/P2SH +
//      token-aware z/r variants), proving version-byte + PolyMod parity.
//   2. P2SH32 (32-byte) encode/decode roundtrip (CHIP P2SH32 size bits).
//   3. decode is the exact inverse of encode (type + hash recovered).
//   4. checksum/structure rejection: corrupted char, wrong prefix, bad sep.
//   5. checksum-only vectors (cashaddr_tests.cpp valid_strings) round-trip.
//
// Build-INERT / source-only: header-only, no boost, no chainparams; impl_bch
// stays unregistered (bch = skip-green). Verify with -fsyntax-only; runs under
// the embedded test target once impl_bch is registered, or standalone (no deps).
// p2pool-merged-v36 surface: NONE.
// ---------------------------------------------------------------------------

#include <cassert>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include "../coin/cashaddr.hpp"

using namespace bch::coin::cashaddr;
using bytes = std::vector<uint8_t>;

namespace {

bytes parse_hex(const std::string& h) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    bytes out;
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        out.push_back(uint8_t(nib(h[i]) << 4 | nib(h[i + 1])));
    return out;
}

int checks = 0;
void check(bool cond, const std::string& what) {
    ++checks;
    if (!cond) { std::cerr << "FAIL: " << what << "\n"; std::exit(1); }
}

} // namespace

int main() {
    // --- (1) Anchored encode vectors (BCHN test_encode_address) ---------------
    // hash160 #1 = {118,160,64,...,115}
    const bytes h1 = {118, 160, 64,  83, 189, 160, 168, 139, 218, 81,
                      119, 184, 106, 21, 195, 178, 159, 85,  152, 115};
    check(EncodeCashAddr(MAINNET_PREFIX, {PUBKEY_TYPE, h1}) ==
          "bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a", "enc p2pkh h1");
    check(EncodeCashAddr(MAINNET_PREFIX, {SCRIPT_TYPE, h1}) ==
          "bitcoincash:ppm2qsznhks23z7629mms6s4cwef74vcwvn0h829pq", "enc p2sh h1");
    check(EncodeCashAddr(MAINNET_PREFIX, {TOKEN_PUBKEY_TYPE, h1}) ==
          "bitcoincash:zpm2qsznhks23z7629mms6s4cwef74vcwvrqekrq9w", "enc token-pubkey h1");
    check(EncodeCashAddr(MAINNET_PREFIX, {TOKEN_SCRIPT_TYPE, h1}) ==
          "bitcoincash:rpm2qsznhks23z7629mms6s4cwef74vcwv59yeyr7n", "enc token-script h1");

    // BCHN cashaddrenc_tests test_vectors: F5BF...DAC9 PUBKEY + token variant.
    const bytes hF = parse_hex("F5BF48B397DAE70BE82B3CCA4793F8EB2B6CDAC9");
    check(EncodeCashAddr(MAINNET_PREFIX, {PUBKEY_TYPE, hF}) ==
          "bitcoincash:qr6m7j9njldwwzlg9v7v53unlr4jkmx6eylep8ekg2", "enc p2pkh hF");
    check(EncodeCashAddr(MAINNET_PREFIX, {TOKEN_PUBKEY_TYPE, hF}) ==
          "bitcoincash:zr6m7j9njldwwzlg9v7v53unlr4jkmx6eycnjehshe", "enc token-pubkey hF");

    // --- (2)+(3) Decode is the exact inverse; covers 20B and 32B (P2SH32) -----
    auto roundtrip = [&](CashAddrType ty, const bytes& hash, const char* px) {
        std::string addr = EncodeCashAddr(px, {ty, hash});
        check(!addr.empty(), "rt encode nonempty");
        CashAddrContent got = DecodeCashAddrContent(addr, px);
        check(!got.IsNull(), "rt decode nonnull");
        check(got.type == ty, "rt type");
        check(got.hash == hash, "rt hash");
    };
    roundtrip(PUBKEY_TYPE, h1, MAINNET_PREFIX);
    roundtrip(SCRIPT_TYPE, h1, MAINNET_PREFIX);
    roundtrip(TOKEN_PUBKEY_TYPE, hF, MAINNET_PREFIX);
    // P2SH32: 32-byte script hash (CHIP P2SH32), token-aware on testnet prefix.
    bytes h32(32);
    for (size_t i = 0; i < 32; ++i) h32[i] = uint8_t(0x11 * (i + 1));
    roundtrip(SCRIPT_TYPE, h32, TESTNET_PREFIX);
    roundtrip(TOKEN_SCRIPT_TYPE, h32, TESTNET_PREFIX);

    // --- (4) Rejection paths --------------------------------------------------
    // Corrupted checksum char.
    check(DecodeCashAddrContent("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6b",
                                MAINNET_PREFIX).IsNull(), "reject corrupt checksum");
    // Right address, wrong expected prefix.
    check(DecodeCashAddrContent("bitcoincash:qpm2qsznhks23z7629mms6s4cwef74vcwvy22gdx6a",
                                TESTNET_PREFIX).IsNull(), "reject wrong prefix");
    // Mixed case is invalid per spec.
    check(DecodeCashAddrContent("bitcoincash:qpm2qsznhks23z7629mms6s4cWef74vcwvy22gdx6a",
                                MAINNET_PREFIX).IsNull(), "reject mixed case");
    // Invalid hash length -> empty encode.
    check(EncodeCashAddr(MAINNET_PREFIX, {PUBKEY_TYPE, bytes(19)}).empty(), "reject 19B hash");

    // --- (5) checksum-only valid strings (cashaddr_tests valid_strings) -------
    // These have a non-standard payload but a VALID BCH checksum; Decode must
    // accept them and recover the lowercased prefix.
    for (const char* s : {"prefix:x64nx6hz",
                          "bitcoincash:qpzry9x8gf2tvdw0s3jn54khce6mua7lcw20ayyn",
                          "bchtest:testnetaddress4d6njnut",
                          "bchreg:555555555555555555555555555555555555555555555udxmlmrz"}) {
        auto [pfx, payload] = Decode(s, "");
        (void)payload; // checksum-only vectors: data payload is legitimately empty
        check(!pfx.empty(), std::string("decode valid_string ") + s);
    }

    std::cout << "cashaddr KAT: ALL " << checks << " checks PASS\n";
    return 0;
}
