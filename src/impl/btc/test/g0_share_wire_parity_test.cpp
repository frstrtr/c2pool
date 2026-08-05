// SPDX-License-Identifier: AGPL-3.0-or-later
//
// G0 — BTC share-message WIRE byte-parity against the canonical golden vector.
//
// share_test.cpp:37 states that "full v35 byte-parity is closed separately by
// the canonical golden-hex vector (G0)" — but the only test consuming that hex
// (LTC_share_test.Init) unpacks and prints with ZERO assertions. This KAT makes
// the promise real: unpack the golden RawShare from wire, re-pack it, and assert
// the emitted bytes are byte-identical to the input. If the sharechain framing
// (VarInt type + contents) ever drifts, we go off-network; this pins it.
//
// Golden vector: the canonical v35 BTC share hex carried in share_test.cpp.
#include <gtest/gtest.h>

#include <string>
#include <vector>

#include <core/pack.hpp>
#include <sharechain/share.hpp>

namespace {

// Canonical golden v35 BTC share (leading VarInt type 0x23 == 35), transcribed
// from src/impl/btc/test/share_test.cpp.
constexpr const char* GOLDEN_SHARE_HEX =
    "23fd9601fe00000020654f11363698fc9a54e43f126f294bd1a33b650148e8b6bb532fc0"
    "8500cb6966e8103066140b041db0022a77e3af9c1de80a16583bed2a6179b63ed410b890"
    "b113cfd0fcd68bafa4096779b90503fd823100731a92d3226d6839617a4b447852353747"
    "66374a575a756e6e43324a7a37325351747746544b68dec14025000000000000fe2302a4"
    "1fb37f52f6747afbbeae61462feaa40b8b3655f8fb7af60843111101ec5f958e93b9a76bb"
    "46536bf807b1caef9635f432d982bd907eb5050130b6ec00aeabc2bb9ca34c5f1ba0bd332"
    "fc3d217d9853754fe42797e32cf9ddddcab6f66ab8056f1b64efa2157281c406fc6a5d9de"
    "6db5e2adf63c86646a4edc91c51f86d74c707c0221e8828011ef310306675b32100739905"
    "93df0d00000000000000000000000100000000000000c357550d5a390b342f665a3d853c0"
    "39a626b803bb37976c20ba0b5ee5a56fceedc0220e67c088987582af73218c99820276bbf"
    "0004c5c18f7dd691f9c4326bfd9930d5567a6d109fec00f4eca887c42e80ddaa57df9bda8"
    "db8b277110a50a9a268b6";

static std::string to_hex_lower(const unsigned char* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 0xf]); }
    return s;
}

// G0.1 — the golden wire round-trips byte-identically through RawShare.
TEST(BTC_g0_share_wire, GoldenRawShareRoundTripsByteIdentical) {
    PackStream in;
    in.from_hex(GOLDEN_SHARE_HEX);

    chain::RawShare rshare;
    in >> rshare;

    PackStream out;
    out << rshare;

    auto got = to_hex_lower(
        reinterpret_cast<const unsigned char*>(out.data()), out.size());
    EXPECT_EQ(got, std::string(GOLDEN_SHARE_HEX));
}

// G0.2 — the golden vector is the pinned v35 share type (leading VarInt == 35).
TEST(BTC_g0_share_wire, GoldenTypeIsV35) {
    PackStream in;
    in.from_hex(GOLDEN_SHARE_HEX);
    chain::RawShare rshare;
    in >> rshare;
    EXPECT_EQ(rshare.type, 35u);
}

} // namespace
