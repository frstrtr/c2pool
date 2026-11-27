// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The V34/V35 share address, exactly as the python DGB network reads it
// (rides dgb_work_source_test). Review 713dc77a0 #7.
//
// Goldens are NOT computed by the code under test: the bech32 cases were
// produced by the oracle's own util/segwit_addr.py (frstrtr/p2pool-dgb-scrypt
// 22761e7, loaded by path) with data.py's script rule (padding_bugfix, set for
// share type >= 35 by load_share: '{:040x}'); the base58 cases by a standalone
// base58check of version || hash160. Empty script = python raises (the share
// is invalid there).
// ---------------------------------------------------------------------------

#include <impl/dgb/params.hpp>
#include <impl/dgb/share.hpp>
#include <impl/dgb/share_check.hpp>
#include <impl/dgb/v35_address.hpp>

#include <btclibs/util/strencodings.h>
#include <core/coin_params.hpp>

#include <gtest/gtest.h>

#include <stdexcept>
#include <string>
#include <vector>

namespace {

struct Vec {
    const char* name;
    const char* addr;
    const char* script;   // hex; "" = invalid in python
};

const Vec kVecs[] = {
    // base58check: DGB versions 30 / 63 only; any other version is an error.
    {"p2pkh", "DB69qk9X8T9A3vZ8odhDxAFedZB9qoKaLG", "76a9144142434445464748494a4b4c4d4e4f505152535488ac"},
    {"p2sh", "STF4LKz2ZQS53E9zcUgjxJEcQCgHJL1Knz", "a9144142434445464748494a4b4c4d4e4f505152535487"},
    {"foreign_version", "16x4JVCsq3EsWvNY53hfQQ63kRSrXWSjnF", ""},
    {"bad_checksum", "DB69qk9X8T9A3vZ8odhDxAFedZB9qoKaL2", ""},
    {"long_payload", "vjXk29SbytNzwuNqSpxYATqf6M1ombMr8Zs", ""},
    // BIP173 bech32 (oracle segwit_addr.py), '{:040x}' program.
    {"p2wpkh", "dgb1qyy3zxfp9ycnjs2f29vkz6t30xqcnyve5n5rjxd", "00142122232425262728292a2b2c2d2e2f3031323334"},
    {"p2wpkh_upper", "DGB1QYY3ZXFP9YCNJS2F29VKZ6T30XQCNYVE5N5RJXD", "00142122232425262728292a2b2c2d2e2f3031323334"},
    {"p2wpkh_lead00", "dgb1qqqq87qgzqvzq2ps8pqys5zcvp58q7yq3lt9yd2", "001400007f0102030405060708090a0b0c0d0e0f1011"},
    {"p2wpkh_lead0n", "dgb1qq5qsyqcyq5rqwzqfpg9scrgwpugpzysnyssrw4", "0014050102030405060708090a0b0c0d0e0f10111213"},
    {"p2wsh", "dgb1qxqcnyve5x5mrwwpe8ganc0f78aqyzsjrg3z5v36gf99yknzdfe8ssnqq30",
     "0020303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"},
    {"p2wsh_lead0n", "dgb1qpgqsyqcyq5rqwzqfpg9scrgwpugpzysnzs23v9ccrydpk8qarc0spufvhd", ""},
    {"p2wsh_lead00", "dgb1qqpaqzqsrqszsvpcgpy9qkrqdpc83qygjzv2p29shrqv35xcur50q92ynyg",
     "001f7a0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e"},
    {"v1_bech32_bip173", "dgb1pxqcnyve5x5mrwwpe8ganc0f78aqyzsjrg3z5v36gf99yknzdfe8s0cs9v3",
     "0020303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f"},
    {"v1_bech32m", "dgb1pxqcnyve5x5mrwwpe8ganc0f78aqyzsjrg3z5v36gf99yknzdfe8s6yqffn", ""},
    {"mixed_case", "dgb1qyY3ZXFP9YCNJS2F29VKZ6T30XQCNYVE5N5RJXD", ""},
    {"wrong_hrp", "ltc1qyy3zxfp9ycnjs2f29vkz6t30xqcnyve5qnawxn", ""},
    {"garbage", "not-an-address", ""},
    {"empty", "", ""},
};

std::string hex(const std::vector<unsigned char>& v)
{
    return HexStr(Span<const unsigned char>(v.data(), v.size()));
}

} // namespace

TEST(DgbV35Address, DecodesExactlyAsThePythonNetwork)
{
    const auto net = dgb::v35_address_net(false);
    for (const auto& v : kVecs) {
        SCOPED_TRACE(v.name);
        const auto s = dgb::v35_address_to_script(v.addr, net);
        if (std::string(v.script).empty())
            EXPECT_FALSE(s.has_value()) << v.addr << " -> " << (s ? hex(*s) : "");
        else {
            ASSERT_TRUE(s.has_value()) << v.addr;
            EXPECT_EQ(hex(*s), v.script);
        }
    }
}

// The sort key: the canonical address string of a D/S/dgb1q script is the
// string the python network sorts outputs by (base58, lowercase bech32).
TEST(DgbV35Address, CanonicalAddressOfAScript)
{
    const auto net = dgb::v35_address_net(false);
    for (const char* name : {"p2pkh", "p2sh", "p2wpkh", "p2wpkh_lead00", "p2wsh"}) {
        SCOPED_TRACE(name);
        for (const auto& v : kVecs) {
            if (std::string(v.name) != name)
                continue;
            EXPECT_EQ(dgb::v35_script_to_address(ParseHex(v.script), net), v.addr);
        }
    }
    EXPECT_EQ(dgb::v35_script_to_address({0x6a, 0x01, 0x00}, net), "");
}

// A V35 share whose address python cannot pay is rejected here too (before:
// an undecodable address fell back to its raw bytes and was accepted).
TEST(DgbV35Address, ShareWithAnUnpayableAddressIsRejected)
{
    const auto params = dgb::make_coin_params(/*testnet=*/false);
    for (const auto& v : kVecs) {
        if (!std::string(v.script).empty())
            continue;
        SCOPED_TRACE(v.name);
        dgb::PaddingBugfixShare share;
        static_assert(dgb::PaddingBugfixShare::version == 35);
        share.m_coinbase.m_data = {0x03, 0x01, 0x02, 0x03};
        const std::string a = v.addr;
        share.m_address.m_data.assign(a.begin(), a.end());
        try {
            dgb::share_init_verify(share, params, /*check_pow=*/false);
            ADD_FAILURE() << "accepted a V35 share paying " << v.addr;
        } catch (const std::invalid_argument& e) {
            EXPECT_NE(std::string(e.what()).find("address"), std::string::npos) << e.what();
        }
    }
}
