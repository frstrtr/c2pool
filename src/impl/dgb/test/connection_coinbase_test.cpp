// DGB Phase B — per-connection Stratum coinbase assembler + split KAT.
//
// Locks dgb::coin::build_connection_coinbase_parts() (coin/connection_coinbase.hpp)
// against the SAME ground-truth oracle vector used by the gentx assembler KAT
// (gentx_coinbase_test.cpp NOSEG_BYTES — derived from frstrtr/p2pool-dgb-scrypt
// util/pack.py + donation 4104ffd0...ac). A PASS proves:
//
//   1. the per-connection coinbase serializes byte-identical to the oracle wire
//      (the assembler path used == the verification SSOT), AND
//   2. the Stratum split invariant holds:
//        coinb1 || extranonce1(4) || extranonce2(4) || coinb2 == full gentx bytes
//      with the 8-byte extranonce slot landing exactly on the OP_RETURN
//      last_txout_nonce (the submit path reconstructs the header off this).
//
// Pure / no tracker: the (ref_hash, last_txout_nonce) are fixed inputs, so the
// vector is the oracle serializer's output — not self-generated.

#include <gtest/gtest.h>
#include <impl/dgb/coin/connection_coinbase.hpp>

#include <optional>
#include <string>
#include <utility>
#include <vector>

namespace {

std::vector<unsigned char> unhex(const std::string& h) {
    std::vector<unsigned char> v; v.reserve(h.size() / 2);
    auto nyb = [](char c) -> int { return (c <= '9') ? c - '0' : (c | 0x20) - 'a' + 10; };
    for (size_t i = 0; i + 1 < h.size(); i += 2)
        v.push_back(static_cast<unsigned char>((nyb(h[i]) << 4) | nyb(h[i + 1])));
    return v;
}
std::string tohex(const std::vector<unsigned char>& v) {
    static const char* H = "0123456789abcdef";
    std::string s; s.reserve(v.size() * 2);
    for (unsigned char b : v) { s.push_back(H[b >> 4]); s.push_back(H[b & 0xf]); }
    return s;
}

// --- inputs shared verbatim with gentx_coinbase_test.cpp NOSEG vector --------
const std::vector<unsigned char> CB  = unhex("03a1b2c3041122334455667788");
const std::vector<unsigned char> P1  = unhex(std::string("76a914") + std::string(40, '1') + "88ac");
const std::vector<unsigned char> P2  = unhex(std::string("76a914") + std::string(40, '2') + "88ac");
const std::vector<unsigned char> DON = unhex("4104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac");

const std::vector<std::pair<std::vector<unsigned char>, uint64_t>> PAYOUTS = {
    {P1, 5000000000ull},
    {P2, 2500000000ull},
};

// ref_hash = 0xab * 32 ; last_txout_nonce LE bytes = 08 07 06 05 04 03 02 01.
const uint64_t NONCE = 0x0102030405060708ull;

// Oracle ground truth (identical to gentx_coinbase_test.cpp NOSEG_BYTES).
const std::string NOSEG_BYTES =
    "01000000010000000000000000000000000000000000000000000000000000000000000000ffffffff0d03a1b2c3041122334455667788ffffffff0400f2052a010000001976a914111111111111111111111111111111111111111188ac00f90295000000001976a914222222222222222222222222222222222222222288ac0100000000000000434104ffd03de44a6e11b9917f3a29f9443283d9871c9d743ef30d5eddcd37094b64d1b3d8090496b53256786bf5c82932ec23c3b74d9f05a6f95a8b5529352656664bac00000000000000002a6a28abababababababababababababababababababababababababababababababab080706050403020100000000";

dgb::coin::ConnCoinbaseParts build() {
    dgb::coin::ConnCoinbaseInputs in;
    in.coinbase_script = CB;
    in.segwit_commitment_script = std::nullopt;
    in.payout_outputs = PAYOUTS;
    in.donation_amount = 1;                 // matches NOSEG donation value (1 sat)
    in.donation_script = DON;
    in.ref_hash = uint256(std::vector<unsigned char>(32, 0xab));
    in.last_txout_nonce = NONCE;
    return dgb::coin::build_connection_coinbase_parts(in);
}

// (1) full assembled bytes == oracle wire.
TEST(ConnCoinbase, FullBytesMatchOracle) {
    auto parts = build();
    EXPECT_EQ(tohex(parts.gentx.bytes), NOSEG_BYTES);
}

// (2) the Stratum split reassembles to the exact oracle bytes with the
//     8-byte extranonce slot filling the OP_RETURN nonce.
TEST(ConnCoinbase, SplitReassemblesToOracle) {
    auto parts = build();
    const std::string extranonce = "0807060504030201"; // en1(4)||en2(4), LE nonce
    EXPECT_EQ(parts.coinb1 + extranonce + parts.coinb2, NOSEG_BYTES);
}

// (3) coinb1 is the prefix up to (excl.) the nonce slot; coinb2 is the locktime.
TEST(ConnCoinbase, Coinb1PrefixCoinb2Locktime) {
    auto parts = build();
    ASSERT_GE(NOSEG_BYTES.size(), size_t{24});
    // coinb1 == oracle minus the last 12 bytes (nonce 8 + locktime 4 = 24 hex)
    EXPECT_EQ(parts.coinb1, NOSEG_BYTES.substr(0, NOSEG_BYTES.size() - 24));
    // coinb2 == final 4 bytes (locktime), all-zero
    EXPECT_EQ(parts.coinb2, "00000000");
}

// (4) the OP_RETURN ref script is the canonical 6a28 || ref_hash || nonce(LE).
TEST(ConnCoinbase, RefOpReturnLayout) {
    auto op = dgb::coin::build_ref_op_return(
        uint256(std::vector<unsigned char>(32, 0xab)), NONCE);
    std::string ref32; for (int i = 0; i < 32; ++i) ref32 += "ab";
    EXPECT_EQ(tohex(op), std::string("6a28") + ref32 + "0807060504030201");
}

} // namespace
