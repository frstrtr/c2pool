// SPDX-License-Identifier: AGPL-3.0-or-later
//
// One scrypt of a stratum submission's 80-byte header on the LTC submit path
// (core::MiningInterface).
//
// The stratum session's vardiff gate (IWorkSource::compute_share_difficulty_pow
// -> MiningInterface::calculate_share_difficulty) hashes the header and hands
// header + digest to mining_submit in JobSnapshot::gate_pow. mining_submit
// hashes the header it derives from the job once for the merged-mining check
// and the block check, and not at all when it is byte-equal to the gate's.
// Counted with MiningInterface::header_scrypt_count().
//
//   1. The gate's SharePow is the header build_header_bytes makes and its
//      scrypt digest; its difficulty equals compute_share_difficulty's.
//   2. Gate + mining_submit = one scrypt of the header (merged-mining
//      manager attached, block found); without a gate pow, mining_submit
//      hashes it once (it was twice: merged check + block check).
//   3. A gate pow for other header bytes is not used: mining_submit hashes.
//   4. Same results: over many nonces the block submissions (count and
//      bytes) are the same with the gate pow, without it, and with a wrong one.

#include <gtest/gtest.h>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <core/coin/node_iface.hpp>
#include <core/coin/work_view.hpp>
#include <core/target_utils.hpp>
#include <core/uint256.hpp>
#include <core/web_server.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <btclibs/util/strencodings.h>
#include <crypto/scrypt.h>

#include <algorithm>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace {

using core::MiningInterface;

struct MockCoinNode : public core::coin::ICoinNode {
    int submit_calls = 0;
    std::vector<std::string> submitted;

    core::coin::WorkView get_work_view() override { return {}; }
    bool submit_block_hex(const std::string& block_hex, bool /*ignore_failure*/) override
    {
        ++submit_calls;
        submitted.push_back(block_hex);
        return true;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

const std::string kCoinb1 = "01000000" "01" + std::string(64, '0') + "ffffffff" "08";
const std::string kCoinb2 = "ffffffff" "01" "00f2052a01000000" "00" "00000000";
const std::string kEn1   = "aabbccdd";
const std::string kEn2   = "00000001";
const std::string kNtime = "5f5e1000";
const std::string kBits  = "207fffff";   // regtest block target: about one header in two
const std::string kPrev  = std::string(62, '0') + "ab";
constexpr uint32_t kVersion = 0x20000000u;

std::string nonce_hex(uint32_t n)
{
    char buf[9];
    std::snprintf(buf, sizeof(buf), "%08x", n);
    return buf;
}

MiningInterface::JobSnapshot make_job()
{
    MiningInterface::JobSnapshot j;
    j.coinb1 = kCoinb1;
    j.coinb2 = kCoinb2;
    j.gbt_prevhash = kPrev;
    j.nbits = kBits;
    j.block_nbits = kBits;
    j.version = kVersion;
    j.tx_data = std::make_shared<std::vector<std::string>>();
    j.segwit_active = false;
    return j;
}

// The vardiff gate as the stratum session runs it.
double gate(MiningInterface& mi, const MiningInterface::JobSnapshot& j, const std::string& nonce,
            core::stratum::SharePow& pow)
{
    return mi.compute_share_difficulty_pow(j.coinb1, j.coinb2, kEn1, kEn2, kNtime, nonce,
                                           j.version, j.gbt_prevhash, j.nbits, j.merkle_branches, pow);
}

struct Rig {
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm{ioc};   // no chains: the merged check still hashes
    MockCoinNode node;
    MiningInterface mi{/*testnet=*/true};          // Blockchain::LITECOIN

    explicit Rig(bool merged = true)
    {
        mi.set_coin_node(&node);
        if (merged)
            mi.set_merged_mining_manager(&mm);
    }

    void submit(const MiningInterface::JobSnapshot& j, const std::string& nonce)
    {
        mi.mining_submit("scrypt-once-miner", "j1", kEn1, kEn2, kNtime, nonce, "1", {}, &j);
    }
};

bool meets_block_target(const core::stratum::SharePow& pow)
{
    uint256 h;
    std::memcpy(h.data(), pow.digest.data(), 32);
    return h <= chain::bits_to_target(static_cast<uint32_t>(std::stoul(kBits, nullptr, 16)));
}

// The first nonce from `from` whose header meets the block target.
std::string block_nonce(MiningInterface& mi, const MiningInterface::JobSnapshot& j, uint32_t from = 0)
{
    for (uint32_t n = from; n < from + 1000; ++n) {
        core::stratum::SharePow pow;
        gate(mi, j, nonce_hex(n), pow);
        if (pow.valid && meets_block_target(pow))
            return nonce_hex(n);
    }
    ADD_FAILURE() << "no nonce met the block target";
    return "00000000";
}

} // namespace

TEST(SubmitScryptOnce, GatePowIsTheHeaderAndItsScryptDigest)
{
    Rig r;
    const auto j = make_job();
    const std::string nonce = "0000abcd";

    const uint64_t c0 = MiningInterface::header_scrypt_count();
    core::stratum::SharePow pow;
    const double d = gate(r.mi, j, nonce, pow);
    EXPECT_EQ(MiningInterface::header_scrypt_count() - c0, 1u);
    ASSERT_TRUE(pow.valid);

    const uint256 root = MiningInterface::reconstruct_merkle_root(kCoinb1 + kEn1 + kEn2 + kCoinb2, {});
    const auto header = MiningInterface::build_header_bytes(kVersion, kPrev, root, kNtime, kBits, nonce);
    ASSERT_EQ(header.size(), 80u);
    EXPECT_TRUE(std::equal(header.begin(), header.end(), pow.header.begin()));
    char digest[32];
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), digest);
    EXPECT_EQ(std::memcmp(digest, pow.digest.data(), 32), 0);

    // Same difficulty as the plain gate.
    EXPECT_EQ(d, r.mi.compute_share_difficulty(j.coinb1, j.coinb2, kEn1, kEn2, kNtime, nonce,
                                               j.version, j.gbt_prevhash, j.nbits, j.merkle_branches));
    // digest_for: only these 80 bytes.
    EXPECT_EQ(pow.digest_for(header.data(), header.size()), pow.digest.data());
    auto other = header;
    other[79] ^= 1;
    EXPECT_EQ(pow.digest_for(other.data(), other.size()), nullptr);
    EXPECT_EQ(pow.digest_for(header.data(), 79), nullptr);
    core::stratum::SharePow none;
    EXPECT_EQ(none.digest_for(header.data(), header.size()), nullptr);
}

TEST(SubmitScryptOnce, OneScryptPerSubmitWithTheGatePow)
{
    Rig r;
    auto j = make_job();
    const std::string nonce = block_nonce(r.mi, j);

    // The stratum session: gate, then mining_submit with the gate's pow.
    const uint64_t c0 = MiningInterface::header_scrypt_count();
    gate(r.mi, j, nonce, j.gate_pow);
    r.submit(j, nonce);
    EXPECT_EQ(MiningInterface::header_scrypt_count() - c0, 1u)
        << "the header of one submission was hashed more than once";
    EXPECT_EQ(r.mi.get_aux_checks(), 1u);   // the merged check ran
    EXPECT_EQ(r.node.submit_calls, 1);       // and the block was found and submitted
}

TEST(SubmitScryptOnce, WithoutGatePowMiningSubmitHashesTheHeaderOnce)
{
    Rig r;
    const auto j = make_job();
    const std::string nonce = block_nonce(r.mi, j);

    const uint64_t c0 = MiningInterface::header_scrypt_count();
    r.submit(j, nonce);
    EXPECT_EQ(MiningInterface::header_scrypt_count() - c0, 1u);   // merged check + block check
    EXPECT_EQ(r.mi.get_aux_checks(), 1u);
    EXPECT_EQ(r.node.submit_calls, 1);
}

TEST(SubmitScryptOnce, GatePowOfOtherHeaderBytesIsNotUsed)
{
    Rig r;
    auto j = make_job();
    const std::string nonce = block_nonce(r.mi, j);
    // A gate pow for the next nonce: valid, but not these header bytes.
    gate(r.mi, j, nonce_hex(std::stoul(nonce, nullptr, 16) + 1), j.gate_pow);
    ASSERT_TRUE(j.gate_pow.valid);

    const uint64_t c0 = MiningInterface::header_scrypt_count();
    r.submit(j, nonce);
    EXPECT_EQ(MiningInterface::header_scrypt_count() - c0, 1u);
    EXPECT_EQ(r.node.submit_calls, 1);
}

TEST(SubmitScryptOnce, SameBlocksWithAndWithoutTheGatePow)
{
    // Three rigs fed the same 32 submissions: with the gate's pow, without
    // one, and with the gate pow of a different header.
    Rig with, without, wrong;
    int found = 0;
    for (uint32_t n = 0; n < 32; ++n) {
        const std::string nonce = nonce_hex(n);
        auto jw = make_job();
        gate(with.mi, jw, nonce, jw.gate_pow);
        with.submit(jw, nonce);

        const auto jn = make_job();
        without.submit(jn, nonce);

        auto jx = make_job();
        gate(wrong.mi, jx, nonce_hex(n + 1000), jx.gate_pow);
        wrong.submit(jx, nonce);

        core::stratum::SharePow p;
        gate(with.mi, jn, nonce, p);
        found += meets_block_target(p) ? 1 : 0;
    }
    EXPECT_GT(found, 0);
    EXPECT_EQ(with.node.submit_calls, found);
    EXPECT_EQ(with.node.submitted, without.node.submitted);
    EXPECT_EQ(with.node.submitted, wrong.node.submitted);
}
