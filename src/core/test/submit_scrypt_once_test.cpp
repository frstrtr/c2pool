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
//   5. A gate pow whose header differs from the submission's in extranonce2,
//      ntime, prevhash, a rolled version bit or a job version 0 (the header
//      takes the default version) is not used: one more scrypt, same blocks.
//   6. Aux (DOGE) blocks found through mining_submit, with a DOGE chain whose
//      target is easy (0x207fffff): the aux blocks submitted, their parent
//      header and parent hash equal an independent scrypt oracle; a parent
//      hash above the aux target submits nothing (a zero parent hash would).
//      With the gate pow, without it, and with the gate pow of other bytes.
//      For the same bytes the snapshot's digest is the one used, and the
//      stratum session fills the snapshot's header and digest from its one
//      gate call (source pin of stratum_server.cpp).

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
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <memory>
#include <optional>
#include <regex>
#include <sstream>
#include <string>
#include <utility>
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

// Header fields the gate hashes other than the job's and the submission's
// (the defaults: the submission's kEn2 / kNtime, the job's prevhash and
// version), for the cases where the gate hashed other bytes.
struct GateIn {
    std::string en2 = kEn2;
    std::string ntime = kNtime;
    std::string prev;                  // empty: the job's
    std::optional<uint32_t> version;   // none: the job's
};

// The vardiff gate as the stratum session runs it.
double gate(MiningInterface& mi, const MiningInterface::JobSnapshot& j, const std::string& nonce,
            core::stratum::SharePow& pow, const GateIn& in = {})
{
    return mi.compute_share_difficulty_pow(j.coinb1, j.coinb2, kEn1, in.en2, in.ntime, nonce,
                                           in.version ? *in.version : j.version,
                                           in.prev.empty() ? j.gbt_prevhash : in.prev,
                                           j.nbits, j.merkle_branches, pow);
}

// Independent oracle: the 80-byte header of a submission on job `j` (field by
// field, as a miner builds it) and its scrypt digest.
std::vector<unsigned char> oracle_header(const MiningInterface::JobSnapshot& j, const std::string& nonce)
{
    std::vector<unsigned char> h;
    const uint32_t version = j.version ? j.version : 536870912u;   // mining_submit's default
    for (int i = 0; i < 4; ++i) h.push_back(static_cast<unsigned char>(version >> (8 * i)));
    uint256 prev;
    prev.SetHex(j.gbt_prevhash);
    h.insert(h.end(), prev.data(), prev.data() + 32);
    const uint256 root = MiningInterface::reconstruct_merkle_root(j.coinb1 + kEn1 + kEn2 + j.coinb2,
                                                                  j.merkle_branches);
    h.insert(h.end(), root.data(), root.data() + 32);
    for (const std::string* f : {&kNtime, &j.nbits, &nonce}) {
        auto b = ParseHex(*f);
        h.insert(h.end(), b.rbegin(), b.rend());
    }
    return h;
}

std::array<unsigned char, 32> oracle_scrypt(const std::vector<unsigned char>& header)
{
    std::array<unsigned char, 32> d{};
    scrypt_1024_1_1_256(reinterpret_cast<const char*>(header.data()), reinterpret_cast<char*>(d.data()));
    return d;
}

uint256 as_uint256(const std::array<unsigned char, 32>& d)
{
    uint256 h;
    std::memcpy(h.data(), d.data(), 32);
    return h;
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

// The count is exactly 1 because this rig has no live template: mining_submit's
// job-less statistics difficulty (calculate_share_difficulty(job_id, ...),
// over the live template's header, not the submission's) returns before
// hashing. With a live template it adds one scrypt of another header (see
// AuxBlocks... below, which counts it separately).
TEST(SubmitScryptOnce, OneScryptPerSubmitWithTheGatePowNoLiveTemplate)
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

// ---------------------------------------------------------------------------
// 5. The gate hashed other bytes than the submission's header: each field.
// ---------------------------------------------------------------------------
TEST(SubmitScryptOnce, GatePowOfAnyOtherHeaderFieldIsHashedAgain)
{
    struct Case {
        const char* name;
        GateIn in;
        uint32_t job_version;
    };
    std::vector<Case> cases;
    {
        Case c{"extranonce2", {}, kVersion};
        c.in.en2 = "00000002";
        cases.push_back(c);
    }
    {
        Case c{"ntime", {}, kVersion};
        c.in.ntime = "5f5e1001";
        cases.push_back(c);
    }
    {
        Case c{"prevhash", {}, kVersion};
        c.in.prev = std::string(62, '0') + "ac";
        cases.push_back(c);
    }
    {
        Case c{"rolled version bit", {}, kVersion};
        c.in.version = kVersion ^ 0x00002000u;
        cases.push_back(c);
    }
    // Job version 0: the gate hashes version 0 (the session's effective
    // version is the job's), the header mining_submit builds the default.
    cases.push_back(Case{"job version 0", {}, 0u});

    for (const auto& c : cases) {
        SCOPED_TRACE(c.name);
        Rig base, got;
        int found = 0;
        for (uint32_t n = 0; n < 12; ++n) {
            const std::string nonce = nonce_hex(n);
            auto jb = make_job();
            jb.version = c.job_version;
            base.submit(jb, nonce);

            auto jg = make_job();
            jg.version = c.job_version;
            gate(got.mi, jg, nonce, jg.gate_pow, c.in);
            ASSERT_TRUE(jg.gate_pow.valid);
            const auto real = oracle_header(jg, nonce);
            ASSERT_FALSE(std::equal(real.begin(), real.end(), jg.gate_pow.header.begin()))
                << "the case did not change the header";
            const uint64_t c0 = MiningInterface::header_scrypt_count();
            got.submit(jg, nonce);
            EXPECT_EQ(MiningInterface::header_scrypt_count() - c0, 1u) << "nonce " << nonce;
            found += as_uint256(oracle_scrypt(real)) <= chain::bits_to_target(0x207fffffu) ? 1 : 0;
        }
        EXPECT_GT(found, 0);
        EXPECT_EQ(got.node.submit_calls, found);
        EXPECT_EQ(got.node.submitted, base.node.submitted);
    }
}

// ---------------------------------------------------------------------------
// 6. Aux (DOGE) blocks through mining_submit, against a scrypt oracle.
// ---------------------------------------------------------------------------
namespace {

constexpr uint32_t kAuxBits = 0x207fffffu;   // easy aux target: about one parent hash in two

struct GbtCoinNode : public core::coin::ICoinNode {
    nlohmann::json work_data;
    std::vector<std::string> submitted;
    core::coin::WorkView get_work_view() override
    {
        core::coin::WorkView v;
        v.m_data = work_data;
        return v;
    }
    bool submit_block_hex(const std::string& hex, bool) override
    {
        submitted.push_back(hex);
        return true;
    }
    bool is_embedded() const override { return false; }
    bool has_rpc() const override { return true; }
};

struct AuxDoge : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip = std::string(62, '0') + "c1";
    std::vector<std::string> submitted;   // every aux block handed to the daemon
    AuxDoge()
    {
        cfg.symbol = "DOGE";
        cfg.chain_id = 98;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = 98;
        w.height = 5'000'001;
        w.coinbase_value = 1000000000000ULL;
        w.block_hash.SetHex(tip);
        w.target = chain::bits_to_target(kAuxBits);
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", 5'000'001}, {"bits", "207fffff"},
            {"curtime", 1793210000}, {"version", 0x620004}, {"coinbasevalue", 1000000000000LL},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string& hex) override
    {
        submitted.push_back(hex);
        return true;
    }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

// A MiningInterface with a live LTC template and a DOGE chain committed in
// its stratum coinbases (the merged-mining share side's rig).
struct AuxRig {
    boost::asio::io_context ioc;
    c2pool::merged::MergedMiningManager mm{ioc};
    AuxDoge* doge{nullptr};
    GbtCoinNode ltc;
    MiningInterface mi{/*testnet=*/true};

    AuxRig()
    {
        auto backend = std::make_unique<AuxDoge>();
        doge = backend.get();
        mm.add_chain(doge->cfg, std::move(backend));
        mm.set_payout_provider([](uint32_t, uint64_t value) {
            std::vector<unsigned char> s{0x76, 0xa9, 0x14};
            s.insert(s.end(), 20, 0x5c);
            s.push_back(0x88);
            s.push_back(0xac);
            return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{{s, value}};
        });
        ltc.work_data = {
            {"previousblockhash", kPrev}, {"version", kVersion},
            {"height", 100}, {"bits", kBits}, {"curtime", 1600000000},
            {"coinbasevalue", 5000000000LL}, {"transactions", nlohmann::json::array()},
            {"rules", nlohmann::json::array({"csv", "!segwit", "taproot"})},
        };
        mi.set_coin_node(&ltc);
        mi.set_merged_mining_manager(&mm);
        mi.set_ref_hash_fn([](const uint256&, const std::vector<unsigned char>&,
                              const std::vector<unsigned char>&, const core::stratum::PayoutKey&,
                              uint64_t, uint32_t, uint32_t,
                              bool, const std::string&, const uint256&,
                              const std::vector<std::pair<uint32_t, std::vector<unsigned char>>>&,
                              const std::vector<uint256>&,
                              const std::optional<uint16_t>&) {
            MiningInterface::RefHashResult r;
            r.ref_hash.SetHex(std::string(64, '5'));
            r.bits = 0x207fffff;
            return r;
        });
        mm.refresh_aux_work();
        mi.refresh_work();
    }

    // A stratum job whose coinbase commits to the DOGE block.
    MiningInterface::JobSnapshot job()
    {
        const std::vector<unsigned char> payout{0x76, 0xa9, 0x14, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10,
                                                11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0x88, 0xac};
        auto cbr = mi.build_connection_coinbase(uint256(), kEn1, payout, {});
        EXPECT_FALSE(cbr.coinb1.empty());
        EXPECT_NE((cbr.coinb1 + cbr.coinb2).find("fabe6d6d"), std::string::npos)
            << "the coinbase does not commit to the DOGE block";
        MiningInterface::JobSnapshot j;
        j.coinb1 = cbr.coinb1;
        j.coinb2 = cbr.coinb2;
        j.gbt_prevhash = kPrev;
        j.nbits = kBits;
        j.block_nbits = kBits;
        j.version = kVersion;
        j.merkle_branches = cbr.snapshot.merkle_branches;
        j.tx_data = cbr.snapshot.tx_data ? cbr.snapshot.tx_data
                                         : std::make_shared<std::vector<std::string>>();
        j.segwit_active = cbr.snapshot.segwit_active;
        j.mweb = cbr.snapshot.mweb;
        j.mweb_active = cbr.snapshot.mweb_active;
        j.subsidy = cbr.snapshot.subsidy;
        j.witness_commitment_hex = cbr.snapshot.witness_commitment_hex;
        j.witness_root = cbr.snapshot.witness_root;
        return j;
    }

    void submit(const MiningInterface::JobSnapshot& j, const std::string& nonce)
    {
        mi.mining_submit("aux-oracle-miner", "j1", kEn1, kEn2, kNtime, nonce, "1", {}, &j);
    }
};

// The AuxPoW of an aux block as build_auxpow_proof writes it, after the aux
// header: parent coinbase | parent hash (32, LE) | coinbase branch + index |
// chain branch + index | parent header (80). Returns {parent hash, parent
// header} as hex, empty on a layout it does not know.
std::pair<std::string, std::string> parse_auxpow(const std::string& block_hex,
                                                  const std::string& parent_coinbase_hex)
{
    size_t at = 160;
    if (block_hex.compare(at, parent_coinbase_hex.size(), parent_coinbase_hex) != 0)
        return {};
    at += parent_coinbase_hex.size();
    const std::string parent_hash = block_hex.substr(at, 64);
    at += 64;
    for (int branch = 0; branch < 2; ++branch) {
        const unsigned long count = std::stoul(block_hex.substr(at, 2), nullptr, 16);
        if (count >= 0xfd)
            return {};
        at += 2 + 64 * count + 8;
    }
    return {parent_hash, block_hex.substr(at, 160)};
}

struct AuxExpect {
    std::string parent_hash_hex;
    std::string parent_header_hex;
};

// Per nonce: what the oracle says the merged check must submit.
std::vector<std::optional<AuxExpect>> aux_oracle(const MiningInterface::JobSnapshot& j, uint32_t nonces)
{
    std::vector<std::optional<AuxExpect>> v;
    for (uint32_t n = 0; n < nonces; ++n) {
        const auto h = oracle_header(j, nonce_hex(n));
        const auto d = oracle_scrypt(h);
        if (as_uint256(d) <= chain::bits_to_target(kAuxBits))
            v.push_back(AuxExpect{HexStr(std::span<const unsigned char>(d.data(), 32)),
                                  HexStr(std::span<const unsigned char>(h.data(), h.size()))});
        else
            v.push_back(std::nullopt);
    }
    return v;
}

} // namespace

TEST(SubmitScryptOnce, AuxBlocksThroughMiningSubmitMatchAScryptOracle)
{
    constexpr uint32_t kNonces = 24;
    enum Mode { with_gate, without_gate, gate_of_other_bytes };
    std::vector<std::string> aux_blocks[3];
    std::vector<std::string> parent_blocks[3];
    std::string coinbases[3];
    for (int mode = with_gate; mode <= gate_of_other_bytes; ++mode) {
        SCOPED_TRACE(mode == with_gate ? "with the gate pow"
                     : mode == without_gate ? "without a gate pow" : "gate pow of other bytes");
        AuxRig r;
        const auto job = r.job();
        const auto oracle = aux_oracle(job, kNonces);
        const std::string parent_cb = job.coinb1 + kEn1 + kEn2 + job.coinb2;
        coinbases[mode] = parent_cb;
        int hits = 0, misses = 0;
        for (uint32_t n = 0; n < kNonces; ++n) {
            const std::string nonce = nonce_hex(n);
            auto j = job;
            // The live template's statistics hash (another header), counted apart.
            uint64_t c = MiningInterface::header_scrypt_count();
            r.mi.calculate_share_difficulty("j1", kEn1, kEn2, kNtime, nonce);
            const uint64_t stats = MiningInterface::header_scrypt_count() - c;

            const size_t before = r.doge->submitted.size();
            c = MiningInterface::header_scrypt_count();
            if (mode == with_gate) {
                gate(r.mi, j, nonce, j.gate_pow);
                // The gate's digest is the oracle's for the submission's header.
                const auto h = oracle_header(j, nonce);
                ASSERT_TRUE(std::equal(h.begin(), h.end(), j.gate_pow.header.begin()));
                ASSERT_EQ(j.gate_pow.digest, oracle_scrypt(h));
            } else if (mode == gate_of_other_bytes) {
                gate(r.mi, j, nonce_hex(n + 1000), j.gate_pow);
            }
            r.submit(j, nonce);
            const uint64_t hashed = MiningInterface::header_scrypt_count() - c;
            // with: gate 1 + stats; without: one in mining_submit + stats;
            // other bytes: gate 1 + one in mining_submit + stats.
            EXPECT_EQ(hashed, (mode == gate_of_other_bytes ? 2u : 1u) + stats) << "nonce " << nonce;

            const size_t made = r.doge->submitted.size() - before;
            if (oracle[n]) {
                ++hits;
                ASSERT_EQ(made, 1u) << "nonce " << nonce << ": the parent hash meets the aux target";
                const auto [hash_hex, header_hex] = parse_auxpow(r.doge->submitted.back(), parent_cb);
                EXPECT_EQ(hash_hex, oracle[n]->parent_hash_hex) << "nonce " << nonce;
                EXPECT_EQ(header_hex, oracle[n]->parent_header_hex) << "nonce " << nonce;
                aux_blocks[mode].push_back(r.doge->submitted.back());
            } else {
                ++misses;
                EXPECT_EQ(made, 0u) << "nonce " << nonce
                                    << ": a parent hash above the aux target submitted an aux block";
            }
        }
        EXPECT_GT(hits, 0);
        EXPECT_GT(misses, 0);
        parent_blocks[mode] = r.ltc.submitted;
    }
    // The three rigs build the same job: then the aux blocks and the parent
    // (LTC) blocks are the same too.
    ASSERT_EQ(coinbases[with_gate], coinbases[without_gate]);
    ASSERT_EQ(coinbases[with_gate], coinbases[gate_of_other_bytes]);
    EXPECT_EQ(aux_blocks[with_gate], aux_blocks[without_gate]);
    EXPECT_EQ(aux_blocks[with_gate], aux_blocks[gate_of_other_bytes]);
    EXPECT_FALSE(parent_blocks[with_gate].empty());
    EXPECT_EQ(parent_blocks[with_gate], parent_blocks[without_gate]);
    EXPECT_EQ(parent_blocks[with_gate], parent_blocks[gate_of_other_bytes]);
}

// For the same 80 bytes the snapshot's digest is the one the merged and the
// block checks use (no second hash): a digest that is not the header's
// changes what they decide. The stratum session is what makes the digest the
// header's: it fills both from its one gate call (pinned below).
TEST(SubmitScryptOnce, SnapshotDigestIsUsedForItsOwnBytes)
{
    AuxRig r;
    const auto job = r.job();
    const auto oracle = aux_oracle(job, 64);
    uint32_t n = 0;
    while (n < oracle.size() && !oracle[n]) ++n;
    ASSERT_LT(n, oracle.size());
    const std::string nonce = nonce_hex(n);

    auto bad = job;
    gate(r.mi, bad, nonce, bad.gate_pow);
    bad.gate_pow.digest.fill(0xff);   // the header's bytes, a digest above every target
    const size_t ltc_before = r.ltc.submitted.size();
    r.submit(bad, nonce);
    EXPECT_TRUE(r.doge->submitted.empty()) << "the merged check hashed the header itself";
    EXPECT_EQ(r.ltc.submitted.size(), ltc_before) << "the block check hashed the header itself";

    // The same submission with the gate's own digest: found on both chains.
    auto ok = job;
    gate(r.mi, ok, nonce, ok.gate_pow);
    r.submit(ok, nonce);
    EXPECT_EQ(r.doge->submitted.size(), 1u);
    EXPECT_EQ(r.ltc.submitted.size(), ltc_before + 1);
}

TEST(SubmitScryptOnce, StratumSessionFillsTheSnapshotDigestFromItsOneGateCall)
{
    std::ifstream f(std::string(C2POOL_SRC_ROOT) + "/core/stratum_server.cpp");
    ASSERT_TRUE(f.is_open());
    std::stringstream ss;
    ss << f.rdbuf();
    const std::string src = ss.str();

    const std::string decl = "core::stratum::SharePow gate_pow;";
    const std::regex call(R"(compute_share_difficulty_pow\(([^;]*?),\s*gate_pow\);)");
    const std::string assign = "snapshot.gate_pow = gate_pow;";
    auto count = [&](const std::string& needle) {
        size_t c = 0;
        for (size_t at = src.find(needle); at != std::string::npos; at = src.find(needle, at + 1)) ++c;
        return c;
    };
    ASSERT_EQ(count(decl), 1u);
    ASSERT_EQ(count(assign), 1u);
    std::smatch m;
    ASSERT_TRUE(std::regex_search(src, m, call)) << "the gate call does not fill gate_pow";
    const size_t d = src.find(decl), g = static_cast<size_t>(m.position(0)), a = src.find(assign);
    EXPECT_LT(d, g);
    EXPECT_LT(g, a);
    // Between the declaration and the snapshot, gate_pow is only the gate's out
    // parameter: no other write, no second gate call.
    const std::string span = src.substr(d + decl.size(), a - d - decl.size());
    EXPECT_EQ(std::regex_search(span, std::regex(R"(gate_pow\s*(=[^=]|\.))")), false);
    size_t calls = 0;
    for (size_t at = span.find("compute_share_difficulty"); at != std::string::npos;
         at = span.find("compute_share_difficulty", at + 1))
        ++calls;
    EXPECT_EQ(calls, 1u);
}
