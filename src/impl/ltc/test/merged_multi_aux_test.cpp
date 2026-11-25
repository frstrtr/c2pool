// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// Merged mining with two or more aux chains (rides share_test).
//
// With one aux chain the root committed in the parent (LTC) coinbase is the
// chain's block hash. With several it is the root of the chain merkle tree
// over all of them: a find has to recover its chain's committed block and
// the branch from the leaves that root was built from, for the job the share
// was mined on (which may be older than the current work). try_submit took
// the root for a block hash: every chain, DOGE included, ended in "No
// matching snapshot" and the block was never submitted.
//
// The submitted blocks are read back and checked with the AuxPoW check Dogecoin
// Core runs (doge::coin::check_auxpow = CAuxPow::check). The one-chain golden
// pins the bytes of the pre-fix path (commitment, coinbase, submitted block).
// Folded into the allowlisted share_test target (no new executable: #769).
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <map>
#include <memory>
#include <optional>
#include <set>
#include <span>
#include <stdexcept>
#include <string>
#include <vector>

#include <boost/asio/io_context.hpp>
#include <nlohmann/json.hpp>

#include <btclibs/crypto/sha256.h>
#include <btclibs/util/strencodings.h>
#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>
#include <c2pool/merged/merged_mining.hpp>
#include <impl/doge/coin/auxpow.hpp>
#include <impl/doge/coin/auxpow_check.hpp>
#include <impl/nmc/coin/aux_expected_index.hpp>

namespace {

using c2pool::merged::AuxPowTree;
using c2pool::merged::MergedMiningManager;

constexpr const char* EASY_TARGET =
    "7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

/// A daemon-shaped backend (multiaddress mode, the block is built from its
/// template) that records what is submitted.
struct Backend : c2pool::merged::IAuxChainBackend {
    c2pool::merged::AuxChainConfig cfg;
    std::string tip;
    int height;
    uint32_t base_version;
    std::vector<std::string> blocks;
    Backend(std::string symbol, uint32_t chain_id, int start_height)
        : tip(std::string(62, '0') + "0" + std::to_string(chain_id % 10)),
          height(start_height),
          base_version((chain_id << 16) | 4u)
    {
        cfg.symbol = std::move(symbol);
        cfg.chain_id = chain_id;
        cfg.multiaddress = true;
    }
    c2pool::merged::AuxWork get_work_template() override
    {
        c2pool::merged::AuxWork w;
        w.chain_id = cfg.chain_id;
        w.height = height;
        w.coinbase_value = 1'000'000'000'000ULL + static_cast<uint64_t>(height);
        w.block_hash.SetHex(tip);
        w.target.SetHex(EASY_TARGET);
        w.prev_block_hash = tip;
        w.block_template = {
            {"previousblockhash", tip}, {"height", height}, {"bits", "207fffff"},
            {"curtime", 1793210000 + height}, {"version", base_version},
            {"coinbasevalue", 1'000'000'000'000LL + height},
            {"transactions", nlohmann::json::array()},
        };
        return w;
    }
    c2pool::merged::AuxWork create_aux_block(const std::string&) override { return get_work_template(); }
    bool connect() override { return true; }
    bool submit_block(const std::string& hex) override { blocks.push_back(hex); return true; }
    bool submit_aux_block(const uint256&, const std::string&) override { return true; }
    std::string get_block_hex(const std::string&) override { return {}; }
    std::string get_best_block_hash() override { return tip; }
    std::vector<NetService> getpeerinfo() override { return {}; }
    const c2pool::merged::AuxChainConfig& config() const override { return cfg; }
};

MergedMiningManager::PayoutProvider payout_provider()
{
    return [](uint32_t chain_id, uint64_t value) {
        std::vector<unsigned char> script{0x76, 0xa9, 0x14};
        script.insert(script.end(), 20, static_cast<unsigned char>(chain_id & 0xff));
        script.push_back(0x88);
        script.push_back(0xac);
        return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{{script, value}};
    };
}

std::string hex_of(const std::vector<uint8_t>& b)
{
    return HexStr(std::span<const unsigned char>(b.data(), b.size()));
}

/// A parent (LTC-shaped) coinbase carrying `commitment` in its scriptSig, as
/// a stratum job's coinbase does: version, one coinbase input whose scriptSig
/// holds the commitment, one output.
std::string parent_coinbase_hex(const std::vector<uint8_t>& commitment, uint8_t salt = 0x11)
{
    std::vector<uint8_t> script{0x03, 0x01, 0x02, 0x03, salt};   // height push + extranonce-ish byte
    script.insert(script.end(), commitment.begin(), commitment.end());
    script.insert(script.end(), 8, salt);   // the rest of the scriptSig

    std::vector<uint8_t> tx{0x01, 0x00, 0x00, 0x00, 0x01};
    tx.insert(tx.end(), 32, 0x00);
    tx.insert(tx.end(), 4, 0xff);
    tx.push_back(static_cast<uint8_t>(script.size()));
    tx.insert(tx.end(), script.begin(), script.end());
    tx.insert(tx.end(), 4, 0xff);   // sequence
    tx.push_back(0x01);             // one output
    for (int i = 0; i < 8; ++i) tx.push_back(0x01);
    tx.push_back(0x00);             // empty scriptPubKey
    tx.insert(tx.end(), 4, 0x00);   // locktime
    return hex_of(tx);
}

/// The 80-byte parent header of a block whose only transaction is `coinbase`.
std::string parent_header_hex(const std::string& coinbase_hex, uint32_t nonce = 7)
{
    const auto cb = ParseHex(coinbase_hex);
    const uint256 cbid = Hash(std::span<const unsigned char>(cb.data(), cb.size()));
    std::vector<uint8_t> hdr;
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(0x20000000u >> (8 * i)));
    hdr.insert(hdr.end(), 32, 0x22);
    hdr.insert(hdr.end(), cbid.data(), cbid.data() + 32);
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(1793210000u >> (8 * i)));
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(0x1e0fffffu >> (8 * i)));
    for (int i = 0; i < 4; ++i) hdr.push_back(static_cast<uint8_t>(nonce >> (8 * i)));
    return hex_of(hdr);
}

void submit_share(MergedMiningManager& mm, const std::vector<uint8_t>& commitment,
                  const std::string& pow = "01", uint8_t salt = 0x11)
{
    const auto cb = parent_coinbase_hex(commitment, salt);
    uint256 parent_hash;
    parent_hash.SetHex(pow);
    mm.try_submit_merged_blocks(parent_header_hex(cb), cb, {}, 0, parent_hash);
}

struct Parsed {
    uint256 hash;           // SHA256d of the 80-byte aux header
    uint32_t version{0};
    doge::coin::CAuxPow<> aux;
    size_t txs{0};
};

Parsed parse_block(const std::string& block_hex)
{
    const auto bytes = ParseHex(block_hex);
    if (bytes.size() < 80)
        throw std::runtime_error("short block");
    PackStream ps(std::span<const std::byte>(reinterpret_cast<const std::byte*>(bytes.data()), bytes.size()));
    Parsed p;
    bool has_aux = false;
    auto hdr = doge::coin::parse_aux_header(ps, p.aux, has_aux);
    EXPECT_TRUE(has_aux) << "the block carries no AuxPoW";
    p.hash = Hash(std::span<const unsigned char>(bytes.data(), 80));
    p.version = static_cast<uint32_t>(hdr.m_version);
    p.txs = ReadCompactSize(ps);
    return p;
}

/// CAuxPow::check for a chain; returns what Core would answer.
std::optional<std::string> core_check(const Parsed& p, uint32_t chain_id)
{
    return doge::coin::check_auxpow(p.aux, p.hash, static_cast<int32_t>(chain_id),
                                    /*strict_chain_id=*/true);
}

struct Rig {
    boost::asio::io_context ioc;
    MergedMiningManager mm{ioc};
    std::vector<Backend*> chains;
    int64_t clock{1000};
    Rig(std::vector<std::pair<std::string, uint32_t>> ids, int start_height = 5'000'001)
    {
        mm.set_clock_for_test([this] { return clock; });
        mm.set_payout_provider(payout_provider());
        for (const auto& [sym, cid] : ids) {
            auto b = std::make_unique<Backend>(sym, cid, start_height);
            chains.push_back(b.get());
            auto cfg = b->cfg;
            mm.add_chain(cfg, std::move(b));
        }
    }
    Backend& chain(size_t i) { return *chains.at(i); }
    uint256 root()
    {
        const auto c = mm.get_auxpow_commitment();
        EXPECT_EQ(c.size(), 44u);
        uint256 r;
        for (int i = 0; i < 32; ++i)
            r.data()[i] = c[4 + 31 - i];
        return r;
    }
};

std::map<uint32_t, uint256> leaves_now(Rig& r)
{
    std::map<uint32_t, uint256> out;
    const auto work = r.mm.get_current_work();
    for (const auto& [cid, w] : work)
        out[cid] = w.block_hash;
    return out;
}

} // namespace

// Reproduction + fix: a share that meets both targets gives a block for each
// chain, each with a proof Core accepts for ITS chain.
TEST(MergedMultiAux, TwoChainsEachSubmitAValidProof)
{
    Rig r({{"DOGE", 98}, {"NMC", 1}});
    r.mm.refresh_aux_work();
    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], 2u) << "tree size";
    EXPECT_EQ(commitment[40], 0u) << "nonce";

    const auto work_before = leaves_now(r);
    submit_share(r.mm, commitment);

    for (size_t i = 0; i < r.chains.size(); ++i) {
        auto& b = r.chain(i);
        ASSERT_EQ(b.blocks.size(), 1u) << b.cfg.symbol << " block was not submitted";
        const auto p = parse_block(b.blocks[0]);
        EXPECT_EQ(p.hash, work_before.at(b.cfg.chain_id)) << b.cfg.symbol;
        EXPECT_EQ(p.txs, 1u);
        EXPECT_TRUE(p.version & 0x100u) << "auxpow version bit";
        EXPECT_EQ(p.version >> 16, b.cfg.chain_id);
        const auto why = core_check(p, b.cfg.chain_id);
        EXPECT_FALSE(why.has_value()) << b.cfg.symbol << ": " << why.value_or("");
        EXPECT_EQ(p.aux.m_chain_merkle_link.m_branch.size(), 1u);
        EXPECT_EQ(p.aux.m_chain_merkle_link.m_index,
                  nmc::coin::aux_expected_index(0, static_cast<int32_t>(b.cfg.chain_id), 1));
    }

    // The two proofs are siblings of each other: each branch is the other
    // chain's committed block hash.
    const auto p0 = parse_block(r.chain(0).blocks[0]);
    const auto p1 = parse_block(r.chain(1).blocks[0]);
    EXPECT_EQ(p0.aux.m_chain_merkle_link.m_branch[0], p1.hash);
    EXPECT_EQ(p1.aux.m_chain_merkle_link.m_branch[0], p0.hash);
    EXPECT_NE(p0.aux.m_chain_merkle_link.m_index, p1.aux.m_chain_merkle_link.m_index);
    EXPECT_EQ(r.mm.get_discovered_blocks().size(), 2u);
}

// A tree of three chains: size 4, every proof verifies, branch length 2.
TEST(MergedMultiAux, ThreeChainTree)
{
    Rig r({{"DOGE", 98}, {"NMC", 1}, {"PEP", 63}});
    const AuxPowTree t = AuxPowTree::build({98, 1, 63});
    r.mm.refresh_aux_work();
    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], t.size);

    const auto work = leaves_now(r);
    submit_share(r.mm, commitment);
    for (size_t i = 0; i < r.chains.size(); ++i) {
        auto& b = r.chain(i);
        ASSERT_EQ(b.blocks.size(), 1u) << b.cfg.symbol;
        const auto p = parse_block(b.blocks[0]);
        EXPECT_EQ(p.hash, work.at(b.cfg.chain_id));
        const auto why = core_check(p, b.cfg.chain_id);
        EXPECT_FALSE(why.has_value()) << b.cfg.symbol << ": " << why.value_or("");
        EXPECT_EQ(p.aux.m_chain_merkle_link.m_branch.size(), 2u) << "log2(size)";
        EXPECT_EQ(p.aux.m_chain_merkle_link.m_index,
                  t.slot_map.at(b.cfg.chain_id));
    }
}

// Slot collision: 98 and 22 agree mod 4, for every nonce; the tree grows until
// they don't (nonce stays 0), and the proofs carry the size and index the
// daemons compute from the nonce and chain id.
TEST(MergedMultiAux, SlotCollisionGrowsTheTreeAndProofsVerify)
{
    for (uint32_t nonce = 0; nonce < 8; ++nonce)
        ASSERT_EQ(nmc::coin::aux_expected_index(nonce, 98, 2),
                  nmc::coin::aux_expected_index(nonce, 22, 2));
    const AuxPowTree t = AuxPowTree::build({98, 22});
    ASSERT_EQ(t.size, 8u) << "two chains that collide at sizes 2 and 4";

    Rig r({{"DOGE", 98}, {"X", 22}});
    r.mm.refresh_aux_work();
    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], 8u);
    EXPECT_EQ(commitment[40], 0u) << "the nonce is never searched";
    submit_share(r.mm, commitment);
    for (size_t i = 0; i < 2; ++i) {
        ASSERT_EQ(r.chain(i).blocks.size(), 1u);
        const auto p = parse_block(r.chain(i).blocks[0]);
        const auto why = core_check(p, r.chain(i).cfg.chain_id);
        EXPECT_FALSE(why.has_value()) << why.value_or("");
        EXPECT_EQ(p.aux.m_chain_merkle_link.m_branch.size(), 3u);
    }
}

// The branch the proof carries is the Core CheckMerkleBranch walk over
// independent double-SHA256 hashes, not a re-derivation with the same helper.
TEST(MergedMultiAux, BranchMatchesCheckMerkleBranch)
{
    AuxPowTree t;
    t.size = 4;
    uint256 h0, h1, h2, h3;
    h0.SetHex(std::string(60, '0') + "1111");
    h1.SetHex(std::string(60, '0') + "2222");
    h2.SetHex(std::string(60, '0') + "3333");
    h3.SetHex(std::string(60, '0') + "4444");
    const std::map<uint32_t, uint256> leaves{{0, h0}, {1, h1}, {2, h2}, {3, h3}};
    auto dsha = [](const uint256& a, const uint256& b) {
        CSHA256 s; unsigned char first[32], second[32];
        s.Write(a.data(), 32).Write(b.data(), 32).Finalize(first);
        CSHA256().Write(first, 32).Finalize(second);
        uint256 r; std::memcpy(r.data(), second, 32); return r;
    };
    const uint256 n01 = dsha(h0, h1), n23 = dsha(h2, h3), root = dsha(n01, n23);
    for (uint32_t slot = 0; slot < 4; ++slot) {
        const auto proof = t.compute_root(leaves, slot);
        EXPECT_EQ(proof.root, root) << "slot " << slot;
        ASSERT_EQ(proof.branch.size(), 2u);
        const uint256 leaf = leaves.at(slot);
        EXPECT_EQ(doge::coin::aux_merkle_branch(leaf, proof.branch, slot), root) << "slot " << slot;
    }
    const auto proof2 = t.compute_root(leaves, 2);
    EXPECT_EQ(proof2.branch[0], h3);
    EXPECT_EQ(proof2.branch[1], n01);
    EXPECT_EQ(proof2.index, 2u);
}

// A stale job: its coinbase commits to an older root; each chain's block and
// branch are the ones of THAT root, not of the current work.
TEST(MergedMultiAux, StaleJobUsesTheCommittedSnapshotOfEachChain)
{
    Rig r({{"DOGE", 98}, {"NMC", 1}});
    r.mm.refresh_aux_work();
    const auto job1_commit = r.mm.get_auxpow_commitment();
    const auto job1_leaves = leaves_now(r);

    // DOGE moves on (new tip) before the share comes in; NMC does not.
    r.chain(0).tip = std::string(62, '0') + "c2";
    r.chain(0).height += 1;
    r.mm.refresh_aux_work();
    ASSERT_NE(r.mm.get_auxpow_commitment(), job1_commit);
    ASSERT_NE(leaves_now(r).at(98), job1_leaves.at(98));

    submit_share(r.mm, job1_commit);
    ASSERT_EQ(r.chain(0).blocks.size(), 1u);
    ASSERT_EQ(r.chain(1).blocks.size(), 1u);
    const auto doge = parse_block(r.chain(0).blocks[0]);
    const auto nmc_blk = parse_block(r.chain(1).blocks[0]);
    EXPECT_EQ(doge.hash, job1_leaves.at(98)) << "the DOGE block of the share's job, not the current one";
    EXPECT_EQ(nmc_blk.hash, job1_leaves.at(1));
    for (auto [p, cid] : {std::pair{&doge, 98u}, std::pair{&nmc_blk, 1u}}) {
        const auto why = core_check(*p, cid);
        EXPECT_FALSE(why.has_value()) << cid << ": " << why.value_or("");
    }
    // The discovered record is the committed block too.
    const auto rec = r.mm.get_discovered_blocks();
    ASSERT_EQ(rec.size(), 2u);
    for (const auto& b : rec)
        EXPECT_EQ(b.block_hash, job1_leaves.at(b.chain_id).GetHex());
}

// A chain with no block in the job's commitment (no payouts when it was
// built; it has older blocks frozen, so the find gets as far as the lookup):
// the round commits to the chain that has a block alone, in the smallest tree
// that holds it (size 1: the root is its block hash, as a V36 peer expects
// from a share carrying that chain only); it gets a valid proof, the other is
// refused and counted.
TEST(MergedMultiAux, ChainMissingFromTheCommitmentIsRefusedTheOtherSubmits)
{
    Rig r({{"DOGE", 98}, {"NMC", 1}});
    bool nmc_pays = true;
    r.mm.set_payout_provider([&nmc_pays](uint32_t chain_id, uint64_t value) {
        if (chain_id == 1 && !nmc_pays) {
            MergedMiningManager::note_payout_miss("tracker_busy");
            return std::vector<std::pair<std::vector<unsigned char>, uint64_t>>{};
        }
        return payout_provider()(chain_id, value);
    });
    r.mm.refresh_aux_work();

    // NMC moves to a new parent and its payouts are not available: its last
    // block cannot be kept (other parent), it leaves the commitment.
    nmc_pays = false;
    r.chain(1).tip = std::string(62, '0') + "f1";
    r.chain(1).height += 1;
    r.mm.refresh_aux_work();
    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], 1u) << "the tree of DOGE alone";
    EXPECT_EQ(r.root(), r.mm.get_current_work().at(98).block_hash);
    const auto infos = r.mm.get_cached_header_infos_and_commitment().first;
    ASSERT_EQ(infos.size(), 1u) << "the shares carry DOGE's header info only";
    EXPECT_EQ(infos[0].chain_id, 98u);
    submit_share(r.mm, commitment);

    ASSERT_EQ(r.chain(0).blocks.size(), 1u) << "the chain in the commitment submits";
    EXPECT_TRUE(r.chain(1).blocks.empty()) << "no block exists for the dropped chain";
    const auto doge = parse_block(r.chain(0).blocks[0]);
    const auto why = core_check(doge, 98);
    EXPECT_FALSE(why.has_value()) << why.value_or("");
    EXPECT_TRUE(doge.aux.m_chain_merkle_link.m_branch.empty()) << "a tree of one: no branch";
    EXPECT_EQ(doge.aux.m_chain_merkle_link.m_index, 0u);
    EXPECT_EQ(r.mm.get_block_refusals_json().value("NMC:not_committed", 0), 1);
}

// A coinbase whose root this node never built, or built too long ago: no
// submission, a counter for each chain, nothing recorded as found.
TEST(MergedMultiAux, UnknownRootFailsClosed)
{
    Rig r({{"DOGE", 98}, {"NMC", 1}});
    r.mm.refresh_aux_work();
    auto bogus = r.mm.get_auxpow_commitment();
    ASSERT_EQ(bogus.size(), 44u);
    bogus[10] ^= 0x5a;  // another root
    submit_share(r.mm, bogus);
    EXPECT_TRUE(r.chain(0).blocks.empty());
    EXPECT_TRUE(r.chain(1).blocks.empty());
    auto refusals = r.mm.get_block_refusals_json();
    EXPECT_EQ(refusals.value("DOGE:no_commitment", 0), 1);
    EXPECT_EQ(refusals.value("NMC:no_commitment", 0), 1);
    EXPECT_TRUE(r.mm.get_discovered_blocks().empty());

    // The root expires with its snapshots.
    const auto old_commit = r.mm.get_auxpow_commitment();
    r.chain(0).tip = std::string(62, '0') + "d2";
    r.chain(0).height += 1;
    r.mm.refresh_aux_work();           // new root, the old one still known
    r.clock += 1000;                    // beyond FROZEN_EXPIRY_SEC
    r.chain(1).tip = std::string(62, '0') + "e2";
    r.chain(1).height += 1;
    r.mm.refresh_aux_work();           // the next rebuild ages out the old root
    submit_share(r.mm, old_commit);
    EXPECT_TRUE(r.chain(0).blocks.empty());
    EXPECT_TRUE(r.chain(1).blocks.empty());
    refusals = r.mm.get_block_refusals_json();
    EXPECT_EQ(refusals.value("DOGE:no_commitment", 0), 2);
    EXPECT_EQ(refusals.value("NMC:no_commitment", 0), 2);
}

// A tree with one chain id given twice (a misconfiguration: two chains can't
// share an id) is one slot, and the manager refuses the second chain rather
// than hanging while the tree grows forever.
TEST(MergedMultiAux, DuplicateChainIdIsRefused)
{
    const AuxPowTree t = AuxPowTree::build({98, 98});
    EXPECT_EQ(t.size, 1u);
    EXPECT_EQ(t.slot_map.size(), 1u);

    Rig r({{"DOGE", 98}, {"DOGE-2", 98}});
    EXPECT_EQ(r.mm.chain_count(), 1u);
    r.mm.refresh_aux_work();
    EXPECT_EQ(r.mm.get_auxpow_commitment().size(), 44u);
    EXPECT_EQ(r.mm.get_auxpow_commitment()[36], 1u) << "still a one-chain tree";
}

// Single non-DOGE chain through the same path as DOGE: one leaf, no
// committed-root record, a block Core accepts.
TEST(MergedMultiAux, SingleNonDogeChainSubmits)
{
    Rig r({{"NMC", 1}});
    r.mm.refresh_aux_work();
    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], 1u);
    const uint256 root = r.root();
    EXPECT_EQ(root, r.mm.get_current_work().at(1).block_hash) << "tree of one: the root is the block hash";
    submit_share(r.mm, commitment);
    ASSERT_EQ(r.chain(0).blocks.size(), 1u);
    const auto p = parse_block(r.chain(0).blocks[0]);
    EXPECT_FALSE(core_check(p, 1).has_value());
    EXPECT_TRUE(p.aux.m_chain_merkle_link.m_branch.empty());
    EXPECT_EQ(p.aux.m_chain_merkle_link.m_index, 0u);
}

// ---- golden: one DOGE chain, byte-identical to the pre-fix path ------------

namespace {

std::string sha256_hex(const std::string& s)
{
    unsigned char out[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(s.data()), s.size()).Finalize(out);
    return HexStr(std::span<const unsigned char>(out, CSHA256::OUTPUT_SIZE));
}

} // namespace

// The exact bytes a DOGE-only setup commits to and submits today: commitment,
// the DOGE coinbase, and the block handed to the daemon (AuxPoW included).
// The digests were produced by the pre-fix tree on the same inputs; a fix that
// touches this path fails here.
TEST(MergedMultiAux, GoldenSingleDogeIsByteIdentical)
{
    Rig r({{"DOGE", 98}}, 5'000'001);
    r.mm.refresh_aux_work();

    const auto commitment = r.mm.get_auxpow_commitment();
    ASSERT_EQ(commitment.size(), 44u);
    EXPECT_EQ(commitment[36], 1u);

    const nlohmann::json tmpl = r.mm.aux_template_json("DOGE");
    const std::string coinbase = tmpl.at("coinbase_hex").get<std::string>();

    submit_share(r.mm, commitment);
    ASSERT_EQ(r.chain(0).blocks.size(), 1u);
    const std::string block = r.chain(0).blocks[0];

    // Golden digests (commitment, coinbase, block) captured before the fix.
    EXPECT_EQ(sha256_hex(hex_of(commitment)), "7a629761367f3e9c7408b76a85e23af5ee2036ea63e685f02d4fdd6b9fd3e0d5");
    EXPECT_EQ(sha256_hex(coinbase), "682679761349d6c8cd7b181c8d89744a06f012dc2f6bb722f25218fdbe4b40b9");
    EXPECT_EQ(sha256_hex(block), "4819d46491a26d06c0e9b70699d4773fabd92ffb91b8474551c3793f1ea78024");
    EXPECT_FALSE(core_check(parse_block(block), 98).has_value());
}
