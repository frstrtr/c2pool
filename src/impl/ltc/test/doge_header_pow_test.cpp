// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// The embedded DOGE header chain and its P2P parsers check every header's
// proof of work above the checkpoint, whatever height a peer reports
// (Dogecoin Core 1.14.9 CheckAuxPowProofOfWork / CAuxPow::check; rides
// share_test):
//   - an AuxPoW header whose proof is valid passes check_auxpow_header and
//     the 'headers' parser; with its parent's PoW short of the header's
//     bits, its commitment missing, a wrong slot, the flag without a proof
//     or another chain id, it is refused (the parser stops before it);
//   - a peer-reported height of 4,000,000,000 switches nothing off: a
//     header before AuxPoW, and one without the AuxPoW flag after it, that
//     fails its own scrypt PoW is refused; the reported height is bounded;
//   - a pinned checkpoint's height takes only the checkpoint's block;
//   - the chain refuses a flagged header unless the proof that came with it
//     verifies (CAuxPow::check); a valid copy is accepted after an invalid
//     copy of the same header, and through 'headers' messages each message's
//     own proofs decide (none shared, kept or evicted between messages);
//   - Core's early-auxpow rule: a flagged header below the activation height
//     is refused;
//   - the checkpoint pin drops a conflicting block at the checkpoint height;
//   - a store from an older format re-roots on load, on main_ltc's own start
//     order (init, then the checkpoint, then genesis: start_doge_chain);
//   - the cost of the parent-PoW check per AuxPoW header, printed.
// ---------------------------------------------------------------------------

#include <gtest/gtest.h>

#include <chrono>
#include <cstdint>
#include <iostream>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <impl/doge/coin/auxpow_check.hpp>
#include <impl/doge/coin/auxpow_header.hpp>
#include <impl/doge/coin/chain_params.hpp>
#include <impl/doge/coin/header_chain.hpp>

#include <core/leveldb_store.hpp>
#include <filesystem>
#include <random>

namespace {

using doge::coin::AuxPowRules;
using doge::coin::CAuxPow;
using ltc::coin::BlockHeaderType;

constexpr uint32_t kEasyBits = 0x207fffff;

uint256 sha256d(const BlockHeaderType& h) { return Hash(pack(h).get_span()); }

uint256 easy_limit()
{
    uint256 l;
    l.SetCompact(kEasyBits);
    return l;
}

AuxPowRules rules()
{
    AuxPowRules r;
    r.pow_limit = easy_limit();
    return r;
}

/// A child header and a valid AuxPoW proof for it: a one-leaf chain merkle
/// tree (size 1, slot 0), a parent coinbase committing to it after the
/// merged-mining magic, a one-tx parent block mined to the child's bits.
struct Aux {
    BlockHeaderType child;
    CAuxPow<> aux;

    explicit Aux(const uint256& prev = uint256(), uint32_t tag = 0)
    {
        child.m_version = 0x00620104;  // chain id 0x62, AuxPoW flag, base version 4
        child.m_previous_block = prev;
        child.m_merkle_root.SetHex(std::to_string(4000 + tag));
        child.m_timestamp = 1700000000 + tag * 60;
        child.m_bits = kEasyBits;
        child.m_nonce = 0;
        commit();
    }
    void commit()
    {
        const uint256 h = sha256d(child);
        std::vector<unsigned char> script = {0x03, 0x01, 0x02, 0x03, 0xfa, 0xbe, 'm', 'm'};
        for (int i = 31; i >= 0; --i)
            script.push_back(h.data()[i]);  // the chain merkle root, reversed
        for (unsigned char b : {1, 0, 0, 0, 0, 0, 0, 0})
            script.push_back(b);            // tree size 1, nonce 0
        ltc::coin::MutableTransaction cb;
        cb.version = 1;
        cb.locktime = 0;
        ltc::coin::TxIn in;
        in.prevout.hash.SetNull();
        in.prevout.index = 0xffffffff;
        in.scriptSig.m_data = script;
        in.sequence = 0xffffffff;
        cb.vin.push_back(in);
        ltc::coin::TxOut out;
        out.value = 625000000;
        out.scriptPubKey.m_data = {0x51};
        cb.vout.push_back(out);
        aux.m_merkle_tx.m_tx = cb;
        aux.m_merkle_tx.m_merkle_link.SetNull();
        aux.m_chain_merkle_link.SetNull();
        auto& p = aux.m_parent_block_header;
        p.m_version = 0x20000000;
        p.m_previous_block.SetHex("1234");
        p.m_merkle_root = doge::coin::parent_coinbase_txid(cb);
        p.m_timestamp = child.m_timestamp;
        p.m_bits = 0x1a01d2c3;
        p.m_nonce = 0;
        mine_parent();
    }
    void mine_parent()
    {
        while (!doge::coin::aux_check_pow(doge::coin::aux_scrypt(aux.m_parent_block_header), child.m_bits,
                                          easy_limit()))
            ++aux.m_parent_block_header.m_nonce;
    }
    void unmine_parent()
    {
        while (doge::coin::aux_check_pow(doge::coin::aux_scrypt(aux.m_parent_block_header), child.m_bits,
                                         easy_limit()))
            ++aux.m_parent_block_header.m_nonce;
    }
    /// A 'headers' message with this one extended header.
    std::vector<uint8_t> message() const
    {
        PackStream ps;
        WriteCompactSize(ps, 1);
        ps << child << aux;
        WriteCompactSize(ps, 0);
        auto sp = ps.get_span();
        return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                    reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
    }
};

/// DOGE parameters a test can mine headers for: testnet4alpha's, with the
/// most permissive PoW limit, a genesis at it, AuxPoW from `auxpow_height`.
struct EasyDoge {
    doge::coin::DOGEChainParams params = doge::coin::DOGEChainParams::testnet4alpha();
    BlockHeaderType genesis;
    explicit EasyDoge(uint32_t auxpow_height)
    {
        params.pow_limit = easy_limit();
        params.auxpow_height = auxpow_height;
        genesis.m_version = 1;
        genesis.m_previous_block.SetNull();
        genesis.m_merkle_root.SetHex("5b2a3f53f605d62c53e62932dac6925e3d74afa5a4b459745c36d42d0ed26a69");
        genesis.m_timestamp = 1391503289;
        genesis.m_bits = kEasyBits;
        genesis.m_nonce = 0;
        params.genesis_hash = sha256d(genesis);
    }
    BlockHeaderType child(const uint256& prev, uint32_t height, int32_t version = 4) const
    {
        BlockHeaderType h;
        h.m_version = version;
        h.m_previous_block = prev;
        h.m_merkle_root.SetHex(std::to_string(7000 + height));
        h.m_timestamp = genesis.m_timestamp + 600 * height;
        h.m_bits = kEasyBits;
        h.m_nonce = height << 8;
        return h;
    }
    void mine(BlockHeaderType& h) const
    {
        while (!doge::coin::check_pow(doge::coin::scrypt_hash(h), h.m_bits, params.pow_limit))
            ++h.m_nonce;
    }
    void unmine(BlockHeaderType& h) const
    {
        while (doge::coin::check_pow(doge::coin::scrypt_hash(h), h.m_bits, params.pow_limit))
            ++h.m_nonce;
    }
};

} // namespace

TEST(DogeHeaderPow, AnAuxPowHeaderIsCheckedAgainstItsProof)
{
    const AuxPowRules r = rules();
    Aux ok;
    EXPECT_EQ(doge::coin::check_auxpow_header(ok.child, &ok.aux, r), std::nullopt);
    {
        const auto m = ok.message();
        const auto p = doge::coin::parse_doge_headers(m.data(), m.size(), &r);
        EXPECT_EQ(p.headers.size(), 1u);
        EXPECT_FALSE(p.truncated_at);
    }

    // The parent's PoW short of the child's bits: refused, by the checker and
    // by the parser (which stops before it).
    Aux weak;
    weak.unmine_parent();
    const auto why = doge::coin::check_auxpow_header(weak.child, &weak.aux, r);
    ASSERT_TRUE(why);
    EXPECT_EQ(*why, "AUX proof of work failed");
    {
        const auto m = weak.message();
        const auto p = doge::coin::parse_doge_headers(m.data(), m.size(), &r);
        EXPECT_TRUE(p.headers.empty());
        EXPECT_EQ(p.truncated_at, std::optional<size_t>(0));
        const auto unchecked = doge::coin::parse_doge_headers(m.data(), m.size());
        EXPECT_EQ(unchecked.headers.size(), 1u) << "without rules the parser checks nothing (as before)";
    }

    // The commitment does not name this header.
    Aux other;
    other.child.m_nonce = 7;  // another hash; the proof commits to the old one
    other.mine_parent();
    ASSERT_TRUE(doge::coin::check_auxpow_header(other.child, &other.aux, r));
    EXPECT_NE(doge::coin::check_auxpow_header(other.child, &other.aux, r)->find("missing chain merkle root"),
              std::string::npos);

    // The parent coinbase not at index 0 of its block.
    Aux not_gen;
    not_gen.aux.m_merkle_tx.m_merkle_link.m_index = 1;
    EXPECT_EQ(doge::coin::check_auxpow_header(not_gen.child, &not_gen.aux, r).value_or(""),
              "AUX POW is not valid: AuxPow is not a generate");

    // The flag without a proof, a proof without the flag, another chain id.
    EXPECT_EQ(doge::coin::check_auxpow_header<ltc::coin::MutableTransaction>(ok.child, nullptr, r).value_or(""),
              "no auxpow on block with auxpow version");
    BlockHeaderType unflagged = ok.child;
    unflagged.m_version = 0x00620004;
    EXPECT_EQ(doge::coin::check_auxpow_header(unflagged, &ok.aux, r).value_or(""),
              "auxpow on block with non-auxpow version");
    BlockHeaderType foreign = ok.child;
    foreign.m_version = 0x00630104;
    EXPECT_EQ(doge::coin::check_auxpow_header(foreign, &ok.aux, r).value_or(""), "block does not have our chain ID");

    // A proof checked against the mainnet limit: the easy bits are above it.
    AuxPowRules mainnet = doge::coin::auxpow_rules(doge::coin::DOGEChainParams::mainnet());
    EXPECT_EQ(doge::coin::check_auxpow_header(ok.child, &ok.aux, mainnet).value_or(""), "AUX proof of work failed");

    // A block: the same check, a throw when it fails.
    {
        PackStream ps;
        ps << weak.child << weak.aux;
        WriteCompactSize(ps, 0);
        auto sp = ps.get_span();
        std::vector<uint8_t> b(reinterpret_cast<const uint8_t*>(sp.data()),
                               reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
        EXPECT_THROW(doge::coin::parse_doge_block(b.data(), b.size(), &r), std::runtime_error);
        EXPECT_NO_THROW(doge::coin::parse_doge_block(b.data(), b.size()));
    }
}

TEST(DogeHeaderPow, AHugeClaimedHeightSwitchesNothingOff)
{
    // Before AuxPoW (from 1,000 here): every header's own scrypt.
    {
        EasyDoge d(1000);
        doge::coin::HeaderChain chain(d.params);
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(d.genesis));
        chain.set_peer_tip_height(4'000'000'000u);
        BlockHeaderType bad = d.child(sha256d(d.genesis), 1);
        d.unmine(bad);
        EXPECT_FALSE(chain.add_header(bad)) << "PoW fails, 4e9 below the claimed tip";
        BlockHeaderType good = d.child(sha256d(d.genesis), 1);
        d.mine(good);
        EXPECT_TRUE(chain.add_header(good));
        EXPECT_LT(chain.peer_tip_height(), 4'000'000'000u) << "bounded by the tip's growth";
    }
    // After AuxPoW: a header without the flag meets its bits itself.
    {
        EasyDoge d(0);
        doge::coin::HeaderChain chain(d.params);
        ASSERT_TRUE(chain.init());
        ASSERT_TRUE(chain.add_header(d.genesis));
        chain.set_peer_tip_height(4'000'000'000u);
        BlockHeaderType plain = d.child(sha256d(d.genesis), 1, 0x00620004);
        d.unmine(plain);
        EXPECT_FALSE(chain.add_header(plain)) << "no proof, no own PoW";
        d.mine(plain);
        EXPECT_TRUE(chain.add_header(plain));
    }
}

TEST(DogeHeaderPow, AWrongHashAtTheCheckpointHeightIsRefused)
{
    EasyDoge d(1000);
    doge::coin::HeaderChain chain(d.params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(d.genesis));
    std::vector<BlockHeaderType> c;
    uint256 prev = sha256d(d.genesis);
    for (uint32_t h = 1; h <= 3; ++h) {
        BlockHeaderType x = d.child(prev, h);
        d.mine(x);
        ASSERT_TRUE(chain.add_header(x));
        prev = sha256d(x);
        c.push_back(x);
    }
    chain.set_dynamic_checkpoint(2, sha256d(c[1]));  // below the tip: pinned only
    EXPECT_EQ(chain.height(), 3u);
    BlockHeaderType sibling = d.child(sha256d(c[0]), 2);
    sibling.m_merkle_root.SetHex("abcdef");
    d.mine(sibling);
    EXPECT_FALSE(chain.add_header(sibling)) << "another block at the checkpoint height";
    BlockHeaderType next = d.child(prev, 4);
    d.mine(next);
    EXPECT_TRUE(chain.add_header(next));
}

// The parent-PoW check costs one scrypt per AuxPoW header (DOGE above the
// 6,160,000 checkpoint: ~285,000 headers).
TEST(DogeHeaderPow, AuxPowCheckCostPerHeader)
{
    const AuxPowRules r = rules();
    Aux a;
    constexpr int N = 2000;
    const auto t0 = std::chrono::steady_clock::now();
    int ok = 0;
    for (int i = 0; i < N; ++i)
        ok += doge::coin::check_auxpow_header(a.child, &a.aux, r) ? 0 : 1;
    const double us = std::chrono::duration<double, std::micro>(std::chrono::steady_clock::now() - t0).count() / N;
    std::cout << "[doge-header-pow] AuxPoW check " << us << " us/header: 285,000 headers " << us * 285000 / 1e6
              << " s (one thread)" << std::endl;
    EXPECT_EQ(ok, N);
}


// The chain refuses a flagged header unless its AuxPoW proof was stashed and
// verifies; a valid stashed proof is accepted (Dogecoin Core
// CheckAuxPowProofOfWork, enforced inside the header chain so no ingest path
// bypasses it).
TEST(DogeHeaderPow, ChainRequiresAVerifiedAuxPowProofForAFlaggedHeader)
{
    EasyDoge d(1);  // AuxPoW from height 1
    doge::coin::HeaderChain chain(d.params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(d.genesis));

    Aux a(sha256d(d.genesis), 1);
    const uint256 h = sha256d(a.child);
    ASSERT_EQ(doge::coin::check_auxpow_header(a.child, &a.aux, rules()), std::nullopt);

    // No proof with the header: refused (the flag alone is not trusted).
    EXPECT_FALSE(chain.add_header(a.child)) << "a flagged header with no proof";
    EXPECT_EQ(chain.height(), 0u);

    // A tampered proof: refused. The parent's merkle root no longer commits to
    // the parent coinbase, so the proof fails CAuxPow::check (or, if the new
    // parent hash misses the bits, the parent proof-of-work check first).
    doge::coin::CAuxPow<> bad = a.aux;
    bad.m_parent_block_header.m_merkle_root.SetHex("1");
    ASSERT_TRUE(doge::coin::check_auxpow_header(a.child, &bad, rules()).has_value());
    EXPECT_FALSE(chain.add_header(a.child, &bad)) << "a tampered proof";
    EXPECT_EQ(chain.height(), 0u);

    // The valid proof, after the tampered copy of the same header: accepted.
    // Each copy is judged on its own (Core AcceptBlockHeader).
    EXPECT_TRUE(chain.add_header(a.child, &a.aux));
    EXPECT_EQ(chain.height(), 1u);
    (void)h;
}

// Core's early-auxpow rule: a flagged header below the activation height is
// refused.
TEST(DogeHeaderPow, EarlyAuxPowHeaderIsRefused)
{
    EasyDoge d(1000);  // AuxPoW from height 1000
    doge::coin::HeaderChain chain(d.params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(d.genesis));
    BlockHeaderType flagged = d.child(sha256d(d.genesis), 1, 0x00620104);  // the flag, below activation
    d.mine(flagged);  // even with its own PoW
    EXPECT_FALSE(chain.add_header(flagged)) << "Core: auxpow block before activation (early-auxpow-block)";
    EXPECT_EQ(chain.height(), 0u);
}

// The checkpoint pin drops a conflicting block already at the checkpoint
// height (Core assume-valid / bad-fork-prior-to-checkpoint).
TEST(DogeHeaderPow, PinDropsAConflictingBlockAtTheCheckpointHeight)
{
    EasyDoge d(1000);
    doge::coin::HeaderChain chain(d.params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(d.genesis));
    std::vector<BlockHeaderType> c;
    uint256 prev = sha256d(d.genesis);
    for (uint32_t hh = 1; hh <= 3; ++hh) {
        BlockHeaderType x = d.child(prev, hh);
        d.mine(x);
        ASSERT_TRUE(chain.add_header(x));
        prev = sha256d(x);
        c.push_back(x);
    }
    uint256 other;
    other.SetHex("00000000000000000000000000000000000000000000000000000000000d0e99");
    chain.set_dynamic_checkpoint(2, other);  // not the block the chain holds at height 2
    EXPECT_FALSE(chain.has_header(sha256d(c[1]))) << "the conflicting block is dropped";
    EXPECT_FALSE(chain.has_header(sha256d(c[2]))) << "and its descendant";
    EXPECT_TRUE(chain.has_header(sha256d(c[0])));
    EXPECT_EQ(chain.tip()->block_hash, other) << "the checkpoint, seeded above the surviving tip";
}

// A store written in an older format (no format marker) re-roots at the
// checkpoint on load: the headers above it are dropped and re-fetched (their
// AuxPoW proofs cannot be re-checked from the stored base headers).
TEST(DogeHeaderPow, StoreRerootsAtTheCheckpointOnAnOlderFormat)
{
    std::mt19937_64 rng(std::random_device{}());
    const auto dir = std::filesystem::temp_directory_path() / ("doge_hdr_reroot_" + std::to_string(rng()));
    EasyDoge d(1000);
    doge::coin::DOGEChainParams::Checkpoint cp;
    cp.height = 1000;
    cp.hash.SetHex("00000000000000000000000000000000000000000000000000000000000d1000");
    d.params.fast_start_checkpoint = cp;

    std::vector<uint256> above;
    {
        doge::coin::HeaderChain chain(d.params, dir.string());
        ASSERT_TRUE(chain.init());  // seeds at the checkpoint (height 1000)
        chain.set_require_auxpow_proof(false);  // persist some above-checkpoint headers
        uint256 prev = cp.hash;
        for (uint32_t k = 1; k <= 3; ++k) {
            BlockHeaderType x = d.child(prev, 1000 + k);
            x.m_version = 0x00620104;
            ASSERT_TRUE(chain.add_header(x));
            prev = sha256d(x);
            above.push_back(sha256d(x));
        }
        ASSERT_EQ(chain.height(), 1003u);
    }
    // Simulate an older store: remove the format marker this build writes.
    {
        core::LevelDBStore db(dir.string(), core::LevelDBOptions{});
        ASSERT_TRUE(db.open());
        db.remove("fmt");
    }
    {
        doge::coin::HeaderChain chain(d.params, dir.string());
        ASSERT_TRUE(chain.init());  // re-roots on load
        EXPECT_EQ(chain.height(), 1000u) << "dropped back to the checkpoint";
        for (const auto& h : above)
            EXPECT_FALSE(chain.has_header(h)) << "an above-checkpoint header was kept";
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}


namespace {

/// A 'headers' message carrying these extended headers.
std::vector<uint8_t> headers_message(const std::vector<std::pair<BlockHeaderType, CAuxPow<>>>& entries)
{
    PackStream ps;
    WriteCompactSize(ps, entries.size());
    for (const auto& [h, aux] : entries) {
        ps << h << aux;
        WriteCompactSize(ps, 0);
    }
    auto sp = ps.get_span();
    return std::vector<uint8_t>(reinterpret_cast<const uint8_t*>(sp.data()),
                                reinterpret_cast<const uint8_t*>(sp.data()) + sp.size());
}

/// One 'headers' message through the production seam: the raw parser, then
/// the headers callback taking that message's proofs, then add_headers.
int deliver_headers(doge::coin::HeaderChain& chain, const std::vector<uint8_t>& msg)
{
    const auto hdrs = doge::coin::parse_doge_headers_message_with_proofs(msg.data(), msg.size());
    const auto proofs = doge::coin::take_message_proofs(hdrs.size());
    return chain.add_headers(hdrs, &proofs);
}

} // namespace

// Through 'headers' messages each message's own proofs decide: a message
// carrying an invalid copy of a header is refused, a later message carrying
// a valid copy of the same header is accepted, and a message's proofs are
// not affected by any number of messages parsed in between.
TEST(DogeHeaderPow, EachHeadersMessageIsCheckedAgainstItsOwnProofs)
{
    EasyDoge d(1);
    doge::coin::HeaderChain chain(d.params);
    ASSERT_TRUE(chain.init());
    ASSERT_TRUE(chain.add_header(d.genesis));

    Aux a(sha256d(d.genesis), 1);
    CAuxPow<> bad = a.aux;
    bad.m_parent_block_header.m_merkle_root.SetHex("1");
    ASSERT_TRUE(doge::coin::check_auxpow_header(a.child, &bad, rules()).has_value());

    EXPECT_EQ(deliver_headers(chain, headers_message({{a.child, bad}})), 0) << "the invalid copy";
    EXPECT_EQ(chain.height(), 0u);
    EXPECT_EQ(deliver_headers(chain, headers_message({{a.child, a.aux}})), 1) << "the valid copy, later";
    EXPECT_EQ(chain.height(), 1u);

    // A message's proofs are its own: parse it, then 10,000 other messages,
    // then add it with the proofs taken at its parse.
    Aux b(sha256d(a.child), 2);
    const auto msg_b = headers_message({{b.child, b.aux}});
    const auto hdrs_b = doge::coin::parse_doge_headers_message_with_proofs(msg_b.data(), msg_b.size());
    const auto proofs_b = doge::coin::take_message_proofs(hdrs_b.size());
    Aux other(uint256(), 100);
    const auto m = headers_message({{other.child, other.aux}});
    for (uint32_t k = 0; k < 10000; ++k)
        (void)doge::coin::parse_doge_headers_message_with_proofs(m.data(), m.size());
    EXPECT_EQ(chain.add_headers(hdrs_b, &proofs_b), 1);
    EXPECT_EQ(chain.height(), 2u);

    // Proofs that do not match the message's headers count are none.
    EXPECT_EQ(doge::coin::take_message_proofs(3).size(), 3u);
}

// main_ltc's start order: init() (which loads the store and, on an older
// format, drops its headers), then the checkpoint (set_dynamic_checkpoint),
// then genesis when empty -- doge::coin::start_doge_chain, the same call
// main_ltc and main_dgb make. The parameters carry no fast-start checkpoint,
// as in production.
TEST(DogeHeaderPow, StoreRerootsOnMainLtcsStartOrder)
{
    std::mt19937_64 rng(std::random_device{}());
    const auto dir = std::filesystem::temp_directory_path() / ("doge_hdr_start_" + std::to_string(rng()));
    EasyDoge d(1000);
    ASSERT_FALSE(d.params.fast_start_checkpoint.has_value());
    const std::string cp_hex = "00000000000000000000000000000000000000000000000000000000000d1001";
    const std::string checkpoint = "1000:" + cp_hex;
    uint256 cp_hash;
    cp_hash.SetHex(cp_hex);

    auto add_above = [&](doge::coin::HeaderChain& chain, uint32_t from, uint32_t n) {
        std::vector<uint256> hs;
        uint256 prev = chain.get_header_by_height(from - 1)->block_hash;
        for (uint32_t k = 0; k < n; ++k) {
            BlockHeaderType x = d.child(prev, from + k);
            x.m_version = 0x00620104;
            EXPECT_TRUE(chain.add_header(x));
            prev = sha256d(x);
            hs.push_back(prev);
        }
        return hs;
    };

    std::vector<uint256> above;
    {
        doge::coin::HeaderChain chain(d.params, dir.string());
        ASSERT_TRUE(chain.init());
        doge::coin::start_doge_chain(chain, checkpoint, d.genesis);
        ASSERT_EQ(chain.height(), 1000u);
        chain.set_require_auxpow_proof(false);  // store some headers to drop
        above = add_above(chain, 1001, 3);
        ASSERT_EQ(chain.height(), 1003u);
    }
    {
        core::LevelDBStore db(dir.string(), core::LevelDBOptions{});
        ASSERT_TRUE(db.open());
        db.remove("fmt");  // as a store from an older format
    }
    std::vector<uint256> kept;
    {
        doge::coin::HeaderChain chain(d.params, dir.string());
        ASSERT_TRUE(chain.init());
        doge::coin::start_doge_chain(chain, checkpoint, d.genesis);
        EXPECT_EQ(chain.height(), 1000u) << "re-rooted at the checkpoint the start applies";
        EXPECT_EQ(chain.tip()->block_hash, cp_hash);
        for (const auto& h : above)
            EXPECT_FALSE(chain.has_header(h)) << "a header from the older store was kept";
        chain.set_require_auxpow_proof(false);
        kept = add_above(chain, 1001, 2);
    }
    {
        // The format marker is written: the next start drops nothing.
        core::LevelDBStore db(dir.string(), core::LevelDBOptions{});
        ASSERT_TRUE(db.open());
        std::vector<uint8_t> fmt;
        EXPECT_TRUE(db.get("fmt", fmt));
    }
    {
        doge::coin::HeaderChain chain(d.params, dir.string());
        ASSERT_TRUE(chain.init());
        doge::coin::start_doge_chain(chain, checkpoint, d.genesis);
        EXPECT_EQ(chain.height(), 1002u);
        for (const auto& h : kept)
            EXPECT_TRUE(chain.has_header(h));
    }
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
}
