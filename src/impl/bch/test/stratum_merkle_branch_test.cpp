// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// BCH stratum merkle branch KAT (rides bch_g2_block_assembly_roundtrip_test).
//
// WorkData::m_hashes is the body txid list [tx1..txN] in CTOR order (ascending
// txid) with NO coinbase slot. The stratum branches handed to the miner must
// satisfy, for every N:
//
//     fold(coinbase_txid, branches) == merkle_root([coinbase_txid, tx1..txN])
//
// where fold is acc = SHA256d(acc || b) over the branches in order, and the
// merkle root is plain SHA256d pairwise with the last element duplicated on
// an odd row. N == 0 gives an empty branch list and root == coinbase txid.
//
// Checked at three levels:
//   1. bch::coin::stratum_merkle_siblings over synthetic txids, N = 0..9 and
//      33, against a reference merkle written in this file.
//   2. BCHWorkSource::get_stratum_merkle_branches() over a real embedded
//      template (HeaderChain + Mempool -> TemplateBuilder), same N, through
//      the wire hex; plus the m_hashes shape (no coinbase slot, every
//      selected txid, ascending).
//   3. A won block through build_connection_coinbase + mining_submit with
//      body txs: the dispatched block re-deserializes and the merkle root of
//      its body equals the root in its header.
// ---------------------------------------------------------------------------

#include <algorithm>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <memory>
#include <span>
#include <string>
#include <vector>

#include <core/hash.hpp>
#include <core/stratum_types.hpp>
#include <core/uint256.hpp>
#include <btclibs/util/strencodings.h>

#include "../coin/block_assembly.hpp"
#include "../coin/header_chain.hpp"
#include "../coin/mempool.hpp"
#include "../coin/merkle.hpp"
#include "../coin/template_builder.hpp"
#include "../coin/transaction.hpp"
#include "../stratum/work_source.hpp"

namespace {

int g_failures = 0;

#define SMB_CHECK(cond) do { if (!(cond)) { \
    std::cerr << "  FAIL: " #cond " @ stratum_merkle_branch_test.cpp:" << __LINE__ \
              << " (" << g_ctx << ")\n"; ++g_failures; } } while (0)

std::string g_ctx;

using bch::coin::MutableTransaction;
using bch::coin::TxIn;
using bch::coin::TxOut;

// ── Reference merkle (independent of bch::coin) ─────────────────────────────

uint256 ref_pair(const uint256& l, const uint256& r)
{
    unsigned char buf[64];
    std::memcpy(buf, l.data(), 32);
    std::memcpy(buf + 32, r.data(), 32);
    return Hash(std::span<const unsigned char>(buf, sizeof(buf)));
}

uint256 ref_root(std::vector<uint256> level)
{
    if (level.empty()) return uint256::ZERO;
    while (level.size() > 1) {
        std::vector<uint256> next;
        for (size_t i = 0; i < level.size(); i += 2)
            next.push_back(ref_pair(level[i], i + 1 < level.size() ? level[i + 1] : level[i]));
        level.swap(next);
    }
    return level[0];
}

uint256 ref_block_root(const uint256& coinbase_txid, const std::vector<uint256>& body)
{
    std::vector<uint256> leaves;
    leaves.push_back(coinbase_txid);
    leaves.insert(leaves.end(), body.begin(), body.end());
    return ref_root(leaves);
}

// Miner side: fold the coinbase txid up the branch list.
uint256 fold(const uint256& coinbase_txid, const std::vector<uint256>& branches)
{
    uint256 acc = coinbase_txid;
    for (const auto& b : branches) acc = ref_pair(acc, b);
    return acc;
}

// Wire branch (hex of the LE-internal bytes) -> uint256, as mining_submit
// and the miner decode it.
std::vector<uint256> decode_branches(const std::vector<std::string>& hexes)
{
    std::vector<uint256> out;
    for (const auto& h : hexes) {
        uint256 b;
        auto bytes = ParseHex(h);
        if (bytes.size() == 32) std::memcpy(b.begin(), bytes.data(), 32);
        else b = uint256::ONE;  // poison: a malformed branch must not fold right
        out.push_back(b);
    }
    return out;
}

uint256 synthetic_hash(uint32_t i)
{
    unsigned char b[4] = {uint8_t(i), uint8_t(i >> 8), uint8_t(i >> 16), uint8_t(i >> 24)};
    return Hash(std::span<const unsigned char>(b, sizeof(b)));
}

const std::vector<unsigned> kSizes = {0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 33};

// ── 1. SSOT helper ──────────────────────────────────────────────────────────

void check_siblings_fold()
{
    const uint256 cb = synthetic_hash(0xC0FFEE);
    for (unsigned n : kSizes) {
        g_ctx = "siblings N=" + std::to_string(n);
        std::vector<uint256> txs;
        for (unsigned i = 0; i < n; ++i) txs.push_back(synthetic_hash(0x1000 + i));

        const auto sibs = bch::coin::stratum_merkle_siblings(txs);
        const uint256 want = ref_block_root(cb, txs);
        SMB_CHECK(fold(cb, sibs) == want);

        // The reference agrees with the consensus merkle SSOT.
        std::vector<uint256> leaves{cb};
        leaves.insert(leaves.end(), txs.begin(), txs.end());
        SMB_CHECK(bch::coin::compute_merkle_root(leaves) == want);

        if (n == 0) {
            SMB_CHECK(sibs.empty());
            SMB_CHECK(want == cb);
        } else {
            SMB_CHECK(!sibs.empty());
            if (!sibs.empty())
                SMB_CHECK(sibs[0] == txs[0]);  // level-0 sibling of the coinbase is tx1
        }
    }
}

// ── Embedded template rig ───────────────────────────────────────────────────

bch::coin::BCHChainParams rig_params()
{
    auto p = bch::coin::BCHChainParams::mainnet();
    uint256 cp;
    cp.SetHex("00000000000000000002c0ffeec0ffeec0ffeec0ffeec0ffeec0ffeec0ffee00");
    p.fast_start_checkpoint = bch::coin::BCHChainParams::Checkpoint{100000, cp};
    return p;
}

// One-in, one-out body tx spending a distinct confirmed outpoint.
MutableTransaction body_tx(uint32_t i)
{
    MutableTransaction tx;
    tx.version = 2;
    tx.locktime = 0;
    TxIn in;
    in.prevout.hash = synthetic_hash(0xF0000 + i);
    in.prevout.index = i;
    in.sequence = 0xffffffff;
    tx.vin.push_back(in);
    TxOut out;
    out.value = 50000 + i;
    tx.vout.push_back(out);
    return tx;
}

struct Rig {
    bch::coin::BCHChainParams params = rig_params();
    bch::coin::HeaderChain    chain{params};
    bch::coin::Mempool        mempool;
    std::vector<uint256>      body_txids;   // ascending (CTOR)
    std::vector<unsigned char> submitted;
    bool                      submit_called = false;
    std::unique_ptr<bch::stratum::BCHWorkSource> ws;

    explicit Rig(unsigned n)
    {
        SMB_CHECK(chain.init());
        SMB_CHECK(chain.tip().has_value());
        for (unsigned i = 0; i < n; ++i) {
            auto tx = body_tx(i);
            SMB_CHECK(mempool.add_tx_with_known_fee(tx, 1000 + 37 * i));
            body_txids.push_back(bch::coin::compute_txid(tx));
        }
        std::sort(body_txids.begin(), body_txids.end());
        ws = std::make_unique<bch::stratum::BCHWorkSource>(
            chain, mempool, /*is_testnet=*/false,
            [this](const std::vector<unsigned char>& block, uint32_t) -> bool {
                submitted = block;
                submit_called = true;
                return true;
            });
    }
};

// ── 2. producer shape + real wire builder ───────────────────────────────────

void check_work_source_branches()
{
    const uint256 cb = synthetic_hash(0xCB);
    for (unsigned n : kSizes) {
        g_ctx = "work source N=" + std::to_string(n);
        Rig rig(n);

        // Producer: m_hashes == every selected body txid, ascending, no
        // coinbase slot, aligned with transactions[].txid.
        auto wd = bch::coin::TemplateBuilder::build_template(rig.chain, rig.mempool, false);
        SMB_CHECK(wd.has_value());
        if (!wd) continue;
        SMB_CHECK(wd->m_hashes == rig.body_txids);
        SMB_CHECK(std::is_sorted(wd->m_hashes.begin(), wd->m_hashes.end()));
        const auto& txs_json = wd->m_data["transactions"];
        SMB_CHECK(txs_json.size() == wd->m_hashes.size());
        for (size_t i = 0; i < txs_json.size() && i < wd->m_hashes.size(); ++i)
            SMB_CHECK(txs_json[i]["txid"].get<std::string>() == wd->m_hashes[i].GetHex());

        // Consumer: the real stratum branch builder, decoded from the wire.
        const auto branches = decode_branches(rig.ws->get_stratum_merkle_branches());
        SMB_CHECK(fold(cb, branches) == ref_block_root(cb, rig.body_txids));
        if (n == 0) SMB_CHECK(branches.empty());
    }
}

// ── 3. won block end to end ─────────────────────────────────────────────────

// Mainnet legacy P2PKH: accepted by BCHWorkSource's own-coin payout check.
constexpr const char* kPayoutAddr = "1BvBMSEYstWetqTFn5Au4m4GFg7xJaNVN2";

void check_won_block(unsigned n)
{
    g_ctx = "won block N=" + std::to_string(n);
    Rig rig(n);
    auto& ws = *rig.ws;

    const std::vector<unsigned char> payout_script = {
        0x76, 0xa9, 0x14,
        0x77, 0xbf, 0xf2, 0x0c, 0x60, 0xe5, 0x22, 0xdf, 0xaa, 0x33,
        0x50, 0xc3, 0x9b, 0x03, 0x0a, 0x5d, 0x00, 0x4e, 0x83, 0x9a,
        0x88, 0xac};
    const std::string en1 = "deadbeef";
    const std::string en2 = "01020304";

    auto cbr = ws.build_connection_coinbase(uint256(), en1, payout_script, {});
    SMB_CHECK(!cbr.coinb1.empty());
    if (cbr.coinb1.empty()) return;

    const auto tmpl = ws.get_current_work_template();
    core::stratum::JobSnapshot job;
    job.coinb1          = cbr.coinb1;
    job.coinb2          = cbr.coinb2;
    job.merkle_branches = cbr.snapshot.merkle_branches;
    job.tx_data         = cbr.snapshot.tx_data;
    job.gbt_prevhash    = tmpl["previousblockhash"].get<std::string>();
    job.version         = static_cast<uint32_t>(tmpl["version"].get<int>());
    job.nbits           = tmpl["bits"].get<std::string>();
    job.block_nbits     = "2100ffff";   // target ~2^256: every digest is a block
    job.share_bits      = 0x2100ffffu;
    job.subsidy         = cbr.snapshot.subsidy;

    SMB_CHECK(job.tx_data && job.tx_data->size() == n);
    SMB_CHECK(job.merkle_branches.size() == bch::coin::stratum_merkle_siblings(rig.body_txids).size());

    auto result = ws.mining_submit(kPayoutAddr, "job-merkle", en1, en2,
                                   "60000000", "00000000", "rid", {}, &job);
    SMB_CHECK(result.is_boolean() && result.get<bool>());
    SMB_CHECK(rig.submit_called);
    if (!rig.submit_called) return;

    // The block as dispatched: its body root must be the header root.
    const auto chk = bch::coin::verify_assembled_block(
        std::span<const unsigned char>(rig.submitted.data(), rig.submitted.size()));
    SMB_CHECK(chk.ok);
    SMB_CHECK(chk.tx_count == n + 1);
    SMB_CHECK(chk.computed_merkle_root == chk.header_merkle_root);

    // And both equal the reference root over [coinbase_txid, tx1..txN].
    auto cb_bytes = ParseHex(job.coinb1 + en1 + en2 + job.coinb2);
    const uint256 cb_txid = Hash(std::span<const unsigned char>(cb_bytes.data(), cb_bytes.size()));
    SMB_CHECK(chk.header_merkle_root == ref_block_root(cb_txid, rig.body_txids));
    SMB_CHECK(fold(cb_txid, decode_branches(job.merkle_branches)) == chk.header_merkle_root);
}

} // namespace

int run_stratum_merkle_branch_checks()
{
    g_failures = 0;
    check_siblings_fold();
    check_work_source_branches();
    for (unsigned n : {0u, 1u, 2u, 3u, 7u})
        check_won_block(n);
    if (g_failures == 0)
        std::cout << "stratum_merkle_branch_test: all checks passed\n";
    else
        std::cerr << "stratum_merkle_branch_test: " << g_failures << " check(s) failed\n";
    return g_failures;
}
