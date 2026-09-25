// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_unknown_fork_fuse_kat.cpp
//
// FORK-FUSE: the native node must survive an unknown Monero hard fork safely.
// At the first block of a fork this build does not implement (FCMP++/Carrot
// v17 is the next one), the node must STOP LOUDLY -- trip the unknown-fork
// fuse, withdraw templates and tx admission -- and must NOT score the honest,
// upgraded peers that send it the new blocks and transactions.
//
// THE FAILURE THIS PINS. Before the fix a v17 block failed parse_block()
// (TrailingBytes on the two tree fields, BadMinerTx on the Carrot output tag)
// BEFORE the fuse check was ever reached, and ChainIndex::offer_locked_
// charged the sender PeerFault::BadData = MalformedBody = 10 points = a ban at
// message 1. The relay txpool mapped an FCMP++ transaction (rct type 7) to
// BadVersion/drop and a tx version above 2 to Structural/drop. Every upgraded
// peer would be banned and the node would stall on the old tip.
//
// TEST INPUTS. Regtest cannot mint a v17 block, so the inputs are real bytes
// made v17-shaped (fcmp++-stage cryptonote_basic.h): the major version is
// bumped above MAX_IMPLEMENTED_HF_VERSION, the coinbase output becomes
// txout_to_carrot_v1 (tag 0x01, key[32] + view_tag[3] + anchor[16]) and
// fcmp_pp_n_tree_layers (u8) + fcmp_pp_tree_root[32] are appended after
// tx_hashes. The txs are the real mainnet BP+ corpus with the version or rct
// type bumped, plus an FCMP++-shaped tx (empty ring, Carrot outputs, type 7).
//
// WHAT RUNS.
//   A. The REAL ChainIndex on a from-genesis regtest chain with a recording
//      fetcher: above-version blocks (v17-shaped, bump-only, a real mainnet
//      v16 block bumped, unattached) are refused WITHOUT a penalty; the fuse
//      trips once one attaches; templates stop; the tip does not move.
//   B. The REAL RelayedTxPool: above-version txs refused as NotUnderstood,
//      no drop offence, counted; malformed txs of a known format keep their
//      exact pre-fix verdicts.
//   C. v16 malformed blocks keep their exact pre-fix verdicts and penalties.
//   D. LIVE LEVIN: the REAL XmrPeerPool + REAL ChainIndex + REAL
//      RelayedTxPool, wired as XmrNativeNode wires them, against a monerod
//      stand-in on loopback that pushes the crafted block (2008) and the
//      crafted txs (2002). The link must survive with fail_score 0; a v16
//      garbage block is still banned at message 1.
//
// Only interfaces that existed before the fix are needed for the behavioural
// checks, so this file also builds against the pre-fix tree, where it FAILS
// (A, B, D); the checks of the new surface (EvalStatus::UnknownFork, the
// counters) are compiled only when C2POOL_XMR_UNKNOWN_FORK_FUSE is defined.
// ---------------------------------------------------------------------------
#include <chrono>
#include <cstdio>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <vector>

#include <boost/asio.hpp>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_fork_choice.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/chain/xmr_row_store.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/p2p/xmr_peer_pool.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_c2a_golden.hpp"
#include "xmr_p2p_kat_util.hpp"
#include "xmr_tx_weight_golden.hpp"

using namespace c2pool::xmr::native;
namespace p2p   = c2pool::xmr::native::p2p;
namespace levin = c2pool::xmr::native::levin;
namespace kat   = c2pool::xmr::native::kat;
namespace asio  = boost::asio;
using tcp = asio::ip::tcp;

namespace {

using Bytes = std::vector<std::uint8_t>;

Bytes from_hex(const char* hex) {
    Bytes out;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return 0;
    };
    const std::size_t n = std::strlen(hex);
    for (std::size_t i = 0; i + 1 < n; i += 2)
        out.push_back(static_cast<std::uint8_t>((nib(hex[i]) << 4) | nib(hex[i + 1])));
    return out;
}

void put_varint(Bytes& o, std::uint64_t v) { blob_write_varint(o, v); }

constexpr std::uint8_t IMPL   = MAX_IMPLEMENTED_HF_VERSION;           // 16 today
constexpr std::uint8_t FUTURE = MAX_IMPLEMENTED_HF_VERSION + 1;       // 17 = FCMP++/Carrot

// =============================================================================
// blocks: the reorg-follow / D3a KAT shape on a from-genesis regtest chain
// =============================================================================
Hash tag_id(std::uint64_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[31] = 0x5a;
    return h;
}

// out_tag 0x03 = txout_to_tagged_key (v16), 0x01 = txout_to_carrot_v1 (v17).
// tree_fields appends fcmp_pp_n_tree_layers + fcmp_pp_tree_root after tx_hashes.
BlockEntry make_block(std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
                      const Hash& prev, std::uint32_t nonce, std::uint64_t height,
                      std::uint64_t reward, std::uint8_t out_tag = 0x03,
                      bool tree_fields = false) {
    Bytes b;
    put_varint(b, major);
    put_varint(b, minor);
    put_varint(b, timestamp);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));

    put_varint(b, 2);                       // miner_tx version
    put_varint(b, height + 60);             // unlock_time
    put_varint(b, 1);                       // one input
    b.push_back(0xFF);                      // TX_IN_GEN
    put_varint(b, height);
    put_varint(b, 1);                       // one output
    put_varint(b, reward);
    b.push_back(out_tag);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x10 + i));   // key
    if (out_tag == 0x01) {
        for (int i = 0; i < 3; ++i)  b.push_back(static_cast<std::uint8_t>(0x70 + i));  // view tag[3]
        for (int i = 0; i < 16; ++i) b.push_back(static_cast<std::uint8_t>(0x80 + i));  // anchor_enc[16]
    } else {
        b.push_back(0x00);                  // view tag[1]
    }
    put_varint(b, 33);                      // tx_extra length
    b.push_back(0x01);                      // TX_EXTRA_TAG_PUBKEY (D_e for a 1-output Carrot cb)
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x40 + i));
    b.push_back(0x00);                      // rct type NULL

    put_varint(b, 0);                       // no transaction hashes
    if (tree_fields) {
        b.push_back(0x07);                  // fcmp_pp_n_tree_layers
        for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0xC0 + i));   // tree root
    }

    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}

// The v17-shaped block: major/minor above the implemented range, a Carrot
// coinbase output, and the two trailing tree fields.
BlockEntry make_v17_block(const Hash& prev, std::uint64_t height, std::uint64_t timestamp,
                          std::uint64_t reward) {
    return make_block(FUTURE, FUTURE, timestamp, prev, 0x17171717u, height, reward,
                      /*out_tag=*/0x01, /*tree_fields=*/true);
}

// A real mainnet v16 block (C2a golden) with ONLY the major (and minor) varint
// bumped: body is v16-shaped, parses today, and would be judged by v16 rules.
BlockEntry real_v16_block_bumped() {
    Bytes b = from_hex(golden_c2a::BLOCKS[0].blob_hex);
    // header starts with varint major (0x10) varint minor (0x10): one byte each
    b[0] = FUTURE;
    b[1] = FUTURE;
    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}

Hash id_of(const BlockEntry& e) {
    EvaluatedBlock ev;
    std::string    why;
    if (evaluate_block(e, ev, why) != EvalStatus::Ok) return Hash{};
    return ev.input.identity.id;
}

class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        cur_ = current;
        nxt_ = next;
        return true;
    }
    bool seed_resident(const Hash& s) const {
        if (cur_ && *cur_ == s) return true;
        return nxt_ && *nxt_ == s;
    }
    VerifyStatus verify(const std::uint8_t*, std::size_t, const Hash& seed,
                        std::uint64_t, std::uint64_t, std::uint8_t out[32]) {
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }

private:
    std::optional<Hash> cur_, nxt_;
};

constexpr std::uint64_t GENESIS_TS = 1'700'000'000ull;

U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }

ChainRow genesis_row() {
    ChainRow row;
    row.height                  = 0;
    row.id                      = tag_id(0);
    row.prev_id                 = Hash{};
    row.timestamp               = GENESIS_TS;
    row.major_version           = 1;
    row.minor_version           = 0;
    row.block_weight            = 80;
    row.long_term_weight        = 80;
    row.difficulty              = u128_of(1, 0);
    row.cumulative_difficulty   = u128_of(1, 0);
    row.already_generated_coins = 0;
    row.pow_verified            = true;
    return row;
}

std::uint64_t base_at(std::uint64_t agc) {
    std::uint64_t base = 0;
    (void)get_block_reward(300'000, 300, agc, hf_rules_version(IMPL), base);
    return base;
}

constexpr std::uint64_t OWN_BLOCKS = 3;

// A regtest index at height OWN_BLOCKS, forced synced so templates flow.
struct Chain {
    ModelVerifier                         mv;
    LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions                     opts;
    std::unique_ptr<ChainIndex>           idx;
    Hash                                  tip_id{};
    std::uint64_t                         tip_h   = 0;
    std::uint64_t                         tip_agc = 0;

    Chain() {
        opts.net         = XmrNet::Regtest;
        opts.require_pow = true;
        idx = std::make_unique<ChainIndex>(opts, src);
        const ChainRow g = genesis_row();
        idx->seed_direct(g, {DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                         {g.block_weight}, {g.long_term_weight}, {g.timestamp}, {{0, g.id}});
        tip_id = g.id;
        for (std::uint64_t h = 1; h <= OWN_BLOCKS; ++h) {
            BlockEntry e = make_block(IMPL, IMPL, GENESIS_TS + 120 * h, tip_id,
                                      static_cast<std::uint32_t>(h * 31), h, base_at(tip_agc));
            const OfferResult r = idx->offer_block(nullptr, e, /*own_mined=*/true);
            kat::check(r.outcome == OfferOutcome::Connected, "rig: own block connects");
            tip_agc = accumulate_generated_coins(tip_agc, base_at(tip_agc));
            tip_id  = r.id;
            tip_h   = h;
        }
        idx->force_synced(true);
    }

    BlockEntry next_v16(std::uint32_t nonce = 7) const {
        return make_block(IMPL, IMPL, GENESIS_TS + 120 * (tip_h + 1), tip_id, nonce,
                          tip_h + 1, base_at(tip_agc));
    }
    BlockEntry next_v17() const {
        return make_v17_block(tip_id, tip_h + 1, GENESIS_TS + 120 * (tip_h + 1), base_at(tip_agc));
    }
};

PeerRef peer(std::uint64_t id) {
    PeerRef p;
    p.peer_id = id;
    p.addr    = "10.0.0." + std::to_string(id) + ":18080";
    return p;
}

// =============================================================================
// A. above-version blocks: refused, NOT penalised, fuse trips, templates stop
// =============================================================================
void test_unknown_fork_block_index() {
    struct Case { const char* name; int kind; };
    const Case cases[] = {
        {"v17-shaped (Carrot coinbase + tree fields)", 0},
        {"bump-only (v16 body, major 17)",             1},
    };
    for (const Case& c : cases) {
        Chain ch;
        fakes::FakeFetcher fetcher;
        ch.idx->set_fetcher(&fetcher);
        kat::checkf(ch.idx->template_inputs().has_value(),
                    "A[%s]: templates flow before the fork block", c.name);

        BlockEntry e = c.kind == 0 ? ch.next_v17()
                                   : make_block(FUTURE, FUTURE, GENESIS_TS + 120 * (ch.tip_h + 1),
                                                ch.tip_id, 99, ch.tip_h + 1, base_at(ch.tip_agc));
        const PeerRef p = peer(7);
        const OfferResult r = ch.idx->offer_block(&p, e, /*own_mined=*/false);

        std::printf("A[%s]: outcome=%s eval=%s peer_fault=%d penalties=%zu why=\"%s\"\n",
                    c.name, to_string(r.outcome), to_string(r.eval), r.peer_fault ? 1 : 0,
                    fetcher.penalties.size(), r.why.c_str());
        kat::checkf(r.outcome == OfferOutcome::Rejected, "A[%s]: the block is refused", c.name);
        kat::checkf(!r.peer_fault, "A[%s]: the refusal is NOT a peer fault", c.name);
        kat::checkf(fetcher.penalties.empty(), "A[%s]: the sender is NOT penalised (%zu penalties)",
                    c.name, fetcher.penalties.size());
        kat::checkf(ch.idx->tip() && ch.idx->tip()->height == ch.tip_h,
                    "A[%s]: the tip does not move", c.name);
        kat::checkf(ch.idx->alt_size() == 0, "A[%s]: nothing is parked", c.name);
        kat::checkf(!ch.idx->template_inputs().has_value(),
                    "A[%s]: templates are withdrawn after the fork block", c.name);
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
        kat::checkf(r.eval == EvalStatus::UnknownFork, "A[%s]: eval is UnknownFork", c.name);
        kat::checkf(r.height == ch.tip_h + 1, "A[%s]: placed at tip+1", c.name);
        const HfFuse f = ch.idx->hf_fuse();
        kat::checkf(f.tripped() && f.first_version() == FUTURE && f.first_height() == ch.tip_h + 1,
                    "A[%s]: fuse tripped at v%u h=%llu", c.name, f.first_version(),
                    static_cast<unsigned long long>(f.first_height()));
        kat::checkf(!f.allows(HfCapability::Template) && !f.allows(HfCapability::AdmitTx)
                    && f.allows(HfCapability::Follow),
                    "A[%s]: the fuse withdraws Template and AdmitTx only", c.name);
        kat::checkf(ch.idx->unknown_fork_blocks() == 1 && ch.idx->unknown_fork_unattached() == 0,
                    "A[%s]: counted once, attached", c.name);

        // A second push of the same block and a v18 one: counted, still no
        // penalty, the fuse records the higher version.
        (void)ch.idx->offer_block(&p, e, false);
        BlockEntry e18 = make_block(FUTURE + 1, FUTURE + 1, GENESIS_TS + 120 * (ch.tip_h + 1),
                                    ch.tip_id, 5, ch.tip_h + 1, base_at(ch.tip_agc), 0x01, true);
        (void)ch.idx->offer_block(&p, e18, false);
        kat::checkf(fetcher.penalties.empty(), "A[%s]: repeats are not penalised either", c.name);
        kat::checkf(ch.idx->unknown_fork_blocks() == 3, "A[%s]: 3 counted", c.name);
        kat::checkf(ch.idx->hf_fuse().highest_version() == FUTURE + 1,
                    "A[%s]: the fuse records the highest version seen", c.name);
#endif
        // A v16 block is still followed normally after the trip (Follow is a
        // surviving capability): the chain we have is not discarded.
        const OfferResult r16 = ch.idx->offer_block(&p, ch.next_v16(), false);
        kat::checkf(r16.outcome == OfferOutcome::Connected,
                    "A[%s]: a v16 block still connects after the trip (%s)", c.name,
                    to_string(r16.outcome));
    }
}

void test_unknown_fork_block_unattached_and_real() {
    // A real mainnet v16 block, bumped: its parent is not in a regtest index.
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef p = peer(8);
    const OfferResult r = ch.idx->offer_block(&p, real_v16_block_bumped(), false);
    std::printf("A[real mainnet v16 block, major bumped, unattached]: outcome=%s eval=%s "
                "peer_fault=%d penalties=%zu\n",
                to_string(r.outcome), to_string(r.eval), r.peer_fault ? 1 : 0,
                fetcher.penalties.size());
    kat::check(!r.peer_fault && fetcher.penalties.empty(),
               "A[real]: a bumped real block is not a peer fault");
    kat::check(ch.idx->template_inputs().has_value(),
               "A[real]: an UNATTACHED above-version block does not trip the fuse");
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
    kat::check(r.eval == EvalStatus::UnknownFork, "A[real]: eval is UnknownFork");
    kat::check(!ch.idx->hf_fuse().tripped(), "A[real]: fuse not tripped");
    kat::check(ch.idx->unknown_fork_blocks() == 1 && ch.idx->unknown_fork_unattached() == 1,
               "A[real]: counted as unattached");

    // evaluate_block() itself: header first, body never judged.
    EvaluatedBlock ev;
    std::string    why;
    kat::check(evaluate_block(ch.next_v17(), ev, why) == EvalStatus::UnknownFork,
               "A[eval]: v17-shaped -> UnknownFork");
    kat::check(!eval_status_is_peer_fault(EvalStatus::UnknownFork),
               "A[eval]: UnknownFork is not a peer fault");
    kat::check(ev.input.parsed.header.major_version == FUTURE
               && ev.input.coinbase.height == ch.tip_h + 1,
               "A[eval]: header and coinbase height are handed back");
    kat::check(why.find("major_version 17") != std::string::npos,
               "A[eval]: the reason names the version");
#endif
}

// =============================================================================
// C. v16 malformed blocks: exact pre-fix verdicts and penalties
// =============================================================================
void test_v16_malformed_blocks_unchanged() {
    struct Case { const char* name; BlockEntry e; };
    Chain ch;
    std::vector<Case> cases;
    {   // garbage
        BlockEntry e; e.block_blob.assign(24, 0xA5); cases.push_back({"garbage-24B", e});
    }
    {   // truncated v16 block
        BlockEntry e = ch.next_v16(); e.block_blob.resize(e.block_blob.size() / 2);
        cases.push_back({"v16-truncated", e});
    }
    {   // v16 header with trailing tree fields
        BlockEntry e = make_block(IMPL, IMPL, GENESIS_TS + 120 * (ch.tip_h + 1), ch.tip_id, 3,
                                  ch.tip_h + 1, base_at(ch.tip_agc), 0x03, /*tree_fields=*/true);
        cases.push_back({"v16-trailing-tree-fields", e});
    }
    {   // v16 header with a Carrot coinbase output
        BlockEntry e = make_block(IMPL, IMPL, GENESIS_TS + 120 * (ch.tip_h + 1), ch.tip_id, 4,
                                  ch.tip_h + 1, base_at(ch.tip_agc), 0x01, false);
        cases.push_back({"v16-carrot-coinbase", e});
    }
    {   // major 0
        BlockEntry e = ch.next_v16(); e.block_blob[0] = 0x00; cases.push_back({"major-0", e});
    }
    {   // major 300 (varint 0xac 0x02): not a uint8 -- malformed, not a fork
        BlockEntry e = ch.next_v16();
        e.block_blob.erase(e.block_blob.begin());
        e.block_blob.insert(e.block_blob.begin(), {0xac, 0x02});
        cases.push_back({"major-300", e});
    }
    {   // v16, coinbase overpays (caught at connect)
        BlockEntry e = make_block(IMPL, IMPL, GENESIS_TS + 120 * (ch.tip_h + 1), ch.tip_id, 9,
                                  ch.tip_h + 1, base_at(ch.tip_agc) + 1);
        cases.push_back({"v16-overpay", e});
    }
    // The pre-fix verdicts, pinned: every case is Rejected, a BadData peer
    // fault, one penalty; the eval status is BadBlockBlob except the overpay
    // (Ok, rejected at connect).
    for (Case& c : cases) {
        fakes::FakeFetcher fetcher;
        ch.idx->set_fetcher(&fetcher);
        const PeerRef p = peer(9);
        const OfferResult r = ch.idx->offer_block(&p, c.e, false);
        std::printf("C[%s]: outcome=%s eval=%s peer_fault=%d fault=%s penalties=%zu\n", c.name,
                    to_string(r.outcome), to_string(r.eval), r.peer_fault ? 1 : 0,
                    to_string(r.fault), fetcher.penalties.size());
        const bool overpay = std::string(c.name) == "v16-overpay";
        kat::checkf(r.outcome == OfferOutcome::Rejected, "C[%s]: rejected", c.name);
        kat::checkf(r.peer_fault && r.fault == PeerFault::BadData, "C[%s]: BadData peer fault", c.name);
        kat::checkf(fetcher.penalties.size() == 1 && fetcher.penalties[0].fault == PeerFault::BadData,
                    "C[%s]: exactly one BadData penalty (%zu)", c.name, fetcher.penalties.size());
        kat::checkf(r.eval == (overpay ? EvalStatus::Ok : EvalStatus::BadBlockBlob),
                    "C[%s]: eval %s", c.name, to_string(r.eval));
        ch.idx->set_fetcher(nullptr);
    }
    kat::check(ch.idx->template_inputs().has_value(), "C: malformed v16 blocks never trip the fuse");
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
    kat::check(ch.idx->unknown_fork_blocks() == 0, "C: none counted as unknown-fork");
#endif
}

// =============================================================================
// B. transactions: above-version not understood (no drop); v16 malformed as before
// =============================================================================
std::vector<Bytes> bp_plus_corpus() {
    std::vector<Bytes> out;
    for (std::size_t i = 0; i < golden::FULL_TX_COUNT; ++i) {
        Bytes blob = from_hex(golden::FULL_TXS[i].full_hex);
        DecodedTx d;
        if (decode_relayed_tx(blob, d) == TxDecodeStatus::Ok) out.push_back(std::move(blob));
    }
    return out;
}

std::size_t rct_type_offset(const Bytes& tx) {
    TxWeightInfo info;
    if (parse_tx_full(tx, info) != TxParseStatus::Ok) return 0;
    return info.prefix_size;
}

// An FCMP++-shaped tx (fcmp++-stage): version 2, one input with an EMPTY ring
// and a key image, two Carrot outputs, a 33-byte extra, rct type 7 + fee +
// a stand-in for the rest (never read: the format is not understood).
Bytes fcmp_shaped_tx() {
    Bytes b;
    put_varint(b, 2);
    put_varint(b, 0);
    put_varint(b, 1);
    b.push_back(0x02); put_varint(b, 0); put_varint(b, 0);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x21 + i));
    put_varint(b, 2);
    for (int o = 0; o < 2; ++o) {
        put_varint(b, 0);
        b.push_back(0x01);
        for (int i = 0; i < 51; ++i) b.push_back(static_cast<std::uint8_t>(o * 60 + i));
    }
    put_varint(b, 33);
    b.push_back(0x01);
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x90 + i));
    b.push_back(0x07);
    put_varint(b, 123456);
    for (int i = 0; i < 200; ++i) b.push_back(static_cast<std::uint8_t>(i));
    return b;
}

struct TxCase { const char* name; Bytes blob; bool above; };

std::vector<TxCase> tx_cases() {
    const std::vector<Bytes> corpus = bp_plus_corpus();
    kat::check(!corpus.empty(), "B: the BP+ golden corpus is present");
    const Bytes& real = corpus.front();
    const std::size_t rt = rct_type_offset(real);
    kat::check(rt > 0 && real[rt] == RCT_TYPE_BULLETPROOF_PLUS, "B: rct type offset located");

    std::vector<TxCase> v;
    { Bytes b = real; b[0] = 0x03;             v.push_back({"real-bp+ version->3", b, true}); }
    { Bytes b = real; b[rt] = 0x07;            v.push_back({"real-bp+ rct->7 (FCMP++)", b, true}); }
    { v.push_back({"fcmp++-shaped (carrot outs, empty ring, type 7)", fcmp_shaped_tx(), true}); }
    // v16 malformed / refused cases, verdicts pinned to pre-fix behaviour:
    { Bytes b = real; b[0] = 0x00;             v.push_back({"version 0", b, false}); }
    { Bytes b = real; b.resize(b.size() / 2);  v.push_back({"real-bp+ truncated", b, false}); }
    { Bytes b = real; b[rt] = 0x01;            v.push_back({"real-bp+ rct->1 (known, unsupported)", b, false}); }
    { Bytes b = fcmp_shaped_tx();
      // same shape, known rct type 6: a Carrot output in a v16-format tx is malformed
      const std::size_t off = 1 + 1 + 1 + 1 + 1 + 1 + 32 + 1 + 2 * (1 + 1 + 51) + 1 + 33;
      b[off] = 0x06;                           v.push_back({"carrot outs + rct 6", b, false}); }
    { Bytes b(40, 0x02);                       v.push_back({"garbage", b, false}); }
    return v;
}

void test_tx_verdicts() {
    RelayedTxPool pool(TxpoolConfig{}, nullptr);
    pool.set_synced(true);
    const PeerRef p = peer(3);
    std::size_t drops_above = 0, drops_known = 0, known = 0;
    for (TxCase& c : tx_cases()) {
        const auto vs = pool.on_relayed(p, {c.blob}, true);
        kat::check(vs.size() == 1, "B: one verdict");
        if (vs.empty()) continue;
        const TxRelayVerdict& v = vs.front();
        std::printf("B[%s]: reason=%s drop_offense=%d\n", c.name, to_string(v.reason),
                    v.drop_offense ? 1 : 0);
        if (c.above) {
            if (v.drop_offense) ++drops_above;
            kat::checkf(!v.drop_offense, "B[%s]: above-version tx is NOT a drop offence", c.name);
            kat::checkf(v.reason != TxRelayVerdict::Reason::Accepted, "B[%s]: not admitted", c.name);
        } else {
            ++known;
            if (v.drop_offense) ++drops_known;
            kat::checkf(v.drop_offense, "B[%s]: malformed known-format tx still a drop offence",
                        c.name);
            const bool badver = std::string(c.name).find("rct->1") != std::string::npos;
            kat::checkf(v.reason == (badver ? TxRelayVerdict::Reason::BadVersion
                                            : TxRelayVerdict::Reason::Structural),
                        "B[%s]: pre-fix reason kept (%s)", c.name, to_string(v.reason));
        }
    }
    std::printf("B: above-version drops=%zu (want 0); known-format drops=%zu/%zu (want all)\n",
                drops_above, drops_known, known);
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
    const TxpoolStats s = pool.stats();
    std::printf("B: stats rejected=%llu rejected_not_understood=%llu count=%llu\n",
                static_cast<unsigned long long>(s.rejected),
                static_cast<unsigned long long>(s.rejected_not_understood),
                static_cast<unsigned long long>(s.count));
    kat::check(s.rejected_not_understood == 3, "B: 3 counted not-understood");
    kat::check(s.count == 0, "B: nothing admitted");
    kat::check(tx_format_above_implemented(fcmp_shaped_tx()), "B: classifier: FCMP++ shape");
#endif
}

// =============================================================================
// D. live levin: real pool + real index + real txpool vs a pushing stand-in
// =============================================================================
constexpr std::uint64_t STANDIN_PEER_ID = 0x00f0f0f0f0f0f017ull;

class StandinDaemon {
public:
    explicit StandinDaemon(asio::io_context& io)
        : acc_(io, tcp::endpoint(asio::ip::make_address("127.0.0.1"), 0)), sock_(io) {
        acc_.listen();
        acc_.async_accept(sock_, [this](const boost::system::error_code& ec) {
            if (ec) return;
            arm();
        });
    }

    std::string key() const { return "127.0.0.1:" + std::to_string(acc_.local_endpoint().port()); }

    void push_block(const BlockEntry& e, std::uint64_t peer_height) {
        levin::NewBlock nb;
        nb.b = e;
        nb.current_blockchain_height = peer_height;
        Bytes body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_new_fluffy_block(nb, body, err)) return;
        write(levin::make_notify(levin::CMD_NEW_FLUFFY_BLOCK, body));
    }

    void push_txs(std::vector<Bytes> txs) {
        levin::NewTransactions m;
        m.txs = std::move(txs);
        m.dandelionpp_fluff = true;
        Bytes body;
        levin::MessageError err = levin::MessageError::None;
        if (!levin::encode_new_transactions(m, body, err)) return;
        write(levin::make_notify(levin::CMD_NEW_TRANSACTIONS, body));
    }

private:
    void write(const Bytes& frame) {
        boost::system::error_code ec;
        asio::write(sock_, asio::buffer(frame), ec);
    }

    void arm() {
        sock_.async_read_some(asio::buffer(chunk_),
            [this](const boost::system::error_code& ec, std::size_t n) {
                if (ec) return;
                buf_.insert(buf_.end(), chunk_, chunk_ + n);
                drain();
                arm();
            });
    }

    static std::uint64_t le(const std::uint8_t* p, int n) {
        std::uint64_t v = 0;
        for (int i = n - 1; i >= 0; --i) v = (v << 8) | p[i];
        return v;
    }

    void drain() {
        for (;;) {
            if (buf_.size() < levin::HEADER_SIZE) return;
            const std::uint8_t* p = buf_.data();
            const std::uint64_t cb    = le(p + 8, 8);
            const std::uint32_t cmd   = static_cast<std::uint32_t>(le(p + 17, 4));
            const std::uint32_t flags = static_cast<std::uint32_t>(le(p + 25, 4));
            if (cb > 64u * 1024u * 1024u) { buf_.clear(); return; }
            if (buf_.size() < levin::HEADER_SIZE + cb) return;
            buf_.erase(buf_.begin(),
                       buf_.begin() + levin::HEADER_SIZE + static_cast<std::ptrdiff_t>(cb));
            if ((flags & levin::PACKET_RESPONSE) != 0) continue;
            levin::MessageError err = levin::MessageError::None;
            if (cmd == levin::CMD_HANDSHAKE) {
                levin::HandshakeResponse r;
                r.node_data.network_id    = levin::network_id_of(levin::XmrNet::Stagenet);
                r.node_data.peer_id       = STANDIN_PEER_ID;
                r.node_data.my_port       = 38080;
                r.node_data.support_flags = levin::SUPPORT_FLAG_FLUFFY_BLOCKS;
                r.payload_data            = sync();
                Bytes out;
                if (levin::encode_handshake_response(r, out, err))
                    write(levin::make_response(levin::CMD_HANDSHAKE, out, levin::RC_HANDLER_OK));
            } else if (cmd == levin::CMD_TIMED_SYNC) {
                levin::TimedSyncResponse r;
                r.payload_data = sync();
                Bytes out;
                if (levin::encode_timed_sync_response(r, out, err))
                    write(levin::make_response(levin::CMD_TIMED_SYNC, out, levin::RC_HANDLER_OK));
            }
        }
    }

    static PeerSyncData sync() {
        PeerSyncData s;
        s.current_height        = 3;
        s.cumulative_difficulty = u128_of(3, 0);
        s.top_id                = tag_id(0);
        s.top_version           = IMPL;
        return s;
    }

    tcp::acceptor acc_;
    tcp::socket   sock_;
    std::uint8_t  chunk_[16384]{};
    Bytes         buf_;
};

struct LiveNode {
    asio::io_context                  io;
    Chain                             ch;
    RelayedTxPool                     txpool{TxpoolConfig{}, nullptr};
    std::shared_ptr<p2p::XmrPeerPool> pool;
    std::unique_ptr<StandinDaemon>    link;

    LiveNode() {
        txpool.set_synced(true);
        link = std::make_unique<StandinDaemon>(io);
        p2p::XmrPeerPool::Config c;
        c.net = levin::XmrNet::Stagenet;
        c.link.handshake.net          = levin::XmrNet::Stagenet;
        c.link.handshake.our_peer_id  = 0x1122334455667788ull;
        c.link.handshake_timeout_ms   = 2'000;
        c.link.invoke_timeout_ms      = 2'000;
        c.link.timed_sync_interval_ms = 3'600'000;
        c.link.timed_sync_jitter_ms   = 0;
        c.link.peer_timeout_ms        = 3'600'000;
        c.link.tick_ms                = 50;
        c.maintenance_tick_ms         = 25;
        c.connect_timeout_ms          = 2'000;
        c.use_seeds                   = false;
        c.dial.target_outbound        = 8;
        c.dial.max_per_netgroup       = 8;
        c.dial.anchor_slots           = 0;
        c.dial.rotation_interval_ms   = 0;
        c.manual_peers.push_back(link->key());
        pool = p2p::XmrPeerPool::create(io, c, {ch.idx.get(), ch.idx.get(), &txpool});
        ch.idx->set_fetcher(pool.get());
        pool->start();
        kat::check(wait_for([&] { return pool->peer_count() == 1; }), "D rig: the link is up");
    }

    ~LiveNode() {
        pool->stop();
        pump(100);
        ch.idx->set_fetcher(nullptr);
    }

    void pump(int ms) {
        io.restart();
        io.run_for(std::chrono::milliseconds(ms));
    }

    template <class F>
    bool wait_for(F pred, int budget_ms = 4000) {
        for (int spent = 0; spent < budget_ms; spent += 5) {
            if (pred()) return true;
            pump(5);
        }
        return pred();
    }

    bool connected() const {
        for (const auto& pr : pool->peers()) if (pr.first.addr == link->key()) return true;
        return false;
    }

    std::uint32_t score() const {
        const auto* r = pool->store().find(link->key());
        return r ? r->fail_score : 0;
    }

    // Deliver one frame, then let every fault / ban post land.
    template <class Push>
    void deliver(Push push) {
        const std::uint64_t in_before = pool->telemetry().frames_in;
        push();
        wait_for([&] { return pool->telemetry().frames_in > in_before; }, 2000);
        pump(60);
    }
};

void test_live_levin() {
    // D1. the v17-shaped block, pushed as a 2008
    {
        LiveNode n;
        const bool tmpl_before = n.ch.idx->template_inputs().has_value();
        n.deliver([&] { n.link->push_block(n.ch.next_v17(), n.ch.tip_h + 1); });
        const auto t = n.pool->telemetry();
        std::printf("D1 live 2008 v17 block: link_up=%d fail_score=%u bans=%llu tip=%llu "
                    "templates %d->%d\n",
                    n.connected() ? 1 : 0, n.score(), static_cast<unsigned long long>(t.bans),
                    static_cast<unsigned long long>(n.ch.idx->tip()->height), tmpl_before ? 1 : 0,
                    n.ch.idx->template_inputs().has_value() ? 1 : 0);
        kat::check(n.connected(), "D1: the upgraded peer is NOT dropped");
        kat::check(n.score() == 0, "D1: fail_score unchanged (0)");
        kat::check(t.bans == 0, "D1: no ban");
        kat::check(n.ch.idx->tip()->height == n.ch.tip_h, "D1: tip unchanged");
        kat::check(tmpl_before && !n.ch.idx->template_inputs().has_value(),
                   "D1: templates stop after the fork block");
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
        kat::check(n.ch.idx->hf_fuse().tripped(), "D1: the fuse tripped");
#endif
    }
    // D2. above-version txs, pushed as a 2002
    {
        LiveNode n;
        std::vector<Bytes> txs;
        for (TxCase& c : tx_cases()) if (c.above) txs.push_back(c.blob);
        const std::size_t sent = txs.size();
        n.deliver([&] { n.link->push_txs(std::move(txs)); });
        const auto t = n.pool->telemetry();
        std::printf("D2 live 2002 %zu above-version txs: link_up=%d fail_score=%u bans=%llu\n",
                    sent, n.connected() ? 1 : 0, n.score(), static_cast<unsigned long long>(t.bans));
        kat::check(n.connected(), "D2: the relaying peer is NOT dropped");
        kat::check(n.score() == 0, "D2: fail_score unchanged (0)");
        kat::check(t.bans == 0, "D2: no ban");
    }
    // D3. regression: a v16 garbage block is still banned at message 1
    {
        LiveNode n;
        BlockEntry g; g.block_blob.assign(24, 0xA0);
        n.deliver([&] { n.link->push_block(g, 1); });
        const auto t = n.pool->telemetry();
        std::printf("D3 live 2008 v16 garbage block: link_up=%d bans=%llu\n",
                    n.connected() ? 1 : 0, static_cast<unsigned long long>(t.bans));
        kat::check(!n.connected() && t.bans == 1, "D3: garbage v16 block still banned at message 1");
    }
    // D4. regression: a v16 malformed tx (truncated real BP+) is still a drop offence
    {
        LiveNode n;
        Bytes b = bp_plus_corpus().front();
        b.resize(b.size() / 2);
        n.deliver([&] { n.link->push_txs({b}); });
        const auto t = n.pool->telemetry();
        std::printf("D4 live 2002 truncated v16 tx: link_up=%d bans=%llu\n",
                    n.connected() ? 1 : 0, static_cast<unsigned long long>(t.bans));
        kat::check(!n.connected() && t.bans == 1, "D4: malformed v16 tx still banned at message 1");
    }
}

} // namespace

int main() {
    test_unknown_fork_block_index();
    test_unknown_fork_block_unattached_and_real();
    test_v16_malformed_blocks_unchanged();
    test_tx_verdicts();
    test_live_levin();
    return kat::report("xmr_native_unknown_fork_fuse_kat");
}
