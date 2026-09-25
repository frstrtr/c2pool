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
// When the network moves to a fork this build does not implement (FCMP++/Carrot
// v17 is the next one), the node must STOP LOUDLY -- withdraw templates and tx
// admission -- and must NOT score the honest, upgraded peers that send it the
// new blocks and transactions. FORK-FUSE-2: and ONE forged above-version
// header (its PoW cannot be checked here) must not be enough to stop it: that
// is only a SUSPECT alarm; the trip needs >= 2 distinct peers AND a stalled
// v16 tip, and clears when v16 extends the tip by 2 (section E).
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
//      v16 block bumped, unattached) are refused WITHOUT a penalty; one of
//      them is a SUSPECT alarm only (templates continue); the tip does not move.
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
//   E. FORK-FUSE-2 (the fuse must not be trippable by one forged header): a
//      lone above-version block is only a SUSPECT alarm (templates continue);
//      two peers forging headers while v16 blocks keep arriving never trip it;
//      a real fork (>= 2 distinct peers AND a stalled v16 tip for the stall
//      period, on an injected clock) trips it, and 2 v16 blocks clear it; the
//      above-version id is held back from the want list, so the REAL
//      SyncDriver asks for it once, not every refetch_reask_ms.
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
#include "impl/xmr/native/node/xmr_sync_driver.hpp"
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
    // The bump-only forgery: a v16 body on our tip with the major version
    // bumped. Its v16-rule id is computable (id_of_forged), so a lying peer can
    // announce it in a chain entry.
    BlockEntry forged_v17(std::uint32_t nonce) const {
        return make_block(FUTURE, FUTURE, GENESIS_TS + 120 * (tip_h + 1), tip_id, nonce,
                          tip_h + 1, base_at(tip_agc));
    }
    // One honest v16 block on the tip, from `p`.
    bool extend_v16(const PeerRef* p, std::uint32_t nonce) {
        const OfferResult r = idx->offer_block(p, next_v16(nonce), false);
        if (r.outcome != OfferOutcome::Connected) return false;
        tip_agc = accumulate_generated_coins(tip_agc, base_at(tip_agc));
        tip_id  = r.id;
        tip_h  += 1;
        return true;
    }
};

// The v16-rule id of a blob that still parses as v16 (base and fix alike).
Hash id_of_forged(const BlockEntry& e) {
    ParsedBlock pb;
    if (parse_block(e.block_blob, pb) != BlockParseStatus::Ok) return Hash{};
    return block_identity(e.block_blob.data(), pb).id;
}

// FORK-FUSE-2's poll. On the pre-fix tree there is none (the latch needs no
// clock), so the behavioural checks below run there unchanged and fail.
void uf_poll(Chain& ch, std::uint64_t now_ms) {
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    (void)ch.idx->check_unknown_fork(now_ms);
#else
    (void)ch; (void)now_ms;
#endif
}

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
        // FORK-FUSE-2: ONE above-version block is an unauthenticated claim
        // (its PoW cannot be checked). It is a SUSPECT alarm; templates go on.
        kat::checkf(ch.idx->template_inputs().has_value(),
                    "A[%s]: templates CONTINUE after a lone above-version block (suspect only)",
                    c.name);
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
        kat::checkf(r.eval == EvalStatus::UnknownFork, "A[%s]: eval is UnknownFork", c.name);
        kat::checkf(r.height == ch.tip_h + 1, "A[%s]: placed at tip+1", c.name);
        kat::checkf(!ch.idx->hf_fuse().tripped(),
                    "A[%s]: the rolled-fork latch is NOT tripped by an above-version block", c.name);
        kat::checkf(ch.idx->unknown_fork_blocks() == 1 && ch.idx->unknown_fork_unattached() == 0,
                    "A[%s]: counted once, attached", c.name);
#endif
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
        {
            const UnknownForkWatch w = ch.idx->unknown_fork_watch();
            kat::checkf(w.state() == UnknownForkState::Suspect && !w.tripped()
                        && w.distinct_peers() == 1 && w.suspect_alarms() == 1,
                        "A[%s]: watch is SUSPECT, 1 peer, 1 alarm (state=%s)", c.name,
                        to_string(w.state()));
        }
#endif
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)

        // A second push of the same block and a v18 one: counted, still no
        // penalty, the fuse records the higher version.
        (void)ch.idx->offer_block(&p, e, false);
        BlockEntry e18 = make_block(FUTURE + 1, FUTURE + 1, GENESIS_TS + 120 * (ch.tip_h + 1),
                                    ch.tip_id, 5, ch.tip_h + 1, base_at(ch.tip_agc), 0x01, true);
        (void)ch.idx->offer_block(&p, e18, false);
        kat::checkf(fetcher.penalties.empty(), "A[%s]: repeats are not penalised either", c.name);
        kat::checkf(ch.idx->unknown_fork_blocks() == 3, "A[%s]: 3 counted", c.name);
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
        kat::checkf(ch.idx->unknown_fork_watch().highest_version() == FUTURE + 1
                    && ch.idx->unknown_fork_watch().suspect_alarms() == 1,
                    "A[%s]: the watch records the highest version seen, alarm once per peer",
                    c.name);
#endif
        kat::checkf(ch.idx->template_inputs().has_value(),
                    "A[%s]: templates still flow after repeats from the same peer", c.name);
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
        kat::check(tmpl_before && n.ch.idx->template_inputs().has_value(),
                   "D1: templates CONTINUE after one peer's above-version block (suspect only)");
#if defined(C2POOL_XMR_UNKNOWN_FORK_FUSE)
        kat::check(!n.ch.idx->hf_fuse().tripped(), "D1: the latch did not trip");
#endif
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
        kat::check(n.ch.idx->unknown_fork_watch().state() == UnknownForkState::Suspect,
                   "D1: the watch is SUSPECT");
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


// =============================================================================
// E. FORK-FUSE-2: suspect, quorum + stall trip, clear, bounded id set
// =============================================================================
constexpr std::uint64_t MIN_MS   = 60'000;
constexpr std::uint64_t STALL_MS = 30 * MIN_MS;   // UNKNOWN_FORK_STALL_MS_DEFAULT

bool tmpl(const Chain& ch) { return ch.idx->template_inputs().has_value(); }
// The gate the node feeds the relay txpool from (NativeNode::publish_tx_gate_).
bool admit(const Chain& ch) { return ch.idx->view().sync_state().synced; }

// E1. One forging peer, no v16 progress for 2 h: SUSPECT only, never trips.
void test_e1_single_peer_never_trips() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef p = peer(21);
    std::uint64_t now = 1'000'000;
    uf_poll(ch, now);
    std::size_t tmpl_off = 0;
    for (int k = 0; k < 2 * 60 * 12; ++k) {         // every 5 s for 2 h
        (void)ch.idx->offer_block(&p, ch.forged_v17(static_cast<std::uint32_t>(k)), false);
        now += 5'000;
        uf_poll(ch, now);
        if (!tmpl(ch)) ++tmpl_off;
    }
    std::printf("E1 one peer x %d forged headers over 2 h, no v16 block: tmpl_off_polls=%zu "
                "penalties=%zu\n", 2 * 60 * 12, tmpl_off, fetcher.penalties.size());
    kat::check(tmpl_off == 0, "E1: one peer never withdraws templates (even with a stalled tip)");
    kat::check(admit(ch), "E1: tx admission stays open");
    kat::check(fetcher.penalties.empty(), "E1: the peer is not penalised");
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    const UnknownForkWatch w = ch.idx->unknown_fork_watch();
    std::printf("E1: state=%s blocks=%llu alarms=%llu peers=%zu trips=%llu\n", to_string(w.state()),
                static_cast<unsigned long long>(w.blocks()),
                static_cast<unsigned long long>(w.suspect_alarms()), w.distinct_peers(),
                static_cast<unsigned long long>(w.trips()));
    kat::check(w.state() == UnknownForkState::Suspect && w.trips() == 0,
               "E1: SUSPECT, 0 trips");
    kat::check(w.blocks() == 2 * 60 * 12 && w.suspect_alarms() == 1,
               "E1: every block counted, one alarm for the one peer");
#endif
}

// E2. Two forging peers every 5 s for 3 h while honest v16 blocks arrive every
// 120 s: never trips, templates and blocks continue, nobody penalised.
void test_e2_two_peers_with_v16_progress() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef p1 = peer(31), p2 = peer(32), honest = peer(33);
    std::uint64_t now = 1'000'000;
    uf_poll(ch, now);
    std::size_t tmpl_off = 0, v16 = 0, forged = 0;
    const std::uint64_t h0 = ch.tip_h;
    for (int k = 1; k <= 3 * 60 * 12; ++k) {         // 5 s steps, 3 h
        (void)ch.idx->offer_block((k & 1) ? &p1 : &p2, ch.forged_v17(static_cast<std::uint32_t>(k)), false);
        ++forged;
        if (k % 24 == 0) {                            // every 120 s
            if (ch.extend_v16(&honest, static_cast<std::uint32_t>(1000 + k))) ++v16;
        }
        now += 5'000;
        uf_poll(ch, now);
        if (!tmpl(ch)) ++tmpl_off;
    }
    std::printf("E2 two peers x %zu forged headers over 3 h, %zu v16 blocks: tip %llu->%llu "
                "tmpl_off_polls=%zu penalties=%zu\n", forged, v16,
                static_cast<unsigned long long>(h0), static_cast<unsigned long long>(ch.tip_h),
                tmpl_off, fetcher.penalties.size());
    kat::check(tmpl_off == 0, "E2: two forging peers never withdraw templates while v16 advances");
    kat::check(v16 == 90 && ch.tip_h == h0 + 90, "E2: every honest v16 block connected");
    kat::check(fetcher.penalties.empty(), "E2: nobody penalised");
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    const UnknownForkWatch w = ch.idx->unknown_fork_watch();
    std::printf("E2: state=%s blocks=%llu alarms=%llu trips=%llu\n", to_string(w.state()),
                static_cast<unsigned long long>(w.blocks()),
                static_cast<unsigned long long>(w.suspect_alarms()),
                static_cast<unsigned long long>(w.trips()));
    kat::check(w.trips() == 0 && w.blocks() == forged, "E2: 0 trips, every block counted");
#endif
}

// E3. A real fork: two distinct peers send above-version blocks and no v16
// block extends the tip. Trips at the stall period (+ one poll), withdraws
// templates AND tx admission, then clears after 2 v16 blocks.
void test_e3_quorum_stall_trip_and_clear() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef p1 = peer(41), p2 = peer(42), honest = peer(43);
    const std::uint64_t t0 = 5'000'000;
    uf_poll(ch, t0);
    (void)ch.idx->offer_block(&p1, ch.next_v17(), false);
    (void)ch.idx->offer_block(&p2, ch.forged_v17(77), false);
    kat::check(tmpl(ch) && admit(ch), "E3: two peers alone (no stall yet) do not trip");
    std::uint64_t trip_at = 0;
    for (std::uint64_t t = t0; t <= t0 + STALL_MS + 5'000; t += 500) {   // 500 ms polls
        uf_poll(ch, t);
        if (!tmpl(ch)) { trip_at = t; break; }
    }
    std::printf("E3 quorum 2 + stall: trip after %llu ms (stall period %llu ms)\n",
                static_cast<unsigned long long>(trip_at ? trip_at - t0 : 0),
                static_cast<unsigned long long>(STALL_MS));
    kat::check(trip_at == t0 + STALL_MS, "E3: trips exactly at the stall period (one 500 ms poll)");
    kat::check(!tmpl(ch) && !admit(ch), "E3: templates and tx admission withdrawn on trip");
    kat::check(fetcher.penalties.empty(), "E3: nobody penalised");
    // Follow survives: one v16 block still connects, but one is not enough.
    kat::check(ch.extend_v16(&honest, 501), "E3: a v16 block still connects while tripped");
    uf_poll(ch, trip_at + 60'000);
    kat::check(!tmpl(ch), "E3: one v16 block does not clear the trip");
    kat::check(ch.extend_v16(&honest, 502), "E3: a second v16 block connects");
    uf_poll(ch, trip_at + 120'000);
    std::printf("E3 clear: templates=%d admit=%d after 2 v16 blocks\n", tmpl(ch) ? 1 : 0,
                admit(ch) ? 1 : 0);
    kat::check(tmpl(ch) && admit(ch), "E3: 2 v16 blocks clear the trip; templates resume");
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    const UnknownForkWatch w = ch.idx->unknown_fork_watch();
    kat::check(w.trips() == 1 && w.clears() == 1 && w.state() == UnknownForkState::Normal,
               "E3: 1 trip, 1 clear, back to normal");
    kat::check(!ch.idx->hf_fuse().tripped(), "E3: the rolled-fork latch untouched");

    // Quorum is required: the same stall with ONE peer never trips; the same
    // peer from two ports on MAINNET is one /16 group.
    Chain c2;
    uf_poll(c2, t0);
    (void)c2.idx->offer_block(&p1, c2.next_v17(), false);
    for (std::uint64_t t = t0; t <= t0 + 4 * STALL_MS; t += 60'000) uf_poll(c2, t);
    kat::check(tmpl(c2), "E3: one peer + 2 h stall does not trip (quorum)");
#endif
}

// E4. The bounded id set: a lying peer announces a forged above-version block
// in a chain entry and serves it on every GET_OBJECTS. The REAL SyncDriver
// asks for it once, not every refetch_reask_ms (15 s) for 10 minutes.
void test_e4_no_rerequest() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef liar = peer(51);
    PeerSyncData sd;
    sd.current_height        = ch.tip_h + 1;      // level with us: no chain asks
    sd.cumulative_difficulty = u128_of(ch.tip_h + 1, 0);
    sd.top_id                = ch.tip_id;
    sd.top_version           = IMPL;
    fetcher.peer_table.push_back({liar, sd});

    const BlockEntry forged = ch.forged_v17(4242);
    const Hash       fid    = id_of_forged(forged);
    // A real next-fork block (unparseable as v16) announced under some id.
    const BlockEntry real17 = ch.next_v17();
    Hash rid = tag_id(0xABCDEF);

    const std::uint64_t t0 = 9'000'000;
    uf_poll(ch, t0);
    for (int leg = 0; leg < 2; ++leg) {
        const Hash want = leg == 0 ? fid : rid;
        const BlockEntry& serve = leg == 0 ? forged : real17;
        ChainEntry e;
        e.start_height = ch.tip_h;
        e.total_height = ch.tip_h + 2;
        e.ids = {ch.tip_id, want};
        ch.idx->on_chain_entry(liar, std::move(e));
        rt::SyncDriver drv(fetcher, *ch.idx, *ch.idx, tag_id(0), [] { return true; },
                           [&] { return ch.idx->refetch_wanted(); });
        fetcher.object_requests.clear();
        std::size_t asks = 0;
        const std::uint64_t base_t = t0 + static_cast<std::uint64_t>(leg) * 20 * MIN_MS;
        for (std::uint64_t t = base_t; t < base_t + 10 * MIN_MS; t += 500) {
            uf_poll(ch, t);
            const std::size_t before = fetcher.object_requests.size();
            drv.tick(t);
            for (std::size_t i = before; i < fetcher.object_requests.size(); ++i)
                for (const Hash& h : fetcher.object_requests[i].ids)
                    if (h == want) {
                        ++asks;
                        std::vector<BlockEntry> blocks{serve};
                        ch.idx->on_objects(liar, std::move(blocks), {}, ch.tip_h + 2);
                    }
        }
        std::printf("E4[%s]: requests for the above-version id over 10 min = %zu "
                    "(re-requests %zu) penalties=%zu templates=%d\n",
                    leg == 0 ? "forged v16-body, id announced" : "v17-shaped, id by height",
                    asks, asks ? asks - 1 : 0, fetcher.penalties.size(), tmpl(ch) ? 1 : 0);
        kat::checkf(asks == 1, "E4[%d]: the above-version id is requested once (<= 1 per id), got %zu",
                    leg, asks);
        kat::check(fetcher.penalties.empty(), "E4: the liar is not penalised for it");
        kat::check(tmpl(ch), "E4: one lying peer does not withdraw templates");
    }
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    kat::check(ch.idx->unknown_fork_id_known(fid) && ch.idx->unknown_fork_id_known(rid),
               "E4: both ids are in the bounded set");
    // Bounded: 300 distinct forged ids leave at most 256 behind.
    for (int k = 0; k < 300; ++k)
        (void)ch.idx->offer_block(&liar, ch.forged_v17(static_cast<std::uint32_t>(90000 + k)), false);
    std::printf("E4: bounded set holds %zu ids after 300 more forgeries\n", ch.idx->unknown_fork_ids());
    kat::check(ch.idx->unknown_fork_ids() <= 256, "E4: the id set is bounded (<= 256)");
#endif
}


// =============================================================================
// F. FORK-FUSE-3: a lying above-version peer must not make the node lag
// =============================================================================
// The honest chain the F tests follow: v16 blocks the index does not have yet,
// built on whatever the index holds at `from_h` / `from_id`.
struct HonestChain {
    std::vector<BlockEntry> blocks;   // [0] is at height from_h + 1
    std::vector<Hash>       ids;
    std::uint64_t           from_h = 0;
    Hash                    from_id{};
    std::uint64_t           agc    = 0;
    std::uint32_t           nonce  = 0;
    std::uint64_t tip_h() const { return from_h + blocks.size(); }
    Hash          tip_id() const { return ids.empty() ? from_id : ids.back(); }
    void mine() {
        const std::uint64_t h = tip_h() + 1;
        BlockEntry e = make_block(IMPL, IMPL, GENESIS_TS + 120 * h, tip_id(), 0x3000u + (++nonce), h,
                                  base_at(agc));
        agc = accumulate_generated_coins(agc, base_at(agc));
        ids.push_back(id_of(e));
        blocks.push_back(std::move(e));
    }
    const BlockEntry* find(const Hash& id) const {
        for (std::size_t i = 0; i < ids.size(); ++i) if (ids[i] == id) return &blocks[i];
        return nullptr;
    }
};

std::uint64_t our_tip_h(const Chain& ch) {
    const auto t = ch.idx->tip();
    return t ? t->height : 0;
}
Hash our_tip_id(const Chain& ch) {
    const auto t = ch.idx->tip();
    return t ? t->id : Hash{};
}

std::unique_ptr<rt::SyncDriver> make_driver(fakes::FakeFetcher& fetcher, Chain& ch) {
    return std::make_unique<rt::SyncDriver>(
        fetcher, *ch.idx, *ch.idx, tag_id(0), [] { return true; },
        [&ch] { return ch.idx->refetch_wanted(); }, rt::SyncDriver::RefetchFn{},
        rt::SyncDriverConfig{}
#if defined(C2POOL_XMR_SYNC_UNPRODUCTIVE_BACKOFF)
        , [&ch](const PeerRef& p) { return ch.idx->unknown_fork_peer_flagged(p); }
#endif
    );
}

bool contains_id(const std::vector<Hash>& v, const Hash& h) {
    for (const Hash& x : v) if (x == h) return true;
    return false;
}

// F1. THE HELD-ID STALL (the FORK-FUSE-2 verify's probe E5 shape). An honest
// peer's chain entry wants its block at tip+1; ONE lying peer pushes a
// bogus-parent v17-shaped block that CLAIMS height tip+1. Before the fix the
// honest wanted id at that height went into the held set and refetch_wanted()
// withheld it for the 10 min TTL; after it the honest id is offered at once,
// and ids the liar itself announced or served stay held.
void test_f1_honest_id_not_held() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef honest = peer(61), liar = peer(62);
    HonestChain hc;
    hc.from_h = ch.tip_h; hc.from_id = ch.tip_id; hc.agc = ch.tip_agc;
    hc.mine();                                   // the honest block at tip+1
    const Hash hid = hc.ids[0];

    const std::uint64_t t0 = 11'000'000;
    uf_poll(ch, t0);
    {
        ChainEntry e;
        e.start_height = ch.tip_h;
        e.total_height = ch.tip_h + 2;
        e.ids = {ch.tip_id, hid};
        ch.idx->on_chain_entry(honest, std::move(e));
    }
    kat::check(contains_id(ch.idx->refetch_wanted(), hid), "F1: the honest id is wanted before the lie");
    // The lie: a v17-shaped block on a parent nobody has, claiming tip+1.
    (void)ch.idx->offer_block(&liar, make_v17_block(tag_id(0xBAD0BAD), ch.tip_h + 1,
                                                    GENESIS_TS + 120 * (ch.tip_h + 1),
                                                    base_at(ch.tip_agc)), false);
    uf_poll(ch, t0 + 500);
    const bool offered_now = contains_id(ch.idx->refetch_wanted(), hid);
    // The REAL SyncDriver's first tick after the lie: is the honest id on the wire?
    PeerSyncData hs;
    hs.current_height        = ch.tip_h + 2;
    hs.cumulative_difficulty = u128_of(ch.tip_h + 2, 0);
    hs.top_id                = hid;
    hs.top_version           = IMPL;
    PeerSyncData ls          = hs;
    ls.current_height        = ch.tip_h + 2;
    ls.cumulative_difficulty = u128_of(1ull << 40, 0);
    fetcher.peer_table = {{liar, ls}, {honest, hs}};
    auto drv = make_driver(fetcher, ch);
    drv->tick(t0 + 1'000);
    std::size_t asks_first_tick = 0, asks_to_honest = 0;
    for (const auto& r : fetcher.object_requests)
        for (const Hash& h : r.ids)
            if (h == hid) { ++asks_first_tick; if (r.peer.addr == honest.addr) ++asks_to_honest; }
    // And over the next 10 minutes of 500 ms ticks with nobody answering.
    std::size_t asks_10min = asks_first_tick;
    for (std::uint64_t t = t0 + 1'500; t < t0 + 10 * MIN_MS; t += 500) {
        uf_poll(ch, t);
        const std::size_t before = fetcher.object_requests.size();
        drv->tick(t);
        for (std::size_t i = before; i < fetcher.object_requests.size(); ++i)
            for (const Hash& h : fetcher.object_requests[i].ids) if (h == hid) ++asks_10min;
    }
    std::printf("F1 honest id at the height a bogus-parent v17 push claims: in refetch_wanted=%d "
                "asked on the first tick=%zu (to the honest peer %zu) asked over 10 min=%zu penalties=%zu\n",
                offered_now ? 1 : 0, asks_first_tick, asks_to_honest, asks_10min, fetcher.penalties.size());
    kat::check(offered_now, "F1: the honest wanted id is NOT held back by the liar's claimed height");
    kat::checkf(asks_first_tick >= 1, "F1: the honest id is asked for at once (first tick), got %zu",
                asks_first_tick);
    kat::check(fetcher.penalties.empty(), "F1: the liar is not penalised");
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    kat::check(!ch.idx->unknown_fork_id_known(hid), "F1: the honest id is not in the held set");
#endif

    // The liar's OWN ids stay held: an id it announced in its chain entry at
    // the height its v17 push claims (attached on our tip, and bogus-parent).
    for (int leg = 0; leg < 2; ++leg) {
        const Hash x = tag_id(0xF1F100 + static_cast<std::uint64_t>(leg));
        ChainEntry e;
        e.start_height = ch.tip_h;
        e.total_height = ch.tip_h + 2;
        e.ids = {ch.tip_id, x};
        ch.idx->on_chain_entry(liar, std::move(e));
        kat::check(contains_id(ch.idx->refetch_wanted(), x), "F1: the liar's announced id is wanted first");
        const BlockEntry lie = leg == 0
            ? ch.next_v17()
            : make_v17_block(tag_id(0xBAD0BAD + 1), ch.tip_h + 1, GENESIS_TS + 120 * (ch.tip_h + 1),
                             base_at(ch.tip_agc));
        (void)ch.idx->offer_block(&liar, lie, false);
        uf_poll(ch, t0 + 10 * MIN_MS + 1'000 + static_cast<std::uint64_t>(leg));
        const bool held = !contains_id(ch.idx->refetch_wanted(), x);
        std::printf("F1 liar's own announced id, %s v17 push at tip+1: held=%d\n",
                    leg == 0 ? "attached" : "bogus-parent", held ? 1 : 0);
        kat::checkf(held, "F1[%d]: the liar's own announced id stays held", leg);
    }
    // The honest block still connects.
    const OfferResult r = ch.idx->offer_block(&honest, hc.blocks[0], false);
    kat::check(r.outcome == OfferOutcome::Connected, "F1: the honest block connects");
}

// F2. THE STORM AND THE LAG. A lying peer advertises the heaviest chain (10
// blocks ahead), answers every REQUEST_CHAIN with a chain whose top is an
// above-version block, serves that block on GET_OBJECTS, answers `missed` for
// every honest id, and pushes a v17-shaped header on our tip every 5 s. An
// honest peer mines a block every 60 s; every other one reaches us only as the
// child's push (its parent must be FETCHED), as when a fluffy push is missed.
// Before the fix the driver asked the liar for its chain on (nearly) every
// 500 ms tick and sent it every want-list batch, so the honest parent was
// asked of the liar every 15 s and never of the honest peer: the node fell
// behind for the whole run. After it the liar gets a chain request only on a
// bounded exponential back-off, the honest peer serves the parent at once, and
// the node stays within 2 blocks. Nobody is penalised; nothing trips.
void test_f2_storm_and_lag() {
    Chain ch;
    fakes::FakeFetcher fetcher;
    ch.idx->set_fetcher(&fetcher);
    const PeerRef honest = peer(71), liar = peer(72);
    HonestChain hc;
    hc.from_h = ch.tip_h; hc.from_id = ch.tip_id; hc.agc = ch.tip_agc;

    constexpr std::uint64_t RUN_MS = 20 * MIN_MS;
    const std::uint64_t t0 = 13'000'000;
    uf_poll(ch, t0);
    auto drv = make_driver(fetcher, ch);
    std::size_t chain_to_liar = 0, chain_to_honest = 0, objs_to_liar = 0, objs_to_honest = 0;
    std::size_t max_lag = 0, lag_samples_over2 = 0, tmpl_off = 0;
    std::size_t fc = 0, oc = 0;
    std::uint64_t forged = 0;
    for (std::uint64_t t = t0; t < t0 + RUN_MS; t += 500) {
        const std::uint64_t k = (t - t0) / 500;
        // The honest peer mines every 60 s; odd blocks are pushed, even ones
        // reach us only as their child's parent.
        if (k % 120 == 60) {
            hc.mine();
            if (hc.blocks.size() % 2 == 0)
                (void)ch.idx->offer_block(&honest, hc.blocks.back(), false);   // child: parks, wants its parent
        }
        // The liar forges on our tip every 5 s (+ a bogus-parent claim ahead).
        if (k % 10 == 3) {
            const std::uint64_t h = our_tip_h(ch);
            (void)ch.idx->offer_block(&liar, make_v17_block(our_tip_id(ch), h + 1, GENESIS_TS + 120 * (h + 1),
                                                            base_at(0)), false);
            ++forged;
        }
        const std::uint64_t ours = our_tip_h(ch);
        PeerSyncData hs;
        hs.current_height        = hc.tip_h() + 1;
        hs.cumulative_difficulty = u128_of(hc.tip_h() + 1, 0);
        hs.top_id                = hc.tip_id();
        hs.top_version           = IMPL;
        PeerSyncData ls          = hs;
        ls.current_height        = ours + 11;
        ls.cumulative_difficulty = u128_of(1ull << 40, 0);
        ls.top_version           = FUTURE;
        fetcher.peer_table = {{liar, ls}, {honest, hs}};

        uf_poll(ch, t);
        drv->tick(t);
        if (!tmpl(ch)) ++tmpl_off;

        // Answer what the driver put on the wire.
        for (; fc < fetcher.chain_requests.size(); ++fc) {
            const auto& rq = fetcher.chain_requests[fc];
            const std::uint64_t h = our_tip_h(ch);
            ChainEntry e;
            if (rq.peer.addr == liar.addr) {
                ++chain_to_liar;
                e.start_height = h;
                e.total_height = h + 11;
                e.ids = {our_tip_id(ch), tag_id(0xF2000000ull + k)};
                ch.idx->on_chain_entry(liar, std::move(e));
            } else {
                ++chain_to_honest;
                e.start_height = h;
                e.ids = {our_tip_id(ch)};
                for (std::uint64_t j = h + 1; j <= hc.tip_h(); ++j) e.ids.push_back(hc.ids[j - hc.from_h - 1]);
                e.total_height = h + e.ids.size();
                ch.idx->on_chain_entry(honest, std::move(e));
            }
        }
        for (; oc < fetcher.object_requests.size(); ++oc) {
            const auto rq = fetcher.object_requests[oc];
            std::vector<BlockEntry> blocks;
            std::vector<Hash>       missed;
            if (rq.peer.addr == liar.addr) {
                ++objs_to_liar;
                for (const Hash& id : rq.ids) {
                    if (hc.find(id)) missed.push_back(id);
                    else {
                        const std::uint64_t h = our_tip_h(ch);
                        blocks.push_back(make_v17_block(our_tip_id(ch), h + 1, GENESIS_TS + 120 * (h + 1), base_at(0)));
                    }
                }
                ch.idx->on_objects(liar, std::move(blocks), std::move(missed), our_tip_h(ch) + 11);
            } else {
                ++objs_to_honest;
                for (const Hash& id : rq.ids) {
                    if (const BlockEntry* b = hc.find(id)) blocks.push_back(*b);
                    else missed.push_back(id);
                }
                ch.idx->on_objects(honest, std::move(blocks), std::move(missed), hc.tip_h() + 1);
            }
        }
        const std::uint64_t now_ours = our_tip_h(ch);
        const std::size_t lag = hc.tip_h() > now_ours ? static_cast<std::size_t>(hc.tip_h() - now_ours) : 0;
        if (lag > max_lag) max_lag = lag;
        if (lag > 2) ++lag_samples_over2;
    }
    std::printf("F2 20 min, liar 10 ahead + %llu forged pushes, honest %zu blocks (half only by parent fetch): "
                "our tip %llu vs honest %llu, max lag=%zu (samples > 2: %zu), REQUEST_CHAIN liar=%zu honest=%zu, "
                "GET_OBJECTS liar=%zu honest=%zu, penalties=%zu tmpl_off=%zu\n",
                static_cast<unsigned long long>(forged), hc.blocks.size(),
                static_cast<unsigned long long>(our_tip_h(ch)), static_cast<unsigned long long>(hc.tip_h()),
                max_lag, lag_samples_over2, chain_to_liar, chain_to_honest, objs_to_liar, objs_to_honest,
                fetcher.penalties.size(), tmpl_off);
    kat::checkf(max_lag <= 2, "F2: the node stays within 2 blocks of the honest chain (max lag %zu)", max_lag);
    kat::check(our_tip_h(ch) == hc.tip_h(), "F2: every honest block connected by the end");
    // Back-off 5 s doubling to 300 s: asks at 0, 5, 15, 35, 75, 155, 315, 615, 915 s (+ the
    // honest-timeout fallbacks, none here) -- 9 in 20 min, bound 7 + ceil((1200-315)/300) = 10.
    kat::checkf(chain_to_liar <= 10, "F2: REQUEST_CHAIN to the liar bounded (<= 10 in 20 min), got %zu",
                chain_to_liar);
    kat::check(fetcher.penalties.empty(), "F2: nobody penalised");
    kat::check(tmpl_off == 0, "F2: templates never withdrawn (one liar, v16 advancing)");
#if defined(C2POOL_XMR_UNKNOWN_FORK_WATCH)
    const UnknownForkWatch w = ch.idx->unknown_fork_watch();
    kat::check(w.trips() == 0, "F2: 0 trips");
#endif
#if defined(C2POOL_XMR_SYNC_UNPRODUCTIVE_BACKOFF)
    const auto& ds = drv->stats();
    std::printf("F2 driver: chain_requests=%llu to_flagged=%llu backoff_skips=%llu flagged_peers=%zu\n",
                static_cast<unsigned long long>(ds.chain_requests),
                static_cast<unsigned long long>(ds.chain_requests_unproductive),
                static_cast<unsigned long long>(ds.unproductive_backoff_skips), ds.unproductive_peers);
    // Every chain request to the liar but the very first (sent before its
    // first above-version block flagged it) is a back-off ask.
    kat::check(ds.chain_requests_unproductive + 1 == chain_to_liar,
               "F2: the driver counts the liar's back-off chain requests");
    kat::check(ch.idx->unknown_fork_peer_flagged(liar) && !ch.idx->unknown_fork_peer_flagged(honest),
               "F2: the liar is flagged, the honest peer is not");
    // The flag clears when that peer serves a v16 block that connects.
    hc.mine();
    const OfferResult r = ch.idx->offer_block(&liar, hc.blocks.back(), false);
    kat::check(r.outcome == OfferOutcome::Connected && !ch.idx->unknown_fork_peer_flagged(liar),
               "F2: a connecting v16 block from the liar clears its flag");
#endif
}

} // namespace

int main() {
    test_unknown_fork_block_index();
    test_unknown_fork_block_unattached_and_real();
    test_v16_malformed_blocks_unchanged();
    test_tx_verdicts();
    test_live_levin();
    test_e1_single_peer_never_trips();
    test_e2_two_peers_with_v16_progress();
    test_e3_quorum_stall_trip_and_clear();
    test_e4_no_rerequest();
    test_f1_honest_id_not_held();
    test_f2_storm_and_lag();
    return kat::report("xmr_native_unknown_fork_fuse_kat");
}
