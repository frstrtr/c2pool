// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_reorg_follow_kat.cpp
//
// REORG-FOLLOW: the node adopts a heavier branch that forked BELOW its tip,
// while it is running, without being restarted.
//
// WHY THIS FILE EXISTS NEXT TO xmr_chain_index_kat.cpp, WHICH ALREADY TESTS
// REORGS. That file's fixture seeds a full 735-row difficulty window before it
// connects anything, because it is replaying stagenet from an anchor. Every
// reorg in it therefore reaches a fork point the window already covers, and it
// passes -- 1717 checks, 0 failures -- while a from-genesis node could not
// reorganise at all. The gate was `RowStore::difficulty_window_ending_at`,
// which refused any window whose span reached below height 0, so
// `branch_difficulty_locked_` could not price a single block that attached
// anywhere but the tip until the chain was 735 blocks long. That is every
// regtest rig, always, and the first day of any from-genesis sync. The offer
// path then made it invisible: it answered ParkedOrphan and returned WITHOUT
// storing the block, so the fork-point child of a rival branch was destroyed on
// every delivery, the alt pool never held a candidate, and the fork choice
// never ran. A node that lost a same-height race sat on its own tip forever and
// only a restart -- which re-syncs through the TIP path, where the window is
// whatever the consensus state holds -- appeared to "fix" it.
//
// So this file boots the way a regtest node boots: ONE seeded row at height 0,
// one difficulty row, nothing below. Everything it asserts was impossible
// before the fix, and none of it is reachable from an anchored fixture.
//
//   A  ROWS      -- the young-chain window at RowStore level: granted only when
//                   the store holds the chain from height 0, refused when it
//                   merely starts high, and the "do not invent a window past
//                   the pre-window" refusal survives the relaxation.
//   B  FOLLOW    -- a genesis-booted index at height 8 is handed the rival
//                   branch of a same-height race and then its extension: it
//                   holds, judges, and ADOPTS, in one live object, with no
//                   re-seed and no snapshot reload between the two offers.
//   C  WALK      -- delivery bottom-up, with a hole. A block whose parent is a
//                   parked UNRESOLVED alt used to be dropped by the same
//                   return; now it is held, the missing parent is named in
//                   refetch_wanted(), and filling the hole resolves the whole
//                   branch and switches. Also: refetch_wanted() stops naming
//                   ids we are already holding the bytes for, which is what
//                   made the driver re-ask forever.
//   D  BOUNDS    -- the relaxation buys no new powers. Deeper than
//                   max_reorg_depth is refused and journaled; equal work
//                   against our own block is KEPT (D-14) and the rival is held
//                   so the accounting can see the race; a lighter branch never
//                   switches.
//
// No sockets, no RandomX, no daemon: a model verifier stands in for the PoW
// source exactly as the C2c KAT's does. Registered in BOTH build.yml --target
// lists -- a registered-but-unbuilt target reads as "***Not Run" and fails
// ctest with exit 8 (the #1539 lesson).
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_fork_choice.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/chain/xmr_row_store.hpp"
#include "impl/xmr/native/consensus/xmr_reward.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"

using namespace c2pool::xmr::native;

static int g_checks = 0;
static int g_fail   = 0;

static void checkf(bool cond, const char* fmt, ...) {
    ++g_checks;
    if (!cond) {
        ++g_fail;
        if (g_fail <= 25) {
            va_list ap;
            va_start(ap, fmt);
            std::vfprintf(stderr, fmt, ap);
            va_end(ap);
            std::fputc('\n', stderr);
        }
    }
}

static U128 u128_of(std::uint64_t lo, std::uint64_t hi) { U128 d; d.lo = lo; d.hi = hi; return d; }
static bool u128_eq(const U128& a, const U128& b) { return a.lo == b.lo && a.hi == b.hi; }

static Hash tag_id(std::uint64_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[31] = 0x5a;
    return h;
}

static PeerRef peer(std::uint64_t id) {
    PeerRef p;
    p.peer_id = id;
    p.addr    = "10.9.0." + std::to_string(id) + ":18080";
    return p;
}

// =============================================================================
// building a block (the C2c KAT's shape: a structurally real Monero block with
// one coinbase output and no transactions)
// =============================================================================
static void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) { blob_write_varint(o, v); }

static BlockEntry make_block(std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
                             const Hash& prev, std::uint32_t nonce, std::uint64_t height,
                             std::uint64_t reward, std::uint8_t salt = 0) {
    std::vector<std::uint8_t> b;
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
    b.push_back(0x03);                      // TX_OUT_TO_TAGGED_KEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x10 + i));
    b.push_back(salt);                      // view tag doubles as the sibling salt
    put_varint(b, 33);                      // tx_extra length
    b.push_back(0x01);                      // TX_EXTRA_TAG_PUBKEY
    for (int i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>(0x40 + i));
    b.push_back(0x00);                      // rct type NULL

    put_varint(b, 0);                       // no transaction hashes

    BlockEntry e;
    e.block_blob = std::move(b);
    return e;
}

static Hash id_of(const BlockEntry& e) {
    EvaluatedBlock ev;
    std::string    why;
    if (evaluate_block(e, ev, why) != EvalStatus::Ok) return Hash{};
    return ev.input.identity.id;
}

// =============================================================================
// a model RandomX verifier, shaped exactly like c2pool::xmr::LightVerifier
// =============================================================================
class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };

    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        ++rekeys;
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
        ++hashes;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        return VerifyStatus::Accept;
    }

    std::uint64_t rekeys = 0;
    std::uint64_t hashes = 0;

private:
    std::optional<Hash> cur_, nxt_;
};

struct EventLog {
    std::vector<node::MainchainEvent> events;
    void attach(ChainIndex& idx) {
        idx.subscribe([this](const node::MainchainEvent& e) { events.push_back(e); });
    }
    std::size_t count(node::MainchainEventKind k) const {
        std::size_t n = 0;
        for (const auto& e : events) if (e.kind == k) ++n;
        return n;
    }
    void clear() { events.clear(); }
};

// =============================================================================
// the regtest boot: ONE row at height 0, ONE difficulty row, nothing below
// =============================================================================
// This is xmr_chain_boot.hpp's try_seed_() reproduced with a synthetic genesis:
// a private chain starts at the newest implemented fork version from height 1
// (REGTEST_HARD_FORKS), so every block below carries that major version, and the
// index is left with base_height() == 0 -- the state the whole fix is about.
static constexpr std::uint8_t  REG_MAJOR = MAX_IMPLEMENTED_HF_VERSION;
static constexpr std::uint64_t GENESIS_TS = 1'700'000'000ull;

static ChainRow genesis_row() {
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

static void seed_genesis(ChainIndex& idx) {
    const ChainRow g = genesis_row();
    idx.seed_direct(g,
                    /*difficulty_window=*/{DifficultyRow{g.timestamp, g.cumulative_difficulty}},
                    /*short_term_weights=*/{g.block_weight},
                    /*long_term_weights=*/{g.long_term_weight},
                    /*timestamps_60=*/{g.timestamp},
                    /*seed_ids=*/{{0, g.id}});
}

// The un-penalised base reward for a block of negligible weight at a given
// already_generated_coins, straight out of the consensus reward code. Needed
// because a young chain is NOT in tail emission: the reward changes every block,
// so a branch's coinbase has to be priced at the branch's own emission, which is
// the main chain's up to the fork point and its own above it.
static std::uint64_t base_at(std::uint64_t agc) {
    std::uint64_t base = 0;
    (void)get_block_reward(/*penalty_median=*/300'000, /*block_weight=*/300, agc,
                           hf_rules_version(REG_MAJOR), base);
    return base;
}

// The consensus row at a height. The IChainView reads hand back a
// ChainMainBlock, which deliberately carries no cumulative difficulty and no
// emission; both of those live on the state's own row.
static const ChainRow* row_at(const ChainIndex& idx, std::uint64_t height) {
    for (const ChainRow& r : idx.view().state().rows())
        if (r.height == height) return &r;
    return nullptr;
}

// The already_generated_coins standing at a height on the best chain.
static std::uint64_t agc_at(const ChainIndex& idx, std::uint64_t height) {
    const ChainRow* r = row_at(idx, height);
    return r ? r->already_generated_coins : 0;
}

// A from-genesis index driven to `n` blocks, every one of them ours.
struct Rig {
    ModelVerifier                         mv;
    LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions                     opts;
    ChainIndex*                           idx = nullptr;
    EventLog                              log;
    fakes::FakeFetcher                    fetcher;
    std::vector<Hash>                     main_ids;   // index 0 == height 1
    PeerRef                               them = peer(3);

    explicit Rig(std::uint64_t n_main = 8, std::uint64_t max_reorg = 720) {
        opts.net             = XmrNet::Regtest;
        opts.max_reorg_depth = max_reorg;
        opts.require_pow     = true;
        opts.tie             = TieBreak::PreferOwn;
        idx = new ChainIndex(opts, src);
        seed_genesis(*idx);
        idx->set_fetcher(&fetcher);
        log.attach(*idx);

        Hash prev = genesis_row().id;
        for (std::uint64_t h = 1; h <= n_main; ++h) {
            BlockEntry e = block_for(prev, h, agc_at(*idx, h - 1), /*salt=*/0, /*ts_shift=*/0);
            const OfferResult r = idx->offer_block(nullptr, e, /*own_mined=*/true);
            checkf(r.outcome == OfferOutcome::Connected,
                   "rig: main block %llu became %s (%s)",
                   static_cast<unsigned long long>(h), to_string(r.outcome), r.why.c_str());
            prev = r.id;
            main_ids.push_back(prev);
        }
        log.clear();
    }

    ~Rig() { delete idx; }

    // A block at `height` on top of `prev`, priced at the emission standing at
    // `agc` (the branch's own), with `salt` separating siblings.
    static BlockEntry block_for(const Hash& prev, std::uint64_t height, std::uint64_t agc,
                                std::uint8_t salt, std::int64_t ts_shift) {
        const std::uint64_t ts =
            static_cast<std::uint64_t>(static_cast<std::int64_t>(GENESIS_TS + 120 * height)
                                       + ts_shift);
        return make_block(REG_MAJOR, REG_MAJOR, ts, prev,
                          static_cast<std::uint32_t>(height * 31 + salt), height, base_at(agc),
                          salt);
    }

    Hash tip_id() const {
        const auto t = idx->tip();
        return t ? t->id : Hash{};
    }
    std::uint64_t tip_height() const {
        const auto t = idx->tip();
        return t ? t->height : 0;
    }
};

// A branch of `count` blocks hanging off `fork_id` at `fork_height`, priced at
// the emission standing at the fork point and rolled forward on its own.
// Returned newest-last; NOT offered.
static std::vector<BlockEntry> build_branch(const ChainIndex& idx, const Hash& fork_id,
                                            std::uint64_t fork_height, std::size_t count,
                                            std::uint8_t salt_base, std::int64_t ts_shift = 0) {
    std::vector<BlockEntry> out;
    Hash          prev = fork_id;
    std::uint64_t agc  = agc_at(idx, fork_height);
    for (std::size_t i = 0; i < count; ++i) {
        const std::uint64_t h = fork_height + 1 + i;
        BlockEntry e = Rig::block_for(prev, h, agc,
                                      static_cast<std::uint8_t>(salt_base + i), ts_shift);
        agc  = accumulate_generated_coins(agc, base_at(agc));
        prev = id_of(e);
        out.push_back(std::move(e));
    }
    return out;
}

// =============================================================================
// A. the young-chain window, at RowStore level
// =============================================================================
static void push_row(RowStore& s, std::uint64_t h, std::uint64_t ts, std::uint64_t cd) {
    ChainRow r;
    r.height                = h;
    r.id                    = tag_id(h);
    r.timestamp             = ts;
    r.cumulative_difficulty = u128_of(cd, 0);
    s.push(r, false, Hash{});
}

static void test_young_window() {
    // A store that holds the chain from its first block.
    RowStore young;
    for (std::uint64_t h = 0; h <= 20; ++h) push_row(young, h, 5000 + 60 * h, 1 + h);

    checkf(young.base_height() == 0, "rows: a from-genesis store reports base_height %llu",
           static_cast<unsigned long long>(young.base_height()));

    std::vector<DifficultyRow> out;
    checkf(!young.difficulty_window_ending_at(20, DIFFICULTY_BLOCKS_COUNT, out),
           "rows: the young-chain window was granted WITHOUT the opt-in");
    checkf(out.empty(), "rows: a refused window left rows behind");

    checkf(young.difficulty_window_ending_at(20, DIFFICULTY_BLOCKS_COUNT, out,
                                             /*allow_young_chain=*/true),
           "rows: the young-chain window was refused to a store holding height 0");
    checkf(out.size() == 21, "rows: young window has %zu rows, expected 21", out.size());
    checkf(!out.empty() && out.front().timestamp == 5000,
           "rows: young window does not start at height 0");
    checkf(!out.empty() && out.back().timestamp == 5000 + 60 * 20,
           "rows: young window does not end at the height asked for");

    // A store that merely STARTS high: the chain may be long, we just cannot see
    // it, and that refusal has to stay a refusal.
    RowStore high;
    for (std::uint64_t h = 1000; h <= 1010; ++h) push_row(high, h, 9000 + h, 10'000 + h);
    checkf(high.base_height() == 1000, "rows: a trimmed store reports base_height %llu",
           static_cast<unsigned long long>(high.base_height()));
    checkf(!high.difficulty_window_ending_at(1005, DIFFICULTY_BLOCKS_COUNT, out, true),
           "rows: a window was invented for a store that starts above height 0");

    // The pre-windowed (anchored) store: the relaxation must not reach it, and
    // the "do not invent a window past the pre-window" refusal must survive.
    RowStore anchored;
    std::vector<DifficultyRow> pre;
    for (std::uint64_t i = 0; i < DIFFICULTY_BLOCKS_COUNT; ++i)
        pre.push_back(DifficultyRow{5000 + i, u128_of(i, 0)});
    anchored.seed_pre_window(1000, pre);                 // heights 266..1000
    for (std::uint64_t h = 1001; h <= 1010; ++h) push_row(anchored, h, 9000 + h, 10'000 + h);
    checkf(anchored.base_height() == 1000 + 1 - DIFFICULTY_BLOCKS_COUNT,
           "rows: an anchored store reports base_height %llu",
           static_cast<unsigned long long>(anchored.base_height()));
    checkf(anchored.difficulty_window_ending_at(1005, DIFFICULTY_BLOCKS_COUNT, out, true),
           "rows: the anchored window spanning the pre-window was not assembled");
    checkf(out.size() == DIFFICULTY_BLOCKS_COUNT, "rows: anchored window is the wrong length");
    checkf(!anchored.difficulty_window_ending_at(1005, DIFFICULTY_BLOCKS_COUNT + 400, out, true),
           "rows: a window reaching past the pre-window was invented under the opt-in");
}

// =============================================================================
// B. a genesis-booted index follows a heavier branch below its tip
// =============================================================================
static void test_follow_after_race_loss() {
    Rig f(8);
    ChainIndex& idx = *f.idx;

    const std::uint64_t fork_height = 7;
    const Hash          fork_id     = f.main_ids[6];         // height 7
    const Hash          our_tip     = f.main_ids[7];         // height 8, ours

    checkf(f.tip_height() == 8, "follow: the rig did not reach height 8 (at %llu)",
           static_cast<unsigned long long>(f.tip_height()));

    // The rival at the SAME height, from a peer. ts_shift keeps it a distinct
    // block; the difficulty window below the fork is identical, so the work is
    // equal and D-14 keeps ours.
    std::vector<BlockEntry> rival = build_branch(idx, fork_id, fork_height, 2, /*salt_base=*/11);

    const OfferResult r8 = idx.offer_block(&f.them, rival[0], /*own_mined=*/false);
    checkf(r8.outcome == OfferOutcome::StoredAsAlt,
           "follow: the rival at the contested height became %s (%s) -- before the fix this "
           "path DROPPED it and answered ParkedOrphan",
           to_string(r8.outcome), r8.why.c_str());
    checkf(idx.have_block(id_of(rival[0])),
           "follow: the index does not hold the rival it said it stored");
    checkf(idx.alt_size() == 1, "follow: alt pool holds %zu candidates, expected 1",
           idx.alt_size());

    // It was JUDGED, not merely kept: a young chain used to make this
    // impossible, and an unresolved candidate can never win a fork choice.
    const std::vector<ChainIndex::AltTip> tips = idx.alt_tips();
    checkf(tips.size() == 1 && tips[0].resolved,
           "follow: the rival is parked UNRESOLVED -- its branch difficulty was not computable");

    // Equal work: we keep our own block (D-14), and we are still at our tip.
    checkf(f.tip_id() == our_tip, "follow: equal work did not keep our own block");
    checkf(f.log.count(node::MainchainEventKind::Reorg) == 0,
           "follow: an equal-work rival caused a reorg");

    // Monero buries the rival branch: it gets the next block. Now it is
    // strictly heavier, and the node must follow it WITHOUT being restarted --
    // same object, same seeded state, no reload between these two offers.
    const OfferResult r9 = idx.offer_block(&f.them, rival[1], /*own_mined=*/false);
    checkf(r9.outcome == OfferOutcome::Reorged,
           "follow: the heavier branch became %s (%s), expected Reorged",
           to_string(r9.outcome), r9.why.c_str());

    checkf(f.tip_height() == 9, "follow: tip is at %llu after the switch, expected 9",
           static_cast<unsigned long long>(f.tip_height()));
    checkf(f.tip_id() == id_of(rival[1]), "follow: the adopted tip is not the rival branch tip");
    checkf(idx.is_on_best_chain(id_of(rival[0])),
           "follow: the fork-point child of the adopted branch is not on the best chain");

    // Exactly one Reorg, of depth 1, and the block it displaced is Orphaned --
    // which is what the settlement clock reads to refuse crediting it.
    checkf(f.log.count(node::MainchainEventKind::Reorg) == 1,
           "follow: %zu Reorg events, expected 1", f.log.count(node::MainchainEventKind::Reorg));
    for (const auto& e : f.log.events)
        if (e.kind == node::MainchainEventKind::Reorg)
            checkf(e.depth == 1, "follow: Reorg reported depth %llu, expected 1",
                   static_cast<unsigned long long>(e.depth));
    checkf(f.log.count(node::MainchainEventKind::Orphan) == 1,
           "follow: %zu Orphan events, expected 1", f.log.count(node::MainchainEventKind::Orphan));

    checkf(!idx.is_on_best_chain(our_tip), "follow: our displaced block is still best-chain");
    const Burial b = idx.burial_of(our_tip);
    checkf(b.status == BurialStatus::Orphaned,
           "follow: our displaced block reads as %s, expected Orphaned", to_string(b.status));

    // The journal says what happened, once, and it committed.
    checkf(idx.journal().committed() == 1, "follow: the journal committed %llu reorgs, expected 1",
           static_cast<unsigned long long>(idx.journal().committed()));

    // The chain is still a chain: heights 1..9 contiguous, every parent linking.
    for (std::uint64_t h = 2; h <= 9; ++h) {
        const auto cur  = idx.by_height(h);
        const auto prev = idx.by_height(h - 1);
        checkf(cur && prev && cur->prev_id == prev->id,
               "follow: height %llu does not link to its parent after the switch",
               static_cast<unsigned long long>(h));
    }
}

// =============================================================================
// C. bottom-up delivery with a hole -- the walk to the fork point
// =============================================================================
static void test_walk_to_fork() {
    Rig f(8);
    ChainIndex& idx = *f.idx;

    const std::uint64_t fork_height = 5;
    const Hash          fork_id     = f.main_ids[4];    // height 5
    const Hash          our_tip     = f.main_ids[7];    // height 8, ours

    // A branch of five off height 5: heights 6..10, two blocks longer than the
    // three above the fork point, so strictly more work.
    std::vector<BlockEntry> br = build_branch(idx, fork_id, fork_height, 5, /*salt_base=*/21);

    // Deliver it TOP DOWN, which is what a push followed by refetches does: the
    // tip first, then its parent, then its parent...
    const OfferResult top = idx.offer_block(&f.them, br[4], /*own_mined=*/false);
    checkf(top.outcome == OfferOutcome::ParkedOrphan,
           "walk: the pushed branch tip became %s, expected ParkedOrphan", to_string(top.outcome));
    checkf(idx.have_block(id_of(br[4])), "walk: the parked branch tip was not kept");

    // Its parent is named for the fetcher.
    std::vector<Hash> want = idx.refetch_wanted();
    bool names_parent = false;
    for (const Hash& h : want) if (h == id_of(br[3])) names_parent = true;
    checkf(names_parent, "walk: the parked tip's parent is not in refetch_wanted()");

    // And the id we ALREADY hold is not asked for again. This is the loop that
    // made a stuck node look like a slow peer: the want list is standing, so
    // without the filter the driver re-asked for a block sitting in its own alt
    // pool every refetch_reask_ms, forever.
    for (const Hash& h : want)
        checkf(!(h == id_of(br[4])), "walk: refetch_wanted() names a block we are holding");

    // The next one down. Its parent is the block we just parked, which is
    // UNRESOLVED -- "branch difficulty is unknown until the parent resolves".
    // That is the exact return that used to destroy the block: it answered
    // ParkedOrphan and stored nothing.
    const OfferResult mid = idx.offer_block(&f.them, br[3], /*own_mined=*/false);
    checkf(mid.outcome == OfferOutcome::ParkedOrphan,
           "walk: a block above an unresolved parent became %s", to_string(mid.outcome));
    checkf(idx.have_block(id_of(br[3])),
           "walk: a block above an unresolved parent was DROPPED, not parked");

    for (std::size_t i = 3; i-- > 1; ) {
        const OfferResult r = idx.offer_block(&f.them, br[i], /*own_mined=*/false);
        checkf(r.outcome == OfferOutcome::ParkedOrphan,
               "walk: branch block %zu became %s", i, to_string(r.outcome));
        checkf(idx.have_block(id_of(br[i])), "walk: branch block %zu was dropped", i);
    }
    checkf(idx.alt_size() == 4, "walk: alt pool holds %zu of the 4 parked blocks", idx.alt_size());
    checkf(f.tip_id() == our_tip, "walk: the tip moved while the branch was still unjudgeable");

    // Now the fork-point child lands. Its parent IS on the best chain, so it is
    // judgeable; resolving it cascades up the branch and the switch follows in
    // the same call -- no restart, no second delivery of anything.
    const OfferResult bottom = idx.offer_block(&f.them, br[0], /*own_mined=*/false);
    checkf(bottom.outcome == OfferOutcome::Reorged,
           "walk: the fork-point child became %s (%s), expected Reorged",
           to_string(bottom.outcome), bottom.why.c_str());

    checkf(f.tip_height() == 10, "walk: tip is at %llu after the switch, expected 10",
           static_cast<unsigned long long>(f.tip_height()));
    checkf(f.tip_id() == id_of(br[4]), "walk: the adopted tip is not the branch tip");
    for (std::size_t i = 0; i < br.size(); ++i)
        checkf(idx.is_on_best_chain(id_of(br[i])),
               "walk: branch block %zu is not on the best chain after the switch", i);

    checkf(f.log.count(node::MainchainEventKind::Reorg) == 1,
           "walk: %zu Reorg events, expected 1", f.log.count(node::MainchainEventKind::Reorg));
    checkf(f.log.count(node::MainchainEventKind::Orphan) == 3,
           "walk: %zu Orphan events, expected 3 (heights 6,7,8)",
           f.log.count(node::MainchainEventKind::Orphan));
    for (const auto& e : f.log.events)
        if (e.kind == node::MainchainEventKind::Reorg)
            checkf(e.depth == 3, "walk: Reorg reported depth %llu, expected 3",
                   static_cast<unsigned long long>(e.depth));

    // Nothing we now hold on the best chain is still being asked for.
    want = idx.refetch_wanted();
    for (const Hash& h : want)
        for (std::size_t i = 0; i < br.size(); ++i)
            checkf(!(h == id_of(br[i])),
                   "walk: refetch_wanted() still names adopted branch block %zu", i);
}

// =============================================================================
// D. the bounds the relaxation must not move
// =============================================================================
static void test_bounds() {
    // --- deeper than the horizon: refused and journaled ----------------------
    {
        Rig f(8, /*max_reorg=*/2);
        ChainIndex& idx = *f.idx;
        const std::uint64_t fork_height = 4;
        const Hash          fork_id     = f.main_ids[3];
        const Hash          our_tip     = f.main_ids[7];

        std::vector<BlockEntry> br = build_branch(idx, fork_id, fork_height, 6, /*salt_base=*/31);
        for (std::size_t i = 0; i < br.size(); ++i)
            (void)idx.offer_block(&f.them, br[i], /*own_mined=*/false);

        checkf(f.tip_id() == our_tip,
               "bounds: a branch 4 below the tip was adopted with max_reorg_depth 2");
        checkf(f.log.count(node::MainchainEventKind::Reorg) == 0,
               "bounds: a too-deep branch produced a Reorg event");
        checkf(idx.journal().committed() == 0, "bounds: a too-deep branch committed a reorg");
        checkf(idx.journal().refused() > 0,
               "bounds: a too-deep branch was refused SILENTLY -- nothing in the journal");
    }

    // --- equal work against our own block: kept, and the rival is HELD -------
    {
        Rig f(8);
        ChainIndex& idx = *f.idx;
        const Hash our_tip = f.main_ids[7];
        std::vector<BlockEntry> rival =
            build_branch(idx, f.main_ids[6], 7, 1, /*salt_base=*/41, /*ts_shift=*/0);

        const OfferResult r = idx.offer_block(&f.them, rival[0], /*own_mined=*/false);
        checkf(r.outcome == OfferOutcome::StoredAsAlt,
               "bounds: the equal-work rival became %s", to_string(r.outcome));
        checkf(f.tip_id() == our_tip, "bounds: equal work did not keep our own block (D-14)");
        // Held, so the accounting layer can see the race at all: in this branch
        // the rival never becomes a mainchain event.
        const std::vector<ChainIndex::AltTip> tips = idx.alt_tips();
        checkf(tips.size() == 1 && tips[0].height == 8 && !tips[0].own_mined,
               "bounds: the equal-work rival is not visible as an alt tip");
        checkf(f.log.count(node::MainchainEventKind::Reorg) == 0,
               "bounds: equal work produced a reorg");
    }

    // --- a lighter branch never switches -------------------------------------
    {
        Rig f(8);
        ChainIndex& idx = *f.idx;
        const Hash our_tip = f.main_ids[7];
        // Two blocks off height 4: heights 5 and 6, four blocks short of our
        // tip, so strictly less work.
        std::vector<BlockEntry> br = build_branch(idx, f.main_ids[3], 4, 2, /*salt_base=*/51);
        for (std::size_t i = 0; i < br.size(); ++i) {
            const OfferResult r = idx.offer_block(&f.them, br[i], /*own_mined=*/false);
            checkf(r.outcome == OfferOutcome::StoredAsAlt,
                   "bounds: a lighter branch block became %s (%s)",
                   to_string(r.outcome), r.why.c_str());
        }
        checkf(f.tip_id() == our_tip, "bounds: a lighter branch was adopted");
        checkf(f.log.count(node::MainchainEventKind::Reorg) == 0,
               "bounds: a lighter branch produced a reorg");
    }
}

// =============================================================================
// E. the young-chain relaxation does not change what the chain COMPUTES
// =============================================================================
// The branch walk and the apply path must arrive at the same difficulty for the
// same block, or the switch refuses itself ("branch difficulty disagreed with
// the connected difficulty"). On a young chain those two are the relaxed
// RowStore window and the consensus state's own rolling window, so this is the
// check that they hold the same rows.
static void test_branch_and_apply_agree() {
    Rig f(8);
    ChainIndex& idx = *f.idx;

    const ChainRow* before = row_at(idx, 8);
    checkf(before != nullptr, "agree: no row at the tip before the branch arrives");
    const U128 our_tip_cd = before ? before->cumulative_difficulty : U128{};

    std::vector<BlockEntry> br = build_branch(idx, f.main_ids[5], 6, 3, /*salt_base=*/61);
    for (std::size_t i = 0; i < br.size(); ++i)
        (void)idx.offer_block(&f.them, br[i], /*own_mined=*/false);

    checkf(f.tip_height() == 9, "agree: the heavier branch did not become the tip");
    // Had the two windows disagreed, the switch would have rolled itself back
    // and the journal would say ValidationFailed instead of committing.
    checkf(idx.journal().committed() == 1,
           "agree: the branch difficulty disagreed with the connected difficulty");

    const ChainRow* adopted = row_at(idx, 9);
    checkf(adopted != nullptr, "agree: no row at the adopted tip height");
    checkf(adopted && u128_greater(adopted->cumulative_difficulty, our_tip_cd),
           "agree: the adopted tip does not carry strictly more work than the one it replaced");

    // Every row the switch re-applied carries a difficulty the state computed,
    // and the chain's cumulative difficulty is still the running sum of them.
    U128 sum = genesis_row().cumulative_difficulty;
    for (std::uint64_t h = 1; h <= 9; ++h) {
        const ChainRow* row = row_at(idx, h);
        if (!row) { checkf(false, "agree: height %llu missing", (unsigned long long)h); break; }
        sum = u128_add(sum, row->difficulty);
        checkf(u128_eq(sum, row->cumulative_difficulty),
               "agree: cumulative difficulty at height %llu is not the running sum",
               static_cast<unsigned long long>(h));
    }
}

// =============================================================================
int main() {
    test_young_window();
    test_follow_after_race_loss();
    test_walk_to_fork();
    test_bounds();
    test_branch_and_apply_agree();

    std::printf("xmr_native_reorg_follow_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
