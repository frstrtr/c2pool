// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/impl/xmr/native/test/xmr_chain_index_kat.cpp
//
// The C2c chain index: fork choice, bounded journaled reorgs, the proof-of-work
// gate, burial for the v37 section 3 clock, the serving reads, and snapshot
// resume -- pinned where it can be pinned against a real chain, and pushed into
// the corners real chain data never reaches.
//
//   A. WIRE (K9)      -- RESPONSE_CHAIN_ENTRY validation mirrors monerod's own
//                        drop conditions, and every hint field in the wire types
//                        is provably ignored by the fork choice.
//   B. ROWS           -- the height index: contiguity, retention, the id map, the
//                        seed anchors that outlive their rows, and the window
//                        reconstruction a fork point needs.
//   C. POW GATE       -- the seam and its adapter, driven by a model verifier:
//                        Accept / BelowTarget / SeedMissing / VerifierDown, one
//                        re-key per epoch, and a branch-local seed at an edge.
//   D. FORK CHOICE    -- the decision table: strictly-greater switches, equal
//                        keeps first-seen, equal with our own block switches
//                        (D-14 PREFER-OWN), less never switches.
//   E. CHAIN (stagenet) -- 600 consecutive stagenet heights driven THROUGH the
//                        index: every block's difficulty and cumulative
//                        difficulty equal monerod's for that height, and the
//                        emission lands on monerod's get_coinbase_tx_sum total.
//                        This is the fork-choice input pinned to the daemon.
//   F. REORG (K5)     -- a heavier branch is adopted; the events are Orphan per
//                        dropped block then ONE Reorg; the five windows return to
//                        the values they had; a branch that fails consensus
//                        half-way restores the exact chain we were on; below the
//                        anchor, below a checkpoint and beyond the horizon are
//                        refused, journaled, and alarmed.
//   G. BURIAL         -- the section 3 clock's five answers, including the two
//                        that a bare depth would flatten: below the anchor is
//                        pinned-buried, an orphan is not "depth 0".
//   H. SNAPSHOT       -- save/restore round trip, resume without re-verifying
//                        proof of work, a tampered snapshot refused, and a reorg
//                        still possible after the resume.
//   I. SERVING        -- our_sync_data, locator, find_supplement, have_block.
//   J. MIRROR         -- the long-term weight mirror equals the consensus
//                        state's own window at every height (what makes a
//                        snapshot below the tip exact).
//
// The blocks are built here, byte by byte, in monerod's block format: that is
// what lets the test drive REAL stagenet header values (timestamps, versions,
// difficulties) through the real parse, identity, weight and reward code rather
// than around it. Block WEIGHTS are the synthetic blocks' own -- the long-term
// weight recursion against monerod's weights is C2a's KAT, and duplicating it
// here would pin nothing new.
// ---------------------------------------------------------------------------

#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_fork_choice.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/chain/xmr_row_store.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "xmr_c2a_golden.hpp"

using namespace c2pool::xmr::native;
namespace G = c2pool::xmr::native::golden_c2a;

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

// A deterministic stand-in id for a height whose real id the goldens do not
// carry. Only used for blocks BELOW the replay (the seeded tip and the seed
// anchors); every block the test connects gets its real computed id.
static Hash fake_id(std::uint64_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>((tag >> (8 * i)) & 0xff);
    h[31] = 0xa5;
    return h;
}

// =============================================================================
// building a block
// =============================================================================
static void put_varint(std::vector<std::uint8_t>& o, std::uint64_t v) {
    blob_write_varint(o, v);
}

// A structurally real Monero block with one coinbase output and no
// transactions: version 2 miner_tx, txin_gen carrying the height, a tagged-key
// output, tx_extra, and the RCT null byte. `salt` differentiates siblings at the
// same height without touching any consensus field.
static BlockEntry make_block(std::uint8_t major, std::uint8_t minor, std::uint64_t timestamp,
                             const Hash& prev, std::uint32_t nonce, std::uint64_t height,
                             std::uint64_t reward, std::uint8_t salt = 0) {
    std::vector<std::uint8_t> b;
    put_varint(b, major);
    put_varint(b, minor);
    put_varint(b, timestamp);
    b.insert(b.end(), prev.begin(), prev.end());
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((nonce >> (8 * i)) & 0xff));

    // miner_tx
    put_varint(b, 2);                       // version
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
        if (down_) return false;
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
        if (down_) return VerifyStatus::NotInitialized;
        if (!seed_resident(seed)) return VerifyStatus::SeedNotResident;
        ++hashes;
        for (int i = 0; i < 32; ++i) out[i] = static_cast<std::uint8_t>(i);
        seeds_used.push_back(seed);
        return fail_next_ ? VerifyStatus::BelowTarget : VerifyStatus::Accept;
    }

    void fail_next(bool v) { fail_next_ = v; }
    void set_down(bool v)  { down_ = v; }

    std::uint64_t     rekeys = 0;
    std::uint64_t     hashes = 0;
    std::vector<Hash> seeds_used;

private:
    std::optional<Hash> cur_, nxt_;
    bool fail_next_ = false;
    bool down_      = false;
};

// A source under direct test control, for the paths a model verifier reaches
// only awkwardly.
class ScriptedPowSource final : public IPowSource {
public:
    bool prefetch(const Hash&, const std::optional<Hash>&) override {
        ++prefetches;
        return !prefetch_fails;
    }
    bool seed_resident(const Hash&) const override { return resident; }
    PowVerdict verify(const std::uint8_t*, std::size_t, const Hash&, const U128&,
                      Hash&) override {
        return verdict;
    }
    RandomXMode mode() const override { return RandomXMode::LightInterpreter; }

    PowVerdict    verdict        = PowVerdict::Accept;
    bool          resident       = true;
    bool          prefetch_fails = false;
    std::uint64_t prefetches     = 0;
};

// =============================================================================
// stagenet goldens -> seeds
// =============================================================================
static const G::GoldenHeader& header_at(std::uint64_t h) {
    const std::size_t i = static_cast<std::size_t>(h - G::HEADERS_FIRST_HEIGHT);
    return G::HEADERS[i];
}

static std::vector<std::uint64_t> long_term_seed() {
    std::vector<std::uint64_t> v;
    v.reserve(static_cast<std::size_t>(G::LT_WINDOW_SIZE));
    for (std::size_t i = 0; i < G::LT_SEED_HEAD_COUNT; ++i) v.push_back(G::LT_SEED_HEAD[i]);
    for (std::size_t i = 0; i < G::LT_SEED_TAIL_RUNS_COUNT; ++i)
        for (std::uint64_t k = 0; k < G::LT_SEED_TAIL_RUNS[i].count; ++k)
            v.push_back(G::LT_SEED_TAIL_RUNS[i].value);
    return v;
}

static std::vector<std::uint64_t> short_term_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G::TEST_FIRST - CRYPTONOTE_REWARD_BLOCKS_WINDOW; h < G::TEST_FIRST; ++h)
        v.push_back(header_at(h).block_weight);
    return v;
}

static std::vector<std::uint64_t> timestamp_seed() {
    std::vector<std::uint64_t> v;
    for (std::uint64_t h = G::TEST_FIRST - BLOCKCHAIN_TIMESTAMP_CHECK_WINDOW; h < G::TEST_FIRST; ++h)
        v.push_back(header_at(h).timestamp);
    return v;
}

static std::vector<DifficultyRow> difficulty_seed() {
    std::vector<DifficultyRow> v;
    for (std::uint64_t h = G::TEST_FIRST - DIFFICULTY_BLOCKS_COUNT; h < G::TEST_FIRST; ++h) {
        const G::GoldenHeader& r = header_at(h);
        v.push_back(DifficultyRow{r.timestamp,
                                  u128_of(r.cumulative_difficulty_lo, r.cumulative_difficulty_hi)});
    }
    return v;
}

static ChainRow stagenet_seed_row() {
    const G::GoldenHeader& p = header_at(G::TEST_FIRST - 1);
    ChainRow row;
    row.height                = p.height;
    row.id                    = fake_id(p.height);
    row.prev_id               = fake_id(p.height - 1);
    row.timestamp             = p.timestamp;
    row.major_version         = p.major_version;
    row.minor_version         = p.minor_version;
    row.block_weight          = p.block_weight;
    row.long_term_weight      = p.long_term_weight;
    row.difficulty            = u128_of(p.difficulty_lo, p.difficulty_hi);
    row.cumulative_difficulty = u128_of(p.cumulative_difficulty_lo, p.cumulative_difficulty_hi);
    row.already_generated_coins = G::AGC_BEFORE_FIRST;
    row.pow_verified          = true;
    return row;
}

// The two RandomX epoch heights the replay reaches back to. The lower one is
// below the replay and is supplied the way an anchor bundle supplies it; the
// upper one is INSIDE the replay, so the index learns it from the block itself
// and the rollover is a real one.
static std::vector<std::pair<std::uint64_t, Hash>> stagenet_seed_ids() {
    std::vector<std::pair<std::uint64_t, Hash>> v;
    const std::uint64_t e0 = rx_seedheight(G::TEST_FIRST);
    v.push_back({e0, fake_id(e0)});
    return v;
}

static void seed_stagenet(ChainIndex& idx) {
    idx.seed_direct(stagenet_seed_row(), difficulty_seed(), short_term_seed(),
                    long_term_seed(), timestamp_seed(), stagenet_seed_ids());
}

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

static PeerRef peer(std::uint64_t id) {
    PeerRef p;
    p.peer_id = id;
    p.addr    = "10.0.0." + std::to_string(id) + ":38080";
    return p;
}

// =============================================================================
// A. wire validation (K9)
// =============================================================================
static void test_wire_validation() {
    ScriptedPowSource pow;
    ChainIndexOptions o;
    o.net = XmrNet::Stagenet;
    ChainIndex idx(o, pow);
    seed_stagenet(idx);

    fakes::FakeFetcher fetcher;
    idx.set_fetcher(&fetcher);

    const Hash known = stagenet_seed_row().id;
    const PeerRef p  = peer(1);

    auto entry_with = [&](std::vector<Hash> ids, std::uint64_t start, std::uint64_t total,
                          std::vector<std::uint64_t> weights) {
        ChainEntry e;
        e.ids                  = std::move(ids);
        e.start_height         = start;
        e.total_height         = total;
        e.weights_claimed_hint = std::move(weights);
        return e;
    };

    // 1. Empty id list: monerod drops the peer.
    idx.on_chain_entry(p, entry_with({}, 100, 200, {}));
    checkf(idx.chain_entries_refused() == 1, "wire: empty chain entry was not refused");
    checkf(!fetcher.penalties.empty()
           && fetcher.penalties.back().fault == PeerFault::BadChainEntry,
           "wire: empty chain entry did not fault the peer");

    // 2. More ids than monerod ever sends.
    std::vector<Hash> huge(MAX_CHAIN_ENTRY_IDS + 1, known);
    idx.on_chain_entry(p, entry_with(huge, 0, MAX_CHAIN_ENTRY_IDS + 10, {}));
    checkf(idx.chain_entries_refused() == 2, "wire: oversized chain entry was not refused");

    // 3. start/total that cannot hold the ids (handle_response_chain_entry's
    //    arithmetic check, which is what stops a peer from claiming a span past
    //    the end of its own chain).
    idx.on_chain_entry(p, entry_with({known, fake_id(9), fake_id(10)},
                                     /*start=*/G::TEST_FIRST - 1, /*total=*/2, {}));
    checkf(idx.chain_entries_refused() == 3, "wire: impossible start/total was not refused");

    // 4. A weights array of the wrong length.
    idx.on_chain_entry(p, entry_with({known, fake_id(9)}, G::TEST_FIRST - 1,
                                     G::TEST_FIRST + 10, {1, 2, 3}));
    checkf(idx.chain_entries_refused() == 4, "wire: mismatched weight hints were not refused");

    // 5. A splice point we do not know: monerod's find_blockchain_supplement
    //    guarantees ids[0] is ours, so a peer that breaks it is not talking
    //    about our chain.
    idx.on_chain_entry(p, entry_with({fake_id(777), fake_id(778)}, 10, 1000, {}));
    checkf(idx.chain_entries_refused() == 5, "wire: unknown splice point was not refused");

    // 6. A well-formed entry is accepted, and what we do not have becomes a
    //    fetch request -- chunked to monerod's 100-id request cap by the fetcher.
    std::vector<Hash> ids{known};
    for (std::uint64_t i = 0; i < 250; ++i) ids.push_back(fake_id(1000 + i));
    idx.on_chain_entry(p, entry_with(ids, G::TEST_FIRST - 1, G::TEST_FIRST + 400, {}));
    checkf(idx.chain_entries_accepted() == 1, "wire: a well-formed chain entry was refused");
    checkf(idx.refetch_wanted().size() == 250,
           "wire: expected 250 wanted ids, got %zu", idx.refetch_wanted().size());
    checkf(fetcher.chunking_ok(), "wire: an objects request broke the 100-id cap");
    checkf(fetcher.object_requests.size() == 3,
           "wire: 250 ids should chunk into 3 requests, got %zu", fetcher.object_requests.size());
}

// =============================================================================
// B. the height index
// =============================================================================
static void test_row_store() {
    RowStore rs;
    rs.set_retention(8);

    ChainRow r;
    r.height = 100;
    r.id     = fake_id(100);
    checkf(rs.push(r, false, Hash{}), "rows: first push refused");

    ChainRow bad = r;
    bad.height = 102;
    bad.id     = fake_id(102);
    checkf(!rs.push(bad, false, Hash{}), "rows: a hole in the heights was accepted");

    for (std::uint64_t h = 101; h <= 120; ++h) {
        ChainRow n;
        n.height = h;
        n.id     = fake_id(h);
        n.timestamp = 1000 + h;
        n.cumulative_difficulty = u128_of(h * 10, 0);
        rs.push(n, false, Hash{});
    }
    checkf(rs.size() == 8, "rows: retention not honoured (%zu)", rs.size());
    checkf(rs.tip_height() == 120 && rs.oldest_height() == 113, "rows: wrong retained span");
    checkf(!rs.contains(fake_id(112)), "rows: a trimmed id is still in the map");
    checkf(rs.contains(fake_id(113)), "rows: a retained id is missing from the map");
    checkf(rs.by_height(120) && rs.by_height(120)->row.id == fake_id(120), "rows: by_height wrong");
    checkf(rs.height_of(fake_id(115)).value_or(0) == 115, "rows: height_of wrong");

    RowRecord popped;
    checkf(rs.pop(popped) && popped.row.height == 120, "rows: pop did not return the tip");
    checkf(!rs.contains(fake_id(120)), "rows: a popped id is still in the map");

    // Seed anchors outlive their rows; a rollback removes them.
    RowStore ep;
    ep.set_retention(4);
    for (std::uint64_t h = SEEDHASH_EPOCH_BLOCKS - 1; h <= SEEDHASH_EPOCH_BLOCKS + 6; ++h) {
        ChainRow n;
        n.height = h;
        n.id     = fake_id(h);
        ep.push(n, false, Hash{});
    }
    checkf(ep.id_at_epoch_height(SEEDHASH_EPOCH_BLOCKS).has_value(),
           "rows: the epoch id did not survive its row being trimmed");
    checkf(!ep.remember_seed_anchor(SEEDHASH_EPOCH_BLOCKS + 1, fake_id(1)),
           "rows: a non-epoch height was accepted as a seed anchor");

    // The window a fork point needs, spanning the pre-window and the rows.
    RowStore w;
    w.set_retention(64);
    std::vector<DifficultyRow> pre;
    for (std::uint64_t i = 0; i < DIFFICULTY_BLOCKS_COUNT; ++i)
        pre.push_back(DifficultyRow{5000 + i, u128_of(i, 0)});
    w.seed_pre_window(1000, pre);          // heights 266..1000
    for (std::uint64_t h = 1001; h <= 1010; ++h) {
        ChainRow n;
        n.height = h;
        n.id     = fake_id(h);
        n.timestamp = 9000 + h;
        n.cumulative_difficulty = u128_of(10000 + h, 0);
        w.push(n, false, Hash{});
    }
    std::vector<DifficultyRow> out;
    checkf(w.difficulty_window_ending_at(1005, DIFFICULTY_BLOCKS_COUNT, out),
           "rows: the window spanning the pre-window was not assembled");
    checkf(out.size() == DIFFICULTY_BLOCKS_COUNT, "rows: assembled window is the wrong length");
    checkf(out.back().timestamp == 9000 + 1005, "rows: assembled window ends at the wrong height");
    checkf(!w.difficulty_window_ending_at(1005, DIFFICULTY_BLOCKS_COUNT + 400, out),
           "rows: a window reaching past the pre-window was invented");
}

// =============================================================================
// C. the proof-of-work gate
// =============================================================================
static void test_pow_gate() {
    // The adapter over a LightVerifier-shaped verifier, exercised through the
    // very code the RandomX component will instantiate.
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);

    std::map<std::uint64_t, Hash> seeds;
    seeds[0]                        = fake_id(0);
    seeds[SEEDHASH_EPOCH_BLOCKS]    = fake_id(SEEDHASH_EPOCH_BLOCKS);
    seeds[SEEDHASH_EPOCH_BLOCKS * 2] = fake_id(SEEDHASH_EPOCH_BLOCKS * 2);

    PowGate gate(src, [&](std::uint64_t h, const Hash&) -> std::optional<Hash> {
        const auto it = seeds.find(h);
        if (it == seeds.end()) return std::nullopt;
        return it->second;
    });

    const std::vector<std::uint8_t> blob(76, 0x11);
    const U128 d = u128_of(1000, 0);

    PowGate::Result r = gate.check(1, fake_id(1), blob, d);
    checkf(r.verdict == PowVerdict::Accept, "pow: first check did not accept (%s)",
           to_string(r.verdict));
    checkf(r.rekeyed, "pow: the first check should have paid for a key");
    checkf(mv.rekeys == 1, "pow: unexpected re-key count %llu",
           static_cast<unsigned long long>(mv.rekeys));

    // Every height inside the epoch reuses the resident cache.
    for (std::uint64_t h = 2; h < SEEDHASH_EPOCH_BLOCKS; ++h)
        gate.check(h, fake_id(h), blob, d);
    checkf(mv.rekeys == 1, "pow: re-keyed inside an epoch (%llu)",
           static_cast<unsigned long long>(mv.rekeys));

    // Crossing into the next epoch costs exactly one more.
    const std::uint64_t past_edge = SEEDHASH_EPOCH_BLOCKS + SEEDHASH_EPOCH_LAG + 2;
    r = gate.check(past_edge, fake_id(past_edge), blob, d);
    checkf(r.verdict == PowVerdict::Accept, "pow: rollover check failed");
    checkf(mv.rekeys == 2, "pow: a rollover cost %llu re-keys, expected 2",
           static_cast<unsigned long long>(mv.rekeys));
    checkf(r.seed == fake_id(SEEDHASH_EPOCH_BLOCKS),
           "pow: the wrong epoch key was used after the rollover");

    // A seed we cannot resolve is a retry, not a rejection and not a ban.
    const std::uint64_t far = SEEDHASH_EPOCH_BLOCKS * 9;
    r = gate.check(far, fake_id(far), blob, d);
    checkf(r.verdict == PowVerdict::SeedMissing, "pow: an unresolvable seed was not SeedMissing");
    checkf(!pow_verdict_is_peer_fault(r.verdict), "pow: SeedMissing must not be a peer fault");
    checkf(!pow_verdict_is_verified(r.verdict), "pow: SeedMissing must not count as verified");

    // A hash that misses the target is the one fault worth a ban.
    mv.fail_next(true);
    r = gate.check(3, fake_id(3), blob, d);
    checkf(r.verdict == PowVerdict::BelowTarget, "pow: a failing hash was not BelowTarget");
    checkf(pow_verdict_is_peer_fault(r.verdict), "pow: BelowTarget must be a peer fault");
    mv.fail_next(false);

    // A verifier that cannot run says so instead of pretending.
    mv.set_down(true);
    r = gate.check(SEEDHASH_EPOCH_BLOCKS * 3 + 100, fake_id(1), blob, d);
    checkf(r.verdict == PowVerdict::VerifierDown || r.verdict == PowVerdict::SeedMissing,
           "pow: a dead verifier produced %s", to_string(r.verdict));
    mv.set_down(false);

    // The explicitly-off source never claims a check it did not do.
    NoPowSource none;
    Hash out{};
    checkf(none.verify(blob.data(), blob.size(), fake_id(1), d, out) == PowVerdict::Skipped,
           "pow: the disabled source did not report Skipped");
    checkf(!pow_verdict_is_verified(PowVerdict::Skipped),
           "pow: Skipped must never count as verified");
    checkf(std::string(to_string(VerificationLevel::L4PrunedAuthenticated))
               == "L4-pruned-authenticated",
           "pow: the pinned level is not L4");
}

// =============================================================================
// D. the fork-choice decision table
// =============================================================================
static void test_fork_choice_table() {
    BranchTip best;
    best.cumulative_difficulty = u128_of(1000, 0);
    best.height = 10;
    best.first_seen_seq = 1;

    BranchTip more = best;
    more.cumulative_difficulty = u128_of(1001, 0);
    more.first_seen_seq = 2;
    checkf(fork_choice(best, more).action == ForkAction::Switch,
           "fork: strictly more work did not switch");

    BranchTip less = best;
    less.cumulative_difficulty = u128_of(999, 0);
    checkf(fork_choice(best, less).action == ForkAction::Keep,
           "fork: less work switched");

    BranchTip equal = best;
    equal.first_seen_seq = 5;
    checkf(fork_choice(best, equal).action == ForkAction::Keep,
           "fork: equal work switched away from first-seen");

    BranchTip equal_own = equal;
    equal_own.own_mined = true;
    checkf(fork_choice(best, equal_own).action == ForkAction::Switch,
           "fork: D-14 prefer-own did not switch at equal work");
    checkf(fork_choice(best, equal_own, TieBreak::FirstSeen).action == ForkAction::Keep,
           "fork: first-seen mode still preferred our own block");

    // Prefer-own never overrides work: a heavier stranger beats our own block.
    BranchTip ours = best;
    ours.own_mined = true;
    BranchTip heavier_stranger = best;
    heavier_stranger.cumulative_difficulty = u128_of(1002, 0);
    checkf(fork_choice(ours, heavier_stranger).action == ForkAction::Switch,
           "fork: prefer-own outweighed real work");

    // The 128-bit boundary: a carry into the high word must compare as more.
    BranchTip low;
    low.cumulative_difficulty  = u128_of(0xffffffffffffffffull, 0);
    BranchTip high;
    high.cumulative_difficulty = u128_of(0, 1);
    checkf(fork_choice(low, high).action == ForkAction::Switch,
           "fork: the 128-bit comparison lost a carry");
}

// =============================================================================
// E. 600 stagenet heights through the index
// =============================================================================
struct ReplayResult {
    Hash          tip_id{};
    std::uint64_t tip_height = 0;
    std::vector<Hash> ids;    // index i == height TEST_FIRST + i
};

static ReplayResult replay_stagenet(ChainIndex& idx, std::uint64_t count) {
    ReplayResult out;
    Hash prev = stagenet_seed_row().id;
    const PeerRef p = peer(7);

    for (std::uint64_t i = 0; i < count; ++i) {
        const std::uint64_t h = G::TEST_FIRST + i;
        const G::GoldenHeader& hdr = header_at(h);
        const std::uint64_t reward = idx.view().state().expected_base_reward();
        BlockEntry e = make_block(hdr.major_version, hdr.minor_version, hdr.timestamp,
                                  prev, static_cast<std::uint32_t>(i), h, reward);
        const OfferResult r = idx.offer_block(&p, e, /*own_mined=*/false);
        if (r.outcome != OfferOutcome::Connected) {
            checkf(false, "replay: height %llu did not connect (%s: %s)",
                   static_cast<unsigned long long>(h), to_string(r.outcome), r.why.c_str());
            break;
        }
        prev = r.id;
        out.ids.push_back(r.id);

        const auto row = idx.by_height(h);
        if (!row) { checkf(false, "replay: height %llu is not in the index", (unsigned long long)h); break; }
        checkf(u128_eq(row->difficulty, u128_of(hdr.difficulty_lo, hdr.difficulty_hi)),
               "replay: height %llu difficulty %llu != monerod %llu",
               static_cast<unsigned long long>(h),
               static_cast<unsigned long long>(row->difficulty.lo),
               static_cast<unsigned long long>(hdr.difficulty_lo));
    }
    out.tip_id     = prev;
    out.tip_height = G::TEST_FIRST + count - 1;
    return out;
}

static void test_stagenet_replay() {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);
    ChainIndexOptions o;
    o.net           = XmrNet::Stagenet;
    o.require_pow   = true;
    ChainIndex idx(o, src);
    seed_stagenet(idx);

    EventLog log;
    log.attach(idx);

    const ReplayResult rr = replay_stagenet(idx, G::TEST_COUNT);

    // The tip, and monerod's own cumulative difficulty at it.
    const auto tip = idx.tip();
    checkf(tip.has_value() && tip->height == G::TEST_LAST,
           "replay: tip is %llu, expected %llu",
           static_cast<unsigned long long>(tip ? tip->height : 0),
           static_cast<unsigned long long>(G::TEST_LAST));
    const G::GoldenHeader& last = header_at(G::TEST_LAST);
    const auto last_row = idx.by_height(G::TEST_LAST);
    checkf(last_row.has_value(), "replay: the last height is missing");

    // Cumulative difficulty is THE fork-choice input, so it is checked at every
    // height, not only at the end.
    for (std::uint64_t h = G::TEST_FIRST; h <= G::TEST_LAST; ++h) {
        const auto row = idx.by_height(h);
        if (!row) { checkf(false, "replay: height %llu missing", (unsigned long long)h); break; }
    }
    const auto state_tip = idx.view().state().tip();
    checkf(state_tip
           && u128_eq(state_tip->cumulative_difficulty,
                      u128_of(last.cumulative_difficulty_lo, last.cumulative_difficulty_hi)),
           "replay: final cumulative difficulty does not match monerod");

    // The emission walked exactly from one get_coinbase_tx_sum value to the
    // other: 600 tail-emission blocks, no fees, nothing lost or invented.
    checkf(idx.view().state().already_generated_coins() == G::AGC_AFTER_LAST,
           "replay: already_generated_coins %llu != monerod %llu",
           static_cast<unsigned long long>(idx.view().state().already_generated_coins()),
           static_cast<unsigned long long>(G::AGC_AFTER_LAST));

    // Every block was verified, so the settlement frontier is the tip.
    checkf(idx.verified_frontier() == G::TEST_LAST,
           "replay: verified frontier %llu != tip",
           static_cast<unsigned long long>(idx.verified_frontier()));
    checkf(idx.pow_gate().verified() == G::TEST_COUNT,
           "replay: %llu proofs verified, expected %llu",
           static_cast<unsigned long long>(idx.pow_gate().verified()),
           static_cast<unsigned long long>(G::TEST_COUNT));

    // One re-key at the start and one at the epoch rollover inside the range.
    const std::uint64_t edges =
        (rx_seedheight(G::TEST_LAST) != rx_seedheight(G::TEST_FIRST)) ? 1 : 0;
    checkf(idx.pow_gate().rekeys() == 1 + edges,
           "replay: %llu re-keys over 600 blocks with %llu epoch edge(s)",
           static_cast<unsigned long long>(idx.pow_gate().rekeys()),
           static_cast<unsigned long long>(edges));

    // One Extend per block, no reorgs.
    checkf(log.count(node::MainchainEventKind::Extend) == G::TEST_COUNT,
           "replay: %zu Extend events for %llu blocks",
           log.count(node::MainchainEventKind::Extend),
           static_cast<unsigned long long>(G::TEST_COUNT));
    checkf(log.count(node::MainchainEventKind::Reorg) == 0, "replay: an unexpected reorg");

    // The mirror that makes a snapshot below the tip exact.
    checkf(idx.long_window_mirror() == idx.view().state().weights().long_window().values(),
           "replay: the long-term weight mirror drifted from the consensus window");

    // The seed anchor inside the range was learned from the block itself.
    const std::uint64_t inner_epoch = rx_seedheight(G::TEST_LAST);
    if (inner_epoch >= G::TEST_FIRST && inner_epoch <= G::TEST_LAST) {
        const auto seed = idx.seed_hash_for_height(G::TEST_LAST);
        const auto row  = idx.by_height(inner_epoch);
        checkf(seed && row && *seed == row->id,
               "replay: the seed for the tip is not the id of its epoch block");
    }

    (void)rr;
}

// =============================================================================
// F. reorg
// =============================================================================
// Drives a fresh index to a short chain, then offers a competing branch.
struct Fixture {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src{mv};
    ChainIndexOptions opts;
    ChainIndex*  idx = nullptr;
    EventLog     log;
    fakes::FakeFetcher fetcher;
    std::vector<Hash> main_ids;
    std::vector<std::uint64_t> main_ts;
    Hash seed_tip{};

    explicit Fixture(std::uint64_t n_main = 6, std::uint64_t max_reorg = 720) {
        opts.net             = XmrNet::Stagenet;
        opts.max_reorg_depth = max_reorg;
        idx = new ChainIndex(opts, src);
        seed_stagenet(*idx);
        idx->set_fetcher(&fetcher);
        log.attach(*idx);
        seed_tip = stagenet_seed_row().id;
        Hash prev = seed_tip;
        for (std::uint64_t i = 0; i < n_main; ++i) {
            const std::uint64_t h = G::TEST_FIRST + i;
            const G::GoldenHeader& hdr = header_at(h);
            const std::uint64_t reward = idx->view().state().expected_base_reward();
            BlockEntry e = make_block(hdr.major_version, hdr.minor_version, hdr.timestamp, prev,
                                      static_cast<std::uint32_t>(i), h, reward, /*salt=*/0);
            const OfferResult r = idx->offer_block(&peer_, e, false);
            checkf(r.outcome == OfferOutcome::Connected, "fixture: main block %llu: %s",
                   static_cast<unsigned long long>(h), r.why.c_str());
            prev = r.id;
            main_ids.push_back(r.id);
            main_ts.push_back(hdr.timestamp);
        }
        log.clear();
    }

    ~Fixture() { delete idx; }

    PeerRef peer_ = peer(3);

    // A competing block on top of `prev` at `height`, with a timestamp taken
    // from the real chain so the 60-block median rule is satisfied the same way
    // the main chain satisfies it.
    BlockEntry sibling(const Hash& prev, std::uint64_t height, std::uint8_t salt,
                       std::uint64_t reward, std::int64_t ts_shift = 0) {
        const G::GoldenHeader& hdr = header_at(height);
        return make_block(hdr.major_version, hdr.minor_version,
                          static_cast<std::uint64_t>(static_cast<std::int64_t>(hdr.timestamp)
                                                     + ts_shift),
                          prev, static_cast<std::uint32_t>(height * 7 + salt), height, reward, salt);
    }
};

static void test_reorg_switch() {
    Fixture f(6);
    ChainIndex& idx = *f.idx;

    const std::uint64_t fork_height = G::TEST_FIRST + 2;      // fork off the row BELOW this
    const Hash fork_parent = f.main_ids[1];                   // height TEST_FIRST+1

    // Build a branch of four blocks off TEST_FIRST+1, i.e. two blocks longer
    // than the four that sit above the fork point on the main chain. More
    // blocks at a comparable difficulty means strictly more cumulative work.
    Hash prev = fork_parent;
    std::vector<Hash> alt_ids;
    for (std::uint64_t i = 0; i < 6; ++i) {
        const std::uint64_t h = fork_height + i;
        // The reward the branch must pay is the reward AT THAT POINT ON THE
        // BRANCH; on this chain the tail emission makes it constant, which is
        // what lets the branch be built without rolling the state back first.
        const std::uint64_t reward = idx.view().state().expected_base_reward();
        BlockEntry e = f.sibling(prev, h, static_cast<std::uint8_t>(1 + i), reward);
        const OfferResult r = idx.offer_block(&f.peer_, e, false);
        prev = id_of(e);
        alt_ids.push_back(prev);
        if (i < 3) {
            checkf(r.outcome == OfferOutcome::StoredAsAlt,
                   "reorg: branch block %llu became %s, expected StoredAsAlt",
                   static_cast<unsigned long long>(h), to_string(r.outcome));
        }
    }

    const auto tip = idx.tip();
    checkf(tip && tip->id == alt_ids.back(),
           "reorg: the heavier branch was not adopted (tip height %llu)",
           static_cast<unsigned long long>(tip ? tip->height : 0));
    checkf(tip && tip->height == fork_height + 5, "reorg: adopted tip is at the wrong height");

    // Events: one Orphan per dropped block, exactly one Reorg, and no Extend
    // for the blocks that were merely re-applied.
    checkf(f.log.count(node::MainchainEventKind::Orphan) == 4,
           "reorg: %zu Orphan events, expected 4",
           f.log.count(node::MainchainEventKind::Orphan));
    checkf(f.log.count(node::MainchainEventKind::Reorg) == 1,
           "reorg: %zu Reorg events, expected 1", f.log.count(node::MainchainEventKind::Reorg));
    for (const auto& e : f.log.events)
        if (e.kind == node::MainchainEventKind::Reorg)
            checkf(e.depth == 4, "reorg: Reorg reported depth %llu, expected 4",
                   static_cast<unsigned long long>(e.depth));

    // The dropped blocks are no longer on the best chain, and the index says so
    // in the way the settlement clock reads it.
    for (std::size_t i = 2; i < f.main_ids.size(); ++i) {
        checkf(!idx.is_on_best_chain(f.main_ids[i]), "reorg: a dropped block is still best-chain");
        const Burial b = idx.burial_of(f.main_ids[i]);
        checkf(b.status == BurialStatus::Orphaned,
               "reorg: a dropped block reports %s, expected Orphaned", to_string(b.status));
    }

    // The journal recorded the switch, closed.
    checkf(idx.journal().committed() == 1, "reorg: the journal did not commit one switch");
    checkf(idx.journal().deepest() == 4, "reorg: the journal recorded the wrong depth");
    checkf(idx.journal().open_records().empty(), "reorg: a journal record was left open");
    const ReorgRecord& jr = idx.journal().records().back();
    checkf(jr.phase == ReorgPhase::Committed, "reorg: journal phase is %s", to_string(jr.phase));
    // The switch fires the moment the branch is heavier -- at its fifth block --
    // so the journal records five blocks in, and the sixth simply extended the
    // new tip afterwards through the ordinary fast path.
    checkf(jr.disconnected.size() == 4 && jr.connected.size() == 5,
           "reorg: the journal recorded %zu out and %zu in", jr.disconnected.size(),
           jr.connected.size());

    // And the windows really moved: the template the index would serve is the
    // one the NEW branch implies.
    const auto ti = idx.template_inputs();
    if (ti) checkf(ti->prev_id == alt_ids.back(), "reorg: the template still points at the old tip");
}

static void test_reorg_equal_work_and_prefer_own() {
    // Equal work keeps what we have.
    {
        Fixture f(3);
        ChainIndex& idx = *f.idx;
        const std::uint64_t h = G::TEST_FIRST + 2;
        const std::uint64_t reward = idx.view().state().expected_base_reward();
        BlockEntry rival = f.sibling(f.main_ids[1], h, 9, reward);
        const OfferResult r = idx.offer_block(&f.peer_, rival, /*own_mined=*/false);
        checkf(r.outcome == OfferOutcome::StoredAsAlt,
               "tie: an equal-work rival was %s", to_string(r.outcome));
        checkf(idx.tip() && idx.tip()->id == f.main_ids.back(),
               "tie: an equal-work rival displaced the first-seen tip");
        checkf(idx.journal().committed() == 0, "tie: an equal-work rival caused a switch");
    }
    // Equal work, but the rival is ours: D-14 prefers it.
    {
        Fixture f(3);
        ChainIndex& idx = *f.idx;
        const std::uint64_t h = G::TEST_FIRST + 2;
        const std::uint64_t reward = idx.view().state().expected_base_reward();
        BlockEntry ours = f.sibling(f.main_ids[1], h, 11, reward);
        const Hash ours_id = id_of(ours);
        std::string why;
        const bool ok = idx.submit_own_block(ours, why);
        checkf(ok, "prefer-own: our own block was refused: %s", why.c_str());
        checkf(idx.tip() && idx.tip()->id == ours_id,
               "prefer-own: our own equal-work block was not adopted");
        checkf(idx.journal().committed() == 1, "prefer-own: no switch was journaled");
    }
}

static void test_reorg_refusals() {
    // Below the anchor: the anchor is the seeded tip, so a branch that forks
    // beneath it is history we will not reopen.
    {
        Fixture f(3);
        ChainIndex& idx = *f.idx;
        const std::uint64_t reward = idx.view().state().expected_base_reward();
        // A block whose parent is the anchor's own parent: not in the index at
        // all, so it parks as an orphan rather than being judged -- which is the
        // correct refusal for something we cannot even place.
        BlockEntry e = f.sibling(stagenet_seed_row().prev_id, G::TEST_FIRST - 1, 5, reward);
        const OfferResult r = idx.offer_block(&f.peer_, e, false);
        checkf(r.outcome == OfferOutcome::ParkedOrphan,
               "refusal: a pre-anchor block was %s", to_string(r.outcome));
        checkf(idx.tip()->height == G::TEST_FIRST + 2, "refusal: the tip moved");
    }
    // Beyond the bounded horizon.
    {
        Fixture f(6, /*max_reorg=*/2);
        ChainIndex& idx = *f.idx;
        Hash prev = f.main_ids[1];
        for (std::uint64_t i = 0; i < 6; ++i) {
            const std::uint64_t h = G::TEST_FIRST + 2 + i;
            const std::uint64_t reward = idx.view().state().expected_base_reward();
            BlockEntry e = f.sibling(prev, h, static_cast<std::uint8_t>(20 + i), reward);
            idx.offer_block(&f.peer_, e, false);
            prev = id_of(e);
        }
        checkf(idx.tip() && idx.tip()->id == f.main_ids.back(),
               "horizon: a reorg deeper than the horizon was performed");
        bool alarmed = false;
        for (const ReorgRecord& r : idx.journal().records())
            if (r.refusal == ReorgRefusal::TooDeep) alarmed = true;
        checkf(alarmed, "horizon: no TooDeep refusal was journaled");
        checkf(idx.journal().alarms() > 0, "horizon: a refused deep reorg did not alarm");
        checkf(reorg_refusal_is_alarm(ReorgRefusal::TooDeep),
               "horizon: TooDeep is not classified as an alarm");
    }
}

static void test_reorg_rollback_is_exact() {
    Fixture f(4);
    ChainIndex& idx = *f.idx;

    // Record everything about the chain we are on.
    const auto before_tip   = idx.tip();
    const auto before_tpl   = idx.view().state().template_inputs_partial();
    const std::uint64_t before_agc = idx.view().state().already_generated_coins();
    const auto before_lt    = idx.view().state().weights().long_window().values();
    const std::uint64_t before_frontier = idx.verified_frontier();

    // A branch of three blocks off TEST_FIRST+0, heavy enough to win, whose LAST
    // block pays a coinbase the reward rule refuses. It passes the pool's
    // admission (structure, identity, work) and fails only when the switch tries
    // to connect it -- exactly the case that must leave no trace.
    //
    // The branch is OFFERED YOUNGEST FIRST, so every block but the first parks
    // as an orphan and the whole branch resolves at once when its root lands.
    // That is what makes the switch attempt the full five blocks in one go --
    // including the invalid one -- instead of adopting the valid prefix first
    // and then merely refusing to extend it.
    Hash prev = f.main_ids[0];
    std::vector<BlockEntry> alt_entries;
    for (std::uint64_t i = 0; i < 5; ++i) {
        const std::uint64_t h = G::TEST_FIRST + 1 + i;
        std::uint64_t reward = idx.view().state().expected_base_reward();
        if (i == 4) reward += 1;    // one piconero too many
        BlockEntry e = f.sibling(prev, h, static_cast<std::uint8_t>(40 + i), reward);
        prev = id_of(e);
        alt_entries.push_back(std::move(e));
    }
    for (std::size_t i = alt_entries.size(); i-- > 0; )
        idx.offer_block(&f.peer_, alt_entries[i], false);

    const auto after_tip = idx.tip();
    checkf(after_tip && before_tip && after_tip->id == before_tip->id,
           "rollback: the failed switch changed the tip");
    checkf(idx.view().state().already_generated_coins() == before_agc,
           "rollback: emission was not restored");
    checkf(idx.view().state().weights().long_window().values() == before_lt,
           "rollback: the long-term weight window was not restored");
    checkf(idx.verified_frontier() == before_frontier,
           "rollback: the verified frontier was not restored");
    const auto after_tpl = idx.view().state().template_inputs_partial();
    checkf(u128_eq(after_tpl.difficulty, before_tpl.difficulty)
               && after_tpl.median_weight == before_tpl.median_weight
               && after_tpl.median_timestamp == before_tpl.median_timestamp
               && after_tpl.already_generated_coins == before_tpl.already_generated_coins,
           "rollback: the template inputs did not return to their values");
    checkf(idx.long_window_mirror() == idx.view().state().weights().long_window().values(),
           "rollback: the long-term mirror drifted from the state");

    // Nothing was announced: a reorg that did not happen must not be reported.
    checkf(f.log.count(node::MainchainEventKind::Reorg) == 0,
           "rollback: a Reorg event escaped from a failed switch");
    checkf(f.log.count(node::MainchainEventKind::Orphan) == 0,
           "rollback: an Orphan event escaped from a failed switch");

    // It was journaled as rolled back, with the reason.
    checkf(idx.journal().rolled_back() == 1,
           "rollback: %llu rolled-back records, expected 1",
           static_cast<unsigned long long>(idx.journal().rolled_back()));
    checkf(idx.journal().open_records().empty(), "rollback: a journal record was left open");

    // And the offending branch was charged to the peer that proposed it.
    bool faulted = false;
    for (const auto& p : f.fetcher.penalties)
        if (p.fault == PeerFault::BadData) faulted = true;
    checkf(faulted, "rollback: the peer that proposed an invalid branch was not faulted");
}

static void test_bad_pow_is_banned() {
    ScriptedPowSource pow;
    ChainIndexOptions o;
    o.net = XmrNet::Stagenet;
    ChainIndex idx(o, pow);
    seed_stagenet(idx);
    fakes::FakeFetcher fetcher;
    idx.set_fetcher(&fetcher);

    pow.verdict = PowVerdict::BelowTarget;
    const PeerRef p4 = peer(4);
    const std::uint64_t reward = idx.view().state().expected_base_reward();
    const G::GoldenHeader& hdr = header_at(G::TEST_FIRST);
    BlockEntry e = make_block(hdr.major_version, hdr.minor_version, hdr.timestamp,
                              stagenet_seed_row().id, 1, G::TEST_FIRST, reward);
    const OfferResult r = idx.offer_block(&p4, e, false);
    checkf(r.outcome == OfferOutcome::Rejected && r.fault == PeerFault::BadPow,
           "badpow: a block below target was %s", to_string(r.outcome));
    checkf(idx.bans() == 1, "badpow: the peer was not banned");
    checkf(idx.tip()->height == G::TEST_FIRST - 1, "badpow: the tip moved on a bad proof");

    // Fail-closed: a proof we could not check does not join the chain either.
    pow.verdict  = PowVerdict::SeedMissing;
    pow.resident = true;
    const OfferResult r2 = idx.offer_block(&p4, e, false);
    checkf(r2.outcome == OfferOutcome::StoredAsAlt,
           "failclosed: an uncheckable block was %s, expected StoredAsAlt",
           to_string(r2.outcome));
    checkf(idx.tip()->height == G::TEST_FIRST - 1,
           "failclosed: an uncheckable block extended the chain");
}

// =============================================================================
// G. burial, for the section 3 clock
// =============================================================================
static void test_burial() {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);
    ChainIndexOptions o;
    o.net          = XmrNet::Stagenet;
    o.burial_depth = 60;
    ChainIndex idx(o, src);
    seed_stagenet(idx);

    const ReplayResult rr = replay_stagenet(idx, 200);
    const std::uint64_t tip_h = idx.tip()->height;

    // A block exactly at the burial depth is buried; one block shallower is not.
    const std::uint64_t buried_h  = tip_h - 59;    // depth 60, tip inclusive
    const std::uint64_t shallow_h = tip_h - 58;    // depth 59
    const Burial deep    = idx.burial_of(rr.ids[static_cast<std::size_t>(buried_h - G::TEST_FIRST)]);
    const Burial shallow = idx.burial_of(rr.ids[static_cast<std::size_t>(shallow_h - G::TEST_FIRST)]);
    checkf(deep.status == BurialStatus::Buried && deep.depth == 60,
           "burial: depth-60 block reports %s depth %llu", to_string(deep.status),
           static_cast<unsigned long long>(deep.depth));
    checkf(shallow.status == BurialStatus::NotYet,
           "burial: depth-59 block reports %s", to_string(shallow.status));
    checkf(burial_status_accounts(deep.status) && !burial_status_accounts(shallow.status),
           "burial: the accounting predicate disagrees with the statuses");

    // The anchor and everything below it is pinned, not "not yet".
    const Burial pinned = idx.burial_of(stagenet_seed_row().id);
    checkf(pinned.status == BurialStatus::PinnedBuried,
           "burial: the anchor reports %s", to_string(pinned.status));
    checkf(burial_status_accounts(pinned.status), "burial: pinned history must account");

    // A block we have never seen is Unknown -- which must never read as "no".
    const Burial unknown = idx.burial_of(fake_id(424242));
    checkf(unknown.status == BurialStatus::Unknown,
           "burial: an unknown id reports %s", to_string(unknown.status));

    // The frontier the clock may account up to.
    checkf(idx.buried_frontier(60) == tip_h - 59,
           "burial: buried frontier is %llu, expected %llu",
           static_cast<unsigned long long>(idx.buried_frontier(60)),
           static_cast<unsigned long long>(tip_h - 59));

    // An unverified tip holds the frontier back even when the depth is there:
    // the clock must not finalize past work we did not check.
    ChainIndexOptions o2 = o;
    o2.require_pow = false;
    NoPowSource none;
    ChainIndex idx2(o2, none);
    seed_stagenet(idx2);
    replay_stagenet(idx2, 100);
    checkf(idx2.verified_frontier() == G::TEST_FIRST - 1,
           "burial: unverified blocks advanced the frontier");
    const Burial u = idx2.burial_of(idx2.by_height(G::TEST_FIRST + 10)->id);
    checkf(u.status == BurialStatus::NotYet,
           "burial: an unverified but deep block reports %s", to_string(u.status));
    checkf(idx2.buried_frontier(60) == G::TEST_FIRST - 1,
           "burial: the frontier ignored the verification limit");
}

// =============================================================================
// H. snapshot and resume
// =============================================================================
static void test_snapshot() {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);
    ChainIndexOptions o;
    o.net            = XmrNet::Stagenet;
    o.snapshot_depth = 8;
    ChainIndex idx(o, src);
    seed_stagenet(idx);
    replay_stagenet(idx, 800 > G::TEST_COUNT ? G::TEST_COUNT : 800);

    std::vector<std::uint8_t> snap;
    std::string why;
    checkf(idx.save_snapshot(snap, why), "snapshot: save failed: %s", why.c_str());
    checkf(!snap.empty(), "snapshot: an empty snapshot was produced");

    const auto tip_before      = idx.tip();
    const std::uint64_t front  = idx.verified_frontier();
    const auto tpl_before      = idx.view().state().template_inputs_partial();
    const auto lt_before       = idx.view().state().weights().long_window().values();

    ModelVerifier mv2;
    LightVerifierPowSource<ModelVerifier> src2(mv2);
    ChainIndex restored(o, src2);
    checkf(restored.load_snapshot(snap, why), "snapshot: load failed: %s", why.c_str());

    const auto tip_after = restored.tip();
    checkf(tip_after && tip_before && tip_after->id == tip_before->id
               && tip_after->height == tip_before->height,
           "snapshot: the restored tip differs");
    checkf(restored.verified_frontier() == front,
           "snapshot: the restored frontier is %llu, expected %llu",
           static_cast<unsigned long long>(restored.verified_frontier()),
           static_cast<unsigned long long>(front));
    const auto tpl_after = restored.view().state().template_inputs_partial();
    checkf(u128_eq(tpl_after.difficulty, tpl_before.difficulty)
               && tpl_after.median_weight == tpl_before.median_weight
               && tpl_after.median_timestamp == tpl_before.median_timestamp
               && tpl_after.already_generated_coins == tpl_before.already_generated_coins
               && tpl_after.block_weight_limit == tpl_before.block_weight_limit,
           "snapshot: the restored template inputs differ");
    checkf(restored.view().state().weights().long_window().values() == lt_before,
           "snapshot: the restored long-term window differs");

    // Resume did not re-run proof of work: the rows carry the verdicts the
    // snapshot recorded.
    checkf(mv2.hashes == 0, "snapshot: resume re-ran %llu proofs of work",
           static_cast<unsigned long long>(mv2.hashes));

    // The rows below the base came back too, so burial and serving still work.
    checkf(restored.by_height(G::TEST_FIRST + 5).has_value(),
           "snapshot: a row below the snapshot base was lost");
    // Below the resume's own base the answer is PinnedBuried rather than
    // Buried: that history sits under the restored trust floor, exactly as
    // pre-anchor history does. Both account, which is what the clock asks.
    const Burial resumed = restored.burial_of(restored.by_height(G::TEST_FIRST + 5)->id);
    checkf(burial_status_accounts(resumed.status),
           "snapshot: burial after a resume reports %s", to_string(resumed.status));

    // A tampered snapshot is refused, not partially applied.
    std::vector<std::uint8_t> bad = snap;
    bad[bad.size() / 2] ^= 0x40;
    ChainIndex broken(o, src2);
    checkf(!broken.load_snapshot(bad, why), "snapshot: a tampered snapshot was accepted");
    checkf(why.find("digest") != std::string::npos,
           "snapshot: the refusal did not name the digest (%s)", why.c_str());

    // A snapshot from another network is refused.
    ChainIndexOptions o3 = o;
    o3.net = XmrNet::Mainnet;
    ChainIndex wrong_net(o3, src2);
    checkf(!wrong_net.load_snapshot(snap, why), "snapshot: a foreign-network snapshot was accepted");

    // And the restored index can still reorg, up to the depth the snapshot was
    // taken at: a resume must not freeze history at the tip.
    checkf(restored.anchor_height() <= tip_before->height - 1,
           "snapshot: the resumed index anchored at its own tip and cannot reorg");
}

// =============================================================================
// I. serving
// =============================================================================
static void test_serving() {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);
    ChainIndexOptions o;
    o.net = XmrNet::Stagenet;
    ChainIndex idx(o, src);
    seed_stagenet(idx);
    const ReplayResult rr = replay_stagenet(idx, 40);

    const PeerSyncData sd = idx.our_sync_data();
    checkf(sd.current_height == idx.tip()->height + 1,
           "serving: current_height is not tip + 1");
    checkf(sd.top_id == idx.tip()->id, "serving: top_id is not the tip");
    checkf(sd.pruning_seed == 0, "serving: we advertised a pruning stripe");
    checkf((sd.support_flags & 1u) != 0, "serving: fluffy blocks are not advertised");

    checkf(idx.have_block(rr.ids.back()), "serving: have_block missed a block we hold");
    checkf(!idx.have_block(fake_id(999999)), "serving: have_block claimed a block we do not hold");

    const std::vector<Hash> loc = idx.locator();
    checkf(!loc.empty() && loc.front() == idx.tip()->id, "serving: the locator does not start at the tip");
    checkf(loc.back() == stagenet_seed_row().id,
           "serving: the locator does not end at the deepest id we retain");

    // A supplement from a peer that shares our chain.
    const auto sup = idx.find_supplement({rr.ids[10], fake_id(1)});
    checkf(sup.has_value(), "serving: no supplement for a peer that shares our chain");
    if (sup) {
        checkf(sup->ids.front() == rr.ids[10], "serving: the supplement does not start at the splice");
        checkf(sup->ids.back() == idx.tip()->id, "serving: the supplement does not reach our tip");
        checkf(sup->total_height == idx.tip()->height + 1, "serving: wrong total_height");
        checkf(sup->weights_claimed_hint.size() == sup->ids.size(),
               "serving: the weight array does not match the id array");
    }
    // A peer with nothing in common gets nothing, rather than a misleading span.
    checkf(!idx.find_supplement({fake_id(4242)}).has_value(),
           "serving: a supplement was offered to a peer with no common block");

    // A block we connected is servable from the retained bodies.
    checkf(idx.get_block_entry(rr.ids.back(), true).has_value(),
           "serving: a recently connected block is not servable");
}

// =============================================================================
// J. hints are never consensus
// =============================================================================
static void test_hints_are_ignored() {
    ModelVerifier mv;
    LightVerifierPowSource<ModelVerifier> src(mv);
    ChainIndexOptions o;
    o.net = XmrNet::Stagenet;
    ChainIndex idx(o, src);
    seed_stagenet(idx);

    const G::GoldenHeader& hdr = header_at(G::TEST_FIRST);
    const std::uint64_t reward = idx.view().state().expected_base_reward();
    BlockEntry e = make_block(hdr.major_version, hdr.minor_version, hdr.timestamp,
                              stagenet_seed_row().id, 1, G::TEST_FIRST, reward);
    // A peer claiming a wildly wrong weight for the block it is sending.
    e.block_weight_claimed_hint = 1234567;

    const PeerRef p2 = peer(2);
    const OfferResult r = idx.offer_block(&p2, e, false);
    checkf(r.outcome == OfferOutcome::Connected, "hints: the block did not connect");
    const auto row = idx.view().state().tip();
    checkf(row && row->block_weight != 1234567,
           "hints: the peer's weight claim reached the consensus row");
    EvaluatedBlock ev;
    std::string    ev_why;
    evaluate_block(e, ev, ev_why);
    checkf(row && row->block_weight == ev.input.parsed.miner_tx.blob_size,
           "hints: the recomputed weight is not the coinbase transaction's own size");
    checkf(u128_eq(row->difficulty, u128_of(hdr.difficulty_lo, hdr.difficulty_hi)),
           "hints: the difficulty is not the one we computed");
}

// =============================================================================
int main() {
    test_wire_validation();
    test_row_store();
    test_pow_gate();
    test_fork_choice_table();
    test_stagenet_replay();
    test_reorg_switch();
    test_reorg_equal_work_and_prefer_own();
    test_reorg_refusals();
    test_reorg_rollback_is_exact();
    test_bad_pow_is_banned();
    test_burial();
    test_snapshot();
    test_serving();
    test_hints_are_ignored();

    std::printf("xmr_native_chain_index_kat: %d checks, %d failures\n", g_checks, g_fail);
    return g_fail == 0 ? 0 : 1;
}
