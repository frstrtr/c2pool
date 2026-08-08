// SPDX-License-Identifier: AGPL-3.0-or-later
//
// PR-2 FORWARD — src/impl/dash/coin/mined_commitment_index.hpp
//
// dashd's mined-commitment store, ported from v23.1.7 llmq/blockprocessor.cpp
// and fed from OUR OWN block replay instead of an mnlistdiff round trip.
//
// WHY THESE KATS EXIST
// --------------------
// The measured 12-hour daemonless soak declined 84.3% of its steady-state
// non-serves with cause=qc-plan-underivable, and only that cause had a fat
// tail (512, 302, 283, 249, 194 s). The slot each of those waits was blocked
// on had, in most cases, already been mined by another miner — in a block this
// node had ALREADY folded. `compute_required_qc_slots` just could not see it,
// because `has_mined` read only the QuorumManager and the QuorumManager is
// fed by request/response.
//
// THE KATS
//   A  REAL MAINNET, 3101 blocks: seed the h=2513685 active set (88
//      commitments, from a genesis-based mnlistdiff off a mainnet dashd),
//      replay 2513686..2516786 through the index, and at EVERY block re-derive
//      merkleRootQuorums from the index's own active set
//      (GetMinedAndActiveCommitmentsUntilBlock, blockprocessor.cpp:660) and
//      byte-match the block's committed cbTx root. 3101 consecutive equalities
//      exercise the non-rotated last-K-mined walk, the rotated
//      latest-per-quorumIndex walk, and the null skip, against chain truth.
//   B  the SAME replay answers has_mined_commitment() for every non-null
//      commitment it saw, and NEVER for a null one.
//   C  arm() REFUSES on a live tip and names UndoBlock.
//   D  unarmed => nothing is ingested.
//   E  forward contiguity: a skipped height is refused, not silently absorbed.
//   F  the money-path seam: build_daemonless_qc_plan's `also_has_mined` drops
//      an already-mined slot from the mandatory set — and does NOT when the
//      seam is absent (the default every existing caller keeps).
//   G  issue #90: active_set_shortfall names WHICH type is short.
//
// Every one of C, D, E, F is red-provable by deleting the guard it names; the
// comment on each says exactly which line to break.
//
// Fixture provenance: identical files to test_dash_replay_quorum_engine.cpp
// (captured 2026-08-05 from a read-only mainnet Dash Core v23 node).

#include <gtest/gtest.h>

#include <impl/dash/coin/mined_commitment_index.hpp>
#include <impl/dash/coin/dkg_commitments.hpp>
#include <impl/dash/coin/quorum_root.hpp>
#include <impl/dash/coin/vendor/llmq_commitment.hpp>

#include <core/pack.hpp>
#include <core/uint256.hpp>

#include <algorithm>
#include <cstdint>
#include <fstream>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

using dash::coin::LlmqNetwork;
using dash::coin::MinedCommitmentIndex;
using dash::coin::MinedCommitmentIndexConfig;
using dash::coin::MinedBlockInput;
using dash::coin::MinedIngestResult;
using dash::coin::TipPosture;
using dash::coin::vendor::CFinalCommitment;
using dash::coin::vendor::CFinalCommitmentTxPayload;

namespace {

std::vector<unsigned char> from_hex(const std::string& hex)
{
    std::vector<unsigned char> out;
    if (hex.size() % 2) return out;
    out.reserve(hex.size() / 2);
    for (size_t i = 0; i < hex.size(); i += 2) {
        auto nib = [](char c) -> int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return c - 'a' + 10;
            if (c >= 'A' && c <= 'F') return c - 'A' + 10;
            return -1;
        };
        const int hi = nib(hex[i]), lo = nib(hex[i + 1]);
        if (hi < 0 || lo < 0) return {};
        out.push_back(static_cast<unsigned char>((hi << 4) | lo));
    }
    return out;
}

std::vector<std::string> read_lines(const std::string& name)
{
    const std::string path = std::string(DASH_FIXTURE_DIR) + "/" + name;
    std::ifstream f(path);
    EXPECT_TRUE(f.good()) << "cannot open fixture: " << path;
    std::vector<std::string> lines;
    std::string l;
    while (std::getline(f, l))
        if (!l.empty() && l[0] != '#') lines.push_back(l);
    return lines;
}

std::vector<std::string> split_ws(const std::string& l)
{
    std::istringstream ss(l);
    std::vector<std::string> f;
    std::string t;
    while (ss >> t) f.push_back(t);
    return f;
}

std::optional<CFinalCommitment> parse_commitment_hex(const std::string& hex)
{
    auto bytes = from_hex(hex);
    if (bytes.empty()) return std::nullopt;
    CFinalCommitment c;
    try {
        ::PackStream s(bytes);
        s >> c;
        if (s.cursor_size() != 0) return std::nullopt;
    } catch (const std::exception&) {
        return std::nullopt;
    }
    return c;
}

std::optional<CFinalCommitmentTxPayload> parse_qc_payload_hex(
    const std::string& hex)
{
    auto bytes = from_hex(hex);
    if (bytes.empty()) return std::nullopt;
    CFinalCommitmentTxPayload qc;
    std::vector<unsigned char> b(bytes.begin(), bytes.end());
    if (!dash::coin::vendor::parse_qfcommit_payload(b, qc))
        return std::nullopt;
    return qc;
}

struct ScanBlock {
    uint32_t height{0};
    uint256  block_hash;
    uint256  mrq;                       // committed cbTx merkleRootQuorums
    std::vector<std::string> qc_hex;    // type-6 payloads, in tx order
};

std::vector<ScanBlock> load_scan()
{
    std::vector<ScanBlock> out;
    for (const auto& l :
         read_lines("dash_mainnet_quorum_scan_2513685_2516786.txt")) {
        auto f = split_ws(l);
        EXPECT_EQ(f.size(), 5u) << l.substr(0, 80);
        if (f.size() != 5) continue;
        ScanBlock b;
        b.height = static_cast<uint32_t>(std::stoul(f[0]));
        b.block_hash.SetHex(f[1]);
        b.mrq.SetHex(f[2]);
        if (f[4] != "-") {
            std::stringstream ss(f[4]);
            std::string item;
            while (std::getline(ss, item, ',')) b.qc_hex.push_back(item);
        }
        out.push_back(std::move(b));
    }
    return out;
}

/// height -> hash for everything the KAT can resolve: the 21 pre-window
/// blocks (2513664..2513684, the surrounding cycle base run) plus every
/// scanned block. This stands in for the PoW-verified header chain that
/// production passes as `hash_at_height`.
std::map<uint32_t, uint256> build_hash_map(const std::vector<ScanBlock>& scan)
{
    std::map<uint32_t, uint256> m;
    for (const auto& l :
         read_lines("dash_mainnet_block_hashes_2513664_2513684.txt")) {
        auto f = split_ws(l);
        EXPECT_EQ(f.size(), 2u);
        if (f.size() != 2) continue;
        uint256 h;
        h.SetHex(f[1]);
        m[static_cast<uint32_t>(std::stoul(f[0]))] = h;
    }
    for (const auto& b : scan) m[b.height] = b.block_hash;
    return m;
}

MinedCommitmentIndex::HashAtHeightFn hash_fn(
    const std::map<uint32_t, uint256>& m)
{
    return [&m](uint32_t h) -> std::optional<uint256> {
        auto it = m.find(h);
        if (it == m.end()) return std::nullopt;
        return it->second;
    };
}

MinedCommitmentIndex make_armed(LlmqNetwork net = LlmqNetwork::Mainnet)
{
    MinedCommitmentIndexConfig cfg;
    cfg.enabled = true;
    cfg.network = net;
    MinedCommitmentIndex idx(cfg);
    TipPosture posture;
    posture.live = false;
    posture.declared_by = "KAT: no live-tip lane feeds this index";
    const auto v = idx.arm(posture);
    EXPECT_TRUE(v.armed) << v.reason;
    return idx;
}

/// Seed the anchor's 88-commitment active set. Columns:
/// type qidx base_height quorumHash commitment_hex.
size_t seed_anchor(MinedCommitmentIndex& idx)
{
    size_t n = 0;
    for (const auto& l :
         read_lines("dash_mainnet_active_quorums_2513685.txt")) {
        auto f = split_ws(l);
        EXPECT_EQ(f.size(), 5u) << l.substr(0, 80);
        if (f.size() != 5) continue;
        auto c = parse_commitment_hex(f[4]);
        if (!c) {
            ADD_FAILURE() << "commitment slice must parse byte-exact: "
                          << l.substr(0, 80);
            continue;
        }
        std::string err;
        EXPECT_TRUE(idx.seed_mined_commitment(
            static_cast<uint32_t>(std::stoul(f[2])), *c, err)) << err;
        ++n;
    }
    return n;
}

/// evo/cbtx.cpp CalcCbTxMerkleRootQuorums over whatever the index says is
/// ACTIVE at `height`: SerializeHash each commitment, sort the leaves, merkle.
uint256 root_from_index(const MinedCommitmentIndex& idx, uint32_t height)
{
    std::vector<uint256> leaves;
    for (const auto* r : idx.active_records_until_block(height))
        leaves.push_back(dash::coin::hash_commitment(r->commitment));
    std::sort(leaves.begin(), leaves.end(),
              [](const uint256& a, const uint256& b) {
                  return std::memcmp(a.data(), b.data(), 32) < 0;
              });
    return dash::coin::compute_merkle_root_local(std::move(leaves));
}

} // namespace

// ═══════════════════════════════════════════════════════════════════════════
// KAT-A — 3101 real mainnet blocks: the ACTIVE SET the port derives
//         reproduces every block's committed merkleRootQuorums.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, MainnetActiveSetReproducesCommittedQuorumRoot)
{
    const auto scan = load_scan();
    ASSERT_GE(scan.size(), 3000u) << "scan fixture truncated";
    const auto hashes = build_hash_map(scan);

    auto idx = make_armed();
    const size_t seeded = seed_anchor(idx);
    // The mainnet chainparams quotas are 24+32+4+4+24 = 88.
    EXPECT_EQ(seeded, 88u)
        << "the anchor's active set IS dashd's GetMinedAndActiveCommitments"
           "UntilBlock at h=2513685";
    EXPECT_TRUE(idx.active_set_shortfall(2513685).empty())
        << "a full anchor seed leaves no type short — this is the seed issue"
           " #90 asks for";

    idx.seed_cursor(2513685);
    auto at_h = hash_fn(hashes);

    size_t checked = 0, with_qc = 0, payloads = 0;
    for (const auto& b : scan) {
        if (b.height == 2513685) continue;   // the cursor block itself
        MinedBlockInput in;
        in.height     = b.height;
        in.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            ASSERT_TRUE(p.has_value())
                << "qfcommit payload must parse byte-exact at h=" << b.height;
            in.commitments.push_back(p->commitment);
            ++payloads;
        }
        if (!in.commitments.empty()) ++with_qc;
        std::string err;
        const auto r = idx.process_input(in, at_h, &err);
        ASSERT_EQ(r, MinedIngestResult::Applied)
            << "h=" << b.height << ": " << err;

        // THE PROOF: the root over the index's own active set, byte-matched
        // against the block's committed cbTx root.
        EXPECT_EQ(root_from_index(idx, b.height).GetHex(), b.mrq.GetHex())
            << "merkleRootQuorums mismatch at h=" << b.height;
        ++checked;
    }
    EXPECT_GE(checked, 3000u);
    EXPECT_GT(with_qc, 100u) << "the window must actually carry commitments";
    EXPECT_GT(payloads, 500u);
    // The port's own bookkeeping must add up: every payload was either mined
    // into the store or skipped as a null.
    EXPECT_EQ(idx.stats().commitments_mined + idx.stats().commitments_null,
              static_cast<uint64_t>(payloads));
    EXPECT_EQ(idx.stats().blocks_refused, 0u);
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-B — has_mined_commitment() is true for every non-null commitment the
//         replay saw, and NEVER for a null one.
//
// RED: delete the `if (is_null_commitment(qc)) { ++…; continue; }` arm in
// process_input (mined_commitment_index.hpp) — a null then writes a mined
// record and the null half of this test fails. That arm is the whole reason
// the store can be trusted: dashd's ProcessCommitment returns at
// blockprocessor.cpp:310-320 WITHOUT writing DB_MINED_COMMITMENT, because a
// null means the DKG failed and the slot must stay mandatory for whoever
// mines next.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, MinedIsTrueForRealCommitmentsAndFalseForNulls)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);
    auto idx = make_armed();
    seed_anchor(idx);
    idx.seed_cursor(2513685);
    auto at_h = hash_fn(hashes);

    std::vector<std::pair<uint8_t, uint256>> real_seen, null_seen;
    for (const auto& b : scan) {
        if (b.height == 2513685) continue;
        MinedBlockInput in;
        in.height     = b.height;
        in.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            ASSERT_TRUE(p.has_value());
            if (MinedCommitmentIndex::is_null_commitment(p->commitment))
                null_seen.emplace_back(p->commitment.llmqType,
                                       p->commitment.quorumHash);
            else
                real_seen.emplace_back(p->commitment.llmqType,
                                       p->commitment.quorumHash);
            in.commitments.push_back(p->commitment);
        }
        std::string err;
        ASSERT_EQ(idx.process_input(in, at_h, &err),
                  MinedIngestResult::Applied) << err;
    }

    ASSERT_FALSE(real_seen.empty());
    for (const auto& [t, qh] : real_seen)
        EXPECT_TRUE(idx.has_mined_commitment(t, qh))
            << "type=" << int(t) << " quorum=" << qh.GetHex()
            << " was mined on mainnet and the store must say so";

    // Nulls are not quorums. A null does NOT close the slot — dashd writes no
    // DB_MINED_COMMITMENT for it (blockprocessor.cpp:310-320), so the slot
    // stays mandatory and a REAL commitment for the SAME quorumHash may be
    // mined later in the same window. That happens on this window, so the
    // assertion is over the nulls that were never superseded: those, and only
    // those, must still read not-mined.
    size_t null_only = 0;
    for (const auto& [t, qh] : null_seen) {
        const bool superseded =
            std::any_of(real_seen.begin(), real_seen.end(),
                        [&](const auto& r) {
                            return r.first == t && r.second == qh;
                        });
        if (superseded) continue;
        ++null_only;
        EXPECT_FALSE(idx.has_mined_commitment(t, qh))
            << "a NULL commitment that was never superseded must NEVER read "
               "as mined (dashd writes no DB_MINED_COMMITMENT for it, "
               "blockprocessor.cpp:310-320)";
    }
    EXPECT_GT(null_only, 0u)
        << "this window must contain at least one never-superseded null, or "
           "the null-skip arm is untested here";
    EXPECT_EQ(idx.stats().commitments_null,
              static_cast<uint64_t>(null_seen.size()));

    // And a quorum hash the chain never committed to is not mined.
    uint256 fake;
    fake.SetHex("dead00000000000000000000000000000000000000000000000000000000beef");
    EXPECT_FALSE(idx.has_mined_commitment(2, fake));
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-C — the arm guard: REFUSES on a live tip, and says why.
//
// RED: change `if (posture.live)` in MinedCommitmentIndex::arm() to
// `if (false)`. This test then fails on the first EXPECT_FALSE. That guard is
// the whole safety story of the forward half: dashd's UndoBlock
// (v23.1.7 llmq/blockprocessor.cpp:383-408) is not ported, so on a reorging
// node a phantom mined record would drop a mandatory qfcommit out of the
// served template => bad-qc-missing => lost block.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, RefusesToArmOnALiveTip)
{
    MinedCommitmentIndexConfig cfg;
    cfg.enabled = true;
    MinedCommitmentIndex idx(cfg);

    TipPosture live;
    live.live = true;
    live.declared_by = "FoldLiveTail is wired";
    const auto refused = idx.arm(live);
    EXPECT_FALSE(refused.armed);
    EXPECT_FALSE(idx.armed());
    EXPECT_NE(refused.reason.find("UndoBlock"), std::string::npos)
        << "the refusal must name the missing half: " << refused.reason;
    EXPECT_NE(refused.reason.find("bad-qc-missing"), std::string::npos)
        << "and the consequence: " << refused.reason;
    EXPECT_NE(refused.reason.find("FoldLiveTail is wired"), std::string::npos)
        << "and WHO declared the posture: " << refused.reason;

    TipPosture frozen;
    frozen.live = false;
    frozen.declared_by = "replay-only consumer";
    EXPECT_TRUE(idx.arm(frozen).armed);
    EXPECT_TRUE(idx.armed());
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-C2 — the flag itself: a default-constructed config never arms.
//
// RED: default MinedCommitmentIndexConfig::enabled to true.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, DefaultConfigIsOffAndNeverArms)
{
    MinedCommitmentIndex idx{MinedCommitmentIndexConfig{}};
    TipPosture frozen;
    frozen.live = false;
    const auto v = idx.arm(frozen);
    EXPECT_FALSE(v.armed);
    EXPECT_NE(v.reason.find("feature flag is off"), std::string::npos)
        << v.reason;
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-D — an UNARMED store ingests nothing.
//
// RED: delete the `if (!m_armed) return fail(NotArmed, …)` line in
// process_input.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, UnarmedStoreIngestsNothing)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);
    MinedCommitmentIndexConfig cfg;
    cfg.enabled = true;
    MinedCommitmentIndex idx(cfg);   // arm() never called
    idx.seed_cursor(2513685);

    // Find the first scanned block that actually carries a commitment.
    const ScanBlock* carrier = nullptr;
    for (const auto& b : scan)
        if (b.height > 2513685 && !b.qc_hex.empty()) { carrier = &b; break; }
    ASSERT_NE(carrier, nullptr);

    MinedBlockInput in;
    in.height     = 2513686;
    in.block_hash = scan[1].block_hash;
    auto p = parse_qc_payload_hex(carrier->qc_hex.front());
    ASSERT_TRUE(p.has_value());
    in.commitments.push_back(p->commitment);

    std::string err;
    EXPECT_EQ(idx.process_input(in, hash_fn(hashes), &err),
              MinedIngestResult::NotArmed);
    EXPECT_EQ(idx.size(), 0u);
    EXPECT_FALSE(idx.has_mined_commitment(p->commitment.llmqType,
                                          p->commitment.quorumHash));
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-E — forward contiguity. A skipped height is REFUSED, never absorbed.
//
// RED: delete the `height != m_height + 1` clause in process_input. The store
// then swallows a gap, and — with no UndoBlock — a gap can never be repaired
// by re-walking, so every later has_mined answer is unfalsifiable.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, ForwardContiguityIsEnforced)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);
    auto idx = make_armed();
    seed_anchor(idx);
    idx.seed_cursor(2513685);
    auto at_h = hash_fn(hashes);

    // Skip 2513686 entirely and offer 2513687.
    const ScanBlock* skipped = nullptr;
    for (const auto& b : scan) if (b.height == 2513687) skipped = &b;
    ASSERT_NE(skipped, nullptr);

    MinedBlockInput in;
    in.height     = skipped->height;
    in.block_hash = skipped->block_hash;
    std::string err;
    EXPECT_EQ(idx.process_input(in, at_h, &err),
              MinedIngestResult::NonContiguous);
    EXPECT_NE(err.find("forward-only"), std::string::npos) << err;
    EXPECT_EQ(idx.height(), 2513685u) << "a refused block must not move the cursor";

    // The same block IS accepted once the gap is closed.
    for (const auto& b : scan) {
        if (b.height != 2513686) continue;
        MinedBlockInput ok;
        ok.height     = b.height;
        ok.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            ASSERT_TRUE(p.has_value());
            ok.commitments.push_back(p->commitment);
        }
        EXPECT_EQ(idx.process_input(ok, at_h, &err),
                  MinedIngestResult::Applied) << err;
    }
    EXPECT_EQ(idx.process_input(in, at_h, &err), MinedIngestResult::Applied)
        << err;
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-F — THE MONEY PATH. build_daemonless_qc_plan's `also_has_mined` seam:
//         a slot the chain already mined stops being mandatory, and WITHOUT
//         the seam it does not.
//
// RED: replace the `also_has_mined ? also_has_mined(t, qh) : false` in
// dkg_commitments.hpp build_daemonless_qc_plan with `false`. The
// "with the index" half then reports the same gap as the "without" half and
// this test fails. That expression is the ONLY byte-visible change this PR
// makes to a served template.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, AlreadyMinedSlotLeavesTheMandatorySet)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);

    // Pick a REAL mainnet non-rotated type-4 (LLMQ_100_67, dkgInterval 24)
    // commitment out of the window, and a template height at which type 4 is
    // the ONLY enabled type in its DKG mining window. That isolation matters:
    // the plan is per-height ALL-OR-NOTHING, so if any other type also had an
    // unsatisfiable slot at that height the comparison would be about the
    // wrong slot (the first attempt at this KAT blocked on type 3 and proved
    // nothing).
    auto only_type4_in_window = [](uint32_t h) {
        for (const auto& p : dash::coin::enabled_llmqs(LlmqNetwork::Mainnet)) {
            const bool in = dash::coin::is_mining_phase(p, h);
            if (p.type == 4 ? !in : in) return false;
        }
        return true;
    };

    std::optional<CFinalCommitment> subject;
    uint32_t subject_mined_h = 0, next_h = 0;
    for (const auto& b : scan) {
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            if (!p) continue;
            const auto& c = p->commitment;
            if (MinedCommitmentIndex::is_null_commitment(c)) continue;
            if (c.llmqType != 4) continue;
            const uint32_t cycle_start = b.height - (b.height % 24u);
            for (uint32_t k = 10; k <= 18; ++k) {
                if (!only_type4_in_window(cycle_start + k)) continue;
                subject         = c;
                subject_mined_h = b.height;
                next_h          = cycle_start + k;
                break;
            }
            if (subject) break;
        }
        if (subject) break;
    }
    ASSERT_TRUE(subject.has_value())
        << "the fixture window must contain a real type-4 commitment whose "
           "cycle has a height where only type 4 is in its mining window";

    auto at_height = [&hashes](uint32_t h) -> std::optional<uint256> {
        auto it = hashes.find(h);
        if (it == hashes.end()) return std::nullopt;
        return it->second;
    };
    auto height_of = [&hashes](const uint256& qh) -> std::optional<uint32_t> {
        for (const auto& [h, hash] : hashes) if (hash == qh) return h;
        return std::nullopt;
    };

    dash::coin::QuorumManager empty_qmgr;   // nothing learned from mnlistdiff

    // WITHOUT the seam: the slot is mandatory, nothing satisfies it, the whole
    // height fails closed — exactly today's cause=qc-plan-underivable.
    dash::coin::RequiredQcSlot gap_without{};
    auto plan_without = dash::coin::build_daemonless_qc_plan(
        LlmqNetwork::Mainnet, next_h, empty_qmgr, at_height, height_of,
        /*cache=*/nullptr, /*null_evidence=*/nullptr, &gap_without);
    ASSERT_FALSE(plan_without.has_value());
    EXPECT_FALSE(gap_without.quorum_hash.IsNull())
        << "the refusal must be a SLOT gap, not a structural one";

    // WITH the seam, fed by an index that replayed the block that mined it.
    auto idx = make_armed();
    seed_anchor(idx);
    idx.seed_cursor(2513685);
    auto at_h = hash_fn(hashes);
    for (const auto& b : scan) {
        if (b.height <= 2513685) continue;
        MinedBlockInput in;
        in.height     = b.height;
        in.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            ASSERT_TRUE(p.has_value());
            in.commitments.push_back(p->commitment);
        }
        std::string err;
        ASSERT_EQ(idx.process_input(in, at_h, &err),
                  MinedIngestResult::Applied) << err;
        if (b.height >= subject_mined_h) break;
    }
    ASSERT_TRUE(idx.has_mined_commitment(subject->llmqType,
                                         subject->quorumHash));

    dash::coin::RequiredQcSlot gap_with{};
    auto plan_with = dash::coin::build_daemonless_qc_plan(
        LlmqNetwork::Mainnet, next_h, empty_qmgr, at_height, height_of,
        /*cache=*/nullptr, /*null_evidence=*/nullptr, &gap_with,
        [&idx](uint8_t t, const uint256& qh) {
            return idx.has_mined_commitment(t, qh);
        });

    // The control arm must actually have blocked on THIS slot, or the
    // comparison below is vacuous.
    ASSERT_TRUE(gap_without.quorum_hash == subject->quorumHash
                && gap_without.params.type == subject->llmqType)
        << "control arm must block on the subject slot; it blocked on type="
        << int(gap_without.params.type)
        << " quorum=" << gap_without.quorum_hash.GetHex();

    // WITH the seam the slot is no longer mandatory, nothing else is in its
    // window, and the height PLANS — the whole refusal disappears.
    EXPECT_TRUE(plan_with.has_value())
        << "the chain mined this commitment at h=" << subject_mined_h
        << " and h=" << next_h << " has no other type in a DKG window; with "
           "the mined-commitment index wired the slot must stop being "
           "mandatory (dashd GetNumCommitmentsRequired, "
           "llmq/blockprocessor.cpp:455, skips a slot HasMinedCommitment "
           "answers true for). Blocking gap was type="
        << int(gap_with.params.type)
        << " quorum=" << gap_with.quorum_hash.GetHex();
    if (plan_with)
        EXPECT_TRUE(plan_with->commitments.empty())
            << "an already-mined slot is DROPPED, not served: the template "
               "must carry no type-6 tx at this height";
}

// ═══════════════════════════════════════════════════════════════════════════
// KAT-G — issue #90: the active-set shortfall NAMES the type that is short.
//
// A forward replay from a modern anchor with NO active-set seed can never
// complete on mainnet, because LLMQ_50_60's last 24 commitments were mined
// before DIP0024 (~h 1738698) and stay in dashd's active set forever
// (GetMinedAndActiveCommitmentsUntilBlock walks the CHAINPARAMS list,
// blockprocessor.cpp:664). That is the whole reason the replay quorum-root
// counter read 0/4684 and could not disagree with anything.
//
// RED: make active_set_shortfall() return {} unconditionally.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, ShortfallNamesTheTypeThatBlocksSelfCheckArming)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);

    // UNSEEDED: replay alone, exactly the production posture that produced
    // the 0/4684 line.
    auto cold = make_armed();
    cold.seed_cursor(2513685);
    auto at_h = hash_fn(hashes);
    for (const auto& b : scan) {
        if (b.height <= 2513685) continue;
        MinedBlockInput in;
        in.height     = b.height;
        in.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            ASSERT_TRUE(p.has_value());
            in.commitments.push_back(p->commitment);
        }
        std::string err;
        ASSERT_EQ(cold.process_input(in, at_h, &err),
                  MinedIngestResult::Applied) << err;
    }
    const auto miss = cold.active_set_shortfall(cold.height());
    ASSERT_FALSE(miss.empty())
        << "3101 blocks of forward replay cannot complete the mainnet active "
           "set — if this passes, the premise of issue #90 has changed";
    bool names_50_60 = false;
    for (const auto& [t, n] : miss)
        if (t == 1) { names_50_60 = true; EXPECT_EQ(n, 24u); }
    EXPECT_TRUE(names_50_60)
        << "type 1 (LLMQ_50_60) is the permanent shortfall: no forward replay "
           "from a modern anchor can observe its 24 frozen commitments";
    EXPECT_NE(cold.summary().find("active_set=INCOMPLETE"), std::string::npos)
        << cold.summary();

    // SEEDED: the same 88-commitment mnlistdiff seed the KAT-A anchor uses
    // closes it — so the counter CAN be made to measure something.
    auto warm = make_armed();
    EXPECT_EQ(seed_anchor(warm), 88u);
    EXPECT_TRUE(warm.active_set_shortfall(2513685).empty());
    warm.seed_cursor(2513685);
    EXPECT_NE(warm.summary().find("active_set=COMPLETE"), std::string::npos)
        << warm.summary();
}
