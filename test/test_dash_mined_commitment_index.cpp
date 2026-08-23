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
//   H  bad-qc-block: a commitment whose quorumHash is not our chain's block
//      hash at the derived base height is REFUSED (:407).
//   I  bad-qc-height: a commitment mined outside its type's DKG mining window
//      is REFUSED (:435).
//   J  bad-qc-dup: two non-rotated commitments of one type in one block are
//      REFUSED on the parsed entry point too (:377).
//   K  body-not-bound: process_block — the BODY entry point production wires
//      into the pre_fold hook — itself refuses a body that does not fold to
//      the header's committed merkle root (:302), writes nothing, and does
//      not advance the cursor.
//
// Every one of C, D, E, F, H, I, J, K is red-provable by deleting the guard it
// names; the comment on each says exactly which line to break. H/I/J each
// carry a CONTROL that differs from the subject in exactly one property, so
// the rejection is attributable to the arm under test and not to some other
// refusal upstream of it.
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
using dash::coin::MinedUndoResult;
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

/// An armed index with pruning and journal trimming turned OFF for the span of
/// a KAT, so a derived merkleRootQuorums at a PAST height is reconstructed from
/// the full retained history rather than the count-bounded window — the undo
/// KATs compare roots at a rolled-back cursor, and the count bound would
/// otherwise legitimately evict a past-height active entry over 3101 blocks.
MinedCommitmentIndex make_armed_full(LlmqNetwork net = LlmqNetwork::Mainnet)
{
    MinedCommitmentIndexConfig cfg;
    cfg.enabled     = true;
    cfg.network     = net;
    cfg.keep_cycles = 65535;      // no inversed-index pruning within the window
    cfg.undo_window = 1000000u;   // journal retains the whole KAT window
    MinedCommitmentIndex idx(cfg);
    TipPosture posture;
    posture.live = false;
    posture.declared_by = "KAT: replay-only consumer";
    const auto v = idx.arm(posture);
    EXPECT_TRUE(v.armed) << v.reason;
    return idx;
}

/// Parse the scan into the contiguous list of MinedBlockInput above the anchor
/// (heights 2513686..2516786), nulls included, in tx order.
std::vector<MinedBlockInput> build_scan_inputs(const std::vector<ScanBlock>& scan)
{
    std::vector<MinedBlockInput> ins;
    for (const auto& b : scan) {
        if (b.height <= 2513685) continue;
        MinedBlockInput in;
        in.height     = b.height;
        in.block_hash = b.block_hash;
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            EXPECT_TRUE(p.has_value());
            if (p) in.commitments.push_back(p->commitment);
        }
        ins.push_back(std::move(in));
    }
    return ins;
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

// ═══════════════════════════════════════════════════════════════════════════
// KAT-H / KAT-I / KAT-J — THE THREE PORTED REJECTION ARMS, each with a
// CONTROL that differs in exactly one property.
//
// The 3101-block KAT-A only ever feeds VALID mainnet blocks, so it exercises
// none of dashd's rejections: all three of these arms could be replaced with
// `if (false)` and the suite stayed green. None of them can produce a false
// TRUE has_mined_commitment (a rejected block writes nothing either way), so
// this was a COVERAGE hole rather than a serving hole — but an arm nothing
// constrains is an arm that can be deleted by accident, and then the store
// starts accepting commitments dashd's ConnectBlock would have rejected.
//
// Each KAT below runs the SAME real mainnet commitment twice: once in the
// shape the chain actually had (CONTROL → Applied) and once with exactly one
// property broken (SUBJECT → the named dashd rejection). Delete the arm and
// the subject becomes Applied too, which is the red.
// ═══════════════════════════════════════════════════════════════════════════

namespace {

struct SubjectQc {
    dash::coin::vendor::CFinalCommitment commitment;
    uint32_t mined_height{0};
};

/// The first real non-null NON-ROTATED (type 4, LLMQ_100_67, dkgInterval 24,
/// mining window [10,18]) commitment in the scan window, with the height the
/// chain mined it at.
std::optional<SubjectQc> first_type4_commitment(const std::vector<ScanBlock>& scan)
{
    for (const auto& b : scan) {
        for (const auto& hex : b.qc_hex) {
            auto p = parse_qc_payload_hex(hex);
            if (!p) continue;
            const auto& c = p->commitment;
            if (c.llmqType != 4) continue;
            if (MinedCommitmentIndex::is_null_commitment(c)) continue;
            SubjectQc s;
            s.commitment   = c;
            s.mined_height = b.height;
            return s;
        }
    }
    return std::nullopt;
}

} // namespace

// ── KAT-H — bad-qc-block: the commitment's quorumHash must BE our chain's
//    block hash at the derived quorum base height.
//    Upstream: llmq/blockprocessor.cpp:300-307 (GetQuorumBlockHash, :487) and
//    the `quorumHash != qc.quorumHash` reject at :311.
//    Port: mined_commitment_index.hpp:407.
//
//    Without it, a commitment naming ANY quorumHash — including one from
//    another chain or one a peer invented — gets recorded as mined, and
//    has_mined_commitment() then answers true for a quorum that does not
//    exist on our chain, dropping a MANDATORY qfcommit slot out of the
//    served template (dashd bad-qc-missing, a lost block).
//
//    RED: replace `if (*base_hash != qc.quorumHash)` with `if (false)`.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, BadQcBlockRejectsACommitmentNotBoundToOurChain)
{
    const auto scan   = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);

    const auto subj = first_type4_commitment(scan);
    ASSERT_TRUE(subj.has_value())
        << "the fixture window must contain a real non-null type-4 commitment";

    MinedBlockInput in;
    in.height     = subj->mined_height;
    for (const auto& b : scan)
        if (b.height == subj->mined_height) in.block_hash = b.block_hash;
    ASSERT_FALSE(in.block_hash.IsNull());

    // ── CONTROL: the commitment exactly as the chain mined it.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        MinedBlockInput ok = in;
        ok.commitments.push_back(subj->commitment);
        std::string err;
        ASSERT_EQ(idx.process_input(ok, at_h, &err), MinedIngestResult::Applied)
            << err;
        EXPECT_TRUE(idx.has_mined_commitment(subj->commitment.llmqType,
                                             subj->commitment.quorumHash));
    }

    // ── SUBJECT: one byte of quorumHash flipped. Everything else — height,
    //    type, mining window, contents — is identical.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        MinedBlockInput bad = in;
        auto tampered = subj->commitment;
        tampered.quorumHash.data()[0] ^= 0xff;
        bad.commitments.push_back(tampered);
        std::string err;
        EXPECT_EQ(idx.process_input(bad, at_h, &err),
                  MinedIngestResult::BadQcBlock)
            << "a commitment whose quorumHash is not our chain's block hash at "
               "the derived base height must be rejected bad-qc-block "
               "(blockprocessor.cpp:311); got err=" << err;
        EXPECT_NE(err.find("bad-qc-block"), std::string::npos) << err;
        // Nothing may be written by a refused block.
        EXPECT_FALSE(idx.has_mined_commitment(tampered.llmqType,
                                              tampered.quorumHash));
        EXPECT_EQ(idx.height(), subj->mined_height - 1)
            << "a refused block must not advance the cursor";
        EXPECT_EQ(idx.stats().commitments_mined, 0u);
    }
}

// ── KAT-I — bad-qc-height: a commitment may only be mined INSIDE its type's
//    DKG mining window.
//    Upstream: llmq/blockprocessor.cpp:327 (`!IsMiningPhase` → bad-qc-height).
//    Port: mined_commitment_index.hpp:435.
//
//    Type 4 is dkgInterval 24, window [10,18]. Control and subject use the
//    SAME commitment and the SAME quorum base (same cycle), so the only
//    difference between Applied and rejected is the block height's phase.
//
//    RED: replace `if (!is_mining_phase(*p, height))` with `if (false)`.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, BadQcHeightRejectsMiningOutsideTheDkgWindow)
{
    const auto scan   = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);

    const auto subj = first_type4_commitment(scan);
    ASSERT_TRUE(subj.has_value());

    // A whole type-4 cycle that lies inside the scanned window.
    const uint32_t cycle = (subj->mined_height / 24u) * 24u;
    const uint32_t h_in  = cycle + 12;   // phase 12 ∈ [10,18]
    const uint32_t h_out = cycle + 20;   // phase 20 ∉ [10,18]
    ASSERT_EQ(dash::coin::is_mining_phase(dash::coin::kLlmq100_67, h_in), true);
    ASSERT_EQ(dash::coin::is_mining_phase(dash::coin::kLlmq100_67, h_out), false);

    // Bind the commitment honestly to OUR chain at the cycle's quorum base,
    // so the bad-qc-block arm cannot be what answers here.
    const uint32_t base_h =
        cycle + static_cast<uint32_t>(subj->commitment.quorumIndex);
    auto base_hash = at_h(base_h);
    ASSERT_TRUE(base_hash.has_value()) << "base h=" << base_h;
    auto qc = subj->commitment;
    qc.quorumHash = *base_hash;

    auto run_at = [&](uint32_t height, std::string& err) {
        auto idx = make_armed();
        idx.seed_cursor(height - 1);
        MinedBlockInput in;
        in.height = height;
        auto it = hashes.find(height);
        EXPECT_NE(it, hashes.end());
        if (it != hashes.end()) in.block_hash = it->second;
        in.commitments.push_back(qc);
        return idx.process_input(in, at_h, &err);
    };

    // ── CONTROL: inside the window.
    std::string err_in;
    ASSERT_EQ(run_at(h_in, err_in), MinedIngestResult::Applied) << err_in;

    // ── SUBJECT: same commitment, same quorum base, 8 blocks later.
    std::string err_out;
    EXPECT_EQ(run_at(h_out, err_out), MinedIngestResult::BadQcHeight)
        << "h=" << h_out << " is phase " << (h_out % 24)
        << ", outside the type-4 DKG mining window [10,18]; dashd rejects "
           "bad-qc-height (blockprocessor.cpp:327). err=" << err_out;
    EXPECT_NE(err_out.find("bad-qc-height"), std::string::npos) << err_out;
}

// ── KAT-J — bad-qc-dup (the PER-BLOCK arm): at most one commitment per
//    NON-ROTATED type per block.
//    Upstream: llmq/blockprocessor.cpp:445-450 ("only allow one commitment
//    per type and per block (This was changed with rotation)").
//    Port: mined_commitment_index.hpp:377 — the re-assert on the PARSED entry
//    point, which is the one a caller that assembled MinedBlockInput itself
//    reaches (the body path's copy is at :332).
//
//    Without it a caller can smuggle two type-4 commitments into one block;
//    both stage, both write, and the store's last-K-mined walk now holds a
//    history no dashd would have accepted.
//
//    RED: replace `if (!p->use_rotation && ++per_type_count[p->type] > 1)`
//         at :377 with `if (false)`.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, BadQcDupRejectsTwoNonRotatedOfOneTypeInABlock)
{
    const auto scan   = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);

    const auto subj = first_type4_commitment(scan);
    ASSERT_TRUE(subj.has_value());

    MinedBlockInput base;
    base.height = subj->mined_height;
    for (const auto& b : scan)
        if (b.height == subj->mined_height) base.block_hash = b.block_hash;
    ASSERT_FALSE(base.block_hash.IsNull());

    // ── CONTROL: one type-4 commitment — the chain's own shape.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        MinedBlockInput one = base;
        one.commitments.push_back(subj->commitment);
        std::string err;
        ASSERT_EQ(idx.process_input(one, at_h, &err),
                  MinedIngestResult::Applied) << err;
        EXPECT_EQ(idx.stats().commitments_mined, 1u);
    }

    // ── SUBJECT: the SAME commitment twice in one block.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        MinedBlockInput two = base;
        two.commitments.push_back(subj->commitment);
        two.commitments.push_back(subj->commitment);
        std::string err;
        EXPECT_EQ(idx.process_input(two, at_h, &err),
                  MinedIngestResult::BadQcDupInBlock)
            << "two non-rotated type-4 commitments in one block is dashd's "
               "bad-qc-dup (blockprocessor.cpp:448); got err=" << err;
        EXPECT_NE(err.find("bad-qc-dup"), std::string::npos) << err;
        EXPECT_FALSE(idx.has_mined_commitment(subj->commitment.llmqType,
                                              subj->commitment.quorumHash))
            << "a refused block must write NOTHING — the staging rule";
        EXPECT_EQ(idx.height(), subj->mined_height - 1);
        EXPECT_EQ(idx.stats().commitments_mined, 0u);
    }
}

// ── KAT-K — process_block: the BODY entry point must ITSELF refuse a body
//    that does not bind to its header.
//    Port: mined_commitment_index.hpp:302 (`block_body_binds_to_header`).
//
//    Every other KAT in this file drives process_input — the PARSED entry
//    point, where the body↔header binding is the CALLER's proof. Production
//    wires process_block into the pre_fold hook (main_dash.cpp), and
//    process_block is where the store asserts the binding for itself (the
//    TRUST BOUNDARY note in the header). Without this test the suite is green
//    around the one function production actually calls.
//
//    Consequence if the guard is absent — the same chain KAT-H proves for
//    :407: a forged/mutated body writes mined records, has_mined_commitment()
//    answers true for a quorum not on our chain, a MANDATORY qfcommit slot
//    leaves the served template, and dashd rejects the found block
//    bad-qc-missing (blockprocessor.cpp:198) — a LOST BLOCK.
//
//    CONTROL and SUBJECT share one body: the real type-6 payload set the
//    chain mined at the subject height, byte-exact from the mainnet capture,
//    behind a coinbase-shaped tx 0. The header commits the merkle root over
//    exactly that tx set (the same fold block_body_binds_to_header applies),
//    so the control is Applied. The subject mutates ONE transaction — the
//    coinbase — while the header keeps committing the ORIGINAL tx set: the
//    delivered body no longer folds to the committed root, and nothing else
//    about it changed. That is the real-PoW-header + forged-body attack the
//    E2 finding-A guard exists for.
//
//    RED: replace `if (!block_body_binds_to_header(block))` at :302 with
//    `if (false)`. The subject then parses cleanly (the mutated tx is the
//    type-0 coinbase, which the type-6 walk skips), every downstream arm
//    passes, and the forged body is Applied: records written, cursor
//    advanced — all five subject expectations fail.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndex, ProcessBlockRefusesABodyNotBoundToItsHeader)
{
    const auto scan   = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);

    const auto subj = first_type4_commitment(scan);
    ASSERT_TRUE(subj.has_value())
        << "the fixture window must contain a real non-null type-4 commitment";

    const ScanBlock* sb = nullptr;
    for (const auto& b : scan)
        if (b.height == subj->mined_height) sb = &b;
    ASSERT_NE(sb, nullptr);
    ASSERT_FALSE(sb->qc_hex.empty());

    // Assemble the BODY the entry point sees: coinbase-shaped tx 0, then
    // every type-6 tx the chain mined at this height, extra_payload
    // byte-exact from the capture.
    dash::coin::BlockType blk;
    blk.m_bits = 0x19158dc7u;   // non-null header
    {
        dash::coin::MutableTransaction coinbase;
        coinbase.version = 3;
        coinbase.type    = 0;
        dash::coin::TxIn cin;
        cin.prevout.hash  = uint256::ZERO;
        cin.prevout.index = 0xffffffffu;
        coinbase.vin.push_back(cin);
        blk.m_txs.push_back(std::move(coinbase));
    }
    for (const auto& hex : sb->qc_hex) {
        dash::coin::MutableTransaction tx;
        tx.version       = 3;
        tx.type          = CFinalCommitmentTxPayload::SPECIALTX_TYPE;   // 6
        tx.extra_payload = from_hex(hex);
        ASSERT_FALSE(tx.extra_payload.empty());
        blk.m_txs.push_back(std::move(tx));
    }
    ASSERT_GE(blk.m_txs.size(), 2u);

    // Bind body to header: commit the root over the actual tx set — the same
    // fold block_body_binds_to_header applies (compute_merkle_root over
    // sha256d(canonical tx bytes)).
    {
        std::vector<uint256> txids;
        for (const auto& tx : blk.m_txs) {
            auto packed = ::pack(tx);
            txids.push_back(::Hash(packed.get_span()));
        }
        blk.m_merkle_root = dash::coin::compute_merkle_root(txids);
    }
    ASSERT_TRUE(dash::coin::block_body_binds_to_header(blk));

    // ── CONTROL: the bound body at its real height → Applied, records
    //    written, cursor advanced.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        std::string err;
        ASSERT_EQ(idx.process_block(subj->mined_height, sb->block_hash, blk,
                                    at_h, &err),
                  MinedIngestResult::Applied) << err;
        EXPECT_TRUE(idx.has_mined_commitment(subj->commitment.llmqType,
                                             subj->commitment.quorumHash))
            << "the real block's type-4 commitment must be recorded as mined";
        EXPECT_EQ(idx.height(), subj->mined_height);
        EXPECT_EQ(idx.stats().blocks_ingested, 1u);
        // Every payload the body carried was either mined or a null skip.
        EXPECT_EQ(idx.stats().commitments_mined + idx.stats().commitments_null,
                  static_cast<uint64_t>(sb->qc_hex.size()));
    }

    // ── SUBJECT: ONE transaction mutated (the coinbase), header unchanged —
    //    the delivered body no longer folds to the committed root.
    {
        auto idx = make_armed();
        idx.seed_cursor(subj->mined_height - 1);
        dash::coin::BlockType forged = blk;
        forged.m_txs[0].locktime ^= 1u;         // m_merkle_root NOT updated
        ASSERT_FALSE(dash::coin::block_body_binds_to_header(forged));
        std::string err;
        EXPECT_EQ(idx.process_block(subj->mined_height, sb->block_hash,
                                    forged, at_h, &err),
                  MinedIngestResult::BodyNotBound)
            << "a body that does not fold to the header's committed merkle "
               "root must be refused body-not-bound at the entry point "
               "(mined_commitment_index.hpp:302); got err=" << err;
        EXPECT_NE(err.find("body-not-bound"), std::string::npos) << err;
        // Nothing may be written by a refused body — the staging rule.
        EXPECT_FALSE(idx.has_mined_commitment(subj->commitment.llmqType,
                                              subj->commitment.quorumHash));
        EXPECT_EQ(idx.height(), subj->mined_height - 1)
            << "a refused body must not advance the cursor";
        EXPECT_EQ(idx.stats().commitments_mined, 0u);
        EXPECT_EQ(idx.stats().blocks_ingested, 0u);
        EXPECT_EQ(idx.stats().blocks_refused, 1u);
    }
}

// ═══════════════════════════════════════════════════════════════════════════
// THE UNDO HALF — dashd's CQuorumBlockProcessor::UndoBlock
// (v23.1.7 llmq/blockprocessor.cpp:383-408), ported as undo_input / undo_block
// / handle_reorg. These KATs are what let the index ARM on a live tip: without
// a proven symmetric rollback a reorg would leave a phantom mined record and
// drop a MANDATORY qfcommit out of the served template (bad-qc-missing, a lost
// block). Each is red-provable by breaking exactly the arm it names.
// ═══════════════════════════════════════════════════════════════════════════

// ── KAT-L — the port itself: a disconnected block's mined records are erased
//    EXACTLY, and re-connecting the same blocks reproduces identical state.
//
//    Connect the anchor + a 3101-block run, snapshot the store at a fork height
//    A (cursor, size, derived merkleRootQuorums, the has_mined set), connect on
//    to the tip B, then DISCONNECT B..A+1 in strict LIFO through undo_input.
//    After the undo the store must be byte-for-byte the A snapshot again:
//    every commitment mined ABOVE the fork is gone (no phantom), every one at
//    or below it survives, size and derived root are identical. Re-connecting
//    the same tail then reproduces the B snapshot exactly — add and remove are
//    inverse.
//
//    RED: make erase_writes_at() a no-op (or drop the `m_mined.erase(...)` in
//    it, or stop undo_input decrementing m_height). A disconnected block's
//    mined records then linger: has_mined_commitment stays true for a
//    commitment the roll-back removed, idx.size() does not return to sizeA, and
//    the derived root at A no longer matches — the phantom-record failure the
//    whole arm exists to prevent.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndexUndo, UndoErasesExactlyAndReconnectReproducesState)
{
    const auto scan = load_scan();
    ASSERT_GE(scan.size(), 3000u);
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);
    const auto ins = build_scan_inputs(scan);
    ASSERT_GE(ins.size(), 100u);

    // Heights that mined at least one non-null commitment.
    std::vector<uint32_t> nn_heights;
    for (const auto& in : ins) {
        for (const auto& c : in.commitments)
            if (!MinedCommitmentIndex::is_null_commitment(c)) {
                nn_heights.push_back(in.height);
                break;
            }
    }
    ASSERT_GE(nn_heights.size(), 2u)
        << "the window must mine non-null commitments at >=2 heights";
    const uint32_t lateH = nn_heights.back();
    ASSERT_GT(lateH, nn_heights.front());
    const uint32_t A = lateH - 1;             // the fork / split cursor
    const uint32_t B = ins.back().height;     // the full tip
    ASSERT_LE(nn_heights.front(), A);
    ASSERT_LT(A, B);

    // Non-null (type,quorumHash) mined at/below A, and those FIRST mined above
    // A. A quorum is mined at most once (bad-qc-dup), so the two sets are
    // disjoint by construction.
    std::vector<std::pair<uint8_t, uint256>> early, late;
    for (const auto& in : ins) {
        for (const auto& c : in.commitments) {
            if (MinedCommitmentIndex::is_null_commitment(c)) continue;
            const std::pair<uint8_t, uint256> k{c.llmqType, c.quorumHash};
            if (in.height <= A) {
                early.push_back(k);
            } else if (std::find(early.begin(), early.end(), k) == early.end()) {
                late.push_back(k);
            }
        }
    }
    ASSERT_FALSE(early.empty());
    ASSERT_FALSE(late.empty());

    auto idx = make_armed_full();
    ASSERT_EQ(seed_anchor(idx), 88u);
    idx.seed_cursor(2513685);

    // ── Connect to A; snapshot.
    size_t iA = 0;
    for (; iA < ins.size(); ++iA) {
        std::string err;
        ASSERT_EQ(idx.process_input(ins[iA], at_h, &err),
                  MinedIngestResult::Applied) << err;
        if (ins[iA].height == A) break;
    }
    ASSERT_EQ(idx.height(), A);
    const size_t  sizeA = idx.size();
    const uint256 rootA = root_from_index(idx, A);
    for (const auto& [t, qh] : early)
        ASSERT_TRUE(idx.has_mined_commitment(t, qh));

    // ── Connect to B; snapshot.
    for (size_t i = iA + 1; i < ins.size(); ++i) {
        std::string err;
        ASSERT_EQ(idx.process_input(ins[i], at_h, &err),
                  MinedIngestResult::Applied) << err;
    }
    ASSERT_EQ(idx.height(), B);
    const size_t  sizeB = idx.size();
    const uint256 rootB = root_from_index(idx, B);
    ASSERT_GT(sizeB, sizeA);
    for (const auto& [t, qh] : late)
        ASSERT_TRUE(idx.has_mined_commitment(t, qh));

    // ── DISCONNECT B..A+1 in strict LIFO through the UndoBlock port.
    for (size_t i = ins.size(); i-- > iA + 1; ) {
        std::string err;
        ASSERT_EQ(idx.undo_input(ins[i], &err), MinedUndoResult::Undone) << err;
        ASSERT_EQ(idx.height(), ins[i].height - 1)
            << "each disconnect steps the cursor back exactly one";
    }

    // EXACT rollback to the A snapshot.
    EXPECT_EQ(idx.height(), A);
    EXPECT_EQ(idx.size(), sizeA);
    EXPECT_EQ(root_from_index(idx, A).GetHex(), rootA.GetHex())
        << "the derived merkleRootQuorums at the fork must be identical after "
           "the roll-back";
    for (const auto& [t, qh] : early)
        EXPECT_TRUE(idx.has_mined_commitment(t, qh))
            << "a commitment mined at/below the fork must survive the undo";
    for (const auto& [t, qh] : late)
        EXPECT_FALSE(idx.has_mined_commitment(t, qh))
            << "a commitment mined ABOVE the fork must be erased — dashd "
               "UndoBlock (blockprocessor.cpp:399); a lingering one is the "
               "phantom mined record that arming on a live tip forbids";

    // ── RE-CONNECT the same tail: the B snapshot is reproduced byte-for-byte.
    for (size_t i = iA + 1; i < ins.size(); ++i) {
        std::string err;
        ASSERT_EQ(idx.process_input(ins[i], at_h, &err),
                  MinedIngestResult::Applied)
            << "re-connect from the rolled-back cursor must be contiguous: "
            << err;
    }
    EXPECT_EQ(idx.height(), B);
    EXPECT_EQ(idx.size(), sizeB);
    EXPECT_EQ(root_from_index(idx, B).GetHex(), rootB.GetHex());
    for (const auto& [t, qh] : late)
        EXPECT_TRUE(idx.has_mined_commitment(t, qh));
    for (const auto& [t, qh] : early)
        EXPECT_TRUE(idx.has_mined_commitment(t, qh));
    EXPECT_EQ(idx.stats().blocks_disconnected,
              static_cast<uint64_t>(ins.size() - (iA + 1)));
}

// ── KAT-M — handle_reorg: the LIVE driver rolls the tip back to the fork point
//    a switched chain implies, and lands on EXACTLY the state a forward-only
//    walk to that fork would have produced.
//
//    Connect anchor + the full run to tip B. Then present a divergent chain to
//    handle_reorg — real block hashes at/below a fork F, a flipped hash above
//    it — as production's header chain would after a branch switch. The store
//    must disconnect every height above F (journal-driven, no body re-supplied)
//    and stop at F. A reference index connected forward-only to F must match it
//    record-for-record: same size, same derived merkleRootQuorums.
//
//    RED: make handle_reorg's fork test `*on_chain == jit->second.block_hash`
//    always false (it then rolls back past the fork), or make erase_writes_at()
//    a no-op (the tip is not rolled back at all). Either way the post-reorg
//    store no longer equals the forward-to-F reference.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndexUndo, HandleReorgRollsBackToForkPointExactly)
{
    const auto scan = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);
    const auto ins = build_scan_inputs(scan);
    ASSERT_GE(ins.size(), 100u);

    std::vector<uint32_t> nn_heights;
    for (const auto& in : ins)
        for (const auto& c : in.commitments)
            if (!MinedCommitmentIndex::is_null_commitment(c)) {
                nn_heights.push_back(in.height);
                break;
            }
    ASSERT_GE(nn_heights.size(), 2u);
    const uint32_t F = nn_heights.back() - 1;   // a fork with a non-null above it

    // Build the store forward to the tip.
    auto idx = make_armed_full();
    ASSERT_EQ(seed_anchor(idx), 88u);
    idx.seed_cursor(2513685);
    for (const auto& in : ins) {
        std::string err;
        ASSERT_EQ(idx.process_input(in, at_h, &err), MinedIngestResult::Applied)
            << err;
    }
    const uint32_t B = idx.height();
    ASSERT_GT(B, F);

    // Reference: a fresh store walked forward-only to F.
    auto ref = make_armed_full();
    ASSERT_EQ(seed_anchor(ref), 88u);
    ref.seed_cursor(2513685);
    for (const auto& in : ins) {
        if (in.height > F) break;
        std::string err;
        ASSERT_EQ(ref.process_input(in, at_h, &err), MinedIngestResult::Applied)
            << err;
    }
    ASSERT_EQ(ref.height(), F);

    // The switched chain: truth at/below F, a divergent hash above it.
    auto reorg_at_h = [&hashes, F](uint32_t h) -> std::optional<uint256> {
        auto it = hashes.find(h);
        if (it == hashes.end()) return std::nullopt;
        if (h <= F) return it->second;
        uint256 flipped = it->second;
        flipped.data()[0] ^= 0xff;              // a block the new branch lacks
        return flipped;
    };

    std::string uerr;
    ASSERT_EQ(idx.handle_reorg(reorg_at_h, &uerr), MinedUndoResult::Undone)
        << uerr;

    // Landed on the fork, and IS the forward-to-F state.
    EXPECT_EQ(idx.height(), F);
    EXPECT_EQ(idx.size(), ref.size())
        << "handle_reorg must leave exactly the mined set a forward walk to the "
           "fork would have";
    EXPECT_EQ(root_from_index(idx, F).GetHex(), root_from_index(ref, F).GetHex());
    EXPECT_EQ(idx.stats().blocks_disconnected, B - F);

    // Every commitment first mined above the fork is gone; the fork's own set
    // is intact and answers has_mined identically to the reference.
    for (const auto& in : ins) {
        for (const auto& c : in.commitments) {
            if (MinedCommitmentIndex::is_null_commitment(c)) continue;
            EXPECT_EQ(idx.has_mined_commitment(c.llmqType, c.quorumHash),
                      ref.has_mined_commitment(c.llmqType, c.quorumHash))
                << "post-reorg has_mined disagrees with the forward-to-fork "
                   "reference for a type=" << int(c.llmqType) << " quorum";
        }
    }

    // And it can fold forward again from the fork.
    for (const auto& in : ins) {
        if (in.height <= F) continue;
        std::string err;
        ASSERT_EQ(idx.process_input(in, at_h, &err), MinedIngestResult::Applied)
            << "re-fold from the fork must be contiguous: " << err;
    }
    EXPECT_EQ(idx.height(), B);
}

// ── KAT-N — the arm gate, both directions. With the undo half ported, a LIVE
//    tip ARMS when the caller declares a reorg-undo handler wired, and still
//    REFUSES (naming UndoBlock, bad-qc-missing and who declared it) when it
//    does not. Existence of the undo code is not the same as a caller driving
//    it, and the guard demands the latter.
//
//    RED: change `if (posture.live && !posture.reorg_undo_wired)` in arm() to
//    `if (posture.live)` — the wired arm is then refused and the first
//    EXPECT_TRUE fails; or to `if (false)` — the unwired live tip arms and the
//    unsafe-refusal half fails.
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndexUndo, ArmsOnLiveTipOnlyWhenReorgUndoWired)
{
    MinedCommitmentIndexConfig cfg;
    cfg.enabled = true;

    // LIVE + wired -> ARMS.
    {
        MinedCommitmentIndex idx(cfg);
        TipPosture p;
        p.live             = true;
        p.reorg_undo_wired = true;
        p.declared_by      = "header-chain reorg seam drives handle_reorg";
        const auto v = idx.arm(p);
        EXPECT_TRUE(v.armed) << v.reason;
        EXPECT_TRUE(idx.armed());
        EXPECT_NE(v.reason.find("UndoBlock"), std::string::npos)
            << "the arming verdict names the ported half: " << v.reason;
        EXPECT_NE(v.reason.find("header-chain reorg seam drives handle_reorg"),
                  std::string::npos)
            << "and who declared the wiring: " << v.reason;
    }

    // LIVE + NOT wired -> REFUSES, and still names the risk.
    {
        MinedCommitmentIndex idx(cfg);
        TipPosture p;
        p.live             = true;
        p.reorg_undo_wired = false;
        p.declared_by      = "FoldLiveTail wired but no undo handler";
        const auto v = idx.arm(p);
        EXPECT_FALSE(v.armed);
        EXPECT_FALSE(idx.armed());
        EXPECT_NE(v.reason.find("UndoBlock"), std::string::npos) << v.reason;
        EXPECT_NE(v.reason.find("bad-qc-missing"), std::string::npos) << v.reason;
        EXPECT_NE(v.reason.find("FoldLiveTail wired but no undo handler"),
                  std::string::npos) << v.reason;
    }
}

// ── KAT-O — undo_block, the BODY entry point (mirror of process_block): it
//    parses the disconnected block's type-6 payloads itself and asserts the
//    body binds to its header before erasing, and undo is strictly LIFO.
//
//    RED: delete undo_block's `block_body_binds_to_header` guard (a forged body
//    then drives an erase), or delete undo_input's `in.height != m_height`
//    clause (a non-tip disconnect is silently accepted).
// ═══════════════════════════════════════════════════════════════════════════
TEST(DashMinedCommitmentIndexUndo, UndoBlockBodyPathAndLifoGuard)
{
    const auto scan   = load_scan();
    const auto hashes = build_hash_map(scan);
    auto at_h = hash_fn(hashes);

    const auto subj = first_type4_commitment(scan);
    ASSERT_TRUE(subj.has_value());

    const ScanBlock* sb = nullptr;
    for (const auto& b : scan)
        if (b.height == subj->mined_height) sb = &b;
    ASSERT_NE(sb, nullptr);
    ASSERT_FALSE(sb->qc_hex.empty());

    // A header-bound body: coinbase-shaped tx 0, then the real type-6 txs.
    dash::coin::BlockType blk;
    blk.m_bits = 0x19158dc7u;
    {
        dash::coin::MutableTransaction coinbase;
        coinbase.version = 3;
        coinbase.type    = 0;
        dash::coin::TxIn cin;
        cin.prevout.hash  = uint256::ZERO;
        cin.prevout.index = 0xffffffffu;
        coinbase.vin.push_back(cin);
        blk.m_txs.push_back(std::move(coinbase));
    }
    for (const auto& hex : sb->qc_hex) {
        dash::coin::MutableTransaction tx;
        tx.version       = 3;
        tx.type          = CFinalCommitmentTxPayload::SPECIALTX_TYPE;
        tx.extra_payload = from_hex(hex);
        ASSERT_FALSE(tx.extra_payload.empty());
        blk.m_txs.push_back(std::move(tx));
    }
    {
        std::vector<uint256> txids;
        for (const auto& tx : blk.m_txs) {
            auto packed = ::pack(tx);
            txids.push_back(::Hash(packed.get_span()));
        }
        blk.m_merkle_root = dash::coin::compute_merkle_root(txids);
    }
    ASSERT_TRUE(dash::coin::block_body_binds_to_header(blk));

    // Connect the block, then UNDO it through the body entry point.
    auto idx = make_armed_full();
    idx.seed_cursor(subj->mined_height - 1);
    std::string err;
    ASSERT_EQ(idx.process_block(subj->mined_height, sb->block_hash, blk, at_h,
                                &err),
              MinedIngestResult::Applied) << err;
    ASSERT_TRUE(idx.has_mined_commitment(subj->commitment.llmqType,
                                         subj->commitment.quorumHash));
    ASSERT_EQ(idx.height(), subj->mined_height);

    ASSERT_EQ(idx.undo_block(subj->mined_height, sb->block_hash, blk, &err),
              MinedUndoResult::Undone) << err;
    EXPECT_EQ(idx.height(), subj->mined_height - 1)
        << "undo_block rolls the cursor back one";
    EXPECT_FALSE(idx.has_mined_commitment(subj->commitment.llmqType,
                                          subj->commitment.quorumHash))
        << "the body entry point must erase the same records process_block "
           "wrote";
    EXPECT_EQ(idx.stats().blocks_disconnected, 1u);

    // LIFO guard: a body that does not bind to its header must not drive an
    // erase, and only the TIP is disconnectable.
    {
        auto idx2 = make_armed_full();
        idx2.seed_cursor(subj->mined_height - 1);
        ASSERT_EQ(idx2.process_block(subj->mined_height, sb->block_hash, blk,
                                     at_h, &err),
                  MinedIngestResult::Applied) << err;

        dash::coin::BlockType forged = blk;
        forged.m_txs[0].locktime ^= 1u;         // m_merkle_root NOT updated
        ASSERT_FALSE(dash::coin::block_body_binds_to_header(forged));
        EXPECT_EQ(idx2.undo_block(subj->mined_height, sb->block_hash, forged,
                                  &err),
                  MinedUndoResult::BodyNotBound);
        EXPECT_TRUE(idx2.has_mined_commitment(subj->commitment.llmqType,
                                              subj->commitment.quorumHash))
            << "a forged body must NOT erase anything";
        EXPECT_EQ(idx2.height(), subj->mined_height);

        // Disconnecting a non-tip height is refused not-tip.
        MinedBlockInput wrong;
        wrong.height = subj->mined_height - 5;   // not the cursor
        EXPECT_EQ(idx2.undo_input(wrong, &err), MinedUndoResult::NotTip);
        EXPECT_NE(err.find("not-tip"), std::string::npos) << err;
        EXPECT_EQ(idx2.height(), subj->mined_height)
            << "a refused disconnect must not move the cursor";
    }
}
