// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_epoch_kat -- RULES RATCHET R1: the EPOCH TABLE in the ledger and
// the stores (operator rulings 2026-10-03, spec sec. 3 and 4.1).
//
//   Y  V37Y / V37V always present from epoch 1: the byte layout of the two
//      sections, the empty-ledger anchor of an XMR ledger (a golden), a ledger
//      without a table unchanged (the BTC / DASH anchor keeps its bytes).
//   D  the Deployment codec (61 B), the genesis deployment, validity.
//   R  the RATCHET event: lock_in_epoch -> V37V carries the decision; apply_ratchet
//      -> epoch_cur, m_rules, V37Y move, V37V drops e, SUM finalW before == after,
//      no row / pending / anchor / lane height changes, seq +1, the leaf is
//      "V37L" 0x04 epoch_no rules_digest H_act (golden); forward only.
//   S  settle store schema 7: every record ver 7, kinds 1-3 round-trip with the
//      box, kind 4 is 55 B and round-trips, ver 8 is "newer than reader", a
//      kind-4 record under a pre-7 version is refused; the RecoveryDriver
//      replays a RATCHET at its position and REFUSES a RATCHET for an epoch
//      the build's table lacks (the fail-closed matrix, row 1).
//   G  GenesisRec v2: round trip, its own version byte 2, a v1 record is not a
//      v2 record; XmrNode::genesis_open_refusal: another pool / network / chain
//      -> refuse, raw on mainnet -> refuse, an epoch the build lacks -> refuse,
//      {1,2} announced-not-active -> open (row 2), absent -> open.
//   O  owed_rules_of(LaneRules) mirrors the ledger rules the daemon derives.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/w6_persistence.hpp>
#include <c2pool/v37/owed_event_log.hpp>
#include <c2pool/v37/xmr/xmr_epoch.hpp>
#include <c2pool/v37/xmr/xmr_lane_rules.hpp>
#include <c2pool/v37/xmr/xmr_lane_rules_build.hpp>
#include <c2pool/v37/xmr/xmr_pool_tag.hpp>
#include <c2pool/v37/xmr/xmr_settle_store.hpp>
#include <c2pool/v37/xmr/xmr_node.hpp>

namespace settle  = c2pool::v37n::settle;
namespace ep      = c2pool::v37n::xmr::epoch;
namespace lr      = c2pool::v37n::xmr::lanerules;
namespace persist = c2pool::v37n::persist;
namespace lineage = c2pool::v37n::xmr::lineage;
namespace oe      = c2pool::v37n::owedevent;
using ::v37::bytes32;
using ::v37::u64;
using c2pool::v37n::xmr::SettleEvent;
using c2pool::v37n::xmr::SettleEvKind;
using c2pool::v37n::xmr::MemSettleStore;
using c2pool::v37n::xmr::RecoveryDriver;
using c2pool::v37n::xmr::RecoveredState;
namespace sc = c2pool::v37n::xmr::store_codec;

namespace {
int g_fail = 0, g_checks = 0;
#define CHECK(cond, ...) do { const bool _ok = (cond); ++g_checks; if (!_ok) ++g_fail; \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); std::printf(__VA_ARGS__); std::printf("\n"); } while (0)

std::string hex(const std::uint8_t* p, std::size_t n) {
    static const char* d = "0123456789abcdef"; std::string s; s.reserve(2 * n);
    for (std::size_t i = 0; i < n; ++i) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}
template <class V> std::string hex(const V& v) { return hex(reinterpret_cast<const std::uint8_t*>(v.data()), v.size()); }
bytes32 b32(std::uint8_t seed) { bytes32 b{}; for (int i = 0; i < 32; ++i) b[i] = static_cast<std::uint8_t>(seed + i); return b; }

// Frozen (regenerate with V37_XMR_EPOCH_KAT_PRINT=1 only on a deliberate move):
// the owed_digest of an EMPTY XMR ledger whose epoch table is {1: rules_digest =
// b32(0x33), H_act 0} with the plain (non-Merkle) rows: sha256d("V37Q" || V37Y || V37V).
constexpr const char* GOLDEN_EMPTY_XMR_ANCHOR = "ecc2d793bfb2b539d2e8e6d299f10628ae7b3e5321eaac301331186af129d320";
// The RATCHET leaf payload for (epoch 2, rules_digest b32(0x44), H_act 5000), hex.
constexpr const char* GOLDEN_RATCHET_LEAF_PAYLOAD = "5633374c04020000004445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f606162638813000000000000";

settle::OwedLedgerRules rules_a() {
    settle::OwedLedgerRules r; r.arm_floor = 1000; r.rotate_on_payment = true; r.decay_horizon = 8; r.decay_half_life = 2; r.anchor_cut = true; r.lane_height = true; r.decay_from_gross = true;
    return r;
}
settle::OwedLedgerRules rules_b() { settle::OwedLedgerRules r = rules_a(); r.decay_horizon = 16; r.decay_half_life = 4; return r; }

settle::LedgerEpochTable table12(bool with_two) {
    settle::LedgerEpochTable t = settle::genesis_epoch_table(b32(0x33), rules_a());
    if (with_two) {
        settle::EpochRow r2; r2.epoch_no = 2; r2.rules_digest = b32(0x44); r2.kind = 1; r2.state = settle::EpochState::Defined; r2.rules = rules_b();
        t.rows.push_back(r2);
    }
    return t;
}

void suite_y() {
    std::printf("== Y. V37Y / V37V first in `rest`, always, from epoch 1 ==\n");
    settle::OwedLedger plain(7);                                  // no table: BTC / DASH
    settle::OwedLedger xmr(7, settle::genesis_epoch_table(b32(0x33), settle::OwedLedgerRules{}));
    CHECK(plain.epochs() == nullptr && xmr.epochs() != nullptr && xmr.epoch_cur() == 1 && xmr.epoch_max() == 1 && xmr.epoch_of(0) == 1 && xmr.epoch_of(~u64{0}) == 1,
          "a ledger without a table reports none; the XMR ledger: epoch_cur 1, epoch_max 1, epoch_of(h) = 1 for every h");
    // the empty-ledger anchor: sha256d("V37Q" || "V37Y" u32 1 b32 digest u64 0 || "V37V" u8 0)
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'Q', 'V', '3', '7', 'Y', 1, 0, 0, 0};
    const bytes32 rd = b32(0x33);
    pre.insert(pre.end(), rd.begin(), rd.end());
    for (int i = 0; i < 8; ++i) pre.push_back(0);
    pre.insert(pre.end(), {'V', '3', '7', 'V', 0});
    const bytes32 want = ::v37::sha256d(pre);
    CHECK(xmr.owed_digest() == want, "the empty XMR ledger's owed_digest == sha256d(\"V37Q\" || V37Y(1, digest, 0) || V37V(n 0)) (%zu-byte preimage)", pre.size());
    if (std::getenv("V37_XMR_EPOCH_KAT_PRINT")) std::printf("GOLDEN_EMPTY_XMR_ANCHOR=%s\n", hex(xmr.owed_digest()).c_str());
    CHECK(hex(xmr.owed_digest()) == GOLDEN_EMPTY_XMR_ANCHOR, "frozen empty XMR anchor %s... (moves ONCE, on this flag day)", hex(xmr.owed_digest()).substr(0, 16).c_str());
    std::vector<std::uint8_t> plain_pre = {'V', '3', '7', 'Q'};
    CHECK(plain.owed_digest() == ::v37::sha256d(plain_pre), "a ledger without a table: the bare \"V37Q\" anchor (BTC / DASH unchanged)");
    CHECK(plain.owed_digest() != xmr.owed_digest(), "the two anchors differ: V37Y / V37V are in the XMR digest from the first byte");
    settle::OwedLedger xmr2(7, settle::genesis_epoch_table(b32(0x34), settle::OwedLedgerRules{}));
    CHECK(xmr2.owed_digest() != xmr.owed_digest(), "another epoch-1 rules_digest -> another empty anchor");
    // a locked-in row shows up in V37V as (epoch_no, kind, h_L, H_act)
    settle::OwedLedger t1(7, table12(false)), t2(7, table12(true));   // the same epoch-1 rules (rules_a: decay on, anchor, lane height)
    const bytes32 d0 = t2.owed_digest();
    CHECK(d0 == t1.owed_digest() && d0 != xmr.owed_digest(), "a DEFINED (not locked-in) epoch-2 row is NOT in the digest (V37V commits decisions); the tagged sections of rules_a are");
    CHECK(t2.lock_in_epoch(2, 4000, 5000), "lock_in_epoch(2, h_L 4000, H_act 5000)");
    const bytes32 d1 = t2.owed_digest();
    std::vector<std::uint8_t> pre1(pre.begin(), pre.end() - 1);   // ... "V37V" then n = 1 | u32 2 | u8 1 | u64 4000 | u64 5000
    pre1.push_back(1); pre1.insert(pre1.end(), {2, 0, 0, 0, 1});
    const u64 hl = 4000, ha = 5000;
    for (int i = 0; i < 8; ++i) pre1.push_back(static_cast<std::uint8_t>(hl >> (8 * i)));
    for (int i = 0; i < 8; ++i) pre1.push_back(static_cast<std::uint8_t>(ha >> (8 * i)));
    // then the tagged sections of rules_a (decay on: V37K with no rows; anchor: V37A 0; lane height: V37Z 0)
    pre1.insert(pre1.end(), {'V', '3', '7', 'K', 'V', '3', '7', 'A', 0, 'V', '3', '7', 'Z', 0, 0, 0, 0, 0, 0, 0, 0});
    CHECK(d1 != d0 && d1 == ::v37::sha256d(pre1), "V37V = n 1 | (u32 2, u8 kind 1, u64 4000, u64 5000): the lock-in decision is committed, before the tagged sections (%zu-byte preimage)", pre1.size());
    CHECK(!t2.lock_in_epoch(2, 1, 2) && !t2.lock_in_epoch(1, 1, 2) && !t2.lock_in_epoch(9, 1, 2), "lock_in: a LOCKED_IN row, the current epoch, an unknown epoch -> refused");
}

void suite_d() {
    std::printf("== D. the Deployment codec (61 B) and the table's validity ==\n");
    ep::Deployment d; d.epoch_no = 2; d.rules_digest = b32(0x44); d.kind = 1; d.start_height = 3412000; d.timeout_height = 3455200; d.fixed_height = 0;
    const auto b = ep::encode_deployment(d);
    CHECK(b.size() == 61 && ep::kDeploymentBytes == 61, "61 bytes");
    CHECK(b[0] == 2 && b[1] == 0 && std::memcmp(b.data() + 4, d.rules_digest.data(), 32) == 0 && b[36] == 1 &&
              b[37] == 0x20 && b[38] == 0x10 && b[39] == 0x34 && b[40] == 0 && b[45] == 0xe0 && b[46] == 0xb8 && b[47] == 0x34,   // 3412000 = 0x341020, 3455200 = 0x34b8e0
          "layout: u32 epoch_no | b32 rules_digest | u8 kind | u64 start | u64 timeout | u64 fixed, little-endian");
    CHECK(ep::get_deployment(b.data()) == d, "round trip");
    const auto g = ep::genesis_deployment(b32(0x33));
    CHECK(g.epoch_no == 1 && g.kind == 0 && g.rules_digest == b32(0x33) && g.start_height == 0 && g.timeout_height == 0 && g.fixed_height == 0,
          "genesis_deployment: epoch 1, kind 0, start/timeout/fixed 0");
    CHECK(ep::deployments_refusal({g}).empty() && ep::deployments_refusal({g, d}).empty(), "{1} and {1, 2 (kind 1)} are valid");
    CHECK(!ep::deployments_refusal({}).empty(), "an empty list is refused (epoch 1 is mandatory)");
    CHECK(!ep::deployments_refusal({d}).empty(), "a list without epoch 1 first is refused");
    { auto x = g; x.kind = 1; CHECK(!ep::deployments_refusal({x}).empty(), "epoch 1 of kind 1 is refused"); }
    { auto x = g; x.start_height = 5; CHECK(!ep::deployments_refusal({x}).empty(), "epoch 1 with a start is refused"); }
    { auto x = d; x.epoch_no = 1; CHECK(!ep::deployments_refusal({g, x}).empty(), "a repeated epoch_no is refused"); }
    { auto x = d; x.timeout_height = x.start_height; CHECK(!ep::deployments_refusal({g, x}).empty(), "kind 1 with timeout <= start is refused"); }
    { auto x = d; x.fixed_height = 7; CHECK(!ep::deployments_refusal({g, x}).empty(), "kind 1 with a fixed height is refused"); }
    { auto x = d; x.kind = 2; x.timeout_height = 0; x.fixed_height = x.start_height + 120; CHECK(ep::deployments_refusal({g, x}).empty(), "kind 2 with fixed > start, timeout 0 is valid"); }
    { auto x = d; x.kind = 2; x.timeout_height = 0; x.fixed_height = x.start_height; CHECK(!ep::deployments_refusal({g, x}).empty(), "kind 2 with fixed <= start is refused"); }
    { auto x = d; x.kind = 3; CHECK(!ep::deployments_refusal({g, x}).empty(), "an unknown kind is refused"); }
    { std::vector<ep::Deployment> many{g}; for (std::uint32_t e = 2; e <= 65; ++e) { auto x = d; x.epoch_no = e; many.push_back(x); }
      CHECK(!ep::deployments_refusal(many).empty() && ep::deployments_refusal(std::vector<ep::Deployment>(many.begin(), many.begin() + 64)).empty(),
            "65 entries refused, 64 accepted (the HELLO bound)"); }
    { const std::vector<ep::Deployment> gd{g, d};
      CHECK(ep::epoch_max_of(gd) == 2 && ep::find_deployment(gd, 2) != nullptr && ep::find_deployment(gd, 3) == nullptr, "epoch_max_of / find_deployment"); }
    const auto mc = ep::net_consts(0), sc_ = ep::net_consts(2), rc = ep::net_consts(3, 3);
    CHECK(mc.K == 48 && mc.L == 17280 && mc.GRACE == 1440 && mc.TIMEOUT == 43200 && sc_.K == 8 && sc_.L == 8640 && sc_.GRACE == 120 && sc_.TIMEOUT == 10080 &&
              rc.K == 2 && rc.L == 0 && rc.GRACE == 6 && rc.TIMEOUT == 1000,
          "the per-network constants of sec. 6.1 (mainnet 48/17280/1440/43200, stagenet 8/8640/120/10080, regtest 2/0/2 D_conf/1000)");
    CHECK(mc.GRACE >= 60 + 1 && sc_.GRACE >= 60 + 1 && rc.GRACE >= 3 + 1, "GRACE >= D_conf + 1 on every row (C7)");
}

void suite_r() {
    std::printf("== R. the RATCHET event: LedgerContinuity, forward only, the kind-4 leaf ==\n");
    settle::OwedLedger L(7, table12(true));
    // a few rows and a pending block, so continuity has something to hold
    settle::OwedLedger::Amounts c1{{b32(0x01), 5000}, {b32(0x02), 700}};
    L.on_block_found("b1", c1, {});
    L.on_block_finalized("b1", 100);
    settle::OwedLedger::Amounts c2{{b32(0x03), 900}};
    L.on_block_found("b2", c2, {});   // pending
    const auto before_rows = L.effective_owed_all();
    long long sum_before = 0; for (const auto& [k, v] : before_rows) { (void)k; sum_before += v; }
    const u64 seq0 = L.ledger_seq();
    const bytes32 d_before = L.owed_digest();
    CHECK(!L.apply_ratchet(2), "apply_ratchet(2) on a DEFINED row is refused (not LOCKED_IN)");
    CHECK(L.lock_in_epoch(2, 4000, 5000), "lock_in_epoch(2)");
    const bytes32 d_locked = L.owed_digest();
    CHECK(L.ledger_seq() == seq0 && d_locked != d_before, "a lock-in is a decision, not a mutation: seq unchanged, the digest commits V37V");
    CHECK(L.rules().decay_horizon == 8 && L.epoch_cur() == 1, "before the event: m_rules = epoch 1 (horizon 8), epoch_cur 1");
    CHECK(L.apply_ratchet(2), "apply_ratchet(2)");
    CHECK(L.epoch_cur() == 2 && L.rules().decay_horizon == 16 && L.epochs()->find(2)->state == settle::EpochState::Active,
          "after: epoch_cur 2, m_rules = epoch 2 (horizon 16), the row ACTIVE");
    const auto after_rows = L.effective_owed_all();
    long long sum_after = 0; for (const auto& [k, v] : after_rows) { (void)k; sum_after += v; }
    CHECK(after_rows == before_rows && sum_before == sum_after && sum_before == 5700, "LedgerContinuity: every row and SUM finalW (%lld) unchanged", sum_after);
    CHECK(L.ledger_seq() == seq0 + 1, "the event takes the next seq (%llu -> %llu)", (unsigned long long)seq0, (unsigned long long)L.ledger_seq());
    const bytes32 d_after = L.owed_digest();
    CHECK(d_after != d_locked, "the digest moves: V37Y = (2, digest(2), 5000), V37V drops epoch 2");
    // V37Y / V37V bytes after the event: sha256d("V37Q" || rows || "V37Y" 2 digest44 5000 || "V37V" 0 || the tagged sections)
    std::vector<std::uint8_t> pre = {'V', '3', '7', 'Q'};
    for (const auto& [k, w] : after_rows) {
        if (w == 0) continue;
        pre.insert(pre.end(), k.begin(), k.end());
        const u64 uw = static_cast<u64>(w);
        for (int i = 0; i < 8; ++i) pre.push_back((uw >> (8 * i)) & 0xff);
        const u64 fe = L.first_eligible_of(k);
        for (int i = 0; i < 8; ++i) pre.push_back((fe >> (8 * i)) & 0xff);
    }
    pre.insert(pre.end(), {'V', '3', '7', 'Y', 2, 0, 0, 0});
    const bytes32 rd2 = b32(0x44); pre.insert(pre.end(), rd2.begin(), rd2.end());
    const u64 ha = 5000; for (int i = 0; i < 8; ++i) pre.push_back((ha >> (8 * i)) & 0xff);
    pre.insert(pre.end(), {'V', '3', '7', 'V', 0});
    // the tagged sections of epoch 2's rules: decay on (V37K, empty here) ... anchor (V37A), lane height (V37Z)
    pre.insert(pre.end(), {'V', '3', '7', 'K'});
    pre.insert(pre.end(), {'V', '3', '7', 'A', 0});
    pre.insert(pre.end(), {'V', '3', '7', 'Z'}); for (int i = 0; i < 8; ++i) pre.push_back(0);
    CHECK(d_after == ::v37::sha256d(pre), "the digest after the event is sha256d(\"V37Q\" || rows || V37Y(2, digest(2), 5000) || V37V(0) || V37K || V37A || V37Z)");
    CHECK(!L.apply_ratchet(2) && !L.lock_in_epoch(2, 1, 2) && !L.apply_ratchet(1), "forward only: no re-apply, no re-lock, never back to epoch 1");
    // the leaf
    const auto leaf = oe::ratchet_payload(2, b32(0x44), 5000);
    std::vector<std::uint8_t> want = {'V', '3', '7', 'L', 4, 2, 0, 0, 0};
    want.insert(want.end(), rd2.begin(), rd2.end());
    for (int i = 0; i < 8; ++i) want.push_back((ha >> (8 * i)) & 0xff);
    CHECK(leaf == want && leaf.size() == 4 + 1 + 4 + 32 + 8 && oe::leaf_evkind(leaf) == oe::EV_RATCHET, "the kind-4 leaf payload = \"V37L\" 04 u32 epoch_no b32 rules_digest u64 H_act (49 B), no bid / bin / amaps");
    if (std::getenv("V37_XMR_EPOCH_KAT_PRINT")) std::printf("GOLDEN_RATCHET_LEAF_PAYLOAD=%s\n", hex(leaf).c_str());
    CHECK(hex(leaf) == GOLDEN_RATCHET_LEAF_PAYLOAD, "frozen leaf payload %s...", hex(leaf).substr(0, 24).c_str());
    CHECK(oe::leaf_evkind(oe::found_payload("b", {}, {})) == oe::EV_FOUND && oe::leaf_evkind({1, 2, 3}) == 0, "leaf_evkind branches on the kind byte after the tag");
    // the pending block still books under the new epoch's rules; the finalize keeps working
    L.on_block_finalized("b2", 200);
    long long s3 = 0; for (const auto& [k, v] : L.effective_owed_all()) { (void)k; s3 += v; }
    CHECK(s3 == 6600, "the pending block finalizes after the event: SUM finalW 6600");
}

void suite_s() {
    std::printf("== S. settle store schema 7: records, the box, kind 4, fail-closed replay ==\n");
    CHECK(sc::SCHEMA_VER == 7, "SCHEMA_VER 7");
    SettleEvent f; f.kind = SettleEvKind::Found; f.bid = "aa"; f.credit[b32(1)] = 10; f.payout[b32(2)] = 3;
    f.has_cut = true; f.cut_pos = 77; f.cut_spine.assign(32, 'x'); f.has_lane = true; f.lane_height = 1234; f.lane_gross.insert(b32(1));
    ::v37::U256 w1; w1.v[0] = 5000; ::v37::U256 w2; w2.v[0] = 7; w2.v[1] = 1;
    f.box[0x0000] = w1; f.box[0x8002] = w2;
    const std::string sf = f.serialize();
    CHECK(static_cast<std::uint8_t>(sf[0]) == 7 && static_cast<std::uint8_t>(sf[1]) == 1, "a FOUND record is written as ver 7, kind 1");
    const SettleEvent bf = SettleEvent::deserialize(sf);
    CHECK(bf.kind == SettleEvKind::Found && bf.bid == "aa" && bf.credit == f.credit && bf.payout == f.payout && bf.has_cut && bf.cut_pos == 77 &&
              bf.has_lane && bf.lane_height == 1234 && bf.lane_gross == f.lane_gross && bf.box.size() == 2 && bf.box.at(0) == w1 && bf.box.at(0x8002) == w2,
          "FOUND round-trips with the lane section and the box (u8 n | n x (u16 ballot | b32 weight))");
    SettleEvent fin; fin.kind = SettleEvKind::Finalize; fin.bid = "aa"; fin.bin_height = 160;
    const std::string sfin = fin.serialize();
    const SettleEvent bfin = SettleEvent::deserialize(sfin);
    CHECK(static_cast<std::uint8_t>(sfin[0]) == 7 && bfin.kind == SettleEvKind::Finalize && bfin.bin_height == 160 && bfin.box.empty() && !bfin.has_lane,
          "FINALIZE: ver 7, every section present (empty), box n = 0, lane flag 0");
    SettleEvent r; r.kind = SettleEvKind::Ratchet; r.epoch_no = 2; r.rules_digest = b32(0x44); r.H_act = 5000; r.akind = 1; r.h_L = 4000;
    const std::string sr = r.serialize();
    CHECK(sr.size() == 55 && c2pool::v37n::xmr::kRatchetRecordBytes == 55 && static_cast<std::uint8_t>(sr[0]) == 7 && static_cast<std::uint8_t>(sr[1]) == 4 &&
              static_cast<std::uint8_t>(sr[2]) == 2 && std::memcmp(sr.data() + 6, r.rules_digest.data(), 32) == 0 && static_cast<std::uint8_t>(sr[38]) == 0x88 &&
              static_cast<std::uint8_t>(sr[46]) == 1 && static_cast<std::uint8_t>(sr[47]) == 0xa0,
          "RATCHET: 55 B = ver 7 | kind 4 | u32 2 | b32 digest | u64 5000 | u8 akind 1 | u64 4000");
    const SettleEvent br = SettleEvent::deserialize(sr);
    CHECK(br.kind == SettleEvKind::Ratchet && br.epoch_no == 2 && br.rules_digest == b32(0x44) && br.H_act == 5000 && br.akind == 1 && br.h_L == 4000, "RATCHET round-trips");
    { std::string s8 = sf; s8[0] = char(8); bool threw = false; std::string what;
      try { SettleEvent::deserialize(s8); } catch (const std::exception& e) { threw = true; what = e.what(); }
      CHECK(threw && what.find("newer than reader") != std::string::npos, "ver 8 -> \"record schema newer than reader\" (fail-closed)"); }
    { std::string s6 = sr; s6[0] = char(6); bool threw = false;
      try { SettleEvent::deserialize(s6); } catch (const std::exception&) { threw = true; }
      CHECK(threw, "a kind-4 record under ver 6 is refused"); }
    { std::string torn = sr.substr(0, 40); bool threw = false;
      try { SettleEvent::deserialize(torn); } catch (const std::exception&) { threw = true; }
      CHECK(threw, "a torn kind-4 record is refused"); }
    // the RecoveryDriver: a RATCHET for an epoch the table LACKS refuses the open (matrix row 1)
    {
        MemSettleStore st;
        auto b = st.batch();
        SettleEvent e1; e1.kind = SettleEvKind::Found; e1.bid = "b1"; e1.credit[b32(1)] = 100;
        SettleEvent e2; e2.kind = SettleEvKind::Finalize; e2.bid = "b1"; e2.bin_height = 100;
        b->put(sc::k_evt(7, 1), e1.serialize()); b->put(sc::k_evt(7, 2), e2.serialize()); b->put(sc::k_evt(7, 3), sr);
        b->commit_sync();
        settle::OwedLedger only1(7, table12(false));
        bool ok = true;
        RecoveryDriver rec(st, 7);
        rec.recover(only1, ok);
        CHECK(!ok, "a build that knows {1} opening a store with RATCHET(2): refused (ok = false)");
        settle::OwedLedger knows2(7, table12(true));
        bool ok2 = true;
        RecoveryDriver rec2(st, 7);
        const RecoveredState rs = rec2.recover(knows2, ok2);
        CHECK(ok2 && rs.max_event_seq == 3 && knows2.epoch_cur() == 2 && knows2.rules().decay_horizon == 16 &&
                  knows2.epochs()->find(2)->H_act == 5000 && knows2.epochs()->find(2)->h_L == 4000,
              "a build that knows {1, 2}: replays the RATCHET at its position (epoch_cur 2, m_rules = epoch 2, H_act 5000 from the record)");
        long long sum = 0; for (const auto& [k, v] : knows2.effective_owed_all()) { (void)k; sum += v; }
        CHECK(sum == 100 && knows2.ledger_seq() == 3, "the replayed ledger: SUM finalW 100, seq 3 (FOUND, FINALIZE, RATCHET)");
        // a ledger without a table (BTC / DASH) never opens a store with a RATCHET record
        settle::OwedLedger none(7);
        bool ok3 = true; RecoveryDriver rec3(st, 7); rec3.recover(none, ok3);
        CHECK(!ok3, "a ledger without an epoch table refuses a store with a RATCHET record");
    }
}

void suite_g() {
    std::printf("== G. GenesisRec v2 and the open rules ==\n");
    persist::GenesisRecV2 g;
    g.first_share_hash = b32(0x10); g.params.window = 8640; g.params.c0 = 4096; g.params.rollup = 8; g.params.half_life = 2160; g.params.level_caps = {568};
    g.params.journal_depth = 64; g.ts = 1759500000;
    g.pool_id = b32(0x20); g.network = 2; g.chain_id = 0xABCD; g.pool_genesis = b32(0x30);
    g.genesis_form = 1; g.H = 3412000; g.block_hash = b32(0x40); g.headline = "attempt 11: the last flag day";
    persist::GenesisDeploymentRec d1; d1.epoch_no = 1; d1.rules_digest = b32(0x33); d1.kind = 0;
    persist::GenesisDeploymentRec d2; d2.epoch_no = 2; d2.rules_digest = b32(0x44); d2.kind = 1; d2.start = 100; d2.timeout = 200;
    g.epochs = {d1, d2};
    const std::string enc = persist::encode_genesis_v2(g);
    CHECK(static_cast<std::uint8_t>(enc[0]) == 2 && static_cast<std::uint8_t>(enc[1]) == persist::K_GENESIS, "the record leads with its OWN version byte 2 and kind K_GENESIS");
    const auto back = persist::decode_genesis_v2(enc);
    CHECK(back && *back == g, "GenesisRec v2 round-trips (pool_id, network, chain, genesis, form, H, hash, headline, 2 epochs)");
    persist::GenesisRec v1; v1.first_share_hash = b32(0x10); v1.ts = 5;
    CHECK(!persist::decode_genesis_v2(persist::encode_genesis(v1)), "a v1 genesis record is NOT a v2 record (pre-R1 store)");
    CHECK(!persist::decode_genesis_v2(enc.substr(0, enc.size() - 3)), "a torn v2 record is refused");
    CHECK(persist::SCHEMA_VER == 1, "the w6 SCHEMA_VER of the shared records stays 1 (BTC / DASH keep decoding)");
    // the open rules (XmrNode::genesis_open_refusal, pure)
    lineage::PoolIdentity me; me.network = 2; me.chain_id = 0xABCD; me.pool_genesis = b32(0x30); me.pool_id = b32(0x20); me.form = lineage::GenesisForm::Derived;
    using c2pool::v37n::xmr::XmrNode;
    CHECK(XmrNode::genesis_open_refusal(std::nullopt, me, 1).empty(), "no record yet -> open (written fresh)");
    CHECK(XmrNode::genesis_open_refusal(enc, me, 2).empty(), "the record lists {1, 2}, the build knows 2 -> open");
    const std::string r1 = XmrNode::genesis_open_refusal(enc, me, 1);
    CHECK(r1.find("lists epoch 2; this build knows <= 1; upgrade") != std::string::npos, "the record lists epoch 2, the build knows {1} -> refuse: %s", r1.substr(0, 70).c_str());
    { persist::GenesisRecV2 x = g; x.epochs = {d1, d2};   // announced, not active: matrix row 2 = OPEN for a build that knows 2
      CHECK(XmrNode::genesis_open_refusal(persist::encode_genesis_v2(x), me, 2).empty(), "{1, 2} announced (no RATCHET record) -> open; the node is a follower"); }
    { lineage::PoolIdentity o = me; o.pool_id = b32(0x21);
      const std::string w = XmrNode::genesis_open_refusal(enc, o, 2);
      CHECK(w.find("store belongs to pool") != std::string::npos, "another pool_id -> refuse: %s", w.substr(0, 60).c_str()); }
    { lineage::PoolIdentity o = me; o.network = 0;
      CHECK(!XmrNode::genesis_open_refusal(enc, o, 2).empty(), "another network -> refuse"); }
    { persist::GenesisRecV2 x = g; x.genesis_form = 2; lineage::PoolIdentity m0 = me; m0.network = 0; x.network = 0;
      const std::string w = XmrNode::genesis_open_refusal(persist::encode_genesis_v2(x), m0, 2);
      CHECK(w.find("RAW pool genesis and this is mainnet") != std::string::npos, "a raw genesis record on mainnet -> refuse: %s", w.substr(0, 60).c_str()); }
    CHECK(!XmrNode::genesis_open_refusal(persist::encode_genesis(v1), me, 2).empty(), "a v1 record -> refuse (no migration)");
    CHECK(sc::k_genesis(0xABCD) == "v37s:genesis:0000043981", "the store key v37s:genesis:<chain>");
}

void suite_o() {
    std::printf("== O. owed_rules_of(LaneRules) ==\n");
    lr::LaneRules r;
    r.arm_floor = 12530000; r.rotate_on_payment = 1; r.decay_horizon = 8640; r.decay_half_life = 2160; r.anchor_cut = 1; r.merkle_rows = 1;
    r.drops_rule = 7; r.drops_window_rw = 65535; r.drain_rule_version = 1; r.drain_q = 16; r.drain_h_cap = 64;
    const ::v37::LaneParams lp{};
    const settle::OwedLedgerRules o = lr::owed_rules_of(r, lp);
    CHECK(o.arm_floor == 12530000 && o.rotate_on_payment && o.decay_horizon == 8640 && o.decay_half_life == 2160 && o.anchor_cut && o.merkle_rows &&
              o.drops_due && o.raindrop_enrol && o.lane_height && o.decay_from_gross && o.drops_window.on() && o.drops_window.rw == 65535,
          "every ledger bit derives from the list (drops bits from the rule tag 7 = due + raindrop-enrol + window)");
    lr::LaneRules q = r; q.drops_rule = 0; q.drops_window_rw = 0; q.drain_rule_version = 0;
    const settle::OwedLedgerRules oq = lr::owed_rules_of(q, lp);
    CHECK(!oq.drops_due && !oq.raindrop_enrol && !oq.lane_height && !oq.decay_from_gross && !oq.drops_window.on(), "rule tag 0 / no drain -> the bits off");
    const auto deps = lr::genesis_deployments(r);
    CHECK(deps.size() == 1 && deps[0].rules_digest == lr::rules_digest(r) && deps[0].epoch_no == 1 && deps[0].kind == 0, "genesis_deployments: {epoch 1 = rules_digest(r)}");
}

} // namespace

int main() {
    std::printf("=== v37_xmr_epoch_kat (RULES RATCHET R1: the epoch table, V37Y/V37V, kind 4, schema 7, GenesisRec v2) ===\n");
    suite_y();
    suite_d();
    suite_r();
    suite_s();
    suite_g();
    suite_o();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
