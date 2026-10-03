// SPDX-License-Identifier: AGPL-3.0-or-later
// ---------------------------------------------------------------------------
// v37_xmr_ballot_kat -- RULES RATCHET R1: the BALLOT carrier's canon
// (operator rulings 2026-10-03, spec sec. 2.1 / 2.3; the behaviour -- who
// writes the ballot, the tally -- is R2 / R3).
//
//   B  the side ballot word: 0 = today's receipt byte for byte; own flag /
//      epoch bits; every u16 is well-formed (no CheckStage::Reserved).
//   V  XMR_LANE_BV (0x1E): the 134-byte composite (u16 ballot | u16 d | payee |
//      donation), make / decode round trip, well-formed rules (d <= 65534,
//      inner XMR kinds, payee != donation), identity_key goldens, the canon
//      dispatch and descriptor validity (a lane key, never an attribution /
//      aux target), valid with real points.
//   P  project(): a BV identity splits its weight exactly like GA (payee gets
//      W - floor(W d / 65535), the donation the rest) and sums the payee slice
//      into box[ballot], the donation slice into box[0]; a plain ref and a GA
//      composite count under ballot 0; two ballots of one payee merge on the
//      canonical payee key for E_b and stay apart in the box; box == SUM of
//      the view's weights; fold_eb carries the box; the fast path (no
//      composite) fills box[0] with everything.
// ---------------------------------------------------------------------------
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <sharechain/v37/v37_descriptor.hpp>
#include <sharechain/v37/v37_descriptor_xmr.hpp>
#include <sharechain/v37/v37_fixed.hpp>
#include <c2pool/v37/w4_settlement.hpp>
#include <c2pool/v37/xmr/relay/xmr_relay_wire.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_mint.hpp>
#include "impl/xmr/coin/xmr_derivation.hpp"

namespace settle = c2pool::v37n::settle;
namespace relay  = c2pool::v37n::xmr::relay;
namespace vx     = ::v37::xmr;   // (::xmr is the coin namespace of xmr_derivation.hpp)
using ::v37::bytes32;
using ::v37::U256;
using ::v37::MinerId;
using ::v37::ScriptRef;

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

std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{}; sec.data()[0] = k;
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{}; std::memcpy(out.data(), pub.data(), 32); return out;
}
ScriptRef payee_of(std::uint8_t a, std::uint8_t b) { return vx::make_xmr_std(point_of(a), point_of(b)); }

// Frozen identity goldens (regenerate with V37_XMR_BALLOT_KAT_PRINT=1 only on a deliberate move).
constexpr const char* GOLDEN_BV_IDENTITY_8002 = "430a39d3fac1c697c7df3efc89d7ea25ee4ac4d1cd34a7443aea78b74df1bf6d";

struct IdView {
    std::map<MinerId, ::v37::IdentityEntry> m;
    const ::v37::IdentityEntry* find(MinerId id) const { auto it = m.find(id); return it == m.end() ? nullptr : &it->second; }
};
struct View {
    std::map<MinerId, U256> payout;
    std::shared_ptr<const IdView> identities;
    ::v37::LaneParams params;
    ::v37::u64 next_pos = 0;
};
U256 u(std::uint64_t x) { U256 v; v.v[0] = x; return v; }

void suite_b() {
    std::printf("== B. the side ballot word ==\n");
    relay::SideDataV2 s; s.t_lo = 5000; s.identity = bytes32{}; s.chain_id = 7; s.give_author = 655;
    CHECK(s.ballot == 0 && s.bytes().size() == 56 && s.bytes()[54] == 0 && s.bytes()[55] == 0, "ballot defaults to 0: bytes [54..56) zero (today's receipt)");
    s.ballot = 0x8002;
    CHECK(s.bytes()[54] == 0x02 && s.bytes()[55] == 0x80 && relay::SideDataV2::from(s.bytes().data()).ballot == 0x8002, "0x8002 LE at [54..56), round trip");
    CHECK(vx::xmr_ballot_own(0x8002) && vx::xmr_ballot_epoch(0x8002) == 2 && !vx::xmr_ballot_own(0x0002) && vx::xmr_ballot_epoch(0x0002) == 2 &&
              vx::xmr_ballot_own(0x8000) && vx::xmr_ballot_epoch(0x8000) == 0 && vx::xmr_ballot_epoch(0xFFFF) == 0x7FFF,
          "own flag = bit 15, epoch_no = bits 0..14 (0x8000 = own abstain; 0x0002 = epoch 2 by delegation)");
    CHECK(std::string(relay::to_string(relay::CheckStage::InfoDigest)) == "info-digest" && static_cast<int>(relay::CheckStage::InfoDigest) == 7,
          "CheckStage::Reserved is gone; InfoDigest keeps its number (7) so logs stay comparable");
}

void suite_v() {
    std::printf("== V. XMR_LANE_BV (0x1E): the composite lane identity with a ballot ==\n");
    const ScriptRef P = payee_of(1, 2), D = payee_of(3, 4);
    const ScriptRef bv = vx::make_xmr_ballot_identity(0x8002, 655, P, D);
    CHECK(static_cast<std::uint8_t>(bv.kind) == 0x1E && bv.payload.size() == 134 && vx::XMR_BV_PAYLOAD_LEN == 134,
          "kind 0x1E, payload 134 B = u16 ballot | u16 d | u8 kind | 64 | u8 kind | 64");
    CHECK(bv.payload[0] == 0x02 && bv.payload[1] == 0x80 && bv.payload[2] == 0x8f && bv.payload[3] == 0x02 && bv.payload[4] == 0x10 && bv.payload[69] == 0x10,
          "layout: ballot 0x8002 LE, d 655 LE, payee kind XMR_STD at 4, donation kind at 69");
    vx::XmrBallotIdentity g;
    CHECK(vx::decode_xmr_ballot_identity(bv, g) && g.ballot == 0x8002 && g.d == 655 && g.payee == P && g.donation == D, "decode round trip");
    CHECK(vx::xmr_bv_well_formed(bv) && vx::xmr_bv_valid(bv), "well-formed and valid (real prime-order points)");
    CHECK(vx::xmr_bv_well_formed(vx::make_xmr_ballot_identity(0, 0, P, D)), "d = 0 (all to the payee) is well-formed");
    CHECK(vx::xmr_bv_well_formed(vx::make_xmr_ballot_identity(0xFFFF, 65534, P, D)), "d = 65534 and ballot 0xFFFF are well-formed (any u16 ballot)");
    CHECK(!vx::xmr_bv_well_formed(vx::make_xmr_ballot_identity(1, 65535, P, D)), "d = 65535 is NOT well-formed (the whole weight is the donation's: a plain ref)");
    CHECK(!vx::xmr_bv_well_formed(vx::make_xmr_ballot_identity(1, 10, P, P)), "payee == donation is NOT well-formed");
    { ScriptRef x = bv; x.payload.pop_back(); CHECK(!vx::decode_xmr_ballot_identity(x, g), "133 bytes -> no decode"); }
    { ScriptRef x = bv; x.payload[4] = 0x01; CHECK(!vx::decode_xmr_ballot_identity(x, g), "a non-XMR inner kind -> no decode"); }
    { ScriptRef ga = vx::make_xmr_give_author(655, P, D); CHECK(!vx::decode_xmr_ballot_identity(ga, g) && ga.payload.size() == 132, "a GA composite (0x1F, 132 B) is not a BV"); }
    CHECK(::v37::is_xmr_dispatch_kind(vx::XMR_LANE_BV) && ::v37::is_xmr_dispatch_kind(vx::XMR_LANE_GA), "the canon dispatches 0x1E (and 0x1F) to the XMR validator");
    ::v37::PayoutDescriptor d; d.pay = bv;
    CHECK(vx::xmr_descriptor_valid(d), "a descriptor whose pay is a BV composite is valid (a lane key)");
    { ::v37::PayoutDescriptor a; a.pay = P; a.attribution = bv; CHECK(!vx::xmr_descriptor_valid(a, true), "a BV as attribution is refused"); }
    { ::v37::PayoutDescriptor a; a.pay = P; ::v37::AuxEntry ar; ar.chain_id = 1; ar.ref = bv; a.aux.push_back(ar); CHECK(!vx::xmr_descriptor_valid(a), "a BV as an aux target is refused"); }
    const bytes32 id = vx::xmr_identity_key(bv);
    if (std::getenv("V37_XMR_BALLOT_KAT_PRINT")) std::printf("GOLDEN_BV_IDENTITY_8002=%s\n", hex(id).c_str());
    CHECK(hex(id) == GOLDEN_BV_IDENTITY_8002, "frozen identity_key of the (0x8002, 655, P, D) composite %s...", hex(id).substr(0, 16).c_str());
    CHECK(id != vx::xmr_identity_key(vx::make_xmr_ballot_identity(0x0002, 655, P, D)) && id != vx::xmr_identity_key(vx::make_xmr_give_author(655, P, D)) &&
              id != vx::xmr_identity_key(P),
          "the ballot, the composite kind and the payee all give different lane keys");
}

void suite_p() {
    std::printf("== P. project(): the split and the ballot box ==\n");
    const ScriptRef P = payee_of(1, 2), Q = payee_of(5, 6), D = payee_of(3, 4);
    const bytes32 KP = vx::xmr_identity_key(P), KQ = vx::xmr_identity_key(Q), KD = vx::xmr_identity_key(D);
    const ScriptRef bv1 = vx::make_xmr_ballot_identity(0x8002, 655, P, D);    // P votes 2 (own), d = 1%
    const ScriptRef bv2 = vx::make_xmr_ballot_identity(0x0003, 655, P, D);    // P again, delegated 3
    const ScriptRef bv3 = vx::make_xmr_ballot_identity(0x0002, 0, Q, D);      // Q votes 2 by delegation, d 0
    const ScriptRef ga  = vx::make_xmr_give_author(655, Q, D);                // the legacy composite
    auto idv = std::make_shared<IdView>();
    idv->m[1] = ::v37::IdentityEntry{vx::xmr_identity_key(bv1), bv1};
    idv->m[2] = ::v37::IdentityEntry{vx::xmr_identity_key(bv2), bv2};
    idv->m[3] = ::v37::IdentityEntry{vx::xmr_identity_key(bv3), bv3};
    idv->m[4] = ::v37::IdentityEntry{vx::xmr_identity_key(ga), ga};
    idv->m[5] = ::v37::IdentityEntry{KD, D};                                   // a plain ref (the donation's own receipts)
    View v; v.identities = idv;
    v.payout[1] = u(65535 * 10);   // bv1: 655350 -> donation 6550, payee 648800
    v.payout[2] = u(65535 * 4);    // bv2: 262140 -> donation 2620, payee 259520
    v.payout[3] = u(1000);         // bv3: all to Q
    v.payout[4] = u(65535);        // ga : donation 655, payee 64880
    v.payout[5] = u(77);           // plain
    settle::BallotBox box;
    std::size_t unresolved = 0;
    const auto out = settle::project(v, &unresolved, &box);
    std::map<bytes32, U256> w; for (const auto& p : out) w[p.key] = p.weight;
    CHECK(unresolved == 0 && out.size() == 3, "three payees after the split (P, Q, D)");
    CHECK(w[KP] == u(648800 + 259520), "P's weight = both of its ballots' payee slices merged on the canonical key (%llu)", (unsigned long long)w[KP].v[0]);
    CHECK(w[KQ] == u(1000 + 64880), "Q's weight = the d-0 BV slice + the GA payee slice");
    CHECK(w[KD] == u(6550 + 2620 + 655 + 77), "D's weight = every donation slice + its plain receipt");
    CHECK(box.size() == 4 && box[0x8002] == u(648800) && box[0x0003] == u(259520) && box[0x0002] == u(1000) &&
              box[0] == u(6550 + 2620 + 655 + 64880 + 77),
          "box: [0x8002] = P's own-vote slice, [0x0003] = P's delegated slice (apart in the box, merged in E_b), [0x0002] = Q's, [0] = every donation slice + GA + plain");
    U256 tot_box, tot_view;
    for (const auto& [b, x] : box) { (void)b; tot_box += x; }
    for (const auto& [m, x] : v.payout) { (void)m; tot_view += x; }
    CHECK(tot_box == tot_view, "SUM box == SUM of the view's weights (nothing created, nothing lost)");
    // the fast path: no composite -> box[0] == everything
    View plain; plain.identities = idv; plain.payout[5] = u(77);
    settle::BallotBox pb;
    const auto po = settle::project(plain, nullptr, &pb);
    CHECK(po.size() == 1 && pb.size() == 1 && pb[0] == u(77), "no composite: the fast path, box[0] = the whole weight");
    // without a box the output is unchanged (byte-identical consumers)
    const auto out2 = settle::project(v);
    CHECK(out2.size() == out.size(), "project() without a box: the same payees");
    // fold_eb carries the box
    v.params = ::v37::LaneParams{}; v.next_pos = 10;
    const auto f = settle::fold_eb(1000000, v, /*strict=*/false);
    CHECK(f && f->box == box, "fold_eb returns the same box");
    std::uint64_t eb = 0; for (const auto& [k, a] : f->credit) { (void)k; eb += a; }
    CHECK(f && eb == 1000000, "E_b still splits the whole reward (%llu)", (unsigned long long)eb);
}

} // namespace

int main() {
    std::printf("=== v37_xmr_ballot_kat (RULES RATCHET R1: the ballot word, XMR_LANE_BV, the ballot box) ===\n");
    suite_b();
    suite_v();
    suite_p();
    std::printf("=== %d/%d checks passed ===\n", g_checks - g_fail, g_checks);
    return g_fail == 0 ? 0 : 1;
}
