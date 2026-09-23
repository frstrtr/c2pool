// v37_rb_lane_tag_kat — S1: the v0x03 lane_tag + the REJECT_ROUNDABOUT
// admission predicate.
//
//   A  geometry_leaf is the byte-exact canon "V37H" geometry sub-tuple of the
//      default LaneParams; geometry_digest golden (independent Python ref);
//      gate-only LaneParams differences (v37_0 / v37_1 / shipped) do NOT move it,
//      a geometry change DOES
//   B  lane_tag goldens + preimage length + every field is bound
//   C  RbCarriage 46-byte encoding round-trip + strict length
//   D  v0x03 tagged preimage: v0x01 112-byte preimage is a strict prefix
//      (OFF lane hashes byte-identically), tag changes the PoW hash
//   E  REJECT_ROUNDABOUT truth table, first-failing-reason order, pool-id GAP
//      (mismatched chain / geometry / version / authority reject explicitly)
//   F  exhaustive: for every (id, s < n) EXACTLY one roundabout admits; none
//      for s >= n; an override admits its target and rejects its home
//   G  gate OFF: the predicate is a no-op (OK for anything)
#include <algorithm>
#include <string>
#include <vector>

#include <c2pool/v37/roundabout/rb_admission.hpp>

#include "rb_kat_harness.hpp"

using namespace c2pool::v37n::rb;
using rbkat::fill;
using rbkat::hx;
using rbkat::ok;

static std::string hexv(const std::vector<std::uint8_t>& v) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (auto c : v) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
    return s;
}

int main() {
    std::printf("v37_rb_lane_tag_kat\n");
    const ::v37::LaneParams P0 = ::v37::LaneParams::v37_0();
    const ::v37::LaneParams P1 = ::v37::LaneParams::v37_1();
    const ::v37::LaneParams PS = ::v37::LaneParams::shipped();

    // ── A: geometry ─────────────────────────────────────────────────────────
    const char* GEOLEAF =
        "56333748c02100000000000000100000000000000800000000000000700800000000000001000000000000003802000000000000";
    const char* GEO = "a63797f81a68d5adb8218a56ada4a00bdc54958f5623a04656cf97caa28a6e40";
    {
        ok(hexv(geometry_leaf(::v37::LaneParams{})) == GEOLEAF,
           "A1 geometry_leaf(LaneParams{}) == 'V37H'|8640|4096|8|2160|1|568 (canon :2869-2875 order)");
        ok(hx(geometry_digest(::v37::LaneParams{})) == GEO, "A2 geometry_digest golden (py ref)");
        ok(geometry_digest(P0) == geometry_digest(P1) && geometry_digest(P1) == geometry_digest(PS),
           "A3 gate-only differences (v37_0/v37_1/shipped) do not move the geometry");
        ::v37::LaneParams pw = P1; pw.window = 8641;
        ::v37::LaneParams pc = P1; pc.level_caps = {568, 16};
        ::v37::LaneParams ph = P1; ph.half_life = 2161;
        ok(geometry_digest(pw) != geometry_digest(P1) && geometry_digest(pc) != geometry_digest(P1) &&
               geometry_digest(ph) != geometry_digest(P1), "A4 any geometry field change moves the digest");
    }

    // ── B: lane_tag ──────────────────────────────────────────────────────────
    const LaneTagContext ctx = LaneTagContext::of(0, P1, 1);
    {
        ok(lane_tag_preimage(ctx, 5, 3, 2).size() == LANE_TAG_PREIMAGE_BYTES && LANE_TAG_PREIMAGE_BYTES == 64,
           "B1 preimage is 64 bytes");
        ok(hx(lane_tag(ctx, 5, 3, 2)) == "72aa391b979a5748b1601cb9221803c0fad4824424dccc159a0ae79bea4b435b",
           "B2 lane_tag(chain0, geo, v1, auth0, e5, rb3, s2) golden (py ref)");
        const LaneTagContext c7 = LaneTagContext::of(7, P0, 0);
        ok(hx(lane_tag(c7, 0, 0, 0)) == "fd93339faca3ae10e12fb5044c3a7d603ee7005782613430aa12c9d21e80235a",
           "B3 lane_tag(chain7, geo, v0, auth0, 0,0,0) golden (py ref)");
        const bytes32 base = lane_tag(ctx, 5, 3, 2);
        LaneTagContext x = ctx;
        bool bound = true;
        x.chain_id = 1;  if (lane_tag(x, 5, 3, 2) == base) bound = false; x = ctx;
        x.version = 2;   if (lane_tag(x, 5, 3, 2) == base) bound = false; x = ctx;
        x.authority = 1; if (lane_tag(x, 5, 3, 2) == base) bound = false; x = ctx;
        x.geometry[0] ^= 1; if (lane_tag(x, 5, 3, 2) == base) bound = false;
        if (lane_tag(ctx, 6, 3, 2) == base || lane_tag(ctx, 5, 2, 2) == base || lane_tag(ctx, 5, 3, 3) == base)
            bound = false;
        ok(bound, "B4 every tag field (chain, geometry, version, authority, epoch, rb, stripe) is bound");
    }

    // ── C: carriage encoding ─────────────────────────────────────────────────
    {
        RbCarriage c{0x0102030405060708ull, 0xA0B0C0D0u, 0xBEEF, fill(0x5A)};
        const auto enc = encode_carriage(c);
        RbCarriage d;
        ok(enc.size() == RB_CARRIAGE_BYTES && RB_CARRIAGE_BYTES == 46, "C1 46-byte carriage");
        ok(enc[0] == 0x08 && enc[7] == 0x01 && enc[8] == 0xD0 && enc[12] == 0xEF && enc[13] == 0xBE && enc[14] == 0x5A,
           "C2 little-endian field layout @0 epoch, @8 rb, @12 stripe, @14 tag");
        ok(decode_carriage(enc.data(), enc.size(), d) && d == c, "C3 round-trip");
        ok(!decode_carriage(enc.data(), enc.size() - 1, d), "C4 short rejects");
    }

    // ── D: tagged preimage ──────────────────────────────────────────────────
    {
        ::c2pool::v37n::WorkEvent ev;
        ev.chain_id = 0;
        ev.identity = fill(0x11);
        ev.prev_block_hash = fill(0x22);
        ev.prev_own_share = fill(0x33);
        ev.lz_bits = 8;
        ev.nonce = 42;
        const auto p1 = ev.preimage();
        const bytes32 tag = lane_tag(ctx, 1, 0, 0);
        const auto p3 = tagged_preimage(ev, tag);
        ok(p1.size() == 112 && p3.size() == 144, "D1 v0x01 112 B, v0x03 144 B");
        ok(std::equal(p1.begin(), p1.end(), p3.begin()), "D2 v0x01 preimage is a strict prefix");
        ok(std::equal(tag.begin(), tag.end(), p3.begin() + 112), "D3 tag is the last 32 bytes");
        ok(tagged_hash(ev, tag) != ev.hash(), "D4 the tag is under PoW (hash changes)");
        ok(tagged_hash(ev, tag) != tagged_hash(ev, lane_tag(ctx, 1, 0, 1)), "D5 different stripe -> different PoW hash");
    }

    // ── E: REJECT_ROUNDABOUT truth table ────────────────────────────────────
    RoundaboutGate g = RoundaboutGate::btc_candidate();
    Map map = genesis_map(0);
    map.m = 2;
    map.epoch = 9;
    map.last_W.assign(4, 0);
    map.missed.assign(4, 0);
    const bytes32 A = fill(0xA1), B = fill(0xB2);
    map.n[A] = 4;                                              // A: 4 stripes, B: n = 1
    const bytes32 skA1 = stripe_key(0, A, 1);
    const RbIndex homeA1 = rb_home(skA1, 2);
    const RbIndex ovrA1 = (homeA1 + 1) & 3;
    map.overrides[skA1] = ovrA1;                               // stripe A/1 overridden
    {
        const RbIndex rA0 = map.assign(A, 0);
        RbCarriage good = make_carriage(ctx, map, A, 0);
        ok(good.rb_index == rA0 && good.map_epoch == 9, "E0 miner carriage targets assign(A,0)");
        ok(check_roundabout(g, ctx, map, rA0, A, good).ok(), "E1 honest carriage admitted");

        auto reason = [&](const LaneTagContext& vctx, RbIndex my, const bytes32& id, const RbCarriage& c) {
            return check_roundabout(g, vctx, map, my, id, c).reason;
        };
        // (a) pool-id GAP: validator with other chain / geometry / version / authority
        ::v37::LaneParams pw = P1; pw.window = 8641;
        ok(reason(LaneTagContext::of(1, P1, 1), rA0, A, good) == RbReason::TAG_MISMATCH, "E2 other chain_id -> REJECT (tag)");
        ok(reason(LaneTagContext::of(0, pw, 1), rA0, A, good) == RbReason::TAG_MISMATCH, "E3 other geometry -> REJECT (tag)");
        ok(reason(LaneTagContext::of(0, P1, 2), rA0, A, good) == RbReason::TAG_MISMATCH, "E4 other version -> REJECT (tag)");
        ok(reason(LaneTagContext::of(0, P1, 1, 7), rA0, A, good) == RbReason::TAG_MISMATCH, "E5 other authority -> REJECT (tag)");
        RbCarriage forged = good; forged.stripe = 1;             // fields edited, tag stale
        ok(reason(ctx, rA0, A, forged) == RbReason::TAG_MISMATCH, "E6 edited clear field w/o re-tag -> REJECT (tag)");
        // (b) epoch
        RbCarriage ep = good; ep.map_epoch = 8; ep.lane_tag = lane_tag(ctx, 8, ep.rb_index, ep.stripe);
        ok(reason(ctx, rA0, A, ep) == RbReason::EPOCH_MISMATCH, "E7 stale map epoch -> REJECT");
        // (c) rb out of range
        RbCarriage rr = good; rr.rb_index = 4; rr.lane_tag = lane_tag(ctx, 9, 4, 0);
        ok(reason(ctx, rA0, A, rr) == RbReason::RB_OUT_OF_RANGE, "E8 rb_index >= k -> REJECT");
        // (d) stripe >= n
        RbCarriage so = make_carriage(ctx, map, A, 4);
        ok(reason(ctx, so.rb_index, A, so) == RbReason::STRIPE_OUT_OF_RANGE, "E9 stripe >= n(A)=4 -> REJECT");
        RbCarriage sb = make_carriage(ctx, map, B, 1);
        ok(reason(ctx, sb.rb_index, B, sb) == RbReason::STRIPE_OUT_OF_RANGE, "E10 stripe 1 >= n(B)=1 -> REJECT");
        // (e) wrong roundabout (correct tag for a non-assigned rb)
        const RbIndex wrong = (rA0 + 2) & 3;
        RbCarriage wr = good; wr.rb_index = wrong; wr.lane_tag = lane_tag(ctx, 9, wrong, 0);
        ok(reason(ctx, wrong, A, wr) == RbReason::WRONG_ROUNDABOUT, "E11 assign(A,0) != rb_index -> REJECT");
        // (f) valid carriage, but this validator verifies another roundabout
        ok(reason(ctx, (rA0 + 1) & 3, A, good) == RbReason::NOT_MY_ROUNDABOUT, "E12 not this validator's roundabout -> REJECT");
        // first-failing order: stale epoch AND stripe out of range -> epoch reported
        RbCarriage two = so; two.map_epoch = 3; two.lane_tag = lane_tag(ctx, 3, so.rb_index, so.stripe);
        ok(reason(ctx, so.rb_index, A, two) == RbReason::EPOCH_MISMATCH, "E13 first failing reason reported (epoch before stripe)");
        // identity swap: carriage built for A, presented under B's identity
        ok(!check_roundabout(g, ctx, map, rA0, B, make_carriage(ctx, map, A, 2)).ok() ||
               map.assign(B, 0) == map.assign(A, 2),
           "E14 carriage is identity-specific (A's stripe 2 under B rejects unless homes coincide)");
        ok(check_roundabout(g, ctx, map, rA0, A, wr).disp == RbDisposition::REJECT_ROUNDABOUT,
           "E15 one wire disposition: REJECT_ROUNDABOUT");
    }

    // ── F: exhaustive admission uniqueness + override ───────────────────────
    {
        rbkat::SplitMix64 r(0xF00D);
        bool uniq = true, none_oob = true;
        for (int i = 0; i < 200; ++i) {
            const bytes32 id = r.key();
            const std::uint32_t n = 1u << r.below(4);
            if (n > 1) map.n[id] = n;
            for (std::uint32_t s = 0; s < n + 2; ++s) {
                int admitted = 0;
                for (RbIndex rb = 0; rb < 4; ++rb) {
                    RbCarriage c{map.epoch, rb, Stripe(s), lane_tag(ctx, map.epoch, rb, Stripe(s))};
                    if (check_roundabout(g, ctx, map, rb, id, c).ok()) ++admitted;
                    if (roundabout_assignment_ok(map, id, Stripe(s), rb) !=
                        check_roundabout(g, ctx, map, rb, id, c).ok()) uniq = false;
                }
                if (s < n && admitted != 1) uniq = false;
                if (s >= n && admitted != 0) none_oob = false;
            }
        }
        ok(uniq, "F1 every (id, s<n) is admitted by exactly one roundabout; predicate == full check");
        ok(none_oob, "F2 no roundabout admits s >= n");
        RbCarriage atOvr{9, ovrA1, 1, lane_tag(ctx, 9, ovrA1, 1)};
        RbCarriage atHome{9, homeA1, 1, lane_tag(ctx, 9, homeA1, 1)};
        ok(check_roundabout(g, ctx, map, ovrA1, A, atOvr).ok(), "F3 override target admits");
        ok(check_roundabout(g, ctx, map, homeA1, A, atHome).reason == RbReason::WRONG_ROUNDABOUT,
           "F4 overridden stripe's home rejects");
    }

    // ── G: gate OFF no-op ───────────────────────────────────────────────────
    {
        const RoundaboutGate off = RoundaboutGate::for_version(1);
        RbCarriage junk{12345, 999, 777, fill(0xEE)};
        ok(check_roundabout(off, ctx, map, 3, A, junk).ok(), "G1 OFF gate: admission is a no-op (byte-identical path)");
    }

    return rbkat::finish("v37_rb_lane_tag_kat");
}
