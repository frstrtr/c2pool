// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_raindrop_enrol_kat -- RAINDROP ENROL (handoff A3, ruling 2026-09-30).
//
// THE GAP. A payee was enrolled for DROPS only at its first LANE SHARE, so a
// miner whose hashes are all raindrops (never a share) was never enrolled and
// its raindrops were never credited. And the ref a DROPS-only payee is paid
// through was node-local (the raindrop the node happened to see), so a node
// that never saw the raindrop could not rebuild an honest block.
//
// THE FIX. The enrolment book of a composition over [lo, hi) takes the
// earliest of (1) the first lane share + 1, (2) the ledger registry
// (finalized + pending enrol_add, committed as "V37G"), (3) the first raindrop
// bin + 1 inside [lo, hi). The new payees of (3) ride the FOUND as enrol_add
// {eff, ref}; the registry ref is ledger state. With the DROPS due or the
// raindrop-enrol rule on, the HELLO enrol digest carries the rule tag, so a
// mixed fleet is refused at HELLO by name. Gate: set_raindrop_enrol (off in
// make_for_test) and OwedLedgerRules::raindrop_enrol (off by default).
//
//   RE1  a raindrop-only miner is enrolled at its first raindrop bin + 1 in
//        [lo, hi), credited (interval b0 is not: ex ante) and recorded in
//        enrol_add with its ref (RED on the base: never enrolled).
//   RE2  three composers, three raindrop arrival orders, one of them missing
//        every raindrop below lo: byte-identical books, deltas, enrol_add and
//        owed_digest; the registry read from pending == from finalized.
//   RE3  V37G only with the rule on; the rule off ignores enrol_add (digest
//        byte-identical); the wiring switch off == the lane-only book; store
//        schema 4 and the carry-store journal round-trip.
//   RE4  the enrol mode applies: List without the payee / None enrol nobody.
//   RE5  HELLO flag day: a different DROPS rule tag is refused BY NAME
//        (DROPS_RULE_MISMATCH); rule 0 (gate OFF) is byte-identical.
//   RE6  a raindrop whose ref payload is over 255 bytes (the V37G length
//        byte) is refused and never enrolled.
#include <algorithm>
#include <cstdio>
#include <cstring>
#include <map>
#include <optional>
#include <random>
#include <set>
#include <string>
#include <vector>

#include "xmr_relay_test_util.hpp"
#include <c2pool/v37/xmr/xmr_drops_wiring.hpp>
#include <c2pool/v37/xmr/xmr_settle_store.hpp>

using namespace gap2test;
namespace dx = ::c2pool::v37n::xmr::drops;
namespace st = ::c2pool::v37n::settle;
namespace rl = ::c2pool::v37n::xmr::relay;

static constexpr std::uint64_t kD = 10;
static constexpr std::uint64_t kShareDiff = 1024;
static constexpr ::v37::ChainId kChainRE = 0x584D52;

struct HNode {   // the XmrNode seam shape
    std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> range;
    void set_drop_harvester(::c2pool::v37n::DropHarvester*) {}
    void set_enrollment_book(const ::c2pool::v37n::EnrollmentBook*) {}
    void set_pre_harvest(std::function<void(std::uint64_t)>) {}
    void set_drops_price_fn(std::function<st::WorkPrice()>) {}
    void set_harvest_range_fn(std::function<std::vector<st::HarvestedReceipt>(std::uint64_t)> f) { range = std::move(f); }
};
static st::WorkPrice price_of(std::uint64_t reward, std::uint64_t n_shares) {
    st::WorkPrice wp; wp.reward = reward;
    const unsigned __int128 s = static_cast<unsigned __int128>(n_shares);
    wp.sum_weight.v[0] = static_cast<std::uint64_t>(s << 62);
    wp.sum_weight.v[1] = static_cast<std::uint64_t>(s >> 2);
    wp.valid = true;
    return dx::rescale_price(wp, 1);
}
static const std::set<std::uint64_t> kLanes = {130, 170};   // range(130) = [0,120), range(170) = [120,160)

static ::v37::ScriptRef ref_of(std::uint8_t seed) {
    std::array<std::uint8_t, 32> b{}, a{};
    for (int i = 0; i < 32; ++i) { b[i] = static_cast<std::uint8_t>(seed + i); a[i] = static_cast<std::uint8_t>(seed * 3 + i); }
    return ::v37::xmr::make_xmr_std(b, a);
}
struct Drop { ::v37::ScriptRef ref; std::uint64_t bin; bytes32 pow; };
struct Share { bytes32 payee; std::uint64_t bin; };
// P, Q share every bin 101..165; X (DROPS-only) raindrops at 112, 115 and 125;
// Y (DROPS-only) raindrops from 150; P and Q raindrops too.
struct World {
    ::v37::ScriptRef rP = ref_of(0x31), rQ = ref_of(0x32), rX = ref_of(0x34), rY = ref_of(0x35);
    bytes32 P = ::v37::xmr::xmr_identity_key(rP), Q = ::v37::xmr::xmr_identity_key(rQ);
    bytes32 X = ::v37::xmr::xmr_identity_key(rX), Y = ::v37::xmr::xmr_identity_key(rY);
    std::vector<Share> shares;
    std::vector<Drop> drops;
    explicit World(std::uint32_t K) {
        std::mt19937_64 rng(0xA3E17011ULL);
        auto rain = [&](const ::v37::ScriptRef& r, std::uint64_t bin) {
            for (std::uint32_t k = 0; k < K + 1; ++k) {
                bytes32 pow{};
                for (int w = 0; w < 4; ++w) { const std::uint64_t v = rng(); std::memcpy(pow.data() + w * 8, &v, 8); }
                pow[31] = static_cast<std::uint8_t>(0x40 + (rng() % 0xC0));   // a raindrop, never a share
                drops.push_back({r, bin, pow});
            }
        };
        for (std::uint64_t bin = 101; bin <= 165; ++bin) {
            shares.push_back({P, bin}); shares.push_back({Q, bin});
            rain(rP, bin); rain(rQ, bin);
        }
        for (std::uint64_t bin : {112, 115, 125}) rain(rX, bin);
        for (std::uint64_t bin : {150, 152}) rain(rY, bin);
    }
};

#if defined(C2POOL_XMR_RAINDROP_ENROL)
#define RE_FIX 1
#else
#define RE_FIX 0
#endif

static const ::v37::LaneParams kParams = ::v37::LaneParams::for_version(1);

static std::unique_ptr<dx::XmrDropsWiring> make_w(HNode& n, bool enrol_on, rl::EnrolMode m = rl::EnrolMode::Auto,
                                                  std::set<bytes32> set = {}) {
    auto w = dx::XmrDropsWiring::make_for_test(kParams.subthreshold.K, kShareDiff, 1);
    w->attach_chain_order(n, kD);
    w->set_prev_lane_fn([](std::uint64_t h) -> std::optional<std::uint64_t> {
        auto it = kLanes.lower_bound(h);
        if (it == kLanes.begin()) return dx::ChainOrderedHarvest::kNoPrevLane;
        return *std::prev(it);
    });
    w->set_enrol_mode(m);
    w->set_enrol_set(std::move(set));
#if RE_FIX
    w->set_raindrop_enrol(enrol_on);
#else
    (void)enrol_on;
#endif
    return w;
}
static void feed(dx::XmrDropsWiring& w, const std::vector<Drop>& drops) {
    for (const auto& d : drops) {
#if RE_FIX
        (void)w.on_raindrop(d.ref, d.bin, d.pow);
#else
        const bytes32 id = ::v37::xmr::xmr_identity_key(d.ref);
        w.note_drop_ref(id, d.ref);
        (void)w.on_raindrop(id, d.bin, d.pow);
#endif
    }
}
#if !RE_FIX
namespace c2pool::v37n::settle { struct DropsEnrolRec { std::uint64_t eff = 0; ::v37::ScriptRef ref; };
                                 using DropsEnrolRegistry = std::map<bytes32, DropsEnrolRec>; }
#endif
struct Out {
    bool ok = false;
    bytes32 digest{};
    std::map<bytes32, long long> delta;
    st::DropsEnrolRegistry add;
    std::size_t rows = 0;
    std::uint64_t effX = 0, effY = 0, effP = 0;
    bool operator==(const Out& o) const {
        bool same_add = add.size() == o.add.size();
        for (auto a = add.begin(), b = o.add.begin(); same_add && a != add.end(); ++a, ++b)
            same_add = a->first == b->first && a->second.eff == b->second.eff && a->second.ref == b->second.ref;
        return ok == o.ok && digest == o.digest && delta == o.delta && same_add && rows == o.rows;
    }
};
static Out compose(dx::XmrDropsWiring& w, const World& W, std::uint64_t h, const st::DropsEnrolRegistry& reg) {
    Out o;
    const auto rg = w.range_for(h);
    if (!rg) return o;
    dx::LanePrefix lp;
    lp.P = W.shares.size();
    for (const auto& s : W.shares) lp.shares.push_back(dx::LaneShare{s.payee, s.bin, 0});
#if RE_FIX
    const auto lc = w.compose_lane(rg->first, rg->second, lp, &reg);
    o.add = lc.enrol_add;
#else
    (void)reg;
    const auto lc = w.compose_lane(rg->first, rg->second, lp);
#endif
    st::DropsCompose dctx; dctx.price = price_of(600000000000ULL, 1000); dctx.enrollment = &lc.book;
    const auto carry = dx::compose_carry(kParams, lc.rows, dctx);
    o.ok = true; o.digest = carry.enrollment_digest; o.delta = carry.delta; o.rows = lc.rows.size();
    if (const auto* r = lc.book.find(W.X)) o.effX = r->effective_from;
    if (const auto* r = lc.book.find(W.Y)) o.effY = r->effective_from;
    if (const auto* r = lc.book.find(W.P)) o.effP = r->effective_from;
    return o;
}
static st::OwedLedgerRules rules(bool enrol) {
    st::OwedLedgerRules r; r.anchor_cut = true; r.drops_due = true;
#if RE_FIX
    r.raindrop_enrol = enrol;
#else
    (void)enrol;
#endif
    return r;
}
static void book(st::OwedLedger& L, const std::string& bid, const Out& o, bool finalize, std::uint64_t bin) {
    st::DropsFound d;
    d.deposit = o.delta;
#if RE_FIX
    d.enrol_add = o.add;
#endif
    L.on_block_found(bid, {}, {}, std::nullopt, &d);
    if (finalize) L.on_block_finalized(bid, bin);
}
static st::DropsEnrolRegistry registry_of(const st::OwedLedger& L) {
#if RE_FIX
    return L.drops_enrol_registry();
#else
    (void)L; return {};
#endif
}
static long long at(const std::map<bytes32, long long>& m, const bytes32& k) { auto it = m.find(k); return it == m.end() ? 0 : it->second; }

// RE1: a raindrop-only miner is enrolled at its first raindrop bin + 1 in [lo, hi) and credited.
static void re1_unit(Checker& C, const World& W) {
    std::printf("== RE1. a raindrop-only miner is enrolled at first raindrop bin + 1 and credited ==\n");
    HNode n; auto w = make_w(n, true);
    feed(*w, W.drops);
    const Out o = compose(*w, W, 130, {});   // range [0,120): X raindrops at 112, 115
    std::printf("    h=130 rows=%zu effX=%llu delta[X]=%lld enrol_add=%zu digest=%s\n", o.rows, (unsigned long long)o.effX,
                at(o.delta, W.X), o.add.size(), hex(o.digest).substr(0, 16).c_str());
    C(o.ok, "RE1 the composition of h=130 over [0,120) is decidable");
    C(o.effX == 113, "RE1 X (no lane share) is enrolled effective from its first raindrop bin 112 + 1 = 113");
    C(at(o.delta, W.X) > 0, "RE1 X's raindrop at 115 (>= 113) is CREDITED: delta[X] > 0");
    C(o.effP == 102, "RE1 P keeps its lane-share enrolment (first share 101 + 1): min(share, raindrop) = 102");
    const auto ax = o.add.find(W.X);
    C(ax != o.add.end() && ax->second.eff == 113 && ax->second.ref == W.rX,
      "RE1 enrol_add carries X {eff 113, the ref its raindrop named}");
    C(o.add.find(W.Y) == o.add.end(), "RE1 Y (raindrops only from 150, outside [0,120)) is not enrolled yet");
    // ex ante: interval 112 alone (X's first raindrop) is never credited
    HNode n2; auto w2 = make_w(n2, true);
    std::vector<Drop> only112;
    for (const auto& d : W.drops) if (!(d.ref == W.rX) || d.bin == 112) only112.push_back(d);
    feed(*w2, only112);
    const Out o2 = compose(*w2, W, 130, {});
    C(o2.effX == 113 && at(o2.delta, W.X) == 0, "RE1 ex ante: the enrolling raindrop's own interval 112 earns nothing");
}

// RE2: three composers, three arrival orders, one without the raindrops below lo.
static void re2_determinism(Checker& C, const World& W) {
    std::printf("== RE2. three composers: same book, delta, enrol_add and owed_digest in any arrival order ==\n");
    HNode n[3];
    std::unique_ptr<dx::XmrDropsWiring> w[3];
    std::vector<st::OwedLedger> L;
    for (int i = 0; i < 3; ++i) { w[i] = make_w(n[i], true); L.emplace_back(kChainRE, rules(true)); }
    for (int i = 0; i < 3; ++i) {
        std::vector<Drop> d = W.drops;
        if (i == 1) std::reverse(d.begin(), d.end());
        if (i == 2) std::shuffle(d.begin(), d.end(), std::mt19937_64(0xD1CEULL));
        feed(*w[i], d);
    }
    Out o130[3];
    for (int i = 0; i < 3; ++i) o130[i] = compose(*w[i], W, 130, registry_of(L[i]));
    C(o130[0] == o130[1] && o130[0] == o130[2], "RE2 h=130: byte-identical book digest, delta and enrol_add on 3 nodes");
    // h=130 pending on every ledger: the registry read from PENDING
    for (int i = 0; i < 3; ++i) book(L[i], "lane-130", o130[i], false, 0);
    // a late joiner: node 3 has only the raindrops at or above lo = 120 (and never saw X's raindrops)
    HNode n3; auto w3 = make_w(n3, true);
    std::vector<Drop> late; for (const auto& d : W.drops) if (d.bin >= 120) late.push_back(d);
    feed(*w3, late);
    const Out pend0 = compose(*w[0], W, 170, registry_of(L[0]));
    for (int i = 0; i < 3; ++i) L[i].on_block_finalized("lane-130", 130);
    Out o170[3];
    for (int i = 0; i < 3; ++i) o170[i] = compose(*w[i], W, 170, registry_of(L[i]));
    st::OwedLedger L3 = L[0];   // the replicated ledger the late joiner holds
    const Out olate = compose(*w3, W, 170, registry_of(L3));
    std::printf("    h=170 effX=%llu effY=%llu enrol_add=%zu delta[X]=%lld late delta[X]=%lld\n", (unsigned long long)o170[0].effX,
                (unsigned long long)o170[0].effY, o170[0].add.size(), at(o170[0].delta, W.X), at(olate.delta, W.X));
    C(o170[0] == o170[1] && o170[0] == o170[2], "RE2 h=170: byte-identical on 3 nodes (registry from the finalized ledger)");
    C(pend0 == o170[0], "RE2 the registry read from the PENDING row composes the same as from the finalized one");
    C(olate == o170[0], "RE2 the late joiner (no raindrop below lo, never saw X's first raindrops) composes the same");
    C(o170[0].effX == 113 && at(o170[0].delta, W.X) > 0, "RE2 X stays enrolled from 113 through the registry; its raindrop at 125 is credited");
    C(o170[0].add.count(W.X) == 0 && o170[0].add.count(W.Y) == 1 && o170[0].effY == 151,
      "RE2 enrol_add at h=170 holds only the NEW payee Y (first raindrop 150 + 1)");
    for (int i = 0; i < 3; ++i) book(L[i], "lane-170", o170[i], true, 170);
    const bytes32 d0 = L[0].owed_digest();
    C(d0 == L[1].owed_digest() && d0 == L[2].owed_digest(), "RE2 one owed_digest on 3 nodes after both blocks finalize");
    const auto reg = registry_of(L[0]);
    C(reg.count(W.X) && reg.at(W.X).eff == 113 && reg.at(W.X).ref == W.rX && reg.count(W.Y) && reg.at(W.Y).ref == W.rY,
      "RE2 the finalized registry holds X@113 and Y@151 with their refs");
    std::printf("    owed_digest=%s registry=%zu\n", hex(d0).substr(0, 16).c_str(), reg.size());
}

// RE3: V37G only with the rule on; the switch off keeps the lane-only book; persistence round-trips.
static void re3_gate(Checker& C, const World& W) {
    std::printf("== RE3. V37G only with the rule on; gate off byte-identical; store + journal round-trip ==\n");
    HNode n; auto w = make_w(n, true);
    feed(*w, W.drops);
    const Out o = compose(*w, W, 130, {});
    st::OwedLedger off(kChainRE, rules(false)), off_plain(kChainRE, rules(false)), on(kChainRE, rules(true));
    const bytes32 e_off = off.owed_digest(), e_on = on.owed_digest();
    C(!(e_off == e_on), "RE3 rule ON: the empty ledger commits the V37G section (digest differs from rule OFF)");
    book(off, "b", o, true, 130);
    Out no_add = o; no_add.add.clear();
    book(off_plain, "b", no_add, true, 130);
    C(off.owed_digest() == off_plain.owed_digest(), "RE3 rule OFF: enrol_add is ignored (owed_digest byte-identical)");
    C(registry_of(off).empty(), "RE3 rule OFF: no registry");
    const bytes32 before = on.owed_digest();
    book(on, "b", o, false, 0);
    C(on.owed_digest() == before, "RE3 rule ON: a PENDING enrol_add is not in owed_digest (V37G commits the finalized registry)");
    on.on_block_finalized("b", 130);
    st::OwedLedger on2(kChainRE, rules(true));
    book(on2, "b", no_add, true, 130);
    C(!(on.owed_digest() == on2.owed_digest()), "RE3 rule ON: the finalized registry moves owed_digest");
    // ORPHAN before FINALIZE releases the enrolments
    st::OwedLedger orph(kChainRE, rules(true));
    book(orph, "o", o, false, 0);
    const bool had = registry_of(orph).count(W.X) == 1;
    orph.on_block_orphaned("o", {});
    C(had && registry_of(orph).empty() && orph.owed_digest() == e_on, "RE3 ORPHAN before FINALIZE releases enrol_add (registry empty again)");
    // the wiring switch off (make_for_test default) == the lane-only book, no enrol_add
    HNode nf; auto wf = make_w(nf, false);
    feed(*wf, W.drops);
    const Out of = compose(*wf, W, 130, registry_of(on));
    const auto lane_only = dx::lane_enrollment(dx::LanePrefix{W.shares.size(), [&] {
        std::vector<dx::LaneShare> v; for (const auto& s : W.shares) v.push_back(dx::LaneShare{s.payee, s.bin, 0}); return v; }()},
        {}, rl::EnrolMode::Auto);
    C(of.digest == lane_only.book_digest() && of.add.empty() && of.effX == 0,
      "RE3 set_raindrop_enrol OFF: the book is the lane-only book (digest byte-identical), nothing enrolled by raindrop");
#if RE_FIX
    // settle store round-trip (RULES RATCHET R1: every record is ver 7; an empty enrol_add reads back empty)
    namespace xs = ::c2pool::v37n::xmr;
    xs::SettleEvent e; e.kind = xs::SettleEvKind::Found; e.bid = "b";
    st::DropsFound d; d.deposit = o.delta; d.enrol_add = o.add;
    xs::set_drops(e, d);
    const std::string blob = e.serialize();
    const auto back = xs::drops_of(xs::SettleEvent::deserialize(blob));
    C(blob[0] == 7 && back && back->enrol_add == o.add, "RE3 settle store (ver 7) carries enrol_add {eff, ref} and round-trips");
    d.enrol_add.clear(); xs::set_drops(e, d);
    { const auto back0 = xs::drops_of(xs::SettleEvent::deserialize(e.serialize()));
      C(e.serialize()[0] == 7 && back0 && back0->enrol_add.empty(), "RE3 settle store: no enrol_add -> ver 7, an empty registry section reads back"); }
    // the carry-store journal (G record) round-trips
    const std::string path = "/tmp/v37_xmr_raindrop_enrol_kat." + std::to_string(::getpid()) + ".drops";
    std::remove(path.c_str());
    { dx::DropsCarryStore s(path); s.put_booked(std::string(64, 'a'), o.delta); s.put_enrol(std::string(64, 'a'), o.add); }
    dx::DropsCarryStore s2(path);
    const auto ld = s2.load();
    C(ld.malformed == 0 && s2.enrol(std::string(64, 'a')) == o.add, "RE3 carry store: the G record reloads the same enrol_add");
    std::remove(path.c_str());
#else
    C(false, "RE3 settle store schema 4 (absent on the base)");
    C(false, "RE3 carry store G record (absent on the base)");
#endif
}

// RE4: the enrol mode applies to the raindrop rule too.
static void re4_modes(Checker& C, const World& W) {
    std::printf("== RE4. List / None modes ==\n");
    HNode a; auto wl = make_w(a, true, rl::EnrolMode::List, {W.P});
    feed(*wl, W.drops);
    const Out ol = compose(*wl, W, 130, {});
    C(ol.effX == 0 && ol.add.count(W.X) == 0 && ol.effP == 102, "RE4 List {P}: X is not enrolled by its raindrops; P is");
    HNode b; auto wn = make_w(b, true, rl::EnrolMode::None);
    feed(*wn, W.drops);
    const Out on = compose(*wn, W, 130, {});
    C(on.effX == 0 && on.effP == 0 && on.add.empty() && on.delta.empty(), "RE4 None: nobody is enrolled, nothing composed");
    HNode c; auto wa = make_w(c, true, rl::EnrolMode::List, {W.P, W.X});
    feed(*wa, W.drops);
    const Out oa = compose(*wa, W, 130, {});
    C(oa.effX == 113 && oa.add.count(W.X) == 1, "RE4 List {P, X}: X is enrolled at its first raindrop + 1");
}

// RE5: the A3 + A5 flag day at HELLO.
static rl::Hello hello_with(const bytes32& enrol, std::uint64_t nonce) {
    rl::Hello h;
    h.network = 3; h.chain_id = kChainRE; h.share_diff = kShareDiff; h.node_nonce = nonce;
    const bytes32 lpd = rl::lane_params_digest(kParams, kShareDiff, rl::BindMode::None, 3);
    h.lane_params_digest = lpd;
    rl::PoolId id; id.lane_tag = b32_of(0x77); id.version = 3; id.genesis = b32_of(0x78);
    h.pool = id;
    h.enrol_set = enrol;
    return h;
}
static void re5_hello(Checker& C) {
    std::printf("== RE5. HELLO: a different DROPS rule is refused by name; gate OFF byte-identical ==\n");
    const bytes32 lpd = rl::lane_params_digest(kParams, kShareDiff, rl::BindMode::None, 3);
    const bytes32 v1_auto = dx::enrol_mode_digest(rl::EnrolMode::Auto, {});
    const bytes32 v1_hello = dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {});
    std::printf("    gate-OFF enrol digest=%s hello lane_params_digest=%s\n", hex(v1_auto).c_str(), hex(v1_hello).c_str());
    C(v1_auto == rl::enrol_mode_tag(rl::EnrolMode::Auto), "RE5 rule 0: the enrol digest is the v1 mode tag (byte-identical)");
#if RE_FIX
    const std::uint32_t full = rl::drops_rule_tag(true, true), due_only = rl::drops_rule_tag(true, false);
    C(full == 3 && due_only == 1 && rl::drops_rule_tag(false, false) == 0, "RE5 rule tags: due = 1, due + raindrop-enrol = 3, off = 0");
    C(dx::enrol_mode_digest(rl::EnrolMode::Auto, {}, 0) == v1_auto && dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {}, 0) == v1_hello,
      "RE5 rule 0 (gate OFF): enrol digest and HELLO digest byte-identical to the untagged v1");
    const bytes32 v2 = dx::enrol_mode_digest(rl::EnrolMode::Auto, {}, full);
    C(!(v2 == v1_auto) && rl::enrol_rule_of(v2) == full && rl::enrol_rule_of(v1_auto) == 0,
      "RE5 rule ON: the enrol digest is tagged and the peer's rule reads back from it");
    C(!(dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {}, full) == v1_hello), "RE5 rule ON: the HELLO lane digest moves (a mixed fleet never folds)");
    rl::Hello ours = hello_with(v2, 1);
    ours.lane_params_digest = dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {}, full);
    std::vector<rl::Hello> peers;
    rl::Hello pre = hello_with(v1_auto, 2); pre.lane_params_digest = v1_hello; peers.push_back(pre);   // an e4ce78d6b node
    rl::Hello due = hello_with(dx::enrol_mode_digest(rl::EnrolMode::Auto, {}, due_only), 3);
    due.lane_params_digest = dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {}, due_only); peers.push_back(due);
    rl::Hello same = hello_with(v2, 4); same.lane_params_digest = ours.lane_params_digest;
    std::size_t refused = 0, named = 0;
    for (const auto& p : peers) {
        const std::string why = rl::hello_mismatch(ours, p);
        std::printf("    peer rule=%u -> %s\n", rl::enrol_rule_of(*p.enrol_set), why.c_str());
        if (!why.empty()) ++refused;
        if (why.rfind(rl::kDropsRuleMismatch, 0) == 0) ++named;
        // and the other direction
        const std::string back = rl::hello_mismatch(p, ours);
        if (!back.empty()) ++refused;
        if (back.rfind(rl::kDropsRuleMismatch, 0) == 0) ++named;
    }
    std::printf("    mismatched-rule HELLOs: refused=%zu named DROPS_RULE_MISMATCH=%zu of 4\n", refused, named);
    C(refused == 4 && named == 4, "RE5 a peer with another DROPS rule is refused at HELLO BY NAME, both directions (4/4)");
    C(rl::hello_mismatch(ours, same).empty(), "RE5 a peer with the same rule is accepted");
#if defined(C2POOL_XMR_DROPS_WINDOW)
    {   // A4b: the window rule rides the same tag (bit 4): a fleet mixing tag 3 and tag 7 is refused BY NAME
        const std::uint32_t win = rl::drops_rule_tag(true, true, true);
        rl::Hello wp = hello_with(dx::enrol_mode_digest(rl::EnrolMode::Auto, {}, win), 6);
        wp.lane_params_digest = dx::hello_digest_with_enrol(lpd, rl::EnrolMode::Auto, {}, win);
        const std::string a = rl::hello_mismatch(ours, wp), b = rl::hello_mismatch(wp, ours);
        std::printf("    window peer rule=%u -> %s\n", win, a.c_str());
        C(win == 7 && a.rfind(rl::kDropsRuleMismatch, 0) == 0 && b.rfind(rl::kDropsRuleMismatch, 0) == 0 &&
          a.find("window") != std::string::npos,
          "RE5 A4b: the window rule is tag 7; a tag-3 / tag-7 fleet is refused BY NAME both ways (window named)");
        const char* flag_day = "every node of a pool must run the same DROPS due / raindrop-enrol / window rules";
        C(a.find(flag_day) != std::string::npos && b.find(flag_day) != std::string::npos,
          "RE5 A4c: the flag-day text names the window rule too (both ways)");
    }
#endif
    rl::Hello list_other = hello_with(dx::enrol_mode_digest(rl::EnrolMode::List, {b32_of(1)}, full), 5);
    list_other.lane_params_digest = dx::hello_digest_with_enrol(lpd, rl::EnrolMode::List, {b32_of(1)}, full);
    C(rl::hello_mismatch(ours, list_other).rfind(rl::kEnrolSetMismatch, 0) == 0,
      "RE5 same rule, another enrol mode/set: still ENROL_SET_MISMATCH");
#else
    C(false, "RE5 drops rule tag at HELLO (absent on the base: a mixed fleet is refused only by lane roots)");
#endif
}

// RE6: the V37G record carries a ref's length in one byte; a longer ref is refused at the raindrop.
static void re6_ref_bound(Checker& C, const World& W) {
    std::printf("== RE6. a raindrop ref over 255 bytes is refused (the V37G length byte stays unambiguous) ==\n");
#if RE_FIX
    HNode n; auto w = make_w(n, true);
    feed(*w, W.drops);
    ::v37::ScriptRef big = W.rX;
    big.payload.assign(300, 0x5a);
    const bytes32 Z = ::v37::xmr::xmr_identity_key(big);
    std::size_t taken = 0;
    for (const auto& d : W.drops) if (d.ref == W.rX) taken += w->on_raindrop(big, d.bin, d.pow) ? 1 : 0;
    const Out o = compose(*w, W, 130, {});
    bool short_refs = true;
    for (const auto& [k, r] : o.add) { (void)k; short_refs = short_refs && r.ref.payload.size() <= 255; }
    std::printf("    long-ref raindrops taken=%zu enrol_add=%zu\n", taken, o.add.size());
    C(taken == 0, "RE6 on_raindrop refuses every raindrop whose ref payload exceeds 255 bytes");
    C(o.add.count(Z) == 0 && short_refs, "RE6 the long-ref payee is never in enrol_add; every enrolled ref fits the length byte");
    C(o.effX == 113, "RE6 the short-ref payee X is enrolled as before");
#else
    (void)W;
    C(false, "RE6 ref bound (absent on the base)");
#endif
}

int main() {
    Checker C;
    const World W(kParams.subthreshold.K);
    re1_unit(C, W);
    re2_determinism(C, W);
    re3_gate(C, W);
    re4_modes(C, W);
    re5_hello(C);
    re6_ref_bound(C, W);
    return C.done("v37_xmr_raindrop_enrol_kat");
}
