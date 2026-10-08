// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
// ---------------------------------------------------------------------------
// v37_xmr_pathb_bucket_wire_kat (pathb_bucket_wire.hpp; ruling 31 P-7; E-8,
// E-9; C25, C27, C43):
//   codec   FC_GETBUCKETS 54 B and FC_BUCKETS round trips; the not-served
//           frame (187 B); every byte refusal; S (134 B) decode; P-14 / P-39 /
//           P-41 / P-42 defaults.
//   honest  the dense FR-B1 chain (3 leaves at H = b0 + 98) served from the
//           bin store and verified: the leaves, the root, the empty leaf, the
//           references, S adopted once at's carried ids are held; the FR-B1
//           golden payloads (root dc6ff5da...) through the proof check.
//   lying   wrong leaf_count; a bucket subset (a bin skipped, a row
//           withheld); a forged sum in a row (rows only, and with the payload
//           recomputed); a wrong key reference (missing, stray, out of order,
//           not a point); proofs against the wrong prefix root (peaks, path);
//           the shifted index; a two-bin leaf; rows_total above raw_sum /
//           d_min (no row allocated); S_parent with one byte changed (pending,
//           then struck; refused when at's body is held).
//   paging  a 5-row bin over 3 pages reassembled; a missing page asked from a
//           second server; pages out of order; every frame within the buffer
//           for a range of buffers.
//   serving `at` off the best chain, unknown, without S -> n = 0 (no strike);
//           an ancestor of the tip served; a prefix up to the first bin
//           without its references; a joiner's prefix MMR serves only leaves
//           after its prefix; the per-peer budget (in flight, bytes per minute).
// ---------------------------------------------------------------------------
#include <algorithm>
#include <array>
#include <cstdint>
#include <exception>
#include <stdexcept>
#include <optional>
#include <string>
#include <vector>

#include "impl/xmr/pathb/pathb_bin_store.hpp"
#include "impl/xmr/pathb/pathb_bucket_wire.hpp"
#include "impl/xmr/pathb/pathb_buckets.hpp"
#include "impl/xmr/pathb/pathb_lane_rules.hpp"
#include "pathb_kat_bodies.hpp"
#include "pathb_kat_check.hpp"

using namespace pathb_kat;
namespace pb = ::c2pool::xmr::pathb;

namespace {

constexpr std::uint64_t kB0 = 3500000;
constexpr std::uint32_t kChain = 7;
const pb::LaneParams P = pb::kRuledLaneParams;
const std::uint64_t F = P.open_bins;
constexpr std::uint64_t kServerA = 1;
constexpr std::uint64_t kServerB = 2;
const std::uint64_t kFrame = pb::bucket_wire_policy_default(16, pb::zone(16))->frame_bytes;

pb::Hash32 rep(std::uint8_t b) {
    pb::Hash32 h{};
    h.fill(b);
    return h;
}

std::string hx(const pb::Hash32& h) { return hex(h.data(), h.size()); }

pb::Hash32 cid(std::uint8_t tag, std::uint64_t n) {
    pb::Hash32 h{};
    h[0] = tag;
    for (int i = 0; i < 8; ++i) h[1 + i] = static_cast<std::uint8_t>(n >> (8 * i));
    return h;
}

// A placement of `ref` in bin `bin` (own position p_own), optionally with an owner share.
pb::Placement rc(std::uint64_t n, std::uint64_t bin, std::uint64_t p_own, const pb::XmrKeyRef& ref, std::uint64_t work,
                 std::optional<pb::XmrKeyRef> owner = std::nullopt, std::uint16_t p = 0, bool with_ref = true) {
    pb::Placement x;
    x.id = cid(0xEE, n);
    x.bin = bin;
    x.p_own = p_own;
    x.payee = pb::key_ref_identity(ref);
    if (with_ref) x.payee_ref = ref;
    x.work = work;
    if (owner) {
        x.owner = pb::key_ref_identity(*owner);
        x.owner_ref = *owner;
        x.p = p;
    }
    return x;
}

bool step(pb::BinStore& s, const pb::Hash32& id, const pb::Hash32& parent, std::uint64_t h,
          const std::vector<pb::Placement>& pls, bool best = true) {
    bool ok = s.add_carrier(id, parent, h) == pb::AddVerdict::Added;
    for (const pb::Placement& x : pls) ok = ok && s.ingest(id, x) == pb::Ingest::Accepted;
    ok = ok && s.seal(id).has_value();
    if (best) ok = ok && s.switch_best(id) == pb::SwitchVerdict::Switched;
    return ok;
}

// The ratchet state at `at`'s parent and at's carried ids / receipts_root.
pb::RatchetState s_at() {
    pb::RatchetState s = pb::genesis_ratchet_state(pb::kGenesisRulesDigestMainnet);
    s.all = pb::RsWork(36360);
    s.levels = {0, 1, 0, 2};
    return s;
}
const pb::RatchetStateBytes kS = pb::encode_ratchet_state(s_at());
const std::vector<pb::Hash32> kCarried{seq32(0x90), seq32(0xB0)};

pb::BucketsAnchor anchor_of(const pb::BinStore& s, const pb::Hash32& at, bool with_ids = false) {
    const pb::LaneView v = s.view_at(at);
    pb::BucketsAnchor a;
    a.header_held = true;
    a.record = v.record(v.pos());
    a.mmr_root = v.mmr_root();
    a.receipts_root = pb::carrier_receipts_root_over(kCarried, s_at());
    if (with_ids) a.carried_ids = kCarried;
    return a;
}

bool refused(const pb::FrameOutcome& o, pb::BucketsFault f) {
    return o.verdict == pb::FrameVerdict::Refused && o.fault == f && o.strike == 1;
}

pb::FrameOutcome one(const pb::GetBuckets& q, const std::vector<std::uint8_t>& f, const pb::BucketsAnchor& a,
                     std::uint64_t frame_bytes = 0) {
    pb::BucketsAssembly as(q, kB0, F, frame_bytes ? frame_bytes : kFrame);
    return as.add_frame(kServerA, f, a);
}

pb::BucketsReply dec(const std::vector<std::uint8_t>& f) {
    pb::BucketsReply r;
    if (pb::decode_buckets(f, kChain, r) != pb::BucketsWireError::None) throw std::runtime_error("decode");
    return r;
}

std::vector<std::uint8_t> enc(const pb::BucketsReply& r) {
    const std::optional<std::vector<std::uint8_t>> b = pb::encode_buckets(r);
    if (!b) throw std::runtime_error("encode");
    return *b;
}

// A keyed bucket: one row per (ref, work), miner = key_ref_identity(ref).
pb::L1Bucket keyed_bin(std::uint64_t bin, const std::vector<std::pair<pb::XmrKeyRef, std::uint64_t>>& rows) {
    std::vector<pb::WinEntry> es;
    for (const auto& [ref, work] : rows) {
        pb::WinEntry e;
        e.miner = pb::key_ref_identity(ref);
        e.work = work;
        es.push_back(e);
    }
    return pb::seal_from_entries(bin, es);
}

// A committed MMR over hand-made leaves (a forged `at` in the KAT): the anchor
// commits its root at leaf_count = the number of leaves.
struct Forged {
    pb::BinMmr mmr;
    std::vector<pb::L1Bucket> bins;
    pb::BucketsAnchor anchor;
};

Forged forge(const std::vector<pb::L1Bucket>& bins) {
    Forged f;
    for (const pb::L1Bucket& b : bins) f.mmr.append(pb::mmr_leaf_of(b));
    f.bins = bins;
    f.anchor.header_held = true;
    f.anchor.record = kB0 + F - 1 + bins.size();
    f.anchor.mmr_root = f.mmr.root();
    return f;
}

pb::BucketEntry entry_of(const Forged& f, std::size_t i) {
    pb::BucketEntry e;
    e.payload = f.bins[i];
    e.payload.rows.clear();
    e.rows = f.bins[i].rows;
    e.rows_total = static_cast<std::uint32_t>(e.rows.size());
    const std::optional<pb::MmrProof> pr = f.mmr.prefix_proof(i, f.mmr.leaf_count());
    for (const auto& st : pr->path) e.path.push_back(st.first);
    return e;
}

pb::BucketsReply reply_of(const Forged& f, const pb::Hash32& at, std::size_t first, std::size_t count,
                          const std::vector<pb::XmrKeyRef>& refs) {
    pb::BucketsReply r;
    r.chain_id = kChain;
    r.at = at;
    r.leaf_count = f.mmr.leaf_count();
    r.peaks = f.mmr.peaks();
    r.s_parent = kS;
    r.refs = refs;
    for (std::size_t i = first; i < first + count; ++i) r.entries.push_back(entry_of(f, i));
    return r;
}

std::vector<pb::XmrKeyRef> sorted_refs(std::vector<pb::XmrKeyRef> refs) {
    std::sort(refs.begin(), refs.end(), [](const pb::XmrKeyRef& a, const pb::XmrKeyRef& b) {
        return pb::key_ref_identity(a) < pb::key_ref_identity(b);
    });
    return refs;
}

template <class Body>
void run_part(const char* name, Body&& body) {
    try {
        body();
    } catch (const std::exception& e) {
        check(false, std::string(name) + ": exception " + e.what());
    }
}

// ---------------------------------------------------------------------------
// The chains
// ---------------------------------------------------------------------------
const pb::XmrKeyRef ka = key_ref(0x10), kb = key_ref(0x30), kc = key_ref(0x50), kd = key_ref(0x70),
                    ke = key_ref(0x90), kf = key_ref(0xB0), ko = key_ref(0xD0), kz = key_ref(0xF0);

// A: the FR-B1 shape with a keyed identity: one receipt in b0 and in b0 + 2,
// none in b0 + 1; the record reaches b0 + 98 at c3 (3 leaves), b0 + 100 at c5.
struct ChainA {
    pb::BinStore s{P, 64, cid(0x40, 0), kB0, kChain};
    bool ok = true;
    ChainA() {
        ok = ok && step(s, cid(0x40, 1), cid(0x40, 0), kB0, {rc(1, kB0, 1, ka, 18180)});
        ok = ok && step(s, cid(0x40, 2), cid(0x40, 1), kB0 + 2, {rc(2, kB0 + 2, 2, ka, 18180)});
        ok = ok && step(s, cid(0x40, 3), cid(0x40, 2), kB0 + 98, {});
    }
    void extend() {
        ok = ok && step(s, cid(0x40, 4), cid(0x40, 3), kB0 + 99, {});
        ok = ok && step(s, cid(0x40, 5), cid(0x40, 4), kB0 + 100, {});
    }
};

// R: bin b0 holds five payees (one row each), bin b0 + 1 one payee with an
// owner share; the record reaches b0 + 97 at r3 (2 leaves).
struct ChainR {
    pb::BinStore s{P, 64, cid(0x50, 0), kB0, kChain};
    bool ok = true;
    explicit ChainR(bool kf_ref = true) {
        ok = ok && step(s, cid(0x50, 1), cid(0x50, 0), kB0,
                        {rc(11, kB0, 1, ka, 30000), rc(12, kB0, 1, kb, 20000), rc(13, kB0, 1, kc, 25000),
                         rc(14, kB0, 1, kd, 18180), rc(15, kB0, 1, ke, 40000)});
        ok = ok && step(s, cid(0x50, 2), cid(0x50, 1), kB0 + 1, {rc(16, kB0 + 1, 2, kf, 50000, ko, 1000, kf_ref)});
        ok = ok && step(s, cid(0x50, 3), cid(0x50, 2), kB0 + 97, {});
    }
};

// ---------------------------------------------------------------------------
// codec
// ---------------------------------------------------------------------------
void codec_vectors() {
    const pb::GetBuckets q{kChain, seq32(0x20), kB0, kB0 + 2};
    const std::vector<std::uint8_t> qb = *pb::encode_getbuckets(q);
    check(qb.size() == 54 && qb[0] == 0x54 && qb[1] == 1 && qb[2] == 7 && qb[3] == 0 && qb[6] == 0x20 &&
                  qb[38] == static_cast<std::uint8_t>(kB0) && qb[46] == static_cast<std::uint8_t>(kB0 + 2),
          "FC_GETBUCKETS = FH(0x54, 1, chain LE) | at | LE64 bin_lo | LE64 bin_hi (54 B)");
    pb::GetBuckets qd;
    check(pb::decode_getbuckets(qb, kChain, qd) == pb::BucketsWireError::None && qd == q, "FC_GETBUCKETS round trip");
    check(!pb::encode_getbuckets(pb::GetBuckets{kChain, seq32(0x20), kB0 + 2, kB0}).has_value(),
          "FC_GETBUCKETS bin_lo > bin_hi not encoded");
    {
        std::vector<std::uint8_t> sw = qb;
        std::swap_ranges(sw.begin() + 38, sw.begin() + 46, sw.begin() + 46);
        check(pb::decode_getbuckets(sw, kChain, qd) == pb::BucketsWireError::BinRange,
              "FC_GETBUCKETS bin_lo > bin_hi refused");
        std::vector<std::uint8_t> op = qb, ver = qb, tr(qb.begin(), qb.end() - 1), tl = qb;
        op[0] = 0x55;
        ver[1] = 2;
        tl.push_back(0);
        check(pb::decode_getbuckets(op, kChain, qd) == pb::BucketsWireError::Opcode &&
                      pb::decode_getbuckets(ver, kChain, qd) == pb::BucketsWireError::Version &&
                      pb::decode_getbuckets(qb, kChain + 1, qd) == pb::BucketsWireError::ChainId &&
                      pb::decode_getbuckets(tr, kChain, qd) == pb::BucketsWireError::Truncated &&
                      pb::decode_getbuckets(tl, kChain, qd) == pb::BucketsWireError::Trailing,
              "FC_GETBUCKETS: opcode, version, chain_id, 53 B, 55 B refused");
    }

    // FC_BUCKETS from the FR-B1 chain
    ChainA a;
    const pb::GetBuckets req{kChain, cid(0x40, 3), kB0, kB0 + 2};
    const std::vector<std::vector<std::uint8_t>> fr = pb::serve_buckets(a.s, req, kS, kFrame);
    check(a.ok && fr.size() == 1, "FR-B1 chain: one FC_BUCKETS frame");
    const std::vector<std::uint8_t>& f = fr.at(0);
    const pb::BucketsReply r = dec(f);
    check(enc(r) == f, "FC_BUCKETS decode -> encode reproduces the bytes");
    check(f[0] == 0x55 && f[1] == 1 && r.leaf_count == 3 && r.peaks.size() == 2 && r.refs.size() == 1 &&
                  r.entries.size() == 3 && r.s_parent == kS,
          "FC_BUCKETS fields: leaf_count 3, 2 peaks, 1 reference, 3 entries, S");
    // offsets: n_peaks at 46; peaks 47..110; S 111..244; n_refs 245; first reference 249
    check(f[46] == 2 && f[245] == 1 && f[249] == pb::kPayeeKindXmrStd && f[250] == 64,
          "FC_BUCKETS offsets: n_peaks 46, n_refs 245, reference kind / len 249 / 250");
    const std::size_t expect = 187 + 2 * 32 + 66 + 3 * 107 + 2 * 160 + (1 + 1 + 0) * 32;
    check(f.size() == expect, "FC_BUCKETS size = 187 + peaks + references + entries (" + std::to_string(f.size()) + ")");
    const std::vector<std::uint8_t> ns = pb::encode_buckets_not_served(kChain, req.at);
    const pb::BucketsReply nsr = dec(ns);
    check(ns.size() == 187 && nsr.leaf_count == 0 && nsr.peaks.empty() && nsr.entries.empty() && nsr.refs.empty() &&
                  nsr.s_parent == pb::RatchetStateBytes{},
          "not served: 187 B, leaf_count 0, no peaks, S zero, no references, n 0");

    pb::BucketsFrameView v;
    const auto derr = [&](std::vector<std::uint8_t> b, std::uint32_t chain = kChain) {
        return pb::decode_buckets_view(b, chain, v);
    };
    std::vector<std::uint8_t> b;
    b = f, b[0] = 0x54;
    check(derr(b) == pb::BucketsWireError::Opcode, "FC_BUCKETS another opcode refused");
    b = f, b[1] = 2;
    check(derr(b) == pb::BucketsWireError::Version, "FC_BUCKETS frame version 2 refused");
    check(derr(f, kChain + 1) == pb::BucketsWireError::ChainId, "FC_BUCKETS another chain_id refused");
    b = f, b[46] = 3;
    check(derr(b) == pb::BucketsWireError::PeakCount, "FC_BUCKETS n_peaks != popcount(leaf_count) refused");
    b.assign(f.begin(), f.end() - 1);
    check(derr(b) == pb::BucketsWireError::Truncated, "FC_BUCKETS one byte short refused");
    b = f, b.push_back(0);
    check(derr(b) == pb::BucketsWireError::Trailing, "FC_BUCKETS a trailing byte refused");
    b = f, b[249] = 0x11;
    check(derr(b) == pb::BucketsWireError::RefKind, "FC_BUCKETS reference kind other than XMR_STD refused");
    b = f, b[250] = 63;
    check(derr(b) == pb::BucketsWireError::RefLength, "FC_BUCKETS reference len 63 refused");
    // the not-served frame cut after n_refs = 2^32 - 1 (n_refs at 181)
    b.assign(ns.begin(), ns.begin() + 185);
    b[181] = b[182] = b[183] = b[184] = 0xff;
    check(derr(b) == pb::BucketsWireError::Truncated && v.refs.empty(),
          "FC_BUCKETS n_refs 2^32 - 1 with no bytes after it: refused as truncated, nothing allocated");
    // the first entry's n_rows (after the reference table and u16 n)
    const std::size_t e0 = 249 + 66 + 2;
    b = f, b[e0 + 96 + 8] = 0xff, b[e0 + 96 + 9] = 0xff;
    check(derr(b) == pb::BucketsWireError::Truncated, "FC_BUCKETS entry n_rows 65535 refused as truncated");

    // the 134-byte ratchet state
    std::array<std::uint8_t, 134> sb{};
    for (std::size_t i = 0; i < sb.size(); ++i) sb[i] = static_cast<std::uint8_t>(i * 7 + 3);
    check(pb::encode_ratchet_state(pb::decode_ratchet_state(sb)) == sb && pb::decode_ratchet_state(kS) == s_at(),
          "S (134 B): decode inverts encode");

    // policy defaults
    check(pb::transport_ceiling(16, pb::zone(16)) == std::optional<std::uint64_t>(600093) &&
                  pb::transport_ceiling(17, pb::zone(17)) == std::optional<std::uint64_t>(1250126),
          "P-14 = FB_CTX header + blob_cap_ctx: 600,093 (hf 16) / 1,250,126 (hf 17)");
    check(*pb::bucket_wire_policy_default(16, pb::zone(16)) == pb::BucketWirePolicy{600093, 1, 6000930},
          "P-39 = P-14, P-41 = 1, P-42 = 10 x P-39");
    check(pb::kBucketFrameFlag == "--pathb-bucket-frame" && pb::kBucketInflightFlag == "--pathb-bucket-inflight" &&
                  pb::kBucketRateFlag == "--pathb-bucket-rate",
          "policy flags named");
}

// ---------------------------------------------------------------------------
// honest replies
// ---------------------------------------------------------------------------
void honest_vectors() {
    ChainA a;
    const pb::Hash32 at = cid(0x40, 3);
    const pb::GetBuckets req{kChain, at, kB0, kB0 + 2};
    const std::vector<std::uint8_t> f = pb::serve_buckets(a.s, req, kS, kFrame).at(0);
    pb::BucketsAssembly as(req, kB0, F, kFrame);
    const pb::FrameOutcome o = as.add_frame(kServerA, f, anchor_of(a.s, at));
    check(o.verdict == pb::FrameVerdict::Accepted && o.strike == 0 && o.bins_completed == 3 && as.complete(),
          "FR-B1 reply: accepted, 3 bins, no strike");
    pb::BinMmr m;
    bool leaves = as.bins().size() == 3;
    for (std::uint64_t i = 0; leaves && i < 3; ++i) {
        const pb::ServedBin& sb = as.bins().at(kB0 + i);
        leaves = sb.leaf == *a.s.best_mmr().leaf(i) && sb.leaf == pb::mmr_leaf_of(sb.bucket);
        m.append(sb.leaf);
    }
    check(leaves, "FR-B1 reply: the leaves are the store's");
    check(m.root() == *anchor_of(a.s, at).mmr_root, "FR-B1 reply: the received leaves rebuild mmr_root(at)");
    check(as.bins().at(kB0 + 1).bucket.rows.empty() &&
                  as.bins().at(kB0 + 1).leaf == pb::mmr_leaf_of(pb::seal_from_entries(kB0 + 1, {})),
          "FR-B1 reply: bin b0 + 1 is the E-8 empty leaf");
    check(as.refs().size() == 1 && as.refs().count(pb::key_ref_identity(ka)) == 1 &&
                  as.bins().at(kB0).refs == std::vector<pb::XmrKeyRef>{ka},
          "FR-B1 reply: the reference of the one identity");
    check(as.s_pending(), "FR-B1 reply: S pending until at's carried ids are held");
    const pb::SResolution sr = as.resolve_s(anchor_of(a.s, at, true));
    check(!sr.pending && sr.adopted == std::optional<pb::RatchetState>(s_at()) && sr.struck.empty() && !as.s_pending(),
          "FR-B1 reply: S folds with at's receipts_root and is adopted");
    check(as.rows_allocated() == 2, "FR-B1 reply: 2 rows allocated");

    // The FR-B1 golden payloads (miner 0xAA..AA): every proof verifies against
    // dc6ff5da... at leaf_count 3; the empty bin alone is served and accepted;
    // 0xAA..AA has no 66-byte reference, so a reply with its rows is refused.
    const pb::L1Bucket g0 = pb::seal_from_entries(kB0, {pb::WinEntry{rep(0xAA), {}, 18180}});
    const pb::L1Bucket g1 = pb::seal_from_entries(kB0 + 1, {});
    const pb::L1Bucket g2 = pb::seal_from_entries(kB0 + 2, {pb::WinEntry{rep(0xAA), {}, 18180}});
    const Forged g = forge({g0, g1, g2});
    check(hx(*g.anchor.mmr_root) == "dc6ff5da350b6e8e7b21fd6e75332e3d5acb872e3637378a5c476486ed9dd49c" &&
                  hx(pb::mmr_leaf_of(g1)) == "dcd7becdd422d3ff25c6477a1f9f26de4c109baf2930b1361bc7d09d46dc8417",
          "FR-B1 golden: root dc6ff5da..., empty leaf dcd7becd...");
    bool proofs = true;
    for (std::uint64_t i = 0; i < 3; ++i) {
        const pb::BucketEntry e = entry_of(g, i);
        proofs = proofs && pb::mmr_verify(*g.anchor.mmr_root, pb::mmr_leaf_of(e.payload),
                                          pb::wire_proof(i, 3, e.path, g.mmr.peaks()));
    }
    check(proofs, "FR-B1 golden: the wire proofs (leaf_index = bin_lo - b0) verify against dc6ff5da...");
    const pb::GetBuckets g_one{kChain, seq32(0x66), kB0 + 1, kB0 + 1};
    pb::BucketsAssembly ga(g_one, kB0, F, kFrame);
    const pb::FrameOutcome go = ga.add_frame(kServerA, enc(reply_of(g, g_one.at, 1, 1, {})), g.anchor);
    check(go.verdict == pb::FrameVerdict::Accepted && ga.complete() &&
                  hx(ga.bins().at(kB0 + 1).leaf) == "dcd7becdd422d3ff25c6477a1f9f26de4c109baf2930b1361bc7d09d46dc8417",
          "FR-B1 golden: bin b0 + 1 served alone is accepted with leaf dcd7becd...");
    const pb::GetBuckets g_all{kChain, seq32(0x66), kB0, kB0 + 2};
    check(refused(one(g_all, enc(reply_of(g, g_all.at, 0, 3, {})), g.anchor), pb::BucketsFault::RefMissing),
          "FR-B1 golden: the identity 0xAA..AA without a reference -> refused (RefMissing)");
}

// ---------------------------------------------------------------------------
// lying servers
// ---------------------------------------------------------------------------
void lying_vectors() {
    ChainA a;
    const pb::Hash32 at = cid(0x40, 3);
    const pb::GetBuckets req{kChain, at, kB0, kB0 + 2};
    const std::vector<std::uint8_t> f = pb::serve_buckets(a.s, req, kS, kFrame).at(0);
    const pb::BucketsAnchor an = anchor_of(a.s, at);
    const pb::BucketsReply r = dec(f);

    // wrong leaf_count
    {
        pb::BucketsReply x = r;
        x.leaf_count = 4;
        x.peaks = {seq32(0x01)};
        check(refused(one(req, enc(x), an), pb::BucketsFault::LeafCount), "leaf_count 4 at H = b0 + 98 -> LeafCount");
        pb::BucketsAnchor no_root = an;
        no_root.mmr_root.reset();
        check(refused(one(req, enc(x), no_root), pb::BucketsFault::LeafCount),
              "leaf_count 4 refused from the header alone (root not held)");
    }
    // a bucket subset: a bin skipped; a row withheld
    {
        pb::BucketsReply x = r;
        x.entries.erase(x.entries.begin() + 1);
        check(refused(one(req, enc(x), an), pb::BucketsFault::LeafIndex), "a bin skipped (b0, b0 + 2) -> LeafIndex");
        ChainR c;
        const pb::GetBuckets rq{kChain, cid(0x50, 3), kB0, kB0};
        pb::BucketsReply y = dec(pb::serve_buckets(c.s, rq, kS, kFrame).at(0));
        y.entries[0].rows.pop_back();
        y.entries[0].rows_total = 4;
        y.refs.erase(std::remove_if(y.refs.begin(), y.refs.end(),
                                    [&](const pb::XmrKeyRef& k) {
                                        const pb::Hash32 id = pb::key_ref_identity(k);
                                        for (const pb::BucketRow& row : y.entries[0].rows)
                                            if (row.miner == id) return false;
                                        return true;
                                    }),
                     y.refs.end());
        const pb::FrameOutcome o = one(rq, enc(y), anchor_of(c.s, rq.at));
        check(c.ok && refused(o, pb::BucketsFault::Bucket) && o.bucket == pb::BucketFault::CompRoot,
              "a row withheld (4 of 5 rows) -> the completed bucket fails (CompRoot)");
    }
    // a forged sum in a row
    {
        pb::BucketsReply x = r;
        x.entries[0].rows[0].w_miner += pb::Work(1);
        const pb::FrameOutcome o = one(req, enc(x), an);
        check(refused(o, pb::BucketsFault::Bucket) && o.bucket == pb::BucketFault::CompRoot,
              "w_miner + 1 in a row -> refused (CompRoot), server strike 1");
        x.entries[0].payload.raw_sum += pb::Work(1);
        x.entries[0].payload.comp_root_v = pb::comp_root(x.entries[0].rows);
        check(refused(one(req, enc(x), an), pb::BucketsFault::Proof),
              "w_miner + 1 with raw_sum and comp_root recomputed -> the MMR proof fails");
    }
    // a wrong key reference
    {
        pb::BucketsReply x = r;
        x.refs = {kz};
        check(refused(one(req, enc(x), an), pb::BucketsFault::RefMissing),
              "the reference of another key -> the row identity has none (RefMissing)");
        x.refs = sorted_refs({ka, kz});
        check(refused(one(req, enc(x), an), pb::BucketsFault::RefStray),
              "an extra reference whose identity is in no row -> RefStray");
        x.refs.clear();
        check(refused(one(req, enc(x), an), pb::BucketsFault::RefMissing), "no reference -> RefMissing");
        ChainR c;
        const pb::GetBuckets rq{kChain, cid(0x50, 3), kB0, kB0};
        pb::BucketsReply y = dec(pb::serve_buckets(c.s, rq, kS, kFrame).at(0));
        check(y.refs.size() == 5, "chain R bin b0: 5 references");
        std::swap(y.refs[0], y.refs[1]);
        check(refused(one(rq, enc(y), anchor_of(c.s, rq.at)), pb::BucketsFault::RefOrder),
              "references out of identity order -> RefOrder");
        // a reference whose spend key does not decompress, bound to its row
        pb::XmrKeyRef bad = ka;
        bad.spend = non_point();
        const Forged fb = forge({keyed_bin(kB0, {{bad, 18180}})});
        const pb::GetBuckets bq{kChain, seq32(0x67), kB0, kB0};
        check(refused(one(bq, enc(reply_of(fb, bq.at, 0, 1, {bad})), fb.anchor), pb::BucketsFault::RefPoint),
              "a reference that does not decompress -> RefPoint");
    }
    // proofs against the wrong prefix root
    {
        ChainA ax;
        ax.extend();
        check(ax.ok && ax.s.head().leaf_count == 5, "chain A extended to 5 leaves (tip b0 + 100)");
        const pb::BucketsAnchor anx = anchor_of(ax.s, at);
        pb::BucketsReply x = dec(pb::serve_buckets(ax.s, req, kS, kFrame).at(0));
        check(one(req, enc(x), anx).verdict == pb::FrameVerdict::Accepted && x.leaf_count == 3,
              "an ancestor of the tip is served at its own leaf_count (3)");
        pb::BucketsReply y = x;
        y.peaks = ax.s.best_mmr().peaks();  // the peaks of 5 leaves (popcount 2, like 3)
        check(refused(one(req, enc(y), anx), pb::BucketsFault::Peaks), "the peaks of leaf_count 5 sent for 3 -> Peaks");
        pb::BucketsReply z = x;
        z.entries[2].path.clear();
        const std::optional<pb::MmrProof> p5 = ax.s.best_mmr().prefix_proof(2, 5);
        for (const auto& st : p5->path) z.entries[2].path.push_back(st.first);
        check(refused(one(req, enc(z), anx), pb::BucketsFault::Proof),
              "the path of leaf b0 + 2 against the root of 5 leaves -> Proof");
    }
    // the shifted index: leaf j holds bin b0 + j + 1 in a committed MMR
    {
        const Forged s = forge({keyed_bin(kB0 + 1, {{ka, 18180}}), keyed_bin(kB0 + 2, {{ka, 18180}}),
                                keyed_bin(kB0 + 3, {{ka, 18180}})});
        const pb::GetBuckets sq{kChain, seq32(0x68), kB0, kB0 + 2};
        check(refused(one(sq, enc(reply_of(s, sq.at, 0, 3, {ka})), s.anchor), pb::BucketsFault::LeafIndex),
              "shifted index (leaf 0 holds bin b0 + 1, valid proof) -> LeafIndex");
    }
    // a two-bin leaf
    {
        pb::L1Bucket two = keyed_bin(kB0, {{ka, 18180}});
        two.bin_hi = kB0 + 1;
        const Forged t = forge({two});
        const pb::GetBuckets tq{kChain, seq32(0x69), kB0, kB0};
        check(refused(one(tq, enc(reply_of(t, tq.at, 0, 1, {ka})), t.anchor), pb::BucketsFault::LeafIndex),
              "a leaf with bin_hi != bin_lo -> LeafIndex");
    }
    // rows_total against raw_sum / d_min, before any row is allocated
    {
        pb::BucketsReply x = r;
        x.entries[0].rows_total = 1000;
        pb::BucketsAssembly as(req, kB0, F, kFrame);
        check(refused(as.add_frame(kServerA, enc(x), an), pb::BucketsFault::RowsTotal) && as.rows_allocated() == 0,
              "rows_total 1000 > raw_sum / d_min = 1 -> refused before any row is allocated");
        x = r;
        x.entries[0].rows_total = 0;
        check(refused(one(req, enc(x), an), pb::BucketsFault::RowsTotal), "rows_total 0 for a non-empty leaf -> RowsTotal");
        x = r;
        x.entries[1].rows_total = 1;
        check(refused(one(req, enc(x), an), pb::BucketsFault::RowsTotal), "rows_total 1 for the empty leaf -> RowsTotal");
    }
    // S_parent with one byte changed
    {
        pb::BucketsReply x = r;
        x.s_parent[3] ^= 1;
        pb::BucketsAssembly as(req, kB0, F, kFrame);
        check(as.add_frame(kServerA, enc(x), an).verdict == pb::FrameVerdict::Accepted && as.s_pending(),
              "S one byte changed: pending while at's body is not held");
        const pb::SResolution sr = as.resolve_s(anchor_of(a.s, at, true));
        check(!sr.pending && !sr.adopted && sr.struck == std::vector<std::uint64_t>{kServerA},
              "S one byte changed: struck once at's carried ids are held");
        check(refused(one(req, enc(x), anchor_of(a.s, at, true)), pb::BucketsFault::SParent),
              "S one byte changed with at's body held -> SParent");
    }
}

// ---------------------------------------------------------------------------
// receiver order, paging
// ---------------------------------------------------------------------------
void receiver_vectors() {
    ChainA a;
    const pb::Hash32 at = cid(0x40, 3);
    const pb::GetBuckets req{kChain, at, kB0, kB0 + 2};
    const std::vector<std::uint8_t> f = pb::serve_buckets(a.s, req, kS, kFrame).at(0);
    const pb::BucketsAnchor an = anchor_of(a.s, at);

    {
        pb::BucketsAssembly as(req, kB0, F, f.size() - 1);
        const pb::FrameOutcome o = as.add_frame(kServerA, f, an);
        check(o.verdict == pb::FrameVerdict::Drop && o.fault == pb::BucketsFault::OverBuffer && o.strike == 0,
              "a frame above the buffer -> DROP, 0 tokens");
        const pb::FrameOutcome o2 = as.add_frame(kServerA, pb::encode_buckets_not_served(kChain, at), an);
        check(o2.verdict == pb::FrameVerdict::Drop && o2.fault == pb::BucketsFault::Unsolicited,
              "after an oversize frame the server's later frames for the request are dropped");
    }
    {
        const pb::GetBuckets other{kChain, cid(0x40, 2), kB0, kB0 + 2};
        const pb::FrameOutcome o = one(other, f, an);
        check(o.verdict == pb::FrameVerdict::Drop && o.fault == pb::BucketsFault::Unsolicited && o.strike == 0,
              "a reply for another at -> DROP");
        const pb::FrameOutcome n = one(req, pb::encode_buckets_not_served(kChain, at), an);
        check(n.verdict == pb::FrameVerdict::NotServed && n.strike == 0, "n = 0 -> ask another peer, no verdict");
        pb::BucketsAnchor no_hdr;
        const pb::FrameOutcome d1 = one(req, f, no_hdr);
        check(d1.verdict == pb::FrameVerdict::Defer && d1.fault == pb::BucketsFault::AtUnknown && d1.strike == 0,
              "at not held as a header -> DEFER");
        pb::BucketsAnchor no_root = an;
        no_root.mmr_root.reset();
        const pb::FrameOutcome d2 = one(req, f, no_root);
        check(d2.verdict == pb::FrameVerdict::Defer && d2.fault == pb::BucketsFault::RootUnknown && d2.strike == 0,
              "the root over leaf_count(at) not held -> DEFER");
        std::vector<std::uint8_t> bad = f;
        bad[1] = 2;
        const pb::FrameOutcome w = one(req, bad, an);
        check(refused(w, pb::BucketsFault::Wire) && w.wire == pb::BucketsWireError::Version,
              "a frame that does not decode -> refused, server strike 1");
        pb::BucketsAssembly as(req, kB0, F, kFrame);
        const pb::FrameOutcome w1 = as.add_frame(kServerA, bad, an);
        const pb::FrameOutcome w2 = as.add_frame(kServerA, f, an);
        const pb::FrameOutcome w3 = as.add_frame(kServerB, f, an);
        check(w1.strike == 1 && w2.verdict == pb::FrameVerdict::Drop && w2.fault == pb::BucketsFault::Unsolicited &&
                      w2.strike == 0 && w3.verdict == pb::FrameVerdict::Accepted && as.complete(),
              "after a refusal the server's later frames are dropped; another server completes the request");
    }
    {
        const pb::GetBuckets nq{kChain, at, kB0, kB0};
        check(refused(one(nq, f, an), pb::BucketsFault::BinRange), "an entry beyond bin_hi -> BinRange");
        const pb::GetBuckets lq{kChain, at, kB0 + 2, kB0 + 3};
        pb::BucketsReply x = dec(f);
        x.entries.erase(x.entries.begin(), x.entries.begin() + 2);
        x.entries.push_back(x.entries[0]);
        x.entries[1].payload.bin_lo = x.entries[1].payload.bin_hi = kB0 + 3;
        check(refused(one(lq, enc(x), an), pb::BucketsFault::LeafIndex),
              "an entry for bin b0 + 3 at leaf_count 3 -> LeafIndex");
    }

    // paging: chain R, bins b0 (5 rows) and b0 + 1 (1 row with an owner) at 900 B per frame
    ChainR c;
    const pb::Hash32 rat = cid(0x50, 3);
    const pb::GetBuckets rq{kChain, rat, kB0, kB0 + 1};
    const pb::BucketsAnchor ran = anchor_of(c.s, rat);
    const std::vector<std::vector<std::uint8_t>> pages = pb::serve_buckets(c.s, rq, kS, 900);
    bool within = true;
    for (const auto& p : pages) within = within && p.size() <= 900;
    std::vector<pb::BucketsReply> pr;
    for (const auto& p : pages) pr.push_back(dec(p));
    check(c.ok && pages.size() == 4 && within && pr[0].entries.size() == 1 && pr[0].entries[0].rows.size() == 2 &&
                  pr[1].entries[0].row_first == 2 && pr[2].entries[0].row_first == 4 &&
                  pr[2].entries[0].rows.size() == 1 && pr[3].entries[0].payload.bin_lo == kB0 + 1 &&
                  pr[3].refs.size() == 2,
          "paging at 900 B: bin b0 over 3 pages (2, 2, 1 rows), bin b0 + 1 with its owner reference");
    {
        pb::BucketsAssembly as(rq, kB0, F, 900);
        std::vector<pb::FrameOutcome> os;
        for (const auto& p : pages) os.push_back(as.add_frame(kServerA, p, ran));
        bool acc = true;
        for (const auto& o : os) acc = acc && o.verdict == pb::FrameVerdict::Accepted && o.strike == 0;
        check(acc && os[0].bins_completed == 0 && os[1].bins_completed == 0 && os[2].bins_completed == 1 &&
                      os[3].bins_completed == 1 && as.complete(),
              "a 3-page bucket reassembled: complete on its third page");
        const pb::LaneView v = c.s.view_at(rat);
        check(pb::encode_bleaf(pb::SealedBin{as.bins().at(kB0).bucket, as.bins().at(kB0).leaf, 0,
                                             as.bins().at(kB0).refs}) == pb::encode_bleaf(*v.bucket(kB0)) &&
                      pb::encode_bleaf(pb::SealedBin{as.bins().at(kB0 + 1).bucket, as.bins().at(kB0 + 1).leaf, 0,
                                                     as.bins().at(kB0 + 1).refs}) == pb::encode_bleaf(*v.bucket(kB0 + 1)),
              "the reassembled buckets and references equal the server's");
    }
    {
        pb::BucketsAssembly as(rq, kB0, F, 900);
        const pb::FrameOutcome o1 = as.add_frame(kServerA, pages[0], ran);
        as.abandon(kServerA);  // page 2 not received in time
        const pb::FrameOutcome o3 = as.add_frame(kServerA, pages[2], ran);
        std::uint32_t strikes = o1.strike + o3.strike;
        for (const auto& p : pages) strikes += as.add_frame(kServerB, p, ran).strike;
        check(o1.verdict == pb::FrameVerdict::Accepted && o3.verdict == pb::FrameVerdict::Drop && as.complete() &&
                      strikes == 0,
              "a missing page: asked from a second server, accepted, no strike");
    }
    {
        pb::BucketsAssembly as(rq, kB0, F, 900);
        as.add_frame(kServerA, pages[0], ran);
        check(refused(as.add_frame(kServerA, pages[2], ran), pb::BucketsFault::Order),
              "page 3 after page 1 from one server -> Order");
        pb::BucketsAssembly bs(rq, kB0, F, 900);
        bs.add_frame(kServerA, pages[0], ran);
        pb::BucketsReply x = pr[1];
        x.entries[0].rows_total = 6;
        check(refused(bs.add_frame(kServerA, enc(x), ran), pb::BucketsFault::PageConflict),
              "rows_total 6 on page 2 after 5 on page 1 -> PageConflict");
        pb::BucketsAssembly cs(rq, kB0, F, 900);
        cs.add_frame(kServerA, pages[0], ran);
        x = pr[1];
        x.s_parent[0] ^= 1;
        check(refused(cs.add_frame(kServerA, enc(x), ran), pb::BucketsFault::SChanged),
              "S differs between two frames of one server -> SChanged");
    }
    {
        const pb::GetBuckets one_bin{kChain, rat, kB0, kB0};
        pb::BucketsReply x = dec(pb::serve_buckets(c.s, one_bin, kS, kFrame).at(0));
        pb::BucketsReply y = x;
        y.entries[0].rows_total = 4;
        check(refused(one(one_bin, enc(y), ran), pb::BucketsFault::PageRange), "5 rows sent with rows_total 4 -> PageRange");
        y = x;
        y.entries[0].rows.clear();
        y.refs.clear();
        check(refused(one(one_bin, enc(y), ran), pb::BucketsFault::PageRange),
              "an empty page of a 5-row bin -> PageRange");
    }
    // every frame within the buffer; the reply complete for every buffer from the smallest that holds one row
    {
        bool all = true;
        const std::uint64_t smallest = 187 + 32 + 107 + 32 + 160 + 2 * 66;
        for (std::uint64_t lim : {smallest, smallest + 1, std::uint64_t{700}, std::uint64_t{1000},
                                  std::uint64_t{1500}, std::uint64_t{2500}, kFrame}) {
            const std::vector<std::vector<std::uint8_t>> ps = pb::serve_buckets(c.s, rq, kS, lim);
            pb::BucketsAssembly as(rq, kB0, F, lim);
            for (const auto& p : ps) {
                all = all && p.size() <= lim;
                all = all && as.add_frame(kServerA, p, ran).verdict == pb::FrameVerdict::Accepted;
            }
            all = all && as.complete();
        }
        const std::vector<std::vector<std::uint8_t>> tiny = pb::serve_buckets(c.s, rq, kS, smallest - 1);
        check(all && tiny.size() == 1 && tiny[0].size() == 187, "every frame within the buffer at 7 buffers; below "
                                                                 "the smallest the server answers n = 0");
    }
}

// ---------------------------------------------------------------------------
// serving rule, budget
// ---------------------------------------------------------------------------
void serving_vectors() {
    ChainA a;
    // a side carrier at the same height as c3 (not the best chain)
    check(step(a.s, cid(0x41, 3), cid(0x40, 2), kB0 + 98, {}, false), "a side carrier beside c3");
    const pb::GetBuckets side{kChain, cid(0x41, 3), kB0, kB0 + 2};
    const std::vector<std::vector<std::uint8_t>> sf = pb::serve_buckets(a.s, side, kS, kFrame);
    check(sf.size() == 1 && sf[0] == pb::encode_buckets_not_served(kChain, side.at),
          "at off the server's best chain -> n = 0, leaf_count 0");
    const pb::FrameOutcome so = one(side, sf[0], anchor_of(a.s, side.at));
    check(so.verdict == pb::FrameVerdict::NotServed && so.strike == 0, "the n = 0 reply: no strike");
    const pb::GetBuckets unknown{kChain, seq32(0x77), kB0, kB0 + 2};
    check(pb::serve_buckets(a.s, unknown, kS, kFrame).at(0) == pb::encode_buckets_not_served(kChain, unknown.at),
          "at unknown to the server -> n = 0");
    const pb::GetBuckets best{kChain, cid(0x40, 3), kB0, kB0 + 2};
    check(pb::serve_buckets(a.s, best, std::nullopt, kFrame).at(0) == pb::encode_buckets_not_served(kChain, best.at),
          "S at at's parent not held -> n = 0");
    const pb::GetBuckets below{kChain, cid(0x40, 3), kB0 - 2, kB0};
    check(pb::serve_buckets(a.s, below, kS, kFrame).at(0) == pb::encode_buckets_not_served(kChain, below.at),
          "a range starting below b0 -> n = 0");
    const pb::GetBuckets beyond{kChain, cid(0x40, 3), kB0 + 3, kB0 + 9};
    check(pb::serve_buckets(a.s, beyond, kS, kFrame).at(0) == pb::encode_buckets_not_served(kChain, beyond.at),
          "a range above leaf_count(at) -> n = 0");

    // a bin whose identity has no reference ends the served prefix
    ChainR q(false);
    const pb::Hash32 qat = cid(0x50, 3);
    const pb::GetBuckets qq{kChain, qat, kB0, kB0 + 1};
    const std::vector<std::vector<std::uint8_t>> qf = pb::serve_buckets(q.s, qq, kS, kFrame);
    pb::BucketsAssembly qa(qq, kB0, F, kFrame);
    const pb::FrameOutcome qo = qa.add_frame(kServerA, qf.at(0), anchor_of(q.s, qat));
    check(q.ok && qf.size() == 1 && qo.verdict == pb::FrameVerdict::Accepted && qa.complete_through() == kB0 + 1,
          "a bin without a reference for an identity is not served: the prefix ends before it");
    const pb::GetBuckets qq1{kChain, qat, kB0 + 1, kB0 + 1};
    check(pb::serve_buckets(q.s, qq1, kS, kFrame).at(0) == pb::encode_buckets_not_served(kChain, qat),
          "... and alone it is not served");

    // a joiner's prefix MMR (from the peaks of 3 leaves) serves only the leaves appended after it
    ChainA ax;
    ax.extend();
    const pb::BinMmr& full = ax.s.best_mmr();
    pb::BinMmr pre = *pb::BinMmr::from_peaks(3, *full.prefix_peaks(3));
    pre.append(*full.leaf(3));
    pre.append(*full.leaf(4));
    const pb::LaneView tip = ax.s.view_at(ax.s.best_tip());
    pb::BucketServeSource src;
    src.b0 = kB0;
    src.leaf_count = 5;
    src.mmr = &pre;
    src.bucket = [&tip](std::uint64_t bin) { return tip.bucket(bin); };
    src.s_parent = kS;
    const pb::GetBuckets j1{kChain, ax.s.best_tip(), kB0 + 2, kB0 + 4};
    check(pb::serve_buckets_from(src, j1, kFrame).at(0) == pb::encode_buckets_not_served(kChain, j1.at),
          "a prefix MMR of 3 leaves does not serve leaf 2");
    const pb::GetBuckets j2{kChain, ax.s.best_tip(), kB0 + 3, kB0 + 4};
    pb::BucketsAssembly ja(j2, kB0, F, kFrame);
    const pb::FrameOutcome jo = ja.add_frame(kServerA, pb::serve_buckets_from(src, j2, kFrame).at(0),
                                             anchor_of(ax.s, ax.s.best_tip()));
    check(jo.verdict == pb::FrameVerdict::Accepted && ja.complete(), "... and serves leaves 3 and 4");

    // a body that is not the leaf's (a stale record) ends the served prefix
    {
        std::map<std::uint64_t, pb::SealedBin> held;
        pb::BinMmr m;
        for (std::uint64_t i = 0; i < 4; ++i) {
            pb::SealedBin sb;
            sb.bucket = keyed_bin(kB0 + i, {{ka, 18180 + i}});
            sb.leaf = pb::mmr_leaf_of(sb.bucket);
            sb.refs = {ka};
            m.append(sb.leaf);
            held.emplace(kB0 + i, sb);
        }
        held[kB0 + 2].bucket = keyed_bin(kB0 + 2, {{ka, 30000}});
        held[kB0 + 2].leaf = pb::mmr_leaf_of(held[kB0 + 2].bucket);
        pb::BucketServeSource st;
        st.b0 = kB0;
        st.leaf_count = 4;
        st.mmr = &m;
        st.bucket = [&held](std::uint64_t bin) -> const pb::SealedBin* {
            const auto it = held.find(bin);
            return it == held.end() ? nullptr : &it->second;
        };
        st.s_parent = kS;
        const pb::GetBuckets sq{kChain, seq32(0x6a), kB0, kB0 + 3};
        pb::BucketsAnchor sa;
        sa.header_held = true;
        sa.record = kB0 + F - 1 + 4;
        sa.mmr_root = m.root();
        pb::BucketsAssembly ss(sq, kB0, F, kFrame);
        const pb::FrameOutcome so2 = ss.add_frame(kServerA, pb::serve_buckets_from(st, sq, kFrame).at(0), sa);
        check(so2.verdict == pb::FrameVerdict::Accepted && ss.complete_through() == kB0 + 2,
              "a held body whose leaf is not the MMR's is not served: the prefix ends before it");
    }

    // the per-peer budget
    pb::BucketServeBudget bud(*pb::bucket_wire_policy_default(16, pb::zone(16)));
    const bool a1 = bud.admit(1, 1000);
    const bool a2 = bud.admit(1, 1000);
    bud.done(1);
    const bool a3 = bud.admit(1, 1001);
    check(a1 && !a2 && a3, "P-41: a second request in flight from one peer is DROPPED");
    bud.done(1);
    bud.sent(1, 6000930, 1001);
    const bool a4 = bud.admit(1, 1059);
    const bool a5 = bud.admit(2, 1059);
    const bool a6 = bud.admit(1, 1060);
    check(!a4 && a5 && a6 && bud.inflight(1) == 1, "P-42: 10 x P-39 bytes in a minute -> DROPPED until the minute rolls");
}

}  // namespace

int main() {
    run_part("codec", codec_vectors);
    run_part("honest", honest_vectors);
    run_part("lying", lying_vectors);
    run_part("receiver", receiver_vectors);
    run_part("serving", serving_vectors);
    return finish("v37_xmr_pathb_bucket_wire_kat");
}
