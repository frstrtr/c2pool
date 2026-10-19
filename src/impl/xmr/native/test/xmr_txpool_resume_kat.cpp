// xmr_native_txpool_resume_kat -- TXPOOL-RESUME (mainnet dry run 2, 09-25).
//
// After a clean stop and restart while synced, the native node served
// coinbase-only templates for a whole block (250 s) while the operator's
// monerod held 182-230 transactions, and the backlog relayed before the
// restart was never back-filled. Three seams, each pinned here on the REAL
// components (anchor-booted ChainIndex, RelayedTxPool with input consensus
// wired to real mainnet transactions, PeerDosGuard, NativeMinerDataSource):
//
//   A  GATE      The relay gate is the view's sync_state().synced, the same
//                predicate template_inputs() serves on. A snapshot resume (and
//                an anchor boot at the network tip) installs the index WITHOUT
//                connecting a block, so the pool's chain context stayed at
//                height 0 and every relay was refused RingMemberLocked (each
//                ring member "younger than 10 blocks" against height 1) until
//                the next block connected. The node now seats the pool's tip
//                from the index when the gate opens (RelayedTxPool::seat_tip).
//   B  BACK-FILL A fresh pool asks a peer for its txpool complement (2010); the
//                answer (a 2002) is admitted FLUFFED -- monerod's get_complement
//                returns only publicly relayed txs -- through the same
//                validation as any relay, and it is charged to a solicited
//                credit instead of the per-tx flood bucket.
//   C  WARM      No template (no job) before the pool is warm; once warm the
//                template is byte-for-byte the one an ungated source selects
//                from the same pool (fee/weight selection unchanged).
//
// RED on 269eb722 (the seams do not exist there: A refuses RingMemberLocked,
// B has no complement path, C serves while cold), GREEN on the fix. The
// feature probes are C++20 requires-expressions, so the same source builds
// on both trees and the base failures are runtime FAILs, not a compile error.
// No sockets, no RandomX, no monerod.
//
// TXPOOL-RESUME-2 (the 09-25 verify of the above), three more seams:
//
//   D  CREDIT    The 2010 DoS credit was spent by the FIRST 2002 from the peer
//                after our 2010, answer or not: a fluffed relay racing the
//                answer took it, and the real answer (a whole pool) was then
//                charged to the 512-tx flood bucket. The credit is now bound to
//                the answer's wire shape (dandelionpp_fluff=false: monerod
//                struct_init's the answer; relays on our links are fluffed).
//   E  REGAIN    The back-fill was once per process: a sync loss/regain re-
//                opened the gate with no new round. Every opening is a round.
//   F  HOLD      On a fresh boot the gate opened (and the 2010 went out) on the
//                first MainchainEvent of the batch that closed the sync, before
//                that batch's BlockTxEvents fed the output set: 76 of 77 rings
//                of the answer UNRESOLVED. The gate now opens only once the
//                output set holds the index tip.
//
// D/E/F are RED on 826898d2 (TXPOOL-RESUME) and GREEN on the fix.

#include <atomic>
#include <cstdint>
#include <cstdio>
#include <map>
#include <optional>
#include <set>
#include <string>
#include <vector>

#include "impl/xmr/native/anchor/xmr_anchor_codec.hpp"
#include "impl/xmr/native/chain/xmr_chain_index.hpp"
#include "impl/xmr/native/chain/xmr_pow_gate.hpp"
#include "impl/xmr/native/consensus/xmr_block_id.hpp"
#include "impl/xmr/native/consensus/xmr_block_parse.hpp"
#include "impl/xmr/native/contracts/fakes/fake_fetcher.hpp"
#include "impl/xmr/native/p2p/levin_messages.hpp"
#include "impl/xmr/native/p2p/xmr_p2p_dos.hpp"
#if __has_include("impl/xmr/native/node/xmr_tx_relay_gate.hpp")
#include "impl/xmr/native/node/xmr_tx_relay_gate.hpp"
#endif
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/txpool/xmr_relayed_txpool.hpp"
#include "impl/xmr/native/txpool/xmr_tx_decode.hpp"
#include "xmr_input_consensus_golden.hpp"
#include "xmr_p2p_kat_util.hpp"

namespace native = c2pool::xmr::native;
namespace kat    = c2pool::xmr::native::kat;
namespace T      = c2pool::xmr::native::test;
namespace lv     = c2pool::xmr::native::levin;

using native::BlockEntry;
using native::Hash;
using native::PeerRef;
using native::RelayedTxPool;
using native::TxRelayVerdict;
using native::U128;

namespace {

// --- feature probes (absent on the base tree -> the check FAILS) -------------
template <class P> bool seat_tip_(P& p, std::uint64_t h) {
    if constexpr (requires { p.seat_tip(h); }) { (void)p.seat_tip(h); return true; }
    else { (void)p; (void)h; return false; }
}
template <class P>
std::optional<std::vector<TxRelayVerdict>> complement_(P& p, const PeerRef& r,
                                                       std::vector<std::vector<std::uint8_t>> b) {
    if constexpr (requires { p.on_complement(r, b); }) return p.on_complement(r, std::move(b));
    else { (void)p; (void)r; (void)b; return std::nullopt; }
}
template <class G> bool solicit_(G& g, native::p2p::Millis now) {
    if constexpr (requires { g.note_complement_solicited(now); }) { g.note_complement_solicited(now); return true; }
    else { (void)g; (void)now; return false; }
}
// TXPOOL-RESUME-2: charge a 2002 with its wire shape (absent on 826898d2: the
// 5-argument call, which any 2002 can spend the credit through).
template <class G>
native::p2p::DosAction frame_(G& g, std::size_t bytes, std::size_t units, native::p2p::Millis now,
                              bool complement_shaped) {
    native::p2p::DosFault f = native::p2p::DosFault::None;
    if constexpr (requires { g.on_frame(lv::CMD_NEW_TRANSACTIONS, bytes, units, now, f, complement_shaped); })
        return g.on_frame(lv::CMD_NEW_TRANSACTIONS, bytes, units, now, f, complement_shaped);
    else { (void)complement_shaped; return g.on_frame(lv::CMD_NEW_TRANSACTIONS, bytes, units, now, f); }
}
template <class S> bool warm_gate_(S& s, const std::atomic<bool>* w) {
    if constexpr (requires { s.set_warm_gate(w); }) { s.set_warm_gate(w); return true; }
    else { (void)s; (void)w; return false; }
}

// --- the anchor-booted chain (the xmr_template_dup_tx_kat rig, trimmed) -------
constexpr std::uint64_t kAnchorHeight = 2204000;
constexpr std::uint64_t kAnchorTs     = 1788965550;
constexpr std::uint64_t kBase         = 600000000000ull;

class ModelVerifier {
public:
    enum class VerifyStatus { Accept, BelowTarget, SeedNotResident, NotInitialized };
    bool prefetch_epoch(const Hash& current, const std::optional<Hash>& next) {
        cur_ = current; nxt_ = next; return true;
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

Hash tag_hash(std::uint64_t seed, std::uint8_t tag) {
    Hash h{};
    for (std::size_t i = 0; i < 8; ++i) h[i] = static_cast<std::uint8_t>(seed >> (8 * i));
    for (std::size_t i = 8; i < h.size(); ++i) h[i] = static_cast<std::uint8_t>(tag + i);
    return h;
}

std::vector<std::uint8_t> anchor_blob() {
    std::vector<std::uint8_t> b;
    auto vi = [&](std::uint64_t v) { native::blob_write_varint(b, v); };
    vi(16); vi(16); vi(kAnchorTs);
    for (std::size_t i = 0; i < 32; ++i) b.push_back(static_cast<std::uint8_t>((kAnchorHeight - 1 + i) ^ 0x11));
    for (int i = 0; i < 4; ++i) b.push_back(static_cast<std::uint8_t>((0x0badc0deu >> (8 * i)) & 0xff));
    vi(2); vi(kAnchorHeight + 60); vi(1);
    b.push_back(native::TX_IN_GEN); vi(kAnchorHeight); vi(1); vi(kBase);
    b.push_back(native::TX_OUT_TO_TAGGED_KEY);
    for (std::size_t i = 0; i < 33; ++i) b.push_back(static_cast<std::uint8_t>((i * 7u) ^ 0x11 ^ (kAnchorHeight & 0xff)));
    std::vector<std::uint8_t> extra{0x01};
    for (std::size_t i = 0; i < 32; ++i) extra.push_back(static_cast<std::uint8_t>((i * 3u) + 0x11));
    vi(extra.size()); b.insert(b.end(), extra.begin(), extra.end());
    b.push_back(0x00); vi(0);
    return b;
}

native::AnchorBundle make_bundle(const Hash& id) {
    native::AnchorBundle b;
    b.network = "stagenet"; b.height = kAnchorHeight; b.id = id;
    b.prev_id = tag_hash(kAnchorHeight - 1, 0x10); b.timestamp = kAnchorTs; b.major_version = 16;
    b.cumulative_difficulty.hi = 0; b.cumulative_difficulty.lo = 0xc3772e00dbull;
    b.already_generated_coins  = 18163913490712907281ull;
    const std::uint64_t seed_h = native::rx_seedheight(b.height + 1);
    b.seed_ids.emplace_back(seed_h, tag_hash(seed_h, 0x20));
    U128 cd{}; cd.lo = 0xc2cb6d9d38ull;
    for (std::size_t i = 0; i < native::ANCHOR_DIFFICULTY_WINDOW; ++i) {
        b.difficulty_window.emplace_back(1788876380ull + i * 37ull, cd);
        cd = native::u128_add(cd, U128{0, 3766353ull});
    }
    for (std::size_t i = 0; i < native::ANCHOR_SHORT_TERM_WEIGHTS; ++i) b.short_term_weights.push_back(87ull + (i % 5));
    b.long_term_weights.assign(native::ANCHOR_LONG_TERM_WEIGHTS, 176470ull);
    b.digest = native::anchor_digest(b);
    return b;
}

struct Chain {
    ModelVerifier                                 mv;
    native::LightVerifierPowSource<ModelVerifier> src{mv};
    native::ChainIndex*                           idx = nullptr;
    native::fakes::FakeFetcher                    fetcher;
    bool ok = false;
    Chain() {
        const std::vector<std::uint8_t> blob = anchor_blob();
        native::ParsedBlock pb;
        Hash id{};
        if (native::parse_block(blob, pb) == native::BlockParseStatus::Ok)
            id = native::block_identity(blob.data(), pb).id;
        native::ChainIndexOptions o;
        o.net = native::XmrNet::Stagenet;
        idx = new native::ChainIndex(o, src);
        idx->set_fetcher(&fetcher);
        std::string why;
        ok = idx->boot_from_anchor(make_bundle(id), {}, why);
        kat::checkf(ok, "rig: the index boots from the anchor (%s)", why.c_str());
        idx->force_synced(true);
    }
    ~Chain() { delete idx; }
};

// --- real mainnet transactions with their real ring members ------------------
class RingSource final : public native::IRingMemberSource, public native::ISpentKeyImageView {
public:
    std::map<std::uint64_t, native::OutputRecord> outs;
    bool resolve(std::uint64_t amount, const std::vector<std::uint64_t>& abs,
                 std::vector<native::OutputRecord>& out) const override {
        if (amount != 0) return false;
        out.clear();
        for (std::uint64_t off : abs) {
            auto it = outs.find(off);
            if (it == outs.end()) return false;
            out.push_back(it->second);
        }
        return true;
    }
    bool is_spent(const Hash&) const override { return false; }
};

Hash hash_hex(const char* hex) {
    const std::vector<std::uint8_t> v = kat::from_hex(hex);
    Hash h{};
    for (std::size_t i = 0; i < h.size() && i < v.size(); ++i) h[i] = v[i];
    return h;
}

struct Golden {
    std::vector<std::vector<std::uint8_t>> blobs;
    std::vector<Hash>                      ids;
    RingSource                             rings;   // members at height 0: old
};

// Every golden tx that decodes and whose ring offsets do not collide with an
// earlier tx's (one shared source must resolve every ring to its own members).
Golden golden() {
    Golden g;
    for (const T::GoldenTx& tx : T::input_consensus_golden()) {
        std::vector<std::uint8_t> blob = kat::from_hex(tx.full_hex);
        native::DecodedTx d;
        if (native::decode_relayed_tx(blob.data(), blob.size(), d) != native::TxDecodeStatus::Ok
            || d.clsags.empty() || d.key_offsets.size() != tx.inputs.size())
            continue;
        std::map<std::uint64_t, native::OutputRecord> mine;
        bool clash = false;
        for (std::size_t i = 0; i < d.key_offsets.size(); ++i) {
            std::uint64_t acc = 0;
            for (std::size_t j = 0; j < d.key_offsets[i].size() && j < tx.inputs[i].members.size(); ++j) {
                acc += d.key_offsets[i][j];
                native::OutputRecord o;
                o.pubkey     = hash_hex(tx.inputs[i].members[j].dest);
                o.commitment = hash_hex(tx.inputs[i].members[j].mask);
                o.height = 0; o.unlock_time = 0;
                if (g.rings.outs.count(acc)) clash = true;
                mine[acc] = o;
            }
        }
        if (clash) continue;
        g.rings.outs.insert(mine.begin(), mine.end());
        g.blobs.push_back(std::move(blob));
        g.ids.push_back(d.id);
    }
    return g;
}

PeerRef peer(std::uint64_t id) { PeerRef p; p.peer_id = id; p.addr = "198.51.100." + std::to_string(id) + ":18080"; return p; }

// A pool that relays over a connected tip (the "network" peer's pool).
void fill_peer_pool(RelayedTxPool& p, Golden& g) {
    p.set_input_consensus_sources(&g.rings, &g.rings);
    p.set_synced(true);
    native::BlockTxEvent tip;
    tip.kind = native::BlockTxEvent::Kind::Connected;
    tip.height = kAnchorHeight;
    p.on_block_connected(tip);
    (void)p.on_relayed(peer(9), g.blobs, /*fluff=*/true);
}

// ===========================================================================
void test_a_gate(Golden& g) {
    std::printf("== A. gate: a resumed node admits relays as soon as the gate opens ==\n");
    Chain c;
    if (!c.ok) return;
    const native::SyncState ss = c.idx->view().sync_state();
    const bool tmpl = c.idx->view().template_inputs().has_value();
    kat::checkf(ss.synced && tmpl,
                "A1 the relay-gate predicate (view synced=%d) is the template predicate (template_inputs=%d)",
                ss.synced ? 1 : 0, tmpl ? 1 : 0);
    const auto tip = c.idx->view().tip();
    kat::checkf(tip && tip->height == kAnchorHeight, "A2 rig: the index sits at its boot tip with no block connected");

    RelayedTxPool pool;
    pool.set_input_consensus_sources(&g.rings, &g.rings);
    // What NativeNode::publish_tx_gate_ does when the gate opens: seat the
    // pool's chain context from the index, then open the gate.
    const bool seated = tip && seat_tip_(pool, tip->height);
    pool.set_synced(ss.synced);
    kat::checkf(seated, "A3 the gate-open step seats the pool's tip from the index (RelayedTxPool::seat_tip)");

    const auto v = pool.on_relayed(peer(1), {g.blobs.at(0)}, /*fluff=*/true);
    const bool accepted = v.size() == 1 && v[0].reason == TxRelayVerdict::Reason::Accepted;
    kat::checkf(accepted, "A4 a valid mainnet tx relayed right after the gate opens is ADMITTED (got %s; "
                "base: RingMemberLocked, judged against block 1)",
                v.empty() ? "none" : native::to_string(v[0].reason));
    if (accepted)
        kat::check((v[0].evidence & native::AdmissionEvidence::InputConsensus) == native::AdmissionEvidence::InputConsensus,
                   "A5 ...with full input-consensus evidence (the ring resolved and verified)");
    kat::checkf(pool.stats().rejected_member_locked == 0, "A6 no relay refused RingMemberLocked (%llu)",
                (unsigned long long)pool.stats().rejected_member_locked);

    // A block event after the seat moves the context as before, and a late
    // seat never walks it back.
    native::BlockTxEvent nb;
    nb.kind = native::BlockTxEvent::Kind::Connected;
    nb.height = kAnchorHeight + 1;
    pool.on_block_connected(nb);
    (void)seat_tip_(pool, kAnchorHeight - 500);
    const auto v2 = pool.on_relayed(peer(1), {g.blobs.at(g.blobs.size() > 1 ? 1 : 0)}, true);
    kat::check(!v2.empty() && v2[0].reason != TxRelayVerdict::Reason::RingMemberLocked,
               "A7 a stale seat after a block event is a no-op (context not walked back)");
}

// ===========================================================================
void test_b_backfill(Golden& g) {
    std::printf("== B. back-fill: a fresh pool takes a peer's complement (2010 -> 2002) ==\n");
    RelayedTxPool theirs;
    fill_peer_pool(theirs, g);
    const std::size_t n_theirs = theirs.selectable_backlog().size();
    kat::checkf(n_theirs == g.blobs.size() && n_theirs >= 2,
                "B0 rig: the peer's pool holds %zu selectable mainnet txs (of %zu)", n_theirs, g.blobs.size());

    RelayedTxPool mine;   // the restarted node: gate open, tip seated, pool empty
    mine.set_input_consensus_sources(&g.rings, &g.rings);
    if (!seat_tip_(mine, kAnchorHeight)) {
        // Base tree: no seat. Hand it the tip by a block event so B measures
        // the back-fill path alone, not A's seam again.
        native::BlockTxEvent t0;
        t0.kind = native::BlockTxEvent::Kind::Connected;
        t0.height = kAnchorHeight;
        mine.on_block_connected(t0);
    }
    mine.set_synced(true);

    // Our 2010, on the wire and back.
    lv::GetTxpoolComplement req;
    req.hashes = mine.complement_request_ids();
    std::vector<std::uint8_t> body;
    lv::MessageError err = lv::MessageError::None;
    const bool enc = lv::encode_get_txpool_complement(req, body, err);
    lv::GetTxpoolComplement back;
    const bool dec = enc && lv::decode_get_txpool_complement(body.data(), body.size(), back, err);
    kat::checkf(enc && dec && back.hashes == req.hashes, "B1 the 2010 request round-trips (%zu ids)", req.hashes.size());

    // The peer answers with everything we lack (monerod get_complement).
    std::set<Hash> have(back.hashes.begin(), back.hashes.end());
    std::vector<std::vector<std::uint8_t>> answer;
    for (const auto& e : theirs.selectable_backlog()) {
        if (have.count(e.id)) continue;
        std::vector<std::uint8_t> blob;
        if (theirs.get_tx(e.id, blob)) answer.push_back(std::move(blob));
    }

    // The answer is solicited: a 600-tx answer must not trip the 512-tx flood
    // bucket (an honest peer with a busy pool would be scored as a flooder).
    // (The answer carries its wire shape, dandelionpp_fluff=false: see D.)
    native::p2p::PeerDosGuard guard;
    const bool minted = solicit_(guard, 1000);
    const auto act = frame_(guard, 600 * 2500, 600, 1000, /*complement_shaped=*/true);
    kat::checkf(minted && act == native::p2p::DosAction::Accept,
                "B2 a 600-tx complement answer is accepted on its solicited credit (minted=%d, action=%d)",
                minted ? 1 : 0, (int)act);
    native::p2p::PeerDosGuard unsolicited;
    const auto act2 = frame_(unsolicited, 600 * 2500, 600, 1000, /*complement_shaped=*/true);
    kat::checkf(act2 != native::p2p::DosAction::Accept,
                "B3 (control) the same 600-tx frame UNSOLICITED is still refused by the flood bucket");

    // Control: monerod leaves dandelionpp_fluff zero-initialised in the answer;
    // admitted as-is it would be stem and never selectable (allow_stem=false).
    {
        RelayedTxPool stem;
        stem.set_input_consensus_sources(&g.rings, &g.rings);
        native::BlockTxEvent t0; t0.kind = native::BlockTxEvent::Kind::Connected; t0.height = kAnchorHeight;
        stem.on_block_connected(t0);
        stem.set_synced(true);
        (void)stem.on_relayed(peer(2), answer, /*fluff=*/false);
        kat::checkf(stem.selectable_backlog().empty(),
                    "B4 (control) the answer admitted with its wire stem flag is not selectable (%zu)",
                    stem.selectable_backlog().size());
    }

    const auto v = complement_(mine, peer(2), answer);
    kat::check(v.has_value(), "B5 the pool has a complement-answer path (IRelayedTxSink::on_complement)");
    std::size_t acc = 0;
    if (v) for (const auto& r : *v) if (r.reason == TxRelayVerdict::Reason::Accepted) ++acc;
    const std::size_t n_mine = mine.selectable_backlog().size();
    kat::checkf(v && acc == answer.size() && n_mine == n_theirs,
                "B6 the fresh pool now holds the peer's whole selectable pool: %zu of %zu (accepted %zu, validated)",
                n_mine, n_theirs, acc);
    kat::checkf(mine.stats().rejected == 0, "B7 nothing in the back-fill was refused (%llu)",
                (unsigned long long)mine.stats().rejected);
    kat::checkf(mine.complement_request_ids().size() == n_mine,
                "B8 the next round asks with every id we now hold (%zu)", mine.complement_request_ids().size());
}

// ===========================================================================
void test_c_warm(Golden& g) {
    std::printf("== C. warm: no job before the pool is warm; selection unchanged after ==\n");
    Chain c;
    if (!c.ok) return;
    RelayedTxPool pool;
    fill_peer_pool(pool, g);

    native::tmpl::NativeTemplatePolicy pol;
    pol.band_div = 0;
    native::tmpl::NativeMinerDataSource gated(*c.idx, pool, pol, &pool);
    native::tmpl::NativeMinerDataSource plain(*c.idx, pool, pol, &pool);
    std::atomic<bool> warm{false};
    const bool wired = warm_gate_(gated, &warm);
    kat::check(wired, "C1 the native source takes a warm gate (NativeMinerDataSource::set_warm_gate)");

    std::string why;
    const auto cold = gated.snapshot(&why);
    kat::checkf(!gated.readiness().ok() && !cold.has_value(),
                "C2 while the pool is cold: not ready and NO template (%s)",
                cold ? "a template was served" : why.c_str());

    warm.store(true);
    const auto hot  = gated.snapshot(&why);
    const auto ref  = plain.snapshot(&why);
    kat::checkf(gated.readiness().ok() && hot.has_value(), "C3 once warm the template is served (%s)", why.c_str());
    if (!hot || !ref) return;
    bool same = hot->tx_backlog.size() == ref->tx_backlog.size() && hot->height == ref->height
             && hot->prev_id == ref->prev_id;
    for (std::size_t i = 0; same && i < hot->tx_backlog.size(); ++i)
        same = hot->tx_backlog[i].id == ref->tx_backlog[i].id
            && hot->tx_backlog[i].fee == ref->tx_backlog[i].fee
            && hot->tx_backlog[i].weight == ref->tx_backlog[i].weight;
    kat::checkf(same && !hot->tx_backlog.empty(),
                "C4 the warm template selects exactly what the ungated source selects on the same pool "
                "(%zu txs, same order/fee/weight): fee/weight selection unchanged", hot->tx_backlog.size());
    kat::check(gated.good_citizen_violations() == 0, "C5 no good-citizen violation");
}


// ===========================================================================
void test_d_credit() {
    std::printf("== D. credit: the 2010 credit is spent by the answer, not by a relay racing it ==\n");
    // The answer's wire shape, straight from the codec: monerod's answer is a
    // struct_init'd NOTIFY_NEW_TRANSACTIONS, so dandelionpp_fluff=false is on
    // the wire; a relay is fluffed (and the KV default, when absent, is fluff).
    {
        lv::NewTransactions ans; ans.txs.push_back({0x01, 0x02}); ans.dandelionpp_fluff = false;
        lv::NewTransactions rel; rel.txs.push_back({0x03, 0x04}); rel.dandelionpp_fluff = true;
        std::vector<std::uint8_t> ba, br;
        lv::MessageError err = lv::MessageError::None;
        lv::NewTransactions da, dr;
        const bool ok = lv::encode_new_transactions(ans, ba, err) && lv::encode_new_transactions(rel, br, err)
                     && lv::decode_new_transactions(ba.data(), ba.size(), da, err)
                     && lv::decode_new_transactions(br.data(), br.size(), dr, err);
        kat::checkf(ok && !da.dandelionpp_fluff && dr.dandelionpp_fluff,
                    "D0 rig: the answer decodes stem-flagged (fluff=%d), a relay fluffed (fluff=%d)",
                    ok ? (int)da.dandelionpp_fluff : -1, ok ? (int)dr.dandelionpp_fluff : -1);
    }
    native::p2p::PeerDosGuard g;
    const bool minted = solicit_(g, 1000);
    kat::check(minted, "D1 rig: our 2010 mints the complement credit");
    // A regular fluffed relay (3 txs) lands between our 2010 and the answer.
    const auto a1 = frame_(g, 3 * 2500, 3, 1001, /*complement_shaped=*/false);
    kat::checkf(a1 == native::p2p::DosAction::Accept && g.complement_credits_used() == 0,
                "D2 a fluffed relay racing the answer is charged to the flood bucket and does NOT spend "
                "the credit (action=%d, credits used=%llu; base: 1)",
                (int)a1, (unsigned long long)g.complement_credits_used());
    // The real answer: the peer's whole pool, 600 txs (> the 512-tx bucket).
    const auto a2 = frame_(g, 600 * 2500, 600, 1002, /*complement_shaped=*/true);
    kat::checkf(a2 == native::p2p::DosAction::Accept && g.complement_credits_used() == 1,
                "D3 the real answer spends the credit and is NOT charged to the flood bucket "
                "(action=%d, credits used=%llu; base: refused by the bucket)",
                (int)a2, (unsigned long long)g.complement_credits_used());
    // Single use: a second answer-shaped frame is charged like any 2002.
    const auto a3 = frame_(g, 600 * 2500, 600, 1003, /*complement_shaped=*/true);
    kat::checkf(a3 != native::p2p::DosAction::Accept && g.complement_credits_used() == 1,
                "D4 (control) the credit is single-use: a second 600-tx answer-shaped frame is refused (action=%d)",
                (int)a3);
    // Unsolicited: an answer-shaped frame with no 2010 outstanding mints nothing.
    native::p2p::PeerDosGuard cold;
    const auto a4 = frame_(cold, 600 * 2500, 600, 1000, /*complement_shaped=*/true);
    kat::checkf(a4 != native::p2p::DosAction::Accept && cold.complement_credits_used() == 0,
                "D5 (control) an answer-shaped 600-tx frame with no 2010 outstanding is refused (action=%d)", (int)a4);
}

// ===========================================================================
void test_e_regain() {
    std::printf("== E. regain: every relay-gate opening is a new complement round ==\n");
#if defined(XMR_P2P_HAVE_COMPLEMENT_ROUNDS) && defined(XMR_NATIVE_HAVE_TX_RELAY_GATE_LATCH)
    native::TxRelayGateLatch gate;
    native::p2p::ComplementRounds rounds(2);
    std::map<std::string, std::uint64_t> asked_in;   // link -> round it was last asked in
    auto ask_all = [&] {
        std::size_t n = 0;
        for (const char* k : {"mac", "p1", "p2"})
            if (rounds.may_ask(asked_in[k])) { asked_in[k] = rounds.note_asked(); ++n; }
        return n;
    };
    auto st = gate.evaluate(true);
    if (st.arm_complement) rounds.arm();
    const std::size_t n1 = ask_all();
    kat::checkf(st.open && st.arm_complement && rounds.round() == 1 && n1 == 2,
                "E1 boot: the gate opens, round 1 asks 2 links (quota) (open=%d arm=%d asked=%zu)",
                st.open ? 1 : 0, st.arm_complement ? 1 : 0, n1);
    kat::checkf(ask_all() == 0, "E2 no link is asked twice in one round");
    st = gate.evaluate(false);
    kat::check(st.changed && !st.open && !st.arm_complement, "E3 sync loss closes the gate (no round)");
    st = gate.evaluate(true);
    if (st.arm_complement) rounds.arm();
    const std::size_t n2 = ask_all();
    kat::checkf(st.open && st.arm_complement && rounds.round() == 2 && n2 == 2 && asked_in["mac"] == 2,
                "E4 sync REGAIN re-opens the gate and starts round 2: the same links are asked again (%zu)", n2);
    st = gate.evaluate(true);
    kat::check(!st.changed && !st.arm_complement, "E5 a steady open gate starts no round");
    kat::checkf(gate.opens() == 2 && gate.closes() == 1, "E6 opens=%llu closes=%llu",
                (unsigned long long)gate.opens(), (unsigned long long)gate.closes());
#else
    kat::check(false, "E1 complement rounds + relay-gate latch exist (absent: the back-fill is once per process)");
#endif
}

// ===========================================================================
void test_f_hold(Golden& g) {
    std::printf("== F. hold: the gate opens only once the output set holds the index tip ==\n");
    // Control (both trees): what an answer admitted against a LAGGING output
    // set becomes -- ring unresolved, excluded from every template.
    {
        RingSource lag;   // the output set before the batch's BlockTxEvents: no members yet
        RelayedTxPool pool;
        pool.set_input_consensus_sources(&lag, &lag);
        (void)seat_tip_(pool, kAnchorHeight);
        pool.set_synced(true);
        const auto v = complement_(pool, peer(3), g.blobs);
        const std::size_t sel = pool.selectable_backlog().size();
        kat::checkf(v && pool.stats().unresolved_ring == g.blobs.size() && sel == 0,
                    "F0 (control) a back-fill admitted while the output set lags: %llu of %zu rings unresolved, "
                    "%zu selectable -- the fresh-boot defect", (unsigned long long)pool.stats().unresolved_ring,
                    g.blobs.size(), sel);
    }
#if defined(XMR_NATIVE_HAVE_TX_RELAY_GATE_LATCH)
    native::TxRelayGateLatch gate;
    // The catch-up batch that closes the sync: its MainchainEvents come first.
    gate.note_chain_events_pending();
    auto st = gate.evaluate(/*index synced=*/true);
    kat::checkf(!st.open && st.held && !st.arm_complement,
                "F1 index synced but the batch's BlockTxEvents not yet fed: the gate is HELD, no 2010 (open=%d)",
                st.open ? 1 : 0);
    st = gate.evaluate(true);
    kat::check(!st.open, "F2 ...still held on the next MainchainEvent of the same flush");
    // The tx sink fed the index tip's outputs.
    gate.note_outset_at_tip();
    st = gate.evaluate(true);
    kat::checkf(st.open && st.changed && st.arm_complement && gate.held_before_last_open() == 2,
                "F3 the output set holds the tip: the gate OPENS and the 2010 round starts (held %llu evaluations)",
                (unsigned long long)gate.held_before_last_open());
    // The answer now resolves against the whole output set.
    RelayedTxPool pool;
    pool.set_input_consensus_sources(&g.rings, &g.rings);
    (void)seat_tip_(pool, kAnchorHeight);
    pool.set_synced(st.open);
    const auto v = complement_(pool, peer(3), g.blobs);
    kat::checkf(v && pool.stats().unresolved_ring == 0 && pool.selectable_backlog().size() == g.blobs.size(),
                "F4 the answer admitted after the hold: 0 unresolved, %zu of %zu selectable",
                pool.selectable_backlog().size(), g.blobs.size());
    // Steady state: a new block's flush lags the output set by one event, but an
    // OPEN gate is not closed by it (no refusal window, no spurious round).
    gate.note_chain_events_pending();
    st = gate.evaluate(true);
    kat::check(st.open && !st.changed && !st.arm_complement,
               "F5 steady state: an open gate stays open through a block's flush (no new round)");
    // A sync loss still closes it; a regain waits for the output set again.
    st = gate.evaluate(false);
    kat::check(!st.open && st.changed, "F6 sync loss closes the gate");
    gate.note_chain_events_pending();
    st = gate.evaluate(true);
    kat::check(!st.open && st.held, "F7 regain inside a catch-up flush is held for the output set too");
    gate.note_outset_at_tip();
    st = gate.evaluate(true);
    kat::check(st.open && st.arm_complement, "F8 ...and opens with a new round once the output set holds the tip");
#else
    kat::check(false, "F1 the relay gate waits for the output set (absent: it opens on the first MainchainEvent)");
#endif
}

}  // namespace

int main() {
    Golden g = golden();
    kat::checkf(g.blobs.size() >= 2, "rig: %zu decodable golden mainnet txs with disjoint rings", g.blobs.size());
    if (g.blobs.size() >= 2) {
        test_a_gate(g);
        test_b_backfill(g);
        test_c_warm(g);
        test_d_credit();
        test_e_regain();
        test_f_hold(g);
    }
    return kat::report("xmr_native_txpool_resume_kat");
}
