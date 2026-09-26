// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// v37_xmr_fee_rbind_kat -- SEAM-1 (rbind in the coinbase) + the fee-model
// rulings S3 (give-author in the PoW-committed receipt) and S4 (FeeModelGate,
// tag-folded) on the v37 XMR lane.
//
//   T  SEAM-1 on REAL assembled templates (XmrBlockAssembler, 6 owed + 5 txs,
//      the midstate fast path): with a per-job binder the 0x02 payload is
//      [extra_nonce 4 | rbind 32 | pad | tail]; payload[4..36) ==
//      rbind_v1(chain, side) for every bound job; the served miner_tx prefix
//      re-derives under X6 (canonical_coinbase_matches) with the payload AS
//      ASSEMBLED; the hashing blob's tree root is the root of the TRUE
//      coinbase hash (the patched fast path == a full re-hash); an unbound
//      job's region is zero; no binder => byte-identical to a pre-SEAM-1
//      template.
//   R  the relay mint on those templates: mint -> check_structural ACCEPTS
//      under BindMode::Rbind; swapping payee / give-author / using another
//      job's side -> refused at Bind (before RandomX); an unbound job's
//      receipt is refused at Bind; bind=none still accepts (extra, not
//      different).
//   G  S3 ingest: two nodes with DIFFERENT give-author % fold the same
//      admitted receipts to byte-identical lanes (V37Engine digests) when the
//      gate is ON; the donation's lane weight == Σ(receipt u16s); gate OFF is
//      the master shape (one push of weight 1 per receipt, give-author
//      ignored); each receipt's (pos_first, n_pushes) is reported for the
//      vault / repair; the durable log reloads the split identically.
//   L  S4: lane_params_digest(default) keeps master's golden; ON differs from
//      OFF (a mixed fleet refuses at HELLO, reason named); the fold covers the
//      version; FeeModelGate factory.
//   W  S3 (Family-A): WorkEvent::donation is PoW-committed -- d = 0 keeps the
//      112-byte preimage (every golden holds), d != 0 gives 114 bytes and a
//      different hash; donation_split is exact.
//   J  the job binding: make_job_binding / RbindRegistry (first write wins,
//      bounded FIFO, bind_bytes == rbind), owner-fee substitution lands in the
//      PoW-bound side (identity of the owner).
#include <algorithm>
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <map>
#include <memory>
#include <string>
#include <vector>

#include <unistd.h>

#include "xmr_relay_test_util.hpp"
#include "impl/xmr/template/xmr_block_assembly.hpp"
#include <c2pool/v37/xmr/relay/xmr_rbind_registry.hpp>
#include <c2pool/v37/xmr/relay/xmr_receipt_ingest.hpp>
#include <c2pool/v37/xmr/xmr_fee_model.hpp>
#include <c2pool/v37/v37_engine.hpp>
#include <c2pool/v37/w2_receipt.hpp>

using namespace gap2test;
namespace asm_ = ::c2pool::xmr::assembly;
namespace akat = ::c2pool::xmr::assembly::kat;
namespace x6   = ::v37::xmr::settle;
namespace fee  = ::c2pool::v37n::xmr::fee;
namespace vx   = ::v37::xmr::verify;

namespace {

constexpr u64 kSd = 5000;

// Build a K2-shaped template (6 owed + 5 txs => the extra nonce sits past one
// Keccak block, i.e. the midstate FAST path), optionally with a binder.
std::unique_ptr<asm_::AssembledTemplate> build_tpl(const RbindRegistry* reg, std::string& why, bool bind_fn_only = false) {
    asm_::AssemblyInputs a;
    a.miner = akat::miner(3000000, 300000, 18000000000000000000ull);
    a.settle = akat::lane_ctx();
    a.mempool = akat::txs(5, 2000, 30000000);
    for (unsigned char i = 0; i < 6; ++i) {
        x6::OwedEntry e; e.pay = akat::std_ref(); e.owed = 1000000000ull * (i + 1); e.first_eligible = 100 + (5 - i);
        e.identity = akat::id_of(static_cast<unsigned char>(0x40 + i));
        a.settle.owed.push_back(e);
    }
    if (reg) {
        a.extra_nonce_bind_size = bind_fn_only ? 0 : RbindRegistry::kBindBytes;
        a.extra_nonce_bind = [reg](std::uint32_t en, std::uint8_t* out) { return reg->bind_bytes(en, out); };
    }
    return asm_::XmrBlockAssembler::build(a, &why);
}

// The 0x02 payload of a materialized block.
bool payload_of(const asm_::BlockBytes& b, std::vector<u8>& nonce) {
    BlockLayout L;
    if (!parse_block_layout(b.full_blob, L)) return false;
    const std::vector<u8> prefix(b.full_blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset),
                                 b.full_blob.begin() + static_cast<std::ptrdiff_t>(L.miner_tx_offset + L.prefix_size));
    const std::vector<u8> extra(prefix.end() - static_cast<std::ptrdiff_t>(L.extra_size), prefix.end());
    vx::ParsedTxExtra px;
    if (!vx::parse_tx_extra(extra, px) || !px.has_nonce) return false;
    nonce = px.nonce;
    return true;
}

// The ACCEPT re-derivation over the payload AS ASSEMBLED (what a peer does).
bool canonical_ok(const asm_::AssembledTemplate& t, const asm_::BlockBytes& b, const std::vector<u8>& nonce) {
    x6::CoinbaseInputs ref = t.coinbase_inputs();
    ref.extra_nonce.assign(nonce.begin(), nonce.end());
    x6::ReceivedCoinbase rc; std::uint64_t h = 0; std::size_t used = 0;
    if (!asm_::parse_coinbase_prefix(b.full_blob.data() + b.miner_tx_offset, b.miner_tx_size, rc, &h, &used)) return false;
    const auto cb = x6::build_coinbase(ref);
    return cb.ok && x6::canonical_coinbase_matches(ref, rc).matches && b.coinbase_prefix() == cb.prefix;
}

// The TRUE tree root (full re-hash of the served prefix) vs the one in the hashing blob.
bool root_is_true(const asm_::BlockBytes& b) {
    std::vector<::xmr::coin::Hash256> leaves;
    leaves.push_back(::xmr::coin::coinbase_tx_hash(::xmr::coin::tx_prefix_hash(b.coinbase_prefix())));
    for (const auto& h : b.tx_hashes) leaves.push_back(h);
    return ::xmr::coin::tree_root(leaves) == b.tree_root;
}

std::vector<u8> with_nonce_hb(const asm_::BlockBytes& b, std::uint32_t nonce) {
    std::vector<u8> h = b.hashing_blob;
    for (int i = 0; i < 4; ++i) h[b.nonce_offset + i] = static_cast<u8>(nonce >> (8 * i));
    return h;
}

} // namespace

int main() {
    Checker C;
    std::printf("== v37_xmr_fee_rbind_kat ==\n");
    const u32 chain = akat::lane_ctx().chain_id;
    const ::v37::ScriptRef payA = payee_of("A"), payB = payee_of("B"), owner = payee_of("owner");

    // ── J: the job binding ───────────────────────────────────────────────────
    RbindRegistry reg(4);
    {
        const JobBinding ja = make_job_binding(chain, kSd, payA, 655);
        C(ja.side.identity == ::v37::xmr::xmr_identity_key(payA) && ja.side.chain_id == chain && ja.side.t_lo == kSd &&
          ja.side.give_author == 655 && ja.rbind == rbind_v1(chain, ja.side), "J1 make_job_binding: side (t, identity, chain, u16) + rbind_v1");
        C(reg.put(10, ja) && !reg.put(10, make_job_binding(chain, kSd, payB, 0)), "J2 first write wins (a bound job never changes)");
        std::uint8_t out[32] = {0};
        C(reg.bind_bytes(10, out) && std::memcmp(out, ja.rbind.data(), 32) == 0, "J3 bind_bytes(10) == the job's rbind");
        C(!reg.bind_bytes(11, out), "J4 an unbound extra_nonce -> no bytes (the template leaves zeros)");
        RbindRegistry small(2);
        small.put(1, ja); small.put(2, ja); small.put(3, ja);
        C(small.size() == 2 && !small.get(1) && small.get(3), "J5 bounded FIFO (oldest job ages out)");
        bool hit = false;
        const ::v37::ScriptRef p = fee::choose_payee(payA, owner, 10000, 7, &hit);
        const JobBinding jo = make_job_binding(chain, kSd, p, 0, hit);
        C(hit && jo.payee == owner && jo.side.identity == ::v37::xmr::xmr_identity_key(owner) && jo.owner_substituted,
          "J6 owner-fee hit at job issue: the PoW-bound side names the OWNER");
    }

    // ── T: SEAM-1 in real templates ─────────────────────────────────────────
    RbindRegistry R;
    R.put(7, make_job_binding(chain, kSd, payA, 655));
    R.put(8, make_job_binding(chain, kSd, payB, 0));
    std::string why;
    auto t = build_tpl(&R, why);
    C(t != nullptr, "T1 bound template builds (6 owed + 5 txs) " + why);
    auto t0 = build_tpl(nullptr, why);
    auto tf = build_tpl(&R, why, /*bind_fn_only=*/true);
    C(t0 && tf, "T2 unbound templates build");
    if (!t || !t0 || !tf) return C.done("v37_xmr_fee_rbind_kat");
    {
        asm_::BlockBytes a0, af;
        C(t0->materialize(7, a0) && tf->materialize(7, af) && a0.full_blob == af.full_blob && a0.hashing_blob == af.hashing_blob,
          "T2 a binder with size 0 == no binder: BYTE-IDENTICAL to a pre-SEAM-1 template");
        asm_::BlockBytes b0; C(t0->materialize(0, b0) && b0.extra_nonce_size + 32 == [&]{ asm_::BlockBytes x; (void)t->materialize(0, x); return x.extra_nonce_size; }(),
          "T3 the bound payload is exactly 32 bytes longer ([extra_nonce | rbind 32 | pad | tail])");
    }
    for (std::uint32_t en : {7u, 8u}) {
        asm_::BlockBytes b; std::vector<u8> nonce;
        const std::string tag = "T(en=" + std::to_string(en) + ")";
        const bool mat = t->materialize(en, b, &why) && payload_of(b, nonce);
        C(mat, tag + " materialize + parse 0x02 " + why);
        if (!mat) continue;
        const auto jb = R.get(en);
        C(nonce.size() >= 36 && nonce[0] == static_cast<u8>(en) && nonce[1] == 0 && std::memcmp(nonce.data() + 4, jb->rbind.data(), 32) == 0,
          tag + " payload = [extra_nonce LE | rbind_v1(chain, side) | ...]");
        C(canonical_ok(*t, b, nonce), tag + " served prefix == X6 build_coinbase(payload as assembled): canonical_coinbase_matches");
        C(root_is_true(b), tag + " hashing-blob tree root == root of the TRUE coinbase hash (patched fast path == full re-hash)");
        C(b.miner_tx_offset + 0 < b.extra_nonce_offset && b.extra_nonce_offset - b.miner_tx_offset >= 136,
          tag + " the 0x02 region sits past one Keccak block (the midstate fast path is the one exercised)");
    }
    {
        asm_::BlockBytes b; std::vector<u8> nonce;
        C(t->materialize(9, b) && payload_of(b, nonce) && nonce.size() >= 36 &&
          std::all_of(nonce.begin() + 4, nonce.begin() + 36, [](u8 x) { return x == 0; }) && root_is_true(b) && canonical_ok(*t, b, nonce),
          "T4 an UNBOUND job (en=9): the region stays zero, still a canonical, correctly-hashed block");
    }

    // ── R: the relay mint on SEAM-1 templates ────────────────────────────────
    {
        CheckCtx rb; rb.lane_chain = chain; rb.share_diff = kSd; rb.bind = BindMode::Rbind;
        CheckCtx none = rb; none.bind = BindMode::None;
        asm_::BlockBytes b7, b8, b9;
        (void)t->materialize(7, b7); (void)t->materialize(8, b8); (void)t->materialize(9, b9);
        const JobBinding j7 = *R.get(7), j8 = *R.get(8);
        FbReceipt r7, r8;
        C(mint_receipt(b7.full_blob, with_nonce_hb(b7, 1234), j7.side, j7.payee, r7, &why), "R1 mint on the bound job 7 (payee A, u16 655) " + why);
        C(check_structural(r7, rb).ok(), "R1 check_structural ACCEPTS under bind=rbind (0x02[4..36) == rbind_v1)");
        C(check_structural(r7, none).ok(), "R1 bind=none also accepts it (the binding is extra, not different)");
        C(mint_receipt(b8.full_blob, with_nonce_hb(b8, 99), j8.side, j8.payee, r8, &why) && check_structural(r8, rb).ok(),
          "R2 a second job (payee B, u16 0) on the same template also ACCEPTS");
        auto stage = [&](FbReceipt x) { return check_structural(x, rb).stage; };
        { FbReceipt x = r7; x.payee = payB; x.side.identity = ::v37::xmr::xmr_identity_key(payB); x.receipt.info_digest = side_digest_v2(x.side);
          C(stage(x) == CheckStage::Bind, "R3 payee swapped (identity + info_digest re-made) -> refused at Bind (before RandomX)"); }
        { FbReceipt x = r7; x.side.give_author = 65535; x.receipt.info_digest = side_digest_v2(x.side);
          C(stage(x) == CheckStage::Bind, "R4 give-author inflated to 65535 (info_digest re-made) -> refused at Bind: the u16 is PoW-bound"); }
        { FbReceipt x = r7; x.side.give_author = 0; x.receipt.info_digest = side_digest_v2(x.side);
          C(stage(x) == CheckStage::Bind, "R5 give-author zeroed (a node stripping the donation) -> refused at Bind"); }
        { FbReceipt x; bool ok = mint_receipt(b8.full_blob, with_nonce_hb(b8, 99), j7.side, j7.payee, x, &why);
          C(ok && stage(x) == CheckStage::Bind, "R6 job 7's side on job 8's coinbase -> refused at Bind"); }
        { FbReceipt x; bool ok = mint_receipt(b9.full_blob, with_nonce_hb(b9, 5), j7.side, j7.payee, x, &why);
          C(ok && stage(x) == CheckStage::Bind && check_structural(x, none).ok(), "R7 an UNBOUND job's receipt: refused under rbind, accepted under none"); }
    }

    // ── G: S3 ingest (two nodes, different give-author, same receipts) ──────
    {
        // Receipts minted by node A (u16 328 = 0.5%) and node B (u16 655 = 1%), synthetic blocks.
        std::vector<Admitted> adm;
        for (int i = 0; i < 12; ++i) {
            const bool fromA = (i % 3) != 0;
            const ::v37::ScriptRef p = fromA ? payA : payB;
            const u16 d = fromA ? fee::give_author_u16(0.5) : fee::give_author_u16(1.0);
            const SideDataV2 side = side_for(p, chain, kSd, d);
            const bytes32 rbv = rbind_v1(chain, side);
            const SynthBlock sb = make_block(400 + i, b32_of(static_cast<u8>(50 + i)), 30 + i, &rbv, 2, static_cast<u8>(i));
            Admitted a;
            if (!mint_receipt(sb.full_blob, with_nonce(sb, 1), side, p, a.r)) continue;
            a.id = receipt_id(a.r); a.raw = encode_fb_receipt(a.r); a.bin = 400 + i;
            adm.push_back(a);
        }
        C(adm.size() == 12, "G0 12 PoW-carrying receipts minted (8 from a 0.5% node, 4 from a 1% node)");
        struct Lane {
            std::unique_ptr<c2pool::v37n::V37Engine> eng = std::make_unique<c2pool::v37n::V37Engine>();
            std::vector<std::pair<::v37::ScriptRef, u64>> log;
            std::vector<std::pair<u64, u32>> spans;
            std::unique_ptr<XmrReceiptIngest> ing;
            Lane(bool fee_on, const std::string& durable) {
                eng->start();
                eng->submit_tracked(::v37::LaneRecord::add_lane(7, ::v37::LaneParams{})).get();
                XmrReceiptIngest::Options o; o.chain = 7; o.order = XmrReceiptIngest::Order::Arrival; o.fee_model = fee_on; o.durable_path = durable;
                ing = std::make_unique<XmrReceiptIngest>(o,
                    [this](const ::v37::ScriptRef& p, u64 w, u64& next_after, bytes32& dig) {
                        ::v37::PayoutDescriptor d; d.pay = p;
                        if (!eng->submit_tracked(::v37::LaneRecord::push(7, d, w, 0)).get().applied()) return false;
                        log.emplace_back(p, w);
                        auto s = eng->snapshot(7); next_after = s->next_pos; dig = s->digest; return true;
                    },
                    [this](const Admitted&, u64 pos_first, u32 n, u64, const bytes32&) { spans.emplace_back(pos_first, n); });
            }
            ~Lane() { eng->stop(); }
            bytes32 digest() { return eng->snapshot(7)->digest; }
            u64 next() { return eng->snapshot(7)->next_pos; }
        };
        Lane nodeA(true, ""), nodeB(true, ""), off(false, "");
        for (const auto& a : adm) { nodeA.ing->on_admitted(a); nodeB.ing->on_admitted(a); off.ing->on_admitted(a); }
        C(nodeA.digest() == nodeB.digest() && nodeA.log == nodeB.log,
          "G1 gate ON: nodes with DIFFERENT give-author % fold the same receipts to a BYTE-IDENTICAL lane (" + hex(nodeA.digest()).substr(0, 16) + ")");
        u64 don = 0, tot = 0, want_don = 0;
        for (const auto& [p, w] : nodeA.log) { tot += w; if (p == fee::donation_ref()) don += w; }
        for (const auto& a : adm) want_don += a.r.side.give_author;
        C(tot == adm.size() * fee::kFeeReceiptWeight && don == want_don,
          "G2 each receipt = 65535 lane weight; the donation holds exactly Σ(receipt u16) = " + std::to_string(want_don));
        C(nodeA.next() == 2 * adm.size() && nodeA.spans.size() == adm.size() && nodeA.spans[0] == std::make_pair<u64, u32>(0, 2) &&
          nodeA.spans[1] == std::make_pair<u64, u32>(2, 2), "G3 a d != 0 receipt spans 2 positions, reported as (pos_first, n_pushes) for the vault");
        bool master_shape = off.log.size() == adm.size();
        for (std::size_t i = 0; master_shape && i < adm.size(); ++i) master_shape = off.log[i].first == adm[i].r.payee && off.log[i].second == 1;
        C(master_shape && off.next() == adm.size(), "G4 gate OFF: one push (payee, 1) per receipt, give-author ignored -- master's lane");
        C(off.digest() != nodeA.digest(), "G5 ON vs OFF fold different lanes (why S4 makes a mixed fleet refuse at HELLO)");
        // durable reload replays the split identically
        const std::string path = (std::filesystem::temp_directory_path() / ("v37_fee_rbind_kat_" + std::to_string(::getpid()) + ".receipts")).string();
        std::filesystem::remove(path);
        {
            Lane w(true, path);
            for (const auto& a : adm) w.ing->on_admitted(a);
            Lane r(true, path);
            const std::size_t n = r.ing->reload(nullptr);
            C(n == adm.size() && r.digest() == nodeA.digest() && r.log == nodeA.log, "G6 the durable log reloads the split byte-identically (" + std::to_string(n) + " receipts)");
        }
        std::filesystem::remove(path);
    }

    // ── L: S4 -- the gate is folded into the relay's lane tag ───────────────
    {
        ::v37::LaneParams off;
        const bytes32 d0 = lane_params_digest(off, 2000, BindMode::None);
        C(hex(d0) == "8f49947a8716dc16cf3cbceb01529ba9eb930042693da93f8a43a4186157da3f",
          "L1 gate OFF: lane_params_digest(default, 2000, none) == master's golden (unchanged)");
        ::v37::LaneParams on = off; on.fee = ::v37::FeeModelGate::for_version(1);
        const bytes32 d1 = lane_params_digest(on, 2000, BindMode::None);
        const bytes32 d1r = lane_params_digest(on, 2000, BindMode::Rbind);
        C(d1 != d0 && d1r != lane_params_digest(off, 2000, BindMode::Rbind) && d1 != d1r, "L2 gate ON changes the digest (both bind modes)");
        ::v37::LaneParams on2 = on; on2.fee.version = 2;
        C(lane_params_digest(on2, 2000, BindMode::None) != d1, "L3 the gate version is folded");
        Hello ha; ha.network = 3; ha.chain_id = 7; ha.share_diff = 2000; ha.node_nonce = 1; ha.lane_params_digest = d0;
        Hello hb = ha; hb.node_nonce = 2; hb.lane_params_digest = d1;
        const std::string why2 = hello_mismatch(ha, hb);
        C(why2.find("lane_params_digest") != std::string::npos, "L4 a mixed fleet (OFF vs ON) REFUSES at HELLO with the reason named: " + why2);
        C(!::v37::FeeModelGate{}.enabled && ::v37::FeeModelGate::for_version(1).enabled && !::v37::FeeModelGate::for_version(7).enabled,
          "L5 FeeModelGate: default OFF, v1 ON, unknown OFF");
    }

    // ── W: S3 Family-A -- WorkEvent::donation is PoW-committed ──────────────
    {
        ::c2pool::v37n::WorkEvent e;
        e.chain_id = 3; e.identity = b32_of(1); e.prev_block_hash = b32_of(2); e.prev_own_share = b32_of(3); e.lz_bits = 8; e.nonce = 42;
        const auto p0 = e.preimage();
        C(p0.size() == 112, "W1 donation 0: the preimage stays the 112-byte v0x01/v0x02 form (every golden holds)");
        const bytes32 h0 = e.hash();
        e.donation = 655;
        const auto p1 = e.preimage();
        C(p1.size() == 114 && std::equal(p0.begin(), p0.end(), p1.begin()) && p1[112] == (655 & 0xff) && p1[113] == (655 >> 8),
          "W2 donation 655: preimage = the 112 bytes || le16(655)");
        C(e.hash() != h0, "W3 the donation is PoW-bound: changing it changes the work hash");
        const auto [m, d] = e.donation_split(65535);
        const auto [m2, d2] = e.donation_split(1000);
        C(m == 64880 && d == 655 && m2 + d2 == 1000 && d2 == 9, "W4 donation_split: v36 weights, exact (65535 -> 64880 + 655; 1000 -> 991 + 9)");
    }

    return C.done("v37_xmr_fee_rbind_kat");
}
