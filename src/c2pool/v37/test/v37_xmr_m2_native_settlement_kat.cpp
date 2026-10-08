// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ---------------------------------------------------------------------------
// src/c2pool/v37/test/v37_xmr_m2_native_settlement_kat.cpp   --  M2 KAT
//
// THE CLAIM UNDER TEST, in one sentence: with the option-B provider bound to
// the NATIVE miner-data arm, the pool assembles a whole Monero block whose
// coinbase is still the K_fair settlement coinbase, and building it costs no
// daemon call at all.
//
// The C4 KATs already pin the two halves separately -- xmr_native_template_kat
// pins that the native arm derives monerod's seven get_miner_data fields, and
// xmr_native_template_coinbase_kat pins that the X6 coinbase is unchanged by the
// rebind. What neither of them runs is the thing that actually serves miners:
// XmrSettlementTemplateProvider, the whole-block assembler under it, and the
// bytes that come out. This KAT runs exactly that, end to end, and judges the
// result by re-parsing the assembled block.
//
// WHY THE CHECKS READ BYTES. Every shape assertion below goes through
// inspect_kfair_coinbase(), which re-parses the miner_tx out of `full_blob`
// with parse_coinbase_prefix() -- the parser a PEER uses on a block it did not
// build -- and then re-derives the canonical coinbase and byte-compares. A
// check that asked the settlement seam what it meant to pay could not fail when
// the seam is the thing that is wrong, and the seam is precisely what a rebind
// puts at risk.
//
// SUITES
//   A  NATIVE END TO END. The native arm, over the C4 golden's chain state,
//      drives the provider; the assembled block's coinbase carries the owed
//      payees in K_fair order, the exact-sum residual sink, and the ledger's
//      owed_digest under the tx_extra 0x03 tag. The template also passes the
//      assembler's own structural battery (asm_::kat::check_template) at three
//      extra nonces, so this is not a weaker restatement of it.
//   B  ARM EQUIVALENCE, AT THE BLOCK. The same capture replayed through the
//      PRODUCTION get_miner_data parser over a fake transport gives a provider
//      whose block is byte-identical to the native one from the miner_tx
//      onward, with the same reward, the same tree root and the same coinbase
//      prefix. The header is deliberately excluded: the assembler stamps a
//      fresh timestamp per build, which is a clock difference and not an arm
//      difference.
//   C  NO DAEMON CALL. The native provider refreshes repeatedly with a
//      transport wired up and watching: its call counter stays at zero. The
//      daemon-armed provider's counter moves on the same script, which is what
//      makes the zero mean something.
//   D  READINESS IS FAIL-CLOSED. A native arm with no chain state serves no
//      template: refresh() fails, no template id is ever issued, and current()
//      stays invalid.
//   E  THE SHAPE GATE IS NOT DECORATIVE. Pointed at the wrong owed_digest it
//      REFUSES, the refusal is counted as a provider failure, and -- the part
//      that matters -- the template id does not advance, so no miner is ever
//      handed the block that failed.
//   F  THE RESOLVER. serve=native with fallback OFF and a dead native arm
//      serves nothing rather than quietly serving monerod; with fallback ON it
//      serves monerod, says so, and the daemon pump count moves by exactly one.
//
// SCOPE FENCE: consumer tree + src/impl/xmr. No v37 consensus digest is
// defined and src/sharechain/v37 is not touched (the ref10 point-check
// registrar is linked, as every option-B KAT links it).
// ---------------------------------------------------------------------------
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "impl/xmr/coin/xmr_derivation.hpp"
#include "impl/xmr/native/contracts/fakes/fakes.hpp"
#include "impl/xmr/native/template/xmr_monerod_miner_data.hpp"
#include "impl/xmr/native/template/xmr_native_miner_data.hpp"
#include "impl/xmr/native/template/xmr_resolved_miner_data.hpp"
#include "impl/xmr/native/template/xmr_template_arm.hpp"

#include "c2pool/v37/xmr/xmr_o2_settlement_fixture.hpp"
#include "c2pool/v37/xmr/xmr_o2_settlement_provider.hpp"
#include "c2pool/v37/xmr/xmr_settlement_coinbase_shape.hpp"

#include "xmr_c2a_golden.hpp"
#include "xmr_c4_parity_golden.hpp"
#include "xmr_c4_state_builder.hpp"

using namespace c2pool::xmr::native;
using namespace c2pool::xmr::native::testkit;

namespace o2   = c2pool::v37n::xmr::o2;
namespace asm_ = c2pool::xmr::assembly;
namespace set_ = v37::xmr::settle;
namespace G4   = c2pool::xmr::native::golden_c4;

namespace {

int g_fail = 0;
int g_checks = 0;

#define CHECK(cond, ...)                                       \
    do {                                                       \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
    } while (0)

// The same check, but usable as an expression: a suite that cannot build its
// template must SAY SO and return, not carry on dereferencing a null one.
#define CHECK_RET(cond, ...) ([&] {                            \
        const bool _ok = (cond);                               \
        ++g_checks;                                            \
        if (!_ok) ++g_fail;                                    \
        std::printf("  [%s] ", _ok ? "PASS" : "FAIL");         \
        std::printf(__VA_ARGS__);                              \
        std::printf("\n");                                     \
        return _ok;                                            \
    }())

// ---------------------------------------------------------------------------
// The lane fixture: four DISTINCT payees the LIVE point check accepts.
//
// The option-B settlement source is strict where the raw assembler is not: it
// runs every payee through xmr_ref_valid(), which is the TORSION check, not
// merely "32 bytes that decode". The monero-project tests/crypto vectors the
// assembler's own KAT uses are canonical ed25519 points but are NOT
// prime-order, so they are rejected here -- correctly, and it is worth knowing
// that the two layers differ.
//
// So the keys are DERIVED rather than pasted: P_k = k*G for k = 1..4, through
// the vendored secret_key_to_public_key. Every one of them is prime-order by
// construction (a scalar multiple of the basepoint), they are pairwise
// distinct, and ECDH against them works, which is what the one-time output keys
// need. Four points give four distinct payout identities: three owed payees
// plus the mandated residual sink.
// ---------------------------------------------------------------------------
std::array<std::uint8_t, 32> point_of(std::uint8_t k) {
    ::xmr::coin::SecretKey sec{};
    sec.data()[0] = k;                               // a reduced scalar: 1 <= k <= 4
    ::xmr::coin::PublicKey pub{};
    if (!::xmr::coin::secret_key_to_public_key(sec, pub)) return {};
    std::array<std::uint8_t, 32> out{};
    std::memcpy(out.data(), pub.data(), 32);
    return out;
}

const std::uint32_t LANE_CHAIN = 0x0000ABCDu;

// One owed entry per seeded payee, oldest first (XmrOwedFixture advances the
// bin height per seed, which is exactly the K_fair primary sort key).
struct LaneFixture {
    o2::XmrOwedFixture   ledger{static_cast<::v37::ChainId>(LANE_CHAIN)};
    o2::XmrSettlementConfig scfg;
    std::size_t          n_owed = 0;

    LaneFixture() {
        const auto P1 = point_of(1), P2 = point_of(2), P3 = point_of(3), P4 = point_of(4);

        // Three owed payees, seeded oldest-owed-first.
        ledger.seed_owed(::v37::xmr::make_xmr_std(P1, P2), 3'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_std(P3, P2), 2'000'000'000ull);
        ledger.seed_owed(::v37::xmr::make_xmr_sub(P1, P2), 1'000'000'000ull);
        n_owed = 3;

        // The mandated residual sink: a fourth distinct identity.
        scfg.h_min      = 0;
        scfg.output_cap = 0;               // weight-aware default
        scfg.set_residual_sink_std(P4, P2);
    }
};

// A fake IMonerodTransport that answers one canned get_miner_data body and
// counts what it was asked. The counter is the point: suite C reads it.
class CountingTransport final : public ::c2pool::xmr::node::IMonerodTransport {
public:
    explicit CountingTransport(std::string body) : body_(std::move(body)) {}
    std::uint64_t calls() const { return calls_; }
    void set_error(std::string e) { error_ = std::move(e); }

    void rpc_post(const std::string&,
                  std::function<void(const ::c2pool::xmr::node::RpcResponse&)> cb) override {
        ++calls_;
        ::c2pool::xmr::node::RpcResponse r;
        if (!error_.empty()) { r.error = error_; cb(r); return; }
        r.body.assign(body_.begin(), body_.end());
        cb(r);
    }
    void zmq_subscribe(const std::string&,
                       std::function<void(const ::c2pool::xmr::node::ZmqFrame&)>) override {}

private:
    std::string   body_;
    std::string   error_;
    std::uint64_t calls_ = 0;
};

// Three transactions in the native pool, so the budget under test is
// base_reward + fees and not base_reward alone. An exact-sum check against a
// zero fee total would pass for a coinbase that silently dropped the fees.
void seed_pool(fakes::FakeTxpool& pool) {
    for (unsigned i = 0; i < 3; ++i) {
        fakes::FakeTxpool::Entry e;
        for (std::size_t k = 0; k < 32; ++k)
            e.backlog.id[k] = static_cast<std::uint8_t>(0x80 + i * 7 + k);
        e.backlog.weight = 2000;
        e.backlog.fee    = 30'000'000ull;
        e.backlog.blob_size = 2000;
        // The pool's own default select policy is the daemonless one
        // (Structural | FeePolicy); a transaction with less evidence is not
        // selectable, which is the rule under test elsewhere and not here.
        e.evidence = EVIDENCE_DAEMONLESS_DEFAULT;
        e.seen_from_peers = 2;
        e.blob.assign(e.backlog.weight, static_cast<std::uint8_t>(0xAB));
        std::string key(reinterpret_cast<const char*>(e.backlog.id.data()), 32);
        pool.entries[key] = e;
    }
}

// The shape gate the DAEMON installs, as the KAT installs it: judged against
// the ledger's digest, which the caller supplies from the ledger side.
o2::XmrSettlementTemplateProvider::ShapeGate shape_gate(const o2::XmrOwedFixture& ledger,
                                                        o2::KFairCoinbaseShape* last,
                                                        std::uint64_t* refusals) {
    return [&ledger, last, refusals](const asm_::AssembledTemplate& t, std::string* why) {
        const o2::KFairCoinbaseShape sh =
            o2::inspect_kfair_coinbase(t, ledger.ledger().owed_digest());
        if (last) *last = sh;
        if (!sh.ok) {
            if (refusals) ++*refusals;
            if (why) *why = sh.why;
            return false;
        }
        return true;
    };
}

// ===========================================================================
// Suite A -- the native arm, end to end, judged on the assembled block bytes.
// ===========================================================================
void suite_native_end_to_end() {
    std::printf("== A. NATIVE arm -> option-B provider -> a whole block ==\n");
    std::printf("   fixture: monerod %s %s, get_miner_data at height %llu\n",
                G4::MONEROD_VERSION, G4::NETWORK,
                static_cast<unsigned long long>(G4::MD_HEIGHT));

    BuiltState st;
    build_state(st, G4::MD_HEIGHT - 1);

    fakes::FakeTxpool pool;
    seed_pool(pool);
    tmpl::NativeMinerDataSource src(st.view, pool, {}, &pool);

    LaneFixture lane;
    o2::KFairCoinbaseShape shape;
    std::uint64_t refusals = 0;

    o2::XmrSettlementTemplateProvider provider(src, lane.ledger, lane.scfg, /*share_diff=*/0);
    provider.set_shape_gate(shape_gate(lane.ledger, &shape, &refusals));

    CHECK(provider.refresh(), "refresh() over the native arm: %s",
          provider.last_error().empty() ? "built" : provider.last_error().c_str());

    const o2::SettlementSnapshot snap = provider.current();
    if (!CHECK_RET(snap.valid && snap.tpl != nullptr, "a template is cached")) {
        std::printf("  (suite A cannot continue without a template)\n");
        return;
    }
    CHECK(std::string(snap.source_name) == "native", "the snapshot names the NATIVE arm (%s)",
          snap.source_name);
    CHECK(snap.height == G4::MD_HEIGHT, "template height %llu == the daemon's %llu",
          static_cast<unsigned long long>(snap.height),
          static_cast<unsigned long long>(G4::MD_HEIGHT));
    CHECK(snap.difficulty == G4::MD_DIFFICULTY_LO && snap.difficulty_top64 == G4::MD_DIFFICULTY_HI,
          "template difficulty == the daemon's next difficulty");
    CHECK(snap.major_version == G4::MD_MAJOR_VERSION, "major version %u (inside the CARROT fence)",
          static_cast<unsigned>(snap.major_version));
    CHECK(snap.n_tx == 3, "the native txpool's 3 transactions are in the block (n_tx=%zu)", snap.n_tx);
    CHECK(refusals == 0, "the shape gate refused nothing");

    // --- the shape, as parsed back out of the block --------------------------
    std::printf("   shape: %s\n", shape.describe().c_str());
    CHECK(shape.ok, "K_fair shape: %s", shape.ok ? "OK" : shape.why.c_str());
    CHECK(shape.parses, "the miner_tx prefix re-parses out of full_blob");
    CHECK(shape.canonical, "canonical_coinbase_matches(final inputs, parsed bytes)");
    CHECK(shape.n_owed == lane.n_owed, "%zu owed outputs, one per eligible payee", shape.n_owed);
    CHECK(shape.n_sink == 1 && shape.sink_last, "exactly one residual sink, and it is last");
    CHECK(shape.kfair_order, "the owed outputs are in K_fair oldest-owed-first order");
    CHECK(shape.exact_sum, "exact sum: parsed outputs %llu == base %llu + fees %llu",
          static_cast<unsigned long long>(shape.sum_outputs),
          static_cast<unsigned long long>(shape.base_reward),
          static_cast<unsigned long long>(shape.fees));
    CHECK(shape.fees == 3 * 30'000'000ull, "the fees in the budget are the pool's (%llu)",
          static_cast<unsigned long long>(shape.fees));
    CHECK(shape.owed_digest_bound,
          "tx_extra 0x03 carries mm_commitment_root(chain_id, owed_digest)");
    CHECK(shape.chain_id == LANE_CHAIN, "the lane chain id rode into the commitment (%u)",
          static_cast<unsigned>(shape.chain_id));

    // Non-vacuity: a DIFFERENT ledger digest must not bind to these bytes.
    {
        ::v37::bytes32 wrong = lane.ledger.ledger().owed_digest();
        wrong[0] = static_cast<std::uint8_t>(wrong[0] ^ 0xFF);
        const o2::KFairCoinbaseShape bad = o2::inspect_kfair_coinbase(*snap.tpl, wrong);
        CHECK(!bad.ok, "negative control: another owed_digest does NOT bind (%s)", bad.why.c_str());
    }

    // The assembler's own structural battery over the same template, so this
    // suite is not a weaker restatement of the K_fair shape check.
    {
        std::string log;
        asm_::kat::Checker C(log);
        bool ok = true;
        for (std::uint32_t en : {0u, 1u, 0xFFFFFFFFu})
            ok &= asm_::kat::check_template(C, *snap.tpl, en, "A");
        CHECK(ok && C.fail == 0, "assembler structural battery over the native template: %d/%d",
              C.pass, C.pass + C.fail);
        if (C.fail) std::printf("%s", log.c_str());
    }
}

// ===========================================================================
// Suite B -- the two arms build the same block.
// ===========================================================================
void suite_arm_equivalence() {
    std::printf("== B. NATIVE vs MONEROD arm: the same block from the miner_tx on ==\n");

    BuiltState st;
    build_state(st, G4::MD_HEIGHT - 1);
    fakes::FakeTxpool pool;
    seed_pool(pool);
    tmpl::NativeMinerDataSource native(st.view, pool, {}, &pool);

    // The daemon arm is the PRODUCTION decode path over the captured response.
    CountingTransport tx(G4::MD_RAW_JSON);
    tmpl::MonerodMinerDataSource daemon(tx);
    std::string pwhy;
    CHECK(daemon.poll(&pwhy), "the daemon arm parsed the captured get_miner_data: %s",
          pwhy.empty() ? "ok" : pwhy.c_str());

    // The daemon's get_miner_data carries no tx backlog in this capture, so the
    // two arms are only comparable when the native side selects none either:
    // a fee difference is a POOL difference, and suite A already proved the
    // native pool's fees reach the budget. Here the question is the seven
    // chain-state fields, and nothing else may move.
    fakes::FakeTxpool empty_pool;
    tmpl::NativeMinerDataSource native_nofees(st.view, empty_pool, {}, &empty_pool);

    LaneFixture lane_n, lane_d;
    o2::XmrSettlementTemplateProvider pn(native_nofees, lane_n.ledger, lane_n.scfg, 0);
    o2::XmrSettlementTemplateProvider pd(daemon, lane_d.ledger, lane_d.scfg, 0);

    CHECK(pn.refresh(), "native provider built: %s", pn.last_error().c_str());
    CHECK(pd.refresh(), "monerod provider built: %s", pd.last_error().c_str());

    const o2::SettlementSnapshot sn = pn.current();
    const o2::SettlementSnapshot sd = pd.current();
    if (!CHECK_RET(sn.valid && sd.valid && sn.tpl && sd.tpl, "both arms produced a template")) {
        std::printf("  (suite B cannot continue without both templates)\n");
        return;
    }
    CHECK(sn.height == sd.height, "same height (%llu)", static_cast<unsigned long long>(sn.height));
    CHECK(sn.prev_id == sd.prev_id, "same prev_id");
    CHECK(sn.difficulty == sd.difficulty && sn.difficulty_top64 == sd.difficulty_top64,
          "same difficulty");
    CHECK(sn.reward == sd.reward, "same reward (%llu piconero)",
          static_cast<unsigned long long>(sn.reward));
    CHECK(sn.seed_hash == sd.seed_hash, "same RandomX seed hash");
    CHECK(sn.n_outputs == sd.n_outputs, "same coinbase output count (%zu)", sn.n_outputs);

    asm_::BlockBytes bn, bd;
    std::string wn, wd;
    CHECK(sn.tpl->materialize(7, bn, &wn) && sd.tpl->materialize(7, bd, &wd),
          "both materialise at extra_nonce 7");
    CHECK(bn.coinbase_prefix() == bd.coinbase_prefix(),
          "the coinbase prefixes are BYTE-IDENTICAL (%zu B)", bn.coinbase_prefix().size());
    CHECK(bn.merkle_root == bd.merkle_root, "the same merge-mining commitment root");
    CHECK(bn.tree_root == bd.tree_root, "the same transaction tree root");
    CHECK(bn.full_blob.size() == bd.full_blob.size(), "the same full block size (%zu B)",
          bn.full_blob.size());
    CHECK(bn.miner_tx_offset == bd.miner_tx_offset, "the same header size");
    // The header carries a timestamp the assembler stamps per build; everything
    // from the miner_tx on is arm-determined and must not move.
    CHECK(bn.full_blob.size() == bd.full_blob.size() &&
              std::memcmp(bn.full_blob.data() + bn.miner_tx_offset,
                          bd.full_blob.data() + bd.miner_tx_offset,
                          bn.full_blob.size() - bn.miner_tx_offset) == 0,
          "full_blob is byte-identical from the miner_tx onward (%zu B compared)",
          bn.full_blob.size() - bn.miner_tx_offset);
}

// ===========================================================================
// Suite C -- the native template path makes no daemon call.
// ===========================================================================
void suite_no_daemon_call() {
    std::printf("== C. the NATIVE template path makes no get_miner_data call ==\n");

    BuiltState st;
    build_state(st, G4::MD_HEIGHT - 1);
    fakes::FakeTxpool pool;
    seed_pool(pool);
    tmpl::NativeMinerDataSource native(st.view, pool, {}, &pool);

    CountingTransport tx(G4::MD_RAW_JSON);

    LaneFixture lane;
    o2::XmrSettlementTemplateProvider pn(native, lane.ledger, lane.scfg, 0);
    for (int i = 0; i < 8; ++i) CHECK(pn.refresh(), "native refresh %d", i);
    CHECK(tx.calls() == 0, "the transport was never called (%llu calls)",
          static_cast<unsigned long long>(tx.calls()));
    CHECK(pn.refreshes() == 8 && pn.changes() == 1,
          "8 refreshes, exactly 1 template change (the epoch never moved)");

    // The same script on the daemon arm MOVES the counter, which is what makes
    // the zero above a measurement rather than a transport nobody wired up.
    // This is the PRODUCTION daemon path: the transport constructor owns a
    // MonerodMinerDataSource and pumps it once per refresh.
    LaneFixture lane2;
    o2::XmrSettlementTemplateProvider pd(tx, lane2.ledger, lane2.scfg, 0);
    for (int i = 0; i < 8; ++i) CHECK(pd.refresh(), "monerod refresh %d", i);
    CHECK(tx.calls() == 8, "the daemon arm made one call per refresh (%llu)",
          static_cast<unsigned long long>(tx.calls()));
}

// ===========================================================================
// Suite D -- readiness is fail-closed.
// ===========================================================================
void suite_readiness_fail_closed() {
    std::printf("== D. an unready native arm serves NO template ==\n");

    ChainStateView empty{XmrNet::Stagenet};
    fakes::FakeTxpool pool;
    tmpl::NativeMinerDataSource src(empty, pool);

    LaneFixture lane;
    o2::XmrSettlementTemplateProvider provider(src, lane.ledger, lane.scfg, 0);

    CHECK(!src.readiness().ok(), "the arm reports itself unready (%s)", src.readiness().why.c_str());
    CHECK(!provider.refresh(), "refresh() refuses");
    CHECK(!provider.last_error().empty(), "and says why: %s", provider.last_error().c_str());
    CHECK(provider.template_id() == 0, "no template id was ever issued");
    CHECK(!provider.current().valid, "current() is invalid");
    CHECK(provider.failures() == 1 && provider.changes() == 0, "one failure, no change");
}

// ===========================================================================
// Suite E -- the shape gate refuses, and the refusal reaches no miner.
// ===========================================================================
void suite_shape_gate_refuses() {
    std::printf("== E. the shape gate is load-bearing, not decorative ==\n");

    BuiltState st;
    build_state(st, G4::MD_HEIGHT - 1);
    fakes::FakeTxpool pool;
    seed_pool(pool);
    tmpl::NativeMinerDataSource src(st.view, pool, {}, &pool);

    LaneFixture lane;
    o2::XmrSettlementTemplateProvider provider(src, lane.ledger, lane.scfg, 0);

    // A gate that judges against a digest the template does not settle. This is
    // the same code path a real owed_digest drift would take.
    ::v37::bytes32 wrong = lane.ledger.ledger().owed_digest();
    wrong[31] = static_cast<std::uint8_t>(wrong[31] ^ 0x01);
    std::uint64_t seen = 0;
    provider.set_shape_gate([&](const asm_::AssembledTemplate& t, std::string* why) {
        ++seen;
        const o2::KFairCoinbaseShape sh = o2::inspect_kfair_coinbase(t, wrong);
        if (!sh.ok) { if (why) *why = sh.why; return false; }
        return true;
    });

    CHECK(!provider.refresh(), "refresh() fails when the gate refuses");
    CHECK(seen == 1, "the gate actually ran (%llu call)", static_cast<unsigned long long>(seen));
    CHECK(provider.last_error().find("shape gate REFUSED") != std::string::npos,
          "the error names the gate: %s", provider.last_error().c_str());
    CHECK(provider.template_id() == 0, "NO template id was issued -- no miner can be handed it");
    CHECK(!provider.current().valid, "current() stays invalid");
    CHECK(provider.failures() == 1, "the refusal is counted as a failure");

    // The same provider with the right digest builds, which proves the refusal
    // above was about the digest and not about the fixture.
    o2::KFairCoinbaseShape ok_shape;
    std::uint64_t refusals = 0;
    provider.set_shape_gate(shape_gate(lane.ledger, &ok_shape, &refusals));
    CHECK(provider.refresh(), "the right digest builds: %s", provider.last_error().c_str());
    CHECK(refusals == 0 && ok_shape.ok, "and the shape is OK");
    CHECK(provider.template_id() == 1, "now a template id is issued");
}

// ===========================================================================
// Suite F -- the resolver, through the same provider.
// ===========================================================================
void suite_resolver() {
    std::printf("== F. the arm resolver, seen from the provider ==\n");

    BuiltState st;
    build_state(st, G4::MD_HEIGHT - 1);
    fakes::FakeTxpool pool;
    seed_pool(pool);
    tmpl::NativeMinerDataSource native(st.view, pool, {}, &pool);

    ChainStateView empty{XmrNet::Stagenet};
    fakes::FakeTxpool empty_pool;
    tmpl::NativeMinerDataSource dead(empty, empty_pool);

    CountingTransport tx(G4::MD_RAW_JSON);
    tmpl::MonerodMinerDataSource daemon(tx);
    auto pump = [&daemon](std::string* w) { return daemon.poll(w); };

    // (1) native ready, fallback OFF: serves native, no daemon pump.
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve    = TemplateArm::Native;
        cfg.shadow   = TemplateArm::Monerod;
        cfg.fallback = false;
        tmpl::ArmResolver r(&daemon, &native, cfg);
        tmpl::ResolvedMinerDataSource resolved(r, pump);

        LaneFixture lane;
        o2::XmrSettlementTemplateProvider provider(
            resolved, lane.ledger, lane.scfg, 0,
            [&resolved](std::string* w) { return resolved.resolve(w); });
        CHECK(provider.refresh(), "native-only: builds (%s)", provider.last_error().c_str());
        CHECK(std::string(provider.source_name()) == "native", "serving arm is native");
        CHECK(resolved.daemon_pumps() == 0, "no get_miner_data round trip (%llu)",
              static_cast<unsigned long long>(resolved.daemon_pumps()));
        CHECK(tx.calls() == 0, "and the transport stayed silent");
    }

    // (2) native DEAD, fallback OFF: serves nothing.
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve    = TemplateArm::Native;
        cfg.shadow   = TemplateArm::Monerod;
        cfg.fallback = false;
        tmpl::ArmResolver r(&daemon, &dead, cfg);
        tmpl::ResolvedMinerDataSource resolved(r, pump);

        LaneFixture lane;
        o2::XmrSettlementTemplateProvider provider(
            resolved, lane.ledger, lane.scfg, 0,
            [&resolved](std::string* w) { return resolved.resolve(w); });
        CHECK(!provider.refresh(), "native-only with a dead arm: refuses");
        CHECK(provider.template_id() == 0, "no template id");
        CHECK(tx.calls() == 0, "and it did NOT quietly ask the daemon");
    }

    // (3) native DEAD, fallback ON: serves monerod, loudly, one pump.
    {
        tmpl::TemplateArmConfig cfg;
        cfg.serve    = TemplateArm::Native;
        cfg.shadow   = TemplateArm::Monerod;
        cfg.fallback = true;
        tmpl::ArmResolver r(&daemon, &dead, cfg);
        tmpl::ResolvedMinerDataSource resolved(r, pump);

        LaneFixture lane;
        o2::KFairCoinbaseShape shape;
        std::uint64_t refusals = 0;
        o2::XmrSettlementTemplateProvider provider(
            resolved, lane.ledger, lane.scfg, 0,
            [&resolved](std::string* w) { return resolved.resolve(w); });
        provider.set_shape_gate(shape_gate(lane.ledger, &shape, &refusals));

        const std::uint64_t before = tx.calls();
        CHECK(provider.refresh(), "fallback: builds (%s)", provider.last_error().c_str());
        CHECK(std::string(provider.source_name()) == "monerod", "serving arm is monerod");
        CHECK(resolved.daemon_pumps() == 1, "exactly one get_miner_data round trip");
        CHECK(tx.calls() == before + 1, "the transport was called once");
        CHECK(r.fell_back() && r.fallbacks() == 1, "the fallback is counted");
        CHECK(!r.last_reason().empty(), "and explained: %s", r.last_reason().c_str());
        CHECK(shape.ok && refusals == 0,
              "the fallback template is STILL the K_fair shape (%s)", shape.describe().c_str());
    }
}

} // namespace

int main() {
    std::printf("=== v37_xmr_m2_native_settlement_kat "
                "(M2: the option-B coinbase, built natively) ===\n");
    suite_native_end_to_end();
    suite_arm_equivalence();
    suite_no_daemon_call();
    suite_readiness_fail_closed();
    suite_shape_gate_refuses();
    suite_resolver();
    std::printf("=== %d checks, %d failed ===\n", g_checks, g_fail);
    return g_fail ? 1 : 0;
}
