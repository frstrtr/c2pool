// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// miner_block_path_smoke.cpp  --  Milestone-A miner->block end-to-end smoke
//                                 (Family B: Monero / RandomX lane)
//
// Drives the whole block-winning path through the REAL components, with only
// the two unavoidably-heavy/live seams mocked:
//    * IMonerodTransport   -> MockMonerodTransport (no sockets)  [X2 stub]
//    * IPowVerifier        -> deterministic known-answer mock    [no RandomX]
// Everything else is the production code under test:
//    * XmrStratumServer (X5)           -- login/job/submit control flow + dialect
//    * OwedLedger (W4)                 -- finality-gated EffectiveOwed
//    * FinalizeDriver (F1 contract)    -- per-height, in-order on_block_finalized
//    * build_coinbase (X6, FCMP-fenced)-- OWED -> canonical miner_tx, exact-sum
//    * ref10 point-check backend       -- SAFETY (4), fail-closed descriptors
//
// Stages (each printed PASS/FAIL; nonzero exit on any failure):
//    S0  backends installed (point-check live; fail-closed proven)
//    S1  OWED ledger seeded + F1-finalized in-order  (positive EffectiveOwed)
//    S2  stratum login -> login_ok carries a job (blob/seed/target)
//    S3  stratum job notify serializes
//    S4  winning submit -> status OK, accepted share sunk
//    S5  X6 coinbase built: FCMP-fenced ok, EXACT-SUM == budget,
//        owed outputs are real 8rA stealth keys (nonzero one-time keys)
//    S6  submit_block posted to monerod EXACTLY ONCE via the X2 adapter
//    S7  F1 audit: bin_heights are contiguous, monotone, and NOT the live tip
// ===========================================================================
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "mbp_wiring.hpp"
#include "impl/xmr/stratum/xmr_stratum.hpp"
#include "impl/xmr/coin/xmr_derivation.hpp"

using namespace v37::xmr;
using namespace v37::xmr::mbp;
namespace strat = v37::xmr::stratum;

namespace {

int g_fail = 0;
#define CHECK(cond, ...) do { \
    bool _ok = (cond); \
    std::printf("  [%s] ", _ok ? "PASS" : "FAIL"); \
    std::printf(__VA_ARGS__); std::printf("\n"); \
    if (!_ok) ++g_fail; \
} while (0)

// ---- a valid, torsion-PASS XMR payout ref (STD_KAT prime-order points) -----
::v37::ScriptRef make_ref() {
    ::v37::ScriptRef r;
    r.kind = ::v37::xmr::XMR_STD;
    r.payload.assign(::v37::xmr::kat::STD_KAT.p0.begin(), ::v37::xmr::kat::STD_KAT.p0.end());
    r.payload.insert(r.payload.end(),
                     ::v37::xmr::kat::STD_KAT.p1.begin(), ::v37::xmr::kat::STD_KAT.p1.end());
    return r;
}
::v37::bytes32 id_of(unsigned char seed) {
    ::v37::bytes32 b{};
    for (int i = 0; i < 32; ++i) b[i] = static_cast<unsigned char>(seed + i);
    return b;
}
bool is_zero_key(const ::xmr::coin::PublicKey& k) {
    for (unsigned char b : k.bytes) if (b) return false;
    return true;
}

// ---------------------------------------------------------------------------
// Mock ITemplateSource: one fixed 76-byte hashing blob. mainchain_target and
// lane_target are wide-open so the known-answer PoW clears both.
// ---------------------------------------------------------------------------
class MockTemplateSource : public strat::ITemplateSource {
public:
    bool get_job(std::uint32_t extra_nonce, strat::TemplateJob& out) override {
        out = job_for(extra_nonce);
        return true;
    }
    bool rebuild_blob(std::uint32_t template_id, std::uint32_t extra_nonce,
                      strat::TemplateJob& out) override {
        if (template_id != kTemplateId) return false;
        out = job_for(extra_nonce);
        return true;
    }
    std::uint32_t max_extra_nonces() const override { return 1u << 24; }

    static constexpr std::uint32_t kTemplateId = 0x0000C0DE;
private:
    strat::TemplateJob job_for(std::uint32_t extra_nonce) const {
        strat::TemplateJob t;
        t.blob.assign(strat::HASHING_BLOB_TYPICAL_SIZE, 0);       // 76 B
        // bake the extra_nonce so distinct workers grind disjoint spaces
        for (int i = 0; i < 4; ++i)
            t.blob[8 + i] = static_cast<std::uint8_t>(extra_nonce >> (8 * i));
        t.nonce_offset        = strat::EXPECTED_NONCE_OFFSET_V16;  // 39
        t.template_id         = kTemplateId;
        t.height              = 3000000;
        t.mainchain_target    = 0xFFFFFFFFFFFFFFFFULL;            // easy for the KAT hash
        t.lane_target         = 0xFFFFFFFFFFFFFFFFULL;
        t.monero_major_version = 16;                              // pre-CARROT
        for (auto& b : t.seed_hash) b = 0xAB;
        return t;
    }
};

// ---------------------------------------------------------------------------
// Deterministic known-answer IPowVerifier. Returns an all-zero RandomX hash
// (the best possible), so it clears any nonzero target -- modelling a share
// that wins the network block. NEVER trusts the client result.
// ---------------------------------------------------------------------------
class KnownAnswerPow : public strat::IPowVerifier {
public:
    bool randomx_hash(const std::uint8_t* blob, std::size_t blob_size,
                      std::uint64_t /*height*/,
                      const std::array<std::uint8_t, strat::HASH_SIZE>& /*seed*/,
                      std::array<std::uint8_t, strat::HASH_SIZE>& out_hash,
                      bool /*force_light*/) override {
        ++calls;
        last_blob.assign(blob, blob + blob_size);        // record what we hashed
        out_hash.fill(0x00);                             // known answer: wins
        return true;
    }
    bool meets_target(const std::array<std::uint8_t, strat::HASH_SIZE>& hash,
                      std::uint64_t target) const override {
        std::uint64_t top = 0;
        for (int i = 0; i < 8; ++i)
            top |= static_cast<std::uint64_t>(hash[strat::HASH_SIZE - 8 + i]) << (8 * i);
        return top <= target;
    }
    int calls = 0;
    std::vector<std::uint8_t> last_blob;
};

// ---------------------------------------------------------------------------
// Capture transport: record every wire line the stratum server emits.
// ---------------------------------------------------------------------------
class CaptureTransport : public strat::ITransport {
public:
    bool send_line(std::uint64_t /*cid*/, std::string_view line) override {
        lines.emplace_back(line);
        return true;
    }
    void close(std::uint64_t) override {}
    bool contains(const char* needle) const {
        for (auto& l : lines) if (l.find(needle) != std::string::npos) return true;
        return false;
    }
    std::vector<std::string> lines;
};

} // namespace

int main() {
    std::printf("=== miner->block end-to-end smoke (Family B: XMR lane) ===\n");

    // -----------------------------------------------------------------------
    // S0: descriptor backends. The ref10 point-check TU self-installs at
    // static-init (linked with -DV37_XMR_HAVE_MONERO_CRYPTO). SAFETY (4).
    // -----------------------------------------------------------------------
    std::printf("== S0: descriptor backends (SAFETY 4) ==\n");
    CHECK(point_check_backend_installed(),
          "ed25519 point-check backend live (basepoint passes, identity fails)");
    CHECK(::v37::xmr::xmr_ref_valid(make_ref()),
          "XMR payout ref validates (torsion / prime-order)");

    // -----------------------------------------------------------------------
    // S1: seed the OWED ledger and finalize IN-ORDER through the F1 driver so
    // EffectiveOwed is positive for two identities.
    // -----------------------------------------------------------------------
    std::printf("== S1: OWED ledger seeded + F1-finalized ==\n");
    const ::v37::ChainId kChain = 0xABCD;
    OwedLedger ledger(kChain);
    const ::v37::bytes32 k1 = id_of(0x01);
    const ::v37::bytes32 k2 = id_of(0x40);

    // A prior pool block credited two identities; no payout yet (fresh owed).
    OwedLedger::Amounts credit; credit[k1] = 200000000000ll; credit[k2] = 150000000000ll;
    ledger.on_block_found("blkA", credit, /*payout=*/{});

    // start_height 2999999 = the recovery-restored high-water; blkA at 3000000
    // is the first step this driver confirms.
    FinalizeDriver fdrv(ledger, /*d_conf=*/60, /*start_height=*/2999999);
    fdrv.register_found(/*coin_height=*/3000000, "blkA");
    // tip jumped straight to 3000120 in one ZMQ frame; the driver must still
    // step one height at a time and finalize blkA at its OWN height (3000000),
    // NOT at the tip.
    auto finalized = fdrv.advance_confirmed(/*tip_height=*/3000120);
    CHECK(ledger.is_settled("blkA"), "blkA finalized (SETTLED terminal)");
    CHECK(ledger.effective_owed(k1) == 200000000000ll, "EffectiveOwed(k1) positive");
    CHECK(ledger.effective_owed(k2) == 150000000000ll, "EffectiveOwed(k2) positive");
    CHECK(finalized.size() == 1 && finalized[0].first == 3000000,
          "F1: blkA finalized at its coin height 3000000 (not the tip)");

    // -----------------------------------------------------------------------
    // Coinbase context (consensus-derived) + OWED->X6 bridge + LiveShareSink.
    // -----------------------------------------------------------------------
    CoinbaseContext ctx;
    ctx.monero_major_version = 16;                          // pre-CARROT
    ctx.height = 3000121;                                   // the winning block's height
    for (auto& b : ctx.prev_id.bytes) b = 0x5A;
    ctx.base_reward = 600000000000ull;                      // 0.6 XMR tail
    ctx.fees = 12345678ull;
    ctx.chain_id = kChain;
    ctx.lane_commitment = ledger.owed_digest();             // owed_digest -> MM leaf
    ctx.residual_sink = make_ref();
    ctx.residual_sink_identity = id_of(0x99);
    ctx.h_min = 0;
    ctx.output_cap = 2700;
    ctx.extra_nonce = {0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0};

    auto pay_of = [](const ::v37::bytes32&) -> ::v37::ScriptRef { return make_ref(); };
    auto age_of = [&](const ::v37::bytes32& k) -> std::uint64_t {
        return (k == k1) ? 3000000ull : 3000001ull;         // K_fair age keys
    };
    OwedCoinbaseBridge bridge(ledger, pay_of, age_of);

    ::c2pool::xmr::node::MockMonerodTransport monerod;
    monerod.set_method_body("submit_block",
        "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"result\":{\"status\":\"OK\"}}");

    int receipt_count = 0;
    LiveShareSink sink(monerod, bridge,
        /*ctx_of=*/[&](std::uint32_t){ return ctx; },
        /*receipt_fn=*/[&](const strat::AcceptedShare&){ ++receipt_count; });

    MockTemplateSource templates;
    KnownAnswerPow pow;
    CaptureTransport transport;
    strat::XmrStratumServer server(templates, pow, sink, transport);

    // -----------------------------------------------------------------------
    // S2: login -> login_ok carries a job.
    // -----------------------------------------------------------------------
    std::printf("== S2: stratum login ==\n");
    strat::XmrStratumSession session(/*client_id=*/1);
    bool login_ok = server.handle_login(session, /*req_id=*/1,
        "49Wkfw...stagenet.rig0");        // address.worker (base58 decoded downstream)
    CHECK(login_ok && session.logged_in(), "handle_login accepted, session logged in");
    CHECK(transport.contains("\"job\""), "login_ok carries a job object");
    CHECK(transport.contains("\"seed_hash\""), "job carries seed_hash (RandomX epoch)");
    CHECK(transport.contains("\"status\":\"OK\""), "login result status OK");

    // -----------------------------------------------------------------------
    // S3: a fresh job notification serializes.
    // -----------------------------------------------------------------------
    std::printf("== S3: job notify ==\n");
    const std::size_t before = transport.lines.size();
    server.broadcast_job(session);
    CHECK(transport.lines.size() == before + 1, "broadcast_job emitted one line");
    CHECK(transport.lines.back().find("\"method\":\"job\"") != std::string::npos,
          "job notify uses the CryptoNote job method");

    // -----------------------------------------------------------------------
    // S4: winning submit. job_id 1 was issued at login; nonce=1, result ignored.
    // -----------------------------------------------------------------------
    std::printf("== S4: winning submit ==\n");
    strat::SubmitFields fields;
    fields.rpc_id = std::to_string(session.rpc_id());
    fields.job_id = "00000001";                              // per-connection job id 1
    fields.nonce  = "01000000";                              // little-endian nonce = 1
    fields.result = std::string(64, '0');                    // NEVER trusted for PoW
    const std::size_t before_submit = transport.lines.size();
    bool submit_ok = server.handle_submit(session, /*req_id=*/2, fields);
    CHECK(submit_ok, "handle_submit returned ok");
    CHECK(pow.calls == 1, "PoW recomputed exactly once (authoritative)");
    CHECK(transport.lines.size() == before_submit + 1 &&
          transport.lines.back().find("\"status\":\"OK\"") != std::string::npos,
          "submit accepted with status OK");
    CHECK(receipt_count == 1, "accepted share handed to the v37 work-receipt path");

    // -----------------------------------------------------------------------
    // S5: the X6 coinbase actually built on the winning path.
    // -----------------------------------------------------------------------
    std::printf("== S5: X6 coinbase built (FCMP-fenced, exact-sum, stealth) ==\n");
    const auto& cb = sink.last_build();
    CHECK(cb.ok, "coinbase built ok (major_version 16, inside the FCMP fence)");
    std::uint64_t sum = 0; for (auto& o : cb.outputs) sum += o.amount;
    CHECK(sum == ctx.base_reward + ctx.fees,
          "EXACT-SUM: Sum(vout)=%llu == base_reward+fees=%llu (HF13, no burn)",
          (unsigned long long)sum, (unsigned long long)(ctx.base_reward + ctx.fees));
    bool owed_present = false, all_stealth = true;
    for (auto& o : cb.outputs) {
        if (o.role == ::v37::xmr::settle::CoinbaseOutput::Role::Owed) owed_present = true;
        if (is_zero_key(o.one_time_key)) all_stealth = false;
    }
    CHECK(owed_present, "coinbase carries owed outputs (drawn from EffectiveOwed)");
    CHECK(all_stealth, "every vout is a derived one-time (stealth) key P_i, not descriptor bytes");
    // independent check: R = r*G
    {
        ::xmr::coin::PublicKey Rchk{};
        bool okR = ::xmr::coin::secret_key_to_public_key(cb.r, Rchk) && (Rchk == cb.R);
        CHECK(okR, "tx pubkey R == r*G (deterministic tx key published in tx_extra 0x01)");
    }

    // -----------------------------------------------------------------------
    // S6: submit_block posted to monerod EXACTLY ONCE via the X2 adapter.
    // -----------------------------------------------------------------------
    std::printf("== S6: submit_block via X2 adapter ==\n");
    int submit_block_posts = 0;
    for (const auto& body : monerod.posted_bodies())
        if (::c2pool::xmr::node::MockMonerodTransport::extract_method(body) == "submit_block")
            ++submit_block_posts;
    CHECK(sink.submit_calls() == 1, "LiveShareSink.submit_network_block fired once");
    CHECK(submit_block_posts == 1, "exactly one submit_block RPC posted to monerod");
    CHECK(sink.submit_ok() == 1, "monerod accepted the block (mock status OK)");
    CHECK(sink.refused() == 0, "no fenced/refused build on the winning path");

    // -----------------------------------------------------------------------
    // S7: F1 audit -- bin_heights contiguous, monotone, and never the tip.
    // -----------------------------------------------------------------------
    std::printf("== S7: F1 finalize-driver audit ==\n");
    const auto& seen = fdrv.bin_heights_seen();
    bool contiguous = !seen.empty() && seen.front() == 3000000;
    for (std::size_t i = 1; i < seen.size(); ++i)
        if (seen[i] != seen[i-1] + 1) contiguous = false;
    CHECK(contiguous, "bin_heights are per-height contiguous from 3000000");
    CHECK(!seen.empty() && seen.back() == 3000060,
          "last bin_height is tip-D_conf (3000120-60=3000060), NOT the tip 3000120");
    CHECK(fdrv.last_finalized_height() == 3000060, "driver high-water = 3000060");

    // -----------------------------------------------------------------------
    // S8: FCMP fence negative control -- a post-CARROT major_version must be
    // REFUSED (no coinbase, no submit_block). Proves the fence is load-bearing.
    // -----------------------------------------------------------------------
    std::printf("== S8: FCMP fence negative control ==\n");
    {
        CoinbaseContext carrot = ctx;
        carrot.monero_major_version = 17;                   // > pre-CARROT max (16)
        LiveShareSink fenced_sink(monerod, bridge,
            [&](std::uint32_t){ return carrot; });
        const std::size_t posts_before = monerod.posted_bodies().size();
        fenced_sink.submit_network_block(MockTemplateSource::kTemplateId, 1, 0);
        CHECK(fenced_sink.submit_calls() == 0 && fenced_sink.refused() == 1,
              "v17 winning share REFUSED (CarrotFence), no submit fired");
        CHECK(monerod.posted_bodies().size() == posts_before,
              "no submit_block posted for a fenced (post-CARROT) block");
    }

    std::printf(g_fail == 0
                ? "\nMINER->BLOCK SMOKE OK (0 failures)\n"
                : "\nMINER->BLOCK SMOKE FAILED (%d)\n", g_fail);
    return g_fail == 0 ? 0 : 1;
}
