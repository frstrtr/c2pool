// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// mbp_wiring.hpp  --  Milestone-A "miner -> block" wiring (Family B: XMR lane)
//
// This is the GLUE that binds the X5 stratum front-end seams (ITemplateSource /
// IPowVerifier / IShareSink) to the live-node components, and drives the
// block-winning path end to end:
//
//    accepted network-block share
//       -> read the finality-gated OWED ledger (W4 OwedLedger, ledger #2)
//       -> build the X6 canonical coinbase (settle/xmr_coinbase, FCMP-fenced)
//       -> assemble the miner_tx deterministically
//       -> submit the block to monerod via the X2 adapter (IMonerodTransport).
//
// It ALSO carries the F1 finalize driver (the audit's HIGH finding): the driver
// steps OwedLedger::on_block_finalized() ONCE PER COIN-HEIGHT STEP, IN ORDER,
// with bin_height == the coin high-water AT THAT STEP -- driven off the
// mainchain-index height progression, NEVER jumped to the live monerod tip.
//
// HARD SAFETY honoured here:
//   * NO consensus-digest change. This TU only CALLS build_coinbase() /
//     OwedLedger / meets-target; it defines no owed_digest / lane digest / canon.
//   * F1 contract: FinalizeDriver::advance_confirmed() below is the ONLY caller
//     of on_block_finalized in the live daemon, and it is per-height/in-order.
//   * FCMP fence: build_coinbase() already refuses major_version > 16
//     (CarrotFence); LiveShareSink surfaces that instead of building.
//   * Fail-closed descriptors: install_point_check_backend() must run at startup
//     (SAFETY (4)); without it xmr_ref_valid() is false and the sink refuses.
//   * EXPERIMENTAL / stagenet: LivePowVerifier defaults to light verify only.
// ===========================================================================
#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <map>
#include <string>
#include <vector>

// --- X5 stratum seams (front-end) ------------------------------------------
#include "impl/xmr/stratum/xmr_stratum.hpp"
// --- X6 coinbase settlement executor ---------------------------------------
#include "impl/xmr/settle/xmr_coinbase.hpp"
// --- descriptor XMR kinds + point-check backend seam -----------------------
#include "sharechain/v37/v37_descriptor_xmr.hpp"
// --- W4 finality-gated OWED ledger -----------------------------------------
#include "c2pool/v37/w4_settlement.hpp"
// --- X2 monerod I/O seam ----------------------------------------------------
#include "impl/xmr/node/monerod_transport.hpp"

namespace v37 {
namespace xmr {
namespace mbp {

using ::v37::xmr::stratum::AcceptedShare;
using ::v37::xmr::stratum::IPowVerifier;
using ::v37::xmr::stratum::IShareSink;
using ::v37::xmr::settle::BuildError;
using ::v37::xmr::settle::BuiltCoinbase;
using ::v37::xmr::settle::CoinbaseInputs;
using ::v37::xmr::settle::OwedEntry;
using OwedLedger = ::c2pool::v37n::settle::OwedLedger;

// ---------------------------------------------------------------------------
// The consensus-derived context for the coinbase at one Monero parent. Every
// field is a pure function of the mainchain tip + the lane state, so the
// coinbase is byte-reproducible by every node (X6 invariant). In the live
// daemon the template builder stamps this per template_id; here it is a plain
// value the winning path reads back.
// ---------------------------------------------------------------------------
struct CoinbaseContext {
    std::uint8_t                 monero_major_version = 16;   // FCMP fence key
    std::uint64_t                height = 0;
    ::xmr::coin::Hash256         prev_id{};
    std::uint64_t                base_reward = 0;
    std::uint64_t                fees = 0;
    std::uint32_t                chain_id = 0;
    ::v37::bytes32               lane_commitment{};           // owed_digest / MM leaf
    ::v37::ScriptRef             residual_sink;               // mandated absorber (XMR)
    ::v37::bytes32               residual_sink_identity{};
    std::uint64_t                h_min = 0;
    std::uint32_t                output_cap = 2700;
    std::vector<unsigned char>   extra_nonce;                 // 0x02 padded per-worker
};

// Resolve an OWED ledger key (canonical identity) to its XMR payout target and
// its K_fair age. In the daemon these come from the fold's #1485 identity view;
// the bridge takes them as callbacks so it never reaches into engine internals.
using PayOf   = std::function<::v37::ScriptRef(const ::v37::bytes32&)>;
using AgeOf   = std::function<std::uint64_t(const ::v37::bytes32&)>;

// ===========================================================================
// SAFETY (4): install BOTH descriptor backends at startup. The P-1 descriptor
// validator is header-only (v37_descriptor_xmr.hpp); the ed25519 point-check
// backend is provided by v37_descriptor_xmr_point_check_ref10.cpp, which
// self-installs at static-init when linked with -DV37_XMR_HAVE_MONERO_CRYPTO.
// This helper VERIFIES the backend is live (fail-closed otherwise) so a daemon
// refuses to start a lane whose XMR descriptors cannot be validated.
// ===========================================================================
inline bool point_check_backend_installed() {
    // Basepoint MUST pass; the order-1 identity point MUST fail. If no backend
    // is linked, is_valid_point() is false for both -> returns false.
    return ::v37::xmr::kat::check_torsion_kats();
}

// ===========================================================================
// OWED -> X6 CoinbaseInputs bridge. Reads the finality-gated EffectiveOwed
// vector from the ledger and turns it into the X6 executor's input. build()
// returns the canonical BuiltCoinbase (FCMP-fenced inside build_coinbase()).
// ===========================================================================
class OwedCoinbaseBridge {
public:
    OwedCoinbaseBridge(const OwedLedger& ledger, PayOf pay_of, AgeOf age_of)
        : m_ledger(ledger), m_pay_of(std::move(pay_of)), m_age_of(std::move(age_of)) {}

    // Assemble CoinbaseInputs from the ledger's EffectiveOwed (owed > 0 only).
    CoinbaseInputs make_inputs(const CoinbaseContext& ctx) const {
        CoinbaseInputs in;
        in.monero_major_version = ctx.monero_major_version;
        in.height               = ctx.height;
        in.prev_id              = ctx.prev_id;
        in.base_reward          = ctx.base_reward;
        in.fees                 = ctx.fees;
        in.chain_id             = ctx.chain_id;
        in.lane_commitment      = ctx.lane_commitment;
        in.residual_sink        = ctx.residual_sink;
        in.residual_sink_identity = ctx.residual_sink_identity;
        in.h_min                = ctx.h_min;
        in.output_cap           = ctx.output_cap;
        in.extra_nonce          = ctx.extra_nonce;

        // EffectiveOwed(key) is the ONLY quantity a coinbase may draw on (W4
        // §4.4). K_fair sort keys (first_eligible age, identity) are re-attached
        // via the resolver; the X6 allocate_exact_sum re-sorts deterministically.
        for (const auto& [key, owed] : m_ledger.effective_owed_all()) {
            if (owed <= 0) continue;                       // net-negative repairs skip
            OwedEntry e;
            e.pay            = m_pay_of(key);
            e.owed           = static_cast<std::uint64_t>(owed);
            e.first_eligible = m_age_of(key);
            e.identity       = key;
            in.owed.push_back(e);
        }
        return in;
    }

    BuiltCoinbase build(const CoinbaseContext& ctx) const {
        return ::v37::xmr::settle::build_coinbase(make_inputs(ctx));
    }

private:
    const OwedLedger& m_ledger;
    PayOf             m_pay_of;
    AgeOf             m_age_of;
};

// ===========================================================================
// LiveShareSink  --  the IShareSink implementation for the live daemon.
//
//  * on_accepted_share(): hand the share to the v37 work-receipt / RDWR path
//    (a callback here; the receipt-carrier leg owns the real body).
//  * submit_network_block(): the block-winning path. Build the X6 coinbase
//    from the OWED ledger, assemble the miner_tx, and submit to monerod via
//    the X2 adapter. FCMP-fenced: a CarrotFence build is surfaced, never
//    submitted with a possibly-wrong coinbase.
//
// NOTE (single stitch, documented): the coinbase is a pure function of the
// per-template CoinbaseContext, so in the live daemon it is built at template
// time and baked into the hashing blob the miner grinds; submit_network_block
// then re-materialises the identical bytes. This wiring rebuilds it on the
// winning path from the SAME context, which is byte-identical by construction
// (deterministic r). See gaps in the report re: full-block serialization.
// ===========================================================================
class LiveShareSink : public IShareSink {
public:
    using ReceiptFn = std::function<void(const AcceptedShare&)>;

    LiveShareSink(::c2pool::xmr::node::IMonerodTransport& transport,
                  const OwedCoinbaseBridge& bridge,
                  std::function<CoinbaseContext(std::uint32_t /*template_id*/)> ctx_of,
                  ReceiptFn receipt_fn = {})
        : m_transport(transport), m_bridge(bridge),
          m_ctx_of(std::move(ctx_of)), m_receipt(std::move(receipt_fn)) {}

    void on_accepted_share(const AcceptedShare& share) override {
        ++m_accepted;
        if (m_receipt) m_receipt(share);   // -> W2/W3 work-receipt candidate
    }

    void submit_network_block(std::uint32_t template_id,
                              std::uint32_t nonce,
                              std::uint32_t extra_nonce) override {
        const CoinbaseContext ctx = m_ctx_of(template_id);

        // fail-closed: refuse to build a lane coinbase without the point-check
        // backend (SAFETY (4)) -- the residual sink / owed refs would validate
        // to false and mis-settle.
        if (!point_check_backend_installed()) {
            m_last_error = "point-check backend not installed (fail-closed)";
            ++m_refused;
            return;
        }

        const BuiltCoinbase cb = m_bridge.build(ctx);
        m_last_build = cb;
        if (!cb.ok) {
            // FCMP fence trips here for major_version > 16 (CarrotFence).
            m_last_error = std::string("coinbase build refused: ") +
                           ::v37::xmr::settle::to_string(cb.error);
            ++m_refused;
            return;
        }

        // Assemble the full block-template blob and patch the winning header
        // nonce + extra nonce. The X6 output is the miner_tx prefix (coinbase);
        // the submitter splices it under the header at the template's offsets.
        // For this wiring we submit the coinbase prefix as the load-bearing
        // payload of the submit_block RPC (see gaps: full non-coinbase tx list
        // concatenation is the template leg's get_block_template_blob()).
        const std::string block_hex = to_hex(cb.prefix);
        (void)nonce; (void)extra_nonce;

        std::string body =
            "{\"jsonrpc\":\"2.0\",\"id\":\"0\",\"method\":\"submit_block\","
            "\"params\":[\"" + block_hex + "\"]}";
        m_transport.rpc_post(body, [this](const ::c2pool::xmr::node::RpcResponse& r) {
            if (r.ok()) ++m_submit_ok;
            else { m_last_error = "submit_block transport error: " + r.error; }
        });
        ++m_submit_calls;
    }

    // --- diagnostics (never consensus) -------------------------------------
    std::size_t accepted_shares()  const { return m_accepted; }
    std::size_t submit_calls()     const { return m_submit_calls; }
    std::size_t submit_ok()        const { return m_submit_ok; }
    std::size_t refused()          const { return m_refused; }
    const BuiltCoinbase& last_build() const { return m_last_build; }
    const std::string& last_error() const { return m_last_error; }

private:
    static std::string to_hex(const std::vector<unsigned char>& b) {
        static const char* d = "0123456789abcdef";
        std::string s; s.reserve(b.size() * 2);
        for (unsigned char c : b) { s.push_back(d[c >> 4]); s.push_back(d[c & 0xf]); }
        return s;
    }

    ::c2pool::xmr::node::IMonerodTransport& m_transport;
    const OwedCoinbaseBridge&               m_bridge;
    std::function<CoinbaseContext(std::uint32_t)> m_ctx_of;
    ReceiptFn                               m_receipt;

    std::size_t   m_accepted = 0;
    std::size_t   m_submit_calls = 0;
    std::size_t   m_submit_ok = 0;
    std::size_t   m_refused = 0;
    BuiltCoinbase m_last_build{};
    std::string   m_last_error;
};

// ===========================================================================
// FinalizeDriver  --  the F1 CONTRACT (the audit's HIGH finding).
//
// on_block_finalized MUST be called ONCE PER COIN-HEIGHT STEP, IN ORDER, with
// bin_height == the coin high-water AT THAT STEP -- NEVER the live monerod tip.
// This driver is driven off the mainchain-index height progression: register
// each pool block by the coin height at which it settles, then, as the tip
// advances, confirm every height that is now buried >= D_conf, one at a time.
//
// It deliberately does NOT copy the w4 test harness's reconcile()-at-current-tip
// shape. `advance_confirmed(tip_height)` computes the newly-final height as
// tip_height - D_conf and steps the ledger per height; the bin_height it passes
// is the STEP height, so K_fair ages advance monotonically by one coin block,
// exactly as a real chain buries them.
// ===========================================================================
class FinalizeDriver {
public:
    // `start_height` is the persisted SettleHW high-water restored by the
    // RecoveryDriver at startup (O5.5): the driver confirms only heights ABOVE
    // it, so a restart never re-finalizes and never walks from height 0.
    FinalizeDriver(OwedLedger& ledger, std::uint64_t d_conf,
                   std::uint64_t start_height = 0)
        : m_ledger(ledger), m_dconf(d_conf), m_last_final(start_height) {}

    // Register a pool-found block that settles at coin height `coin_height`.
    void register_found(std::uint64_t coin_height, const std::string& bid) {
        m_found[coin_height] = bid;
    }

    // Advance confirmation to the current mainchain tip. Steps every not-yet-
    // finalized coin height h in (last_finalized, tip - D_conf], IN ORDER,
    // calling on_block_finalized(bid_at_h, h). Returns the ordered list of
    // (height, bid) it finalized this call (for audit/tests).
    std::vector<std::pair<std::uint64_t, std::string>>
    advance_confirmed(std::uint64_t tip_height) {
        std::vector<std::pair<std::uint64_t, std::string>> done;
        if (tip_height < m_dconf) return done;                 // nothing buried yet
        const std::uint64_t final_height = tip_height - m_dconf;
        for (std::uint64_t h = m_last_final + 1; h <= final_height; ++h) {
            // F1: monotone, in-order, bin_height == THIS step's coin high-water
            // (h), not the live tip. This holds even when the tip jumped many
            // blocks in one ZMQ frame -- we still step one height at a time.
            m_bin_heights_seen.push_back(h);
            auto it = m_found.find(h);
            if (it != m_found.end()) {
                m_ledger.on_block_finalized(it->second, /*bin_height=*/h);
                done.emplace_back(h, it->second);
            }
            m_last_final = h;
        }
        return done;
    }

    std::uint64_t last_finalized_height() const { return m_last_final; }
    // The full ordered sequence of bin_heights passed -- proves F1 (monotone,
    // contiguous, never a tip jump).
    const std::vector<std::uint64_t>& bin_heights_seen() const {
        return m_bin_heights_seen;
    }

private:
    OwedLedger&   m_ledger;
    std::uint64_t m_dconf;
    std::uint64_t m_last_final = 0;
    std::map<std::uint64_t, std::string> m_found;
    std::vector<std::uint64_t> m_bin_heights_seen;
};

// ===========================================================================
// LivePowVerifier  --  the production IPowVerifier over the light RandomX
// verifier (pow/randomx_verify.hpp). NOT built into the light smoke (256 MiB
// Argon2d cache + JIT is OOM-hostile / sanitizer-hostile); the smoke swaps a
// deterministic known-answer mock. Declared here so the wiring is complete and
// the seam types line up. Guarded so the header stays light-buildable.
// ===========================================================================
#ifdef MBP_WITH_RANDOMX
} // namespace mbp
} // namespace xmr
} // namespace v37
#include "impl/xmr/pow/randomx_verify.hpp"
namespace v37 { namespace xmr { namespace mbp {

class LivePowVerifier : public IPowVerifier {
public:
    // seed_of resolves height -> the 32-byte RandomX seed (from the mainchain
    // index rx_seed_height lookup). Caches must be prefetched off the hot path.
    using SeedOf = std::function<::c2pool::xmr::SeedHash(std::uint64_t)>;
    explicit LivePowVerifier(SeedOf seed_of) : m_seed_of(std::move(seed_of)) {
        m_ok = m_vm.init();
    }
    bool ready() const { return m_ok; }

    bool randomx_hash(const std::uint8_t* blob, std::size_t blob_size,
                      std::uint64_t height,
                      const std::array<std::uint8_t, stratum::HASH_SIZE>& seed_hash,
                      std::array<std::uint8_t, stratum::HASH_SIZE>& out_hash,
                      bool /*force_light*/) override {
        ::c2pool::xmr::SeedHash seed{};
        for (std::size_t i = 0; i < seed.size(); ++i) seed[i] = seed_hash[i];
        (void)height;
        return m_vm.hash(blob, blob_size, seed, out_hash.data());
    }
    bool meets_target(const std::array<std::uint8_t, stratum::HASH_SIZE>& hash,
                      std::uint64_t target) const override {
        // Monero rule: hash * difficulty < 2^256, with difficulty = 2^64/target
        // approximated by the top-word test the seam documents.
        std::uint64_t top = 0;
        for (int i = 0; i < 8; ++i)
            top |= static_cast<std::uint64_t>(hash[stratum::HASH_SIZE - 8 + i]) << (8 * i);
        return top <= target;
    }

private:
    SeedOf m_seed_of;
    ::c2pool::xmr::LightVerifier m_vm;
    bool m_ok = false;
};
#endif // MBP_WITH_RANDOMX

} // namespace mbp
} // namespace xmr
} // namespace v37
