// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/btc/dash_rpc_coin_backend.hpp   (Track A2 follow-on / PR-1 —
//                                                 DASH REGTEST coin backend)
//
// DashRpcCoinBackend — a REAL c2pool::v37n::btc::ICoinBackend
// (btc_coin_backend.hpp:81-101) bound to ONE `dashd -regtest` / `-devnet` over
// the mature v36 dash::coin::NodeRPC client (src/impl/dash/coin/rpc.hpp:70-266).
// Target: c2pool master 89325e91 (Milestone A-BTC, PR #1521 "c2pool-v37-btc
// daemon lifecycle"). Pinned against Dash Core v23.1.7 (the version the v36
// DASH arm cites, src/impl/dash/coin/work_source.hpp:41; the runbook installs
// exactly that release).
//
// DAEMONFUL by design for the single-node bring-up: the comment stub at
// btc_coin_backend.hpp:186-197 sketches a daemonless embedded-SPV binding
// (HeaderChain + chain_rpc + P2P relay). For ONE node against ONE regtest dashd
// that is the wrong tool — the regtest daemon IS the mainchain, and the reorg
// drill is `invalidateblock`/`reconsiderblock` on it. The SPV binding is the
// Phase-C follow-on behind this same interface. Nothing here is consensus code
// (HARD SAFETY 1): the class only answers the four questions the F1 driver and
// the W5 path ask, plus the two height/canonicality probes main's block-event
// driver needs.
//
// THE FOUR ANSWERS AND THEIR RPC SOURCES ---------------------------------------
//   best_tip()      getblockchaininfo → {blocks, bestblockhash, chain,
//                   initialblockdownload} (NodeRPC::getblockchaininfo, rpc.hpp:212).
//                   Sticky: while dashd is unreachable or in IBD the LAST GOOD
//                   tip is returned (never lower — O5.5 would refuse it anyway);
//                   before the first good read it is {0,"",0}. The height-watch
//                   must use try_best_tip() (std::optional) and skip the tick on
//                   nullopt: a zero tip on a fresh store would be ADMITTED by
//                   O5.5 (w4_settlement.hpp:278-281) and pollute hw_tip.
//   is_canonical()  getblockheader <bid> true → {confirmations, height}
//                   (NodeRPC::getblockheader, rpc.hpp:242). Canonical iff
//                   confirmations >= 0 AND height == h. confirmations == -1 is
//                   dashd's own "known, not on the active chain". RPC error -5
//                   (RPC_INVALID_ADDRESS_OR_KEY "Block not found") is NOT
//                   canonical: dashd never had the block. A TRANSPORT failure is
//                   UNKNOWN: retried under Options::oracle_patience, then thrown
//                   as OracleUnavailable — never mapped to a bool (see the note
//                   on why the throw is safe against BtcFinalizeDriver).
//                   No getblockhash(height) is needed, and NodeRPC has none.
//   block_reward()  getblocktemplate (NodeRPC::getwork → DashWorkData,
//                   rpc.hpp:183; rpc_data.hpp:107-141) → m_coinbase_value −
//                   m_payment_amount = the MINER-SPENDABLE coinbase value
//                   (subsidy + fees − masternode − superblock − platform burn),
//                   i.e. exactly what W5's OwedLedger::propose_coinbase may
//                   distribute (w5_coinbase.hpp:321). NOT
//                   compute_dash_block_reward_post_v20 (subsidy.hpp:63): that
//                   is the MAINNET post-V20 schedule; Dash Core regtest pre-V20
//                   subsidy is difficulty-derived (validation.cpp
//                   GetBlockSubsidyHelper: 1111/(dDiff+1)^2 capped 500 DASH,
//                   halving 150) — the daemon's coinbasevalue is the only
//                   correct source on any net. Served from a TTL'd template
//                   cache keyed by height; a height that is not the current
//                   template's returns 0 (fail-closed: W5 proposes nothing
//                   rather than over-allocating → bad-cb-amount).
//   submit_block()  submitblock <hex> (NodeRPC::submit_block_hex, rpc.hpp:189;
//                   null/duplicate/inconclusive == accepted per
//                   submitblock_result_accepted, rpc_data.hpp:64-75). ARM A
//                   (embedded P2P relay) is NOT wired: on an isolated regtest
//                   with 0 coin peers ARM B is the only delivering leg. The
//                   "v37blk:<bid>:<n>" placeholder XbtcNode::on_block_won still
//                   passes (btc_node.hpp:213, 243-247) is REFUSED with
//                   armed=false so the wire is never fed garbage; the real block
//                   bytes are submitted from the DASHWorkSource SubmitBlockFn
//                   binding in main_v37_btc_dash.cpp.
//
// ★ D8 — H_b COMES FROM THE BLOCK, NEVER FROM THE TEMPLATE (verify-round fix 1)
//   The v36 DASHWorkSource hands its SubmitBlockFn `height = wd ? wd->m_height
//   : 0` from cached_work() (src/impl/dash/stratum/work_source.cpp:2698, the
//   "height~=" of the BLOCK FOUND log at :2700, passed at :2845) — the CURRENT
//   template's height, not the job's. Under v36's own HeightRace case (the
//   job's parent moved after issue — exactly what runbook A7 produces with
//   `invalidateblock` while minerd runs) the block sits at T but would be
//   registered at T+1: canonicality(T+1, bid) answers No at maturity (height
//   mismatch) → irreversible on_block_orphaned of a CANONICAL block, and any
//   node registering the true H_b stamps first_eligible at T+D_conf vs
//   T+1+D_conf → owed_digest fork (w4_settlement.hpp:596-615). wd==nullptr →
//   height 0 → a bid at "height 0" is never stepped (the loop starts at
//   cursor+1). So this backend exposes height_of(hash) (getblockheader.height,
//   valid on ANY branch — a header's height is a property of its parent chain)
//   and main derives H_b = height_of(hashPrevBlock) + 1 from the 80-byte header
//   it is handed (header[4..36) = hashPrevBlock, internal byte order); if the
//   parent is unknown at win time main submits first and registers from
//   height_of(bid) after an ACCEPTED submit (write-ahead-before-announce is
//   relaxed for that fallback only, and stated). Never wd->m_height, never 0.
//
// BYTE-ORDER PIN (CoinTip.id, D6) ---------------------------------------------
//   CoinTip.hash = dashd's display hex (uint256::GetHex(), core/uint256.cpp:
//   160-168 writes the words big-endian from the tail = reversed print) — the
//   bid space the F1 driver, getblockheader and FoundBlockFn's
//   block_hash.GetHex() all share.
//   CoinTip.id   = the INTERNAL (serialization) byte order of that hash = the
//   32 bytes the next header commits to in hashPrevBlock. Persisted by
//   SettleHW::advance (w4_settlement.hpp:267-272) into hw_tip (:284-292) and
//   carried in the O2 cut token (:691-694). parse_block_id() below is pure STL
//   (display hex → reversed bytes) and does NOT go through uint256: c2pool's
//   uint256 is `uint32_t pn[8]` (core/uint256.hpp:34) whose begin()/end()
//   iterate WORDS, so a byte-copy of that range is wrong. Any LTC binding must
//   use the same two helpers; MockCoinBackend::hash_to_id (btc_coin_backend.hpp:
//   167-172) should be rewritten to parse_block_id() with its ASCII fallback
//   for non-hex smoke names (seam S-5; not in this file).
//
// THREADING ----------------------------------------------------------------------
//   NodeRPC::Send() is serialized by its own mutex (rpc.hpp:83-93); this class
//   adds one mutex for its caches. Callers: the height-watch thread (best_tip,
//   is_canonical via the F1 driver, canonicality/on_active_chain via the
//   block-event driver) and the stratum io_context thread (block_reward /
//   is_canonical / submit_block via XbtcNode::on_block_won, height_of from the
//   SubmitBlockFn). XbtcNode itself is NOT thread-safe (GAP-7): the
//   BlockEventDriver (block_event_driver.hpp) owns that serialization.
//
// WHY THE OracleUnavailable THROW IS SAFE against BtcFinalizeDriver::advance_to_tip
//   Each bid is write-ahead-then-mutate (btc_finalize_driver.hpp:174-179), the
//   cursor is persisted per height AFTER all bids of that height (:183-184),
//   SettleHW::advance is idempotent at equal height (w4_settlement.hpp:267-272)
//   and already-finalized bids are skipped via is_pending (:169). An exception
//   mid-loop leaves store and ledger consistent; the height-watch catches it,
//   sleeps, and the next tick re-drives from cursor+1. The in-memory m_hw was
//   already advanced; persist_hw() runs on the next successful tick.
//
// HEAVY TU: includes Boost.Asio/Beast + jsonrpccxx + nlohmann via rpc.hpp. It
// must NOT be included from the Threads-only c2pool-v37-btc target (HARD
// SAFETY 6) — it belongs to the new c2pool-v37-btc-dash target that links the
// src/impl/dash objects (see main_v37_btc_dash.cpp for the link set).
// ===========================================================================
#pragma once

#include <chrono>
#include <cstdint>
#include <memory>
#include <mutex>
#include <optional>
#include <stdexcept>
#include <string>
#include <thread>

#include <nlohmann/json.hpp>
#include <jsonrpccxx/common.hpp>                 // jsonrpccxx::JsonRpcException::Code()

#include <core/uint256.hpp>                      // uint256, uint256S (getblockheader takes a uint256)
#include <core/log.hpp>                          // LOG_INFO / LOG_WARNING / LOG_ERROR
#include <impl/dash/coin/rpc.hpp>                // dash::coin::NodeRPC
#include <impl/dash/coin/rpc_data.hpp>           // dash::coin::DashWorkData

#include <c2pool/v37/btc/btc_coin_backend.hpp>   // ICoinBackend, CoinTip, SubmitResult
#include <c2pool/v37/btc/block_event_driver.hpp> // Canon (the tri-state the driver consumes)

namespace c2pool::v37n::btc {

// ── the byte-order pin (D6), pure STL ─────────────────────────────────────────
// display hex (64 chars, the string dashd/litecoind print) → internal bytes
// (what hashPrevBlock commits to). false on malformed input; `out` untouched.
inline bool parse_block_id(const std::string& display_hex, ::v37::bytes32& out) {
    if (display_hex.size() != 64) return false;
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9') return c - '0';
        if (c >= 'a' && c <= 'f') return c - 'a' + 10;
        if (c >= 'A' && c <= 'F') return c - 'A' + 10;
        return -1;
    };
    ::v37::bytes32 b{};
    for (std::size_t i = 0; i < 32; ++i) {
        const int hi = nib(display_hex[2 * i]), lo = nib(display_hex[2 * i + 1]);
        if (hi < 0 || lo < 0) return false;
        b[31 - i] = static_cast<std::uint8_t>((hi << 4) | lo);   // reversed: display → internal
    }
    out = b;
    return true;
}
// internal 32 bytes (e.g. header[4..36) = hashPrevBlock) → display hex.
inline std::string display_hex_of_internal(const unsigned char* p32) {
    static constexpr char kHex[] = "0123456789abcdef";
    std::string s(64, '0');
    for (std::size_t i = 0; i < 32; ++i) {
        const unsigned char b = p32[31 - i];
        s[2 * i]     = kHex[b >> 4];
        s[2 * i + 1] = kHex[b & 0x0f];
    }
    return s;
}

// The chain-tag fence. Exact, except "devnet" ⊇ "devnet-<name>": a -devnet=<name>
// daemon reports NetworkIDString "devnet-<name>" (v23.1.7 src/util/system.cpp:
// 1135-1139 GetDevNetName, used at src/chainparamsbase.cpp:46).
inline bool chain_matches(const std::string& expect, const std::string& chain) {
    if (chain == expect) return true;
    return expect == "devnet" && chain.rfind("devnet-", 0) == 0;
}

// Dash Core v23.1.7 REGTEST genesis (src/chainparams.cpp:846). Pinned by
// wait_ready() when Options::expect_genesis is set (main sets it for --network
// regtest): the chain tag alone cannot tell two regtest daemons apart, the
// genesis can. Verify on the host with `dash-cli -regtest getblockhash 0`.
inline constexpr const char* kDashRegtestGenesisHex =
    "000008ca1832a4baf228eb1553c03d3a2c8e02399550dd6ea8d65cec3ef23d2e";

// Thrown by is_canonical() ONLY after Options::oracle_patience of continuous
// transport failure (see the file header on why this is safe).
struct OracleUnavailable : std::runtime_error {
    using std::runtime_error::runtime_error;
};
// Thrown by try_best_tip() when the daemon behind the port now reports a
// different chain than the one wait_ready() accepted (dashd restarted on
// another network on the same rpcport — runbook A9's fence drill). FATAL:
// main must exit, never follow the new chain.
struct ChainMismatch : std::runtime_error {
    using std::runtime_error::runtime_error;
};

// The slice of a dashd getblocktemplate the W5 path needs. Cached per height.
struct MinerTemplate {
    std::uint32_t height         = 0;
    std::string   prev_hash;                 // display hex
    std::uint64_t coinbase_value = 0;        // dashd "coinbasevalue": subsidy + fees (duffs)
    std::uint64_t payments       = 0;        // Σ masternode[] + superblock[] + payload burn
    std::chrono::steady_clock::time_point fetched_at{};
    // MINER-spendable: what W5 may distribute across K_fair outputs + miner.
    std::uint64_t miner_value() const {
        return coinbase_value > payments ? coinbase_value - payments : 0;
    }
};

// One getblockheader probe, honestly tri-state.
struct HeaderProbe {
    enum class State : std::uint8_t { Have = 0, Missing = 1, Unknown = 2 };
    State         state         = State::Unknown;
    std::uint64_t height        = 0;         // valid when Have (any branch)
    long long     confirmations = 0;         // valid when Have; dashd: -1 == not on the active chain
    bool on_active_chain() const { return state == State::Have && confirmations >= 0; }
};

class DashRpcCoinBackend final : public ICoinBackend {
public:
    struct Options {
        // Withhold best_tip while getblockchaininfo.initialblockdownload is true.
        // On regtest IBD clears as soon as one block with a fresh timestamp is
        // mined (Dash Core nMaxTipAge); the runbook mines 200 before start.
        bool                      require_not_ibd = true;
        // is_canonical: how long to keep retrying a TRANSPORT failure before
        // throwing OracleUnavailable. Bounded so a dead dashd cannot wedge the
        // height-watch forever; the throw is the fail-closed answer.
        std::chrono::milliseconds oracle_patience{30000};
        std::chrono::milliseconds oracle_backoff{250};
        // block_reward: re-fetch the template if the cached one is older than this.
        std::chrono::seconds      template_ttl{20};
        // The chain tag getblockchaininfo must report ("regtest" / "devnet" /
        // "test" / "main"); wait_ready() refuses any other daemon and
        // try_best_tip() re-checks it on every poll (throws ChainMismatch).
        // "devnet" also accepts "devnet-<name>" (a -devnet=<name> daemon's
        // NetworkIDString carries the name, v23.1.7 src/chainparamsbase.cpp:46).
        std::string               expect_chain = "regtest";
        // Optional genesis pin (display hex); empty = not checked. Regtest:
        // kDashRegtestGenesisHex. (A -devnet=<name> has its own genesis; leave
        // empty there or pin the devnet's own.)
        std::string               expect_genesis;
    };

    // (two constructors rather than `Options opt = {}`: a defaulted argument of a
    //  nested struct with default member initializers is rejected by GCC 13 at
    //  this point of class completion.)
    explicit DashRpcCoinBackend(std::shared_ptr<dash::coin::NodeRPC> rpc)
        : m_rpc(std::move(rpc)), m_opt() {}
    DashRpcCoinBackend(std::shared_ptr<dash::coin::NodeRPC> rpc, Options opt)
        : m_rpc(std::move(rpc)), m_opt(std::move(opt)) {}

    // ── readiness (call BEFORE XbtcNode::open(); the node binds is_canonical at
    //    open, btc_node.hpp:118-123, so the oracle must answer). NodeRPC::connect()
    //    is ASYNC on the io_context (rpc.cpp:36-110: async_resolve → async_connect
    //    → check() on the io thread; m_connected is private, rpc.hpp:101, so there
    //    is nothing to wait on but the first answered call). Poll getblockchaininfo
    //    until it answers with the expected chain (and genesis, when pinned).
    //    Returns false on timeout or a fence mismatch (a regtest node must never
    //    talk to a mainnet dashd; NodeRPC::check() only refuses a "main" daemon
    //    under IS_TESTNET, rpc.cpp:337-347).
    bool wait_ready(std::chrono::seconds timeout) {
        const auto deadline = std::chrono::steady_clock::now() + timeout;
        while (std::chrono::steady_clock::now() < deadline) {
            try {
                const nlohmann::json bci = m_rpc->getblockchaininfo();
                if (bci.is_object() && bci.contains("chain")) {
                    const std::string chain = bci["chain"].get<std::string>();
                    if (!chain_matches(m_opt.expect_chain, chain)) {
                        LOG_ERROR << "[v37-dash] REFUSED: dashd reports chain='" << chain
                                  << "' but --network expects '" << m_opt.expect_chain << "'";
                        return false;
                    }
                    if (!m_opt.expect_genesis.empty()) {
                        const HeaderProbe g = probe_header(m_opt.expect_genesis);
                        if (g.state == HeaderProbe::State::Unknown) { std::this_thread::sleep_for(std::chrono::milliseconds(200)); continue; }
                        if (g.state != HeaderProbe::State::Have || g.height != 0) {
                            LOG_ERROR << "[v37-dash] REFUSED: dashd does not carry the pinned genesis "
                                      << m_opt.expect_genesis << " at height 0 (chain=" << chain << ")";
                            return false;
                        }
                    }
                    LOG_INFO << "[v37-dash] dashd ready: chain=" << chain
                             << " blocks=" << bci.value("blocks", 0)
                             << " ibd=" << bci.value("initialblockdownload", false)
                             << (m_opt.expect_genesis.empty() ? "" : " genesis=pinned");
                    return true;
                }
            } catch (const std::exception&) {
                // not connected yet (Send() returns "" → JsonRpcException parse error) or -28 warmup
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(200));
        }
        LOG_ERROR << "[v37-dash] dashd not ready after " << timeout.count() << "s";
        return false;
    }

    // ── (1) mainchain view ───────────────────────────────────────────────────
    CoinTip best_tip() override {
        if (auto t = try_best_tip()) {
            std::lock_guard<std::mutex> g(m_mu);
            m_last_tip = *t;
            return *t;
        }
        std::lock_guard<std::mutex> g(m_mu);
        return m_last_tip;   // sticky last-good; {0,"",0} before the first good read
    }

    // The honest form: nullopt when dashd is unreachable / in IBD / answers
    // malformed. The height-watch uses THIS and skips the tick on nullopt
    // (never feeds a zero tip). Throws ChainMismatch on the per-poll fence.
    std::optional<CoinTip> try_best_tip() {
        nlohmann::json bci;
        try {
            bci = m_rpc->getblockchaininfo();
        } catch (const std::exception& e) {
            note_transport_fail("getblockchaininfo", e.what());
            return std::nullopt;
        }
        if (!bci.is_object() || !bci.contains("blocks") || !bci.contains("bestblockhash"))
            return std::nullopt;
        const std::string chain = bci.value("chain", std::string("?"));
        if (!chain_matches(m_opt.expect_chain, chain))
            throw ChainMismatch("dashd behind the rpc port now reports chain='" + chain +
                                "' (expected '" + m_opt.expect_chain + "')");
        if (m_opt.require_not_ibd && bci.value("initialblockdownload", false)) {
            std::lock_guard<std::mutex> g(m_mu);
            ++m_withheld_ibd;
            return std::nullopt;
        }
        CoinTip t;
        t.height = bci["blocks"].get<std::uint64_t>();
        t.hash   = bci["bestblockhash"].get<std::string>();
        if (!parse_block_id(t.hash, t.id)) return std::nullopt;   // D6 pin
        return t;
    }

    // ── (2) reorg predicate (the bool seam; tri-state underneath) ───────────
    bool is_canonical(std::uint64_t height, const std::string& bid) override {
        const auto deadline = std::chrono::steady_clock::now() + m_opt.oracle_patience;
        for (;;) {
            switch (canonicality(height, bid)) {
                case Canon::Yes: return true;
                case Canon::No:  return false;
                case Canon::Unknown: break;
            }
            if (std::chrono::steady_clock::now() >= deadline) {
                { std::lock_guard<std::mutex> g(m_mu); ++m_oracle_unavailable; }
                LOG_ERROR << "[v37-dash] ORACLE UNAVAILABLE: getblockheader(" << bid
                          << ") @" << height << " unanswered for "
                          << m_opt.oracle_patience.count() << "ms — refusing to guess";
                throw OracleUnavailable("dashd unreachable for is_canonical(" +
                                        std::to_string(height) + "," + bid + ")");
            }
            std::this_thread::sleep_for(m_opt.oracle_backoff);
        }
    }

    // Tri-state, never throws. Consumed directly by BlockEventDriver::
    // recheck_pending (D11) and, once seam S-3 lands, by a Canon-returning
    // CanonicalFn in btc_finalize_driver.hpp:84.
    Canon canonicality(std::uint64_t height, const std::string& bid) noexcept {
        const HeaderProbe p = probe_header(bid);
        switch (p.state) {
            case HeaderProbe::State::Missing: return Canon::No;        // dashd never had it
            case HeaderProbe::State::Unknown: return Canon::Unknown;   // transport / warmup
            case HeaderProbe::State::Have:    break;
        }
        if (p.confirmations < 0) return Canon::No;   // known, not on the active chain
        if (p.height != height)  return Canon::No;   // on-chain at another height: not our block
        return Canon::Yes;
    }

    // ★ D8: the height oracle. The height of a KNOWN header on ANY branch
    // (dashd indexes side branches too); nullopt when Missing or Unknown.
    std::optional<std::uint64_t> height_of(const std::string& display_hex) noexcept {
        const HeaderProbe p = probe_header(display_hex);
        if (p.state != HeaderProbe::State::Have) return std::nullopt;
        return p.height;
    }
    // D11 helper: true/false when dashd answers (Missing == false), nullopt on Unknown.
    std::optional<bool> on_active_chain(const std::string& display_hex) noexcept {
        const HeaderProbe p = probe_header(display_hex);
        if (p.state == HeaderProbe::State::Unknown) return std::nullopt;
        return p.on_active_chain();
    }

    // getblockheader <hash> true, honestly tri-state. -5 "Block not found" →
    // Missing; anything else that fails (parse error on an empty Send() while
    // disconnected, -28 warming up, -32603 internal, malformed body) → Unknown.
    HeaderProbe probe_header(const std::string& display_hex) noexcept {
        HeaderProbe p;
        nlohmann::json hdr;
        try {
            hdr = m_rpc->getblockheader(uint256S(display_hex), /*verbose=*/true);
        } catch (const jsonrpccxx::JsonRpcException& e) {
            // dashd's error object {code,message} is surfaced by
            // JsonRpcException::fromJson (jsonrpccxx/client.hpp:61-62,
            // common.hpp:49-57) → Code() == RPC_INVALID_ADDRESS_OR_KEY (-5).
            if (e.Code() == -5) { p.state = HeaderProbe::State::Missing; return p; }
            note_transport_fail("getblockheader", e.what());
            return p;
        } catch (const std::exception& e) {
            note_transport_fail("getblockheader", e.what());
            return p;
        }
        if (!hdr.is_object() || !hdr.contains("confirmations") || !hdr.contains("height")) return p;
        try {
            p.confirmations = hdr["confirmations"].get<long long>();
            p.height        = hdr["height"].get<std::uint64_t>();
        } catch (const std::exception&) {
            return p;
        }
        p.state = HeaderProbe::State::Have;
        return p;
    }

    // ── (3) subsidy → MINER-spendable coinbase value at `height` ─────────────
    std::uint64_t block_reward(std::uint64_t height) override {
        const MinerTemplate t = template_for(static_cast<std::uint32_t>(height));
        if (t.height != height) {
            LOG_WARNING << "[v37-dash] block_reward(" << height << "): no template at that "
                        << "height (cached=" << t.height << ") — returning 0 (fail-closed)";
            return 0;
        }
        return t.miner_value();
    }

    // Force a fresh getblocktemplate (the height-watch calls this on every tip
    // change so the cache is never a stale payee set — the DASH stale-payee
    // class, rpc.hpp:124-130). Returns the cached template on RPC failure.
    MinerTemplate refresh_template() {
        try {
            const dash::coin::DashWorkData w = m_rpc->getwork();
            MinerTemplate t;
            t.height         = w.m_height;
            t.prev_hash      = w.m_previous_block.GetHex();
            t.coinbase_value = w.m_coinbase_value;
            t.payments       = w.m_payment_amount;
            t.fetched_at     = std::chrono::steady_clock::now();
            std::lock_guard<std::mutex> g(m_mu);
            m_tmpl = t;
            return t;
        } catch (const std::exception& e) {
            note_transport_fail("getblocktemplate", e.what());
            std::lock_guard<std::mutex> g(m_mu);
            return m_tmpl;
        }
    }
    MinerTemplate template_for(std::uint32_t height) {
        {
            std::lock_guard<std::mutex> g(m_mu);
            const bool fresh = (std::chrono::steady_clock::now() - m_tmpl.fetched_at) < m_opt.template_ttl;
            if (m_tmpl.height == height && fresh) return m_tmpl;
        }
        return refresh_template();
    }
    MinerTemplate current_template() {
        std::lock_guard<std::mutex> g(m_mu);
        return m_tmpl;
    }

    // ── (4) submit ───────────────────────────────────────────────────────────
    SubmitResult submit_block(const std::string& block_hex) override {
        SubmitResult r;
        if (block_hex.empty() || block_hex.rfind("v37blk:", 0) == 0) {
            // The XbtcNode::reconstruct_block_hex placeholder (btc_node.hpp:243-247).
            // Not a block. Refuse loudly, do NOT count as an armed submit; the real
            // bytes come through the DASHWorkSource SubmitBlockFn (main).
            r.armed    = false;
            r.accepted = false;
            r.reason   = "placeholder block hex from XbtcNode (GAP-3) — not submitted; "
                         "real bytes are submitted from the DASHWorkSource SubmitBlockFn";
            return r;
        }
        r.armed = true;
        try {
            r.accepted = m_rpc->submit_block_hex(block_hex, /*ignore_failure=*/false);
            if (!r.accepted)
                r.reason = "dashd submitblock rejected (reason logged by NodeRPC::submit_block_hex)";
        } catch (const std::exception& e) {
            r.accepted = false;
            r.reason   = std::string("submitblock transport failure: ") + e.what();
        }
        {
            std::lock_guard<std::mutex> g(m_mu);
            ++m_submits;
            if (r.accepted) ++m_submits_accepted;
        }
        return r;
    }

    const char* name() const override { return "dash-rpc"; }

    // ── telemetry (read from any thread) ────────────────────────────────────
    struct Stats {
        std::uint64_t transport_failures = 0;
        std::uint64_t withheld_ibd       = 0;
        std::uint64_t oracle_unavailable = 0;
        std::uint64_t submits            = 0;
        std::uint64_t submits_accepted   = 0;
    };
    Stats stats() const {
        std::lock_guard<std::mutex> g(m_mu);
        return Stats{m_transport_failures, m_withheld_ibd, m_oracle_unavailable,
                     m_submits, m_submits_accepted};
    }

private:
    void note_transport_fail(const char* what, const char* why) {
        std::lock_guard<std::mutex> g(m_mu);
        if ((++m_transport_failures % 20) == 1)     // rate-limited
            LOG_WARNING << "[v37-dash] dashd RPC " << what << " failed: " << why;
    }

    std::shared_ptr<dash::coin::NodeRPC> m_rpc;
    Options                              m_opt;
    mutable std::mutex                   m_mu;
    CoinTip                              m_last_tip;
    MinerTemplate                        m_tmpl;
    std::uint64_t m_transport_failures = 0, m_withheld_ibd = 0,
                  m_oracle_unavailable = 0, m_submits = 0, m_submits_accepted = 0;
};

} // namespace c2pool::v37n::btc
