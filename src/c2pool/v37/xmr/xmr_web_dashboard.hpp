// SPDX-License-Identifier: AGPL-3.0-or-later
// Copyright (c) 2026, The c2pool developers (frstrtr/c2pool)
//
// This file is part of c2pool and is distributed under the terms of the GNU
// Affero General Public License, version 3 or (at your option) any later
// version. See COPYING in the repository root.
//
// ===========================================================================
// src/c2pool/v37/xmr/xmr_web_dashboard.hpp   (XMR-WEB)
//
// The c2pool web dashboard for c2pool-v37-xmr: the SAME core::WebServer +
// HttpSession + web-static/ UI every other coin binary serves, fed by a
// READ-ONLY provider. The node publishes a plain XmrWebState (built from state
// it already holds: its own stratum, its owed ledger, its native chain view,
// its relay) and reports accepted stratum shares; the provider turns that into
// the p2pool-compatible JSON endpoints. Nothing here is consensus state, no
// monerod RPC is issued, and nothing is opened unless --web-port is given.
//
// This header is deliberately free of core/ and nlohmann includes (pimpl): the
// daemon TU keeps its own namespace, the web layer lives in the .cpp.
//
// Payout scheme: WRS / PPR (Work Receipt Settlement, pay-per-receipt). The
// served UI never says PPLNS for this coin (see payout_scheme()).
// ===========================================================================
#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace c2pool::v37n::xmr::web {

inline constexpr const char* kPayoutScheme     = "WRS / PPR";
inline constexpr const char* kPayoutSchemeLong = "Work Receipt Settlement (pay-per-receipt)";
inline constexpr std::uint64_t kPicoPerXmr = 1000000000000ULL;

struct XmrWebBlock {
    std::uint64_t height = 0;
    std::string   id_hex;                 // block id, 64 hex
    std::uint64_t time = 0;               // unix seconds (found time, else first seen)
    std::string   status = "pending";     // pending (inside D_conf) | main (settled) | orphan
    bool          own = false;            // this node's own find (else booked from the chain)
    bool          coinbase_known = false; // the full coinbase reward is known (own find: its template's reward)
    std::uint64_t coinbase_total_pico = 0;
    std::uint64_t booked_pico = 0;        // what the lane booked for this block (sum of its payouts)
    std::vector<std::pair<std::string, std::uint64_t>> payouts;   // payee (address) -> piconero
};

struct XmrWebPayee {
    std::string  address;                 // base58 when known, else "key:<hex>"
    std::int64_t owed_pico = 0;           // EffectiveOwed
};

struct XmrWebState {
    std::string   version, network, coinbase_mode;
    std::string   stratum_host;  std::uint16_t stratum_port = 0;
    std::uint64_t chain_height = 0;       // native chain view tip
    std::uint64_t network_difficulty = 0; // the current template's (== the next block's) difficulty
    std::uint64_t template_height = 0;
    std::uint64_t share_difficulty = 0;   // the stratum share target (0 = network)
    std::uint64_t d_conf = 0, finalize_cursor = 0, hw = 0, ledger_seq = 0;
    std::string   owed_digest_hex;
    bool          relay_enabled = false;
    std::size_t   relay_ready = 0, relay_conns = 0;
    std::uint64_t relay_foreign_receipts = 0;    // admitted foreign receipts (cumulative)
    std::string   fee_model = "off";
    double        give_author_pct = 0, owner_fee_pct = 0;
    std::string   owner_address, donation_address, payout_address;
    std::uint64_t stratum_connections = 0, stratum_active = 0, stratum_shares = 0, stratum_rejected = 0;
    std::uint64_t found_registered = 0, found_settled = 0, found_orphaned = 0;
    bool          lane_suspended = false;
    std::vector<XmrWebPayee> owed;        // the owed ledger, one row per payee
    std::vector<XmrWebBlock> blocks;      // newest first
};

class XmrWebDashboard {
public:
    // window_s: the hashrate window. dashboard_dir: the static UI root.
    XmrWebDashboard(std::string host, std::uint16_t port, std::string dashboard_dir,
                    bool testnet, std::uint32_t window_s = 300);
    ~XmrWebDashboard();
    XmrWebDashboard(const XmrWebDashboard&) = delete;
    XmrWebDashboard& operator=(const XmrWebDashboard&) = delete;

    bool start();                          // binds; false = could not bind (node keeps running)
    void stop();
    std::uint16_t bound_port() const;

    // Any thread. The node's whole view, replaced atomically.
    void publish(XmrWebState s);
    // Any thread (the stratum listener). One accepted share at `difficulty`.
    void on_share(double difficulty, const std::string& address, const std::string& worker);
    // Test seam: the clock the hashrate window reads (unix seconds).
    void set_clock_for_test(double (*now_s)());

    // The endpoint bodies (JSON text), exactly what the server answers for
    // `path`; "" = not an XMR-provider path. Exposed for the KAT.
    std::string endpoint_json(const std::string& path) const;

private:
    struct Impl;
    std::unique_ptr<Impl> m;
};

}  // namespace c2pool::v37n::xmr::web
