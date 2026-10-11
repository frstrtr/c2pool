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
// it already holds: its own stratum, its Path B node at the best tip, its
// native chain view, its relay) and reports accepted stratum shares; the
// provider turns that into the p2pool-compatible JSON endpoints and the Path B
// status view (/xmr/pathb). Nothing here is consensus state, no monerod RPC is
// issued, and nothing is opened unless --web-port is given.
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

// One found block (the found line): the block, the Path B tip whose window its
// coinbase pays, the outputs and R, and how it landed.
struct XmrWebFound {
    std::uint64_t height = 0;
    std::string   id_hex;                 // block id, 64 hex
    std::uint64_t time = 0;               // unix seconds (found time)
    std::string   tip_hex;                // the Path B tip
    std::string   window_root_hex;
    std::uint64_t n_outputs = 0;
    std::uint64_t reward_pico = 0;        // R
    std::string   landed;                 // monerod | peer | own-index
};

// One payee of the best tip's window (display only).
struct XmrWebPayeeShare {
    std::string   payee;                  // base58 when known, else "key:<hex>"
    double        share = 0;              // its part of the window's weight
    std::uint64_t amount_pico = 0;        // its output at the current template's R (0: no template)
};

// The Path B node at its best tip.
struct XmrWebPathb {
    std::uint64_t tip_pos = 0;
    std::string   tip_id_hex;
    std::string   cum_work;               // decimal
    std::uint32_t epoch_cur = 0;
    std::uint64_t h_hold = 0;
    std::string   window_root_hex, mmr_root_hex;
    std::uint64_t leaf_count = 0;
    std::uint64_t pending = 0, deferred = 0;
    std::uint64_t repended_last_switch = 0;
    std::string   template_status;
    // alarms
    bool          hold = false;
    bool          fork_fuse = false;
    bool          template_kept = false;  // no new template fits: the previous one kept
    bool          store_poisoned = false;
    std::uint64_t coinbase_internal = 0;  // node-internal coinbase-check outcomes
};

struct XmrWebState {
    std::string   version, network;
    std::string   stratum_host;  std::uint16_t stratum_port = 0;
    std::uint64_t chain_height = 0;       // native chain view tip
    std::uint64_t network_difficulty = 0; // the current template's (== the next block's) difficulty
    std::uint64_t template_height = 0;
    std::uint64_t share_difficulty = 0;   // d_at: the stratum share difficulty at the next position
    bool          relay_enabled = false;
    std::size_t   relay_ready = 0, relay_conns = 0;
    std::uint64_t relay_foreign_receipts = 0;    // admitted foreign receipts (cumulative)
    double        give_author_pct = 0, owner_fee_pct = 0;
    std::string   owner_address, payout_address;
    std::uint64_t stratum_connections = 0, stratum_active = 0, stratum_shares = 0, stratum_rejected = 0;
    bool          lane_suspended = false;
    XmrWebPathb   pathb;
    std::vector<XmrWebPayeeShare> window; // the best tip's window
    std::vector<XmrWebFound> found;       // newest first
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
