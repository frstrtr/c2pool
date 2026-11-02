// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Scan & Plan (companion) — the maturity watch (design §6 #1): per watched
// address, the UTXOs that arrived since the previous scan (each with its
// spendable_from_height and ETA) and ONE alert when a batch-worth has matured.
// Read-only and key-free: it produces a notification, never a file to sign,
// never a submit.
//
// The alert is edge-triggered: it fires when the mature set first reaches the
// policy (min_mature UTXOs, or min_value duffs when set) and not again until
// the mature set has dropped below it (a sweep spent it) and reached it again.
// The state lives in its own file (schema c2wallet-scan-watch/1, beside the
// queue by default), written atomically; the alert itself goes to the queue's
// alert list, so `status` reports it and `ack-alerts` acknowledges it.

#include "Classifier.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace c2w::companion::scan {

inline constexpr const char* kWatchSchema = "c2wallet-scan-watch/1";
// Named load failures (anything but a missing file, which is a first run).
inline constexpr const char* kWatchStateUnreadable = "watch-state-unreadable";
inline constexpr const char* kWatchStateCorrupt = "watch-state-corrupt";

struct WatchAddress {
    std::string address;
    std::vector<std::string> known; // "txid:vout" of every row the previous scan saw (sorted)
    int64_t last_tip = 0;
    bool alerted = false;            // the policy held at the previous scan and was alerted
};

struct WatchState {
    std::string network = "mainnet";
    std::vector<WatchAddress> addresses;
    WatchAddress& entry(const std::string& address); // created on first use
};

// A missing file (ENOENT) is an empty state (true). Any other open / read
// failure is watch-state-unreadable; a file that does not parse, another
// schema or another network is watch-state-corrupt.
bool load_watch_state(const std::string& path, const std::string& network, WatchState& out, std::string& why);
bool save_watch_state(const std::string& path, const WatchState& st, std::string& why);

struct WatchPolicy {
    size_t min_mature = 100;   // the real case: about a month of tenant payouts
    int64_t min_value = 0;     // duffs; 0 = not used
};

struct WatchStep {
    bool first_scan = false;
    std::vector<c2w::dash::Utxo> arrivals;    // rows not seen by the previous scan
    std::vector<ImmatureRow> arriving_immature; // the arrivals still immature, with their ETA
    size_t mature = 0;
    int64_t mature_value = 0;
    bool policy_holds = false;
    bool alert = false;                          // raise the alert now (edge)
    std::string alert_text;
};

// Pure: compares the classification with the address's previous state and
// updates it (known, last_tip, alerted).
WatchStep watch_step(WatchAddress& st, const Classification& cls, const WatchPolicy& policy);

} // namespace c2w::companion::scan
