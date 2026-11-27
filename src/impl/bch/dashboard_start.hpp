// SPDX-License-Identifier: AGPL-3.0-or-later
#pragma once

// Starting the BCH dashboard's WebServer (bch::standup_pool_run).
//
// A failed bind keeps the WebServer; it is never reset. By start() the standup
// has installed hooks that hold its MiningInterface as a raw pointer for the
// whole run: the node's best-share callback, the work source's found-block and
// Best Share sinks. Freeing the server would leave the next share or rig
// submit calling into freed memory. A server that failed to bind holds no
// listener and serves nothing (the stratum port's HTTP hand-off answers 503
// for it). main_btc.cpp and main_dash.cpp keep theirs the same way.
//
// bch_dashboard_pplns_current_test (dashboard_start_test.cpp) starts one on a
// port that is already bound and fires those hooks.

#include <core/log.hpp>
#include <core/web_server.hpp>

#include <cstdint>
#include <memory>
#include <string>

namespace bch {

// Start the dashboard: true when it listens. Never resets `web_server`.
inline bool start_dashboard(std::unique_ptr<core::WebServer>& web_server,
                            const std::string& http_addr, uint16_t http_port)
{
    if (!web_server) return false;
    if (web_server->start()) return true;
    LOG_ERROR << "[BCH-POOL] WebServer FAILED to bind " << http_addr << ":" << http_port
              << " -- dashboard disabled, run-loop continues (the server is kept: the"
                 " node and work-source hooks hold its MiningInterface).";
    return false;
}

} // namespace bch
