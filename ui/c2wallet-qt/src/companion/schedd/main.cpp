// SPDX-License-Identifier: AGPL-3.0-or-later
//
// c2wallet-qt-schedd — the headless inject scheduler (slice S2).
//
// Runs next to a c2pool DASH node and submits queued, already-signed txs to
// the node's loopback /api/tx-inject/submit when their triggers hold. It is
// KEY-FREE (links the key-free c2wallet-companion library; ci/check_key_free.sh
// runs over this binary) and links Qt6::Core + Qt6::Network only (no Gui, no
// Widgets: it runs under systemd with no display; ci/check_no_gui_link.sh).
//
// Everything operator-facing lives in sched/SchedCli (Qt-free, KAT-covered);
// this file only supplies the Qt Network transports (the node, and dashd for
// the Scan & Plan commands), the system clock,
// stdout/stderr and SIGTERM/SIGINT-aware sleeping between ticks. The control
// token is never read from argv or the environment: only the runner reads it,
// from the 0600 --token-file, at the moment of each request.

#include "../scan/QtRpcApi.hpp"
#include "../sched/Clock.hpp"
#include "../sched/QtNodeApi.hpp"
#include "../sched/SchedCli.hpp"

#include <QCoreApplication>

#include <algorithm>
#include <csignal>
#include <ctime>
#include <iostream>
#include <string>
#include <vector>

namespace {

volatile std::sig_atomic_t g_stop = 0;

extern "C" void on_stop_signal(int) { g_stop = 1; }

void install_signal_handlers()
{
    struct sigaction sa {};
    sa.sa_handler = on_stop_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0; // no SA_RESTART: a sleeping runner wakes up and exits
    ::sigaction(SIGTERM, &sa, nullptr);
    ::sigaction(SIGINT, &sa, nullptr);
    struct sigaction ign {};
    ign.sa_handler = SIG_IGN;
    sigemptyset(&ign.sa_mask);
    ::sigaction(SIGPIPE, &ign, nullptr);
}

} // namespace

int main(int argc, char** argv)
{
    // Qt sees only the program name: none of our arguments are Qt options.
    int qt_argc = 1;
    char* qt_argv[] = {argv[0], nullptr};
    QCoreApplication app(qt_argc, qt_argv);
    install_signal_handlers();

    namespace sched = c2w::companion::sched;
    sched::SystemClock clock;
    sched::cli::Env env;
    env.out = &std::cout;
    env.err = &std::cerr;
    env.clock = &clock;
    env.make_api = [](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
        auto api = sched::QtNodeApi::create(url, why);
        if (api) api->set_stop_check([] { return g_stop != 0; });
        return api;
    };
    // Scan & Plan: dashd over the loopback JSON-RPC (credentials from the 0600
    // file at each request), and the node scan with the node's own 120 s cap
    // plus a margin. SIGINT / SIGTERM cancel a scan: the node request is
    // dropped, a running scantxoutset is aborted.
    env.make_rpc = [](const std::string& url, const std::string& auth_file,
                      std::string& why) -> std::unique_ptr<c2w::companion::scan::RpcApi> {
        return c2w::companion::scan::QtRpcApi::create(url, auth_file, why);
    };
    env.make_scan_api = [](const std::string& url, std::string& why) -> std::unique_ptr<sched::NodeApi> {
        auto api = sched::QtNodeApi::create(url, why, 130000);
        if (api) api->set_stop_check([] { return g_stop != 0; });
        return api;
    };
    env.sleep_ms = [](int64_t ms) {
        while (ms > 0 && !g_stop) {
            const int64_t step = std::min<int64_t>(ms, 200);
            struct timespec ts {};
            ts.tv_sec = static_cast<time_t>(step / 1000);
            ts.tv_nsec = static_cast<long>((step % 1000) * 1000000L);
            ::nanosleep(&ts, nullptr);
            ms -= step;
        }
    };
    env.stop_requested = [] { return g_stop != 0; };

    const std::vector<std::string> args(argv + 1, argv + argc);
    const int rc = sched::cli::run(args, env);
    std::cout.flush();
    return rc;
}
